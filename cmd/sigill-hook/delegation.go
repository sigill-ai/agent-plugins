package main

// Agent Delegation v1 (sigill-dotnet spec/agent-delegation-v1.md, §11 maps Claude Code onto it):
// every sub-agent is its own run, bound to its parent in both directions.
//
//	PreToolUse(Agent)  parent seals `delegation`, declaring the child's correlationId and agent id
//	SubagentStart      the child's Control Artifact, then run_start binding that delegation
//	hooks with agent_id  events in the child's own chain
//	SubagentStop       the child's model_output and run_end, then the parent's `delegation_result`
//	SessionEnd         children still open close `aborted` and are resolved before the parent closes
//
// Every intent (a delegation, a result) is saved with the Pending of the event that commits it, so
// after a crash the chain head decides what was sealed (reconcile): never two results for one child.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sigill-ai/agent-plugins/internal/evidence"
	"github.com/sigill-ai/agent-plugins/internal/state"
)

func isAgentTool(tool string) bool { return host.IsDelegationTool(tool) }

// hasRoomToDelegate: the delegation, a result for every open delegation including this one, and run_end
// must all fit in the bundle limit (§4 rule 6). Without room the call is recorded as an ordinary tool_call.
func hasRoomToDelegate(run *state.Run) bool {
	return run.NextSeq+1+run.Outstanding()+1+1 <= maxEvents
}

// safeName keeps a configured sub-agent type usable in an identifier and a file name.
func safeName(t string) string {
	if t == "" || len(t) > 64 {
		return "subagent"
	}
	for _, c := range t {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return "subagent"
		}
	}
	if strings.HasPrefix(t, ".") {
		return "subagent"
	}
	return t
}

// subagentType is the configured role of the sub-agent a delegation starts (never the task); see hostProfile.
func subagentType(toolInput json.RawMessage) string { return host.SubagentType(toolInput) }

// delegate seals the `delegation` declaring a child run, before the sub-agent exists (§4 rule 1).
func (r *recorder) delegate(ctx context.Context, run *state.Run, in input, ext map[string]any) error {
	typ := subagentType(in.ToolInput)
	d := state.Delegation{
		ChildCorrelationID: "urn:uuid:" + evidence.NewUUID(),
		ChildAgentID:       r.cfg.AgentID + ":" + safeName(typ),
		SubagentType:       typ,
		UseID:              in.ToolUseID,
		Seq:                run.NextSeq,
		ResultSeq:          -1,
		CreatedAt:          time.Now(),
		TaskKey:            taskKey(stringField(in.ToolInput, "task_name")),
	}
	return r.delegateWith(ctx, run, in, ext, d)
}

// taskKey is a one-way key of a Codex task name (model-chosen text): kept locally only, to tie a
// follow-up's target to the delegation that spawned the agent. Empty for an empty name.
func taskKey(name string) string {
	if name == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("sigill-codex-task\x00" + name))
	return hex.EncodeToString(sum[:16])
}

func stringField(raw json.RawMessage, key string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	var v string
	_ = json.Unmarshal(m[key], &v)
	return v
}

// followup hands an existing Codex sub-agent new work (collaborationfollowup_task). The agent will run again
// under the same agent_id without a SubagentStart, so the work is declared as a new delegation — a new
// episode, a new child run — bound to the agent whose spawn delegation carries the target's task key. A
// sealed child run is never reopened. When the target cannot be tied to exactly one bound agent, the call is
// an ordinary tool_call; the agent's later events are then kept in the delegating chain with a signed
// capture-fidelity checkpoint (continuation).
func (r *recorder) followup(ctx context.Context, run *state.Run, in input, ext map[string]any) (bool, error) {
	key := taskKey(stringField(in.ToolInput, "target"))
	agent, matches := "", 0
	if key != "" {
		for _, sr := range r.sessionRuns(run) {
			for _, d := range sr.Delegations {
				if d.TaskKey == key && d.ClaudeAgentID != "" && d.FollowupOf == "" && d.ClaudeAgentID != agent {
					agent = d.ClaudeAgentID
					matches++
				}
			}
		}
	}
	if matches != 1 {
		logf(r.store, "run %s: follow-up %s not tied to one sub-agent (%d candidates); recorded as a tool call", run.Name, in.ToolUseID, matches)
		return false, nil
	}
	d := state.Delegation{
		ChildCorrelationID: "urn:uuid:" + evidence.NewUUID(),
		ChildAgentID:       r.cfg.AgentID + ":" + safeName(host.SubagentTypeOf("")),
		SubagentType:       host.SubagentTypeOf(""),
		UseID:              in.ToolUseID,
		Seq:                run.NextSeq,
		ResultSeq:          -1,
		CreatedAt:          time.Now(),
		TaskKey:            key,
		FollowupOf:         agent,
		ClaudeAgentID:      agent,
	}
	return true, r.delegateWith(ctx, run, in, ext, d)
}

// startEpisode opens the child run for the next episode of a Codex sub-agent: the one committed, unresolved
// follow-up delegation for this agent without a run yet. nil when there is none.
func (r *recorder) startEpisode(ctx context.Context, main *state.Run, in input) (*state.Run, error) {
	var parent *state.Run
	idx, n := -1, 0
	for _, sr := range r.sessionRuns(main) {
		if sr.Closed || sr.Broken != "" || sr.CloseRequested != "" {
			continue
		}
		for i, d := range sr.Delegations {
			if d.FollowupOf == in.AgentID && d.Committed(sr) && d.ChildRun == "" && !d.Resolved(sr) {
				parent, idx = sr, i
				n++
			}
		}
	}
	if n != 1 {
		return nil, nil
	}
	d := &parent.Delegations[idx]
	d.ChildRun = time.Now().UTC().Format("20060102T150405Z") + "-" + evidence.NewUUID()[:8]
	if err := r.store.Save(parent); err != nil {
		return nil, err
	}
	child, err := r.newRun(ctx, in, "", parent, d)
	if err != nil {
		if child != nil {
			logf(r.store, "run %s: sub-agent episode run %s could not start: %v", parent.Name, child.Name, err)
		}
		return nil, err
	}
	return child, nil
}

// continuation records, once per run, that a sub-agent acted after its run had closed with no follow-up to
// tie the new work to (an unresolvable follow-up, or a stop hook that asked it to continue). Its events are
// kept in this chain, tagged; the signed checkpoint makes the gap visible and the run closes aborted.
func (r *recorder) continuation(ctx context.Context, run *state.Run, agentID string) error {
	if run.FidelityIssue != "" {
		return nil
	}
	detail := "capture-fidelity: a sub-agent acted after its run had closed without a recorded follow-up; its later events are recorded in this run"
	run.FidelityIssue = detail
	if run.NextSeq+1+run.Outstanding()+1 > maxEvents {
		return r.breakRun(run, detail+"; it could not be recorded within the event budget, so capture stopped")
	}
	if err := r.store.Save(run); err != nil {
		return err
	}
	logf(r.store, "run %s: sub-agent %s continued after its run closed", run.Name, agentID)
	return r.seal(ctx, run, "checkpoint", map[string]any{"detail": detail}, false, false, nil, nil)
}

// delegateWith seals a prepared delegation.
func (r *recorder) delegateWith(ctx context.Context, run *state.Run, in input, ext map[string]any, d state.Delegation) error {
	block := map[string]any{"childCorrelationId": d.ChildCorrelationID, "childAgentId": d.ChildAgentID}
	if d.UseID != "" {
		block["useId"] = d.UseID
	}
	objs := []evidence.Object{evidence.NewObject("delegation-input", "application/json", jsonOrEmpty(in.ToolInput))}
	run.Delegations = append(run.Delegations, d) // the intent travels with this event's Pending
	// Starting a sub-agent is classified like any tool (SIGILL_CONSEQUENTIAL_TOOLS may list Agent/Task) and
	// follows the same timestamp policy as a tool_call.
	conseq := r.cfg.isConsequential(in.ToolName)
	if err := r.seal(ctx, run, "delegation", map[string]any{"delegation": block}, conseq, conseq && run.Policy.Consequential, ext, objs); err != nil {
		if run.Broken == "" { // nothing was requested: forget the intent
			run.Delegations = run.Delegations[:len(run.Delegations)-1]
			_ = r.store.Save(run)
		}
		return err
	}
	run.Delegations[len(run.Delegations)-1].Sig = run.PrevSig
	return r.store.Save(run)
}

// startChild opens the run for a sub-agent that just started (SubagentStart). Claude Code does not say
// which Agent call started it. A sub-agent is bound only when that is unambiguous: exactly one committed,
// unpaired delegation of its type in the session, and pairing not stopped by an earlier contradiction.
// Otherwise its events stay in the delegating chain, tagged, and the delegation remains unresolved (the
// parent then closes aborted): never a guessed binding.
func (r *recorder) startChild(ctx context.Context, main *state.Run, in input) error {
	var parent *state.Run
	idx, candidates := -1, 0
	for _, run := range r.sessionRuns(main) {
		if run.PairingStopped {
			logf(r.store, "session %s: sub-agent %s not bound (pairing stopped after a contradiction)", state.SessionKey(main.SessionID), in.AgentID)
			return nil
		}
		if run.Closed || run.Broken != "" || run.CloseRequested != "" || run.Version() != "2" {
			continue
		}
		for i, d := range run.Delegations {
			if d.Committed(run) && d.ChildRun == "" && !d.Resolved(run) && d.FollowupOf == "" && d.SubagentType == host.SubagentTypeOf(in.AgentType) {
				candidates++
				parent, idx = run, i
			}
		}
	}
	if candidates != 1 {
		if candidates > 1 {
			logf(r.store, "session %s: sub-agent %s not bound: %d pending delegations of type %s", state.SessionKey(main.SessionID), in.AgentID, candidates, in.AgentType)
		}
		return nil // events are recorded in the delegating chain, tagged
	}
	d := &parent.Delegations[idx]
	d.ChildRun = time.Now().UTC().Format("20060102T150405Z") + "-" + evidence.NewUUID()[:8]
	d.ClaudeAgentID = in.AgentID
	if err := r.store.Save(parent); err != nil { // the name is reserved before the directory exists
		return err
	}
	child, err := r.newRun(ctx, in, "", parent, d)
	if err != nil && child != nil {
		logf(r.store, "run %s: sub-agent run %s could not start: %v", parent.Name, child.Name, err)
	}
	return err
}

// sessionRuns loads every run of the session (the main run included, recovered and reconciled).
func (r *recorder) sessionRuns(main *state.Run) []*state.Run {
	runs := []*state.Run{}
	for _, name := range r.store.Runs(main.SessionID) {
		if name == main.Name {
			runs = append(runs, main)
			continue
		}
		run, err := r.store.LoadRun(main.SessionID, name)
		if err != nil || (run.Account != "" && run.Account != r.account) {
			continue
		}
		if r.recover(run) != nil {
			continue
		}
		runs = append(runs, run)
	}
	return runs
}

// childByAgent finds the run recording a sub-agent, by its agent_id: its open episode when it has one,
// otherwise its latest (Codex agents can run several episodes, each its own child run).
func (r *recorder) childByAgent(session, agentID string) (*state.Run, error) {
	var latest *state.Run
	for _, name := range r.store.Runs(session) {
		run, err := r.store.LoadRun(session, name)
		if err != nil || run.ClaudeAgentID != agentID || run.ParentRun == "" {
			continue
		}
		if run.Account != "" && run.Account != r.account {
			return nil, nil
		}
		if err := r.recover(run); err != nil {
			return run, err
		}
		if !run.Closed && run.Broken == "" {
			return run, nil
		}
		if latest == nil || run.StartedAt.After(latest.StartedAt) {
			latest = run
		}
	}
	return latest, nil
}

// closeChild ends a sub-agent run and records the result in its parent, with the same closure protocol as
// every run: its own sub-agents are closed and resolved first; its last output is sealed only while the
// output and run_end still fit the bundle limit; it closes "aborted" when a delegation stays unresolved.
func (r *recorder) closeChild(ctx context.Context, child *state.Run, lastMessage, disposition, detail string) error {
	if !child.Closed && child.Broken == "" {
		if err := r.closeChildren(ctx, child, "parent sub-agent ended"); err != nil {
			return err // the child itself is stopped: nothing more is sealed on it
		}
		var fidelity string
		disposition, fidelity = closureOf(child, disposition)
		detail = joinDetail(fidelity, detail)
		if lastMessage != "" {
			if child.NextSeq+2 <= maxEvents { // model_output + run_end
				objs := []evidence.Object{evidence.NewObject("model-output", "text/markdown", []byte(lastMessage))}
				if err := r.seal(ctx, child, "model_output", nil, false, false, nil, objs); err != nil {
					return err
				}
			} else {
				logf(r.store, "run %s: no room for the sub-agent's last output; closing with run_end", child.Name)
			}
		}
		step := map[string]any{"finalSeq": child.NextSeq, "finalPrevSignatureSha256": child.PrevSig, "runDisposition": disposition}
		if detail != "" {
			step["detail"] = detail
		}
		if err := r.seal(ctx, child, "run_end", step, false, true, nil, nil); err != nil {
			return err
		}
	}
	parent, err := r.store.LoadRun(child.SessionID, child.ParentRun)
	if err != nil {
		return err
	}
	if err := r.recover(parent); err != nil {
		return err
	}
	return r.resolve(ctx, parent, child)
}

// closeChildren ends every sub-agent still open below run (deepest first) and resolves them (§4 rule 7).
// A child that cannot be closed stays unresolved (its parent then closes aborted); that is the child's
// failure. A failure to seal a result in run itself stops run: it is returned, and the caller seals nothing
// more on run.
func (r *recorder) closeChildren(ctx context.Context, run *state.Run, detail string) error {
	for i := range run.Delegations {
		d := run.Delegations[i]
		if !d.Committed(run) || d.Resolved(run) || d.ChildRun == "" {
			continue
		}
		child, err := r.store.LoadRun(run.SessionID, d.ChildRun)
		if err != nil || r.recover(child) != nil {
			continue // never started, or unknown: the delegation stays unresolved and the parent closes aborted
		}
		if err := r.closeChildren(ctx, child, detail); err != nil {
			logf(r.store, "run %s: sub-agent run %s stopped while closing its own sub-agents: %v", run.Name, child.Name, err)
			continue
		}
		if !child.Closed && child.Broken == "" {
			disposition, fidelity := closureOf(child, "aborted")
			step := map[string]any{"finalSeq": child.NextSeq, "finalPrevSignatureSha256": child.PrevSig,
				"runDisposition": disposition, "detail": joinDetail(fidelity, detail)}
			if err := r.seal(ctx, child, "run_end", step, false, true, nil, nil); err != nil {
				logf(r.store, "run %s: sub-agent run %s could not be closed: %v", run.Name, child.Name, err)
				continue
			}
		}
		if err := r.resolve(ctx, run, child); err != nil {
			return err
		}
	}
	if run.Broken != "" {
		return fmt.Errorf("run %s is stopped (%s)", run.Name, run.Broken)
	}
	return nil
}

// closureOf is the disposition a run may close with: never "completed" with an unresolved delegation
// (§4 rule 5) or a known capture-fidelity issue; the issue is returned as the run_end detail.
func closureOf(run *state.Run, wanted string) (disposition, detail string) {
	disposition = wanted
	if run.Outstanding() > 0 || run.FidelityIssue != "" {
		disposition = "aborted"
	}
	return disposition, run.FidelityIssue
}

func joinDetail(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

// resolve seals the parent's `delegation_result` for a closed child — once (§4 rules 3 and 4).
func (r *recorder) resolve(ctx context.Context, parent, child *state.Run) error {
	if !child.Closed || parent.Closed || parent.Broken != "" {
		return nil
	}
	i := -1
	for k, d := range parent.Delegations {
		if d.ChildCorrelationID == child.CorrelationID && d.Committed(parent) && !d.Resolved(parent) {
			i = k
		}
	}
	if i < 0 {
		return nil
	}
	disposition, err := r.runEndDisposition(child)
	if err != nil {
		return err
	}
	block := map[string]any{
		"childCorrelationId":         child.CorrelationID,
		"childRunEndSignatureSha256": child.PrevSig, // the last sealed event is the child's run_end
		"childDisposition":           disposition,
	}
	parent.Delegations[i].ResultSeq = parent.NextSeq // the intent travels with this event's Pending
	if err := r.seal(ctx, parent, "delegation_result", map[string]any{"delegation": block}, false, false, nil, nil); err != nil {
		if parent.Broken == "" {
			parent.Delegations[i].ResultSeq = -1
			_ = r.store.Save(parent)
		}
		return err
	}
	return nil
}

// runEndDisposition reads the disposition the child's sealed run_end states.
func (r *recorder) runEndDisposition(run *state.Run) (string, error) {
	a, err := r.store.LoadArtifact(run, fmt.Sprintf("%04d-run_end", run.NextSeq-1))
	if err != nil {
		return "", err
	}
	var env struct {
		Step struct {
			RunDisposition string `json:"runDisposition"`
		} `json:"step"`
	}
	if err := json.Unmarshal(a.Envelope, &env); err != nil || env.Step.RunDisposition == "" {
		return "", fmt.Errorf("run_end of %s has no disposition", run.Name)
	}
	return env.Step.RunDisposition, nil
}

// reconcile settles delegation intents against the chain head after a crash: what the chain contains was
// sealed, anything at or beyond NextSeq was not.
func (r *recorder) reconcile(run *state.Run) error {
	changed := false
	kept := run.Delegations[:0]
	for _, d := range run.Delegations {
		if d.Sig == "" {
			if d.Seq >= run.NextSeq {
				changed = true
				continue // never sealed
			}
			a, err := r.store.LoadArtifact(run, fmt.Sprintf("%04d-delegation", d.Seq))
			if err != nil {
				return r.breakRun(run, fmt.Sprintf("delegation at seq %d is in the chain but not stored", d.Seq))
			}
			d.Sig = evidence.SignatureSha256(a.Signature)
			changed = true
		}
		if d.ResultSeq >= run.NextSeq {
			d.ResultSeq = -1
			changed = true
		}
		kept = append(kept, d)
	}
	run.Delegations = kept
	if !changed {
		return nil
	}
	return r.store.Save(run)
}

// checkPairing compares Claude Code's own answer (PostToolUse.tool_response.agentId) with the sub-agent
// run bound to that Agent call. On a contradiction the producer's launch-to-child claim is unreliable: a
// checkpoint in the delegating run records it (signed, so verifiers see it), and pairing stops for the rest
// of the session (agent-delegation-v1.md §11). The sealed history is kept as it is.
func (r *recorder) checkPairing(ctx context.Context, run *state.Run, in input) error {
	var resp struct {
		AgentID string `json:"agentId"`
	}
	if json.Unmarshal(in.ToolResponse, &resp) != nil || resp.AgentID == "" {
		return nil
	}
	for _, d := range run.Delegations {
		if d.UseID != in.ToolUseID || d.ClaudeAgentID == "" || d.ClaudeAgentID == resp.AgentID {
			continue
		}
		logf(r.store, "run %s: sub-agent pairing contradiction for %s (bound %s, %s reports %s)",
			run.Name, in.ToolUseID, d.ClaudeAgentID, host.DisplayName, resp.AgentID)
		detail := fmt.Sprintf("capture-fidelity: delegation seq %d paired with a different sub-agent than %s reports", d.Seq, host.DisplayName)
		run.PairingStopped = true
		run.FidelityIssue = detail // the run will close "aborted" with this detail, whatever else happens
		// The checkpoint must not use the slots reserved for results and run_end (§4 rule 6). Without room the
		// contradiction cannot be recorded safely, so capture stops here.
		if run.NextSeq+1+run.Outstanding()+1 > maxEvents {
			return r.breakRun(run, detail+"; it could not be recorded within the event budget, so capture stopped")
		}
		if err := r.store.Save(run); err != nil {
			return err
		}
		return r.seal(ctx, run, "checkpoint", map[string]any{"detail": detail}, false, false, nil, nil)
	}
	return nil
}
