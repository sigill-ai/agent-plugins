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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sigill-ai/claude-plugins/internal/evidence"
	"github.com/sigill-ai/claude-plugins/internal/state"
)

func isAgentTool(tool string) bool { return tool == "Agent" || tool == "Task" }

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

// subagentType is the Agent tool's subagent_type (a role name from configuration, never the task).
func subagentType(toolInput json.RawMessage) string {
	var in struct {
		SubagentType string `json:"subagent_type"`
	}
	_ = json.Unmarshal(toolInput, &in)
	if in.SubagentType == "" {
		return "general-purpose"
	}
	return in.SubagentType
}

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
	}
	block := map[string]any{"childCorrelationId": d.ChildCorrelationID, "childAgentId": d.ChildAgentID}
	if d.UseID != "" {
		block["useId"] = d.UseID
	}
	objs := []evidence.Object{evidence.NewObject("delegation-input", "application/json", jsonOrEmpty(in.ToolInput))}
	run.Delegations = append(run.Delegations, d) // the intent travels with this event's Pending
	if err := r.seal(ctx, run, "delegation", map[string]any{"delegation": block}, false, false, ext, objs); err != nil {
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
// which Agent call started it; launches run one at a time (PreToolUse → SubagentStart → PostToolUse), so
// the oldest pending delegation of the same type is its own. PostToolUse confirms it (checkPairing).
func (r *recorder) startChild(ctx context.Context, main *state.Run, in input) error {
	var parent *state.Run
	idx := -1
	for _, run := range r.sessionRuns(main) {
		if run.Closed || run.Broken != "" || run.CloseRequested != "" || run.Version() != "2" {
			continue
		}
		for i, d := range run.Delegations {
			pending := d.Committed(run) && d.ChildRun == "" && !d.Resolved(run) && d.SubagentType == in.AgentType
			if pending && (parent == nil || d.CreatedAt.Before(parent.Delegations[idx].CreatedAt)) {
				parent, idx = run, i
			}
		}
	}
	if parent == nil {
		return nil // no declared delegation: the sub-agent's events are recorded in the main run, tagged
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

// childByAgent finds the run recording a Claude Code sub-agent, by its agent_id.
func (r *recorder) childByAgent(session, agentID string) (*state.Run, error) {
	for _, name := range r.store.Runs(session) {
		run, err := r.store.LoadRun(session, name)
		if err != nil || run.ClaudeAgentID != agentID || run.ParentRun == "" {
			continue
		}
		if run.Account != "" && run.Account != r.account {
			return nil, nil
		}
		return run, r.recover(run)
	}
	return nil, nil
}

// closeChild ends a sub-agent run (its last output, then run_end) and records the result in its parent.
func (r *recorder) closeChild(ctx context.Context, child *state.Run, lastMessage, disposition, detail string) error {
	if !child.Closed && child.Broken == "" {
		if lastMessage != "" {
			objs := []evidence.Object{evidence.NewObject("model-output", "text/markdown", []byte(lastMessage))}
			if err := r.seal(ctx, child, "model_output", nil, false, false, nil, objs); err != nil {
				return err
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
func (r *recorder) closeChildren(ctx context.Context, run *state.Run, detail string) {
	for i := range run.Delegations {
		d := run.Delegations[i]
		if !d.Committed(run) || d.Resolved(run) || d.ChildRun == "" {
			continue
		}
		child, err := r.store.LoadRun(run.SessionID, d.ChildRun)
		if err != nil || r.recover(child) != nil {
			continue // never started, or unknown: the delegation stays unresolved and the parent closes aborted
		}
		r.closeChildren(ctx, child, detail)
		if !child.Closed && child.Broken == "" {
			step := map[string]any{"finalSeq": child.NextSeq, "finalPrevSignatureSha256": child.PrevSig, "runDisposition": "aborted", "detail": detail}
			if err := r.seal(ctx, child, "run_end", step, false, true, nil, nil); err != nil {
				logf(r.store, "run %s: sub-agent run %s could not be closed: %v", run.Name, child.Name, err)
				continue
			}
		}
		if err := r.resolve(ctx, run, child); err != nil {
			logf(r.store, "run %s: result for %s not recorded: %v", run.Name, child.Name, err)
		}
	}
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
// run opened for that Agent call. A mismatch is a producer fidelity problem (§11), reported locally.
func (r *recorder) checkPairing(run *state.Run, in input) {
	var resp struct {
		AgentID string `json:"agentId"`
	}
	if json.Unmarshal(in.ToolResponse, &resp) != nil || resp.AgentID == "" {
		return
	}
	for _, d := range run.Delegations {
		if d.UseID == in.ToolUseID && d.ClaudeAgentID != "" && d.ClaudeAgentID != resp.AgentID {
			logf(r.store, "run %s: sub-agent pairing mismatch for %s (recorded %s, Claude Code reports %s)",
				run.Name, in.ToolUseID, d.ClaudeAgentID, resp.AgentID)
		}
	}
}
