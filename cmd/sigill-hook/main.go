// sigill-hook records a Claude Code session as an Agent Evidence Profiles v1
// run and seals every step with Sigill — blind: only digests leave the machine.
//
// Claude Code invokes it once per hook event with the event JSON on stdin
// (see hooks/hooks.json). Other modes:
//
//	sigill-hook export <session-id> [out.json] [--run <name>] [--tree]   the run (or its run tree) as a bundle
//	sigill-hook index <session-id> [--run <name>]               (re)upload envelopes to the index
//	sigill-hook finalize <session-id>                           seal a requested run_end (spawned by SessionEnd)
//	sigill-hook status                                          configuration and unfinished runs
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/sigill-ai/claude-plugins/internal/auth"
	"github.com/sigill-ai/claude-plugins/internal/evidence"
	"github.com/sigill-ai/claude-plugins/internal/sigill"
	"github.com/sigill-ai/claude-plugins/internal/state"
)

const (
	activityName = "agent-session" // fixed and neutral: Sigill must not learn what a session is about

	// maxEvents is the portable bundle limit (common rules §7). Ordinary events stop at
	// maxEvents-1 so run_end always fits as the last one.
	maxEvents = 2000
)

// Time budget. hooks.json gives each hook 60s; everything a hook does — waiting for
// the lock, starting a run, every HTTP call, index delivery — shares one deadline,
// and a reserve is kept to persist the outcome and return the intended exit code.
const (
	hookBudget   = 55 * time.Second
	persistSlack = 3 * time.Second
	drainBudget  = 12 * time.Second
	uploadLimit  = 8 * time.Second
)

type input struct {
	SessionID            string          `json:"session_id"`
	HookEventName        string          `json:"hook_event_name"`
	Cwd                  string          `json:"cwd"`
	Source               string          `json:"source"`
	Reason               string          `json:"reason"`
	Prompt               string          `json:"prompt"`
	ToolName             string          `json:"tool_name"`
	ToolInput            json.RawMessage `json:"tool_input"`
	ToolResponse         json.RawMessage `json:"tool_response"`
	ToolError            json.RawMessage `json:"tool_error"`
	Error                json.RawMessage `json:"error"`
	IsInterrupt          *bool           `json:"is_interrupt"`
	ToolUseID            string          `json:"tool_use_id"`
	AgentID              string          `json:"agent_id"`
	AgentType            string          `json:"agent_type"`
	LastAssistantMessage string          `json:"last_assistant_message"`
}

type config struct {
	APIURL        string
	APIKey        string
	CertificateID string
	AgentID       string
	DataDir       string
	FailClosed    bool
	Index         bool
	Qualified     bool // qualified (eIDAS) timestamps where a timestamp is taken; off by default
	Consequential map[string]bool
}

func loadConfig() config {
	data := os.Getenv("CLAUDE_PLUGIN_DATA")
	if data == "" {
		home, _ := os.UserHomeDir()
		data = host.DefaultDataDir(home)
	}
	c := config{
		APIURL:        envOr("SIGILL_API_URL", "https://api.sigill.ai"),
		APIKey:        os.Getenv("SIGILL_API_KEY"),
		CertificateID: os.Getenv("SIGILL_CERTIFICATE_ID"),
		AgentID:       envOr("SIGILL_AGENT_ID", host.DefaultAgentID),
		DataDir:       data,
		FailClosed:    os.Getenv("SIGILL_FAIL_CLOSED") == "1",
		Index:         os.Getenv("SIGILL_INDEX") != "0", // the producer decides; default: upload signed envelopes
		Qualified:     os.Getenv("SIGILL_QUALIFIED") == "1",
		Consequential: map[string]bool{},
	}
	// A config file fills what the environment leaves empty.
	if raw, err := os.ReadFile(filepath.Join(data, "config.json")); err == nil {
		var f struct {
			APIURL, APIKey, CertificateID, AgentID string
			Qualified                              bool
		}
		if json.Unmarshal(raw, &f) == nil {
			if os.Getenv("SIGILL_API_URL") == "" && f.APIURL != "" {
				c.APIURL = f.APIURL
			}
			if c.APIKey == "" {
				c.APIKey = f.APIKey
			}
			if c.CertificateID == "" {
				c.CertificateID = f.CertificateID
			}
			if os.Getenv("SIGILL_AGENT_ID") == "" && f.AgentID != "" {
				c.AgentID = f.AgentID
			}
			if os.Getenv("SIGILL_QUALIFIED") == "" && f.Qualified {
				c.Qualified = true
			}
		}
	}
	tools := envOr("SIGILL_CONSEQUENTIAL_TOOLS", host.DefaultConsequential)
	for _, t := range strings.Split(tools, ",") {
		if t = strings.TrimSpace(t); t != "" {
			c.Consequential[t] = true
		}
	}
	return c
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func (c config) isConsequential(tool string) bool {
	if c.Consequential[tool] {
		return true
	}
	for k := range c.Consequential {
		if strings.HasSuffix(k, "*") && strings.HasPrefix(tool, strings.TrimSuffix(k, "*")) {
			return true
		}
	}
	return false
}

func main() {
	auth.SetHost(host.DisplayName, host.ConnectCommand, host.ClientID)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "export":
			os.Exit(cmdExport(os.Args[2:]))
		case "status":
			os.Exit(cmdStatus())
		case "index":
			os.Exit(cmdIndex(os.Args[2:]))
		case "finalize":
			os.Exit(cmdFinalize(os.Args[2:]))
		case "connect":
			os.Exit(cmdConnect(os.Args[2:]))
		case "disconnect":
			os.Exit(cmdDisconnect())
		case "version":
			fmt.Println(sigill.Version)
			return
		}
	}
	os.Exit(runHook())
}

// runHook never breaks the user's session: problems are logged and the hook exits 0.
// The one exception is explicit enforcement (SIGILL_FAIL_CLOSED=1): a consequential
// tool is then blocked unless its tool_call was durably committed in this invocation —
// whatever the reason it was not (no credentials, broken run, lock or state failure).
func runHook() int {
	hookStart := time.Now()
	cfg := loadConfig()
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<20))
	var in input
	if err == nil {
		err = json.Unmarshal(raw, &in)
	}
	enforce := err == nil && cfg.FailClosed && in.HookEventName == "PreToolUse" && cfg.isConsequential(in.ToolName)
	blocked := func() int {
		if enforce {
			fmt.Fprintln(os.Stderr, "Sigill: this consequential action could not be sealed before running, so it was blocked (SIGILL_FAIL_CLOSED=1).")
			return 2
		}
		return 0
	}
	if err != nil || in.SessionID == "" {
		return blocked()
	}
	store := state.Store{Dir: cfg.DataDir}
	ctx, cancel := context.WithDeadline(context.Background(), hookStart.Add(hookBudget-persistSlack))
	defer cancel()
	if in.HookEventName == "SessionEnd" {
		// Claude Code keeps SessionEnd short: the close intent is made durable first, locally, with no
		// credential, keychain or network work; the detached finalizer resolves credentials and seals.
		if requestClose(ctx, store, in) {
			spawn(in.SessionID)
		}
		return 0
	}
	// Credentials are resolved BEFORE the session lock (lock order: credential, then session).
	be, account, err := newBackend(ctx, cfg)
	if err != nil {
		logf(store, "not recording (event %s): %v", in.HookEventName, err)
		if in.HookEventName == "SessionStart" {
			connectHint(store, err)
		}
		return blocked()
	}
	rec := &recorder{cfg: cfg, store: store, be: be, account: account}
	var run *state.Run
	err = store.WithLock(ctx, in.SessionID, func() error {
		var e error
		run, e = rec.handle(ctx, in)
		return e
	})
	if err != nil {
		logf(store, "session %s event %s: %v", state.SessionKey(in.SessionID), in.HookEventName, err)
	}
	if cfg.Index {
		if run != nil {
			rec.drainSession(ctx, run, drainBudget, in.HookEventName == "SessionStart")
		}
		if in.HookEventName == "SessionStart" {
			rec.sweep(ctx, in.SessionID)
		}
	}
	if enforce && !rec.toolCallCommitted {
		return blocked()
	}
	return 0
}

type recorder struct {
	cfg               config
	store             state.Store
	be                sigill.Backend
	account           string // who records: a run is only ever continued by the account that started it
	toolCallCommitted bool   // this invocation durably committed a tool_call
}

// handle maps one hook event to evidence and returns the run it touched.
func (r *recorder) handle(ctx context.Context, in input) (*state.Run, error) {
	run, err := r.store.Current(in.SessionID)
	if err != nil {
		return nil, err
	}
	if run != nil {
		if err := r.recover(run); err != nil {
			if run.Broken != initInterrupted {
				return run, err
			}
			logf(r.store, "run %s: %s; continuing in a new run", run.Name, initInterrupted)
		}
		if err := r.applyCloseRequest(run); err != nil {
			return run, err
		}
		if run.Account != "" && run.Account != r.account && !run.Closed && run.Broken == "" {
			// Another account or organisation is connected now: the run is left as it is,
			// never continued, finalized or delivered under the new identity.
			_ = r.breakRun(run, "the Sigill connection changed to another account or organisation; this run is not continued")
		}
		if run.Account != "" && run.Account != r.account {
			if in.HookEventName == "SessionEnd" {
				return nil, nil
			}
			run = nil // record from here on in a new run of the current account
		}
	}
	if run != nil && run.Broken == initInterrupted && in.HookEventName != "SessionEnd" {
		run = nil // the interrupted run is kept as it is; this session continues in a fresh run
	}
	if run != nil && (run.Closed || run.Broken != "" || run.CloseRequested != "") {
		if in.HookEventName != "SessionStart" {
			// Producer rule: a broken, closed or closing run is never continued.
			return run, nil
		}
		if run.CloseRequested != "" && !run.Closed && run.Broken == "" {
			// Resumed before the previous run_end was sealed: finish it first.
			if err := r.finalize(ctx, run); err != nil {
				return run, err
			}
		}
		run = nil // a resumed session starts a new run; the old one is kept as it is
	}
	if run == nil {
		if in.HookEventName == "SessionEnd" {
			return nil, nil
		}
		if run, err = r.startRun(ctx, in, ""); err != nil {
			return run, err
		}
		if in.HookEventName == "SessionStart" {
			return run, nil
		}
	} else if in.HookEventName == "SessionStart" {
		// A resumed session continues this run: a session end read before now belongs to an earlier
		// epoch and must never close it.
		run.Resumes++
		if err := r.store.Save(run); err != nil {
			return run, err
		}
	}

	// Agent Delegation v1: a sub-agent's hooks (they carry its agent_id) belong to its own run when one
	// was opened for it at SubagentStart. Without one (a run started by an older version, no room for a
	// delegation, or a missed SubagentStart) they are recorded in this run, tagged, as before.
	target := run
	ext := map[string]any{}
	if in.AgentID != "" && in.HookEventName != "SubagentStart" {
		child, err := r.childByAgent(run.SessionID, in.AgentID)
		if err != nil {
			return run, err
		}
		switch {
		case child != nil && (child.Closed || child.Broken != ""):
			logf(r.store, "run %s: sub-agent event %s after its run ended, not recorded", child.Name, in.HookEventName)
			return run, nil
		case child != nil:
			target = child
		default:
			ext[host.ExtKey] = map[string]any{"agentId": in.AgentID, "agentType": in.AgentType}
		}
	}

	switch in.HookEventName {
	case "SessionStart":
		return run, nil // resumed open run: the chain simply continues

	case "UserPromptSubmit":
		run.PendingInputs = append(run.PendingInputs, evidence.NewObject("model-input", "text/plain", []byte(in.Prompt)))
		return run, r.store.Save(run)

	case "PreToolUse":
		// toolCallCommitted is set by seal() only when THIS invocation durably commits the tool_call (or the
		// delegation for an Agent call): a nil error alone never authorizes a consequential tool.
		if isAgentTool(in.ToolName) && target.Version() == "2" && hasRoomToDelegate(target) {
			err = r.delegate(ctx, target, in, ext)
		} else {
			conseq := r.cfg.isConsequential(in.ToolName)
			step := map[string]any{"tool": toolBlock(in.ToolName, in.ToolUseID, true)}
			objs := []evidence.Object{evidence.NewObject("tool-arguments", "application/json", jsonOrEmpty(in.ToolInput))}
			err = r.record(ctx, &run, target, in, "tool_call", step, conseq, conseq && target.Policy.Consequential, ext, objs)
		}
		return run, err

	case "PostToolUse":
		if isAgentTool(in.ToolName) {
			if err := r.checkPairing(ctx, target, in); err != nil {
				return run, err
			}
		}
		step := map[string]any{"tool": toolBlock(in.ToolName, in.ToolUseID, false)}
		objs := []evidence.Object{evidence.NewObject("tool-result", "application/json", jsonOrEmpty(in.ToolResponse))}
		err = r.record(ctx, &run, target, in, "tool_result", step, false, false, ext, objs)
		return run, err

	case "PostToolUseFailure":
		step := map[string]any{"tool": toolBlock(in.ToolName, in.ToolUseID, false), "detail": "tool failed"}
		objs := []evidence.Object{evidence.NewObject("tool-result", "application/json", failureResult(in))}
		err = r.record(ctx, &run, target, in, "tool_result", step, false, false, ext, objs)
		return run, err

	case "SubagentStart":
		return run, r.startChild(ctx, run, in)

	case "SubagentStop":
		if target != run {
			return run, r.closeChild(ctx, target, in.LastAssistantMessage, "completed", "")
		}
		objs := []evidence.Object{evidence.NewObject("model-output", "text/markdown", []byte(in.LastAssistantMessage))}
		err = r.record(ctx, &run, run, in, "model_output", nil, false, false, ext, objs)
		return run, err

	case "Stop":
		objs := append(append([]evidence.Object{}, run.PendingInputs...), evidence.NewObject("model-output", "text/markdown", []byte(in.LastAssistantMessage)))
		run, err = r.event(ctx, run, in, "model_output", nil, false, false, ext, objs)
		if err == nil {
			run.PendingInputs = nil
			err = r.store.Save(run)
		}
		return run, err

	case "SessionEnd":
		// Record the request durably and fast; the finalizer seals run_end.
		reason := in.Reason
		if reason == "" {
			reason = "other"
		}
		run.CloseRequested = reason
		return run, r.store.Save(run)
	}
	return run, nil
}

// record seals an event in target; when target is the main run and the event limit opened a new
// segment, *main follows it.
func (r *recorder) record(ctx context.Context, main **state.Run, target *state.Run, in input, stepType string, step map[string]any,
	conseq, stamp bool, ext map[string]any, objs []evidence.Object) error {
	next, err := r.event(ctx, target, in, stepType, step, conseq, stamp, ext, objs)
	if target == *main && next != nil {
		*main = next
	}
	return err
}

// event seals an ordinary event. At the bundle limit the run is closed first and the
// event opens a new run (explicit segmentation, never a reused correlationId or seq).
func (r *recorder) event(ctx context.Context, run *state.Run, in input, stepType string, step map[string]any, conseq, stamp bool,
	ext map[string]any, objs []evidence.Object) (*state.Run, error) {
	// One slot per open delegation is reserved for its result, and one for run_end (delegation §4 rule 6).
	if run.NextSeq >= maxEvents-1-run.Outstanding() {
		if run.ParentRun != "" {
			// A sub-agent run cannot continue in a new segment (its parent declared one run): it ends here.
			logf(r.store, "run %s: event limit reached, the sub-agent's later events are not recorded", run.Name)
			return run, r.closeChild(ctx, run, "", "aborted", "event limit")
		}
		run.CloseRequested = "event limit"
		if err := r.finalize(ctx, run); err != nil {
			return run, err
		}
		next, err := r.startRun(ctx, in, run.CorrelationID)
		if err != nil {
			return next, err
		}
		run = next
	}
	return run, r.seal(ctx, run, stepType, step, conseq, stamp, ext, objs)
}

// finalize seals the requested run_end and closes the run.
func (r *recorder) finalize(ctx context.Context, run *state.Run) error {
	if run.Closed || run.Broken != "" {
		return nil
	}
	// Sub-agents still running end with the session, and their results go in first: a run closes
	// "completed" only when every delegation has its result (delegation §4 rule 5). If recording a result
	// failed, this run is stopped and nothing more — run_end included — is sealed on it.
	if err := r.closeChildren(ctx, run, "session ended"); err != nil {
		return err
	}
	disposition, detail := closureOf(run, "completed")
	if run.CloseRequested != "" {
		detail = joinDetail(detail, "session ended: "+run.CloseRequested)
	}
	step := map[string]any{"finalSeq": run.NextSeq, "finalPrevSignatureSha256": run.PrevSig, "runDisposition": disposition}
	if detail != "" {
		step["detail"] = detail
	}
	return r.seal(ctx, run, "run_end", step, false, true, nil, nil)
}

// startRun creates a new run directory, seals the Control Artifact (BEFORE) and run_start.
func (r *recorder) startRun(ctx context.Context, in input, segmentOf string) (*state.Run, error) {
	return r.newRun(ctx, in, segmentOf, nil, nil)
}

// newRun starts the session's main run, or — with parent and d — the sub-agent run d declared.
func (r *recorder) newRun(ctx context.Context, in input, segmentOf string, parent *state.Run, d *state.Delegation) (*state.Run, error) {
	now := time.Now()
	uuid := evidence.NewUUID()
	run := &state.Run{
		SessionID:     in.SessionID,
		Name:          now.UTC().Format("20060102T150405Z") + "-" + uuid[:8],
		CorrelationID: "urn:uuid:" + uuid,
		AgentID:       r.cfg.AgentID,
		AgentVersion:  hostVersion(ctx),
		Policy:        evidence.TimestampPolicy{Profile: "throughput", Consequential: true},
		URIs:          map[string]string{},
		StartedAt:     now,
		SegmentOf:     segmentOf,
		Account:       r.account,
		SchemaVersion: "2",
		Qualified:     r.cfg.Qualified,
	}
	if d != nil {
		// The child signs what its parent declared: correlationId and agent id (delegation §3.3).
		run.Name, run.CorrelationID, run.AgentID = d.ChildRun, d.ChildCorrelationID, d.ChildAgentID
		run.ParentCorrelationID, run.ParentDelegationSig, run.ParentRun = parent.CorrelationID, d.Sig, parent.Name
		run.ClaudeAgentID = in.AgentID
		run.CertificateID = parent.CertificateID
		run.Qualified = parent.Qualified
	}
	// One run, one signer: the certificate is fixed when the run starts — the
	// organisation's own (BYOC) when configured, else the Sigill Platform Seal.
	if run.CertificateID == "" {
		run.CertificateID = r.cfg.CertificateID
	}
	if run.CertificateID == "" {
		id, err := r.be.PlatformCertificate(ctx)
		if err != nil {
			return nil, err
		}
		run.CertificateID = id
	}
	newDir := r.store.NewRun
	if d != nil {
		newDir = r.store.NewChildRun
	}
	if err := newDir(run); err != nil {
		return nil, err
	}
	instructions := collect(in.Cwd, host.InstructionFiles, host.InstructionDefault)
	if d != nil {
		// A sub-agent's instruction set is its definition file (custom agents); built-in types have none.
		if def := host.AgentDefinition(d.SubagentType); def != "" {
			instructions = collect(in.Cwd, []string{def}, def)
		}
	}
	objs := []evidence.Object{
		evidence.NewObject("instruction-set", "text/markdown", instructions),
		evidence.NewObject("execution-policy", "application/json", collect(in.Cwd, host.SettingsFiles, host.SettingsDefault)),
		evidence.NewObject("control-set", "application/json", baselineControlSet(r.cfg)),
	}
	env := evidence.ControlArtifact(now, evidence.Actor{Type: "system", ID: host.RecorderID, Version: sigill.Version},
		activityName, run.CorrelationID, run.AgentID, run.AgentVersion, host.ControlSetID, "1", run.Policy, objs)
	if err := r.commitSealed(ctx, run, env, evidence.ControlArtifactContentType, objs, true, state.Pending{Name: "ctrl", Seq: -1}); err != nil {
		return run, err
	}
	if d != nil {
		return run, r.seal(ctx, run, "run_start", nil, false, false, nil, nil)
	}
	// session: a one-way reference to the Claude Code session, so a resumed session or one split at
	// the event limit is shown as one trace. It reveals nothing about the session or its user.
	src := map[string]any{"source": in.Source, "session": sessionRef(in.SessionID)}
	if segmentOf != "" {
		src["segmentOf"] = segmentOf
	}
	return run, r.seal(ctx, run, "run_start", nil, false, false, map[string]any{host.ExtKey: src}, nil)
}

// seal builds the next chain event and commits it.
func (r *recorder) seal(ctx context.Context, run *state.Run, stepType string, step map[string]any, conseq, stamp bool, ext map[string]any, objs []evidence.Object) error {
	var binds map[string]any
	if run.NextSeq == 0 {
		binds = map[string]any{"controlArtifactSignatureSha256": run.ControlSig} // run_start binds the control basis
		if run.ParentCorrelationID != "" {
			binds["parentDelegationSignatureSha256"] = run.ParentDelegationSig // … and a sub-agent's, its parent's delegation
			binds["parentCorrelationId"] = run.ParentCorrelationID
		}
	}
	env := evidence.Event(time.Now(), run.Version(), evidence.Actor{Type: "agent", ID: run.AgentID, Version: run.AgentVersion},
		activityName, run.CorrelationID, run.NextSeq, run.PrevSig, binds, stepType, step, conseq, stamp, ext, objs)
	p := state.Pending{Name: fmt.Sprintf("%04d-%s", run.NextSeq, stepType), Seq: run.NextSeq, Close: stepType == "run_end"}
	if err := r.commitSealed(ctx, run, env, evidence.ExecutionEvidenceContentType, objs, stamp, p); err != nil {
		return err
	}
	if stepType == "tool_call" || stepType == "delegation" {
		r.toolCallCommitted = true
	}
	return nil
}

// commitSealed is the crash-consistent commit protocol for one artifact:
//
//  1. persist Pending (what is about to be sealed) — before any network I/O;
//  2. request the seal; any failure, or a missing required timestamp, stops the run;
//  3. persist the artifact (and its outbox entry) atomically;
//  4. advance the chain head and clear Pending in one atomic state write.
//
// After a crash, recover() completes step 4 when step 3 is on disk and otherwise
// stops the run. A sequence number is never issued twice.
func (r *recorder) commitSealed(ctx context.Context, run *state.Run, env map[string]any, contentType string,
	objs []evidence.Object, stamp bool, p state.Pending) error {
	// The one place every seal passes: a stopped or closed run never seals again (common rules §6.3 —
	// a seq is never reused after a failed or ambiguous seal, and nothing follows run_end).
	if run.Broken != "" {
		return fmt.Errorf("run %s is stopped (%s): nothing more is sealed", run.Name, run.Broken)
	}
	if run.Closed {
		return fmt.Errorf("run %s is closed: nothing more is sealed", run.Name)
	}
	canonical, hash, err := evidence.EnvelopeHash(env)
	if err != nil {
		return r.breakRun(run, "envelope could not be canonicalized")
	}
	p.EnvelopeHash = hash
	p.Queue = r.cfg.Index
	run.Pending = &p
	if err := r.store.Save(run); err != nil {
		run.Pending = nil
		return err // nothing was requested; the run is unchanged on disk
	}
	res, err := r.sealWithRetry(ctx, hash, contentType, run.CertificateID, objs, stamp, run.Qualified)
	if err == nil && evidence.SignatureSha256(res.Signature) == "" {
		err = errors.New("seal response has no classical signature")
	}
	if err == nil && stamp {
		err = evidence.CheckSignatureTimestamp(res.Signature) // common rules §6.2
	}
	if err != nil {
		var quota *sigill.QuotaError
		if errors.As(err, &quota) {
			// Not a sealing failure: nothing was sealed, and the run ends here (a seq is never skipped).
			return r.breakRun(run, fmt.Sprintf("not recorded from %s on: %v", p.Name, err))
		}
		return r.breakRun(run, fmt.Sprintf("%s could not be sealed: %v", p.Name, err))
	}
	art := state.Artifact{Envelope: canonical, Signature: res.Signature, ObjectDigests: evidence.Digests(objs)}
	if err := r.store.SaveArtifact(run, p.Name, art, r.cfg.Index); err != nil {
		return r.breakRun(run, fmt.Sprintf("%s was sealed but could not be stored: %v", p.Name, err))
	}
	return r.advance(run, p, evidence.SignatureSha256(res.Signature))
}

// sealWithRetry retries only a request refused BEFORE processing (throttling), as the same
// pending event, within the hook deadline. Anything else — including an ambiguous timeout —
// is returned and stops the run (common rules §6.3: never skip an event and continue).
func (r *recorder) sealWithRetry(ctx context.Context, hash, contentType, cert string, objs []evidence.Object, stamp, qualified bool) (*sigill.SealResult, error) {
	for {
		res, err := r.be.SignHashes(ctx, hash, contentType, cert, objs, stamp, qualified)
		var re *sigill.RetryableError
		if !errors.As(err, &re) {
			return res, err
		}
		wait := re.After + time.Duration(rand.IntN(500))*time.Millisecond
		if time.Until(deadlineOf(ctx)) < wait+2*time.Second {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(wait):
		}
	}
}

// advance moves the chain head past a stored artifact (step 4).
func (r *recorder) advance(run *state.Run, p state.Pending, sig string) error {
	if p.Seq < 0 {
		run.ControlSig = sig
	} else {
		run.PrevSig = sig
		run.NextSeq = p.Seq + 1
	}
	if p.Close {
		run.Closed = true
	}
	run.Pending = nil
	return r.store.Save(run)
}

// recover completes or stops an interrupted commit (see commitSealed).
func (r *recorder) recover(run *state.Run) error {
	p := run.Pending
	if run.Broken != "" {
		return nil
	}
	if p == nil {
		if run.NextSeq == 0 && !run.Closed {
			// Started but never reached run_start (the process died after creating the run or after its
			// Control Artifact): nothing may be sealed on this chain, least of all a tool_call at seq 0.
			return r.breakRun(run, initInterrupted)
		}
		return r.reconcile(run)
	}
	if a, err := r.store.LoadArtifact(run, p.Name); err == nil {
		if _, h, herr := evidence.EnvelopeHash(json.RawMessage(a.Envelope)); herr == nil && h == p.EnvelopeHash {
			if sig := evidence.SignatureSha256(a.Signature); sig != "" {
				if p.Queue { // the delivery marker may not have been written before the crash
					if err := r.store.Enqueue(run, p.Name); err != nil {
						return err
					}
				}
				if err := r.advance(run, *p, sig); err != nil {
					return err
				}
				if run.NextSeq == 0 && !run.Closed {
					// The recovered artifact was the Control Artifact, but run_start never followed: the same
					// interrupted initialization as above, reached through a pending commit.
					return r.breakRun(run, initInterrupted)
				}
				return r.reconcile(run)
			}
		}
	}
	return r.breakRun(run, fmt.Sprintf("interrupted while sealing %s; the outcome is unknown, so the run is not continued", p.Name))
}

// initInterrupted marks a run whose start was interrupted before run_start was sealed.
const initInterrupted = "interrupted while starting: run_start was never sealed"

func (r *recorder) breakRun(run *state.Run, reason string) error {
	run.Broken = reason
	run.Pending = nil
	if err := r.store.Save(run); err != nil {
		return fmt.Errorf("%s (and the run state could not be saved: %v)", reason, err)
	}
	return errors.New(reason)
}

// Index delivery is batched (DESIGN-4): a batch is at most indexBatchItems artifacts and
// indexBatchBytes serialized, under the MCP request limit; a drain only runs when enough
// is queued, the oldest entry has waited long enough, or a flush is forced (session start,
// finalize).
const (
	indexBatchItems = 50
	indexBatchBytes = 192 << 10
	flushItems      = 20
	flushAge        = 60 * time.Second
)

// drain delivers the run's queued artifacts to the index within budget. Failures never
// affect the session: retryable ones stay queued, permanent rejections are logged and dropped.
func (r *recorder) drain(ctx context.Context, run *state.Run, budget time.Duration, force bool) {
	if run.Account != "" && run.Account != r.account {
		return // never deliver one account's run under another
	}
	pending := r.store.PendingDelivery(run)
	if len(pending) == 0 || (!force && !run.Closed && len(pending) < flushItems && r.store.OldestPendingAge(run) < flushAge) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for len(pending) > 0 {
		left := time.Until(deadlineOf(ctx))
		if left < time.Second {
			return
		}
		batch, size := []sigill.IndexItem{}, 0
		for len(pending) > 0 && len(batch) < indexBatchItems {
			a, err := r.store.LoadArtifact(run, pending[0])
			if err != nil {
				r.store.Delivered(run, pending[0]) // nothing to deliver
				pending = pending[1:]
				continue
			}
			item := sigill.IndexItem{Key: pending[0], Envelope: a.Envelope, Signature: a.Signature, ObjectDigests: a.ObjectDigests}
			n := len(a.Envelope) + len(a.Signature) + 256
			if len(batch) > 0 && size+n > indexBatchBytes {
				break
			}
			batch, size = append(batch, item), size+n
			pending = pending[1:]
		}
		if len(batch) == 0 {
			return
		}
		uctx, ucancel := context.WithTimeout(ctx, min(left, 2*uploadLimit))
		outcomes, err := r.be.IndexBatch(uctx, batch)
		ucancel()
		if err != nil {
			logf(r.store, "run %s: index unavailable, %d queued for retry", run.Name, len(batch)+len(pending))
			return
		}
		retry := false
		for _, o := range outcomes {
			switch o.Status {
			case "indexed", "exists":
				r.store.Delivered(run, o.Key)
			case "rejected":
				logf(r.store, "run %s %s: index rejected (%s), not retried", run.Name, o.Key, o.Code)
				r.store.Delivered(run, o.Key)
			default:
				retry = true
			}
		}
		if retry || len(outcomes) < len(batch) {
			return // try again on a later hook
		}
	}
}

// drainSession delivers the queued artifacts of every run of the session — the main run and its
// sub-agent runs — within one budget.
func (r *recorder) drainSession(ctx context.Context, main *state.Run, budget time.Duration, force bool) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for _, name := range r.store.Runs(main.SessionID) {
		left := time.Until(deadlineOf(ctx))
		if left < time.Second {
			return
		}
		run := main
		if name != main.Name {
			loaded, err := r.store.LoadRun(main.SessionID, name)
			if err != nil || len(r.store.PendingDelivery(loaded)) == 0 {
				continue
			}
			run = loaded
		}
		r.drain(ctx, run, left, force)
	}
}

// sweep finishes other sessions' runs whose finalizer did not complete (the process
// was killed, the machine slept): at most one per hook, only with time to spare.
func (r *recorder) sweep(ctx context.Context, self string) {
	for _, key := range r.store.SessionKeys() {
		if time.Until(deadlineOf(ctx)) < 20*time.Second || key == state.SessionKey(self) {
			continue
		}
		run, err := r.store.CurrentForKey(key)
		if err != nil || run == nil {
			continue
		}
		ours := func(x *state.Run) bool { return x.Account == "" || x.Account == r.account }
		due := !run.Closed && run.Broken == "" && run.CloseRequested != "" && ours(run)
		for _, name := range r.store.PendingCloseRunsForKey(key) {
			// Requests for another account's runs stay for that account and never make a session a candidate.
			if x, err := r.store.LoadRun(run.SessionID, name); err != nil || ours(x) {
				due = true
			}
		}
		if !due {
			continue
		}
		_ = r.store.WithLock(ctx, run.SessionID, func() error {
			_, err := r.finishSession(ctx, run.SessionID)
			return err
		})
		return
	}
}

func deadlineOf(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(hookBudget)
}

// requestClose records that the session ended on its current run and reports whether a finalizer must run.
//
// It never waits for the session lock: a hook that is sealing holds that lock for up to the full hook
// budget, longer than Claude Code lets SessionEnd live. The request is a separate, atomically written file
// bound to the run that was current; the finalizer, a sweep or the next hook applies it under the lock.
func requestClose(ctx context.Context, store state.Store, in input) bool {
	run, err := store.Current(in.SessionID) // read-only: state files are replaced atomically
	if err != nil || run == nil || run.Closed || run.Broken != "" {
		if err != nil {
			logf(store, "session %s event SessionEnd: %v", state.SessionKey(in.SessionID), err)
		}
		return false
	}
	reason := in.Reason
	if reason == "" {
		reason = "other"
	}
	if err := store.RequestClose(in.SessionID, run.Name, run.Resumes, reason); err != nil {
		logf(store, "session %s event SessionEnd: %v", state.SessionKey(in.SessionID), err)
		return false
	}
	return true
}

// applyCloseRequest turns this run's lock-free close requests into its CloseRequested, under the session
// lock. Only requests naming this run and its current resume epoch apply; requests for other runs are left
// for those runs. The run state is saved before the requests are removed, so a crash in between only
// applies them twice, and only the requests read here are removed.
func (r *recorder) applyCloseRequest(run *state.Run) error {
	reqs := r.store.CloseRequestsFor(run.SessionID, run.Name)
	if len(reqs) == 0 {
		return nil
	}
	if !run.Closed && run.Broken == "" && run.CloseRequested == "" {
		for _, q := range reqs {
			if q.Resumes == run.Resumes {
				run.CloseRequested = q.Reason
				break
			}
		}
		if run.CloseRequested != "" {
			if err := r.store.Save(run); err != nil {
				return err
			}
		}
	}
	for _, q := range reqs {
		r.store.ClearCloseRequest(q)
	}
	return nil
}

// finishSession, under the session lock, applies every pending close request of the session to the run
// it names (current or not) and seals run_end where one is due. It returns the current run.
func (r *recorder) finishSession(ctx context.Context, session string) (*state.Run, error) {
	cur, err := r.store.Current(session)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, name := range r.store.PendingCloseRuns(session) {
		if cur != nil && name == cur.Name {
			continue
		}
		run, err := r.store.LoadRun(session, name)
		if errors.Is(err, fs.ErrNotExist) {
			logf(r.store, "session %s: close request for unknown run %s dropped", state.SessionKey(session), name)
			for _, q := range r.store.CloseRequestsFor(session, name) {
				r.store.ClearCloseRequest(q)
			}
			continue
		}
		if err != nil {
			errs = append(errs, err) // the request stays for a later attempt
			continue
		}
		errs = append(errs, r.finishRun(ctx, run))
	}
	if cur != nil {
		errs = append(errs, r.finishRun(ctx, cur))
	}
	return cur, errors.Join(errs...)
}

func (r *recorder) finishRun(ctx context.Context, run *state.Run) error {
	if run.Account != "" && run.Account != r.account {
		return nil // never finalized under another identity; its requests stay
	}
	if err := r.recover(run); err != nil {
		return err
	}
	if err := r.applyCloseRequest(run); err != nil {
		return err
	}
	if run.CloseRequested == "" || run.Closed || run.Broken != "" {
		return nil
	}
	return r.finalize(ctx, run)
}

// spawn starts the detached finalizer (a variable so tests can observe it).
var spawn = spawnFinalizer

// spawnFinalizer starts `sigill-hook finalize` in its own session so it outlives the
// SessionEnd hook, whose time budget Claude Code keeps short.
func spawnFinalizer(session string) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "finalize", session)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if cmd.Start() == nil {
		_ = cmd.Process.Release()
	}
}

func cmdFinalize(args []string) int {
	if len(args) < 1 {
		return 2
	}
	cfg := loadConfig()
	store := state.Store{Dir: cfg.DataDir}
	ctx, cancel := context.WithTimeout(context.Background(), hookBudget)
	defer cancel()
	be, account, err := newBackend(ctx, cfg)
	if err != nil {
		logf(store, "finalize %s: %v", state.SessionKey(args[0]), err)
		return 0 // the next session start finishes it once connected
	}
	rec := &recorder{cfg: cfg, store: store, be: be, account: account}
	var run *state.Run
	err = store.WithLock(ctx, args[0], func() error {
		cur, err := rec.finishSession(ctx, args[0])
		if cur != nil && (cur.Account == "" || cur.Account == account) {
			run = cur
		}
		return err
	})
	if err != nil {
		logf(store, "finalize %s: %v", state.SessionKey(args[0]), err)
	}
	if cfg.Index && run != nil {
		rec.drainSession(ctx, run, 20*time.Second, true)
	}
	return 0
}

func toolBlock(name, useID string, withOperation bool) map[string]any {
	b := map[string]any{"name": name}
	if withOperation {
		if op := operation(name); op != "" {
			b["operation"] = op
		}
	}
	if useID != "" {
		b["useId"] = useID
	}
	return b
}

func operation(tool string) string {
	switch tool {
	case "Read", "Grep", "Glob", "LS", "WebSearch", "WebFetch":
		return "read"
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		return "write"
	case "Bash":
		return "execute"
	case "apply_patch":
		return "write"
	}
	if host.IsDelegationTool(tool) {
		return "delegate"
	}
	return ""
}

func jsonOrEmpty(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("null")
	}
	return raw
}

// failureResult is the local representation of a failed tool call that its digest pins:
// the hook's failure fields, never sent anywhere (only their digest is).
func failureResult(in input) []byte {
	out, _ := json.Marshal(map[string]any{
		"tool_response": in.ToolResponse,
		"tool_error":    in.ToolError,
		"error":         in.Error,
		"is_interrupt":  in.IsInterrupt,
	})
	return out
}

// Configuration collection bounds: the control basis pins the configuration files that
// applied, read as regular files only, within these sizes. Content stays local.
const (
	maxConfigFile  = 256 << 10
	maxConfigTotal = 1 << 20
)

// collect concatenates the configuration files that applied, one header per file, so
// their digest pins the exact configuration. A file that exists but cannot be pinned
// (not a regular file, too large, unreadable) is recorded as such — never silently skipped.
func collect(cwd string, rel []string, homeRel string) []byte {
	var b strings.Builder
	paths := []string{}
	for _, p := range rel {
		paths = append(paths, filepath.Join(cwd, p))
	}
	if h, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(h, homeRel))
	}
	total := 0
	for _, p := range paths {
		data, err := readConfigFile(p, min(maxConfigFile, maxConfigTotal-total))
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			fmt.Fprintf(&b, "=== %s NOT PINNED: %v\n", p, err)
		default:
			total += len(data)
			fmt.Fprintf(&b, "=== %s (%d bytes)\n", p, len(data))
			b.Write(data)
			b.WriteString("\n")
		}
	}
	return []byte(b.String())
}

// readConfigFile follows a symlink to its target but reads only a regular file, never
// blocking on a FIFO or device, and at most max bytes.
func readConfigFile(p string, max int) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if fi.Size() > int64(max) {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return data, nil
}

func baselineControlSet(cfg config) []byte {
	tools := []string{}
	for t := range cfg.Consequential {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	out, _ := json.Marshal(map[string]any{
		"id": host.ControlSetID, "version": "1",
		"description":        "Recorder baseline: every tool call and result is sealed in capture order; consequential tools are timestamped before they run.",
		"consequentialTools": tools,
	})
	return out
}

func hostVersion(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, host.VersionCommand[0], host.VersionCommand[1:]...).Output()
	if err != nil {
		return "unknown"
	}
	v := strings.TrimSpace(string(out))
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(v, host.VersionTrim), host.VersionTrim))
}

// logf writes a diagnostic line. Lines carry ids, step names and status codes only —
// never content, envelopes, response bodies or credentials.
func logf(store state.Store, format string, args ...any) {
	store.AppendLog(time.Now().UTC().Format(time.RFC3339) + " " + fmt.Sprintf(format, args...))
}

// selectRun resolves [--run <name>] (default: the session's current run).
func selectRun(store state.Store, session string, args []string) (*state.Run, []string, error) {
	rest := []string{}
	name := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--run" && i+1 < len(args) {
			name = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	if name == "" {
		run, err := store.Current(session)
		if run == nil && err == nil {
			err = errors.New("no recorded run for that session")
		}
		return run, rest, err
	}
	run, err := store.LoadRun(session, name)
	return run, rest, err
}

// cmdExport writes one run as an AgentRunBundle (common rules §7).
func cmdExport(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: sigill-hook export <session-id> [out.json] [--run <name>] [--tree]")
		return 2
	}
	cfg := loadConfig()
	store := state.Store{Dir: cfg.DataDir}
	run, rest, err := selectRun(store, args[0], args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "runs of this session:", strings.Join(store.Runs(args[0]), ", "))
		return 1
	}
	tree := false
	files := rest[:0]
	for _, a := range rest {
		if a == "--tree" {
			tree = true
		} else {
			files = append(files, a)
		}
	}
	rest = files
	var bundle any = runBundle(store, run)
	if tree {
		// The run and every sub-agent run below it (Agent Delegation v1 §6.1).
		runs := []any{}
		var walk func(r *state.Run)
		walk = func(r *state.Run) {
			runs = append(runs, runBundle(store, r))
			for _, d := range r.Delegations {
				if d.ChildRun == "" {
					continue
				}
				if child, err := store.LoadRun(r.SessionID, d.ChildRun); err == nil {
					walk(child)
				}
			}
		}
		walk(run)
		bundle = map[string]any{"format": "AgentRunTreeBundle", "bundleVersion": "1", "rootCorrelationId": run.CorrelationID, "runs": runs}
	}
	out, _ := json.MarshalIndent(bundle, "", "  ")
	if len(rest) > 0 {
		if err := os.WriteFile(rest[0], out, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	os.Stdout.Write(out)
	return 0
}

// runBundle is one run as an AgentRunBundle (common rules §7), digests only.
func runBundle(store state.Store, run *state.Run) map[string]any {
	var control *state.Artifact
	events := []state.Artifact{}
	for _, n := range store.ArtifactNames(run) {
		a, err := store.LoadArtifact(run, n)
		if err != nil {
			continue
		}
		if n == "ctrl" {
			control = &a
		} else {
			events = append(events, a)
		}
	}
	return map[string]any{"format": "AgentRunBundle", "bundleVersion": "1", "correlationId": run.CorrelationID, "controlArtifact": control, "artifacts": events}
}

func cmdStatus() int {
	cfg := loadConfig()
	fmt.Printf("sigill-hook %s\napi: %s\n", sigill.Version, cfg.APIURL)
	if cfg.APIKey != "" {
		fmt.Println("auth: API key (SIGILL_API_KEY) — Sigill sign-in is not used while a key is set")
	} else {
		m := auth.New(cfg.DataDir)
		cred, _ := m.Current()
		switch {
		case cred == nil:
			fmt.Println("auth: not connected — run " + auth.ConnectCommand)
		case cred.Uncertain != "":
			fmt.Printf("auth: Sigill sign-in, needs renewal (%s) — run %s\n", cred.Uncertain, auth.ConnectCommand)
		default:
			fmt.Printf("auth: Sigill sign-in, organisation %s, connected %s, stored in %s\n",
				cred.TenantID, cred.ConnectedAt.Format("2006-01-02"), m.Store.Name())
		}
	}
	fmt.Printf("certificate: %s\nagent: %s\ndata: %s\nfail-closed: %v\nindex upload: %v\nqualified timestamps: %v\n",
		certText(cfg.CertificateID), cfg.AgentID, cfg.DataDir, cfg.FailClosed, cfg.Index, cfg.Qualified)
	store := state.Store{Dir: cfg.DataDir}
	for _, key := range store.SessionKeys() {
		for _, name := range store.PendingCloseRunsForKey(key) {
			fmt.Printf("run %s: session ended, run_end not sealed yet (the finalizer or next session start finishes it)\n", name)
		}
		for _, run := range store.RunsForKey(key) {
			switch {
			case run.Broken != "":
				fmt.Printf("run %s: stopped — %s\n", run.Name, run.Broken)
			case run.CloseRequested != "" && !run.Closed:
				fmt.Printf("run %s: session ended, run_end not sealed yet (next session start finishes it)\n", run.Name)
			}
			if run.FidelityIssue != "" {
				fmt.Printf("run %s: %s — it closes aborted\n", run.Name, run.FidelityIssue)
			}
			if n := len(store.PendingDelivery(run)); n > 0 {
				fmt.Printf("run %s: %d artifacts waiting for index delivery\n", run.Name, n)
			}
		}
	}
	return 0
}

func certText(id string) string {
	if id == "" {
		return "Sigill Platform Seal (SIGILL_CERTIFICATE_ID selects your organisation's own certificate)"
	}
	return id + " (your certificate)"
}

// cmdIndex (re)uploads every sealed artifact of one run to the evidence index.
// Safe to repeat: the platform answers an already indexed seal with 200.
func cmdIndex(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: sigill-hook index <session-id> [--run <name>]")
		return 2
	}
	cfg := loadConfig()
	store := state.Store{Dir: cfg.DataDir}
	run, _, err := selectRun(store, args[0], args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	be, account, err := newBackend(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if run.Account != "" && run.Account != account {
		fmt.Fprintln(os.Stderr, "this run was recorded under another account or organisation; connect that account to upload it")
		return 1
	}
	failed := 0
	for _, n := range store.ArtifactNames(run) {
		a, err := store.LoadArtifact(run, n)
		if err != nil {
			continue
		}
		out, err := be.IndexBatch(ctx, []sigill.IndexItem{{Key: n, Envelope: a.Envelope, Signature: a.Signature, ObjectDigests: a.ObjectDigests}})
		if err != nil || len(out) != 1 || (out[0].Status != "indexed" && out[0].Status != "exists") {
			failed++
			fmt.Fprintf(os.Stderr, "%s: not indexed\n", n)
			continue
		}
		store.Delivered(run, n)
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// newBackend picks the transport. The mode is explicit and never falls back: an API key in
// SIGILL_API_KEY selects REST (headless CI); otherwise Sigill sign-in (OAuth) over MCP. An
// expired or revoked sign-in never silently switches to a key, and vice versa.
func newBackend(ctx context.Context, cfg config) (sigill.Backend, string, error) {
	if cfg.APIKey != "" {
		sum := sha256.Sum256([]byte(cfg.APIKey))
		return sigill.New(cfg.APIURL, cfg.APIKey), "apikey|" + strings.TrimRight(cfg.APIURL, "/") + "|" + hex.EncodeToString(sum[:8]), nil
	}
	m := auth.New(cfg.DataDir)
	token, cred, err := m.AccessToken(ctx, cfg.APIURL)
	if err != nil {
		return nil, "", err
	}
	return sigill.NewMCP(cred.Issuer, token), cred.Account(), nil
}

// connectHint tells the user, at most once a day, why nothing is being recorded. Printed
// as the SessionStart hook's systemMessage.
func connectHint(store state.Store, err error) {
	if !store.Once("connect-hint", 24*time.Hour) {
		return
	}
	msg := "Sigill: this session is not being recorded — run " + auth.ConnectCommand + " to sign in."
	if !errors.Is(err, auth.ErrNotConnected) {
		msg = "Sigill: this session is not being recorded — " + err.Error()
	}
	out, _ := json.Marshal(map[string]string{"systemMessage": msg})
	fmt.Println(string(out))
}

func cmdConnect(args []string) int {
	cfg := loadConfig()
	if cfg.APIKey != "" {
		fmt.Fprintln(os.Stderr, "SIGILL_API_KEY is set, so the plugin uses the API key. Unset it to use Sigill sign-in.")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	m := auth.New(cfg.DataDir)
	cred, err := m.Connect(ctx, auth.ConnectOptions{
		Issuer: cfg.APIURL, ClientID: os.Getenv("SIGILL_OAUTH_CLIENT_ID"), UseDCR: os.Getenv("SIGILL_OAUTH_DCR") == "1",
		OpenBrowser: auth.OpenBrowser, Out: os.Stdout,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Not connected:", err)
		return 1
	}
	fmt.Printf("Connected to Sigill (organisation %s). Sessions are recorded from the next session start.\n", cred.TenantID)
	return 0
}

func cmdDisconnect() int {
	cfg := loadConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := auth.New(cfg.DataDir).Disconnect(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("Disconnected from Sigill.")
	return 0
}

// sessionRef is the producer-stated session reference: SHA-256 over a fixed label and the
// Claude Code session id, first 128 bits as hex.
func sessionRef(sessionID string) string {
	sum := sha256.Sum256([]byte("sigill-claude-code-session:" + sessionID))
	return hex.EncodeToString(sum[:16])
}
