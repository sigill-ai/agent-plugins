package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigill-ai/claude-plugins/internal/state"
)

// runHookWith feeds one event to runHook the way Claude Code does (stdin), with the given environment.
func runHookWith(t *testing.T, env map[string]string, e input) int {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	raw, _ := json.Marshal(e)
	r, w, _ := os.Pipe()
	w.Write(raw)
	w.Close()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	return runHook()
}

// R2-4: SessionEnd makes the close intent durable without any credential or network work, so a slow
// refresh or keychain can never lose it; the finalizer is spawned to do the rest.
func TestSessionEnd_RecordsCloseIntentWithoutCredentialWork(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "e0000000-0000-4000-8000-0000000000a1"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(10 * time.Second) }))
	defer slow.Close()
	spawned := ""
	spawn = func(s string) { spawned = s }
	defer func() { spawn = spawnFinalizer }()

	start := time.Now()
	code := runHookWith(t, map[string]string{"CLAUDE_PLUGIN_DATA": rec.cfg.DataDir, "SIGILL_API_URL": slow.URL, "SIGILL_API_KEY": "k"},
		input{SessionID: sid, HookEventName: "SessionEnd", Reason: "prompt_input_exit"})
	if code != 0 || time.Since(start) > 2*time.Second {
		t.Fatalf("SessionEnd took %s (exit %d): it must not wait for credentials or the network", time.Since(start), code)
	}
	run, _ := rec.store.Current(sid)
	req, ok := rec.store.CloseRequestFor(sid)
	if !ok || req.Reason != "prompt_input_exit" || req.Run != run.Name || spawned != sid {
		t.Fatalf("close intent %+v, finalizer %q", req, spawned)
	}
}

func failClosedEnv(rec *recorder, url string, extra map[string]string) map[string]string {
	env := map[string]string{"CLAUDE_PLUGIN_DATA": rec.cfg.DataDir, "SIGILL_API_URL": url, "SIGILL_API_KEY": "test-key",
		"SIGILL_FAIL_CLOSED": "1", "SIGILL_INDEX": "0"}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

// R2-5: a sub-agent at its event budget is closed, and its tool_call is NOT recorded: under fail-closed the
// consequential tool must be blocked, even though closing the child succeeded.
func TestFailClosed_ChildAtBudget_BlocksTheTool(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	_, rec.account, _ = newBackend(context.Background(), config{APIURL: srv.URL, APIKey: "test-key"}) // the account runHook resolves
	sid := "e0000000-0000-4000-8000-0000000000a2"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		agentCall(sid, "t1", "researcher", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "researcher"},
	} {
		mustHook(t, rec, e)
	}
	child := childRuns(t, rec, sid)[0]
	child.NextSeq = maxEvents - 1 // the next ordinary event would take run_end's slot
	if err := rec.store.Save(child); err != nil {
		t.Fatal(err)
	}
	code := runHookWith(t, failClosedEnv(rec, srv.URL, nil), input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash",
		ToolUseID: "t2", AgentID: "a1", AgentType: "researcher", ToolInput: json.RawMessage(`{"command":"rm -rf x"}`)})
	if code != 2 {
		t.Fatalf("exit %d: an unrecorded consequential tool must be blocked", code)
	}
	if c := childRuns(t, rec, sid)[0]; !c.Closed {
		t.Fatal("the child at its budget is closed")
	}
}

// R2-10: Agent listed as consequential gets the tool_call policy — and a delegation sealed without its
// required timestamp stops the run and blocks the call.
func TestFailClosed_ConsequentialAgentNeedsItsTimestamp(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "e0000000-0000-4000-8000-0000000000a3"
	env := failClosedEnv(rec, srv.URL, map[string]string{"SIGILL_CONSEQUENTIAL_TOOLS": "Agent,Task,Bash"})
	if code := runHookWith(t, env, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()}); code != 0 {
		t.Fatal(code)
	}
	if code := runHookWith(t, env, agentCall(sid, "t1", "researcher", "")); code != 0 {
		t.Fatalf("a stamped consequential delegation is allowed (exit %d)", code)
	}
	run, _ := rec.store.Current(sid)
	_, arts := events(t, rec, run)
	del := decode(t, arts[len(arts)-1])
	if del.Step["type"] != "delegation" || del.Step["consequential"] != true || del.Step["timestamp"] != "required" {
		t.Fatalf("delegation step %v", del.Step)
	}
	fake.mu.Lock()
	fake.noStamp = true
	fake.mu.Unlock()
	if code := runHookWith(t, env, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Task", ToolUseID: "t3",
		ToolInput: json.RawMessage(`{"subagent_type":"researcher"}`)}); code != 2 {
		t.Fatalf("exit %d: a consequential Task without its timestamp must be blocked", code)
	}
}

// R2-6: a process killed right after creating a run (no Control Artifact yet), or right after its Control
// Artifact (no run_start), must never get a tool_call sealed at seq 0: that run is stopped and the
// session continues in a fresh, properly started run.
func TestInterruptedInitialization_IsNeverContinued(t *testing.T) {
	for _, afterControl := range []bool{false, true} {
		fake := &fakeSigill{}
		srv := httptest.NewServer(http.HandlerFunc(fake.handler))
		rec := newRec(t, srv.URL, nil)
		sid := "e0000000-0000-4000-8000-0000000000a4"
		mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
		dead, _ := rec.store.Current(sid)
		// Roll the durable state back to the moment of death.
		os.Remove(filepath.Join(rec.cfg.DataDir, "sessions", state.SessionKey(sid), "runs", dead.Name, "0000-run_start.json"))
		dead.NextSeq, dead.PrevSig, dead.Pending = 0, "", nil
		if !afterControl {
			os.Remove(filepath.Join(rec.cfg.DataDir, "sessions", state.SessionKey(sid), "runs", dead.Name, "ctrl.json"))
			dead.ControlSig = ""
		}
		if err := rec.store.Save(dead); err != nil {
			t.Fatal(err)
		}
		mustHook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t1", ToolInput: json.RawMessage(`{}`)})
		old, _ := rec.store.LoadRun(sid, dead.Name)
		if old.Broken != initInterrupted || old.NextSeq != 0 {
			t.Fatalf("afterControl=%v: the interrupted run must be stopped untouched: %+v", afterControl, old)
		}
		cur, _ := rec.store.Current(sid)
		if cur.Name == dead.Name || strings.Join(steps(t, rec, cur), ",") != "run_start,tool_call" {
			t.Fatalf("afterControl=%v: the session continues in a fresh run: %v", afterControl, steps(t, rec, cur))
		}
		srv.Close()
	}
}

// R2-7: killed after the artifact was stored but before its delivery marker: recovery recreates the marker,
// so the event (here run_end) still reaches the index.
func TestRecovery_RecreatesTheDeliveryMarker(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, func(c *config) { c.Index = true })
	sid := "e0000000-0000-4000-8000-0000000000a5"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionEnd", Reason: "other"})
	finalizeNow(t, rec, sid)
	run, _ := rec.store.Current(sid)
	name := fmt.Sprintf("%04d-run_end", run.NextSeq-1)
	// Roll back to the crash: artifact on disk, no marker, chain head not advanced.
	rec.store.Delivered(run, name)
	p := state.Pending{Name: name, Seq: run.NextSeq - 1, Close: true, Queue: true, EnvelopeHash: envelopeHashOf(t, rec, run, name)}
	run.Pending, run.NextSeq, run.Closed = &p, run.NextSeq-1, false
	if err := rec.store.Save(run); err != nil {
		t.Fatal(err)
	}
	cur, _ := rec.store.Current(sid)
	if err := rec.recover(cur); err != nil {
		t.Fatal(err)
	}
	if !cur.Closed {
		t.Fatal("recovery commits the stored run_end")
	}
	found := false
	for _, n := range rec.store.PendingDelivery(cur) {
		found = found || n == name
	}
	if !found {
		t.Fatal("the delivery marker must be recreated")
	}
}

// R2-8: a sub-agent stopping on its last free slot closes within the bundle limit: run_end takes the slot,
// the output is left out.
func TestChildClosure_LastSlotStaysWithinTheLimit(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "e0000000-0000-4000-8000-0000000000a6"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		agentCall(sid, "t1", "researcher", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "researcher"},
	} {
		mustHook(t, rec, e)
	}
	child := childRuns(t, rec, sid)[0]
	child.NextSeq = maxEvents - 1
	rec.store.Save(child)
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SubagentStop", AgentID: "a1", LastAssistantMessage: "a long answer"})
	child = childRuns(t, rec, sid)[0]
	if !child.Closed || child.NextSeq != maxEvents {
		t.Fatalf("closed %v at %d events, want %d", child.Closed, child.NextSeq, maxEvents)
	}
	a, err := rec.store.LoadArtifact(child, fmt.Sprintf("%04d-run_end", maxEvents-1))
	if err != nil || decode(t, a).Step["runDisposition"] != "completed" {
		t.Fatal("run_end must take the last slot")
	}
}

// R2-8: a sub-agent that stops while its own sub-agent runs closes that one first (aborted, resolved);
// with a delegation that never started a sub-agent it closes aborted.
func TestChildClosure_ResolvesItsOwnSubAgentsFirst(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "e0000000-0000-4000-8000-0000000000a7"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		agentCall(sid, "t1", "planner", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "planner"},
		agentCall(sid, "t2", "researcher", "a1"),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a2", AgentType: "researcher"},
		agentCall(sid, "t3", "fetcher", "a1"), // never starts
		{SessionID: sid, HookEventName: "SubagentStop", AgentID: "a1", LastAssistantMessage: "done early"},
	} {
		mustHook(t, rec, e)
	}
	by := map[string]*state.Run{}
	for _, c := range childRuns(t, rec, sid) {
		by[c.ClaudeAgentID] = c
	}
	_, ra := events(t, rec, by["a2"])
	if decode(t, ra[len(ra)-1]).Step["runDisposition"] != "aborted" {
		t.Fatal("the running grandchild is closed aborted")
	}
	got := strings.Join(steps(t, rec, by["a1"]), ",")
	if got != "run_start,delegation,delegation,delegation_result,model_output,run_end" {
		t.Fatalf("planner: %s", got)
	}
	_, pa := events(t, rec, by["a1"])
	if decode(t, pa[len(pa)-1]).Step["runDisposition"] != "aborted" {
		t.Fatal("an unresolved delegation (fetcher never started) forces aborted")
	}
}

// Pairing: two pending delegations of the same type make SubagentStart ambiguous — nothing is bound, the
// sub-agent's events stay in the delegating chain, and the session closes aborted (unresolved delegations).
func TestPairing_AmbiguousIsNeverGuessed(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "e0000000-0000-4000-8000-0000000000a8"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		agentCall(sid, "t1", "researcher", ""),
		agentCall(sid, "t2", "researcher", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "researcher"},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t3", AgentID: "a1", AgentType: "researcher", ToolInput: json.RawMessage(`{}`)},
		{SessionID: sid, HookEventName: "SessionEnd", Reason: "other"},
	} {
		mustHook(t, rec, e)
	}
	finalizeNow(t, rec, sid)
	if n := len(childRuns(t, rec, sid)); n != 0 {
		t.Fatalf("%d sub-agent runs bound on an ambiguous start", n)
	}
	main, _ := rec.store.Current(sid)
	if got := strings.Join(steps(t, rec, main), ","); got != "run_start,delegation,delegation,tool_call,run_end" {
		t.Fatalf("main: %s", got)
	}
	_, arts := events(t, rec, main)
	if decode(t, arts[len(arts)-1]).Step["runDisposition"] != "aborted" {
		t.Fatal("unresolved delegations close the session aborted")
	}
}

// Pairing: Claude Code reporting another agentId for the bound call is recorded as a signed capture-fidelity
// checkpoint in the delegating run, and no later sub-agent of the session is bound.
func TestPairing_ContradictionIsRecordedAndStopsPairing(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "e0000000-0000-4000-8000-0000000000a9"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		agentCall(sid, "t1", "researcher", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "researcher"},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Agent", ToolUseID: "t1", ToolResponse: json.RawMessage(`{"agentId":"a9"}`)},
		agentCall(sid, "t2", "reviewer", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a2", AgentType: "reviewer"},
	} {
		mustHook(t, rec, e)
	}
	main, _ := rec.store.Current(sid)
	if !main.PairingStopped {
		t.Fatal("pairing stops after a contradiction")
	}
	_, arts := events(t, rec, main)
	var cp map[string]any
	for _, a := range arts {
		if e := decode(t, a); e.Step["type"] == "checkpoint" {
			cp = e.Step
		}
	}
	if cp == nil || !strings.HasPrefix(cp["detail"].(string), "capture-fidelity: delegation seq 1 ") {
		t.Fatalf("checkpoint %v", cp)
	}
	if n := len(childRuns(t, rec, sid)); n != 1 {
		t.Fatalf("%d sub-agent runs: the reviewer must not be bound after the contradiction", n)
	}
}
