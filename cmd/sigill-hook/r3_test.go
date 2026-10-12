package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sigill-ai/agent-plugins/internal/evidence"
	"github.com/sigill-ai/agent-plugins/internal/state"
)

// TestMain lets a test re-run this binary as a real hook process (SIGILL_HOOK_CHILD=1), so host
// termination can be exercised on an actual process.
func TestMain(m *testing.M) {
	if os.Getenv("SIGILL_HOOK_CHILD") == "1" {
		spawn = func(string) {} // never start a finalizer from a test child
		os.Exit(runHook())
	}
	os.Exit(m.Run())
}

func (f *fakeSigill) failNext(offset int, mode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failAt = map[int]string{len(f.requests) + offset: mode}
}

func (f *fakeSigill) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func hasStep(t *testing.T, rec *recorder, run *state.Run, stepType string) bool {
	t.Helper()
	for _, s := range steps(t, rec, run) {
		if s == stepType {
			return true
		}
	}
	return false
}

// finalizeLocked does what the finalizer does, returning its error instead of failing the test.
func finalizeLocked(t *testing.T, rec *recorder, sid string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return rec.store.WithLock(ctx, sid, func() error {
		cur, err := rec.store.Current(sid)
		if err != nil || cur == nil {
			return err
		}
		if err := rec.recover(cur); err != nil {
			return err
		}
		if err := rec.applyCloseRequest(cur); err != nil {
			return err
		}
		if cur.CloseRequested == "" {
			cur.CloseRequested = "other"
		}
		return rec.finalize(ctx, cur)
	})
}

// R3-1: when the parent's delegation_result cannot be sealed (refused, or an ambiguous answer), the parent
// is stopped: no later hook, SessionEnd or finalizer seals anything more on it — no run_end either.
func TestFailedResult_StopsTheParent_NothingMoreIsSealed(t *testing.T) {
	for _, mode := range []string{"503", "nosig"} {
		t.Run(mode, func(t *testing.T) {
			fake := &fakeSigill{}
			srv := httptest.NewServer(http.HandlerFunc(fake.handler))
			defer srv.Close()
			rec := newRec(t, srv.URL, nil)
			sid := "f1000000-0000-4000-8000-00000000000" + map[string]string{"503": "1", "nosig": "2"}[mode]
			mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
			mustHook(t, rec, agentCall(sid, "t1", "researcher", ""))
			mustHook(t, rec, input{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "researcher"})
			// SubagentStop seals the child's model_output, its run_end, then the parent's delegation_result.
			fake.failNext(3, mode)
			if _, err := hook(t, rec, input{SessionID: sid, HookEventName: "SubagentStop", AgentID: "a1", LastAssistantMessage: "x"}); err == nil {
				t.Fatal("the failed result must surface")
			}
			after := fake.count()
			mustHook(t, rec, input{SessionID: sid, HookEventName: "Stop", LastAssistantMessage: "y"})
			requestClose(context.Background(), rec.store, input{SessionID: sid, HookEventName: "SessionEnd"}) // a stopped run needs none
			_ = finalizeLocked(t, rec, sid)
			if fake.count() != after {
				t.Fatalf("%d seal requests after the parent stopped", fake.count()-after)
			}
			main, _ := rec.store.Current(sid)
			if main.Broken == "" || hasStep(t, rec, main, "run_end") || hasStep(t, rec, main, "delegation_result") {
				t.Fatalf("parent broken=%q steps=%v", main.Broken, steps(t, rec, main))
			}
		})
	}
}

// R3-1, nested: finalize closes a running child and then fails to seal the parent's result for it.
func TestFailedResultDuringFinalize_StopsTheParent(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "f1000000-0000-4000-8000-000000000003"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
	mustHook(t, rec, agentCall(sid, "t1", "planner", ""))
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "planner"})
	mustHook(t, rec, agentCall(sid, "t2", "researcher", "a1"))
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a2", AgentType: "researcher"})
	// finalize: grandchild run_end (1), planner's result (2), planner run_end (3), main's result (4) → refused.
	fake.failNext(4, "503")
	if err := finalizeLocked(t, rec, sid); err == nil {
		t.Fatal("finalize must report the failed result")
	}
	after := fake.count()
	_ = finalizeLocked(t, rec, sid) // a second attempt must not seal either
	if fake.count() != after {
		t.Fatal("nothing may be sealed on a stopped parent")
	}
	main, _ := rec.store.Current(sid)
	if main.Broken == "" || hasStep(t, rec, main, "run_end") {
		t.Fatalf("main broken=%q steps=%v", main.Broken, steps(t, rec, main))
	}
	// The sub-agent runs below it did close (their own chains were sound).
	for _, c := range childRuns(t, rec, sid) {
		if !c.Closed {
			t.Fatalf("sub-agent run %s should be closed", c.Name)
		}
	}
}

// R3-1, the other direction: a grandchild result failing stops only that sub-agent; the main run
// closes aborted (its delegation stays unresolved) and nothing more is sealed on the stopped child.
func TestFailedGrandchildResult_StopsOnlyThatChild(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "f1000000-0000-4000-8000-000000000004"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
	mustHook(t, rec, agentCall(sid, "t1", "planner", ""))
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "planner"})
	mustHook(t, rec, agentCall(sid, "t2", "researcher", "a1"))
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a2", AgentType: "researcher"})
	fake.failNext(2, "503") // grandchild run_end (1), planner's result (2) → refused
	if err := finalizeLocked(t, rec, sid); err != nil {
		t.Fatal(err)
	}
	main, _ := rec.store.Current(sid)
	_, arts := events(t, rec, main)
	end := decode(t, arts[len(arts)-1])
	if end.Step["type"] != "run_end" || end.Step["runDisposition"] != "aborted" {
		t.Fatalf("main closes aborted: %v", end.Step)
	}
	for _, c := range childRuns(t, rec, sid) {
		if c.ClaudeAgentID == "a1" && (c.Broken == "" || hasStep(t, rec, c, "run_end")) {
			t.Fatalf("planner broken=%q steps=%v", c.Broken, steps(t, rec, c))
		}
	}
}

// R3-2: the third durable state of an interrupted start — Pending names the Control Artifact, which was
// stored, and run_start never followed. Recovery completes the control commit and still stops the run:
// no tool_call at seq 0, for the main run (which continues in a fresh run) and for a sub-agent run.
func TestRecoveredControl_WithoutRunStart_IsNeverContinued(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "f2000000-0000-4000-8000-000000000001"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
	mustHook(t, rec, agentCall(sid, "t1", "researcher", ""))
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "researcher"})

	rewind := func(run *state.Run) {
		t.Helper()
		ctrl, err := rec.store.LoadArtifact(run, "ctrl")
		if err != nil {
			t.Fatal(err)
		}
		_, hash, _ := evidence.EnvelopeHash(json.RawMessage(ctrl.Envelope))
		run.Pending = &state.Pending{Name: "ctrl", Seq: -1, EnvelopeHash: hash}
		run.NextSeq, run.ControlSig, run.PrevSig = 0, "", ""
		for _, n := range rec.store.ArtifactNames(run) {
			if n != "ctrl" {
				os.Remove(rec.store.RunPath(run, n+".json"))
			}
		}
		if err := rec.store.Save(run); err != nil {
			t.Fatal(err)
		}
	}
	child := childRuns(t, rec, sid)[0]
	rewind(child)
	if _, err := hook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "t2", AgentID: "a1", ToolInput: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("the sub-agent run must be refused")
	}
	child, _ = rec.store.LoadRun(sid, child.Name)
	if child.Broken != initInterrupted || hasStep(t, rec, child, "tool_call") {
		t.Fatalf("child broken=%q steps=%v", child.Broken, steps(t, rec, child))
	}

	main, _ := rec.store.Current(sid)
	rewind(main)
	rec.toolCallCommitted = false
	mustHook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "t3", ToolInput: json.RawMessage(`{}`)})
	old, _ := rec.store.LoadRun(sid, main.Name)
	if old.Broken != initInterrupted || hasStep(t, rec, old, "tool_call") {
		t.Fatalf("old main broken=%q steps=%v", old.Broken, steps(t, rec, old))
	}
	fresh, _ := rec.store.Current(sid)
	if fresh.Name == main.Name || strings.Join(steps(t, rec, fresh), ",") != "run_start,tool_call" {
		t.Fatalf("fresh run steps %v", steps(t, rec, fresh))
	}
}

// R3-4: SessionEnd never waits for the session lock. With the lock held far longer than Claude Code lets
// SessionEnd live, a real hook process records the run-bound close request and exits on its own before the
// host would kill it; the finalizer later applies it under the lock and seals run_end.
func TestSessionEnd_DoesNotWaitForTheSigningLock(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	_, rec.account, _ = newBackend(context.Background(), config{APIURL: srv.URL, APIKey: "test-key"})
	sid := "f4000000-0000-4000-8000-000000000001"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})

	release := make(chan struct{})
	held := make(chan struct{})
	go func() {
		_ = rec.store.WithLock(context.Background(), sid, func() error { close(held); <-release; return nil })
	}()
	<-held

	raw, _ := json.Marshal(input{SessionID: sid, HookEventName: "SessionEnd", Reason: "prompt_input_exit"})
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "SIGILL_HOOK_CHILD=1", "CLAUDE_PLUGIN_DATA="+rec.cfg.DataDir,
		"SIGILL_API_URL="+srv.URL, "SIGILL_API_KEY=test-key")
	cmd.Stdin = bytes.NewReader(raw)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond): // about when the host gives up on SessionEnd
		cmd.Process.Kill()
		<-done
		t.Fatal("SessionEnd was still running when the host would have killed it")
	}
	run, _ := rec.store.Current(sid)
	if reqs := rec.store.CloseRequestsFor(sid, run.Name); len(reqs) != 1 || reqs[0].Reason != "prompt_input_exit" {
		t.Fatalf("close requests %+v", reqs)
	}
	close(release)
	if err := finalizeLocked(t, rec, sid); err != nil {
		t.Fatal(err)
	}
	run, _ = rec.store.Current(sid)
	_, arts := events(t, rec, run)
	end := decode(t, arts[len(arts)-1])
	if !run.Closed || end.Step["detail"] != "session ended: prompt_input_exit" {
		t.Fatalf("closed=%v run_end %v", run.Closed, end.Step)
	}
	if rec.store.CloseRequestedForKey(state.SessionKey(sid)) {
		t.Fatal("the applied request is removed")
	}
}

// R3-4: a hook killed while waiting for the lock must not matter: the request is written before anything
// waits. A close request for another run never closes the current one, and stays for the run it names.
func TestCloseRequest_IsRunBound(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "f4000000-0000-4000-8000-000000000002"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
	if err := rec.store.RequestClose(sid, "20200101T000000Z-deadbeef", 0, "other"); err != nil {
		t.Fatal(err)
	}
	mustHook(t, rec, input{SessionID: sid, HookEventName: "Stop", LastAssistantMessage: "x"})
	run, _ := rec.store.Current(sid)
	if run.CloseRequested != "" || run.Closed {
		t.Fatal("a request for another run never closes this one")
	}
	if got := rec.store.PendingCloseRuns(sid); len(got) != 1 || got[0] != "20200101T000000Z-deadbeef" {
		t.Fatalf("the other run's request stays pending for it: %v", got)
	}
}

// R3-7: a contradiction found after the child completed is recorded, and the delegating run closes
// "aborted" with the capture-fidelity detail; `status` shows it.
func TestLateContradiction_ClosesAbortedWithFidelityDetail(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "f7000000-0000-4000-8000-000000000001"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		agentCall(sid, "t1", "researcher", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "researcher"},
		{SessionID: sid, HookEventName: "SubagentStop", AgentID: "a1", LastAssistantMessage: "x"},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Agent", ToolUseID: "t1", ToolResponse: json.RawMessage(`{"agentId":"someone-else"}`)},
	} {
		mustHook(t, rec, e)
	}
	t.Setenv("CLAUDE_PLUGIN_DATA", rec.cfg.DataDir)
	out := captureStdout(t, func() { cmdStatus() })
	if !strings.Contains(out, "capture-fidelity") || !strings.Contains(out, "closes aborted") {
		t.Fatalf("status does not show the fidelity issue:\n%s", out)
	}
	if err := finalizeLocked(t, rec, sid); err != nil {
		t.Fatal(err)
	}
	main, _ := rec.store.Current(sid)
	got := steps(t, rec, main)
	if strings.Join(got, ",") != "run_start,delegation,delegation_result,checkpoint,tool_result,run_end" {
		t.Fatalf("steps %v", got)
	}
	_, arts := events(t, rec, main)
	end := decode(t, arts[len(arts)-1])
	if end.Step["runDisposition"] != "aborted" || !strings.Contains(end.Step["detail"].(string), "capture-fidelity") {
		t.Fatalf("run_end %v", end.Step)
	}
}

// R3-7: at the budget boundary the diagnostic cannot be sealed without using the slots reserved for
// results and run_end, so capture stops instead (nothing is sealed, the reason says why).
func TestContradictionAtTheBudgetBoundary_StopsCapture(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "f7000000-0000-4000-8000-000000000002"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		agentCall(sid, "t1", "researcher", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "researcher"},
		{SessionID: sid, HookEventName: "SubagentStop", AgentID: "a1", LastAssistantMessage: "x"},
	} {
		mustHook(t, rec, e)
	}
	main, _ := rec.store.Current(sid)
	main.NextSeq = maxEvents - 1 // only run_end still fits
	if err := rec.store.Save(main); err != nil {
		t.Fatal(err)
	}
	before := fake.count()
	if _, err := hook(t, rec, input{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Agent", ToolUseID: "t1",
		ToolResponse: json.RawMessage(`{"agentId":"someone-else"}`)}); err == nil {
		t.Fatal("capture must stop")
	}
	main, _ = rec.store.Current(sid)
	if fake.count() != before || !strings.Contains(main.Broken, "could not be recorded within the event budget") {
		t.Fatalf("requests %d, broken %q", fake.count()-before, main.Broken)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}
