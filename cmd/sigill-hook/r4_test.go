package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// R4-1: a SessionEnd that read the run before a resume, but published its request after it, belongs to the
// earlier epoch: it never closes the resumed run. The resumed session's own end does.
func TestCloseRequest_ReadBeforeResume_NeverClosesTheResumedRun(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "f5000000-0000-4000-8000-000000000001"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
	before, _ := rec.store.Current(sid) // what the lock-free SessionEnd read

	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "resume", Cwd: t.TempDir()})
	if err := rec.store.RequestClose(sid, before.Name, before.Resumes, "prompt_input_exit"); err != nil {
		t.Fatal(err)
	}
	mustHook(t, rec, input{SessionID: sid, HookEventName: "Stop", LastAssistantMessage: "x"})
	run, _ := rec.store.Current(sid)
	if run.Name != before.Name || run.Resumes != 1 || run.CloseRequested != "" || run.Closed {
		t.Fatalf("the resumed run was closed by an earlier session end: %+v", run)
	}
	if len(rec.store.CloseRequestsFor(sid, run.Name)) != 0 {
		t.Fatal("the stale request is consumed")
	}

	if !requestClose(context.Background(), rec.store, input{SessionID: sid, HookEventName: "SessionEnd", Reason: "logout"}) {
		t.Fatal("the resumed session's end is recorded")
	}
	if err := lockedFinish(t, rec, sid); err != nil {
		t.Fatal(err)
	}
	run, _ = rec.store.Current(sid)
	if !run.Closed || !hasStep(t, rec, run, "run_end") {
		t.Fatal("the resumed session's own end closes the run")
	}
}

// R4-1: a pending request stays recoverable for the run it names even after the session moved on to a
// newer run: the finalizer closes that older run, and leaves the current one open.
func TestCloseRequest_ForAnOlderRun_IsFinishedForThatRun(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "f5000000-0000-4000-8000-000000000002"
	in := input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()}
	mustHook(t, rec, in)
	old, _ := rec.store.Current(sid)
	if err := rec.store.RequestClose(sid, old.Name, old.Resumes, "prompt_input_exit"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	time.Sleep(1100 * time.Millisecond) // run names carry the start second
	if err := rec.store.WithLock(ctx, sid, func() error { _, err := rec.startRun(ctx, in, ""); return err }); err != nil {
		t.Fatal(err)
	}
	cur, _ := rec.store.Current(sid)
	if cur.Name == old.Name {
		t.Fatal("expected a newer current run")
	}

	if err := lockedFinish(t, rec, sid); err != nil {
		t.Fatal(err)
	}
	old, _ = rec.store.LoadRun(sid, old.Name)
	cur, _ = rec.store.LoadRun(sid, cur.Name)
	if !old.Closed || !hasStep(t, rec, old, "run_end") {
		t.Fatal("the older run's request closes the older run")
	}
	if cur.Closed || cur.CloseRequested != "" {
		t.Fatal("the current run is not closed by another run's request")
	}
	if len(rec.store.PendingCloseRuns(sid)) != 0 {
		t.Fatal("the applied request is removed")
	}
}

// lockedFinish does what the finalizer does under the session lock.
func lockedFinish(t *testing.T, rec *recorder, sid string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return rec.store.WithLock(ctx, sid, func() error { _, err := rec.finishSession(ctx, sid); return err })
}
