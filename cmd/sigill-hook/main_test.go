package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sigill-ai/agent-plugins/internal/evidence"
	"github.com/sigill-ai/agent-plugins/internal/evidence/evidencetest"
	"github.com/sigill-ai/agent-plugins/internal/sigill"
	"github.com/sigill-ai/agent-plugins/internal/state"
)

const platformCertID = "22222222-2222-2222-2222-222222222222"

// fakeSigill answers /seal/sign-hashes with a JWS whose signature value is derived
// from the request and, when a timestamp is requested, a sigTst whose "token" carries
// the SHA-512 imprint of that signature value (as a real RFC 3161 token would).
type fakeSigill struct {
	mu        sync.Mutex
	requests  []map[string]any
	certs     []string
	noStamp   bool // answer timestamp requests with a B-B seal (no sigTst)
	failAfter int  // fail every seal request after this many (0 = never)
	delay     time.Duration
	// failAt fails the n-th seal request (1-based): "503" refuses it, "nosig" answers 200 without a usable
	// signature (an ambiguous outcome: the server may have signed).
	failAt map[int]string
}

func (f *fakeSigill) handler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test-key" {
		w.WriteHeader(401)
		return
	}
	switch r.URL.Path {
	case "/seal/certificates":
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": "11111111-1111-1111-1111-111111111111", "source": "byoc", "status": "pending"},
			{"id": platformCertID, "source": "platform", "status": "active"},
		})
		return
	case "/api/agent-evidence/artifacts":
		w.WriteHeader(201)
		return
	case "/seal/sign-hashes":
	default:
		w.WriteHeader(404)
		return
	}
	time.Sleep(f.delay)
	raw, _ := io.ReadAll(r.Body)
	var req map[string]any
	_ = json.Unmarshal(raw, &req)
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.certs = append(f.certs, fmt.Sprint(req["certificateId"]))
	n := len(f.requests)
	fail := f.failAfter > 0 && n > f.failAfter
	noStamp := f.noStamp
	mode := f.failAt[n]
	f.mu.Unlock()
	if fail || mode == "503" {
		w.WriteHeader(503)
		return
	}
	if mode == "nosig" {
		json.NewEncoder(w).Encode(map[string]any{"signature": map[string]any{"signatures": []any{}}, "operationId": evidence.NewUUID()})
		return
	}
	sum := sha256.Sum256(raw)
	sig := base64.RawURLEncoding.EncodeToString(sum[:])
	prot := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"PS256"}`))
	entry := map[string]any{"protected": prot, "signature": sig}
	format := "jades-b-b"
	if _, off := req["timestamp"]; !off && !noStamp {
		token := evidencetest.ForSignature(sig)
		comp, _ := json.Marshal(map[string]any{"sigTst": map[string]any{"tstTokens": []any{map[string]any{"val": base64.StdEncoding.EncodeToString(token)}}}})
		entry["header"] = map[string]any{"etsiU": []string{base64.RawURLEncoding.EncodeToString(comp)}}
		format = "jades-b-t"
	}
	json.NewEncoder(w).Encode(map[string]any{
		"signature":   map[string]any{"signatures": []any{entry}},
		"operationId": evidence.NewUUID(), "format": format,
	})
}

func newRec(t *testing.T, url string, mod func(*config)) *recorder {
	t.Helper()
	cfg := config{APIURL: url, APIKey: "test-key", AgentID: "urn:sigill:agent:claude-code", DataDir: t.TempDir(),
		Consequential: map[string]bool{"Bash": true}}
	if mod != nil {
		mod(&cfg)
	}
	return &recorder{cfg: cfg, store: state.Store{Dir: cfg.DataDir}, be: sigill.New(cfg.APIURL, cfg.APIKey), account: "apikey|test"}
}

// hook runs one event the way runHook does (lock + handle), returning handle's error.
func hook(t *testing.T, rec *recorder, e input) (*state.Run, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rec.toolCallCommitted = false
	var run *state.Run
	err := rec.store.WithLock(ctx, e.SessionID, func() error {
		var e2 error
		run, e2 = rec.handle(ctx, e)
		return e2
	})
	return run, err
}

func mustHook(t *testing.T, rec *recorder, e input) *state.Run {
	t.Helper()
	run, err := hook(t, rec, e)
	if err != nil {
		t.Fatalf("%s: %v", e.HookEventName, err)
	}
	return run
}

func finalizeNow(t *testing.T, rec *recorder, sid string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := rec.store.WithLock(ctx, sid, func() error {
		cur, err := rec.store.Current(sid)
		if err != nil || cur == nil {
			return err
		}
		return rec.finalize(ctx, cur)
	}); err != nil {
		t.Fatal(err)
	}
}

type ev struct {
	Activity struct {
		CorrelationID string `json:"correlationId"`
	} `json:"activity"`
	Chain struct {
		Seq  int    `json:"seq"`
		Prev string `json:"prevSignatureSha256"`
	} `json:"chain"`
	Step  map[string]any    `json:"step"`
	Binds map[string]string `json:"binds"`
}

func events(t *testing.T, rec *recorder, run *state.Run) (state.Artifact, []state.Artifact) {
	t.Helper()
	var ctrl state.Artifact
	var arts []state.Artifact
	for _, n := range rec.store.ArtifactNames(run) {
		a, err := rec.store.LoadArtifact(run, n)
		if err != nil {
			t.Fatal(err)
		}
		if n == "ctrl" {
			ctrl = a
		} else {
			arts = append(arts, a)
		}
	}
	return ctrl, arts
}

func TestFullSession(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, func(c *config) { c.CertificateID = "00000000-0000-0000-0000-000000000001" })
	sid := "701d72b6-f3b4-4b51-8f31-b10d3a6e8d41"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		{SessionID: sid, HookEventName: "UserPromptSubmit", Prompt: "secret prompt text"},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t1", ToolInput: json.RawMessage(`{"file_path":"/x"}`)},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Read", ToolUseID: "t1", ToolResponse: json.RawMessage(`{"ok":true}`)},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "t2", ToolInput: json.RawMessage(`{"command":"rm -rf build"}`)},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t3", AgentID: "a1", AgentType: "general-purpose", ToolInput: json.RawMessage(`{}`)},
		{SessionID: sid, HookEventName: "SubagentStop", AgentID: "a1", LastAssistantMessage: "done"},
		{SessionID: sid, HookEventName: "Stop", LastAssistantMessage: "final answer"},
		{SessionID: sid, HookEventName: "SessionEnd", Reason: "other"},
	} {
		mustHook(t, rec, e)
	}
	finalizeNow(t, rec, sid) // what the spawned finalizer does
	// After close: ignored, the closed chain is never continued.
	if run := mustHook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read"}); !run.Closed {
		t.Fatal("run must be closed")
	}

	for _, req := range fake.requests {
		b, _ := json.Marshal(req)
		for _, secret := range []string{"secret prompt", "rm -rf", "final answer", "file_path", "done"} {
			if strings.Contains(string(b), secret) {
				t.Fatalf("content %q leaked to the sealing service", secret)
			}
		}
		if _, ok := req["label"]; ok {
			t.Fatal("no operation label may be sent")
		}
	}
	run, _ := rec.store.Current(sid)
	ctrl, arts := events(t, rec, run)
	if len(arts) != 8 {
		t.Fatalf("got %d events, want 8", len(arts))
	}
	if dump := os.Getenv("SIGILL_DUMP_DIR"); dump != "" {
		for i, a := range append([]state.Artifact{ctrl}, arts...) {
			raw, _ := json.Marshal(a)
			os.WriteFile(filepath.Join(dump, fmt.Sprintf("%02d.json", i)), raw, 0o644)
		}
	}
	controlSig := evidence.SignatureSha256(ctrl.Signature)
	prev := ""
	for i, a := range arts {
		var e ev
		json.Unmarshal(a.Envelope, &e)
		if e.Chain.Seq != i {
			t.Fatalf("seq %d at %d", e.Chain.Seq, i)
		}
		if i == 0 && e.Binds["controlArtifactSignatureSha256"] != controlSig {
			t.Fatal("run_start does not bind the control artifact")
		}
		if i > 0 && e.Chain.Prev != prev {
			t.Fatalf("broken link at seq %d", i)
		}
		prev = evidence.SignatureSha256(a.Signature)
		if e.Step["type"] == "tool_call" && e.Step["tool"].(map[string]any)["name"] == "Bash" {
			if e.Step["consequential"] != true || e.Step["timestamp"] != "required" {
				t.Fatal("Bash must be consequential and timestamped")
			}
		}
		if e.Step["type"] == "run_end" {
			if int(e.Step["finalSeq"].(float64)) != i || e.Step["finalPrevSignatureSha256"] != e.Chain.Prev {
				t.Fatal("run_end closure fields wrong")
			}
		}
	}
	stamped := 0
	for _, req := range fake.requests {
		if _, off := req["timestamp"]; !off {
			stamped++
		}
	}
	if stamped != 3 { // control artifact, Bash tool_call, run_end
		t.Fatalf("timestamped seals = %d, want 3", stamped)
	}
}

// Common §6.2: a 200 answer without the required timestamp is a sealing failure. The run
// stops, and under enforcement the consequential tool is blocked.
func TestMissingRequiredTimestamp_StopsTheRun(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, func(c *config) { c.FailClosed = true })
	sid := "a0000000-0000-4000-8000-000000000001"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Cwd: t.TempDir()})
	fake.mu.Lock()
	fake.noStamp = true
	fake.mu.Unlock()
	if _, err := hook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "t1", ToolInput: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("a B-B answer to a timestamp-required seal must fail")
	}
	if rec.toolCallCommitted {
		t.Fatal("the tool_call must not count as committed")
	}
	run, _ := rec.store.Current(sid)
	if run.Broken == "" || run.NextSeq != 1 {
		t.Fatalf("run must stop at seq 1: %+v", run)
	}
	// And a cold control artifact without its timestamp never starts a run.
	sid2 := "a0000000-0000-4000-8000-000000000002"
	if _, err := hook(t, rec, input{SessionID: sid2, HookEventName: "SessionStart", Cwd: t.TempDir()}); err == nil {
		t.Fatal("control artifact without timestamp must fail")
	}
}

// Enforcement covers every path where the tool_call was not durably committed: missing
// credentials, a broken run, a cold start whose control seal fails.
func TestFailClosed_BlocksWheneverTheToolCallIsNotCommitted(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	data := t.TempDir()
	run := func(env map[string]string, ev input) int {
		t.Helper()
		for k, v := range map[string]string{"SIGILL_API_URL": srv.URL, "SIGILL_API_KEY": "test-key", "SIGILL_FAIL_CLOSED": "1",
			"CLAUDE_PLUGIN_DATA": data, "SIGILL_INDEX": "0", "SIGILL_CONSEQUENTIAL_TOOLS": "Bash", "SIGILL_CREDENTIAL_STORE": "file"} {
			t.Setenv(k, v)
		}
		for k, v := range env {
			t.Setenv(k, v)
		}
		raw, _ := json.Marshal(ev)
		r, w, _ := os.Pipe()
		w.Write(raw)
		w.Close()
		old := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = old }()
		return runHook()
	}
	bash := func(sid string) input {
		return input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "t", ToolInput: json.RawMessage(`{}`)}
	}
	read := func(sid string) input {
		return input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t", ToolInput: json.RawMessage(`{}`)}
	}

	if code := run(nil, input{SessionID: "s1", HookEventName: "SessionStart", Cwd: t.TempDir()}); code != 0 {
		t.Fatalf("session start exit %d", code)
	}
	if code := run(nil, bash("s1")); code != 0 {
		t.Fatalf("a committed consequential tool_call must not be blocked (exit %d)", code)
	}
	if code := run(map[string]string{"SIGILL_API_KEY": ""}, bash("s2")); code != 2 {
		t.Fatalf("missing credentials must block under enforcement (exit %d)", code)
	}
	if code := run(map[string]string{"SIGILL_API_KEY": ""}, read("s2")); code != 0 {
		t.Fatalf("a non-consequential tool is never blocked (exit %d)", code)
	}
	fake.mu.Lock()
	fake.failAfter = len(fake.requests) // every further seal fails
	fake.mu.Unlock()
	if code := run(nil, bash("s1")); code != 2 {
		t.Fatalf("a failed seal must block (exit %d)", code)
	}
	if code := run(nil, bash("s1")); code != 2 {
		t.Fatalf("a broken run must keep blocking (exit %d)", code)
	}
	if code := run(nil, bash("s3")); code != 2 {
		t.Fatalf("a cold start whose control seal fails must block (exit %d)", code)
	}
	if code := run(map[string]string{"SIGILL_FAIL_CLOSED": "0"}, bash("s3")); code != 0 {
		t.Fatalf("without enforcement nothing is blocked (exit %d)", code)
	}
}

// Crash consistency: an artifact stored but not committed is committed on recovery; a
// pending seal with no stored artifact stops the run. No sequence is ever issued twice.
func TestRecovery_NeverForksTheChain(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)

	// (a) Process died after the artifact was stored, before the head was committed.
	sid := "b0000000-0000-4000-8000-000000000001"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Cwd: t.TempDir()})
	run, _ := rec.store.Current(sid)
	before := *run
	mustHook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t1", ToolInput: json.RawMessage(`{}`)})
	after, _ := rec.store.Current(sid)
	stale := before
	stale.Pending = &state.Pending{Name: "0001-tool_call", Seq: 1, EnvelopeHash: envelopeHashOf(t, rec, after, "0001-tool_call")}
	if err := rec.store.Save(&stale); err != nil {
		t.Fatal(err)
	}
	mustHook(t, rec, input{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Read", ToolUseID: "t1", ToolResponse: json.RawMessage(`{}`)})
	run, _ = rec.store.Current(sid)
	_, arts := events(t, rec, run)
	for i, a := range arts {
		var e ev
		json.Unmarshal(a.Envelope, &e)
		if e.Chain.Seq != i {
			t.Fatalf("recovered chain has seq %d at %d", e.Chain.Seq, i)
		}
	}
	if len(arts) != 3 || run.Broken != "" {
		t.Fatalf("want run_start, tool_call, tool_result after recovery; got %d (broken %q)", len(arts), run.Broken)
	}

	// (b) Process died after Pending was persisted, outcome unknown: the run stops.
	sid2 := "b0000000-0000-4000-8000-000000000002"
	mustHook(t, rec, input{SessionID: sid2, HookEventName: "SessionStart", Cwd: t.TempDir()})
	run, _ = rec.store.Current(sid2)
	run.Pending = &state.Pending{Name: "0001-tool_call", Seq: 1, EnvelopeHash: strings.Repeat("0", 64)}
	rec.store.Save(run)
	if _, err := hook(t, rec, input{SessionID: sid2, HookEventName: "PostToolUse", ToolName: "Read", ToolResponse: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("an unknown outcome must stop the run")
	}
	run, _ = rec.store.Current(sid2)
	if run.Broken == "" || run.NextSeq != 1 {
		t.Fatalf("run must stop without issuing seq 1 again: %+v", run)
	}
	n := len(fake.requests)
	mustHook(t, rec, input{SessionID: sid2, HookEventName: "PreToolUse", ToolName: "Read", ToolInput: json.RawMessage(`{}`)})
	if len(fake.requests) != n {
		t.Fatal("a stopped run must not request further seals")
	}

	// (c) The run directory cannot be written at commit time: nothing forks afterwards.
	sid3 := "b0000000-0000-4000-8000-000000000003"
	mustHook(t, rec, input{SessionID: sid3, HookEventName: "SessionStart", Cwd: t.TempDir()})
	run, _ = rec.store.Current(sid3)
	dir := filepath.Join(rec.cfg.DataDir, "sessions", state.SessionKey(sid3), "runs", run.Name)
	os.Chmod(dir, 0o500)
	_, err := hook(t, rec, input{SessionID: sid3, HookEventName: "PreToolUse", ToolName: "Read", ToolInput: json.RawMessage(`{}`)})
	os.Chmod(dir, 0o700)
	if err == nil && os.Geteuid() != 0 {
		t.Fatal("an unwritable run directory must fail the hook")
	}
	hook(t, rec, input{SessionID: sid3, HookEventName: "PostToolUse", ToolName: "Read", ToolResponse: json.RawMessage(`{}`)})
	run, _ = rec.store.Current(sid3)
	_, arts = events(t, rec, run)
	seen := map[int]bool{}
	for _, a := range arts {
		var e ev
		json.Unmarshal(a.Envelope, &e)
		if seen[e.Chain.Seq] {
			t.Fatalf("seq %d issued twice", e.Chain.Seq)
		}
		seen[e.Chain.Seq] = true
	}
}

func envelopeHashOf(t *testing.T, rec *recorder, run *state.Run, name string) string {
	t.Helper()
	a, err := rec.store.LoadArtifact(run, name)
	if err != nil {
		t.Fatal(err)
	}
	_, h, err := evidence.EnvelopeHash(json.RawMessage(a.Envelope))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A resumed, closed session starts a NEW run; the old run's files are never overwritten
// and an export never mixes runs.
func TestResumedSession_KeepsRunsApart(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "c0000000-0000-4000-8000-000000000001"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Cwd: t.TempDir()})
	mustHook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolInput: json.RawMessage(`{}`)})
	mustHook(t, rec, input{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Read", ToolResponse: json.RawMessage(`{}`)})
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionEnd"})
	finalizeNow(t, rec, sid)
	first, _ := rec.store.Current(sid)
	time.Sleep(1100 * time.Millisecond) // run names are second-resolution + random
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "resume", Cwd: t.TempDir()})
	second, _ := rec.store.Current(sid)
	if second.Name == first.Name || second.CorrelationID == first.CorrelationID {
		t.Fatal("a resumed session must start a new run")
	}
	if runs := rec.store.Runs(sid); len(runs) != 2 {
		t.Fatalf("both runs must be kept, got %v", runs)
	}
	for _, r := range []*state.Run{first, second} {
		r2, _ := rec.store.LoadRun(sid, r.Name)
		_, arts := events(t, rec, r2)
		for _, a := range arts {
			var e ev
			json.Unmarshal(a.Envelope, &e)
			if e.Activity.CorrelationID != r.CorrelationID {
				t.Fatalf("run %s holds an event of another run", r.Name)
			}
		}
	}
	old, _ := rec.store.LoadRun(sid, first.Name)
	if _, arts := events(t, rec, old); len(arts) != 4 || !old.Closed {
		t.Fatalf("the first run must stay intact and closed (%d events)", len(arts))
	}
}

// SessionEnd only records the request; if the finalizer never ran, the next session
// start (any session) finishes the run.
func TestSessionEnd_IsFinishedBySweep(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, func(c *config) { c.Index = true })
	a := "d0000000-0000-4000-8000-000000000001"
	mustHook(t, rec, input{SessionID: a, HookEventName: "SessionStart", Cwd: t.TempDir()})
	n := len(fake.requests)
	run := mustHook(t, rec, input{SessionID: a, HookEventName: "SessionEnd", Reason: "logout"})
	if run.CloseRequested == "" || run.Closed || len(fake.requests) != n {
		t.Fatal("SessionEnd must record the request without sealing in the hook")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	rec.sweep(ctx, "d0000000-0000-4000-8000-000000000002")
	run, _ = rec.store.Current(a)
	if !run.Closed {
		t.Fatal("the sweep must seal the requested run_end")
	}
}

// Common §7: ordinary events stop at 1999 so run_end fits; the session continues in a
// new, explicitly linked run.
func TestEventLimit_SegmentsTheRun(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "e0000000-0000-4000-8000-000000000001"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Cwd: t.TempDir()})
	run, _ := rec.store.Current(sid)
	run.NextSeq = maxEvents - 1 // pretend 1999 events were recorded
	rec.store.Save(run)
	time.Sleep(1100 * time.Millisecond)
	next := mustHook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolInput: json.RawMessage(`{}`)})
	old, _ := rec.store.LoadRun(sid, run.Name)
	if !old.Closed || old.NextSeq != maxEvents {
		t.Fatalf("the full run must close with run_end as event %d: %+v", maxEvents, old)
	}
	if next.Name == run.Name || next.SegmentOf != run.CorrelationID || next.NextSeq != 2 {
		t.Fatalf("the event must open a new linked run: %+v", next)
	}
}

// PostToolUseFailure carries the failure in its own fields, not tool_response.
func TestToolFailure_PinsTheFailureFields(t *testing.T) {
	a := failureResult(input{ToolError: json.RawMessage(`"secret failure A"`)})
	b := failureResult(input{ToolError: json.RawMessage(`"secret failure B"`)})
	if string(a) == string(b) || string(a) == "null" {
		t.Fatal("different failures must have different digests")
	}
	c := failureResult(input{Error: json.RawMessage(`"boom"`), IsInterrupt: new(bool)})
	if !strings.Contains(string(c), "boom") {
		t.Fatal("the documented error field must be pinned too")
	}
}

// Configuration collection reads regular files only, bounded, never blocking.
func TestCollect_RefusesFifosDevicesAndHugeFiles(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".claude"), 0o700)
	if err := syscall.Mkfifo(filepath.Join(dir, "CLAUDE.md"), 0o600); err != nil {
		t.Skip("no mkfifo")
	}
	os.Symlink("/dev/zero", filepath.Join(dir, ".claude", "CLAUDE.md"))
	done := make(chan []byte, 1)
	go func() { done <- collect(dir, []string{"CLAUDE.md", ".claude/CLAUDE.md"}, ".nonexistent-sigill-test") }()
	select {
	case out := <-done:
		if strings.Count(string(out), "NOT PINNED") != 2 {
			t.Fatalf("both unreadable files must be recorded as not pinned:\n%s", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collect blocked on a FIFO or device")
	}
	big := filepath.Join(dir, "big.md")
	os.WriteFile(big, make([]byte, maxConfigFile+1), 0o600)
	if out := collect(dir, []string{"big.md"}, ".nonexistent-sigill-test"); !strings.Contains(string(out), "NOT PINNED") {
		t.Fatal("an oversized file must not be pinned silently")
	}
}

// The storage root must be private; a planted symlink is refused, never followed.
func TestStore_RefusesUnsafePaths(t *testing.T) {
	base := t.TempDir()
	target := t.TempDir()
	os.MkdirAll(filepath.Join(base, "sessions"), 0o700)
	os.Symlink(target, filepath.Join(base, "sessions", state.SessionKey("x")))
	st := state.Store{Dir: base}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := st.WithLock(ctx, "x", func() error { return nil }); err == nil {
		t.Fatal("a symlinked session directory must be refused")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatal("nothing may be written through the link")
	}
	if state.SessionKey("a/b") == state.SessionKey("ab") {
		t.Fatal("session keys must not collide")
	}
}

// Without a configured certificate the run is sealed with the Sigill Platform Seal, resolved
// once when the run starts and kept for every artifact: one run, one signer.
func TestPlatformSealIsTheDefault_AndFixedPerRun(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "3c2b1a00-0000-4000-8000-000000000001"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Cwd: t.TempDir()})
	mustHook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t1", ToolInput: json.RawMessage(`{}`)})
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionEnd"})
	finalizeNow(t, rec, sid)
	run, _ := rec.store.Current(sid)
	if run.CertificateID != platformCertID {
		t.Fatalf("run certificate = %q, want the platform seal", run.CertificateID)
	}
	if len(fake.certs) != 4 {
		t.Fatalf("want ctrl, run_start, tool_call, run_end sealed; got %d", len(fake.certs))
	}
	for _, c := range fake.certs {
		if c != platformCertID {
			t.Fatalf("every artifact must be sealed with the run's certificate, got %q", c)
		}
	}
}

// An index outage never damages recording; undelivered artifacts stay queued until the
// index answers again.
func TestIndexOutageDoesNotBreakTheChain(t *testing.T) {
	fake := &fakeSigill{}
	var mu sync.Mutex
	indexUp := false
	var indexed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent-evidence/artifacts" {
			mu.Lock()
			defer mu.Unlock()
			if !indexUp {
				w.WriteHeader(503)
				return
			}
			var body struct {
				Envelope json.RawMessage `json:"envelope"`
			}
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			indexed = append(indexed, string(body.Envelope))
			w.WriteHeader(201)
			return
		}
		fake.handler(w, r)
	}))
	defer srv.Close()
	rec := newRec(t, srv.URL, func(c *config) { c.Index = true })
	sid := "9b0c1c1e-4d4e-4bb5-9f0f-3d1f6c3c0a11"
	drain := func(run *state.Run) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rec.drain(ctx, run, drainBudget, true)
	}
	drain(mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Cwd: t.TempDir()}))
	run := mustHook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t1", ToolInput: json.RawMessage(`{}`)})
	drain(run)
	if run.Broken != "" || run.NextSeq != 2 {
		t.Fatalf("chain must advance despite the outage: %+v", run)
	}
	if got := rec.store.PendingDelivery(run); len(got) != 3 || got[0] != "ctrl" {
		t.Fatalf("ctrl + 2 events must stay queued, ctrl first: %v", got)
	}
	mu.Lock()
	indexUp = true
	mu.Unlock()
	drain(run)
	if got := rec.store.PendingDelivery(run); len(got) != 0 {
		t.Fatalf("queue must drain once the index is back: %v", got)
	}
	if len(indexed) != 3 || !strings.Contains(indexed[0], evidence.ControlArtifactSchema) {
		t.Fatalf("ctrl first, then run_start and tool_call: got %d", len(indexed))
	}
}

func TestPermanentIndexRejectionIsDropped(t *testing.T) {
	for status, permanent := range map[int]bool{422: true, 409: true, 503: false, 429: false, 401: false, 408: false} {
		if got := (&sigill.IndexError{Status: status}).Permanent(); got != permanent {
			t.Errorf("%d: permanent=%v, want %v", status, got, permanent)
		}
	}
	if (&sigill.IndexError{Status: 409, Body: `{"code":"conflict","message":"retry"}`}).Permanent() {
		t.Error("a lost concurrent race (409 conflict) must be retried")
	}
}

// One deadline bounds the hook: a slow sealing service cannot hold it past its budget.
func TestHookDeadline_BoundsSlowSealing(t *testing.T) {
	fake := &fakeSigill{delay: 3 * time.Second}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	start := time.Now()
	_ = rec.store.WithLock(ctx, "f1", func() error {
		_, err := rec.handle(ctx, input{SessionID: "f1", HookEventName: "SessionStart", Cwd: t.TempDir()})
		return err
	})
	if time.Since(start) > 2500*time.Millisecond {
		t.Fatalf("the hook ran %v past a 1s deadline", time.Since(start))
	}
}

// fakeMCP serves the agent-recording tools over JSON-RPC, reusing fakeSigill's sealing.
type fakeMCP struct {
	seal       *fakeSigill
	mu         sync.Mutex
	throttle   int // answer this many seal calls with a rate_limited tool error first
	batches    []int
	authHeader string
	methods    []string
}

func (f *fakeMCP) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.authHeader = r.Header.Get("Authorization")
	f.mu.Unlock()
	if r.URL.Path != "/mcp" || r.Header.Get("Authorization") != "Bearer oauth-token" {
		w.WriteHeader(401)
		return
	}
	var rpc struct {
		Method string `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	json.NewDecoder(r.Body).Decode(&rpc)
	f.mu.Lock()
	f.methods = append(f.methods, rpc.Method)
	f.mu.Unlock()
	result := func(isErr bool, sc any) {
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"isError": isErr, "structuredContent": sc}})
	}
	switch rpc.Params.Name {
	case "sigill_agent_recording_config":
		result(false, map[string]any{"certificates": []any{map[string]any{"id": platformCertID, "source": "platform"}}})
	case "sigill_seal_agent_artifact":
		f.mu.Lock()
		if f.throttle > 0 {
			f.throttle--
			f.mu.Unlock()
			result(true, map[string]any{"error": "rate_limited", "retryable": true, "retryAfterSeconds": 1})
			return
		}
		f.mu.Unlock()
		var a struct {
			Hash      string `json:"envelope_hash_hex"`
			Type      string `json:"envelope_content_type"`
			Cert      string `json:"certificate_id"`
			Timestamp bool   `json:"timestamp"`
		}
		json.Unmarshal(rpc.Params.Arguments, &a)
		body := map[string]any{"envelopeHashHex": a.Hash, "envelopeContentType": a.Type, "certificateId": a.Cert}
		if !a.Timestamp {
			body["timestamp"] = false
		}
		raw, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/seal/sign-hashes", strings.NewReader(string(raw)))
		req.Header.Set("Authorization", "Bearer test-key")
		f.seal.handler(rec, req)
		var sealed map[string]any
		json.Unmarshal(rec.Body.Bytes(), &sealed)
		result(false, sealed)
	case "sigill_index_agent_artifacts":
		var a struct {
			Items []struct {
				Key string `json:"key"`
			} `json:"items"`
		}
		json.Unmarshal(rpc.Params.Arguments, &a)
		f.mu.Lock()
		f.batches = append(f.batches, len(a.Items))
		f.mu.Unlock()
		out := []any{}
		for _, it := range a.Items {
			out = append(out, map[string]any{"key": it.Key, "status": "indexed"})
		}
		result(false, map[string]any{"results": out})
	default:
		w.WriteHeader(404)
	}
}

// The OAuth transport: the same recorder over the MCP agent-recording tools — throttled
// seals are retried as the same pending event, and delivery is batched.
func TestMCPBackend_RecordsAndIndexesInBatches(t *testing.T) {
	fake := &fakeMCP{seal: &fakeSigill{}, throttle: 1}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	cfg := config{APIURL: srv.URL, AgentID: "urn:sigill:agent:claude-code", DataDir: t.TempDir(), Index: true, Consequential: map[string]bool{"Bash": true}}
	rec := &recorder{cfg: cfg, store: state.Store{Dir: cfg.DataDir}, be: sigill.NewMCP(srv.URL, "oauth-token"), account: srv.URL + "|tenant-1|user-1"}
	sid := "f0000000-0000-4000-8000-000000000001"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Cwd: t.TempDir()})
	for i := 0; i < 5; i++ {
		mustHook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: fmt.Sprint(i), ToolInput: json.RawMessage(`{}`)})
	}
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionEnd"})
	finalizeNow(t, rec, sid)
	run, _ := rec.store.Current(sid)
	if !run.Closed || run.Broken != "" || run.CertificateID != platformCertID || run.Account != rec.account {
		t.Fatalf("run over MCP: %+v", run)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rec.drain(ctx, run, drainBudget, false) // closed run: flushed regardless of size
	if got := rec.store.PendingDelivery(run); len(got) != 0 {
		t.Fatalf("all artifacts must be delivered: %v", got)
	}
	if len(fake.batches) != 1 || fake.batches[0] != 8 { // ctrl, run_start, 5 tool_calls, run_end
		t.Fatalf("want one batch of 8, got %v", fake.batches)
	}
	// The stateless /mcp is called with tools/call only: no initialize round trip per hook process.
	for _, m := range fake.methods {
		if m != "tools/call" {
			t.Fatalf("unexpected MCP method %q", m)
		}
	}
	if len(fake.methods) == 0 {
		t.Fatal("no MCP calls observed")
	}
}

// A run started by one account is never continued, finalized or delivered under another.
func TestAccountChange_StartsANewRun(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "f0000000-0000-4000-8000-000000000002"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Cwd: t.TempDir()})
	first, _ := rec.store.Current(sid)
	rec.account = "apikey|other-organisation"
	time.Sleep(1100 * time.Millisecond)
	next := mustHook(t, rec, input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolInput: json.RawMessage(`{}`)})
	old, _ := rec.store.LoadRun(sid, first.Name)
	if old.Broken == "" || old.NextSeq != 1 {
		t.Fatalf("the old account's run must be left stopped: %+v", old)
	}
	if next.Name == first.Name || next.Account != "apikey|other-organisation" {
		t.Fatalf("the new account records in a new run: %+v", next)
	}
}

// Runs of one Claude Code session (resumed, or split at the limit) carry the same session
// reference; it is a one-way hash, never the session id itself.
func TestSessionReference_LinksSegments(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "f0000000-0000-4000-8000-000000000003"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Cwd: t.TempDir()})
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionEnd"})
	finalizeNow(t, rec, sid)
	time.Sleep(1100 * time.Millisecond)
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "resume", Cwd: t.TempDir()})
	refs := []string{}
	for _, name := range rec.store.Runs(sid) {
		run, _ := rec.store.LoadRun(sid, name)
		a, err := rec.store.LoadArtifact(run, "0000-run_start")
		if err != nil {
			t.Fatal(err)
		}
		var env struct {
			Extensions map[string]map[string]any `json:"extensions"`
		}
		json.Unmarshal(a.Envelope, &env)
		ref, _ := env.Extensions[host.ExtKey]["session"].(string)
		if strings.Contains(string(a.Envelope), sid) {
			t.Fatal("the session id itself must not be in the envelope")
		}
		refs = append(refs, ref)
	}
	if len(refs) != 2 || refs[0] == "" || refs[0] != refs[1] || len(refs[0]) != 32 {
		t.Fatalf("both runs must carry the same 32-hex session reference: %v", refs)
	}
}

// A refused agent evidence quota is reported as such (REST 402 with the platform's code), not as a
// sealing failure; nothing is sealed and the run stops without skipping a seq.
func TestQuotaExceeded_IsReportedAsQuota(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/seal/certificates":
			json.NewEncoder(w).Encode([]map[string]any{{"id": platformCertID, "source": "platform", "status": "active"}})
		case "/seal/sign-hashes":
			w.WriteHeader(402)
			w.Write([]byte(`{"title":"Payment Required","code":"agent_evidence_quota_exceeded","limit":1000,"resetsAt":"2026-10-12T06:44:24Z"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "e1000000-0000-4000-8000-000000000001"
	_, err := hook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
	if err == nil {
		t.Fatal("the start must fail")
	}
	run, _ := rec.store.Current(sid)
	if run == nil || !strings.Contains(run.Broken, "agent evidence quota is used up") || !strings.Contains(run.Broken, "2026-10-12T06:44:24Z") {
		t.Fatalf("broken reason %q", run.Broken)
	}
	if strings.Contains(run.Broken, "could not be sealed") {
		t.Fatal("a refused quota is not a sealing failure")
	}
}

// Qualified timestamps are the producer's choice: off by default, and when chosen only on the
// artifacts that take a timestamp at all.
func TestQualifiedTimestamps_AreOptIn_AndOnlyWhereStamped(t *testing.T) {
	for _, want := range []bool{false, true} {
		fake := &fakeSigill{}
		srv := httptest.NewServer(http.HandlerFunc(fake.handler))
		rec := newRec(t, srv.URL, func(c *config) { c.Qualified = want })
		sid := fmt.Sprintf("e2000000-0000-4000-8000-00000000000%d", map[bool]int{false: 1, true: 2}[want])
		for _, e := range []input{
			{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
			{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t1", ToolInput: json.RawMessage(`{}`)},
			{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "t2", ToolInput: json.RawMessage(`{}`)},
		} {
			mustHook(t, rec, e)
		}
		for _, req := range fake.requests {
			_, off := req["timestamp"]
			stamped := !off
			if q, _ := req["qualified"].(bool); q != (want && stamped) {
				t.Fatalf("qualified=%v on a seal with timestamp=%v (chosen: %v)", q, stamped, want)
			}
		}
		srv.Close()
	}
}
