package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sigill-ai/agent-plugins/internal/evidence"
)

// AiEvidenceEnvelopeV2 v2.1: every object URI the plugin emits is a production-profile reference
// (objects/<uuid>); correlation ids keep their urn:uuid form.
func TestLocator_EveryEmittedObjectURIIsAProductionReference(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, func(c *config) { c.CertificateID = "00000000-0000-0000-0000-000000000001" })
	sid := "7b1d72b6-f3b4-4b51-8f31-b10d3a6e8d42"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		{SessionID: sid, HookEventName: "UserPromptSubmit", Prompt: "a prompt"},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t1", ToolInput: json.RawMessage(`{"file_path":"/x"}`)},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Read", ToolUseID: "t1", ToolResponse: json.RawMessage(`{"ok":true}`)},
		{SessionID: sid, HookEventName: "Stop", LastAssistantMessage: "an answer"},
		{SessionID: sid, HookEventName: "SessionEnd", Reason: "other"},
	} {
		mustHook(t, rec, e)
	}
	finalizeNow(t, rec, sid)

	seen := 0
	for _, req := range fake.requests {
		objs, _ := req["objects"].([]any)
		for _, o := range objs {
			uri, _ := o.(map[string]any)["uri"].(string)
			if !evidence.IsProductionReference(uri) || !strings.HasPrefix(uri, "objects/") {
				t.Fatalf("emitted object URI %q is not objects/<uuid>", uri)
			}
			seen++
		}
	}
	if seen == 0 {
		t.Fatal("no object URIs were emitted")
	}
	run, _ := rec.store.Current(sid)
	if !strings.HasPrefix(run.CorrelationID, "urn:uuid:") {
		t.Fatalf("correlation id %q must stay urn:uuid", run.CorrelationID)
	}
}

// A prompt queued by a pre-upgrade binary carries a urn:uuid URI. It is unsigned until the Stop seal, so it is
// re-minted to objects/<uuid> there; its content and digest are unchanged.
func TestLocator_PendingInputsFromBeforeTheUpgradeAreRemintedBeforeSealing(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, func(c *config) { c.CertificateID = "00000000-0000-0000-0000-000000000001" })
	sid := "7b1d72b6-f3b4-4b51-8f31-b10d3a6e8d43"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
	mustHook(t, rec, input{SessionID: sid, HookEventName: "UserPromptSubmit", Prompt: "queued before the upgrade"})

	// What an older binary left in state.json.
	const legacy = "urn:uuid:6f1c2a4e-0b7d-4c1e-9a52-3d8f0e1b7c90"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rec.store.WithLock(ctx, sid, func() error {
		run, err := rec.store.Current(sid)
		if err != nil {
			return err
		}
		run.PendingInputs[0].URI = legacy
		return rec.store.Save(run)
	}); err != nil {
		t.Fatal(err)
	}

	before := len(fake.requests)
	mustHook(t, rec, input{SessionID: sid, HookEventName: "Stop", LastAssistantMessage: "the answer"})
	if len(fake.requests) != before+1 {
		t.Fatalf("Stop sealed %d requests, want 1", len(fake.requests)-before)
	}
	sum := sha256.Sum256([]byte("queued before the upgrade"))
	want := hex.EncodeToString(sum[:])
	found := false
	for _, o := range fake.requests[before]["objects"].([]any) {
		m := o.(map[string]any)
		uri, _ := m["uri"].(string)
		if uri == legacy || !evidence.IsProductionReference(uri) {
			t.Fatalf("pending input sealed under %q", uri)
		}
		if m["hashHex"] == want {
			found = true
		}
	}
	if !found {
		t.Fatal("the re-minted prompt must keep its digest")
	}
}
