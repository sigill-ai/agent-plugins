package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigill-ai/agent-plugins/internal/evidence"
)

func asCodex(t *testing.T) {
	t.Helper()
	old := host
	host = codexHost
	t.Cleanup(func() { host = old })
}

// The event order and fields below are what codex-cli 0.153 sent to a probe hook for "run ls, then spawn
// one sub-agent that runs pwd": the spawn tool returns before the sub-agent starts, the parent then waits
// with collaborationwait_agent, the sub-agent's tool events carry its agent_id, and tool_response is a
// string. The recording must come out exactly like Claude Code's: a run tree bound in both directions.
func TestCodex_SessionWithSubAgent_RecordsABoundRunTree(t *testing.T) {
	asCodex(t)
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, func(c *config) {
		c.AgentID = codexHost.DefaultAgentID
		c.Consequential = map[string]bool{"Bash": true, "apply_patch": true}
	})
	sid := "019e0000-0000-7000-8000-00000000c0de"
	child := "01a130e7-db47-7a01-950d-9b7510709d25"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		{SessionID: sid, HookEventName: "UserPromptSubmit", Prompt: "run ls, then a sub-agent for pwd"},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "c1", ToolInput: json.RawMessage(`{"command":"ls"}`)},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Bash", ToolUseID: "c1", ToolInput: json.RawMessage(`{"command":"ls"}`), ToolResponse: json.RawMessage(`"probe.sh\nREADME.md"`)},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "collaborationspawn_agent", ToolUseID: "c2",
			ToolInput: json.RawMessage(`{"task_name":"pwd-check","message":"secret task: run pwd","fork_turns":0}`)},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "collaborationspawn_agent", ToolUseID: "c2",
			ToolInput: json.RawMessage(`{"task_name":"pwd-check","message":"secret task: run pwd","fork_turns":0}`), ToolResponse: json.RawMessage(`"spawned"`)},
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: child, AgentType: "default"},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "collaborationwait_agent", ToolUseID: "c3", ToolInput: json.RawMessage(`{"timeout_ms":30000}`)},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "c4", AgentID: child, AgentType: "default", ToolInput: json.RawMessage(`{"command":"pwd"}`)},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Bash", ToolUseID: "c4", AgentID: child, AgentType: "default", ToolInput: json.RawMessage(`{"command":"pwd"}`), ToolResponse: json.RawMessage(`"/secret/dir"`)},
		{SessionID: sid, HookEventName: "SubagentStop", AgentID: child, AgentType: "default", LastAssistantMessage: "child says /secret/dir"},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "collaborationwait_agent", ToolUseID: "c3", ToolInput: json.RawMessage(`{"timeout_ms":30000}`), ToolResponse: json.RawMessage(`"done"`)},
		{SessionID: sid, HookEventName: "Stop", LastAssistantMessage: "final answer"},
		{SessionID: sid, HookEventName: "SessionEnd", Reason: "other"},
	} {
		mustHook(t, rec, e)
	}
	finalizeNow(t, rec, sid)

	main, _ := rec.store.Current(sid)
	want := "run_start,tool_call,tool_result,delegation,tool_result,tool_call,delegation_result,tool_result,model_output,run_end"
	if got := strings.Join(steps(t, rec, main), ","); got != want {
		t.Fatalf("main run:\n got %s\nwant %s", got, want)
	}
	kids := childRuns(t, rec, sid)
	if len(kids) != 1 {
		t.Fatalf("got %d sub-agent runs, want 1", len(kids))
	}
	kid := kids[0]
	if got := strings.Join(steps(t, rec, kid), ","); got != "run_start,tool_call,tool_result,model_output,run_end" {
		t.Fatalf("child run: %s", got)
	}

	_, mainArts := events(t, rec, main)
	childCtrl, childArts := events(t, rec, kid)
	del, start := decode(t, mainArts[3]), decode(t, childArts[0])
	dd := del.Step["delegation"].(map[string]any)
	if dd["childCorrelationId"] != kid.CorrelationID || dd["childAgentId"] != "urn:sigill:agent:codex:default" || dd["useId"] != "c2" {
		t.Fatalf("delegation declares %v", dd)
	}
	if start.Binds["parentDelegationSignatureSha256"] != evidence.SignatureSha256(mainArts[3].Signature) ||
		start.Binds["parentCorrelationId"] != main.CorrelationID ||
		start.Binds["controlArtifactSignatureSha256"] != evidence.SignatureSha256(childCtrl.Signature) {
		t.Fatalf("child run_start binds %v", start.Binds)
	}
	res := decode(t, mainArts[6]).Step["delegation"].(map[string]any)
	if res["childRunEndSignatureSha256"] != evidence.SignatureSha256(childArts[len(childArts)-1].Signature) || res["childDisposition"] != "completed" {
		t.Fatalf("delegation_result %v", res)
	}
	if a := decode(t, mainArts[0]); a.Actor.ID != "urn:sigill:agent:codex" {
		t.Fatalf("main actor %s", a.Actor.ID)
	}
	var startEnv struct {
		Extensions map[string]map[string]any `json:"extensions"`
	}
	_ = json.Unmarshal(mainArts[0].Envelope, &startEnv)
	if _, ok := startEnv.Extensions["ai.sigill.codex"]; !ok {
		t.Fatalf("run_start extensions use the Codex key: %v", startEnv.Extensions)
	}
	// The consequential Bash call is timestamped before it runs; the wait is not.
	if decode(t, mainArts[1]).Step["timestamp"] != "required" || decode(t, mainArts[5]).Step["timestamp"] != "none" {
		t.Fatal("timestamp policy: Bash required, collaborationwait_agent none")
	}
	for _, req := range fake.requests {
		b, _ := json.Marshal(req)
		for _, secret := range []string{"secret task", "/secret/dir", "child says", "final answer", "run ls, then"} {
			if strings.Contains(string(b), secret) {
				t.Fatalf("content %q leaked to the sealing service", secret)
			}
		}
	}
}

func TestCodex_HostProfile(t *testing.T) {
	t.Setenv("SIGILL_HOST", "codex")
	if h := hostFromEnv(); h.Name != "codex" || !h.IsDelegationTool("collaborationspawn_agent") || h.IsDelegationTool("Agent") {
		t.Fatalf("codex profile: %+v", h.Name)
	}
	t.Setenv("SIGILL_HOST", "")
	if h := hostFromEnv(); h.Name != "claude-code" || !h.IsDelegationTool("Agent") || h.IsDelegationTool("collaborationspawn_agent") {
		t.Fatal("Claude Code stays the default host")
	}
	if operation("apply_patch") != "write" {
		t.Fatal("apply_patch is a write")
	}
}

func TestCodex_HooksStatus(t *testing.T) {
	data, home := t.TempDir(), t.TempDir()
	t.Setenv("CODEX_HOME", home)
	if got := codexHooksStatus(data); !strings.Contains(got, "NOT RUNNING") || !strings.Contains(got, "0 of 8") {
		t.Fatalf("no review, no marker: %s", got)
	}
	cfg := ""
	for _, ev := range codexEvents {
		cfg += `[hooks.state."sigill@sigill:hooks/codex-hooks.json:` + ev + `:0:0"]` + "\ntrusted_hash = \"sha256:x\"\n"
	}
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := codexHooksStatus(data); !strings.Contains(got, "no session has started") {
		t.Fatalf("reviewed, no marker: %s", got)
	}
	markHooksActive(data)
	if got := codexHooksStatus(data); !strings.Contains(got, "active") || !strings.Contains(got, "8 of 8") {
		t.Fatalf("marker present: %s", got)
	}
}
