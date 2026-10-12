package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

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
	if got := codexHooksStatus(data); !strings.Contains(got, "no hook delivery observed") || !strings.Contains(got, "0 of 8") || !strings.Contains(got, "no step sealed") {
		t.Fatalf("nothing observed: %s", got)
	}
	// A delivery by an older version (the trust of the updated hooks is unknown) and a stale marker never
	// read as "active" (Codex R8-2).
	writeMarker(data, hooksMarker, "2020-01-01T00:00:00Z 0.0.1")
	if got := codexHooksStatus(data); strings.Contains(got, "active") || !strings.Contains(got, "not by this version") {
		t.Fatalf("older delivery: %s", got)
	}
	cfg := ""
	for _, ev := range codexEvents {
		cfg += `[hooks.state."sigill@sigill:hooks/codex-hooks.json:` + ev + `:0:0"]` + "\ntrusted_hash = \"sha256:x\"\n"
	}
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	markHooksActive(data)
	markRecorded(data)
	got := codexHooksStatus(data)
	if strings.Contains(got, "active") || !strings.Contains(got, "by this version") || !strings.Contains(got, "8 of 8") ||
		!strings.Contains(got, "presence only") || !strings.Contains(got, "last step sealed") {
		t.Fatalf("current delivery: %s", got)
	}
}

// Codex round 8 (R8-1): a sub-agent handed new work with collaborationfollowup_task runs again under the
// same agent_id with no SubagentStart (probed on codex-cli 0.153: target = the spawn's task_name). Each
// episode must be its own bound child run; a sealed run is never reopened, and nothing is dropped.
func codexFollowupSession(sid, child, target string, followup bool) []input {
	spawn := json.RawMessage(`{"task_name":"pwd-check","message":"secret task one"}`)
	evs := []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup"},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "collaborationspawn_agent", ToolUseID: "s1", ToolInput: spawn},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "collaborationspawn_agent", ToolUseID: "s1", ToolInput: spawn, ToolResponse: json.RawMessage(`"{\"task_name\":\"/root/pwd-check\"}"`)},
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: child, AgentType: "default"},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "b1", AgentID: child, AgentType: "default", ToolInput: json.RawMessage(`{"command":"pwd"}`)},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Bash", ToolUseID: "b1", AgentID: child, AgentType: "default", ToolResponse: json.RawMessage(`"/x"`)},
		{SessionID: sid, HookEventName: "SubagentStop", AgentID: child, AgentType: "default", LastAssistantMessage: "first answer"},
	}
	if followup {
		f := json.RawMessage(`{"target":"` + target + `","message":"secret task two"}`)
		evs = append(evs,
			input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "collaborationfollowup_task", ToolUseID: "f1", ToolInput: f},
			input{SessionID: sid, HookEventName: "PostToolUse", ToolName: "collaborationfollowup_task", ToolUseID: "f1", ToolInput: f, ToolResponse: json.RawMessage(`"ok"`)})
	}
	return append(evs,
		input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "b2", AgentID: child, AgentType: "default", ToolInput: json.RawMessage(`{"command":"date"}`)},
		input{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Bash", ToolUseID: "b2", AgentID: child, AgentType: "default", ToolResponse: json.RawMessage(`"Mon"`)},
		input{SessionID: sid, HookEventName: "SubagentStop", AgentID: child, AgentType: "default", LastAssistantMessage: "second answer"},
		input{SessionID: sid, HookEventName: "Stop", LastAssistantMessage: "final"},
		input{SessionID: sid, HookEventName: "SessionEnd", Reason: "other"})
}

func codexRec(t *testing.T) (*recorder, *fakeSigill) {
	t.Helper()
	asCodex(t)
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	t.Cleanup(srv.Close)
	return newRec(t, srv.URL, func(c *config) {
		c.AgentID = codexHost.DefaultAgentID
		c.Consequential = map[string]bool{"Bash": true}
	}), fake
}

func TestCodex_R8_FollowupIsANewBoundEpisode(t *testing.T) {
	rec, fake := codexRec(t)
	sid, child := "019e0000-0000-7000-8000-0000000000f1", "01a13188-0000-7000-8000-000000000001"
	for _, e := range codexFollowupSession(sid, child, "pwd-check", true) {
		if e.ToolName == "Bash" && e.HookEventName == "PreToolUse" {
			rec.toolCallCommitted = false
			mustHook(t, rec, e)
			if !rec.toolCallCommitted {
				t.Fatalf("the sub-agent's consequential call %s was not committed (fail-closed would block it)", e.ToolUseID)
			}
			continue
		}
		mustHook(t, rec, e)
	}
	finalizeNow(t, rec, sid)

	main, _ := rec.store.Current(sid)
	want := "run_start,delegation,tool_result,delegation_result,delegation,tool_result,delegation_result,model_output,run_end"
	if got := strings.Join(steps(t, rec, main), ","); got != want {
		t.Fatalf("main run:\n got %s\nwant %s", got, want)
	}
	kids := childRuns(t, rec, sid)
	if len(kids) != 2 {
		t.Fatalf("got %d episode runs, want 2", len(kids))
	}
	sort.Slice(kids, func(i, j int) bool { return kids[i].StartedAt.Before(kids[j].StartedAt) })
	_, mainArts := events(t, rec, main)
	for i, k := range kids {
		if got := strings.Join(steps(t, rec, k), ","); got != "run_start,tool_call,tool_result,model_output,run_end" {
			t.Fatalf("episode %d: %s", i+1, got)
		}
		_, arts := events(t, rec, k)
		start, end := decode(t, arts[0]), decode(t, arts[len(arts)-1])
		if end.Step["runDisposition"] != "completed" {
			t.Fatalf("episode %d closes %v", i+1, end.Step["runDisposition"])
		}
		del := decode(t, mainArts[[]int{1, 4}[i]]).Step["delegation"].(map[string]any)
		if del["childCorrelationId"] != k.CorrelationID ||
			start.Binds["parentDelegationSignatureSha256"] != evidence.SignatureSha256(mainArts[[]int{1, 4}[i]].Signature) {
			t.Fatalf("episode %d is not bound to its delegation", i+1)
		}
		res := decode(t, mainArts[[]int{3, 6}[i]]).Step["delegation"].(map[string]any)
		if res["childRunEndSignatureSha256"] != evidence.SignatureSha256(arts[len(arts)-1].Signature) {
			t.Fatalf("episode %d result not bound", i+1)
		}
	}
	if decode(t, mainArts[len(mainArts)-1]).Step["runDisposition"] != "completed" {
		t.Fatal("main closes completed")
	}
	for _, req := range fake.requests {
		b, _ := json.Marshal(req)
		for _, secret := range []string{"secret task", "pwd-check", "first answer", "second answer"} {
			if strings.Contains(string(b), secret) {
				t.Fatalf("content %q leaked to the sealing service", secret)
			}
		}
	}
}

// An unresolvable follow-up, or a sub-agent that continues after SubagentStop without one: its later work is
// kept in the delegating chain, tagged, behind a signed capture-fidelity checkpoint; the run closes aborted.
func TestCodex_R8_UntrackedContinuationIsKeptAndDisclosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		followup bool
		target   string
	}{{"unknown follow-up target", true, "someone-else"}, {"continues after SubagentStop", false, ""}} {
		t.Run(tc.name, func(t *testing.T) {
			rec, _ := codexRec(t)
			sid, child := "019e0000-0000-7000-8000-0000000000f2", "01a13188-0000-7000-8000-000000000002"
			for _, e := range codexFollowupSession(sid, child, tc.target, tc.followup) {
				if e.ToolName == "Bash" && e.ToolUseID == "b2" && e.HookEventName == "PreToolUse" {
					rec.toolCallCommitted = false
					mustHook(t, rec, e)
					if !rec.toolCallCommitted {
						t.Fatal("work after the run closed was not recorded (fail-closed would block it)")
					}
					continue
				}
				mustHook(t, rec, e)
			}
			finalizeNow(t, rec, sid)
			main, _ := rec.store.Current(sid)
			got := strings.Join(steps(t, rec, main), ",")
			if !strings.Contains(got, "checkpoint,tool_call,tool_result,model_output") {
				t.Fatalf("main run must keep the continuation behind a checkpoint: %s", got)
			}
			_, arts := events(t, rec, main)
			end := decode(t, arts[len(arts)-1])
			if end.Step["runDisposition"] != "aborted" || !strings.Contains(end.Step["detail"].(string), "capture-fidelity") {
				t.Fatalf("main must close aborted with the fidelity detail: %v", end.Step)
			}
			if kids := childRuns(t, rec, sid); len(kids) != 1 {
				t.Fatalf("no new episode without a bound follow-up: got %d child runs", len(kids))
			}
		})
	}
}

// Codex R8-3: commands run from a skill must use the data directory of the installation they belong to.
func TestCodex_R8_DataDirFollowsTheInstallation(t *testing.T) {
	for _, tc := range []struct{ name, codexHome, exe, want string }{
		{"installed, default home", "", "/Users/u/.codex/plugins/cache/sigill/sigill/0.3.1/libexec/sigill-hook-darwin-arm64",
			"/Users/u/.codex/plugins/data/sigill-sigill"},
		{"older cached version selected", "", "/Users/u/.codex/plugins/cache/sigill/sigill/0.2.9/libexec/sigill-hook-darwin-arm64",
			"/Users/u/.codex/plugins/data/sigill-sigill"},
		{"custom CODEX_HOME with spaces and another marketplace name", "/ignored",
			"/Volumes/My Disk/codex home/plugins/cache/acme-tools/sigill/0.3.1/libexec/sigill-hook-linux-amd64",
			"/Volumes/My Disk/codex home/plugins/data/sigill-acme-tools"},
		{"local checkout uses CODEX_HOME", "/srv/codex", "/home/u/src/agent-plugins/plugins/sigill-evidence/libexec/sigill-hook-linux-amd64",
			"/srv/codex/plugins/data/sigill-sigill"},
		{"managed install, default home", "", "/opt/sigill/sigill-hook-linux-amd64", "/home/u/.codex/plugins/data/sigill-sigill"},
	} {
		home := "/Users/u"
		if strings.HasPrefix(tc.exe, "/home/") || strings.HasPrefix(tc.exe, "/opt/") {
			home = "/home/u"
		}
		if got := codexDataDir(tc.codexHome, home, tc.exe); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}

// Codex R9-1: a follow-up delivered into a running episode (or while an earlier follow-up is pending) is
// steering, not a new episode; repeated idle follow-ups each get their own episode.
func TestCodex_R9_FollowupWhileRunningStaysInTheOpenEpisode(t *testing.T) {
	rec, _ := codexRec(t)
	sid, child := "019e0000-0000-7000-8000-0000000000f9", "01a13188-0000-7000-8000-000000000009"
	skipped := false
	for _, e := range codexFollowupSession(sid, child, "pwd-check", true) {
		if e.HookEventName == "SubagentStop" && !skipped { // the agent is still running when the follow-up arrives
			skipped = true
			continue
		}
		mustHook(t, rec, e)
	}
	finalizeNow(t, rec, sid)
	main, _ := rec.store.Current(sid)
	_, arts := events(t, rec, main)
	if main.Outstanding() != 0 || decode(t, arts[len(arts)-1]).Step["runDisposition"] != "completed" {
		t.Fatalf("phantom episode: outstanding=%d steps=%s", main.Outstanding(), strings.Join(steps(t, rec, main), ","))
	}
	if kids := childRuns(t, rec, sid); len(kids) != 1 {
		t.Fatalf("got %d child runs, want the one open episode", len(kids))
	}
}

func TestCodex_R9_RepeatedIdleFollowupsAreEpisodes(t *testing.T) {
	rec, _ := codexRec(t)
	sid, child := "019e0000-0000-7000-8000-0000000000fa", "01a13188-0000-7000-8000-00000000000a"
	evs := codexFollowupSession(sid, child, "pwd-check", true)
	tail := evs[len(evs)-2:] // Stop, SessionEnd
	evs = evs[:len(evs)-2]
	f := json.RawMessage(`{"target":"pwd-check","message":"third"}`)
	evs = append(evs,
		input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "collaborationfollowup_task", ToolUseID: "f2", ToolInput: f},
		input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "collaborationfollowup_task", ToolUseID: "f3", ToolInput: f}, // pending: steering
		input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "b3", AgentID: child, AgentType: "default", ToolInput: json.RawMessage(`{"command":"ls"}`)},
		input{SessionID: sid, HookEventName: "SubagentStop", AgentID: child, AgentType: "default", LastAssistantMessage: "third answer"})
	for _, e := range append(evs, tail...) {
		mustHook(t, rec, e)
	}
	finalizeNow(t, rec, sid)
	main, _ := rec.store.Current(sid)
	_, arts := events(t, rec, main)
	if n := len(childRuns(t, rec, sid)); n != 3 || main.Outstanding() != 0 || decode(t, arts[len(arts)-1]).Step["runDisposition"] != "completed" {
		t.Fatalf("want 3 bound episodes, completed: episodes=%d outstanding=%d steps=%s", n, main.Outstanding(), strings.Join(steps(t, rec, main), ","))
	}
}

// Codex R9-2: status markers never block or follow links; a failed write does not matter.
func TestCodex_R9_MarkersNeverBlockOrFollowLinks(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{recordedMarker, hooksMarker} {
		_ = os.Remove(filepath.Join(dir, name))
		if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
		done := make(chan struct{})
		go func() { _ = readMarker(dir, name); markRecorded(dir); markHooksActive(dir); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: marker I/O blocked on a FIFO", name)
		}
	}
	victim := filepath.Join(dir, "victim")
	_ = os.WriteFile(victim, []byte("keep"), 0o600)
	_ = os.Remove(filepath.Join(dir, recordedMarker))
	if err := os.Symlink(victim, filepath.Join(dir, recordedMarker)); err != nil {
		t.Fatal(err)
	}
	if readMarker(dir, recordedMarker) != "" {
		t.Fatal("a symlinked marker must not be read")
	}
	markRecorded(dir)
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("writing the marker followed a symlink")
	}
	if readMarker(dir, recordedMarker) == "" {
		t.Fatal("the marker was not replaced")
	}
}
