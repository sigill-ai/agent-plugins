package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigill-ai/agent-plugins/internal/evidence"
	"github.com/sigill-ai/agent-plugins/internal/state"
)

type tev struct {
	SchemaVersion string `json:"schemaVersion"`
	Activity      struct {
		CorrelationID string `json:"correlationId"`
	} `json:"activity"`
	Actor struct {
		ID string `json:"id"`
	} `json:"actor"`
	Step  map[string]any `json:"step"`
	Binds map[string]any `json:"binds"`
}

func decode(t *testing.T, a state.Artifact) tev {
	t.Helper()
	var e tev
	if err := json.Unmarshal(a.Envelope, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func steps(t *testing.T, rec *recorder, run *state.Run) []string {
	t.Helper()
	_, arts := events(t, rec, run)
	out := []string{}
	for _, a := range arts {
		out = append(out, decode(t, a).Step["type"].(string))
	}
	return out
}

// childRuns lists the session's sub-agent runs.
func childRuns(t *testing.T, rec *recorder, sid string) []*state.Run {
	t.Helper()
	out := []*state.Run{}
	for _, n := range rec.store.Runs(sid) {
		r, err := rec.store.LoadRun(sid, n)
		if err != nil {
			t.Fatal(err)
		}
		if r.ParentRun != "" {
			out = append(out, r)
		}
	}
	return out
}

func agentCall(sid, use, typ, agentID string) input {
	return input{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Agent", ToolUseID: use, AgentID: agentID,
		ToolInput: json.RawMessage(`{"subagent_type":"` + typ + `","prompt":"secret task for the sub-agent"}`)}
}

func TestSubAgent_IsItsOwnRun_BoundToTheParentBothWays(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "d0000000-0000-4000-8000-000000000001"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		{SessionID: sid, HookEventName: "UserPromptSubmit", Prompt: "review this"},
		agentCall(sid, "t1", "researcher", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "researcher"},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Agent", ToolUseID: "t1", ToolResponse: json.RawMessage(`{"agentId":"a1","status":"async_launched"}`)},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t2", AgentID: "a1", AgentType: "researcher", ToolInput: json.RawMessage(`{"file_path":"/secret/path"}`)},
		{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Read", ToolUseID: "t2", AgentID: "a1", AgentType: "researcher", ToolResponse: json.RawMessage(`{"ok":true}`)},
		{SessionID: sid, HookEventName: "SubagentStop", AgentID: "a1", AgentType: "researcher", LastAssistantMessage: "child findings"},
		{SessionID: sid, HookEventName: "Stop", LastAssistantMessage: "final answer"},
		{SessionID: sid, HookEventName: "SessionEnd", Reason: "other"},
	} {
		mustHook(t, rec, e)
	}
	finalizeNow(t, rec, sid)

	main, _ := rec.store.Current(sid)
	if got := strings.Join(steps(t, rec, main), ","); got != "run_start,delegation,tool_result,delegation_result,model_output,run_end" {
		t.Fatalf("main run: %s", got)
	}
	kids := childRuns(t, rec, sid)
	if len(kids) != 1 {
		t.Fatalf("got %d sub-agent runs, want 1", len(kids))
	}
	child := kids[0]
	if got := strings.Join(steps(t, rec, child), ","); got != "run_start,tool_call,tool_result,model_output,run_end" {
		t.Fatalf("child run: %s", got)
	}

	_, mainArts := events(t, rec, main)
	del, res, mainEnd := decode(t, mainArts[1]), decode(t, mainArts[3]), decode(t, mainArts[5])
	childCtrl, childArts := events(t, rec, child)
	start, childEnd := decode(t, childArts[0]), decode(t, childArts[len(childArts)-1])

	// The parent declares the child; the child binds the delegation; the result binds the child's run_end.
	dd := del.Step["delegation"].(map[string]any)
	if dd["childCorrelationId"] != child.CorrelationID || dd["childAgentId"] != "urn:sigill:agent:claude-code:researcher" || dd["useId"] != "t1" {
		t.Fatalf("delegation declares %v", dd)
	}
	if start.Binds["parentDelegationSignatureSha256"] != evidence.SignatureSha256(mainArts[1].Signature) ||
		start.Binds["parentCorrelationId"] != main.CorrelationID ||
		start.Binds["controlArtifactSignatureSha256"] != evidence.SignatureSha256(childCtrl.Signature) {
		t.Fatalf("child run_start binds %v", start.Binds)
	}
	if start.Actor.ID != "urn:sigill:agent:claude-code:researcher" || start.Activity.CorrelationID != child.CorrelationID {
		t.Fatal("the child must sign the id and agent its parent declared")
	}
	rd := res.Step["delegation"].(map[string]any)
	if rd["childRunEndSignatureSha256"] != evidence.SignatureSha256(childArts[len(childArts)-1].Signature) || rd["childDisposition"] != "completed" {
		t.Fatalf("delegation_result %v", rd)
	}
	if childEnd.Step["runDisposition"] != "completed" || mainEnd.Step["runDisposition"] != "completed" {
		t.Fatal("both runs close completed")
	}
	for _, a := range append(mainArts, childArts...) {
		if decode(t, a).SchemaVersion != "2" {
			t.Fatal("a run that delegates, and its sub-agent run, use schemaVersion 2")
		}
	}
	if _, ok := start.Binds["session"]; ok {
		t.Fatal("unexpected")
	}
	for _, req := range fake.requests {
		b, _ := json.Marshal(req)
		for _, secret := range []string{"secret task", "/secret/path", "child findings", "final answer", "review this"} {
			if strings.Contains(string(b), secret) {
				t.Fatalf("content %q leaked to the sealing service", secret)
			}
		}
	}
}

func TestSessionEnd_ClosesOpenSubAgentsAborted_AndResolvesThem(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "d0000000-0000-4000-8000-000000000002"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		agentCall(sid, "t1", "general-purpose", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "general-purpose"},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read", ToolUseID: "t2", AgentID: "a1", ToolInput: json.RawMessage(`{}`)},
		{SessionID: sid, HookEventName: "SessionEnd", Reason: "prompt_input_exit"},
	} {
		mustHook(t, rec, e)
	}
	finalizeNow(t, rec, sid)
	main, _ := rec.store.Current(sid)
	child := childRuns(t, rec, sid)[0]
	if !child.Closed {
		t.Fatal("the sub-agent run must be closed with the session")
	}
	_, childArts := events(t, rec, child)
	if decode(t, childArts[len(childArts)-1]).Step["runDisposition"] != "aborted" {
		t.Fatal("an interrupted sub-agent closes aborted")
	}
	_, mainArts := events(t, rec, main)
	res := decode(t, mainArts[len(mainArts)-2])
	if res.Step["type"] != "delegation_result" || res.Step["delegation"].(map[string]any)["childDisposition"] != "aborted" {
		t.Fatalf("the parent records the aborted child before closing: %v", res.Step)
	}
	if decode(t, mainArts[len(mainArts)-1]).Step["runDisposition"] != "completed" {
		t.Fatal("every delegation is resolved, so the parent closes completed")
	}
	// A late event of the closed sub-agent is not recorded anywhere.
	before := len(fake.requests)
	mustHook(t, rec, input{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Read", ToolUseID: "t2", AgentID: "a1"})
	if len(fake.requests) != before {
		t.Fatal("nothing is sealed after the runs closed")
	}
}

func TestDelegationWithoutSubAgent_ClosesTheParentAborted(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "d0000000-0000-4000-8000-000000000003"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
	mustHook(t, rec, agentCall(sid, "t1", "researcher", ""))
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionEnd", Reason: "other"})
	finalizeNow(t, rec, sid)
	main, _ := rec.store.Current(sid)
	_, arts := events(t, rec, main)
	if end := decode(t, arts[len(arts)-1]); end.Step["runDisposition"] != "aborted" {
		t.Fatalf("an unresolved delegation forbids a completed close (§4 rule 5): %v", end.Step)
	}
}

func TestNestedSubAgents_FormAThreeLevelTree(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "d0000000-0000-4000-8000-000000000004"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		agentCall(sid, "t1", "planner", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "planner"},
		agentCall(sid, "t2", "researcher", "a1"), // the sub-agent starts its own sub-agent
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a2", AgentType: "researcher"},
		{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Grep", ToolUseID: "t3", AgentID: "a2", ToolInput: json.RawMessage(`{}`)},
		{SessionID: sid, HookEventName: "SubagentStop", AgentID: "a2", LastAssistantMessage: "x"},
		{SessionID: sid, HookEventName: "SubagentStop", AgentID: "a1", LastAssistantMessage: "y"},
		{SessionID: sid, HookEventName: "SessionEnd", Reason: "other"},
	} {
		mustHook(t, rec, e)
	}
	finalizeNow(t, rec, sid)
	main, _ := rec.store.Current(sid)
	byAgent := map[string]*state.Run{}
	for _, c := range childRuns(t, rec, sid) {
		byAgent[c.ClaudeAgentID] = c
	}
	planner, researcher := byAgent["a1"], byAgent["a2"]
	if planner == nil || researcher == nil || planner.ParentRun != main.Name || researcher.ParentRun != planner.Name {
		t.Fatal("the tree is main → planner → researcher")
	}
	if got := strings.Join(steps(t, rec, planner), ","); got != "run_start,delegation,delegation_result,model_output,run_end" {
		t.Fatalf("planner: %s", got)
	}
	if got := strings.Join(steps(t, rec, main), ","); got != "run_start,delegation,delegation_result,run_end" {
		t.Fatalf("main: %s", got)
	}
}

func TestReconcile_SettlesIntentsFromTheChainHead(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "d0000000-0000-4000-8000-000000000005"
	mustHook(t, rec, input{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()})
	mustHook(t, rec, agentCall(sid, "t1", "researcher", ""))
	main, _ := rec.store.Current(sid)
	want := main.Delegations[0].Sig
	// A crash after the delegation was committed but before its signature was noted, and a result intent
	// whose event never reached the chain.
	main.Delegations[0].Sig = ""
	main.Delegations[0].ResultSeq = main.NextSeq
	main.Delegations = append(main.Delegations, state.Delegation{ChildCorrelationID: "urn:uuid:never", Seq: main.NextSeq, ResultSeq: -1})
	if err := rec.store.Save(main); err != nil {
		t.Fatal(err)
	}
	cur, _ := rec.store.Current(sid)
	if err := rec.recover(cur); err != nil {
		t.Fatal(err)
	}
	if len(cur.Delegations) != 1 || cur.Delegations[0].Sig != want || cur.Delegations[0].ResultSeq != -1 {
		t.Fatalf("reconciled: %+v", cur.Delegations)
	}
}

func TestExportTree_BundlesTheRunAndItsSubAgents(t *testing.T) {
	fake := &fakeSigill{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	rec := newRec(t, srv.URL, nil)
	sid := "d0000000-0000-4000-8000-000000000006"
	for _, e := range []input{
		{SessionID: sid, HookEventName: "SessionStart", Source: "startup", Cwd: t.TempDir()},
		agentCall(sid, "t1", "researcher", ""),
		{SessionID: sid, HookEventName: "SubagentStart", AgentID: "a1", AgentType: "researcher"},
		{SessionID: sid, HookEventName: "SubagentStop", AgentID: "a1", LastAssistantMessage: "x"},
	} {
		mustHook(t, rec, e)
	}
	main, _ := rec.store.Current(sid)
	runs := []map[string]any{runBundle(rec.store, main)}
	for _, d := range main.Delegations {
		c, err := rec.store.LoadRun(sid, d.ChildRun)
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, runBundle(rec.store, c))
	}
	if len(runs) != 2 || runs[1]["correlationId"] != main.Delegations[0].ChildCorrelationID {
		t.Fatal("the tree holds the main run and its sub-agent run")
	}
}
