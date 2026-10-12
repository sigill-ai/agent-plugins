package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// hostProfile is what differs between the agent hosts the recorder runs in. The hook protocol is the same
// shape in both (session_id, tool_name/tool_input/tool_use_id, agent_id on a sub-agent's own events,
// SubagentStart/SubagentStop, last_assistant_message), so everything else — chain, sealing, delegation,
// credentials, crash-safe commit — is shared. The host is chosen by SIGILL_HOST, set in the host's hooks
// file; it defaults to Claude Code.
type hostProfile struct {
	Name           string // "claude-code" | "codex"
	DisplayName    string
	RecorderID     string
	ControlSetID   string
	ExtKey         string // producer extensions key
	DefaultAgentID string
	ClientID       string // OAuth client metadata document (CIMD)
	ConnectCommand string // what a user runs to sign in
	// DefaultDataDir is used when the host does not pass a data directory in the environment.
	DefaultDataDir func(home string) string
	// Instruction files (first found wins) and where a missing one is reported; the same for settings.
	InstructionFiles   []string
	InstructionDefault string
	SettingsFiles      []string
	SettingsDefault    string
	// AgentDefinition returns the instruction file of a configured sub-agent type, or "" when the host has none.
	AgentDefinition func(subagentType string) string
	VersionCommand  []string
	VersionTrim     string
	// DefaultConsequential lists the tools sealed and timestamped before they run.
	DefaultConsequential string
	// IsDelegationTool reports the tool that starts a sub-agent.
	IsDelegationTool func(tool string) bool
	// SubagentType is the configured role of the sub-agent a delegation starts (never the task text).
	SubagentType func(toolInput json.RawMessage) string
	// SubagentTypeOf is the role a SubagentStart reports, compared with SubagentType for pairing.
	SubagentTypeOf func(agentType string) string
}

var claudeCodeHost = hostProfile{
	Name:             "claude-code",
	DisplayName:      "Claude Code",
	RecorderID:       "urn:sigill:recorder:claude-code",
	ControlSetID:     "sigill-claude-code-baseline",
	ExtKey:           "ai.sigill.claude-code",
	DefaultAgentID:   "urn:sigill:agent:claude-code",
	ClientID:         "https://sigill.ai/.well-known/oauth-client/claude-code.json",
	ConnectCommand:   "/sigill:connect",
	DefaultDataDir:   func(home string) string { return filepath.Join(home, ".sigill", "claude-code") },
	InstructionFiles: []string{"CLAUDE.md", ".claude/CLAUDE.md"}, InstructionDefault: ".claude/CLAUDE.md",
	SettingsFiles: []string{".claude/settings.json", ".claude/settings.local.json"}, SettingsDefault: ".claude/settings.json",
	AgentDefinition: func(t string) string { return filepath.Join(".claude", "agents", safeName(t)+".md") },
	VersionCommand:  []string{"claude", "--version"}, VersionTrim: "(Claude Code)",
	DefaultConsequential: "Bash,Write,Edit,MultiEdit,NotebookEdit,mcp__*",
	IsDelegationTool:     func(t string) bool { return t == "Agent" || t == "Task" },
	SubagentType: func(raw json.RawMessage) string {
		var in struct {
			SubagentType string `json:"subagent_type"`
		}
		_ = json.Unmarshal(raw, &in)
		if in.SubagentType == "" {
			return "general-purpose"
		}
		return in.SubagentType
	},
	SubagentTypeOf: func(t string) string { return t },
}

// Codex (OpenAI). Hook fields observed on codex-cli 0.153: spawning a sub-agent is the tool
// collaborationspawn_agent (tool_input: task_name, message, fork_turns) and returns at once; the parent then
// waits with collaborationwait_agent. SubagentStart/SubagentStop carry agent_id and agent_type ("default"),
// and the sub-agent's own tool events carry its agent_id. So the delegation is sealed at PreToolUse of the
// spawn, the child run opens at SubagentStart and closes — with the parent's delegation_result — at
// SubagentStop, exactly as for Claude Code.
var codexHost = hostProfile{
	Name:           "codex",
	DisplayName:    "Codex",
	RecorderID:     "urn:sigill:recorder:codex",
	ControlSetID:   "sigill-codex-baseline",
	ExtKey:         "ai.sigill.codex",
	DefaultAgentID: "urn:sigill:agent:codex",
	ClientID:       "https://sigill.ai/.well-known/oauth-client/codex.json",
	ConnectCommand: "the sigill-connect skill",
	// Codex gives a plugin <data root>/<plugin>-<marketplace>; the hooks file passes it explicitly, this is
	// the same place for commands run by hand.
	DefaultDataDir:   func(home string) string { return filepath.Join(home, ".codex", "plugins", "data", "sigill-sigill") },
	InstructionFiles: []string{"AGENTS.md", ".codex/AGENTS.md"}, InstructionDefault: "AGENTS.md",
	SettingsFiles: []string{".codex/config.toml", ".codex/hooks.json"}, SettingsDefault: ".codex/config.toml",
	AgentDefinition: func(string) string { return "" }, // sub-agents share the session's instructions
	VersionCommand:  []string{"codex", "--version"}, VersionTrim: "codex-cli",
	DefaultConsequential: "Bash,apply_patch,mcp__*",
	IsDelegationTool: func(t string) bool {
		return t == "collaborationspawn_agent" || t == "spawn_agent" || t == "collaboration.spawn_agent"
	},
	SubagentType: func(raw json.RawMessage) string {
		var in struct {
			AgentType string `json:"agent_type"`
		}
		_ = json.Unmarshal(raw, &in)
		if in.AgentType == "" {
			return "default"
		}
		return in.AgentType
	},
	SubagentTypeOf: func(t string) string {
		if t == "" {
			return "default"
		}
		return t
	},
}

// host is the profile of this invocation (SIGILL_HOST; the finalizer inherits the environment).
var host = hostFromEnv()

func hostFromEnv() hostProfile {
	if strings.EqualFold(os.Getenv("SIGILL_HOST"), "codex") {
		return codexHost
	}
	return claudeCodeHost
}
