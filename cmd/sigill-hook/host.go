package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sigill-ai/agent-plugins/internal/sigill"
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
	// IsFollowupTool reports the tool that hands an existing sub-agent new work (no SubagentStart follows).
	IsFollowupTool func(tool string) bool
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
	IsFollowupTool: func(string) bool { return false },
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
	// Hooks receive the plugin data directory from Codex (PLUGIN_DATA); commands run from a skill derive the
	// same directory from where this binary is installed (codexDataDir).
	DefaultDataDir:   func(home string) string { return codexDataDir(os.Getenv("CODEX_HOME"), home, executablePath()) },
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
	// collaborationfollowup_task {message, target}: target is the task_name the agent was spawned under
	// (observed on codex-cli 0.153). The agent runs again with the same agent_id, without SubagentStart, and
	// ends that episode with another SubagentStop.
	IsFollowupTool: func(t string) bool {
		return t == "collaborationfollowup_task" || t == "followup_task" || t == "collaboration.followup_task"
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

// Status markers. Neither proves the hooks run now: Codex skips plugin hooks until they are reviewed (and
// again after each update), and a plugin cannot read Codex's trust state. They record what this installation
// last observed — a hook delivery (with the recorder version that received it) and a committed step — so
// status can say what is known and what is not.
const (
	hooksMarker    = "hooks-last-delivery"
	recordedMarker = "last-recorded-step"
)

// writeMarker replaces a status marker atomically and best-effort: a fresh private temp file (O_EXCL) is
// renamed over the name, so an existing FIFO, symlink or other file at that name is replaced, never opened or
// followed. Failures are ignored — the marker is diagnostic and must never stall or fail a committed seal.
func writeMarker(dataDir, name, value string) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dataDir, "."+name+".tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.WriteString(value)
	if cerr := tmp.Close(); werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return
	}
	if os.Rename(tmp.Name(), filepath.Join(dataDir, name)) != nil {
		os.Remove(tmp.Name())
	}
}

// readMarker reads a small private regular file without blocking or following links; anything else is "".
func readMarker(dataDir, name string) string {
	fh, err := os.OpenFile(filepath.Join(dataDir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 256 {
		return ""
	}
	buf := make([]byte, fi.Size())
	if _, err := io.ReadFull(fh, buf); err != nil {
		return ""
	}
	return strings.TrimSpace(string(buf))
}

// markHooksActive records a SessionStart delivery and the recorder version that received it.
func markHooksActive(dataDir string) {
	writeMarker(dataDir, hooksMarker, time.Now().UTC().Format(time.RFC3339)+" "+sigill.Version)
}

func markRecorded(dataDir string) {
	writeMarker(dataDir, recordedMarker, time.Now().UTC().Format(time.RFC3339))
}

// codexEvents are the events hooks/codex-hooks.json registers, as Codex names them in its review state.
var codexEvents = []string{"session_start", "user_prompt_submit", "pre_tool_use", "post_tool_use",
	"subagent_start", "subagent_stop", "stop", "session_end"}

// codexHooksStatus reports, separately, the last hook delivery observed (and by which version), how many
// Sigill hook entries Codex's config lists (presence only — a plugin cannot verify Codex's trust hash, and
// managed hooks do not appear there), and the last step sealed. It never claims the hooks are active now.
func codexHooksStatus(dataDir string) string {
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		h, _ := os.UserHomeDir()
		home = filepath.Join(h, ".codex")
	}
	listed := 0
	if cfg, err := os.ReadFile(filepath.Join(home, "config.toml")); err == nil {
		for _, ev := range codexEvents {
			if strings.Contains(string(cfg), `hooks.state."sigill@sigill:hooks/codex-hooks.json:`+ev+`:`) {
				listed++
			}
		}
	}
	const fix = "start codex, run /hooks and trust the Sigill hooks (press t); this is needed again after each plugin update, or use managed hooks"
	var b strings.Builder
	delivery := readMarker(dataDir, hooksMarker)
	when, version, _ := strings.Cut(delivery, " ")
	switch {
	case delivery == "":
		fmt.Fprintf(&b, "hooks: no hook delivery observed yet — %s.\n", fix)
	case version != sigill.Version:
		fmt.Fprintf(&b, "hooks: last delivery observed %s by version %s, not by this version (%s) — after an update %s.\n", when, version, sigill.Version, fix)
	default:
		fmt.Fprintf(&b, "hooks: last delivery observed %s by this version; whether Codex runs them now is not verifiable from here — if a newer session was not recorded, %s.\n", when, fix)
	}
	fmt.Fprintf(&b, "hooks in Codex config: %d of %d Sigill entries listed (presence only; managed hooks are not listed)\n", listed, len(codexEvents))
	if rec := readMarker(dataDir, recordedMarker); rec != "" {
		fmt.Fprintf(&b, "recording: last step sealed %s", rec)
	} else {
		b.WriteString("recording: no step sealed yet")
	}
	return b.String()
}

func executablePath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// codexDataDir is the data directory Codex gives this plugin installation: an installed plugin runs from
// <codex home>/plugins/cache/<marketplace>/<plugin>/<version>/libexec/, and Codex's data directory for it is
// <codex home>/plugins/data/<plugin>-<marketplace>. A binary elsewhere (a local checkout, a managed
// /opt install) uses $CODEX_HOME (default ~/.codex) with the Sigill marketplace's names.
func codexDataDir(codexHome, userHome, exe string) string {
	dir := filepath.Dir(exe)    // …/libexec
	ver := filepath.Dir(dir)    // …/<version>
	plugin := filepath.Dir(ver) // …/<plugin>
	mkt := filepath.Dir(plugin) // …/<marketplace>
	cache := filepath.Dir(mkt)  // …/cache
	if exe != "" && filepath.Base(dir) == "libexec" && filepath.Base(cache) == "cache" && filepath.Base(filepath.Dir(cache)) == "plugins" {
		return filepath.Join(filepath.Dir(cache), "data", filepath.Base(plugin)+"-"+filepath.Base(mkt))
	}
	if codexHome == "" {
		codexHome = filepath.Join(userHome, ".codex")
	}
	return filepath.Join(codexHome, "plugins", "data", "sigill-sigill")
}
