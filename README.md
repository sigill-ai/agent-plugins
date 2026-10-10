# Sigill for Claude Code

Record every Claude Code session as **verifiable agent evidence**. The plugin records each
session as an [Agent Evidence Profiles v1](https://github.com/sigill-ai/sigill-dotnet/blob/main/spec/agent-profiles-common-v1.md)
run and seals every step with [Sigill](https://sigill.ai):

- **Before:** a control basis (your CLAUDE.md, settings and the recorder's control set) is
  sealed and timestamped before the agent acts.
- **During:** every tool call, tool result and model output is signed and chained to the one
  before it, so a recorded step cannot be removed, inserted or reordered without detection.
  Consequential tools (`Bash`, `Write`, `Edit`, MCP tools …) are sealed and timestamped
  **before they run**. Sub-agent steps are recorded too, tagged with the sub-agent's role.
- **After:** the session's `run_end` is timestamped, which freezes the whole chain.

**Blind by design.** Prompts, tool arguments, tool results and model output never leave your
machine. The plugin hashes them locally; Sigill receives SHA-256 digests and the signed step
metadata (step types, tool names, times, identifiers) — never content.

> **Status: preview (0.1).** macOS and Linux.

## Install

```
/plugin marketplace add sigill-ai/claude-plugins
/plugin install sigill@sigill
```

## Connect

```
/sigill:connect
```

Your browser opens Sigill sign-in. Approve the connection for your organisation and you are
done — sessions are recorded from the next session start. Each device gets its own
connection; you can see and end them under **Settings → Connected apps** in Sigill, or run
`/sigill:disconnect`. `/sigill:status` shows the connection and any unfinished runs.

The plugin asks only for **agent recording** (`mcp:agent:record`) and to stay connected
(`offline_access`). It cannot read your evidence or use any other Sigill feature. Credentials
are kept in the macOS Keychain or the Linux Secret Service when available, otherwise in a
private file in the plugin's data directory.

Not connected? The plugin records nothing and never interrupts your session; at session
start it reminds you once a day.

## Certificates

Runs are sealed with the shared **Sigill Platform Seal** unless you choose a certificate of
your own. The platform seal proves the record is intact, not who ran the agent. **We
recommend your organisation's own certificate (BYOC)**: runs are then attributed to your
organisation. Set its id once:

```sh
export SIGILL_CERTIFICATE_ID=...   # Sigill → Settings → Certificates
```

The certificate is fixed when a run starts, so every step of a run has one signer.

## Options

| Variable | Default | Meaning |
|---|---|---|
| `SIGILL_CERTIFICATE_ID` | platform seal | Your organisation's certificate (recommended) |
| `SIGILL_AGENT_ID` | `urn:sigill:agent:claude-code` | `agent.id` recorded for the session |
| `SIGILL_CONSEQUENTIAL_TOOLS` | `Bash,Write,Edit,MultiEdit,NotebookEdit,mcp__*` | Tools timestamped before they run |
| `SIGILL_FAIL_CLOSED` | off | `1` blocks a consequential tool unless its step was sealed first — including when the plugin is not connected |
| `SIGILL_INDEX` | on | `0` keeps the signed envelopes local (no upload to your Evidence store) |
| `SIGILL_API_URL` | `https://api.sigill.ai` | API endpoint. A connection is only ever used with the server it was made for |

### Headless CI

Where no browser is available (`claude -p` in a pipeline), set `SIGILL_API_KEY` to an API key
of your organisation. While a key is set the plugin uses it exclusively; it never falls back
from a sign-in to a key or the other way round.

## Your Evidence store

By default each step's **signed envelope** is uploaded to your Sigill Evidence store, so runs
appear under the agent in Evidence: agent → its runs → each run as before / during / after,
with one-click verification. Sigill accepts an envelope only if it matches a seal your
organisation made, with exactly the signature Sigill issued. Uploads happen after each step
is committed locally and in batches; if Sigill is unreachable they stay queued and are
delivered later. `SIGILL_INDEX=0` turns this off.

## Verify a session offline

```sh
"$CLAUDE_PLUGIN_ROOT/libexec/sigill-hook" export <session-id> run.json
```

Open [sigill.ai/verify-run](https://sigill.ai/verify-run) and drop `run.json`. Verification
runs in your browser; Sigill is only asked whether each signature verifies over its digests.

## What it proves — and what it doesn't

A finalized run proves that the recorded steps are unchanged since `run_end` was timestamped,
in the recorded order, under one signer, and that the control basis was sealed before the
first step. It does not prove that every step was captured: the plugin runs on the
developer's machine, and code running as the same user can interfere with it. Organisations
can enable the plugin for everyone through Claude Code managed settings
(`extraKnownMarketplaces` + `enabledPlugins`), which makes it hard to switch off by accident,
not tamper-proof.

A session that ends is finalized by a small background step; if that is interrupted, the next
session start finishes it, and until then the run shows as open.

## How it maps

| Claude Code hook | Evidence |
|---|---|
| `SessionStart` | Control Artifact + `run_start` |
| `UserPromptSubmit` | prompt digest (bound to the next `model_output`) |
| `PreToolUse` | `tool_call` (sealed before the tool runs) |
| `PostToolUse` / `PostToolUseFailure` | `tool_result` |
| `SubagentStop` | sub-agent `model_output` |
| `Stop` | `model_output` |
| `SessionEnd` | `run_end`, timestamped |

A run holds at most 2,000 events (the portable bundle limit); a longer session continues in a
new, linked run.

## Build

```sh
./build.sh          # cross-compiles plugins/sigill-evidence/libexec/sigill-hook-<os>-<arch>
go test ./...       # includes the cross-language vectors from sigill-dotnet
```

Licensed under Apache-2.0.
