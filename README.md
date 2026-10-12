# Sigill for Claude Code and Codex

Record every Claude Code or OpenAI Codex session as **verifiable agent evidence**. The plugin records each
session as an [Agent Evidence Profiles v1](https://github.com/sigill-ai/sigill-dotnet/blob/main/spec/agent-profiles-common-v1.md)
run and seals every step with [Sigill](https://sigill.ai):

- **Before:** a control basis (your CLAUDE.md or AGENTS.md, settings and the recorder's control set) is
  sealed and timestamped before the agent acts.
- **During:** every tool call, tool result and model output is signed and chained to the one
  before it, so a recorded step cannot be removed, inserted or reordered without detection.
  Consequential tools (`Bash`, `Write`, `Edit`, MCP tools …) are sealed and timestamped
  **before they run**.
- **Sub-agents:** each sub-agent is recorded as its own run, bound to the session in both
  directions ([Agent Delegation v1](https://github.com/sigill-ai/sigill-dotnet/blob/main/spec/agent-delegation-v1.md)):
  the session declares it before it starts, and records its sealed result when it ends. A
  sub-agent left out of the evidence, swapped or edited afterwards is detected.
- **After:** the session's `run_end` is timestamped, which freezes the whole chain.

**Blind by design.** Prompts, tool arguments, tool results and model output never leave your
machine. The plugin hashes them locally; Sigill receives SHA-256 digests and the signed step
metadata (step types, tool names, times, identifiers) — never content.

> **Status: preview (0.2).** macOS and Linux.

## Install

```
/plugin marketplace add sigill-ai/agent-plugins
/plugin install sigill@sigill
```

### Codex

```
codex plugin marketplace add sigill-ai/agent-plugins
codex plugin add sigill@sigill
```

Codex runs a plugin's hooks only after you have reviewed them: start `codex`, run `/hooks`
and trust the Sigill hooks (again after each plugin update, since the reviewed definition
changes). Organisations can instead roll the hooks out as managed hooks in
`requirements.toml`, which need no review. Then ask Codex to *connect to Sigill* — the
`sigill-connect` skill signs you in (it needs network access, so approve running it outside
the sandbox). `sigill-status` and `sigill-disconnect` work the same way.

Run the `sigill-status` skill at any time: it tells you whether Codex is actually running the
Sigill hooks (a session start was recorded) and, if not, what to do.

#### Rolling it out to an organisation (no review step)

Hooks defined by an administrator in Codex's `requirements.toml` are trusted by policy: developers
review nothing and cannot switch them off. Install the recorder in a fixed directory with your
device management (copy `plugins/sigill-evidence/libexec/` — the `sigill-hook` launcher, the
`sigill-hook-<os>-<arch>` binaries and `SHA256SUMS`, checked with `shasum -a 256 -c SHA256SUMS` —
to `/opt/sigill`), then add:

```toml
allow_managed_hooks_only = true   # recommended: never record a session twice (managed + plugin hooks)

[hooks]
managed_dir = "/opt/sigill"

[[hooks.SessionStart]]
[[hooks.SessionStart.hooks]]
type = "command"
command = "SIGILL_HOST=codex /opt/sigill/sigill-hook"
timeout = 60

[[hooks.UserPromptSubmit]]
[[hooks.UserPromptSubmit.hooks]]
type = "command"
command = "SIGILL_HOST=codex /opt/sigill/sigill-hook"
timeout = 60

[[hooks.PreToolUse]]
[[hooks.PreToolUse.hooks]]
type = "command"
command = "SIGILL_HOST=codex /opt/sigill/sigill-hook"
timeout = 60

[[hooks.PostToolUse]]
[[hooks.PostToolUse.hooks]]
type = "command"
command = "SIGILL_HOST=codex /opt/sigill/sigill-hook"
timeout = 60

[[hooks.SubagentStart]]
[[hooks.SubagentStart.hooks]]
type = "command"
command = "SIGILL_HOST=codex /opt/sigill/sigill-hook"
timeout = 60

[[hooks.SubagentStop]]
[[hooks.SubagentStop.hooks]]
type = "command"
command = "SIGILL_HOST=codex /opt/sigill/sigill-hook"
timeout = 60

[[hooks.Stop]]
[[hooks.Stop.hooks]]
type = "command"
command = "SIGILL_HOST=codex /opt/sigill/sigill-hook"
timeout = 60

[[hooks.SessionEnd]]
[[hooks.SessionEnd.hooks]]
type = "command"
command = "SIGILL_HOST=codex /opt/sigill/sigill-hook"
timeout = 3
```

Developers connect once with `SIGILL_HOST=codex /opt/sigill/sigill-hook connect` (or the
`sigill-connect` skill, if you also install the plugin for its skills). Settings such as
`SIGILL_CERTIFICATE_ID` or `SIGILL_QUALIFIED=1` go in front of the command in the same way.

The same recorder runs in both hosts (`SIGILL_HOST=codex` in the Codex hooks), with its own
connection, data directory (`~/.codex/plugins/data/sigill-sigill`) and agent id
(`urn:sigill:agent:codex`). Sub-agents started with Codex's `spawn_agent` are recorded as
bound child runs exactly like Claude Code's.

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

Runs are sealed with the **Sigill Platform Seal** — an advanced electronic seal with Sigill's
organisation certificate — unless you choose a certificate of your own. To seal with your
organisation's own certificate (BYOC), set its id once:

```sh
export SIGILL_CERTIFICATE_ID=...   # Sigill → Settings → Certificates
```

The certificate is fixed when a run starts, so every step of a run has one signer.

## Options

| Variable | Default | Meaning |
|---|---|---|
| `SIGILL_CERTIFICATE_ID` | Sigill Platform Seal | Your organisation's own certificate (BYOC) |
| `SIGILL_AGENT_ID` | `urn:sigill:agent:claude-code` | `agent.id` recorded for the session |
| `SIGILL_CONSEQUENTIAL_TOOLS` | `Bash,Write,Edit,MultiEdit,NotebookEdit,mcp__*` | Tools timestamped before they run |
| `SIGILL_FAIL_CLOSED` | off | `1` blocks a consequential tool unless its step was sealed first — including when the plugin is not connected |
| `SIGILL_INDEX` | on | `0` keeps the signed envelopes local (no upload to your Evidence store) |
| `SIGILL_QUALIFIED` | off | `1` takes qualified (eIDAS) timestamps where a step is timestamped; uses your organisation's qualified timestamp quota |
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
| `PreToolUse` | `tool_call` (sealed before the tool runs); for the `Agent` tool, a `delegation` declaring the sub-agent's run |
| `PostToolUse` / `PostToolUseFailure` | `tool_result` |
| `SubagentStart` | the sub-agent's own run: Control Artifact + `run_start` bound to the `delegation` |
| hooks inside a sub-agent | events in the sub-agent's run |
| `SubagentStop` | the sub-agent's `model_output` + `run_end`, then the session's `delegation_result` |
| `Stop` | `model_output` |
| `SessionEnd` | sub-agents still running close `aborted`; then `run_end`, timestamped |

A run holds at most 2,000 events (the portable bundle limit); a longer session continues in a
new, linked run, and one event slot per running sub-agent is kept for its result. Export a
session with its sub-agents as one file: `sigill-hook export <session-id> tree.json --tree`,
and verify it at [sigill.ai/verify-run](https://sigill.ai/verify-run).

## Robustness

- A required timestamp is checked before a step counts as recorded: the seal must carry a well-formed
  RFC 3161 token whose own message imprint is bound to the seal's signature, and whose mandatory TSTInfo
  values (version, policy, serial number, UTC genTime) are valid. (This is a structural check; the TSA's
  signature is verified by verifiers, e.g. sigill.ai/verify-run.)
- With `SIGILL_FAIL_CLOSED=1`, a consequential tool (including `Agent` when listed in
  `SIGILL_CONSEQUENTIAL_TOOLS`) runs only if this hook durably sealed its step.
- A sub-agent is bound to its own run only when the pairing is unambiguous. If Claude Code later reports a
  different sub-agent for that call, a signed `checkpoint` records the contradiction, no further
  sub-agent of the session is bound, and the run closes `aborted` with that detail.
- If a step's seal fails or comes back without a valid timestamp, the run stops: nothing more is sealed
  into it, and its close is never reported as `completed`.
- Session end never waits for the signing lock: it writes its own close request, bound to the run that was
  current and to that run's resume count. The next hook, the background finalizer or a later sweep applies
  it to that run only; a session end read before a resume never closes the resumed run.
- An interrupted token refresh is never replayed: it requires `/sigill:connect` instead. The credential
  store records which backend holds the credential. A store that cannot be read (for example a locked
  keychain) is never treated as empty, and older state that is ambiguous or cannot be fully read requires
  `/sigill:connect`.
- Local state is written atomically and fsynced (file and directory). This survives a process crash; after
  power loss the drive's own cache may still lose the last write (macOS `fsync` does not flush it).
- Sign-in uses Sigill's MCP endpoint, which is stateless: each hook calls `tools/call` directly, without an
  `initialize` round trip.

## Build

```sh
./dev.sh test       # go vet + go test -race, inside a Docker volume
./dev.sh build      # cross-compile all four binaries inside the volume
./dev.sh local      # build this machine's binary into libexec/ for a real run (do not commit)
```

`dev.sh` keeps build output off the host filesystem. The shipped binaries are built and
committed by CI on every push to `main`; pull requests change sources only. The build is
reproducible with the toolchain pinned in `go.mod` — see [SECURITY.md](SECURITY.md) to verify
the binaries and to report a vulnerability. Tests include the cross-language vectors from
sigill-dotnet.

Licensed under Apache-2.0.
