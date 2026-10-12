---
name: sigill-disconnect
description: Disconnect Codex from Sigill — revokes the connection and forgets it on this device. Use only when the user asks to disconnect or sign out of Sigill.
---
Run this shell command exactly as written, outside the sandbox (it needs network access and the Keychain):

SIGILL_HOST=codex "$(ls -d "$HOME"/.codex/plugins/cache/sigill/sigill/*/libexec/sigill-hook | sort -V | tail -1)" disconnect

Tell the user in one sentence whether it succeeded. Do not run anything else.
