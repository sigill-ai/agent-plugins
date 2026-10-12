---
name: sigill-status
description: Show the Sigill recorder's connection, configuration and any unfinished runs. Use when the user asks whether Sigill is connected or recording.
---
Run this shell command exactly as written (it reads the Keychain, so run it outside the sandbox if it is blocked):

SIGILL_HOST=codex "$(ls -d "$HOME"/.codex/plugins/cache/sigill/sigill/*/libexec/sigill-hook | sort -V | tail -1)" status

Summarise the output for the user in a few lines. Do not run anything else.
