---
name: sigill-status
description: Show the Sigill recorder's connection, configuration and any unfinished runs. Use when the user asks whether Sigill is connected or recording.
---
Let <SKILL_DIR> be the absolute path of the directory that contains this SKILL.md file (this plugin installation). Run this shell command exactly as written, with <SKILL_DIR> replaced by that path (keep the quotes; never pick another installation) (it reads the Keychain, so run it outside the sandbox if it is blocked):

SIGILL_HOST=codex "<SKILL_DIR>/../../libexec/sigill-hook" status

Summarise the output for the user in a few lines. Do not run anything else.
