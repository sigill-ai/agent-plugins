---
name: sigill-connect
description: Connect Codex to Sigill — sign in in the browser so sessions are recorded as verifiable agent evidence. Use when the user asks to connect, sign in to or set up Sigill.
---
Let <SKILL_DIR> be the absolute path of the directory that contains this SKILL.md file (this plugin installation). Run this shell command exactly as written, with <SKILL_DIR> replaced by that path (keep the quotes; never pick another installation), with a timeout of 360 seconds:

SIGILL_HOST=codex "<SKILL_DIR>/../../libexec/sigill-hook" connect

It needs network access, opens the browser and stores the connection in the macOS Keychain or the plugin's data directory, so run it outside the sandbox (request escalated permissions). It waits up to five minutes for the user to approve in the browser. Then tell the user, in one or two sentences, whether the connection succeeded (and which organisation) or why it did not. If no browser opened, show the sign-in link it printed. Do not run anything else.
