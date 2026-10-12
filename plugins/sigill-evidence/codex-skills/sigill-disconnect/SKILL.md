---
name: sigill-disconnect
description: Disconnect Codex from Sigill — revokes the connection and forgets it on this device. Use only when the user asks to disconnect or sign out of Sigill.
---
Let <SKILL_DIR> be the absolute path of the directory that contains this SKILL.md file (this plugin installation). Run this shell command exactly as written, with <SKILL_DIR> replaced by that path (keep the quotes; never pick another installation), outside the sandbox (it needs network access and the Keychain):

SIGILL_HOST=codex "<SKILL_DIR>/../../libexec/sigill-hook" disconnect

Tell the user in one sentence whether it succeeded. Do not run anything else.
