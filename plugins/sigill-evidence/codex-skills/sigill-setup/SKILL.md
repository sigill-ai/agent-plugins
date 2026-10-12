---
name: sigill-setup
description: Set up Sigill recording for Codex step by step — sign in, review the hooks, then confirm a session is actually recorded. Use when the user installs Sigill, asks to set it up, or recording does not seem to work.
---
Guide the user through three steps. Let <SKILL_DIR> be the absolute path of the directory that contains this SKILL.md file (this plugin installation); never pick another installation.

1. Sign in. Run, outside the sandbox (it needs network access and the Keychain), with a timeout of 360 seconds:

   SIGILL_HOST=codex "<SKILL_DIR>/../../libexec/sigill-hook" connect

   Report whether it connected and to which organisation. A successful sign-in does NOT mean recording works yet.

2. Review the hooks. Codex runs a plugin's hooks only after the user has reviewed them, and again after every plugin update. Tell the user to type /hooks, check that the Sigill hooks are listed, and press t to trust them. (Organisations can deploy them as managed hooks instead; see the plugin README.)

3. Confirm. Ask the user to start a NEW Codex session, run one shell command in it, and then run:

   SIGILL_HOST=codex "<SKILL_DIR>/../../libexec/sigill-hook" status

   Recording is confirmed only when status shows a hook delivery by this version and a "last step sealed" time from that new session. If not, say which of the three steps is missing. Do not run anything else.
