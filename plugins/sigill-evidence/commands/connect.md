---
description: Connect Claude Code to Sigill — sign in in your browser so sessions are recorded as verifiable agent evidence
allowed-tools: Bash(CLAUDE_PLUGIN_DATA="${CLAUDE_PLUGIN_DATA}" "${CLAUDE_PLUGIN_ROOT}/libexec/sigill-hook" connect)
---
Run this command with the Bash tool and a timeout of 360000 ms, exactly as written:

CLAUDE_PLUGIN_DATA="${CLAUDE_PLUGIN_DATA}" "${CLAUDE_PLUGIN_ROOT}/libexec/sigill-hook" connect

It opens the browser for Sigill sign-in and waits up to five minutes for the user to approve. Then tell the user, in one or two sentences, whether the connection succeeded (and which organisation) or why it did not. If it failed because no browser opened, show the sign-in link it printed. Do not run anything else.
