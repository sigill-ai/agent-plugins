# Security

## Reporting a vulnerability

Email **security@sigill.ai**. Please do not open a public issue for a security problem.

We acknowledge within 1 business day and send a status update within 3 business days.
Good-faith research is welcome; scope, safe-harbor terms and what helps a report move
faster are described at
[sigill.ai/trust-center/responsible-disclosure](https://sigill.ai/trust-center/responsible-disclosure).
We ask for a fair window to fix a confirmed issue before publication, typically 90 days.

In scope for this repository: the `sigill-hook` recorder, its hooks and commands, the
sign-in flow on the device, credential storage, and the build that produces the binaries.

## What you install

The plugin runs the prebuilt `sigill-hook` binary for your platform from
`plugins/sigill-evidence/libexec/`. Those binaries are reproducible: CI rebuilds them from
this source on every push and fails if a single byte differs from what is committed. To check
for yourself, with the Go toolchain named in `go.mod`:

```sh
./build.sh
git diff --exit-code -- plugins/sigill-evidence/libexec   # no output: identical
cd plugins/sigill-evidence/libexec && sha256sum -c SHA256SUMS
```

## Security model, briefly

- **Blind.** Only digests and evidence metadata leave the machine. Prompts, tool input and
  output, and file contents are hashed locally and never sent.
- **Sign-in, not keys.** `/sigill:connect` uses OAuth with PKCE against your Sigill account.
  The resulting credential is limited to recording agent evidence, is bound to this device,
  and is kept in the macOS Keychain or the Secret Service on Linux (a user-only file when
  neither is available). `/sigill:disconnect` revokes it.
- **What it proves.** Each step is sealed and timestamped as it happens, so a recorded run
  cannot later be altered without detection. It does not prove that every step was
  recorded: the recorder runs with your user's privileges, and code running as the same
  user can interfere with it.
