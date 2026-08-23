# sshca — contributor / agent context

SSH certificate authority and management CLI. Single Go binary, one dependency (`urfave/cli/v3` v3.9.0) plus stdlib.

## Read order

1. This file
2. [README.md](README.md) — commands, usage, stability
3. [CHANGELOG.md](CHANGELOG.md) — what shipped per release
4. [main.go](main.go) + [main_test.go](main_test.go) — the entire codebase

## Project shape

**What this is:** an SSH-only certificate tool. Wraps `ssh-keygen -s`, adding a JSONL issuance log, KRL revocation, and renewal that reads principals from an existing certificate.

**What this isn't:**

- An X.509 / TLS cert tool. SSH-only is locked.
- A bastion / connectivity tool. That's a sibling project ([bastionhub](https://github.com/roselabs-io/bastionhub)).
- A policy engine. sshca is schema-neutral — multi-tenant policy (roles, customers, projects) lives in the consumer, not here.

## Constraints

1. **SSH only.** No X.509, no ACME, no TLS.
2. **No cryptography implemented here.** All signing is `ssh-keygen -s`.
3. **Every signature is logged.** `key_id` is required for that reason.
4. **Schema-neutral.** No roles, customers or environments. Policy belongs in the caller.
5. **One issuing machine.** CA keys are files at mode 0600. PKCS#11 and KMS backends are out of scope; a caller needing different custody wraps `cert sign`.

## Contract surface (semver-disciplined)

Two things downstream tools depend on. Breaking changes to either require a major version bump.

**CLI grammar:** subcommand names, flag names, argument positions, exit codes. `sshca --help` is canonical.

**JSONL audit log schema** at `<ca-dir>/issuance-log.jsonl`. One line per sign:

```json
{
  "ts":         "<RFC3339 UTC timestamp>",
  "ca":         "user|host",
  "key_id":     "<from --key-id>",
  "principals": "<comma-joined>",
  "valid":      "<from --valid, e.g. '+8h' or '+52w'>",
  "pubkey":     "<path passed in>",
  "cert":       "<path of emitted -cert.pub>"
}
```

Consumers should ignore unknown fields (new fields may appear in minor releases).

## Don't re-walk these

- **Don't use `Match Principal` in sshd_config.** Not valid OpenSSH syntax — `Match` only accepts `User`, `Group`, `Host`, `LocalAddress`, `LocalPort`, `RDomain`, `Address`. Use `Match User <role>` blocks for cert-auth role enforcement; the cert's principal list matches the target Unix username by default.
- **Don't `chmod` CA private keys casually.** `ca/user_ca` and `ca/host_ca` are 0600 by design.
- **Don't add YAML frontmatter to Markdown docs.** Filename + path is enough.
- **Don't add principal templates as first-class flags.** Principals are policy; sshca stays schema-neutral. Templates belong in a caller.

## File structure

```
sshca/
├── README.md           # commands, usage, stability
├── CHANGELOG.md        # per-release
├── CLAUDE.md           # this file
├── LICENSE             # MIT
├── main.go             # everything
├── main_test.go        # unit + integration tests
├── go.mod / go.sum
└── .github/workflows/  # CI + release
```

## Conventions

- **Filenames:** kebab-case
- **Dates:** ISO `YYYY-MM-DD`
- **No YAML frontmatter** on Markdown docs
- **Version variable** in `main.go` is `var` not `const` so release builds inject the tag via `-ldflags "-X main.version=<tag>"`

## See also

- [bastionhub](https://github.com/roselabs-io/bastionhub) — SSH bastion and reverse tunnels. Calls `sshca cert sign` for certificate operations.
- Internal design notes, roadmap, current operational state, and the long-form cert-mechanics deep dive live in a private workspace (not public).
