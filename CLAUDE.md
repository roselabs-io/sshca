# sshca — contributor / agent context

Small, fast SSH-only certificate authority and management CLI. Single Go binary, two intended deps (`urfave/cli/v3` v3.9.0 + stdlib). Designed to be operable without tribal knowledge ("bus factor zero").

## Read order

1. This file
2. [README.md](README.md) — install + Quick start + Stability promises
3. [CHANGELOG.md](CHANGELOG.md) — what shipped per release
4. [main.go](main.go) + [main_test.go](main_test.go) — the entire codebase

## Project shape

**What this is:** an SSH-only cert / CA tool. Wraps `ssh-keygen -s` with sane defaults, JSONL audit, KRL UX, principal-aware renewal.

**What this isn't:**

- An X.509 / TLS cert tool. SSH-only is locked.
- A bastion / connectivity tool. That's a sibling project ([bastionhub](https://github.com/roselabs-io/bastionhub)).
- A policy engine. sshca is schema-neutral — multi-tenant policy (roles, customers, projects) lives in the consumer, not here.

## Key principles

1. **Bus factor zero.** A new hire reads the README and rotates the CA correctly. No tribal knowledge.
2. **SSH-only scope.** No X.509, no ACME, no TLS.
3. **Thin wrapper over `ssh-keygen`.** Don't reinvent crypto. Differentiate at UX + audit.
4. **JSONL audit by default.** Every sign is recorded with `key_id`, principals, validity, timestamp.
5. **Default-deny for cert grants.** Sensible defaults + explicit flags for everything that grants power.

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
- **Don't add `--principal X` cert templates as first-class flags.** Principals are policy; sshca stays schema-neutral. Templates belong in a consumer (e.g. roles.yaml in an OT-product context).

## File structure

```
sshca/
├── README.md           # public face: install, Quick start, Stability promises
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

- [bastionhub](https://github.com/roselabs-io/bastionhub) — sibling substrate (SSH bastion + reverse tunnels). Shells out to sshca for cert ops.
- Internal design notes, roadmap, current operational state, and the long-form cert-mechanics deep dive live in a private workspace (not public).
