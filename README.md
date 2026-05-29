# sshca

A small, fast SSH-only certificate authority and management CLI.

**v0.1.0** — initial release. Single Go binary, one dep (`urfave/cli/v3`). Linux + macOS + Windows.

## What it does

Manages SSH certificate authorities and signs short-lived SSH certs for users and hosts. Wraps `ssh-keygen` with the things that turn it from "arcane" into "operable by anyone who reads the README":

- One-command CA init with correct permissions
- JSONL audit log auto-populated on every sign
- KRL-based revocation with one-command UX
- Cert renewal with principal auto-inference from existing certs
- `inspect` that reads like English, not raw `ssh-keygen -L` output
- `cert list --expiring 24h` to catch the cert nobody renewed before it bites
- Sensible defaults — no arcane flags

## Design principle: bus factor zero

Cert operations are notorious for being "the thing only one person knows how to do." Renewal procedures rot on Confluence. CA passphrases live in someone's head. Expiry surprises take down prod at 3am. Revocation has never actually been tested.

`sshca`'s acceptance criterion: **a new operator can rotate the CA correctly by reading this README, without asking anyone.**

## Scope

SSH certificates only. No X.509, no TLS, no ACME. The gap that justifies this tool is specifically SSH-cert ergonomics — TLS tooling is well-covered (`step-ca`, `cfssl`, ACME). Mixing both is what makes existing CA tools heavy.

## Install

### Homebrew (macOS + Linuxbrew)

```sh
brew tap roselabs-io/tools
brew install sshca
```

### From source

```sh
git clone https://github.com/roselabs-io/sshca.git
cd sshca
go build -o sshca .       # Linux, macOS
go build -o sshca.exe .   # Windows
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/roselabs-io/sshca/releases) — `.tar.gz` for Unix, `.zip` for Windows, six platforms (linux/darwin/windows × amd64/arm64), SHA-256 checksums attached.

## Quick start

```sh
# 1. Create the CA (one-time)
sshca ca init --dir ./ca

# 2. Sign a cert for an existing pubkey
sshca cert sign --ca user --principal gw-tunnel \
    --valid +8h --key-id alice-bastion-20260529 \
    --dir ./ca alice.pub
# → writes alice-cert.pub + a JSONL audit entry

# 3. Inspect any cert in human-readable form
sshca cert inspect alice-cert.pub

# 4. Tail the audit log (raw JSONL, or filter by principal for a table)
sshca cert list --dir ./ca
sshca cert list --principal gw-tunnel --dir ./ca

# 5. Catch expiring certs (e.g., in your shell prompt or a cron)
sshca cert list --expiring 24h --dir ./ca
sshca cert list --expired --dir ./ca

# 6. Renew (principal auto-inferred from the existing <pubkey>-cert.pub)
sshca cert renew --pubkey-file alice.pub --dir ./ca
# Optional: ship the resulting cert via scp
sshca cert renew --pubkey-file alice.pub --dir ./ca \
    --ship alice@laptop:/Users/alice/.ssh/

# 7. Revoke a cert
sshca cert revoke --ca user --key-id alice-bastion-20260529 --dir ./ca
# Optional: ship the KRL to the sshd that needs it (sshd re-reads every connection)
sshca cert revoke --ca user --key-id alice-bastion-20260529 --dir ./ca \
    --ship root@bastion:/etc/ssh/revoked_keys.krl
```

Override the default CA directory (`./ca`) with `--dir <path>` or `SSHCA_CA_DIR=<path>`.

## Stability promises

Pre-1.0: minor releases may break things. Breaking changes will be called out in [CHANGELOG.md](CHANGELOG.md) with the rationale.

Post-1.0: [SemVer](https://semver.org/). Two surfaces are versioned:

- **CLI grammar** — subcommand names, flag names, exit codes
- **JSONL audit log schema** at `<ca-dir>/issuance-log.jsonl` — fields: `ts`, `ca`, `key_id`, `principals`, `valid`, `pubkey`, `cert`. New fields may be added in minor releases; existing fields will not be renamed or removed without a major version bump.

See [CLAUDE.md](CLAUDE.md) "Contract surface" for details.

## Roadmap

- **v0.2** — `roselabs-io/homebrew-tools` tap; tagged release pipeline polish.
- **Soon** — CA storage upgrades (YubiKey, sealed-VPS, KMS-backed signing).
- **Later** — `sshca rotate` for full CA rotation (currently a runbook-only operation).

`sshca` is intentionally narrow. Multi-tenant policy (roles, customers, projects, principal vocabulary) belongs in the *consumer* of sshca, not here. See [bastionhub](https://github.com/roselabs-io/bastionhub) for a sibling substrate tool that pairs naturally.

## License

MIT. See [LICENSE](LICENSE).
