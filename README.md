# sshca

A small, fast SSH certificate authority and management CLI.

**Status:** Pre-release. Scaffolding stage — code is being migrated from the upstream `gateway` repo.

## What it does

Manages SSH certificate authorities and signs short-lived SSH certs for users and hosts. Wraps `ssh-keygen` with the things that turn it from "arcane" into "operable by anyone who reads the README":

- One-command CA init with correct permissions
- JSONL audit log auto-populated on every sign
- KRL-based revocation with one-command UX
- Cert renewal with principal auto-inference from existing certs
- `inspect` that reads like English, not raw `ssh-keygen -L` output
- Sensible defaults — no arcane flags

## Design principle: bus factor zero

Cert operations are notorious for being "the thing only one person knows how to do." Renewal procedures rot on Confluence. CA passphrases live in someone's head. Expiry surprises take down prod at 3am. Revocation has never actually been tested.

`sshca`'s acceptance criterion: **a new hire can rotate the CA correctly by reading this README, without asking anyone.**

## Scope

SSH certificates only. No X.509, no TLS, no ACME. The gap that justifies this tool is specifically SSH-cert ergonomics — TLS tooling is well-covered (`step-ca`, `cfssl`, ACME). Mixing both is what makes existing CA tools heavy.

## Install

From source (until Homebrew tap lands):

```sh
git clone https://github.com/roselabs-io/sshca.git
cd sshca
go build -o sshca .
```

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

# 5. Renew (principal auto-inferred from the existing <pubkey>-cert.pub)
sshca cert renew --pubkey-file alice.pub --dir ./ca
# Optional: ship the resulting cert via scp
sshca cert renew --pubkey-file alice.pub --dir ./ca \
    --ship alice@laptop:/Users/alice/.ssh/

# 6. Revoke a cert
sshca cert revoke --ca user --key-id alice-bastion-20260529 --dir ./ca
# Optional: ship the KRL to the sshd that needs it
sshca cert revoke --ca user --key-id alice-bastion-20260529 --dir ./ca \
    --ship root@bastion:/etc/ssh/revoked_keys.krl
```

Override the default CA directory (`./ca`) with `--dir <path>` or `SSHCA_CA_DIR=<path>`.

## See also

- [docs/](docs/) — the full documentation tree
- [docs/decisions/inherited.md](docs/decisions/inherited.md) — upstream ADRs that motivated this tool

## License

MIT. See [LICENSE](LICENSE).
