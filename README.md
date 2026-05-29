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

(coming when v0.1 ships)

## Usage

(coming when commands land)

## See also

- [docs/](docs/) — the full documentation tree
- [docs/decisions/inherited.md](docs/decisions/inherited.md) — upstream ADRs that motivated this tool

## License

MIT. See [LICENSE](LICENSE).
