# sshca — Project Context

A small, fast SSH-only certificate authority and management CLI. Single Go binary, two deps (`urfave/cli/v3` + `gopkg.in/yaml.v3`). Designed to be operable without tribal knowledge.

**Status:** Pre-release; scaffolding stage. Code is being migrated from the upstream `gateway` repo per [docs/decisions/inherited.md](docs/decisions/inherited.md).

## Read order for a fresh agent session

1. This file
2. [docs/current-state.md](docs/current-state.md) — what works right now
3. [docs/decisions/](docs/decisions/) — sshca's own ADRs (and [inherited.md](docs/decisions/inherited.md) for upstream decisions that motivated this repo)
4. [docs/planning/backlog.md](docs/planning/backlog.md) — open work
5. [docs/reference/](docs/reference/) — cert mechanics, contract surface, audit log schema (populates as code arrives)

## Project shape

**What this is:** an SSH-only certificate authority and management CLI. Signs short-lived certs, maintains JSONL audit, handles KRL revocation, supports renewal-by-principal-inference. Bus-factor-zero design: operable by anyone who reads the README.

**What this isn't:**

- An X.509 / TLS cert tool (see upstream ADR-006 §"Scope: SSH-only, locked")
- A bastion / connectivity tool (see upstream ADR-008 — that's `bastionhub`)
- A policy engine — sshca is schema-neutral; multi-tenant policy (`roles.yaml`) lives in the consumer (the `gateway` product)

## Key principles

1. **Bus factor zero.** A new hire reads the README and rotates the CA correctly. See upstream ADR-006 §"Design principle: bus factor zero — operable without tribal knowledge".
2. **SSH-only scope.** No X.509, no ACME, no TLS. Focus is the differentiator.
3. **Thin wrapper over `ssh-keygen`.** Don't reinvent crypto. Differentiate at the UX + audit layer. See upstream ADR-002.
4. **JSONL audit by default.** Every sign is recorded with `key_id`, principals, validity, timestamp. The audit log *is* the institutional memory.
5. **Default-deny for cert grants.** Sensible defaults + explicit flags for everything that grants power. See upstream ADR-004.

## Contract surface (semver discipline)

`sshca` exposes two contracts that downstream tools (the `gateway` product, future consumers) depend on:

- **CLI grammar** — subcommands, flags, exit codes
- **Audit log format** — JSONL schema at `<ca-dir>/issuance-log.jsonl`

Breaking changes to either require a major version bump and a deprecation cycle. The discipline holds even with one consumer today — muscle memory matters.

Schema details land in `docs/reference/contracts.md` as code arrives.

## Doc maintenance

Same trigger-action discipline as the upstream `gateway` repo:

- **Runtime change** → update [docs/current-state.md](docs/current-state.md)
- **CLI change** → update [README.md](README.md) examples
- **Non-obvious decision** → write an ADR in [docs/decisions/](docs/decisions/)
- **Backlog item ships** → strip from [docs/planning/backlog.md](docs/planning/backlog.md), add one-liner under "Recently landed" in current-state.md

## Conventions

- **Filenames:** kebab-case. ADRs: `ADR-NNN-short-description.md` (3-digit zero-padded, monotonic in this repo's own series — does *not* continue gateway's numbering).
- **Dates:** ISO `YYYY-MM-DD`.
- **Cross-references:** relative Markdown links inside this repo; absolute GitHub URLs for upstream `gateway` ADRs (see [inherited.md](docs/decisions/inherited.md)).
- **No frontmatter** on Markdown docs. Filename + path is enough.

## See also

- [README.md](README.md) — public overview
- [docs/decisions/inherited.md](docs/decisions/inherited.md) — upstream ADRs that motivated this repo
- The OT-integrator product layer that consumes `sshca` (internal — not OSS).
- [github.com/roselabs-io/bastionhub](https://github.com/roselabs-io/bastionhub) — sibling substrate tool (the SSH-bastion substrate sshca often pairs with)
