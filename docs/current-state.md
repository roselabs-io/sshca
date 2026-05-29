# Current state

> What works right now in `sshca`. Updated on every change.

## Status

**v0.1.0-dev** — core cert/CA commands implemented and smoke-tested end-to-end. Single ~5 MB binary, one dep (`urfave/cli/v3` v3.9.0).

## What works

- `sshca ca init` — generates `user_ca` + `host_ca` keypairs with correct perms (0600)
- `sshca ca show` — prints CA pubkeys + SHA256 fingerprints
- `sshca cert sign --ca user|host --principal X --valid +8h --key-id ID <pubkey>` — signs a cert; writes a JSONL audit entry
- `sshca cert list` — raw JSONL tail of the audit log; `--principal X` switches to a tabular filter
- `sshca cert inspect <cert-file>` — human-readable cert contents (wraps `ssh-keygen -L`)
- `sshca cert renew --pubkey-file PATH [--ship DEST]` — re-signs with principal auto-inferred from the existing `<pubkey>-cert.pub`; optional scp to a destination
- `sshca cert revoke --ca user|host --key-id ID [--ship DEST]` — adds the cert to the local KRL; optional scp to a destination sshd
- `sshca cert krl` — local KRL metadata

The CA directory defaults to `./ca`; override with `--dir` or `$SSHCA_CA_DIR`.

## Audit log contract

`<ca-dir>/issuance-log.jsonl`, one line per sign:

```json
{"ts":"2026-05-29T15:19:36Z","ca":"user","key_id":"alice-smoke-1","principals":"gw-tunnel","valid":"+8h","pubkey":"alice.pub","cert":"alice-cert.pub"}
```

This schema is part of sshca's contract surface — downstream tools (the `gateway` product, future consumers) depend on it. Will be formalized in `docs/reference/contracts.md` (TBD).

## Recently landed

- **2026-05-29** — v0.1.0-dev: cert/CA code migrated from upstream [`roselabs-io/gateway`](https://github.com/roselabs-io/gateway). Cleanups during the move:
  - `--ship-bastion` (which depended on gateway-product config) → generic `--ship DEST` taking an explicit scp target
  - `user issue/revoke/list` subcommands dropped — their functionality is already `cert sign --principal X` / `cert list --principal X` / `cert revoke --key-id X`, keeping sshca schema-neutral per upstream ADR-006
  - `GWCTL_CA_DIR` env var → `SSHCA_CA_DIR`
  - All usage strings rebranded from `gwctl` → `sshca`
- **2026-05-29** — Repo created, doc structure seeded.

## What's NOT here yet

- Cert mechanics reference doc (port from upstream `gateway/docs/reference/ssh/certs.md`) — backlog item #1
- `docs/reference/contracts.md` — semver-disciplined surface for downstream consumers — backlog item #2
- CI/CD — no GitHub Actions yet
- Distribution — no Homebrew tap, no `go install` instructions yet

## See also

- [decisions/inherited.md](decisions/inherited.md) — the upstream decisions that motivated this repo
- [planning/backlog.md](planning/backlog.md) — what's coming next
