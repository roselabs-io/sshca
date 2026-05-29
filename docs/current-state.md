# Current state

> What works right now in `sshca`. Updated on every change.

## Status

**v0.1.0-dev** — core cert/CA commands implemented and smoke-tested end-to-end. Single ~5 MB binary, one dep (`urfave/cli/v3` v3.9.0).

## What works

- `sshca ca init` — generates `user_ca` + `host_ca` keypairs with correct perms (0600)
- `sshca ca show` — prints CA pubkeys + SHA256 fingerprints
- `sshca cert sign --ca user|host --principal X --valid +8h --key-id ID <pubkey>` — signs a cert; writes a JSONL audit entry
- `sshca cert list` — raw JSONL tail of the audit log; `--principal X` switches to a tabular filter; `--expiring DURATION` and `--expired` switch to an expiry-based view (composable with `--principal`)
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

- **2026-05-29** — Release pipeline + unit tests shipped. `.github/workflows/release.yml` triggered on `v*` tag push builds the 6-platform matrix with `-ldflags "-X main.version=<tag>"` injection, packages each binary as `.tar.gz` (Unix) / `.zip` (Windows), generates SHA-256 checksums, and attaches everything to an auto-released GitHub Release. `main.go`'s `version` flipped from `const` to `var` to enable the injection. 9 unit + integration tests in `main_test.go` cover `parseSSHKeygenDuration` (all units + negative + error cases), `parseExpiry` (relative / absolute / `always` / range forms), `formatTimeLeft` (signed truncated durations), and `signCert` integration (user-CA + host-CA happy paths + audit log shape + `inferPrincipalFromCert` round-trip + invalid-CA + missing-CA errors). All pass locally; CI's previously-vacuous `go test ./...` step now has real coverage.
- **2026-05-29** — GitHub Actions CI shipped at `.github/workflows/ci.yml`. 6-platform matrix (linux/darwin/windows × amd64/arm64) runs `go vet` + `go build` per cell on every push to main and every PR. `go test ./...` runs once on linux/amd64 as a placeholder (no test files yet — will become valuable once `parseSSHKeygenDuration`/`parseExpiry`/`inferPrincipalFromCert` get unit tests). Locally-validated: all 6 cells pass vet + build (binary sizes 5.3-5.6 MB across platforms).
- **2026-05-29** — [docs/reference/contracts.md](reference/contracts.md) shipped. Declares the three semver-disciplined surfaces downstream consumers depend on (CLI grammar, JSONL audit log schema, CA directory layout). All of v0.x is *intended-stable but provisional*; v1.0 is the cutoff where the discipline becomes contractual. Documents exit-code conventions, environment variables, expiry-parsing semantics for the `valid` field, and the deprecation cycle for breaking changes.
- **2026-05-29** — `sshca cert list --expiring [DURATION]` + `--expired` shipped. Parses the JSONL `valid` field, computes expiry, filters certs by status. Tabular output with KEY_ID, PRINCIPALS, EXPIRES_AT, TIME_LEFT, STATUS. Composable with `--principal`. Validated against Patrick's live audit log — correctly surfaces the gw-user certs from 2026-05-28 that expired overnight, the freshly renewed one expiring in ~7h, and the +52w tunnel + host certs.
- **2026-05-29** — Cert mechanics reference doc ported from upstream `gateway/docs/reference/ssh/certs.md` → [docs/reference/certs.md](reference/certs.md). Adapted to sshca's standalone context (CLI commands shown as `sshca cert sign` not `gwctl cert sign`; §8 principal taxonomy framed as one OT-flavored worked example, not the canonical schema). Gateway repo's references updated to point to this copy.
- **2026-05-29** — v0.1.0-dev: cert/CA code migrated from upstream [`roselabs-io/gateway`](https://github.com/roselabs-io/gateway). Cleanups during the move:
  - `--ship-bastion` (which depended on gateway-product config) → generic `--ship DEST` taking an explicit scp target
  - `user issue/revoke/list` subcommands dropped — their functionality is already `cert sign --principal X` / `cert list --principal X` / `cert revoke --key-id X`, keeping sshca schema-neutral per upstream ADR-006
  - `GWCTL_CA_DIR` env var → `SSHCA_CA_DIR`
  - All usage strings rebranded from `gwctl` → `sshca`
- **2026-05-29** — Repo created, doc structure seeded.

## What's NOT here yet

- **First tagged release + Homebrew tap.** Release pipeline is in place (`.github/workflows/release.yml` on `v*` tag push). Tag `v0.1.0` to trigger the first GitHub Release; then the `roselabs-io/homebrew-tools` tap can land pointing at the release artifacts.

## See also

- [decisions/inherited.md](decisions/inherited.md) — the upstream decisions that motivated this repo
- [planning/backlog.md](planning/backlog.md) — what's coming next
