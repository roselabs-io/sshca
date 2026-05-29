# Changelog

All notable changes to `sshca` will be documented in this file.

Format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/) once we reach v1.0; until then, breaking changes can land in minor releases — see "Stability promises" in [README.md](README.md).

## [0.1.0] — 2026-05-29

Initial release.

### Added — CA management

- `sshca ca init` — generates user + host CA keypairs with correct permissions (0600). Refuses to overwrite existing CAs.
- `sshca ca show` — prints CA public keys + SHA-256 fingerprints.

### Added — Cert signing

- `sshca cert sign --ca user|host --principal X --valid +8h --key-id ID <pubkey>` — thin wrapper over `ssh-keygen -s` with required `--key-id` (the audit primary key) and sane defaults.
- Every successful sign appends a JSONL entry to `<ca-dir>/issuance-log.jsonl`. Schema documented in [CLAUDE.md](CLAUDE.md) "Contract surface."

### Added — Cert lifecycle

- `sshca cert inspect <cert-file>` — human-readable cert view (wraps `ssh-keygen -L`).
- `sshca cert renew --pubkey-file <path>` — re-signs with principals auto-inferred from the existing `<pubkey>-cert.pub`. Optional `--ship <user@host:/path>` to scp the new cert to a destination.
- `sshca cert revoke --ca user|host --key-id <ID>` — appends to local KRL at `<ca-dir>/revoked_keys.krl`. Optional `--ship <user@host:/path>` to scp the updated KRL (sshd re-reads on every connection — no reload needed).
- `sshca cert krl` — local KRL metadata.

### Added — Audit log queries

- `sshca cert list` — raw JSONL tail of the audit log (backwards-compatible default).
- `sshca cert list --principal <X>` — tabular filter to entries with a specific principal.
- `sshca cert list --expiring <DURATION>` — tabular view of certs whose expiry falls within `now + DURATION` (e.g. `24h`, `7d`, `4w`). Sorted by expires_at ascending. Catches the "cert nobody renewed" before it bites.
- `sshca cert list --expired` — already-expired certs (composable with `--expiring`).

### Added — Cross-platform

- Single Go binary for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`.

### Added — Distribution

- GitHub Actions CI: build + vet matrix on every push/PR across all six platforms.
- GitHub Actions release pipeline: on `v*` tag push, builds the six-platform matrix with `-ldflags "-X main.version=$TAG"` injection, packages as `.tar.gz` (Unix) / `.zip` (Windows), generates SHA-256 checksums, and attaches everything to an auto-released GitHub Release.

### Added — Tests

- 9 unit + integration tests covering `parseSSHKeygenDuration` (all units + edge cases), `parseExpiry` (relative / absolute / `always` / range forms), `formatTimeLeft`, and `signCert` integration paths (user CA + host CA + invalid-CA + missing-CA + audit log shape + `inferPrincipalFromCert` round-trip).

[0.1.0]: https://github.com/roselabs-io/sshca/releases/tag/v0.1.0
