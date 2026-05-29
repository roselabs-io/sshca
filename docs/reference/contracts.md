# Contract surface

This document declares the surface area downstream consumers depend on. **Breaking changes here require a major version bump and a deprecation cycle.** The discipline holds even when the only consumer is a sibling tool in the same `roselabs-io/` org (today: the `gateway` product and [`bastionhub`](https://github.com/roselabs-io/bastionhub)).

Three surfaces are versioned:

1. **CLI grammar** — subcommand names, flag names, argument positions, exit codes
2. **JSONL audit log schema** — field names, types, semantics at `<ca-dir>/issuance-log.jsonl`
3. **CA directory layout** — file names + locations within `<ca-dir>`

Not versioned (intentional): error message wording, help text wording, log lines emitted to stderr, output formatting of non-machine-readable command output (e.g. `cert inspect` is human-formatted; consumers should call `ssh-keygen -L` directly if parsing).

---

## 1. CLI grammar

### Stability levels

| Level | Meaning |
|---|---|
| **Stable** | Will not change name / position / type without a major version bump + 1 minor of deprecation warning. |
| **Provisional** | May change in a minor version. Used during pre-1.0 development; consumers should pin to a specific minor or wait for stabilization. |

All of v0.x is **provisional** until v1.0. Treat the table below as the *intended* stable shape; specific renames will be noted in the changelog when they occur during v0.x.

### Subcommand tree

```
sshca
├── ca
│   ├── init      [stable]   Generate user_ca + host_ca keypairs
│   └── show      [stable]   Print CA pubkeys + fingerprints
└── cert
    ├── sign      [stable]   Sign a pubkey into a cert
    ├── list      [stable]   Tail audit log; --principal / --expiring / --expired filters
    ├── inspect   [stable]   Wraps ssh-keygen -L (human output only)
    ├── renew     [stable]   Re-sign with principal inferred from existing cert
    ├── revoke    [stable]   Add to KRL, optionally ship via scp
    └── krl       [stable]   Show local KRL metadata
```

### Global flags

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--version` / `-v` | bool | false | Print version, exit 0. |
| `--help` / `-h` | bool | false | Print help, exit 0. |

### Per-command flags

#### `sshca ca init`

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--dir` | string | `./ca` (or `$SSHCA_CA_DIR`) | CA directory. |

Exit codes: `0` success, `1` directory not writeable / CA already exists.

#### `sshca ca show`

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--dir` | string | `./ca` | CA directory. |

Output (stdout): `<role>  <pubkey>` followed by `          <fingerprint-line>` for each of user CA and host CA. Format is `ssh-keygen -lf` style — consider parsing the fingerprint with `ssh-keygen -lf` directly rather than scraping this output. Exit codes: `0`, `1` (missing CA).

#### `sshca cert sign`

```
sshca cert sign --ca <user|host> --principal <X[,Y,...]> --valid <window> --key-id <ID> [--dir <path>] <pubkey-file>
```

| Flag | Type | Required | Default | Notes |
|---|---|---|---|---|
| `--ca` | string | yes | — | `user` or `host`. |
| `--principal` | string | yes | — | Comma-separated principal list. |
| `--valid` | string | no | `+8h` | `ssh-keygen -V` format: `+8h`, `+52w`, `from:to`. |
| `--key-id` | string | yes | — | Audit string baked into cert. Required (the audit primary key). |
| `--dir` | string | no | `./ca` | CA directory. |

Positional: `<pubkey-file>` — path to a pubkey file (`.pub`). Required.

Behavior:
- Validates pubkey file exists.
- Invokes `ssh-keygen -s` with appropriate flags.
- Writes `<pubkey>-cert.pub` next to the pubkey.
- Appends one JSONL entry to `<ca-dir>/issuance-log.jsonl` (schema below).
- Prints `✓ cert signed: <cert-path>` followed by `ssh-keygen -L` output of the new cert.

Exit codes: `0` success, `1` validation failure / signing failure / log write failure.

#### `sshca cert list`

| Flag | Type | Notes |
|---|---|---|
| `--principal` | string | Filter to entries containing this principal. Switches to tabular output. |
| `--expiring` | string | DURATION (`24h`, `7d`, `4w`). Show certs expiring within window. Switches to expiry table. |
| `--expired` | bool | Include already-expired certs. Combines with `--expiring`. |
| `--dir` | string | CA directory. |

Behavior:
- No flags: stdout is raw JSONL (the file content verbatim). Stable schema below.
- `--principal X` only: tabular text. Columns: KEY_ID, VALIDITY, ISSUED.
- `--expiring DUR` and/or `--expired`: tabular text. Columns: KEY_ID, PRINCIPALS, EXPIRES_AT (RFC3339), TIME_LEFT, STATUS. Sorted by EXPIRES_AT ascending.

Tabular output column widths are stable enough for fixed-width parsing but consider it human-format. For machine reading, use the raw JSONL + parse `valid` + `ts` yourself.

Exit codes: `0` success, `1` log read failure / invalid `--expiring` value.

#### `sshca cert inspect`

Positional: `<cert-file>`. Wraps `ssh-keygen -L`. Output is whatever ssh-keygen prints — consumers should call ssh-keygen directly if they need to parse.

#### `sshca cert renew`

| Flag | Type | Required | Default | Notes |
|---|---|---|---|---|
| `--pubkey-file` | string | yes | — | Pubkey to re-sign. |
| `--ca` | string | no | `user` | `user` or `host`. |
| `--principal` | string | no | inferred | If absent, parses principal from existing `<pubkey>-cert.pub`. |
| `--valid` | string | no | `+8h` | Validity window. |
| `--name` | string | no | basename of pubkey | Used as key-id prefix. |
| `--ship` | string | no | — | scp destination for the resulting cert. `user@host:/path`. |
| `--dir` | string | no | `./ca` | CA directory. |

Auto-generated key-id format: `<name>-<UTC-timestamp>` where timestamp is `YYYYMMDDTHHmmZ`.

Exit codes: `0`, `1` on any error (parse failure, sign failure, scp failure).

#### `sshca cert revoke`

| Flag | Type | Required | Notes |
|---|---|---|---|
| `--ca` | string | yes | `user` or `host`. |
| `--key-id` | string | no | Revoke by audit key-id. Most common path. |
| `--serial` | int | no | Revoke by cert serial. |
| `--pubkey-file` | string | no | Revoke a raw pubkey by file. |
| `--ship` | string | no | scp destination for the updated KRL. |
| `--dir` | string | no | CA directory. |

At least one of `--key-id`, `--serial`, `--pubkey-file` is required.

Behavior: invokes `ssh-keygen -k` (create) or `-k -u` (update) on `<ca-dir>/revoked_keys.krl`. KRL format is binary, defined by OpenSSH — do not try to parse it; use `ssh-keygen -Q -f <krl> -s <ca-pub>` to test specific revocations.

Exit codes: `0`, `1`.

#### `sshca cert krl`

| Flag | Type | Notes |
|---|---|---|
| `--dir` | string | CA directory. |

Output: file path + byte size + diagnostic command. No machine-readable output today.

### Environment variables

| Variable | Purpose |
|---|---|
| `SSHCA_CA_DIR` | Default for `--dir`. Read at command startup; explicit `--dir` overrides. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic error (invalid input, file not found, signing failure, etc.). The error message on stderr explains. |

Consumers should not depend on more granular exit codes from sshca itself. (Where sshca shells out to `ssh-keygen` and the exit is propagated, the consumer may see ssh-keygen's exit codes — but that's a leaky abstraction; treat as opaque.)

---

## 2. JSONL audit log schema

Location: `<ca-dir>/issuance-log.jsonl`. One line per `sshca cert sign` (and therefore per `sshca cert renew`, which calls sign internally). Append-only; new lines added at end, never modified.

### Schema (v0.x — stable)

```json
{
  "ts":         "<RFC3339 UTC timestamp of sign>",
  "ca":         "<user|host>",
  "key_id":     "<the --key-id value>",
  "principals": "<comma-joined principal list>",
  "valid":      "<the --valid value, e.g. '+8h' or '+52w' or 'YYYYMMDD:YYYYMMDD'>",
  "pubkey":     "<path to pubkey file at sign time>",
  "cert":       "<path to emitted -cert.pub file>"
}
```

Field details:

| Field | Type | Notes |
|---|---|---|
| `ts` | string | RFC3339 (e.g. `2026-05-29T15:19:36Z`). Always UTC. |
| `ca` | string | Always `"user"` or `"host"`. Other values reserved. |
| `key_id` | string | Verbatim copy of `--key-id`. Should be the audit primary key in downstream systems. |
| `principals` | string | Comma-joined list of principals as passed via `--principal`. No spaces around commas. |
| `valid` | string | Verbatim copy of `--valid`. Parsing required to compute expiry — see §3 below. |
| `pubkey` | string | Path the operator passed in. May be absolute or relative. May not exist anymore at read time. |
| `cert` | string | Path of the emitted `-cert.pub`. Same caveats as pubkey. |

### JSONL conventions

- One JSON object per line. No trailing comma. Newline-terminated.
- UTF-8.
- Each line is independently parseable (no cross-line references).
- New fields may be added in minor versions; consumers should ignore unknown fields.
- Existing fields will not be renamed, retyped, or removed without a major version bump.

### Computing expiry from `valid`

The `valid` field carries the same syntax as `ssh-keygen -V` accepts. To compute expiry, consumers should mirror the logic sshca uses internally:

| Input format | Expiry |
|---|---|
| `+<N><unit>` (e.g. `+8h`, `+52w`, `+30d`) | `ts + duration` |
| `<from>:<to>` where `<to>` is `+<duration>` | `ts + duration` (from sign time) |
| `<from>:<to>` where `<to>` is `YYYYMMDD` or `YYYYMMDDHHMMSS` | parse `<to>` as absolute UTC |
| `<from>:always` or `always` | no expiry |

Units recognized: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks). `d` and `w` are sshca extensions over Go's `time.ParseDuration` (which is `s`/`m`/`h` only).

`sshca cert list --expiring` does this parsing for you. Where possible, consumers should use that command rather than re-implementing.

---

## 3. CA directory layout

Within `<ca-dir>` (default `./ca`, override `$SSHCA_CA_DIR` or `--dir`):

| Path | Type | Permissions | Stability |
|---|---|---|---|
| `user_ca` | file | 0600 | Stable. User CA private key. |
| `user_ca.pub` | file | 0644 | Stable. User CA public key. |
| `host_ca` | file | 0600 | Stable. Host CA private key. |
| `host_ca.pub` | file | 0644 | Stable. Host CA public key. |
| `issuance-log.jsonl` | file | 0600 | Stable. Append-only audit log (schema in §2). |
| `revoked_keys.krl` | file | 0644 | Stable. OpenSSH KRL binary format. May not exist if no revocations yet. |

`sshca` will not create or read other paths in `<ca-dir>` in v0.x; downstream tools can use the directory for adjacent state (e.g. backup snapshots) but should namespace under a subdirectory to be future-safe.

---

## 4. Versioning policy

This repo follows [Semantic Versioning](https://semver.org/) for the contracts above.

- **Patch** (`v0.1.0` → `v0.1.1`): bug fixes, error message improvements, internal refactors. No contract changes.
- **Minor** (`v0.1.x` → `v0.2.0`): additive changes — new flags with defaults, new subcommands, new JSONL fields, new audit log files. Existing contracts unchanged.
- **Major** (`v0.x` → `v1.0`, eventually `v1` → `v2`): breaking changes to any of the three surfaces above.

**v0.x specifically**: stability is *intended* (the surfaces above are stable in design) but not *guaranteed* (renames are still possible during pre-1.0 hardening). v1.0 is the cutoff where the discipline becomes contractual.

Deprecation cycle for stable surfaces (post-v1.0):

1. Minor release introduces the new way + emits a deprecation warning when the old way is used.
2. Minor release N+1 keeps both, deprecation warning unchanged.
3. Major release removes the old way.

---

## 5. References

- [README.md](../../README.md) — public-facing pitch + Quick Start
- [docs/current-state.md](../current-state.md) — what works right now
- [docs/reference/certs.md](certs.md) — cert mechanics deep dive
- [decisions/inherited.md](../decisions/inherited.md) — upstream ADRs that informed sshca's existence
