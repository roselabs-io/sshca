# sshca — contributor notes

SSH certificate authority and management CLI. Single Go binary, one dependency
(`urfave/cli/v3` v3.9.0) plus stdlib. The whole implementation is
[main.go](main.go).

## Scope

Certificate mechanics only. Signing is `ssh-keygen -s`; no cryptography is
implemented here.

Out of scope, deliberately:

- **X.509, TLS, ACME.** SSH certificates only.
- **Bastions and connectivity.** See
  [bastionhub](https://github.com/roselabs-io/bastionhub), which calls
  `sshca cert sign`.
- **Policy.** No roles, customers or environments, and no issuance rules. Any
  caller that can run the binary can sign anything the CA can sign.
- **Alternative key custody.** CA keys are files at mode 0600, on one machine.
  PKCS#11 tokens and KMS backends are not planned; a caller needing different
  custody wraps `cert sign`.

## Contract surface

Two things callers depend on. Breaking either requires a major version bump.

**CLI grammar** — subcommand names, flag names, argument positions, exit codes.
`sshca --help` is canonical.

**Issuance log schema** at `<ca-dir>/issuance-log.jsonl`, one line per
signature:

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

Fields may be added in a minor release. Consumers should ignore unknown fields.

## Constraints worth knowing

- **`Match Principal` is not valid `sshd_config` syntax.** `Match` accepts
  `User`, `Group`, `Host`, `LocalAddress`, `LocalPort`, `RDomain` and `Address`
  only. Role enforcement uses `Match User`, because OpenSSH requires a
  certificate's principal to match the target username.
- **`--key-id` is required on every signature.** It is the issuance log's
  primary key and the string that appears in sshd's auth log.
- **CA private keys are 0600.** `ca/user_ca` and `ca/host_ca`.
- **`version` in `main.go` is a `var`, not a `const`**, so release builds can
  inject the tag with `-ldflags "-X main.version=<tag>"`.

## Conventions

- Filenames: kebab-case.
- Dates: ISO `YYYY-MM-DD`.
- No YAML frontmatter in Markdown.
