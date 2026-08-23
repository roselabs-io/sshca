# sshca

An SSH certificate authority and management CLI. Single Go binary, one
dependency (`urfave/cli/v3`). Linux, macOS and Windows.

SSH certificates only — no X.509, no TLS, no ACME.

## Overview

`sshca` maintains a local certificate authority and signs SSH certificates for
users and hosts. It wraps `ssh-keygen`; it implements no cryptography of its
own.

A certificate binds a public key to a set of principals, a validity window
enforced by sshd, and a key ID recorded in an append-only log. A server
configured with `TrustedUserCAKeys` accepts any certificate signed by that CA,
so per-machine `authorized_keys` files are not required.

Beyond `ssh-keygen`, `sshca` adds:

- CA creation with correct file permissions
- A JSONL issuance log written on every signature
- KRL-based revocation addressed by key ID, serial, or public key file
- Renewal that reads principals from an existing certificate
- Expiry queries over the issuance log
- Optional `scp` of a signed certificate or updated KRL to a remote path

## Install

### Homebrew (macOS and Linuxbrew)

```sh
brew tap roselabs-io/tools
brew trust roselabs-io/tools   # recent Homebrew refuses third-party taps otherwise
brew install sshca
```

### Pre-built binaries

[GitHub Releases](https://github.com/roselabs-io/sshca/releases) — `.tar.gz`
for Unix, `.zip` for Windows, six platforms (linux/darwin/windows ×
amd64/arm64), with SHA-256 checksums.

### From source

```sh
git clone https://github.com/roselabs-io/sshca.git
cd sshca
go build -o sshca .       # Linux, macOS
go build -o sshca.exe .   # Windows
```

## Commands

| Command | Description |
|---|---|
| `ca init` | Generate `user_ca` and `host_ca` keypairs. Refuses to overwrite existing keys. |
| `ca show` | Print CA public keys and fingerprints. |
| `cert sign` | Sign a public key. Requires `--ca`, `--principal`, `--key-id`. |
| `cert list` | Read the issuance log. JSONL by default; `--principal`, `--expiring` and `--expired` produce a table. |
| `cert inspect` | Show a certificate's contents. Wraps `ssh-keygen -L`. |
| `cert renew` | Re-sign a public key, taking principals from its existing certificate. |
| `cert revoke` | Add a KRL entry by `--key-id`, `--serial` or `--pubkey-file`. |
| `cert krl` | Show local KRL metadata. |

The CA directory defaults to `./ca` and is overridden by `--dir <path>` or
`SSHCA_CA_DIR`.

## Usage

```sh
# Create the CA. One time.
sshca ca init --dir ./ca

# Sign a public key.
sshca cert sign --ca user --principal gw-tunnel \
    --valid +8h --key-id alice-bastion-20260529 \
    --dir ./ca alice.pub
# Writes alice-cert.pub and appends to the issuance log.

# Read a certificate.
sshca cert inspect alice-cert.pub

# Read the issuance log.
sshca cert list --dir ./ca
sshca cert list --principal gw-tunnel --dir ./ca

# Query expiry.
sshca cert list --expiring 24h --dir ./ca
sshca cert list --expired --dir ./ca

# Renew. Principals are read from the existing alice-cert.pub.
sshca cert renew --pubkey-file alice.pub --dir ./ca
sshca cert renew --pubkey-file alice.pub --dir ./ca \
    --ship alice@laptop:/Users/alice/.ssh/

# Revoke. sshd re-reads the KRL on every connection.
sshca cert revoke --ca user --key-id alice-bastion-20260529 --dir ./ca
sshca cert revoke --ca user --key-id alice-bastion-20260529 --dir ./ca \
    --ship root@bastion:/etc/ssh/revoked_keys.krl
```

`--valid` accepts `ssh-keygen` syntax: a relative window such as `+8h` or
`+52w`, or an absolute range such as `20260601:20260701`. The default is `+8h`.

## CA key storage

The CA private keys are files in the CA directory, mode 0600, without a
passphrase. There is one issuing machine.

PKCS#11 tokens, KMS-backed signing and sealed hosts are not supported and are
not planned. Callers requiring different custody can wrap `sshca cert sign`,
which is the intended extension point.

Losing the CA directory means the CA cannot issue or renew any certificate, and
every server trusting it must be reconfigured with a new CA. Back it up
encrypted.

## Scope

Certificate mechanics only. `sshca` has no concept of users, roles, customers
or environments, and applies no issuance policy — any caller that can run the
binary can sign anything the CA can sign. Policy belongs in the caller.

[bastionhub](https://github.com/roselabs-io/bastionhub) is one such caller.

## Stability

Pre-1.0: minor releases may include breaking changes, documented in
[CHANGELOG.md](CHANGELOG.md).

Post-1.0: [SemVer](https://semver.org/), covering two surfaces.

- **CLI grammar** — subcommand names, flag names, exit codes.
- **Issuance log schema** at `<ca-dir>/issuance-log.jsonl` — fields `ts`, `ca`,
  `key_id`, `principals`, `valid`, `pubkey`, `cert`. Fields may be added in a
  minor release; existing fields are not renamed or removed without a major
  version bump.

## License

MIT. See [LICENSE](LICENSE).
