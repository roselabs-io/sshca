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
| `rotate` | Replace the user or host CA and re-sign its certificates. See [CA rotation](#ca-rotation). |

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
encrypted. Replacing a CA that still exists is `sshca rotate`
([CA rotation](#ca-rotation)).

## CA rotation

`sshca rotate --ca user|host` replaces one CA. It does the following, in order:

1. Refuses to run when `<ca>_ca.prev` exists (a rotation of that CA is in
   progress) or when `<ca>_ca` is missing.
2. Renames `<ca>_ca` and `<ca>_ca.pub` to `<ca>_ca.prev` and `<ca>_ca.prev.pub`.
3. Generates a new ed25519 `<ca>_ca` (mode 0600) and `<ca>_ca.pub`. If
   generation fails, the renamed files are moved back.
4. Writes `<ca>_ca.transition.pub`: the new public key, then the old one, one
   per line.
5. Re-signs, with the new CA, each certificate in the issuance log that was
   signed by that CA. For each public key path, only the latest log entry is
   used. The re-signed certificate keeps the key ID and principals, overwrites
   `<name>-cert.pub`, and gets a new issuance log entry. A relative validity
   (`+8h`, or a range ending in `+…`) becomes `+<seconds>s`, the time left on the
   old certificate; any other validity is passed to `ssh-keygen -V` unchanged.

A log entry is skipped, and listed in the output with the reason, when its
public key file or its certificate file is missing, when the certificate has
expired, when its logged validity cannot be parsed, or when the local KRL
(`revoked_keys.krl`) revokes the certificate. The command exits 1 if any
re-signature or KRL check fails; the new CA and the transition file stay in
place.

| File in the CA directory | Content after `sshca rotate --ca user` |
|---|---|
| `user_ca`, `user_ca.pub` | the new CA |
| `user_ca.prev`, `user_ca.prev.pub` | the CA before the rotation |
| `user_ca.transition.pub` | both public keys, new first |

### Runbook: user CA

The bastion and every endpoint run sshd with `TrustedUserCAKeys` pointing at a
file holding the user CA public key; `/etc/ssh/user_ca.pub` below.

1. Rotate on the CA machine:

   ```sh
   sshca rotate --ca user --dir ./ca
   ```

2. Trust both CAs. On the bastion and on every endpoint, replace the trusted
   key file with the transition file:

   ```sh
   scp ./ca/user_ca.transition.pub root@bastion:/etc/ssh/user_ca.pub
   ```

   sshd reads the file at each authentication, so no reload is needed unless
   the `TrustedUserCAKeys` path itself changed. Certificates from either CA are
   accepted from here on.

3. Deliver the re-signed certificates listed in the output to their holders
   (`scp`, or `sshca cert renew --ship` for a later renewal). For each skipped
   key that still needs access, run `sshca cert sign` or `sshca cert renew`;
   both use the new CA.

4. Check that each certificate in use is signed by the new CA: the
   `Signing CA` fingerprint in `sshca cert inspect <cert>` equals the user CA
   fingerprint in `sshca ca show`. Log in to the bastion and to each endpoint
   with a new certificate.

5. Trust only the new CA. On the bastion and on every endpoint:

   ```sh
   scp ./ca/user_ca.pub root@bastion:/etc/ssh/user_ca.pub
   ```

   Certificates signed by the old CA stop working on the next connection.

6. Delete the old CA and the transition file on the CA machine:

   ```sh
   rm ./ca/user_ca.prev ./ca/user_ca.prev.pub ./ca/user_ca.transition.pub
   ```

### Runbook: host CA

Clients trust the host CA with a `@cert-authority <host-pattern> <key>` line in
`known_hosts`. Each host presents the certificate named by `HostCertificate` in
its `sshd_config`.

1. Rotate: `sshca rotate --ca host --dir ./ca`.
2. On every client, add a `@cert-authority` line for the new key, keeping the
   one for the old key. Each line of `host_ca.transition.pub` is one key.
3. Install each re-signed host certificate at the host's `HostCertificate`
   path and reload sshd (`systemctl reload ssh`); sshd reads host certificates
   at startup only.
4. Connect to each host from a client; no host-key prompt appears.
5. On every client, remove the `@cert-authority` line for the old key.
6. Delete `host_ca.prev`, `host_ca.prev.pub` and `host_ca.transition.pub`.

### Revocation during a rotation

KRL entries by key ID or serial apply to one CA. `sshca cert revoke --key-id`
uses the current `<ca>_ca.pub`, so between steps 1 and 5 it revokes the new
certificate and leaves the old one valid. Revoke by `--pubkey-file` instead: a
KRL entry for a public key revokes that key and every certificate of it,
whichever CA signed it.

Revocations by key ID or serial made before the rotation do not apply to
certificates the new CA signs later. `sshca rotate` does not re-sign a
certificate the KRL revokes.

### Rollback and irreversible steps

Until step 5, a rotation is undone on the CA machine by restoring the old CA:

```sh
mv ./ca/user_ca.prev ./ca/user_ca
mv ./ca/user_ca.prev.pub ./ca/user_ca.pub
rm ./ca/user_ca.transition.pub
```

then putting the old public key back in each trusted key file (or
`known_hosts`), and running `sshca cert renew` for each key that `sshca rotate`
re-signed: its earlier certificate file was overwritten.

These steps cannot be undone:

| Step | Effect |
|---|---|
| `sshca rotate`, step 5 of the command | each re-signed `<name>-cert.pub` is overwritten; the old certificate exists only where it was delivered |
| Runbook step 5 (trust only the new CA) | a holder with only an old-CA certificate loses access. An endpoint where no remaining certificate is accepted is reachable only by break-glass access (console, or a key outside the CA) |
| Runbook step 6 (delete `<ca>_ca.prev`) | the old CA can no longer sign, so the rollback above is no longer possible |

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
