# SSH certificates — what they actually are and why they win

The conceptual + mechanical reference for SSH certificates as used by `sshca`. Standalone read: covers what's in a cert, how verification works, what the CA actually is, where each artifact lives, and the design patterns that emerge when you build a real cert-based auth deployment.

For engineers who've used SSH keys forever and want to understand certificates from the bytes up — what's inside one, how verification works, when they're worth it, when they're not.

This doc was ported from the upstream [`gateway`](https://github.com/roselabs-io/gateway) repo (the OT-integrator project that motivated sshca's bus-factor-zero design) — see [docs/decisions/inherited.md](../decisions/inherited.md). The OT-flavored principal taxonomy in §8 reflects that origin; the rest is general SSH cert knowledge applicable to any cert deployment.

> *Doc note:* §6 and §8 originally used `Match Principal <role>` syntax which is **not valid OpenSSH** (`Match` only takes `User`, `Group`, `Host`, `LocalAddress`, `LocalPort`, `RDomain`, `Address`). Corrected during a V0.6 walking-skeleton deploy in the upstream project; the actual mechanism is "principal matches target Unix username by default, override with `AuthorizedPrincipalsFile`/`Command`, role restrictions live in `Match User` blocks." See §6 and §8 below for the corrected patterns.

---

## 1. The mental model: trust shifts up one level

With **raw keys**, the server holds a list of every public key it trusts (`authorized_keys`). To grant access: add a line. To revoke: remove a line. **The server is the source of truth for identity.**

With **certificates**, the server holds the public key of a **Certificate Authority** (CA). The CA signs short-lived certificates that bind a public key to a set of claims (who, what role, when, from where). Servers trust *anyone the CA vouched for* without ever seeing the individual keys. **The CA is the source of truth for identity; the server is just a verifier.**

```
Raw keys                                  Certificates

┌──────────┐                              ┌──────────┐
│  client  │                              │  client  │
└────┬─────┘                              └────┬─────┘
     │ pubkey                                  │ pubkey + cert
     ▼                                         ▼
┌─────────────────────┐                   ┌────────────────────────┐
│  server checks      │                   │  server checks:        │
│  authorized_keys    │                   │   1. signature valid?  │
│  for THIS pubkey    │                   │   2. CA trusted?       │
└─────────────────────┘                   │   3. principal OK?     │
                                          │   4. validity window?  │
                                          │   5. source addr OK?   │
                                          │   6. KRL miss?         │
                                          └────────────────────────┘
```

That shift — from "the server's `authorized_keys` IS the policy" to "the CA's *signing process* IS the policy" — is the whole point. It's the same shift that x509 made for HTTPS in the 90s, just two decades late to SSH.

---

## 2. What's *in* a certificate (the binary structure)

An SSH certificate is a public key with signed metadata. Concretely, the binary structure (RFC: [PROTOCOL.certkeys](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys) in the OpenSSH source):

| Field | What it carries |
|---|---|
| `nonce` | 32 random bytes — prevents signature collision attacks |
| `public key` | The actual pubkey being certified (e.g. ed25519 point) |
| `serial` | 64-bit issuer-assigned number, useful for revocation by serial |
| `type` | `SSH2_CERT_TYPE_USER` (1) or `SSH2_CERT_TYPE_HOST` (2) — these are different things, see §4 |
| `key_id` | **Free-form audit string.** Whatever the issuer wrote. Logged on auth — this is your audit primary key. Put `patrick@perso-mbp-2026-05-28T14:30Z-by-deploy-bot` and you'll thank yourself later. |
| `valid_principals` | List of allowed principals — for user certs, these are usernames or role-names the cert authorizes (`gw-user`, `debugger`, etc.); for host certs, these are hostnames |
| `valid_after` | UNIX timestamp — earliest second the cert is valid |
| `valid_before` | UNIX timestamp — first second the cert is no longer valid |
| `critical options` | Restrictions the **server MUST** understand or reject the cert (see §9) |
| `extensions` | Permissions the server *may* ignore if unknown (see §9) |
| `reserved` | Always empty in current spec |
| `signature key` | The CA's public key — tells the verifier *which* CA signed this |
| `signature` | The CA's signature over everything above |

Critically: **the signature covers the metadata.** You cannot tamper with principals, validity, or restrictions without invalidating the signature. The CA's signing operation is the trust event.

Inspect any cert with:

```bash
sshca cert inspect id_ed25519-cert.pub
# or equivalently
ssh-keygen -L -f id_ed25519-cert.pub
```

Output:

```
id_ed25519-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:qKvY+iHwhcmm2gIxAoFsVjUc8o7D1dQ7GH+IYB0725U
        Signing CA: ED25519 SHA256:7nN4D2... (using ssh-ed25519)
        Key ID: "patrick@perso-mbp-2026-05-28"
        Serial: 42
        Valid: from 2026-05-28T14:30:00 to 2026-05-28T22:30:00
        Principals:
                gw-user
                debugger
        Critical Options:
                source-address 192.168.1.0/24
        Extensions:
                permit-pty
                permit-port-forwarding
```

This output is the entire trust state of the credential. Get comfortable reading it.

---

## 3. User certs vs host certs — two independent directions of trust

There are **two cert types**, and they exist for symmetric reasons. Most engineers know about user certs; far fewer use host certs, but they're equally valuable.

### User certificate (`cert-type 1`)

Issued to: a person (or bot identity).
Proves: "the user CA trusts this key to act as principal X."
Verified by: the **server's** sshd, by checking `TrustedUserCAKeys`.
Replaces: `authorized_keys` editing.

### Host certificate (`cert-type 2`)

Issued to: a server.
Proves: "the host CA trusts this host to be named Y."
Verified by: the **client's** ssh, by checking `@cert-authority` lines in `known_hosts`.
Replaces: the TOFU "are you sure you want to continue connecting?" fingerprint prompt.

| | User cert | Host cert |
|---|---|---|
| Who signs | User CA | Host CA |
| Who presents at handshake | Client | Server |
| Who verifies | Server | Client |
| Server config | `TrustedUserCAKeys /etc/ssh/user_ca.pub` | `HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub` |
| Client config | (nothing — the cert lives next to the key) | `@cert-authority *.gateway ssh-ed25519 AAAA...` in `known_hosts` |
| Principal meaning | Username or role | Hostname pattern |
| `sshca` command | `sshca cert sign --ca user --principal X ...` | `sshca cert sign --ca host --principal X ...` |

**Use separate CAs for user vs host.** Compromise of the user CA shouldn't let an attacker impersonate hosts, and vice versa. Different blast radius, different rotation cadence, different storage requirements. `sshca ca init` generates both by default for this reason.

---

## 4. How verification actually works at handshake time

Two flows, in order. Both happen during the **user-authentication** phase of the SSH connection (after transport-layer encryption is established but before any shell/channel exists).

### Host cert verification (client side, server identity)

1. Server presents its host pubkey + host cert in the transport-layer handshake.
2. Client's ssh reads `~/.ssh/known_hosts` (and `/etc/ssh/ssh_known_hosts`) looking for a `@cert-authority` line.
3. If found, ssh validates: signature is valid, signing CA matches the `@cert-authority` entry, `valid_principals` contains the hostname the client typed (`ssh customer-001.gateway` → principal "customer-001.gateway" must be in the cert), validity window covers now.
4. All pass → server identity trusted. No fingerprint prompt.
5. Any fail → fall through to TOFU (or refuse, if `StrictHostKeyChecking` is set).

### User cert verification (server side, client identity)

1. Client presents user cert + signs a challenge with the corresponding private key (proves it holds the matching private key).
2. Server's sshd checks `TrustedUserCAKeys`. If the cert's signing CA matches → continue. If not → reject (fall through to `authorized_keys` if any).
3. Validity window covers now? Else reject.
4. The target Unix user (e.g. `gw-user`) appears in `valid_principals`? Else reject. **`AuthorizedPrincipalsFile`** can override this — points at a per-user file mapping principals to roles, useful for "any principal listed here counts as auth'd."
5. Source IP matches `critical option source-address`? Else reject.
6. Cert not in `RevokedKeys` KRL? Else reject.
7. All pass → authenticated. Extensions decide what the session can do (PTY, port-forwarding, etc.).

Each check is independent. A cert can fail at any of them — read the sshd auth log to see which.

---

## 5. The CA — what it actually is

The CA is just **a keypair**. No special software, no infrastructure required for the minimal case. The "private key" is the *signing* key; the "public key" is what servers trust.

`sshca ca init` generates one (well, two — user CA + host CA) with correct permissions:

```bash
sshca ca init --dir ./ca
# generates:
#   ./ca/user_ca, ./ca/user_ca.pub   (user CA keypair, 0600 perms)
#   ./ca/host_ca, ./ca/host_ca.pub   (host CA keypair, 0600 perms)
```

Equivalent raw `ssh-keygen` (what sshca wraps):

```bash
ssh-keygen -t ed25519 -f ./ca/user_ca -N '' -C 'user CA'
```

The `-N ''` skips a passphrase — convenient if a CI job needs to sign without interaction. **For production, passphrase-protect it** and unseal it only when signing.

`./ca/user_ca` (private) = the trust root. Whoever holds this can issue any cert. Treat it like a root password.
`./ca/user_ca.pub` = what gets distributed to every server's `TrustedUserCAKeys`.

There's no centralized infrastructure. A CA is *just a private key being used a certain way.* That said, in practice you want:

- A safe place for the private key (filesystem on a hardened box, YubiKey, HSM, or sealed in Vault/OpenBao) — see §11
- A workflow that gates what gets signed (CLI tool, CI job, slack bot — whatever)
- An issuance log (append-only, ideally git-committed or sqlite) — `sshca` writes `<ca-dir>/issuance-log.jsonl` automatically
- A revocation mechanism (KRL) — `sshca cert revoke` wraps it
- A rotation procedure (because CAs *will* be rotated) — see §11

The actual `ssh-keygen -s` command is one line. Everything else is operational discipline — which is exactly the gap sshca exists to close.

---

## 6. Where each artifact lives — and where permissions get assigned

Two questions worth answering visually before diving into commands: **where does each cert artifact physically live**, and **where do permissions get assigned to a cert** (because the answer is in three different places, and conflating them confuses everything).

### Where each artifact lives

```
                              CA HOLDER
                          (offline / hardened)
                                  │
                                  │ signs user cert
                                  │ ships pubkeys (one-time)
                                  ▼
                              USER LAPTOP
                                  │
                                  │ ssh -J bastion gateway
                                  ▼
                                BASTION ────────► GATEWAY
                              (verifier)         (verifier)
                              trusts CA pub      trusts CA pub
                              checks KRL


  WHO HOLDS WHAT:

  CA private keys   →  CA holder ONLY
                       (offline VPS, YubiKey, Vault, sealed env)
                       NEVER on the bastion. NEVER on a gateway.

  CA public keys    →  Bastion (/etc/ssh/user_ca.pub)
                       Each gateway (same file)
                       One file each, almost-never changes.

  User certs        →  Each user's laptop, next to their key
                       (~/.ssh/id_ed25519-cert.pub)
                       ssh client presents it at handshake.
                       Bastion never stores them.

  Host certs        →  Each gateway (/etc/ssh/ssh_host_*-cert.pub)
                       sshd presents at handshake.
                       Bastion has its own host cert too.

  Host CA pubkey    →  Each client laptop
                       (~/.ssh/known_hosts, as @cert-authority line)
                       Tells the client to skip TOFU for known CAs.

  KRL               →  Bastion (/etc/ssh/revoked_keys.krl)
                       And each gateway, if you want gateway-side
                       revocation. Re-read on every connection.
```

**Key property: the bastion stores O(1) cert artifacts** — one CA pubkey + one KRL + one of its own host certs. Regardless of fleet size. No `authorized_keys` to grow.

### Where permissions get assigned (three levels)

This is the part most engineers blur. Permissions to a cert are decided in **three distinct places**:

```
  LEVEL 1: ISSUANCE POLICY  (upstream, at the CA holder)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   WHO is allowed to ASK for WHAT cert?
   Decided by: a human, a script, a GitOps PR, a Slack bot.
   This is your control plane — the policy ABOVE the CA.
   sshca is intentionally NOT this layer; it stays schema-neutral.

   "Patrick can issue gw-user certs for himself, 8h max.
    Only the GitHub Actions bot can issue gw-deployer certs.
    Customer-support team can issue debugger certs for the
    customer they're assigned to, valid during business hours."


                                  │ once Level 1 says "yes",
                                  ▼ sshca cert sign is invoked


  LEVEL 2: BAKED INTO THE CERT  (at signing time, immutable)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   sshca cert sign \
       --ca user \
       --principal "gw-user,debugger"  ◀━━ principals = roles the cert authorizes
       --valid "+8h"                   ◀━━ validity window
       --key-id "patrick@2026-05-28"   ◀━━ key_id (audit primary key)
       <pubkey-file>

   (equivalent ssh-keygen -s flags wrapped by sshca:)
   -O source-address=10/8        ◀━━ critical: must come from this IP
   -O force-command="..."        ◀━━ critical: can only run this command
   -O permit-pty                 ◀━━ extension: interactive shell allowed

   The CA's signature covers all of this. You cannot tamper
   with one byte without invalidating the cert.


                                  │ user puts cert next to their key,
                                  ▼ ssh client presents at connect


  LEVEL 3: ENFORCED AT THE SERVER  (sshd, at connection time)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   /etc/ssh/sshd_config:

     TrustedUserCAKeys /etc/ssh/user_ca.pub   ◀━ "I trust this CA"
     RevokedKeys       /etc/ssh/revoked_keys.krl

     # Important: OpenSSH's Match directive does NOT support a
     # `Principal` criterion. The supported conditions are User,
     # Group, Host, LocalAddress, LocalPort, RDomain, Address.
     #
     # The default principal check: the cert's valid_principals
     # list must contain the TARGET UNIX USERNAME. So a cert with
     # principal `gw-user` connecting as user `gw-user` succeeds;
     # the same cert connecting as user `root` is rejected.
     #
     # Role restrictions therefore live in `Match User` blocks —
     # one Unix user per role. To map MULTIPLE principals onto
     # one Unix user, use AuthorizedPrincipalsFile (a file listing
     # accepted principals per-user) or AuthorizedPrincipalsCommand
     # (dynamic version).

     Match User gw-tunnel                       ◀━━ unix user gw-tunnel:
         AllowTcpForwarding remote                  reverse tunnel only.
         PermitListen       12001-12099             Any cert with principal
         ForceCommand       /bin/false              "gw-tunnel" can auth here.
         PermitTTY          no

     Match User gw-user                         ◀━━ unix user gw-user:
         AllowTcpForwarding local                   passthrough only.
         ForceCommand       /bin/false              Any cert with principal
         PermitTTY          no                      "gw-user" can auth here.

     Match User gw-debug                        ◀━━ unix user gw-debug:
         AllowTcpForwarding local                   shell + local forwarding.
         PermitTTY          yes                     Match-by-username is the
                                                    primary enforcement unit.
```

The three levels:

| Level | Lives at | What it decides | Who builds it |
|---|---|---|---|
| **1. Issuance policy** | CA holder + surrounding workflow | Who is allowed to ASK for which cert | Your control plane — GitOps + UI + fleet awareness. `sshca` deliberately does NOT do this; schema-neutrality is its scope discipline. |
| **2. Cert content** | The cert file itself (signed, immutable) | Principals + validity + source + force-command + extensions | `sshca cert sign` wraps `ssh-keygen -s`. You don't build this; you call it. |
| **3. Server enforcement** | `/etc/ssh/sshd_config` `Match User` blocks (one Unix user per role) + optionally `AuthorizedPrincipalsFile`/`Command` | What each role is allowed to do at sshd | OpenSSH's sshd. You configure once per role. |

`sshca` lives squarely at Level 2 — the thin wrapper around `ssh-keygen -s` with sane defaults, JSONL audit, KRL UX, and renewal-by-principal-inference. Level 1 (issuance policy) is the differentiated layer above; for the OT-integrator case, that's the [`gateway`](https://github.com/roselabs-io/gateway) product. Level 3 (sshd enforcement) is vanilla OpenSSH; for the SSH-bastion case, the role drop-ins are shipped by [`bastionhub`](https://github.com/roselabs-io/bastionhub).

---

## 7. Creating certs — practical commands

### Set up a user CA + tell a server to trust it (one-time)

```bash
# On a safe machine — NOT the verifier server itself, ideally
sshca ca init --dir ./ca
# generates ./ca/user_ca{,.pub} and ./ca/host_ca{,.pub}

# Distribute the user CA pubkey to the server
scp ./ca/user_ca.pub server-root:/etc/ssh/user_ca.pub

# On the server: add to sshd_config (in a drop-in)
cat > /etc/ssh/sshd_config.d/20-user-ca.conf <<'EOF'
TrustedUserCAKeys /etc/ssh/user_ca.pub
RevokedKeys /etc/ssh/revoked_keys.krl
EOF
systemctl reload ssh
```

The CA's *private* key never touches the verifier server. Server only verifies.

### Issue a user cert

```bash
sshca cert sign \
    --ca user \
    --principal "gw-user" \
    --valid "+8h" \
    --key-id "patrick@perso-mbp-2026-05-28T14:30Z" \
    --dir ./ca \
    ~/.ssh/id_ed25519.pub
```

What sshca wraps (`ssh-keygen -s`):

| sshca flag | sshca | ssh-keygen equivalent |
|---|---|---|
| Which CA to use | `--ca user|host` | `-s <path/to/user_ca>` or `-s <path/to/host_ca>` |
| Audit string | `--key-id "..."` | `-I "..."` |
| Principals | `--principal "a,b"` | `-n "a,b"` |
| Validity | `--valid "+8h"` or `"20260528:20260529"` | `-V "..."` |
| Host vs user cert | `--ca host` adds `-h` | `-h` (host cert) |
| CA dir | `--dir ./ca` or `$SSHCA_CA_DIR` | (path passed to `-s`) |

`sshca cert sign` additionally:
- Auto-appends a JSONL entry to `<ca-dir>/issuance-log.jsonl` (audit trail)
- Validates pubkey file exists
- Outputs the resulting `<pubkey>-cert.pub` path

Output: `~/.ssh/id_ed25519-cert.pub` next to the existing key. **The SSH client picks it up automatically** — no extra config needed; if a `*-cert.pub` exists next to the private key, ssh presents it at auth time.

### Issue a host cert (for a server)

```bash
# On the server: ship its host pubkey to the host CA holder
scp /etc/ssh/ssh_host_ed25519_key.pub ca-host:/tmp/customer-001.pub

# On the CA holder
sshca cert sign \
    --ca host \
    --principal "customer-001.gateway,12001.bastion.roselabs.io" \
    --valid "+52w" \
    --key-id "customer-001-gateway-2026-05-28" \
    --dir ./ca \
    /tmp/customer-001.pub

# Result: /tmp/customer-001-cert.pub
# Ship back to the server
scp /tmp/customer-001-cert.pub server:/etc/ssh/ssh_host_ed25519_key-cert.pub

# Tell the server's sshd to use it
cat >> /etc/ssh/sshd_config.d/30-host-cert.conf <<'EOF'
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
EOF
systemctl reload ssh
```

`--ca host` is what makes it a *host* certificate (adds the `-h` flag to ssh-keygen under the hood). Without it, you get a user cert that won't work for server identity.

### Client trusts the host CA (one-time, per laptop)

```bash
# Add to ~/.ssh/known_hosts
echo '@cert-authority *.gateway,*.bastion.roselabs.io ssh-ed25519 AAAA...host-ca-pubkey...' >> ~/.ssh/known_hosts
```

After this, every server whose host cert is signed by that CA = automatically trusted. No more fingerprint prompts when you onboard the 18th customer.

### Renewing a cert

```bash
sshca cert renew --pubkey-file ~/.ssh/id_ed25519.pub --dir ./ca
# Re-signs with principals auto-inferred from the existing ~/.ssh/id_ed25519-cert.pub.
# Defaults: ca=user, valid=+8h, key-id auto-generated from pubkey basename + timestamp.
# Optional --ship user@host:/path scp's the new cert next.
```

`renew` is the bus-factor-zero command: an operator doesn't have to remember the original principal vocabulary; sshca extracts it from the existing cert.

### Listing the audit log

```bash
sshca cert list                            # raw JSONL tail
sshca cert list --principal gw-tunnel      # tabular filter to a principal
```

The audit log at `<ca-dir>/issuance-log.jsonl` is one line per sign. Schema is sshca's contract surface — downstream consumers parse it. See `docs/reference/contracts.md` (TBD) for the schema.

---

## 8. Principal design patterns

A cert principal is just a string — but the *vocabulary* of principals is where most of your control-plane design lives. The patterns below come from the OT-integrator project that motivated sshca; they're shown here as one worked example of how organizations design principal vocabularies. Your taxonomy will likely look different.

**Key intuition specific to gateways (OT-flavored example):** when you "SSH into" a gateway router, you usually don't want a *shell* on the router — you want access to *what's reachable through the router*. The powerful principals scope **port forwarding to specific destinations**, not shell access. Shell on the gateway itself is the rare exception, reserved for OS-level maintenance and tightly time-boxed.

### Realistic principal taxonomy (OT-integrator example)

The "How it's enforced" column mixes two layers: **cert-level** (`force-command`, `source-address`, validity, the permit-* extensions — all baked into the cert at signing time, by `sshca cert sign`) and **server-side** (`PermitOpen`, `PermitListen`, `Match User` blocks — sshd config, shipped by something like `bastionhub`). `permitopen`/`permitlisten` are **not** cert options; they're sshd_config / authorized_keys directives. To bind them per-principal, use `AuthorizedPrincipalsCommand` (Pattern B below).

| Principal | What it grants | How it's enforced |
|---|---|---|
| **`gw-tunnel`** | The gateway dialing OUT to bastion (reverse tunnel only) | Cert: `no-pty`, `force-command=/bin/false`. Server: `Match User gw-tunnel` + `PermitListen 12001-12099` |
| **`gw-deploy-bot`** | CI runs ONE specific deploy command, nothing else | Cert: `force-command="/opt/deploy/run --strict"`, `source-address=<github-actions-cidr>`, `no-pty`, no forwarding |
| **`gw-edge-ssh-<edge-name>`** | Passthrough to ONE specific edge behind the gateway | Cert: `no-pty`, `force-command=/bin/false`. Server: `Match User gw-passthrough` + per-principal `permitopen` via `AuthorizedPrincipalsCommand` |
| **`gw-console-only`** | Hit a fleet console widget over HTTP. Nothing else. | Cert: `no-pty`, `force-command=/bin/false`. Server: `Match User gw-passthrough` + `PermitOpen localhost:8080` |
| **`gw-luci-only`** | OpenWrt LuCI router UI (HTTP). Network ops only. | Cert: `no-pty`, `force-command=/bin/false`. Server: `Match User gw-passthrough` + `PermitOpen localhost:80` |
| **`gw-debug`** | Engineer troubleshooting: PTY + ANY edge + 8h limit. | Cert: `permit-pty`, `permit-port-forwarding`, `--valid +8h`. Server: `Match User gw-debug` + `PermitOpen 192.168.100.0/24:*,localhost:*` |
| **`gw-router-admin`** | Actual shell on the gateway box. **Reserved for OS maintenance.** Rare. Dual signoff at Level 1. | Cert: `permit-pty`, `--valid +1h`, `source-address=<patrick-static-ip>`. Server: `Match User root` (or dedicated admin user) |

**Observation:** the cert layer enforces `force-command`, `source-address`, and the permit-* extensions. The server layer (`Match User` + `PermitOpen`/`PermitListen`) enforces destination scoping — which means destination scoping is *role-family-level* (one per Match User block), not per-principal, unless you use `AuthorizedPrincipalsCommand` to vary it per principal.

### Worked example: `gw-edge-ssh-customer-001-controller-1`

The most architecturally interesting principal — "you can reach this one device through the gateway, and nothing else." Walk it end-to-end across the three levels.

**Level 1 — issuance policy (decided at the CA holder by the upstream consumer):**

```yaml
# roles.yaml (git-tracked, PR-gated) — lives in the gateway product, not sshca
patrick:
  certs:
    - principal: gw-edge-ssh-customer-001-controller-1
      max_validity: 4h
      source_addresses: [10.0.0.0/8]
      requires_approval: false  # Patrick is on rotation for customer-001
```

PR merges → CI runs the registry compiler → invokes `sshca cert sign` → emits cert artifact.

**Level 2 — baked into the cert (immutable, signed):**

```bash
sshca cert sign \
    --ca user \
    --principal "gw-user,gw-edge-ssh-customer-001-controller-1" \
    --valid "+4h" \
    --key-id "patrick@2026-05-28T15:00-customer-001-incident-447" \
    --dir ./ca \
    ~/.ssh/id_ed25519.pub

# Critical options + extensions to add via raw ssh-keygen passthrough
# (sshca does NOT currently expose every ssh-keygen flag — for advanced
# critical options, drop down to ssh-keygen -s directly. See backlog.)
```

Note **two principals**: one (`gw-user`) for bastion auth, one (`gw-edge-ssh-customer-001-controller-1`) for gateway auth. Same cert, presented at both servers, each reads its own principal.

**Level 3 — enforcement (each server applies its own rules):**

Because OpenSSH `Match` doesn't take a `Principal` criterion, the per-role enforcement maps onto Unix users. Two patterns, in increasing sophistication:

**Pattern A — one Unix user per role family (simplest):**

```
BASTION /etc/ssh/sshd_config.d/20-user-ca.conf:
    TrustedUserCAKeys /etc/ssh/user_ca.pub

    Match User gw-user
        AllowTcpForwarding local
        ForceCommand        /bin/false
        PermitTTY           no
        # nothing about destinations — bastion is just pass-through


GATEWAY /etc/ssh/sshd_config.d/20-user-ca.conf:
    TrustedUserCAKeys /etc/ssh/user_ca.pub

    Match User gw-passthrough
        AllowTcpForwarding local
        PermitOpen          192.168.100.10:22
        ForceCommand        /bin/false
        PermitTTY           no
```

The cert presents principals `gw-user,gw-passthrough`. ssh connects as user `gw-user` to bastion (one principal matches) and as user `gw-passthrough` to gateway (the other matches). Each server's `Match User` block applies its restrictions. **Coarse-grained: every cert with principal `gw-passthrough` gets the same `PermitOpen`.**

**Pattern B — AuthorizedPrincipalsCommand for principal-level granularity:**

If you want `gw-edge-ssh-customer-001-controller-1` to behave differently from `gw-edge-ssh-customer-002-controller-3` while sharing one Unix user, use `AuthorizedPrincipalsCommand`. It runs a script that gets the cert's principal as input and returns an `authorized_keys`-style line (which can include `permitopen=` per principal). Heavier but unlocks fine-grained per-principal policy without proliferating Unix users.

```
# /etc/ssh/sshd_config.d/30-passthrough-acl.conf
Match User gw-passthrough
    AuthorizedPrincipalsCommand /usr/local/bin/principal-to-acl %u %i
    AuthorizedPrincipalsCommandUser gw-passthrough
    PermitTTY no
    ForceCommand /bin/false
```

Where `/usr/local/bin/principal-to-acl` reads the principal name (passed via `%i`) and emits, for example:
```
permitopen="192.168.100.10:22" <principal-name>     # for gw-edge-ssh-customer-001-controller-1
permitopen="192.168.100.20:22" <principal-name>     # for gw-edge-ssh-customer-001-controller-2
```

The `bastionhub` substrate tool ships the Pattern B drop-in + skeleton script in `deploy/bastion/`.

### The architectural property worth naming

> A cert can carry **multiple principals**, and each server it touches applies its **own** `Match User` rules (or `AuthorizedPrincipalsCommand` decisions) based on which principal matches the target Unix user at that hop.

One cert authenticates at the bastion as Unix user `gw-user` (principal `gw-user` matched → "pass through, no shell") AND at the gateway as Unix user `gw-passthrough` (principal `gw-edge-ssh-customer-001-controller-1` matched via AuthorizedPrincipalsCommand → "forward to one IP, no shell"). **The cert is identity; each server independently decides what that identity is allowed to do at each hop.**

You cannot get this clean separation with raw keys without per-host `authorized_keys` choreography that drifts the moment fleet shape changes.

### Why this matters for sshca

`sshca` doesn't care what your principal vocabulary looks like — it's schema-neutral by design. But understanding *how principals decompose into Unix-user mapping + `AuthorizedPrincipalsCommand` patterns* is what lets you design a vocabulary that's actually enforceable. The above is one worked example from one domain; your taxonomy will look different but the constraints (no `Match Principal`, principal-to-Unix-user mapping, per-principal granularity needs `AuthorizedPrincipalsCommand`) are universal.

---

## 9. Cert restrictions — critical options vs extensions

Two flavors of restriction live in a cert. The distinction matters.

### Critical options (`-O critical:...` or specific flags)

Server **MUST** understand and enforce these. If sshd sees a critical option it doesn't recognize, it **rejects the cert.** Fail-closed.

| Option | What it does |
|---|---|
| `force-command="..."` | Cert can only run this exact command (overrides whatever the user typed) — useful for git-over-ssh, deploy scripts |
| `source-address="cidr,cidr,..."` | Cert only valid from these source IPs/networks |
| `verify-required` | Requires FIDO2 user verification (touch) for every signing operation |

`sshca cert sign` does not currently expose every `ssh-keygen -s` critical-option flag (the focus is the common case + audit + KRL). For advanced critical options today, drop down to `ssh-keygen -s` directly with the same CA file; the JSONL audit log won't capture those signs unless you re-implement that side. Surfacing these via sshca flags is a known follow-up.

Example with raw `ssh-keygen -s`:

```bash
ssh-keygen -s ./ca/user_ca \
    -I "ci-deploy" -n gw-user -V "+8h" \
    -O source-address="10.0.0.0/8,192.168.1.50" \
    -O force-command="/usr/local/bin/deploy" \
    deploy.pub
```

### Extensions (`-O extension:...`)

Server **MAY ignore** these if unknown. Fail-open. Used for permissions that gracefully degrade.

| Extension | What it does (when supported) |
|---|---|
| `permit-X11-forwarding` | Allow X11 forwarding |
| `permit-agent-forwarding` | Allow `-A` agent forwarding |
| `permit-port-forwarding` | Allow `-L`/`-R`/`-D` |
| `permit-pty` | Allow interactive PTY |
| `permit-user-rc` | Allow `~/.ssh/rc` to run on login |
| `no-touch-required` | For FIDO2 keys, don't require touch (use sparingly) |

By default, `ssh-keygen -s` (and `sshca cert sign`, which wraps it) includes **all five permit-* extensions**. To create a more restrictive cert, override with `-O clear` first via raw `ssh-keygen -s`:

```bash
ssh-keygen -s ./ca/user_ca -I "tunnel-only" -n gw-tunnel -V "+8h" \
    -O clear \
    -O permit-port-forwarding \
    tunnel.pub
```

`-O clear` strips the defaults; subsequent `-O permit-X` lines re-add only what you want.

**The control-plane policy you actually want is encoded here.** "CI deployer can run `deploy` only, from this source IP, for 1 hour." "Debugger can get a PTY but no port-forwarding." "Tunnel host can only forward, no shell." All certificate-native.

---

## 10. Revocation (KRL) — for the rare case you can't wait for expiry

Most cert revocation is "wait for expiry." With 8h validity, the wait is at most 8h. For most use cases that's enough.

Sometimes it isn't. KRL = **Key Revocation List**. A compact binary file listing revoked keys, cert serials, or key-ids.

```bash
# sshca wraps the common cases:
sshca cert revoke --ca user --key-id "patrick@perso-mbp-2026-05-28" --dir ./ca
sshca cert revoke --ca user --serial 42 --dir ./ca
sshca cert revoke --ca user --pubkey-file bad_key.pub --dir ./ca

# Optional --ship DEST scp's the updated KRL to a destination sshd
sshca cert revoke --ca user --key-id "..." --ship root@bastion:/etc/ssh/revoked_keys.krl --dir ./ca

# Inspect what's in the local KRL
sshca cert krl --dir ./ca
```

Equivalent raw `ssh-keygen` (what sshca wraps):

```bash
# Create a new KRL or update an existing one
ssh-keygen -k -f ./ca/revoked_keys.krl -s ./ca/user_ca.pub - <<'EOF'
serial: 42
EOF

# Inspect KRL
ssh-keygen -Q -f ./ca/revoked_keys.krl
```

The server's sshd config (`RevokedKeys /etc/ssh/revoked_keys.krl`) re-reads on connection — no daemon reload needed. KRL changes are *fast* in terms of propagation; the slow part is getting the KRL onto every server you operate.

For a single-bastion deployment: trivial. For a multi-tenant CA serving many bastions: this is a distribution problem worth designing once (push via the deploy-gating workflow? sync via git pull?).

---

## 11. CA management — the parts that aren't fun but matter

The `ssh-keygen -s` mechanics are easy. The operational discipline around the CA is where production work lives.

### Where the CA private key lives

In ascending order of operational maturity:

| Storage | Risk | When it's right |
|---|---|---|
| Filesystem, root-owned, no passphrase | Server compromise = identity compromise | Prototype, single-user |
| Filesystem, passphrase-protected | Brute-force-resistant offline; passphrase still typeable | Solo developer, "real" but simple |
| YubiKey / hardware token | Key physically can't leave the chip; CA must be physically present to sign | Solo or small team, prod |
| HSM (cloud KMS, Yubico HSM2) | Same protections + API access + audit | Multi-tenant, regulated |
| Vault / OpenBao SSH secrets engine | Full audit + RBAC + automated rotation | When you also need other secrets management |

`sshca` today (v0.1.0-dev) ships the filesystem-0600 path. Hardening to YubiKey / sealed-VPS / KMS-backed signing is on the backlog — see `docs/planning/backlog.md`.

### Rotation procedure (write before you need it)

Naive rotation: generate new CA, swap `TrustedUserCAKeys` on every server, reissue every active cert. *Painful at scale.*

Mature rotation: use an **intermediate CA**. Root CA signs an intermediate; intermediate signs day-to-day certs. Servers trust the root; rotate the intermediate frequently without touching server config. Root only rotates rarely (years). This is how x509 PKI does it.

sshca today does not implement intermediate CAs. The single-CA model is appropriate at v0.1.0-dev scale; intermediate-CA support is on the longer-horizon roadmap.

### Break-glass

If the CA is lost / corrupted / compromised, you need a way back into the server to fix things. Options:

1. **Long-lived break-glass cert.** Issue one cert with 1-year validity, broad principals, store the private key + cert offline (paper, sealed envelope). Use it only in emergencies.
2. **Raw key fallback in `authorized_keys`.** Keep one root-owned raw key entry for break-glass. Defeats the "authorized_keys is empty" goal, but it's pragmatic.
3. **Out-of-band console access.** Hetzner/whoever has a web console — physical access to the box. Slowest, but works when SSH is broken entirely.

Pick at least one. Document it. Practice it once.

---

## 12. Cert lifecycle in practice

The day-to-day shape with `sshca`:

```
1. Engineer needs access
   ↓
2. CA holder (or CI pipeline) runs:
   sshca cert sign --ca user --principal gw-user --valid +8h \
       --key-id "patrick-bastion-$(date -u +%Y%m%dT%H%MZ)" \
       --dir ./ca patrick.pub
   ↓
3. Cert file emitted next to pubkey; engineer drops it in ~/.ssh/
   ↓
4. ssh client picks it up automatically (because *-cert.pub sits next to the key)
   ↓
5. Server verifies on connect; allows in
   ↓
6. 8h later: cert expires. Engineer renews:
   sshca cert renew --pubkey-file ~/.ssh/patrick.pub --dir ./ca
   (principal auto-inferred from existing -cert.pub)
   ↓
7. If engineer leaves the company: no action required.
   Their certs already expire. The CA stops signing for them.
   ↓
8. For urgent revocation:
   sshca cert revoke --ca user --key-id "..." --ship root@server:/etc/ssh/revoked_keys.krl
```

Compare to the keys-only flow: step 2 is "SSH to the server, edit `authorized_keys`, hope they leave gracefully so you remember to remove the line later." Step 6 vanishes (keys don't expire). Step 7 is "remember to revoke."

The cert version *replaces a human-remembered task with a mechanical expiry.* That's the real win — and the bus-factor-zero design principle behind sshca.

---

## 13. Tradeoffs vs raw keys — the honest summary

| | Raw keys | Certificates |
|---|---|---|
| Server config to onboard a new identity | Edit `authorized_keys` | None — CA already trusted |
| Server config to revoke | Edit `authorized_keys` | None at server (KRL if urgent, expiry otherwise) |
| Time-bound access | `expiry-time=` option (rarely used) | Native, default, mandatory |
| Audit of "who can SSH in" | Read `authorized_keys` | Read CA issuance log (sshca's JSONL) |
| Policy granularity | Per-key options inline | Native principals, source-addr, force-command, extensions |
| Setup complexity | Trivial (ssh-keygen + paste) | Need a CA, distribution, signing workflow |
| Failure modes | Forgotten cleanup, drift, accumulating dead keys | CA compromise (catastrophic), forgotten renewals (annoying — sshca's `cert list --expiring` is meant for this) |
| Scaling cost | Linear in fleet × users | ~Constant after setup |
| Right answer at 1 user, 1 server | **Raw keys.** Certs are overkill. | Yes, but overkill. |
| Right answer at 5 users, 20 servers | Painful but works | Worth the setup |
| Right answer at 50+ users / 100+ servers | Untenable | The only answer |

The reason sshca exists at all is that *the operational discipline* around certs is what most shops fail at, not the cert mechanics. CA passphrase in someone's head, expiry surprises at 3am, revocation never tested, audit via shell history — these are the failure modes sshca's bus-factor-zero design targets. The `ssh-keygen -s` part has been right since 2010.

---

## 14. Related reading

- [sshca README](../../README.md) — the public-facing pitch
- [sshca CLAUDE.md](../../CLAUDE.md) — agent / contributor context
- [docs/decisions/inherited.md](../decisions/inherited.md) — the upstream ADRs that motivated this tool
- [github.com/roselabs-io/gateway](https://github.com/roselabs-io/gateway) — the OT-integrator project where sshca was born. Its `docs/reference/ssh/` has companion primers: [01-three-layer-stack](https://github.com/roselabs-io/gateway/blob/main/docs/reference/ssh/01-three-layer-stack.md), [02-tunnels](https://github.com/roselabs-io/gateway/blob/main/docs/reference/ssh/02-tunnels.md), [07-restricted-user](https://github.com/roselabs-io/gateway/blob/main/docs/reference/ssh/07-restricted-user.md), [keys.md](https://github.com/roselabs-io/gateway/blob/main/docs/reference/ssh/keys.md).
- [github.com/roselabs-io/bastionhub](https://github.com/roselabs-io/bastionhub) — the SSH-bastion substrate; consumes sshca for cert signing.
- [OpenSSH PROTOCOL.certkeys](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys) — the canonical cert format spec.

---

## Things skipped

- **x509 / TLS certificates** — different format, different toolchain (`openssl`, `step certificate`), different protocols (HTTPS, mTLS). Relevant when HTTP services appear. Same conceptual shape (CA-signed metadata + key), incompatible bytes. Out of scope for sshca per its SSH-only scope discipline.
- **SSH agent + cert interactions** — agents serve certs too; nothing surprising. `ssh-add` loads them along with keys.
- **Certificate transparency for SSH** — doesn't really exist (x509 has CT logs; SSH doesn't, mostly because nobody runs a public SSH CA infrastructure at internet scale).
- **PKCS#11 / smartcard backends for CA signing** — the right answer when CA-key-on-filesystem isn't acceptable. On the longer-horizon roadmap; see `docs/planning/backlog.md`.

---

*Ported from upstream `gateway` repo 2026-05-29 as part of the three-repo decomposition. Add to it as cert features get implemented in sshca.*
