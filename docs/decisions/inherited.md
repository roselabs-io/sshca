# Inherited decisions

`sshca` was extracted from the [`roselabs-io/gateway`](https://github.com/roselabs-io/gateway) monorepo during the three-repo decomposition (2026-05-29). The decisions that motivated sshca's existence and shape are documented as ADRs in the `gateway` repo's [`docs/decisions/`](https://github.com/roselabs-io/gateway/tree/main/docs/decisions). They're **not duplicated here** — links below, with sshca-specific relevance noted.

This repo's own ADR series starts fresh at ADR-001 when sshca makes its first independent decision (see [README.md](README.md)).

## ADRs from `gateway` that apply to `sshca`

| Upstream ADR | Subject | Relevance to sshca |
|---|---|---|
| [ADR-001](https://github.com/roselabs-io/gateway/blob/main/docs/decisions/ADR-001-replace-raw-key-auth-with-ssh-certs.md) | Replace raw-key auth with SSH certificates | The cert-auth foundation `sshca` implements |
| [ADR-002](https://github.com/roselabs-io/gateway/blob/main/docs/decisions/ADR-002-thin-ca-wrapper-not-step-ca-or-vault.md) | Thin CA wrapper, not `step-ca` or Vault | The architectural shape: single binary, two deps, thin wrapper over `ssh-keygen`. Why sshca is small. |
| [ADR-004](https://github.com/roselabs-io/gateway/blob/main/docs/decisions/ADR-004-principal-taxonomy-default-no-shell.md) | Principal taxonomy — default principals grant no shell | The cert-default vocabulary sshca encodes (`force-command=/bin/false`, `no-pty`, etc.) |
| [ADR-006](https://github.com/roselabs-io/gateway/blob/main/docs/decisions/ADR-006-bifurcate-cert-tool-from-gateway-product.md) | Bifurcate `sshca` from gateway product | Why `sshca` exists as its own thing. SSH-only scope locked, bus-factor-zero design principle. |
| [ADR-007](https://github.com/roselabs-io/gateway/blob/main/docs/decisions/ADR-007-retire-gwctl-three-repo-decomposition.md) | Retire `gwctl`; three-repo decomposition | The overall context: `sshca` + `bastionhub` + `gateway` as three independent tools. |

## How to evolve from here

When sshca makes a decision that diverges from or extends one of the inherited ADRs (e.g., a scope change, a new constraint discovered post-extraction), write a fresh ADR in `docs/decisions/` here — don't edit the upstream one. Link back to the inherited ADR being extended.

When an upstream ADR becomes obsolete for sshca (e.g., something stops applying because sshca evolved), note it here with a strikethrough + brief explanation, and write a superseding ADR in this repo.
