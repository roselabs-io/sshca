# Backlog

> Forward-looking only. For "what works right now?", see [../current-state.md](../current-state.md). For "what was decided?", see [../decisions/](../decisions/).

## Active

_(none — substrate completeness items shipped; next cross-cutting chunk is CI/CD + Homebrew tap, see below.)_

## Soon

- **First sshca-series ADR.** First independent decision sshca makes after the migration — likely a flag rename or output-format polish discovered as the tool gets real usage.
- **CI/CD setup.** GitHub Actions: build, test, release. Single binary per platform (darwin-arm64, darwin-amd64, linux-amd64, linux-arm64).
- **Homebrew tap.** `roselabs-io/homebrew-tools` with `sshca` as the first formula.
- **`sshca --help` polish pass.** Every flag has a one-line "when you'd use it" explanation. Bus-factor-zero criterion.
- **README usage examples.** Real `sshca ca init → cert sign → cert renew → cert revoke` walk-through. The README is the bus-factor-zero touchstone — should be enough on its own to operate the tool.

## Later

- **CA storage upgrades.** YubiKey-backed, sealed-VPS, KMS-backed signing. Currently filesystem-0600 only — acceptable at solo-operator scale, needs hardening before there's a second issuer.
- **Multi-operator audit log story.** Concurrent JSONL appends or move to SQLite. Decide based on first multi-operator use case, not pre-emptively.
- **Distribution beyond Homebrew.** `go install`, Debian/Arch/Nix packages, GitHub Releases binaries.
- **`sshca rotate` for CA rotation.** Generate new CA, re-sign existing certs (where possible), publish trust transition. Risky operation; needs runbook before it lands.

## Parked

- **X.509 / TLS support.** Out of scope per upstream [ADR-006](https://github.com/roselabs-io/gateway/blob/main/docs/decisions/ADR-006-bifurcate-cert-tool-from-gateway-product.md). SSH-only is the differentiator.
- **A GUI / web UI.** Out of scope. CLI-first. If a UI ever appears, it ships separately and consumes sshca's CLI grammar contract.
- **Policy-engine features** (roles, multi-tenancy, customer schemas). Belong in the consumer (the `gateway` product), not in sshca. Sshca stays schema-neutral.
