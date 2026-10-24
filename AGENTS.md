# AGENTS.md

Instructions for agent sessions working in this repository. `pipeline.yaml` names this file for
`docs.agents`, `docs.contract`, `docs.review_posture` and `docs.operating_model`.

## Repository

SSH certificate authority and management CLI: a single Go binary (`go.mod`: `go 1.25.5`, one dependency,
`urfave/cli/v3` v3.9.0, plus stdlib). Signing is `ssh-keygen -s`.

| Path | Content |
|---|---|
| `main.go` | the whole implementation; `version` is a `var` set with `-ldflags "-X main.version=<tag>"` at release |
| `main_test.go` | the tests (`go test ./...`) |
| `README.md`, `CHANGELOG.md` | usage, release notes |
| `CLAUDE.md` | the line `@AGENTS.md`, which makes Claude Code read this file |
| `.gemini/settings.json` | sets `context.fileName` to `AGENTS.md`, which makes Gemini CLI read this file |
| `.github/workflows/release.yml` | on a pushed `v*` tag, or called by `release` of `sshca-ci.yml` with a tag: builds six targets, archives, `checksums.txt`, a GitHub Release; then, unless the tag contains `-`, a `repository_dispatch` (`formula-update`, `tool`, `tag`) to `roselabs-io/homebrew-tools` with the secret `HOMEBREW_TAP_TOKEN` |
| `.github/workflows/sshca-ci.yml` | `validate` (PR metadata) and `gate` (`just gate`); on a push to `main`, `release-tag` and `release` (Releases) |
| `.github/workflows/sshca-pm.yml` | the issue and board sync of Governor |
| `.github/workflows/sshca-audit.yml` | `just audit` on a pull request or push to `main` that changes `go.mod` or `go.sum`, weekly on `main`, and on dispatch |
| `pipeline.yaml` | the Governor dispatcher's config for this repository |
| Governor's package preflight (`tools/local_preflight.py` of the Governor package, run by the dispatcher; this repository keeps no copy) | the local check the dispatcher runs: `just check`, then `just gate` |
| `tools/secret_scan.py`, `.secrets.baseline` | the offline secret scan of the tracked files and the findings it accepts |

No key or token is tracked. CA private keys stay on the operator's machine; `.gitignore` excludes
`ca/`, `*.pem`, `*.key` and `*-cert.pub.local`.

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
  "ts":             "<RFC3339 UTC timestamp>",
  "ca":             "user|host",
  "key_id":         "<from --key-id>",
  "principals":     "<comma-joined>",
  "valid":          "<from --valid, e.g. '+8h' or '+52w'>",
  "pubkey":         "<path passed in>",
  "cert":           "<path of emitted -cert.pub>",
  "ca_fingerprint": "<SHA256 fingerprint of the signing CA public key>"
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

## Commands

| Recipe | Runs |
|---|---|
| `just check` | `go vet ./...` with `-p "${GOVERNOR_JOBS:-1}"`; fails when `gofmt -l .` lists a file |
| `just test` | `go test ./...` with `-p "${GOVERNOR_JOBS:-1}"` |
| `just build` | `go vet` and `go build` with `CGO_ENABLED=0` and `-p "${GOVERNOR_JOBS:-1}"` for linux, darwin and windows on amd64 and arm64, into a temporary directory |
| `just secrets-env` | creates `.venv` with detect-secrets 1.5.0 through uv; needs the network; not part of the gate |
| `just secrets` | `tools/secret_scan.py` with `.venv/bin/python`: detect-secrets over every file of `git ls-files`; fails on a finding `.secrets.baseline` does not hold, and when `.venv` is missing |
| `just gate` | `check`, `secrets`, `test`, `build`; the deterministic gate CI runs |
| `just audit` | `govulncheck ./...` (v1.9.0, through `go run`); needs the network; not part of the gate |
| `just fix` | `gofmt -w .` |
| `just ff` | switches to `main` and fast-forwards it from `origin`; refuses local changes or a diverged `main` |

`up`, `down` and `logs` are not applicable (`checks.recipes.not_applicable` of `pipeline.yaml`):
there is no local stack. `just`, Go and uv are required.

detect-secrets is pinned in `secrets-env`, outside `go.mod`. `just secrets` installs nothing and needs
no network; run `just secrets-env` once per checkout before `just gate`. The scan reads
`.secrets.baseline` and writes nothing. It covers tracked files only, not untracked files or Git
history, and finds what detect-secrets' patterns and entropy rules find. To accept a finding that is
not a secret, or to refresh the baseline's line numbers:

```sh
git ls-files -z | xargs -0 uv tool run --from detect-secrets==1.5.0 detect-secrets scan --no-verify --baseline .secrets.baseline
```

then review the changed entries in the diff.

`just audit` reports a vulnerability only when the code calls the affected symbol; it exits non-zero
then. A finding is triaged like a review finding: a fix, or a recorded disposition with its
follow-up issue. govulncheck scans with the local Go toolchain, so standard-library findings depend
on the Go version that runs it.

## CI

All workflows run on GitHub-hosted `ubuntu-latest`. The repository is public; the organization's
self-hosted runners do not serve it. `validate` and `sshca-pm.yml` check out the private
`roselabs-io/governor` with the organization secret `GOVERNOR_PM_TOKEN`, which a workflow run from a
fork does not receive.

## Releases

A release is made by a PR that adds a version heading `## [X.Y.Z] — YYYY-MM-DD` to `CHANGELOG.md`,
above the previous one, usually by renaming `[Unreleased]` and adding an empty `[Unreleased]` above it.
After the PR merges, the push to `main` runs `sshca-ci.yml`; when `gate` passes:

1. `release-tag` reads the first heading of `CHANGELOG.md` of the form `## [X.Y.Z]`. `[Unreleased]`
   and a prerelease heading (`[X.Y.Z-rc.1]`) do not match.
2. When the tag `vX.Y.Z` does not exist, it creates it on the pushed commit and pushes it with
   `GITHUB_TOKEN`.
3. `release` calls `release.yml` with the tag: the six archives, `checksums.txt`, the GitHub Release
   and the `formula-update` dispatch.

A push whose first version heading already has its tag releases nothing. A tag pushed with
`GITHUB_TOKEN` starts no workflow, so `release.yml` runs through the call, not through its tag
trigger; a tag pushed by a person still runs it. Prerelease tags are not created from CI.

Runs of `sshca-ci.yml` on `main` are not cancelled in progress. A run still waiting when a newer push
arrives is cancelled, and the newer run tags its own commit, which contains the waiting one; when both
pushes add a version heading, only the newer version is released. When the release fails after the
tag exists, the next push does not retry it: re-run the failed jobs of the run.

A bad release is not deleted: revert on `main` and merge a new patch heading, which releases the next
version. The tap formula is rolled back by reverting its commit in `roselabs-io/homebrew-tools`.

## Pull requests

A PR from a branch `agent/<N>-…` carries exactly one `Sshca-Issue: #N` line; a dispatched run also
requires a `Sshca-Agent` line naming a configured lane. `validate` of `sshca-ci.yml` checks both.
`sshca-pm.yml` moves issue N on the board from that line. `autonomy: full`: every approved PR merges
through the merge queue. A ticket with `merge: manual` in its metadata block, or a PR that changes a
path matching `review.protected_paths`, is still left to a person.

A change to the CLI grammar or the issuance log schema is a contract change (Contract surface, above) and is recorded in `CHANGELOG.md`.

## Finding triage

`docs.operating_model` in `pipeline.yaml` names this file. Each independent-review finding is
triaged before a correction is requested. The dispatcher runs this as a read-only triage session
(Governor `governor/docs/service/finishing.md`, Review triage); an operator correcting by hand
applies the same rules:

Only a CRITICAL finding requests changes; a review with WARNING and INFO findings only approves, and
its WARNINGs are triaged before the merge queue (Governor `governor/docs/postures/pr-review-posture.md`).

1. Open the cited code and confirm the finding against it. A finding that does not hold is answered
   on the PR with the evidence, and no correction is requested for it.
2. Request a correction for every confirmed CRITICAL and for every confirmed WARNING that is a
   boundary finding: security (including credentials, private keys and what the dispatcher pushes,
   merges or deletes), data loss, or the issue's contract or scope.
3. Each other confirmed WARNING is either corrected or dispositioned: a PR comment names the
   follow-up issue and why deferral is safe, and the follow-up issue is opened.

Every later review of the PR receives the dispositions and does not reopen one without new evidence.
