# AGENTS.md

Instructions for agent sessions working in this repository. `pipeline.yaml` names this file for
`docs.agents`, `docs.contract`, `docs.review_posture` and `docs.operating_model`.

[`CLAUDE.md`](CLAUDE.md) holds the scope, the contract surface (CLI grammar, issuance log schema),
the constraints and the conventions. This file does not repeat them.

## Repository

A Go CLI (`go.mod`: `go 1.25.5`, one dependency, `urfave/cli/v3`). Signing is `ssh-keygen -s`.

| Path | Content |
|---|---|
| `main.go` | the whole implementation; `version` is a `var` set with `-ldflags "-X main.version=<tag>"` at release |
| `main_test.go` | the tests (`go test ./...`) |
| `README.md`, `CHANGELOG.md`, `CLAUDE.md` | usage, release notes, contributor notes |
| `.github/workflows/release.yml` | on a `v*` tag: builds six targets, archives, `checksums.txt`, a GitHub Release; then, unless the tag contains `-`, a `repository_dispatch` (`formula-update`, `tool`, `tag`) to `roselabs-io/homebrew-tools` with the secret `HOMEBREW_TAP_TOKEN` |
| `.github/workflows/sshca-ci.yml` | `validate` (PR metadata) and `gate` (`just gate`) |
| `.github/workflows/sshca-pm.yml` | the issue and board sync of Governor |
| `.github/workflows/sshca-audit.yml` | `just audit` on a pull request or push to `main` that changes `go.mod` or `go.sum`, weekly on `main`, and on dispatch |
| `pipeline.yaml` | the Governor dispatcher's config for this repository |
| Governor's package preflight (`tools/local_preflight.py` of the Governor package, run by the dispatcher; this repository keeps no copy) | the local check the dispatcher runs: `just check`, then `just gate` |
| `tools/secret_scan.py`, `.secrets.baseline` | the offline secret scan of the tracked files and the findings it accepts |

No key or token is tracked. CA private keys stay on the operator's machine; `.gitignore` excludes
`ca/`, `*.pem`, `*.key` and `*-cert.pub.local`.

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

## Pull requests

A PR from a branch `agent/<N>-…` carries exactly one `Sshca-Issue: #N` line; a dispatched run also
requires a `Sshca-Agent` line naming a configured lane. `validate` of `sshca-ci.yml` checks both.
`sshca-pm.yml` moves issue N on the board from that line. `autonomy: tiered`: an approved PR merges
through the merge queue, except the PR of a complex or exceptional ticket, whose merge is left to a
person.

A change to the CLI grammar or the issuance log schema is a contract change (`CLAUDE.md`, Contract
surface) and is recorded in `CHANGELOG.md`.

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
