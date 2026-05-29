# Current state

> What works right now in `sshca`. Updated on every change.

## Status

Pre-release. Scaffolding stage. No commands implemented yet.

## What's shipped

Nothing — `sshca` hasn't tagged a release. The scaffold builds (`go build`) and prints help text.

## Where the code currently lives

The cert/CA implementation lives in the upstream `gateway` repo at [`cli/main.go`](https://github.com/roselabs-io/gateway/blob/main/cli/main.go) (the `ca *`, `cert *`, `user *` subcommands). It's being migrated here per [planning/backlog.md](planning/backlog.md) item #1.

## Recently landed

- **2026-05-29** — Repo created (`roselabs-io/sshca`), doc structure seeded, MIT-licensed, scaffold `main.go` builds and prints planned commands.

## See also

- [decisions/inherited.md](decisions/inherited.md) — the upstream decisions that motivated this repo
- [planning/backlog.md](planning/backlog.md) — what's coming next
