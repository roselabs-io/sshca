# Go CLI recipes of the command contract. `check` and `gate` are what the local preflight runs.

# Static checks: vet and formatting.
check:
    go vet -p "${GOVERNOR_JOBS:-1}" ./...
    test -z "$(gofmt -l .)"

# The test suite.
test:
    go test -p "${GOVERNOR_JOBS:-1}" ./...

# `go vet` and `go build` with CGO_ENABLED=0 for the six release targets of `release.yml` (the build
# matrix of `sshca-ci.yml`). The binaries are written to a temporary directory and removed.
build:
    #!/usr/bin/env sh
    set -eu
    out="$(mktemp -d)"
    trap 'rm -rf "$out"' EXIT
    for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
        echo "go vet $target"
        CGO_ENABLED=0 GOOS="${target%/*}" GOARCH="${target#*/}" go vet -p "${GOVERNOR_JOBS:-1}" ./...
        echo "go build $target"
        CGO_ENABLED=0 GOOS="${target%/*}" GOARCH="${target#*/}" go build -p "${GOVERNOR_JOBS:-1}" -o "$out/sshca-${target%/*}-${target#*/}" .
    done

# Creates `.venv` with detect-secrets 1.5.0 for `secrets`. Needs uv and the network; not part of the gate.
secrets-env:
    uv venv --allow-existing .venv
    uv pip install --python .venv detect-secrets==1.5.0

# The offline secret scan of the tracked files against `.secrets.baseline` (`tools/secret_scan.py`),
# with the Python of `.venv`. Installs nothing; exits 1 when `.venv` is missing.
secrets:
    #!/usr/bin/env sh
    set -eu
    if [ ! -x .venv/bin/python ]; then echo "secrets: .venv is missing; run: just secrets-env" >&2; exit 1; fi
    .venv/bin/python tools/secret_scan.py

# The deterministic gate CI runs.
gate: check secrets test build

# The Go module dependencies against the Go vulnerability database. Needs the network; not part of
# the gate (`sshca-audit.yml`).
audit:
    go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

# Apply the formatter.
fix:
    gofmt -w .

# Switch to main and fast-forward it from origin; refuses local changes or a diverged main.
ff:
    #!/usr/bin/env sh
    set -eu
    if [ -n "$(git status --porcelain)" ]; then echo "ff: the working tree has changes" >&2; exit 1; fi
    git switch main
    git fetch origin main
    git merge --ff-only origin/main
