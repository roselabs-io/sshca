# Go CLI recipes of the command contract. `check` and `gate` are what the local preflight runs.

# Static checks: vet and formatting.
check:
    go vet ./...
    test -z "$(gofmt -l .)"

# The test suite.
test:
    go test -p "${GOVERNOR_JOBS:-1}" ./...

# `go vet` and `go build` with CGO_ENABLED=0 for the six release targets of `release.yml` (the build
# matrix of `ci.yml`). The binaries are written to a temporary directory and removed.
build:
    #!/usr/bin/env sh
    set -eu
    out="$(mktemp -d)"
    trap 'rm -rf "$out"' EXIT
    for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
        echo "go vet $target"
        CGO_ENABLED=0 GOOS="${target%/*}" GOARCH="${target#*/}" go vet ./...
        echo "go build $target"
        CGO_ENABLED=0 GOOS="${target%/*}" GOARCH="${target#*/}" go build -o "$out/sshca-${target%/*}-${target#*/}" .
    done

# The deterministic gate CI runs.
gate: check test build

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
