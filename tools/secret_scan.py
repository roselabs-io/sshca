"""The offline secret scan of the tracked files, run by `just secrets` inside `just gate`.

```sh
uv run --no-project --with detect-secrets==1.5.0 python tools/secret_scan.py
```

Run in a Git checkout, it scans every file of `git ls-files` with detect-secrets, using the plugins,
filters and results of `.secrets.baseline` in the current directory. A finding is a secret the
baseline does not hold, compared by file, secret hash and type, not by line. Each finding is printed
as `path:line: type` and the exit is 1; with none the exit is 0, and 2 when the baseline cannot be
read. The scan writes nothing, also when the baseline's line numbers are out of date.

The baseline was written with `--no-verify`, so no plugin calls a service to verify a finding and
the scan runs without the network. To accept a finding that is not a secret, or to refresh the
baseline's line numbers:

```sh
git ls-files -z | xargs -0 uv tool run --from detect-secrets==1.5.0 detect-secrets scan --no-verify --baseline .secrets.baseline
```

then review the changed entries in the diff. Limits: the detectors are detect-secrets' patterns and
entropy rules, so a secret of an unknown format with low entropy is not found; untracked files and
Git history are not scanned. Installing detect-secrets needs the network once; uv caches it.
"""

from __future__ import annotations

import subprocess
import sys

from detect_secrets import SecretsCollection
from detect_secrets.core import baseline
from detect_secrets.exceptions import UnableToReadBaselineError
from detect_secrets.settings import transient_settings

BASELINE = ".secrets.baseline"


def findings() -> list[str]:
    """``path:line: type`` of each secret of the tracked files that the baseline does not hold."""
    tracked = subprocess.run(["git", "ls-files", "-z"], capture_output=True, text=True, check=True).stdout
    with transient_settings({}):
        accepted = baseline.load(baseline.load_from_file(BASELINE), BASELINE)
        scanned = SecretsCollection()
        scanned.scan_files(*filter(None, tracked.split("\0")))
        new = scanned - accepted
    return sorted(f"{path}:{secret.line_number}: {secret.type}" for path, secret in new)


def main() -> int:
    try:
        found = findings()
    except UnableToReadBaselineError:
        print(f"{BASELINE}: missing or not JSON", file=sys.stderr)
        return 2
    for finding in found:
        print(finding)
    if found:
        print(f"{len(found)} secrets not in {BASELINE}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
