#!/usr/bin/env python3
"""The local check the dispatcher runs on a committed candidate: `just secrets-env`, `just check`,
then `just gate`.

Writes the record the dispatcher reads, `<git dir>/sshca-preflight/result.json` (`status`,
`reason`, `base`, `mode`, `checks`, `candidate`), and appends command output to `checks.log` beside
it. The dispatcher accepts a `passed` record of mode `recipes` only when `just check` and
`just gate` both exited 0, so a replacement check keeps those two names in `checks`. The script runs
no other program: preparing the checkout belongs to the recipes, and `just secrets-env` prepares
the secret scan's environment before the gate. `--status` prints the saved record. Exit 0 when the
status is `passed`, else 1.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

CHECKS = {
    "just secrets-env": ["just", "secrets-env"],
    "just check": ["just", "check"],
    "just gate": ["just", "gate"],
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def location() -> Path:
    return Path(git("rev-parse", "--absolute-git-dir")) / "sshca-preflight" / "result.json"


def candidate(base: str) -> dict:
    return {
        "head": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "base": git("rev-parse", base),
        "dirty": bool(git("status", "--porcelain", "--untracked-files=all")),
    }


def save(path: Path, record: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        json.dump(record, file, indent=2)


def execute(base: str) -> dict:
    path = location()
    record = {"status": "blocked", "reason": "", "base": base, "mode": "recipes", "checks": {}}
    save(path, record)
    record["candidate"] = candidate(base)
    if record["candidate"]["dirty"]:
        record["reason"] = "commit all candidate changes before preflight"
    else:
        for name, command in CHECKS.items():
            with open(path.with_name("checks.log"), "ab") as log:
                log.write((" ".join(command) + "\n").encode())
                code = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False).returncode
            record["checks"][name] = code
            if code:
                record["status"] = "failed"
                record["reason"] = f"{name} exited {code}; inspect checks.log"
                break
        else:
            record["status"] = "passed"
        if candidate(base) != record["candidate"]:
            record.update(status="blocked", reason="candidate changed during preflight")
    save(path, record)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()
    if args.status:
        try:
            record = json.loads(location().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            record = {"status": "unknown", "reason": "no preflight record"}
    else:
        record = execute(args.base)
    print(json.dumps(record, indent=2))
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
