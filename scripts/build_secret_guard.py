#!/usr/bin/env python3
"""Keep an allowlisted build secret inside the one binary it is compiled into.

A secret reaches this script only through the environment, under its own
allowlisted name, and is never printed, written, or passed as an argument.

  value NAME             the value is usable: one line of 16-512 printable,
                         non-space ASCII characters
  absent NAME FILE...    the value appears in none of the files
  present NAME FILE      the value appears in the file (it was compiled in)
  payload PAYLOAD_DIR    a finished payload: every recorded secret is in its
                         own integration's binary and in no other file
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MINIMUM, MAXIMUM = 16, 512


class Leak(SystemExit):
    def __init__(self, message: str):
        super().__init__(f"build secret check failed: {message}")


def secret(name: str) -> bytes:
    """The held value of NAME. Too short a value would match unrelated bytes,
    and whitespace would not survive being compiled in verbatim."""
    value = os.environ.get(name, "")
    if not value:
        raise Leak(f"{name} is not set")
    if not MINIMUM <= len(value) <= MAXIMUM or any(not "!" <= char <= "~" for char in value):
        raise Leak(
            f"{name} must be {MINIMUM}-{MAXIMUM} printable ASCII characters with no spaces or "
            "line breaks (set the secret without a trailing newline)"
        )
    return value.encode("ascii")


def contains(path: Path, needle: bytes) -> bool:
    return needle in path.read_bytes()


def check_payload(payload: Path) -> None:
    allowed = json.loads((ROOT / "build-secrets.json").read_text(encoding="utf-8"))["integrations"]
    require = os.environ.get("COUCH_FEED_REQUIRE_BUILD_SECRETS", "0") == "1"
    binaries = {}
    for line in (payload / "selected.tsv").read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        binaries[fields[0]] = payload / fields[0] / fields[3]
    files = [path for path in sorted(payload.rglob("*")) if path.is_file() or path.is_symlink()]
    checked = 0
    for integration_id, names in sorted(allowed.items()):
        recorded = None
        if integration_id in binaries:
            receipt = json.loads((payload / integration_id / "provenance.json").read_text(encoding="utf-8"))
            recorded = receipt.get("built_with_secrets")
            if not isinstance(recorded, list) or any(name not in names for name in recorded):
                raise Leak(f"{integration_id} provenance does not record its build secrets")
            if require and recorded != names:
                raise Leak(f"{integration_id} is publishable only when built with {', '.join(names)}")
        for name in names:
            if not os.environ.get(name):
                if recorded and name in recorded:
                    raise Leak(f"{name} is recorded in {integration_id} provenance but is not available to check")
                continue
            needle = secret(name)
            own = binaries.get(integration_id)
            for path in files:
                if path.is_symlink():
                    raise Leak(f"payload contains a symlink: {path.relative_to(payload)}")
                if path != own and contains(path, needle):
                    raise Leak(f"{name} appears in {path.relative_to(payload)}")
            compiled_in = own is not None and contains(own, needle)
            if compiled_in != bool(recorded and name in recorded):
                raise Leak(f"{integration_id} provenance and binary disagree about {name}")
            checked += 1
    print(f"build secret check passed: {checked} secret(s) confined to their own binaries")


def main(argv: list[str]) -> None:
    if len(argv) >= 2 and argv[0] == "value" and len(argv) == 2:
        secret(argv[1])
    elif len(argv) >= 3 and argv[0] == "absent":
        needle = secret(argv[1])
        for path in map(Path, argv[2:]):
            if contains(path, needle):
                raise Leak(f"{argv[1]} appears in {path.name}")
    elif len(argv) == 3 and argv[0] == "present":
        if not contains(Path(argv[2]), secret(argv[1])):
            raise Leak(f"{argv[1]} was supplied but is not compiled into {Path(argv[2]).name}")
    elif len(argv) == 2 and argv[0] == "payload":
        check_payload(Path(argv[1]).resolve())
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
