#!/usr/bin/env python3
"""Validate an unsigned payload artifact before the protected signer uses it."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"payload validation failed: {message}")


if len(sys.argv) != 4:
    raise SystemExit(f"Usage: {sys.argv[0]} FEED_ROOT CORE_CHECKOUT PAYLOAD_DIR")

feed, core, payload = map(Path, sys.argv[1:])
pin = json.loads((feed / "source-pin.json").read_text(encoding="utf-8"))
policy = json.loads((feed / "feed-policy.json").read_text(encoding="utf-8"))
if (payload / "CORE_COMMIT").read_text(encoding="utf-8").strip() != pin["commit"]:
    fail("artifact core commit does not match source pin")
catalog = json.loads((core / "integrations/catalog.json").read_text(encoding="utf-8"))
entries = {entry["id"]: entry for entry in catalog["integrations"]}
selected = []
for integration_id in policy["channels"]["preview"]["ids"]:
    entry = entries.get(integration_id)
    if entry is None:
        fail(f"missing selected integration {integration_id}")
    selected.append((integration_id, entry))
for integration_id, entry in selected:
    directory = payload / integration_id
    binary = directory / entry["binary"]
    manifest = directory / "manifest.json"
    provenance = directory / "provenance.json"
    if not all(path.is_file() for path in (binary, manifest, provenance)):
        fail(f"{integration_id} payload is incomplete")
    artifact_manifest = json.loads(manifest.read_text(encoding="utf-8"))
    core_manifest = json.loads((core / entry["manifest"]).read_text(encoding="utf-8"))
    record = json.loads(provenance.read_text(encoding="utf-8"))
    expected = {
        "schema": 1,
        "core_commit": pin["commit"],
        "id": integration_id,
        "version": core_manifest["version"],
        "binary": entry["binary"],
        "binary_sha256": digest(binary),
        "manifest_sha256": digest(manifest),
    }
    if artifact_manifest != core_manifest or record != expected:
        fail(f"{integration_id} manifest or provenance does not match pinned core")
print("payload provenance valid")
