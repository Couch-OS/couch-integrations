#!/usr/bin/env python3
"""Validate an unsigned multi-source payload before the protected signer.

An integration listed in build-secrets.json is publishable only when its
receipt records every one of its build secrets. --review also accepts a receipt
that records none: a pull request build, which has no secrets and compiled the
integration's placeholder. The signing job never passes --review.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"payload validation failed: {message}")


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain an object")
    return value


arguments = sys.argv[1:]
review = arguments[:1] == ["--review"]
if review:
    del arguments[0]
if len(arguments) != 3:
    raise SystemExit(f"Usage: {sys.argv[0]} [--review] FEED_ROOT SOURCES_DIR PAYLOAD_DIR")

feed, sources, payload = map(Path, arguments)
pins = load(feed / "source-pin.json")
policy = load(feed / "feed-policy.json")
build_secrets = load(feed / "build-secrets.json").get("integrations")
if not isinstance(build_secrets, dict):
    fail("build-secrets.json must map integration IDs to secret names")
if load(payload / "SOURCE_PINS.json") != pins:
    fail("artifact source pins do not match the reviewed feed pins")

for integration_id in policy["channels"]["preview"]["ids"]:
    source = sources / "integrations" / integration_id
    metadata = load(source / "integration.json")
    pin = pins["integrations"].get(integration_id)
    if pin is None:
        fail(f"missing source pin for {integration_id}")
    directory = payload / integration_id
    binary = directory / metadata["binary"]
    manifest = directory / "manifest.json"
    provenance = directory / "provenance.json"
    if any(path.is_symlink() or not path.is_file() for path in (binary, manifest, provenance)):
        fail(f"{integration_id} payload is incomplete or contains a symlink")
    artifact_manifest = load(manifest)
    source_manifest = load(source / metadata["manifest"])
    try:
        cargo = tomllib.loads((source / metadata["cargo_manifest"]).read_text(encoding="utf-8"))
        sdk_commit = cargo["dependencies"]["couch-sdk"]["rev"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read {integration_id} SDK pin: {error}")
    record = load(provenance)
    expected = {
        "schema": 2,
        "source_repository": pin["repository"],
        "source_commit": pin["commit"],
        "sdk_repository": pins["tooling"]["repository"],
        "sdk_commit": sdk_commit,
        "tooling_repository": pins["tooling"]["repository"],
        "tooling_commit": pins["tooling"]["commit"],
        "id": integration_id,
        "version": source_manifest["version"],
        "binary": metadata["binary"],
        "binary_sha256": digest(binary),
        "manifest_sha256": digest(manifest),
    }
    if integration_id in build_secrets:
        required = build_secrets[integration_id]
        recorded = record.get("built_with_secrets")
        if recorded != required and not (review and recorded == []):
            fail(
                f"{integration_id} was not built with its required build secrets "
                f"({', '.join(required)}); only a main-branch admission build is publishable"
            )
        expected["built_with_secrets"] = recorded
    if artifact_manifest != source_manifest or record != expected:
        fail(f"{integration_id} manifest or provenance does not match its pinned source")

allowed = set(policy["channels"]["preview"]["ids"])
for child in payload.iterdir():
    if child.is_dir() and child.name not in allowed:
        fail(f"payload contains unselected integration {child.name}")
print("payload provenance valid")
