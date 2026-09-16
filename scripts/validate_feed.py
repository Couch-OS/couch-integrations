#!/usr/bin/env python3
"""Validate the Couch source pin, channel policy, and committed APK trust key."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMIT = re.compile(r"[0-9a-f]{40}")
EXPECTED_REPOSITORY = "https://github.com/dangerouslaser/couch.git"
CHANNELS = {"preview", "stable"}
PUBLISHABLE_TIERS = {"preview", "production"}


class InvalidFeed(ValueError):
    pass


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InvalidFeed(f"cannot read {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise InvalidFeed(f"{path.name} must be an object")
    return value


def exact_keys(value: dict, expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise InvalidFeed(f"{context} keys must be exactly {sorted(expected)}")


def safe_component(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not value.startswith(".")
        and all(
            byte.isascii()
            and (byte.isalnum() or byte in {".", "+", "_", "-"})
            for byte in value
        )
    )


def safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = Path(value)
    return not path.is_absolute() and all(safe_component(part) for part in path.parts)


def source_pin() -> dict:
    pin = load_json(ROOT / "source-pin.json")
    exact_keys(pin, {"schema", "repository", "commit"}, "source-pin.json")
    if (
        pin["schema"] != 1
        or pin["repository"] != EXPECTED_REPOSITORY
        or not isinstance(pin["commit"], str)
        or not COMMIT.fullmatch(pin["commit"])
    ):
        raise InvalidFeed("source-pin.json must name dangerouslaser/couch at one full commit SHA")
    return pin


def policy() -> dict:
    value = load_json(ROOT / "feed-policy.json")
    exact_keys(value, {"schema", "channels"}, "feed-policy.json")
    channels = value["channels"]
    if value["schema"] != 1 or not isinstance(channels, dict) or set(channels) != CHANNELS:
        raise InvalidFeed("feed-policy.json must define preview and stable channels")
    for channel, rule in channels.items():
        if not isinstance(rule, dict):
            raise InvalidFeed(f"{channel} policy must be an object")
        exact_keys(rule, {"ids", "allowed_tiers"}, f"{channel} policy")
        if (
            not isinstance(rule["ids"], list)
            or not all(safe_component(item) for item in rule["ids"])
            or len(set(rule["ids"])) != len(rule["ids"])
            or not isinstance(rule["allowed_tiers"], list)
            or not all(
                isinstance(item, str) and item in PUBLISHABLE_TIERS
                for item in rule["allowed_tiers"]
            )
            or not rule["allowed_tiers"]
            or len(set(rule["allowed_tiers"])) != len(rule["allowed_tiers"])
        ):
            raise InvalidFeed(f"{channel} policy has invalid IDs or tiers")
    if value["channels"]["stable"]["allowed_tiers"] != ["production"]:
        raise InvalidFeed("stable policy must allow production tier only")
    return value


def validate_key() -> None:
    path = ROOT / "keys/couch-integrations.rsa.pub"
    try:
        data = path.read_text(encoding="ascii")
    except OSError as error:
        raise InvalidFeed(f"cannot read committed APK public key: {error}") from error
    if "REPLACE_WITH" in data:
        raise InvalidFeed("replace keys/couch-integrations.rsa.pub before enabling admission or publish")
    if not data.startswith("-----BEGIN PUBLIC KEY-----") or not data.rstrip().endswith("-----END PUBLIC KEY-----"):
        raise InvalidFeed("committed APK public key must be a PEM public key")
    checked = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(path), "-noout"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if checked.returncode:
        raise InvalidFeed(f"committed APK public key is invalid: {checked.stderr.strip()}")


def git_head(core: Path) -> str:
    checked = subprocess.run(
        ["git", "-C", str(core), "rev-parse", "HEAD"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if checked.returncode:
        raise InvalidFeed(f"cannot read checked out Couch source: {checked.stderr.strip()}")
    return checked.stdout.strip()


def validate_catalog(core: Path, pin: dict, selected_policy: dict) -> None:
    if git_head(core) != pin["commit"]:
        raise InvalidFeed("checked out Couch source does not match source-pin.json")
    catalog_path = core / "integrations/catalog.json"
    catalog = load_json(catalog_path)
    if catalog.get("schema") != 1 or catalog.get("protocol_version") != 1:
        raise InvalidFeed("pinned Couch catalog must use integration protocol 1")
    entries = catalog.get("integrations")
    if not isinstance(entries, list):
        raise InvalidFeed("pinned Couch catalog has no integration list")
    by_id = {}
    for entry in entries:
        if not isinstance(entry, dict) or not safe_component(entry.get("id")):
            raise InvalidFeed("pinned Couch catalog has an invalid integration ID")
        integration_id = entry["id"]
        if integration_id in by_id:
            raise InvalidFeed(f"pinned Couch catalog repeats integration {integration_id}")
        by_id[integration_id] = entry
    for channel, rule in selected_policy["channels"].items():
        for integration_id in rule["ids"]:
            entry = by_id.get(integration_id)
            if entry is None:
                raise InvalidFeed(f"{channel} selects missing integration {integration_id}")
            tier = entry.get("tier")
            synthetic = entry.get("synthetic", False)
            if not isinstance(tier, str) or not isinstance(synthetic, bool):
                raise InvalidFeed(f"{integration_id} catalog tier or synthetic flag is invalid")
            if channel == "stable" and tier != "production":
                raise InvalidFeed(f"stable selects non-production integration {integration_id}")
            if tier == "test-only" or synthetic:
                raise InvalidFeed(f"{channel} must never publish synthetic or test-only {integration_id}")
            if tier not in rule["allowed_tiers"]:
                raise InvalidFeed(f"{channel} selects {integration_id} at disallowed tier {tier!r}")
            manifest_name = entry.get("manifest")
            binary = entry.get("binary")
            if not safe_relative_path(manifest_name) or not safe_component(binary):
                raise InvalidFeed(f"{integration_id} catalog paths are invalid")
            manifest = (core / manifest_name).resolve()
            if not manifest.is_relative_to(core.resolve()):
                raise InvalidFeed(f"{integration_id} manifest escapes the pinned Couch source")
            try:
                manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise InvalidFeed(f"{integration_id} manifest is unreadable: {error}") from error
            if (
                not isinstance(manifest_data, dict)
                or manifest_data.get("protocol_version") != 1
                or manifest_data.get("id") != integration_id
                or not isinstance(manifest_data.get("version"), str)
                or not manifest_data["version"]
                or manifest_data.get("executable") != f"bin/{binary}"
            ):
                raise InvalidFeed(f"{integration_id} manifest does not match its catalog record")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True, help="checkout of the pinned Couch source")
    args = parser.parse_args()
    try:
        pin = source_pin()
        selected_policy = policy()
        validate_key()
        validate_catalog(args.core.resolve(), pin, selected_policy)
    except InvalidFeed as error:
        print(f"feed validation failed: {error}", file=sys.stderr)
        return 1
    print(f"feed policy valid for Couch {pin['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
