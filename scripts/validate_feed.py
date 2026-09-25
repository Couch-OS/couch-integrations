#!/usr/bin/env python3
"""Validate immutable integration sources, channel policy, and APK trust."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMIT = re.compile(r"[0-9a-f]{40}")
# The Couch repositories are moving from dangerouslaser to the Couch-OS
# organization. GitHub redirects transferred Git URLs, so a pin may name either
# owner, spelled exactly as listed: one canonical URL per repository and owner.
OWNERS = ("dangerouslaser", "Couch-OS")
REPOSITORY = re.compile(
    r"https://github\.com/(?P<owner>{})/(?P<name>[a-z0-9][a-z0-9._-]*)(?<!\.git)\.git".format(
        "|".join(map(re.escape, OWNERS))
    )
)
CORE_REPOSITORIES = frozenset(f"https://github.com/{owner}/couch.git" for owner in OWNERS)
# The plugin protocol versions the pinned tooling host admits.
PROTOCOL_VERSIONS = frozenset({1, 2, 3, 4, 5})
RECEIPT_FIELDS = frozenset({
    "schema", "source_repository", "source_commit", "sdk_repository",
    "sdk_commit", "tooling_repository", "tooling_commit", "id", "version",
    "binary", "binary_sha256", "manifest_sha256",
})
# An integration named in build-secrets.json carries one more receipt field: the
# names (never the values) of the build secrets its binary was compiled with.
# Every other receipt keeps exactly the twelve fields above.
RECEIPT_SECRETS_FIELD = "built_with_secrets"
RECEIPT_COMMITS = ("source_commit", "sdk_commit", "tooling_commit")
RECEIPT_REPOSITORIES = ("source_repository", "sdk_repository", "tooling_repository")
CHANNELS = {"preview", "stable"}
PUBLISHABLE_TIERS = {"preview", "production"}
METADATA_KEYS = {
    "schema", "protocol_version", "id", "tier", "synthetic",
    "cargo_manifest", "cargo_package", "binary", "manifest",
}
REQUIRED_ADMISSION_CALLS = {
    "conformance": "testing::conformance(",
    "failure": "testing::failure(",
    "timeout_no_retry": "testing::timeout_no_retry(",
    "spike": "testing::spike(",
    "concurrent_package_startup_is_offline_and_race_free": "testing::Package::new(",
}
CONCURRENT_ADMISSION = {
    "concurrent_package_startup_is_offline_and_race_free": "testing::Package::new(",
}


BUILD_SECRET_NAME = re.compile(r"COUCH(?:_[A-Z0-9]+)+")


class InvalidFeed(ValueError):
    pass


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InvalidFeed(f"cannot read {path}: {error}") from error
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
        and all(byte.isascii() and (byte.isalnum() or byte in {".", "+", "_", "-"}) for byte in value)
    )


def safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = Path(value)
    return not path.is_absolute() and all(safe_component(part) for part in path.parts)


def validate_pin(pin: object, context: str, *, core: bool = False) -> dict:
    if not isinstance(pin, dict):
        raise InvalidFeed(f"{context} must be an object")
    exact_keys(pin, {"repository", "commit"}, context)
    repository = pin["repository"]
    commit = pin["commit"]
    if (
        not isinstance(repository, str)
        or not REPOSITORY.fullmatch(repository)
        or (core and repository not in CORE_REPOSITORIES)
        or not isinstance(commit, str)
        or not COMMIT.fullmatch(commit)
        or commit == "0" * 40
    ):
        raise InvalidFeed(f"{context} must name an allowed repository at one full commit SHA")
    return pin


def source_pins() -> dict:
    pins = load_json(ROOT / "source-pin.json")
    exact_keys(pins, {"schema", "tooling", "integrations"}, "source-pin.json")
    if pins["schema"] != 2 or not isinstance(pins["integrations"], dict):
        raise InvalidFeed("source-pin.json must use multi-source schema 2")
    validate_pin(pins["tooling"], "tooling source", core=True)
    for integration_id, pin in pins["integrations"].items():
        if not safe_component(integration_id):
            raise InvalidFeed("source-pin.json has an invalid integration ID")
        validate_pin(pin, f"{integration_id} source")
    return pins


def policy() -> dict:
    value = load_json(ROOT / "feed-policy.json")
    exact_keys(value, {"schema", "channels"}, "feed-policy.json")
    channels = value["channels"]
    if value["schema"] != 1 or not isinstance(channels, dict) or set(channels) != CHANNELS:
        raise InvalidFeed("feed-policy.json must define preview and stable channels")
    selected: list[str] = []
    for channel, rule in channels.items():
        if not isinstance(rule, dict):
            raise InvalidFeed(f"{channel} policy must be an object")
        exact_keys(rule, {"ids", "allowed_tiers"}, f"{channel} policy")
        if (
            not isinstance(rule["ids"], list)
            or not all(safe_component(item) for item in rule["ids"])
            or len(set(rule["ids"])) != len(rule["ids"])
            or not isinstance(rule["allowed_tiers"], list)
            or not all(isinstance(item, str) and item in PUBLISHABLE_TIERS for item in rule["allowed_tiers"])
            or not rule["allowed_tiers"]
            or len(set(rule["allowed_tiers"])) != len(rule["allowed_tiers"])
        ):
            raise InvalidFeed(f"{channel} policy has invalid IDs or tiers")
        selected.extend(rule["ids"])
    if len(set(selected)) != len(selected):
        raise InvalidFeed("an integration may appear in only one channel")
    if value["channels"]["stable"]["allowed_tiers"] != ["production"]:
        raise InvalidFeed("stable policy must allow production tier only")
    return value


def build_secret_prefix(integration_id: str) -> str:
    """The only environment namespace an integration's build secrets may use."""
    return "COUCH_" + re.sub(r"[^A-Z0-9]", "_", integration_id.upper()) + "_"


def build_secrets() -> dict[str, list[str]]:
    """The reviewed allowlist of build-time secrets: integration ID to the
    environment variable names its compile step may receive.

    Only this file grants a secret. An integration repository cannot ask for
    one, and a name must sit in its own integration's COUCH_<ID>_ namespace, so
    it can never shadow a toolchain variable or another integration's secret.
    """
    value = load_json(ROOT / "build-secrets.json")
    exact_keys(value, {"schema", "integrations"}, "build-secrets.json")
    allowed = value["integrations"]
    if value["schema"] != 1 or not isinstance(allowed, dict):
        raise InvalidFeed("build-secrets.json must map integration IDs to secret names")
    prefixes: set[str] = set()
    for integration_id, names in allowed.items():
        if not safe_component(integration_id):
            raise InvalidFeed("build-secrets.json has an invalid integration ID")
        prefix = build_secret_prefix(integration_id)
        if prefix in prefixes:
            raise InvalidFeed(f"build-secrets.json IDs collide in the {prefix} namespace")
        prefixes.add(prefix)
        if (
            not isinstance(names, list)
            or not names
            or not all(isinstance(name, str) for name in names)
            or names != sorted(set(names))
        ):
            raise InvalidFeed(f"{integration_id} build secrets must be a sorted list of unique names")
        for name in names:
            if not BUILD_SECRET_NAME.fullmatch(name) or not name.startswith(prefix):
                raise InvalidFeed(f"{integration_id} build secret {name!r} must be named {prefix}...")
    return allowed


def repository_name(repository: object) -> str | None:
    """Return the repository name of an allowed-owner GitHub URL, else None."""
    match = REPOSITORY.fullmatch(repository) if isinstance(repository, str) else None
    return match["name"] if match else None


def validate_retained_receipt(
    approved: object, existing: object, allowed_secrets: dict[str, list[str]] | None = None,
) -> None:
    """Allow reuse of a published APK only when its original receipt describes
    the approved payload's exact bytes.

    Two historical differences are tolerated: a pin commit may have advanced
    without changing the package, and a repository may have moved between the
    allowed owners under the same name. Every other field must be identical,
    including the names of the build secrets an allowlisted integration was
    compiled with.
    """
    fields = RECEIPT_FIELDS
    if isinstance(approved, dict) and isinstance(approved.get("id"), str) \
            and approved["id"] in (allowed_secrets or {}):
        fields = RECEIPT_FIELDS | {RECEIPT_SECRETS_FIELD}
    if (
        not isinstance(approved, dict)
        or not isinstance(existing, dict)
        or set(approved) != fields
        or set(existing) != fields
    ):
        raise InvalidFeed("existing APK provenance receipt has an invalid shape")
    for field in RECEIPT_COMMITS:
        if not isinstance(existing[field], str) or not COMMIT.fullmatch(existing[field]):
            raise InvalidFeed(f"existing APK provenance receipt has an invalid {field}")
    for field in RECEIPT_REPOSITORIES:
        name = repository_name(existing[field])
        if name is None:
            raise InvalidFeed(f"existing APK provenance receipt has an invalid {field}")
        if name != repository_name(approved[field]):
            raise InvalidFeed(f"existing APK {field} names a different repository than the approved payload")
    identity = fields.difference(RECEIPT_COMMITS, RECEIPT_REPOSITORIES)
    if any(existing[field] != approved[field] for field in identity):
        raise InvalidFeed("existing APK immutable provenance differs from approved payload")


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
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if checked.returncode:
        raise InvalidFeed(f"committed APK public key is invalid: {checked.stderr.strip()}")


def git_head(source: Path) -> str:
    checked = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if checked.returncode:
        raise InvalidFeed(f"cannot read checked out source {source}: {checked.stderr.strip()}")
    return checked.stdout.strip()


def contained_file(source: Path, relative: object, context: str) -> Path:
    if not safe_relative_path(relative):
        raise InvalidFeed(f"{context} path is invalid")
    resolved = (source / str(relative)).resolve()
    if not resolved.is_relative_to(source.resolve()) or not resolved.is_file():
        raise InvalidFeed(f"{context} path is missing or escapes its source")
    return resolved


def dependency_pin(dependency: object, context: str) -> tuple[str, str]:
    if not isinstance(dependency, dict):
        raise InvalidFeed(f"{context} must be a pinned Git dependency")
    if dependency.get("git") not in CORE_REPOSITORIES or not COMMIT.fullmatch(str(dependency.get("rev", ""))):
        raise InvalidFeed(f"{context} must pin the Couch repository at a full commit")
    if "path" in dependency or "branch" in dependency or "tag" in dependency:
        raise InvalidFeed(f"{context} cannot use a local path, branch, or tag")
    return dependency["git"], dependency["rev"]


def validate_integration(source: Path, integration_id: str, pin: dict) -> dict:
    if git_head(source) != pin["commit"]:
        raise InvalidFeed(f"checked out {integration_id} source does not match its pin")
    metadata = load_json(source / "integration.json")
    exact_keys(metadata, METADATA_KEYS, f"{integration_id} integration.json")
    if (
        metadata["schema"] != 1
        or type(metadata["protocol_version"]) is not int
        or metadata["protocol_version"] not in PROTOCOL_VERSIONS
        or metadata["id"] != integration_id
        or not isinstance(metadata["tier"], str)
        or not isinstance(metadata["synthetic"], bool)
        or not safe_component(metadata["cargo_package"])
        or not safe_component(metadata["binary"])
    ):
        raise InvalidFeed(f"{integration_id} source metadata is invalid")
    cargo_path = contained_file(source, metadata["cargo_manifest"], f"{integration_id} Cargo manifest")
    cargo_config_path = (source / ".cargo/config.toml").resolve()
    if not cargo_config_path.is_relative_to(source.resolve()) or not cargo_config_path.is_file():
        raise InvalidFeed(f"{integration_id} Cargo config is missing or escapes its source")
    manifest_path = contained_file(source, metadata["manifest"], f"{integration_id} plugin manifest")
    admission_path = contained_file(source, "tests/admission.rs", f"{integration_id} admission tests")
    try:
        cargo = tomllib.loads(cargo_path.read_text(encoding="utf-8"))
        cargo_config = tomllib.loads(cargo_config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InvalidFeed(f"{integration_id} Cargo configuration is unreadable: {error}") from error
    if cargo.get("package", {}).get("name") != metadata["cargo_package"]:
        raise InvalidFeed(f"{integration_id} Cargo package does not match integration.json")
    if cargo_config.get("target", {}).get("armv7-unknown-linux-musleabihf", {}).get("linker") != "rust-lld":
        raise InvalidFeed(f"{integration_id} must use rust-lld for the ARMv7 target")
    manifest = load_json(manifest_path)
    admission = admission_path.read_text(encoding="utf-8")
    required = CONCURRENT_ADMISSION
    if metadata["protocol_version"] < 3:
        required = REQUIRED_ADMISSION_CALLS
    for case, harness_call in required.items():
        declaration = re.compile(rf"#\[test\]\s*fn\s+{re.escape(case)}\s*\(")
        if not declaration.search(admission) or harness_call not in admission:
            raise InvalidFeed(f"{integration_id} admission must reuse the shared {case} case")
    if metadata["protocol_version"] == 3:
        tests = "\n".join(
            path.read_text(encoding="utf-8") for path in sorted((source / "tests").glob("*.rs"))
        )
        if manifest.get("children") and "testing_v3::children(" not in tests:
            raise InvalidFeed(f"{integration_id} admission must reuse the shared children case")
        if manifest.get("pairing") and "testing_v3::pairing(" not in tests:
            raise InvalidFeed(f"{integration_id} admission must reuse the shared pairing case")
    dependencies = {
        dependency_pin(cargo.get(table, {}).get(name), f"{integration_id} {prefix}{name}")
        for table, prefix in (("dependencies", ""), ("dev-dependencies", "dev "))
        for name in ("couch-plugin", "couch-sdk")
    }
    revisions = {revision for _, revision in dependencies}
    if len(revisions) != 1:
        raise InvalidFeed(f"{integration_id} SDK dependencies do not share one revision")
    # Either core URL resolves to the same repository, but Cargo treats two
    # spellings as two sources and would build duplicate protocol crates.
    if len({repository for repository, _ in dependencies}) != 1:
        raise InvalidFeed(f"{integration_id} SDK dependencies do not share one Couch repository URL")
    metadata = dict(metadata)
    metadata["sdk_commit"] = revisions.pop()
    if (
        manifest.get("protocol_version") != metadata["protocol_version"]
        # The core refuses a manifest whose minimum core protocol differs from
        # its own protocol, and reads an absent minimum as 1.
        or manifest.get("min_core_protocol_version", 1) != metadata["protocol_version"]
        or manifest.get("id") != integration_id
        or not isinstance(manifest.get("version"), str)
        or not manifest["version"]
        or manifest.get("executable") != f"bin/{metadata['binary']}"
    ):
        raise InvalidFeed(f"{integration_id} plugin manifest does not match integration.json")
    metadata["source"] = source
    metadata["manifest_data"] = manifest
    return metadata


def validate_sources(sources: Path, pins: dict, selected_policy: dict) -> dict[str, dict]:
    tooling = sources / "tooling"
    if git_head(tooling) != pins["tooling"]["commit"]:
        raise InvalidFeed("checked out tooling source does not match its pin")
    for required in (
        "tools/arm-cc-env.sh", "tools/fetch-zig.sh",
        "tools/integrations/build-apk.sh", "tools/integrations/build-repository.sh",
    ):
        contained_file(tooling, required, "tooling")
    selected: dict[str, dict] = {}
    for channel, rule in selected_policy["channels"].items():
        for integration_id in rule["ids"]:
            pin = pins["integrations"].get(integration_id)
            if pin is None:
                raise InvalidFeed(f"{channel} selects unpinned integration {integration_id}")
            metadata = validate_integration(sources / "integrations" / integration_id, integration_id, pin)
            tier = metadata["tier"]
            if channel == "stable" and tier != "production":
                raise InvalidFeed(f"stable selects non-production integration {integration_id}")
            if tier == "test-only" or metadata["synthetic"]:
                raise InvalidFeed(f"{channel} must never publish synthetic or test-only {integration_id}")
            if tier not in rule["allowed_tiers"]:
                raise InvalidFeed(f"{channel} selects {integration_id} at disallowed tier {tier!r}")
            selected[integration_id] = metadata
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, help="checkout tree created by checkout_sources.sh")
    parser.add_argument("--pins-only", action="store_true", help="validate committed pins without checkouts")
    parser.add_argument("--emit-pins", action="store_true", help="emit validated checkout pins as TSV")
    parser.add_argument("--emit-selected", action="store_true", help="emit selected integration metadata as TSV")
    parser.add_argument(
        "--emit-build-secrets", action="store_true",
        help="emit every allowlisted build secret name, and whether its integration is selected, as TSV",
    )
    parser.add_argument(
        "--retained-receipt", nargs=2, type=Path, metavar=("APPROVED", "EXISTING"),
        help="check that a published APK receipt may be reused for an approved payload receipt",
    )
    args = parser.parse_args()
    try:
        pins = source_pins()
        selected_policy = policy()
        allowed_secrets = build_secrets()
        validate_key()
        if args.retained_receipt:
            validate_retained_receipt(*map(load_json, args.retained_receipt), allowed_secrets)
            return 0
        if args.emit_pins:
            print("\t".join(("tooling", pins["tooling"]["repository"], pins["tooling"]["commit"])))
            for integration_id, pin in sorted(pins["integrations"].items()):
                print("\t".join((f"integrations/{integration_id}", pin["repository"], pin["commit"])))
            return 0
        if args.pins_only:
            return 0
        if args.sources is None:
            raise InvalidFeed("--sources is required unless --pins-only is used")
        selected = validate_sources(args.sources.resolve(), pins, selected_policy)
        if args.emit_build_secrets:
            # Every allowlisted name is listed so the build can scrub all of
            # them; only a preview-selected integration is ever compiled.
            published = selected_policy["channels"]["preview"]["ids"]
            for integration_id, names in sorted(allowed_secrets.items()):
                for name in names:
                    if integration_id in published:
                        print("\t".join((integration_id, name, "selected", selected[integration_id]["binary"])))
                    else:
                        print("\t".join((integration_id, name, "unselected", "-")))
            return 0
        if args.emit_selected:
            for integration_id in selected_policy["channels"]["preview"]["ids"]:
                item = selected[integration_id]
                print("\t".join((
                    integration_id, item["cargo_manifest"], item["cargo_package"], item["binary"],
                    item["manifest"], pins["integrations"][integration_id]["repository"],
                    pins["integrations"][integration_id]["commit"], item["sdk_commit"],
                )))
            return 0
    except InvalidFeed as error:
        print(f"feed validation failed: {error}", file=sys.stderr)
        return 1
    print(f"feed policy valid for {len(selected)} independently pinned integration source(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
