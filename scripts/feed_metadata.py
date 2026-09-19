#!/usr/bin/env python3
"""Signed freshness metadata for each channel: feed.json and feed.json.sig.

The Alpine index is signed but never expires and has no order, so an old,
validly signed index can be replayed for ever. feed.json names one index by
its hash, carries a sequence that only grows and an expiry date, and lists
every package with its size, hash and protocol numbers. It is signed with the
same key as the index and the packages:

    openssl dgst -sha256 -sign KEY -out feed.json.sig feed.json

This script never builds or changes a package or an index. It reads the bytes
that are about to be deployed and describes them.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import time
from pathlib import Path

CHANNELS = ("preview", "stable")
SCHEMA = 1
VALIDITY_SECONDS = 30 * 24 * 60 * 60
INDEX = "APKINDEX.tar.gz"
METADATA = "feed.json"
SIGNATURE = "feed.json.sig"
# A remote refuses larger files before it parses them.
METADATA_LIMIT = 256 * 1024
SIGNATURE_LIMIT = 1024
MANIFEST_LIMIT = 1024 * 1024
# reusable-index: the previous index cannot be reused, build a new one.
REBUILD = 10

APK_NAME = re.compile(r"couch-integration-([a-z0-9_-]+)-([A-Za-z0-9._+]+)-r0\.apk")
DOCUMENT_KEYS = ["schema", "channel", "sequence", "issued", "expires", "index", "packages"]
INDEX_KEYS = ["path", "size", "sha256"]
PACKAGE_KEYS = ["id", "version", "apk", "size", "sha256", "protocol_version", "min_core_protocol_version"]


class InvalidMetadata(Exception):
    pass


def clock() -> int:
    """Publish time in whole seconds. COUCH_FEED_NOW fixes it for tests."""
    value = os.environ.get("COUCH_FEED_NOW", "")
    if not value:
        return int(time.time())
    if not re.fullmatch(r"[1-9][0-9]{0,11}", value):
        raise InvalidMetadata("COUCH_FEED_NOW must be whole seconds since the Unix epoch")
    return int(value)


def rfc3339(seconds: int) -> str:
    moment = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def file_identity(path: Path) -> tuple[int, str]:
    data = path.read_bytes()
    return len(data), hashlib.sha256(data).hexdigest()


def version_order(version: str) -> list[tuple[int, int, str]]:
    """0.10.0 sorts after 0.9.0; text parts sort after numbers."""
    return [(0, int(part), "") if part.isdigit() else (1, 0, part)
            for part in re.split(r"[.+_-]", version)]


def positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def describe_apk(path: Path) -> dict:
    """One packages[] entry, read from the APK that is published.

    The protocol numbers come from the manifest inside the package, so an APK
    reused from an earlier publication is described without rebuilding it. An
    absent min_core_protocol_version means 1, as in couch-plugin's manifest.rs.
    """
    match = APK_NAME.fullmatch(path.name)
    if match is None:
        raise InvalidMetadata(f"{path.name} is not named couch-integration-ID-VERSION-r0.apk")
    integration_id, version = match.groups()
    wanted = f"usr/lib/couch/integrations/{integration_id}/manifest.json"
    manifest = None
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                if not member.name.endswith("/manifest.json") and member.name != "manifest.json":
                    continue
                if member.name != wanted or not member.isfile() or manifest is not None:
                    raise InvalidMetadata(f"{path.name} must hold exactly one manifest, at {wanted}")
                if member.size > MANIFEST_LIMIT:
                    raise InvalidMetadata(f"{path.name} manifest is too large")
                manifest = json.loads(archive.extractfile(member).read().decode("utf-8"))
    except (OSError, tarfile.TarError, EOFError, ValueError) as error:
        raise InvalidMetadata(f"cannot read the manifest of {path.name}: {error}") from error
    if not isinstance(manifest, dict):
        raise InvalidMetadata(f"{path.name} must hold exactly one manifest, at {wanted}")
    if manifest.get("id") != integration_id or manifest.get("version") != version:
        raise InvalidMetadata(f"{path.name} manifest names another id or version")
    protocol = manifest.get("protocol_version")
    minimum = manifest.get("min_core_protocol_version", 1)
    if not positive_integer(protocol) or not positive_integer(minimum):
        raise InvalidMetadata(f"{path.name} manifest has an invalid protocol version")
    size, sha256 = file_identity(path)
    return {
        "id": integration_id,
        "version": version,
        "apk": path.name,
        "size": size,
        "sha256": sha256,
        "protocol_version": protocol,
        "min_core_protocol_version": minimum,
    }


def indexed_apks(index: Path) -> list[str]:
    """File names of the packages a signed APKINDEX.tar.gz lists."""
    try:
        with tarfile.open(index, "r:gz") as archive:
            text = archive.extractfile("APKINDEX").read().decode("utf-8")
    except (OSError, KeyError, AttributeError, tarfile.TarError, EOFError, ValueError) as error:
        raise InvalidMetadata(f"cannot read {index}: {error}") from error
    names = []
    for block in text.split("\n\n"):
        fields = dict(line.split(":", 1) for line in block.splitlines() if ":" in line)
        if fields:
            if "P" not in fields or "V" not in fields:
                raise InvalidMetadata(f"{index} has a record without a name or version")
            names.append(f"{fields['P']}-{fields['V']}.apk")
    if len(set(names)) != len(names):
        raise InvalidMetadata(f"{index} lists a package twice")
    return sorted(names)


def describe_packages(directory: Path) -> list[dict]:
    packages = [describe_apk(path) for path in directory.glob("*.apk") if path.is_file()]
    return sorted(packages, key=lambda item: (item["id"], version_order(item["version"]), item["version"]))


def describe_channel(site: Path, channel: str) -> tuple[dict, list[dict]]:
    """The index and packages entries for the bytes under SITE/CHANNEL/armv7.

    The directory and the index must name the same packages: metadata that
    lists a package the index does not offer, or the reverse, is never signed.
    """
    directory = site / channel / "armv7"
    index = directory / INDEX
    if not index.is_file():
        raise InvalidMetadata(f"{channel} has no {INDEX}")
    packages = describe_packages(directory)
    if sorted(item["apk"] for item in packages) != indexed_apks(index):
        raise InvalidMetadata(f"{channel} index and package files do not name the same packages")
    size, sha256 = file_identity(index)
    return {"path": INDEX, "size": size, "sha256": sha256}, packages


def document(channel: str, now: int, index: dict, packages: list[dict]) -> dict:
    return {
        "schema": SCHEMA,
        "channel": channel,
        "sequence": now,
        "issued": rfc3339(now),
        "expires": rfc3339(now + VALIDITY_SECONDS),
        "index": index,
        "packages": packages,
    }


def serialize(value: dict) -> bytes:
    """The exact signed bytes: two-space indent, keys in the order written
    above, one trailing newline. A fixed clock gives fixed bytes."""
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def openssl(*arguments: object) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["openssl", *map(str, arguments)], check=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def signature_verifies(public_key: Path, metadata: Path, signature: Path) -> bool:
    return openssl("dgst", "-sha256", "-verify", public_key, "-signature", signature, metadata).returncode == 0


def load_signed(site: Path, channel: str, public_key: Path) -> dict | None:
    """The signed metadata of one channel of a site, or None when it has none.

    Only a site from before feed metadata has none. Half a pair, a signature
    that does not verify or a misshapen document is an error, never "none":
    the sequence check must not be skipped because an archive is damaged.
    """
    metadata = site / channel / "armv7" / METADATA
    signature = site / channel / "armv7" / SIGNATURE
    if not metadata.exists() and not signature.exists():
        return None
    if not metadata.is_file() or not signature.is_file():
        raise InvalidMetadata(f"{channel} has only one of {METADATA} and {SIGNATURE}")
    if metadata.stat().st_size > METADATA_LIMIT or signature.stat().st_size > SIGNATURE_LIMIT:
        raise InvalidMetadata(f"{channel} feed metadata is larger than a remote accepts")
    if not signature_verifies(public_key, metadata, signature):
        raise InvalidMetadata(f"{channel} {METADATA} is not signed by {public_key.name}")
    try:
        value = json.loads(metadata.read_text(encoding="utf-8"))
    except ValueError as error:
        raise InvalidMetadata(f"{channel} {METADATA} is not JSON: {error}") from error
    if (
        not isinstance(value, dict)
        or value.get("schema") != SCHEMA
        or value.get("channel") != channel
        or not positive_integer(value.get("sequence"))
        or not isinstance(value.get("index"), dict)
        or not isinstance(value.get("packages"), list)
    ):
        raise InvalidMetadata(f"{channel} {METADATA} is not schema {SCHEMA} metadata for this channel")
    return value


def verify_channel(site: Path, channel: str, public_key: Path) -> dict:
    """Signed metadata that describes exactly the index and packages beside it."""
    value = load_signed(site, channel, public_key)
    if value is None:
        raise InvalidMetadata(f"{channel} has no {METADATA}")
    index, packages = describe_channel(site, channel)
    if value["index"] != index:
        raise InvalidMetadata(f"{channel} {INDEX} is not the index that {METADATA} names")
    if value["packages"] != packages:
        raise InvalidMetadata(f"{channel} packages are not the ones that {METADATA} lists")
    return value


def previous_sequences(previous: Path, public_key: Path) -> dict[str, int]:
    found = {channel: load_signed(previous, channel, public_key) for channel in CHANNELS}
    missing = [channel for channel, value in found.items() if value is None]
    if missing and len(missing) != len(CHANNELS):
        raise InvalidMetadata(
            f"the previous site has feed metadata for some channels but not for {', '.join(missing)}")
    return {channel: value["sequence"] for channel, value in found.items() if value is not None}


def check_sequence(previous: Path, public_key: Path, now: int) -> None:
    for channel, sequence in previous_sequences(previous, public_key).items():
        if now <= sequence:
            raise InvalidMetadata(
                f"refusing to publish {channel} sequence {now}: the previous publication is "
                f"{sequence}, and a remote refuses a feed that does not move forward")


def write(site: Path, previous: Path, key: Path, public_key: Path) -> None:
    now = clock()
    check_sequence(previous, public_key, now)
    for channel in CHANNELS:
        index, packages = describe_channel(site, channel)
        metadata = site / channel / "armv7" / METADATA
        signature = site / channel / "armv7" / SIGNATURE
        data = serialize(document(channel, now, index, packages))
        if len(data) > METADATA_LIMIT:
            raise InvalidMetadata(f"{channel} {METADATA} is larger than a remote accepts")
        metadata.write_bytes(data)
        signed = openssl("dgst", "-sha256", "-sign", key, "-out", signature, metadata)
        if signed.returncode != 0:
            raise InvalidMetadata(f"cannot sign {channel} {METADATA}: {signed.stderr.strip()}")
        verify_channel(site, channel, public_key)
        print(f"{channel}: sequence {now}, expires {rfc3339(now + VALIDITY_SECONDS)}, "
              f"{len(packages)} package(s), index {index['sha256']}")


def reusable_index(previous: Path, public_key: Path, channel: str, packages: Path) -> bool:
    """Whether the previous signed index already lists exactly these packages.

    An index carries the time it was made, so building one again changes its
    bytes. Reusing it keeps a publication that adds nothing byte for byte.
    """
    if load_signed(previous, channel, public_key) is None:
        print(f"{channel}: no previous feed metadata, building a new index")
        return False
    value = verify_channel(previous, channel, public_key)
    if value["packages"] != describe_packages(packages):
        print(f"{channel}: the package set changed, building a new index")
        return False
    print(f"{channel}: the package set is unchanged, reusing index {value['index']['sha256']}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    def command(name: str, *options: str, help: str) -> None:
        sub = commands.add_parser(name, help=help)
        for option in options:
            sub.add_argument(option, type=Path, required=True)

    command("write", "--site", "--previous", "--key", "--public-key",
            help="write, sign and check feed.json for every channel of SITE")
    command("verify", "--site", "--public-key",
            help="check that every channel of SITE has signed metadata describing its exact bytes")
    command("check-sequence", "--previous", "--public-key",
            help="refuse a publish time that is not later than the previous publication")
    command("reusable-index", "--previous", "--public-key", "--packages",
            help=f"exit 0 when the previous index lists exactly PACKAGES, {REBUILD} when it must be rebuilt")
    commands.choices["reusable-index"].add_argument("--channel", choices=CHANNELS, required=True)
    args = parser.parse_args()
    try:
        if args.command == "write":
            write(args.site, args.previous, args.key, args.public_key)
        elif args.command == "verify":
            for channel in CHANNELS:
                value = verify_channel(args.site, channel, args.public_key)
                print(f"{channel}: sequence {value['sequence']}, expires {value['expires']}, "
                      f"{len(value['packages'])} package(s)")
        elif args.command == "check-sequence":
            check_sequence(args.previous, args.public_key, clock())
        elif not reusable_index(args.previous, args.public_key, args.channel, args.packages):
            return REBUILD
    except InvalidMetadata as error:
        print(f"feed metadata failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
