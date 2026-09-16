#!/bin/sh
# Build only channel-selected ARM payloads. This is deliberately unsigned;
# signing remains confined to publish.sh and its protected environment.
set -eu

[ "$#" = 2 ] || { echo "Usage: $0 SOURCES_DIR OUTPUT_DIR" >&2; exit 64; }
sources=$(CDPATH= cd -- "$1" && pwd -P)
out=$2
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
tooling="$sources/tooling"

python3 "$root/scripts/validate_feed.py" --sources "$sources"
[ ! -e "$out" ] || { echo "output already exists: $out" >&2; exit 1; }
mkdir -p "$out"
python3 "$root/scripts/validate_feed.py" --sources "$sources" --emit-selected >"$out/selected.tsv"
cp "$root/source-pin.json" "$out/SOURCE_PINS.json"

while IFS="$(printf '\t')" read -r integration_id cargo_manifest package binary manifest repository commit sdk_commit; do
    source="$sources/integrations/$integration_id"
    (
        cd "$tooling"
        . tools/arm-cc-env.sh
        cd "$source"
        cargo build --locked --release --target armv7-unknown-linux-musleabihf \
            --manifest-path "$cargo_manifest" -p "$package" --bin "$binary"
    )
    mkdir -p "$out/$integration_id"
    cp "$source/target/armv7-unknown-linux-musleabihf/release/$binary" "$out/$integration_id/$binary"
    cp "$source/$manifest" "$out/$integration_id/manifest.json"
    sha256sum "$out/$integration_id/$binary" "$out/$integration_id/manifest.json"
    python3 - "$out/$integration_id" "$integration_id" "$binary" "$repository" "$commit" \
        "$sdk_commit" "$root/source-pin.json" <<'PY'
import hashlib, json, sys
from pathlib import Path

payload, integration_id, binary, repository, commit, sdk_commit, pins_path = sys.argv[1:]
payload = Path(payload)
pins = json.loads(Path(pins_path).read_text(encoding="utf-8"))
manifest = json.loads((payload / "manifest.json").read_text(encoding="utf-8"))
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
(payload / "provenance.json").write_text(json.dumps({
    "schema": 2,
    "source_repository": repository,
    "source_commit": commit,
    "sdk_repository": pins["tooling"]["repository"],
    "sdk_commit": sdk_commit,
    "tooling_repository": pins["tooling"]["repository"],
    "tooling_commit": pins["tooling"]["commit"],
    "id": integration_id,
    "version": manifest["version"],
    "binary": binary,
    "binary_sha256": digest(payload / binary),
    "manifest_sha256": digest(payload / "manifest.json"),
}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
done <"$out/selected.tsv" >"$out/SHA256SUMS"
