#!/bin/sh
# Build only channel-selected ARM payloads. This is deliberately unsigned;
# signing remains confined to publish.sh and its protected environment.
#
# This script never holds a build secret. An integration that build-secrets.json
# grants one is compiled beforehand by build_with_secrets.sh, and its binary is
# taken from that script's STAGE_DIR instead of being compiled here.
set -eu

[ "$#" = 2 ] || [ "$#" = 3 ] || { echo "Usage: $0 SOURCES_DIR OUTPUT_DIR [STAGE_DIR]" >&2; exit 64; }
sources=$(CDPATH= cd -- "$1" && pwd -P)
out=$2
stage=
[ "$#" = 2 ] || stage=$(CDPATH= cd -- "$3" && pwd -P)
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
tooling="$sources/tooling"

python3 "$root/scripts/validate_feed.py" --sources "$sources"
[ ! -e "$out" ] || { echo "output already exists: $out" >&2; exit 1; }
secrets=$(python3 "$root/scripts/validate_feed.py" --sources "$sources" --emit-build-secrets)
for name in $(printf '%s\n' "$secrets" | cut -f 2); do
    eval "[ -z \"\${$name-}\" ]" || { echo "$name must not be set here; see build_with_secrets.sh" >&2; exit 1; }
done
mkdir -p "$out"
python3 "$root/scripts/validate_feed.py" --sources "$sources" --emit-selected >"$out/selected.tsv"
cp "$root/source-pin.json" "$out/SOURCE_PINS.json"

while IFS="$(printf '\t')" read -r integration_id cargo_manifest package binary manifest repository commit sdk_commit; do
    source="$sources/integrations/$integration_id"
    mkdir -p "$out/$integration_id"
    if printf '%s\n' "$secrets" | cut -f 1 | grep -Fqx -- "$integration_id"; then
        [ -n "$stage" ] && [ -f "$stage/$integration_id/$binary" ] && [ -f "$stage/$integration_id/built_with_secrets" ] || {
            echo "$integration_id receives build secrets: compile it with build_with_secrets.sh and pass its STAGE_DIR" >&2
            exit 1
        }
        cp "$stage/$integration_id/$binary" "$out/$integration_id/$binary"
        built_with_secrets=$(tr '\n' ' ' <"$stage/$integration_id/built_with_secrets")
        built_with_secrets="recorded:${built_with_secrets% }"
    else
        (
            cd "$tooling"
            . tools/arm-cc-env.sh
            cd "$source"
            cargo build --locked --release --target armv7-unknown-linux-musleabihf \
                --manifest-path "$cargo_manifest" -p "$package" --bin "$binary"
        )
        cp "$source/target/armv7-unknown-linux-musleabihf/release/$binary" "$out/$integration_id/$binary"
        built_with_secrets=none
    fi
    cp "$source/$manifest" "$out/$integration_id/manifest.json"
    sha256sum "$out/$integration_id/$binary" "$out/$integration_id/manifest.json"
    python3 - "$out/$integration_id" "$integration_id" "$binary" "$repository" "$commit" \
        "$sdk_commit" "$root/source-pin.json" "$built_with_secrets" <<'PY'
import hashlib, json, sys
from pathlib import Path

payload, integration_id, binary, repository, commit, sdk_commit, pins_path, built_with_secrets = sys.argv[1:]
payload = Path(payload)
pins = json.loads(Path(pins_path).read_text(encoding="utf-8"))
manifest = json.loads((payload / "manifest.json").read_text(encoding="utf-8"))
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
# Names only, and only for an integration that build-secrets.json lists. An
# empty list is a review build that fell back to the integration's placeholder.
secrets = {} if built_with_secrets == "none" else {
    "built_with_secrets": sorted(built_with_secrets.removeprefix("recorded:").split()),
}
(payload / "provenance.json").write_text(json.dumps(secrets | {
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
