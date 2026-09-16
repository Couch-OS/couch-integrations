#!/bin/sh
# Build only the channel-selected ARM payloads. This is deliberately unsigned
# and safe for pull-request runners; signing is confined to publish.sh.
set -eu

[ "$#" = 2 ] || { echo "Usage: $0 CORE_CHECKOUT OUTPUT_DIR" >&2; exit 64; }
core=$1
out=$2
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)

python3 "$root/scripts/validate_feed.py" --core "$core"
[ ! -e "$out" ] || { echo "output already exists: $out" >&2; exit 1; }
mkdir -p "$out"

# The current policy deliberately has one preview package. Keep the selection
# in JSON so a future package cannot bypass validate_feed's tier check.
python3 - "$root/feed-policy.json" "$core/integrations/catalog.json" <<'PY' >"$out/selected.tsv"
import json, sys
policy, catalog = map(lambda p: json.load(open(p, encoding="utf-8")), sys.argv[1:])
entries = {entry["id"]: entry for entry in catalog["integrations"]}
for integration_id in policy["channels"]["preview"]["ids"]:
    entry = entries[integration_id]
    print("\t".join((integration_id, entry["cargo_package"], entry["binary"], entry["manifest"])))
PY

while IFS="$(printf '\t')" read -r integration_id package binary manifest; do
    (
        cd "$core"
        . tools/arm-cc-env.sh
        cd clients
        cargo build --locked --release --target armv7-unknown-linux-musleabihf -p "$package" --bin "$binary"
    )
    mkdir -p "$out/$integration_id"
    cp "$core/clients/target/armv7-unknown-linux-musleabihf/release/$binary" "$out/$integration_id/$binary"
    cp "$core/$manifest" "$out/$integration_id/manifest.json"
    sha256sum "$out/$integration_id/$binary" "$out/$integration_id/manifest.json"
done <"$out/selected.tsv" >"$out/SHA256SUMS"
printf '%s\n' "$(git -C "$core" rev-parse HEAD)" >"$out/CORE_COMMIT"
python3 - "$out" <<'PY'
import hashlib, json, sys
from pathlib import Path

out = Path(sys.argv[1])
commit = (out / "CORE_COMMIT").read_text(encoding="utf-8").strip()
for line in (out / "selected.tsv").read_text(encoding="utf-8").splitlines():
    integration_id, _package, binary, _manifest = line.split("\t")
    payload = out / integration_id
    manifest = json.loads((payload / "manifest.json").read_text(encoding="utf-8"))
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    (payload / "provenance.json").write_text(json.dumps({
        "schema": 1,
        "core_commit": commit,
        "id": integration_id,
        "version": manifest["version"],
        "binary": binary,
        "binary_sha256": digest(payload / binary),
        "manifest_sha256": digest(payload / "manifest.json"),
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
