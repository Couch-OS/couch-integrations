#!/bin/sh
# Materialize every immutable source pin in a predictable checkout tree.
set -eu

[ "$#" = 1 ] || { echo "Usage: $0 OUTPUT_DIR" >&2; exit 64; }
out=$1
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
[ ! -e "$out" ] || { echo "source output already exists: $out" >&2; exit 1; }
mkdir -p "$out"

pins=$(mktemp "${TMPDIR:-/tmp}/couch-feed-pins.XXXXXX")
trap 'rm -f "$pins"' EXIT HUP INT TERM
python3 "$root/scripts/validate_feed.py" --pins-only --emit-pins >"$pins"
while IFS="$(printf '\t')" read -r relative repository commit; do
    destination="$out/$relative"
    mkdir -p "$(dirname "$destination")"
    git clone --filter=blob:none --no-checkout "$repository" "$destination"
    git -C "$destination" fetch --depth=1 origin "$commit"
    git -C "$destination" checkout --detach "$commit"
    test "$(git -C "$destination" rev-parse HEAD)" = "$commit"
done <"$pins"

python3 "$root/scripts/validate_feed.py" --sources "$out"
