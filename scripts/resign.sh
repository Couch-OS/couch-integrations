#!/bin/sh
# Re-sign the published feed without publishing anything new.
#
# feed.json is valid for 30 days, so it is signed again every week even when no
# package changed. This takes the newest published site (restored from its
# release archive), keeps every package, index and receipt byte for byte, and
# writes only a fresh feed.json and feed.json.sig for each channel.
#
# It needs no sources, no payload and no Docker: nothing is built. It trusts
# the previous site only as far as its signed metadata goes. The previous
# feed.json must verify with the committed public key and must name exactly the
# index and packages found beside it, or nothing is signed.
set -eu

[ "$#" = 3 ] || { echo "Usage: $0 PRIVATE_KEY PREVIOUS_SITE OUTPUT_DIR" >&2; exit 64; }
key=$(CDPATH= cd -- "$(dirname "$1")" && printf '%s/%s' "$(pwd -P)" "$(basename "$1")")
previous=$(CDPATH= cd -- "$2" && pwd -P)
case "$3" in /*) out=$3 ;; *) out=$PWD/$3 ;; esac
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
public_key="$root/keys/couch-integrations.rsa.pub"

[ -f "$key" ] || { echo "private signing key is missing" >&2; exit 1; }
[ ! -e "$out" ] || { echo "output already exists: $out" >&2; exit 1; }

derived=$(mktemp "${TMPDIR:-/tmp}/couch-feed-public.XXXXXX")
committed=$(mktemp "${TMPDIR:-/tmp}/couch-feed-committed.XXXXXX")
trap 'rm -f "$derived" "$committed"' EXIT HUP INT TERM
openssl pkey -in "$key" -pubout -outform DER >"$derived"
openssl pkey -pubin -in "$public_key" -outform DER >"$committed"
cmp -s "$derived" "$committed" || {
    echo "APK_SIGNING_KEY does not match keys/couch-integrations.rsa.pub" >&2
    exit 1
}

python3 "$root/scripts/feed_metadata.py" verify --site "$previous" --public-key "$public_key" || {
    echo "the previous site cannot be re-signed. Publish it in full instead:" >&2
    echo "  gh workflow run publish.yml --ref main -f admission_run_id=SUCCESSFUL_MAIN_ADMISSION_RUN_ID" >&2
    exit 1
}
python3 "$root/scripts/feed_metadata.py" check-sequence --previous "$previous" --public-key "$public_key"

# Landing pages come from this checkout. Everything a remote verifies comes
# from the previous site unchanged, including the pin snapshot that describes it.
mkdir -p "$out"
cp -a "$root/feed/." "$out/"
for channel in preview stable; do
    cmp -s "$previous/$channel/couch-integrations.rsa.pub" "$public_key" || {
        echo "the previous $channel site was published with another key; publish in full instead" >&2
        exit 1
    }
    rm -rf "$out/$channel/armv7"
    mkdir -p "$out/$channel"
    cp -a "$previous/$channel/armv7" "$out/$channel/armv7"
    cp "$previous/$channel/couch-integrations.rsa.pub" "$previous/$channel/SOURCE_PINS.json" "$out/$channel/"
done

python3 "$root/scripts/feed_metadata.py" write --site "$out" --previous "$previous" \
    --key "$key" --public-key "$public_key"
