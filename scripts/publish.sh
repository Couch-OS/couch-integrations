#!/bin/sh
# Sign only a payload built by an approved unprivileged admission run. The
# protected job never recompiles an integration binary.
#
# Every channel also gets signed freshness metadata, feed.json and
# feed.json.sig (scripts/feed_metadata.py). COUCH_FEED_NOW, whole seconds since
# the Unix epoch, replaces the clock so a test can publish at a known time.
set -eu

[ "$#" = 5 ] || { echo "Usage: $0 SOURCES_DIR PRIVATE_KEY PREVIOUS_SITE PAYLOAD_DIR OUTPUT_DIR" >&2; exit 64; }
sources=$(CDPATH= cd -- "$1" && pwd -P)
tooling="$sources/tooling"
key=$(CDPATH= cd -- "$(dirname "$2")" && printf '%s/%s' "$(pwd -P)" "$(basename "$2")")
previous=$(CDPATH= cd -- "$3" && pwd -P)
payload=$(CDPATH= cd -- "$4" && pwd -P)
case "$5" in /*) out=$5 ;; *) out=$PWD/$5 ;; esac
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)

# A pull request payload is built without build secrets (build-secrets.json),
# so its allowlisted integrations carry their placeholder. test_publish.sh may
# sign one with a disposable key by setting COUCH_FEED_REVIEW_PAYLOAD=1. The
# production key must never do so: this is its DER SHA-256, and a checkout that
# still trusts it refuses review mode outright. tests/test_build_secrets.py
# keeps the value in step with keys/couch-integrations.rsa.pub.
production_key_sha256=2e6f19b020bd150147e2f690a2e8e7f589fe4b7dfa28ba8aa1f8bacefe51d205
review=
case "${COUCH_FEED_REVIEW_PAYLOAD:-0}" in
    0) ;;
    1)
        trusted=$(openssl pkey -pubin -in "$root/keys/couch-integrations.rsa.pub" -outform DER | openssl dgst -sha256 -r)
        [ "${trusted%% *}" != "$production_key_sha256" ] || {
            echo "review payloads can be signed only with a disposable key, never the production key" >&2
            exit 1
        }
        review=--review
        ;;
    *) echo "COUCH_FEED_REVIEW_PAYLOAD must be 0 or 1" >&2; exit 64 ;;
esac

python3 "$root/scripts/validate_feed.py" --sources "$sources"
python3 "$root/scripts/validate_payload.py" $review "$root" "$sources" "$payload"
[ -f "$key" ] || { echo "private signing key is missing" >&2; exit 1; }
[ -d "$previous" ] && [ ! -e "$out" ] || { echo "previous site or output is invalid" >&2; exit 1; }
public_key="$root/keys/couch-integrations.rsa.pub"
# Refuse a publish time that does not move the feed forward before anything is
# written: a remote refuses a sequence lower than one it has already seen.
python3 "$root/scripts/feed_metadata.py" check-sequence --previous "$previous" --public-key "$public_key"

derived=$(mktemp "${TMPDIR:-/tmp}/couch-feed-public.XXXXXX")
committed=$(mktemp "${TMPDIR:-/tmp}/couch-feed-committed.XXXXXX")
trap 'rm -f "$derived" "$committed"' EXIT HUP INT TERM
openssl pkey -in "$key" -pubout -outform DER >"$derived"
openssl pkey -pubin -in "$root/keys/couch-integrations.rsa.pub" -outform DER >"$committed"
cmp -s "$derived" "$committed" || {
    echo "APK_SIGNING_KEY does not match keys/couch-integrations.rsa.pub" >&2
    exit 1
}

# Keep host-side output directories owned by the runner. Container-created
# parent directories would prevent the unprivileged runner moving/cleaning them.
mkdir -p "$out" "$out/packages" "$out/stable-packages" "$out/provenance" "$out/new" \
    "$out/repository/armv7" "$out/stable-build/armv7"
cp -a "$root/feed/." "$out/"
if [ -d "$previous/preview/armv7" ]; then
    find "$previous/preview/armv7" -maxdepth 1 -type f -name 'couch-integration-*.apk' -exec cp {} "$out/packages/" \;
    find "$previous/preview/armv7" -maxdepth 1 -type f -name 'couch-integration-*.provenance.json' -exec cp {} "$out/provenance/" \;
fi

python3 "$root/scripts/validate_feed.py" --sources "$sources" --emit-selected >"$out/source-selected.tsv"
while IFS="$(printf '\t')" read -r integration_id cargo_manifest package binary manifest repository commit sdk_commit; do
    version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' \
        "$sources/integrations/$integration_id/$manifest")
    printf '%s\t%s\t%s\n' "$integration_id" "$version" "$binary"
done <"$out/source-selected.tsv" >"$out/selected.tsv"

while IFS="$(printf '\t')" read -r integration_id version binary; do
    name="couch-integration-$integration_id-$version-r0.apk"
    package="$out/packages/$name"
    provenance="$out/provenance/${name%.apk}.provenance.json"
    artifact_provenance="$payload/$integration_id/provenance.json"
    if [ -e "$package" ]; then
        [ -f "$provenance" ] || { echo "existing $name has no provenance receipt" >&2; exit 1; }
        # Reuse keeps the original receipt. It may record an older pin commit or
        # the same repository before its owner moved; see validate_feed.py.
        # Keep stdin away from the checker: it is this loop's selected.tsv.
        python3 "$root/scripts/validate_feed.py" \
            --retained-receipt "$artifact_provenance" "$provenance" </dev/null
        continue
    fi
    mkdir -p "$out/payload"
    cp "$payload/$integration_id/$binary" "$out/payload/$binary"
    cp "$payload/$integration_id/manifest.json" "$out/payload/$integration_id-manifest.json"
    # The basename is part of the APK signature key identity. It must remain
    # couch-integrations.rsa, matching couch-integrations.rsa.pub.
    docker run --rm --platform linux/arm/v7 \
        -v "$tooling:/src:ro" -v "$out:/out" \
        -v "$key:/couch-integrations.rsa:ro" \
        -v "$root/keys/couch-integrations.rsa.pub:/couch-integrations.rsa.pub:ro" \
        alpine:3.21 sh -ec '
            apk add --no-cache alpine-sdk binutils jq >/dev/null
            # abuild creates its own intermediate index and must trust our
            # public key inside this disposable packaging container.
            cp /couch-integrations.rsa.pub /etc/apk/keys/
            /src/tools/integrations/build-apk.sh "$1" "$2" \
              "/out/payload/$3" "/out/payload/$1-manifest.json" \
              /couch-integrations.rsa /out/new
        ' sh "$integration_id" "$version" "$binary"
    cp "$out/new/$name" "$package"
    cp "$artifact_provenance" "$provenance"
done <"$out/selected.tsv"

# An index records when it was made, so building one again changes its bytes.
# A channel whose package set is exactly the one its previous signed metadata
# lists keeps its previous index byte for byte; any other channel gets a new one.
index_is_reusable() {
    status=0
    python3 "$root/scripts/feed_metadata.py" reusable-index --previous "$previous" \
        --public-key "$public_key" --channel "$1" --packages "$2" || status=$?
    case "$status" in
        0) return 0 ;;
        10) return 1 ;;
        *) exit 1 ;;
    esac
}
build_preview=1
build_stable=1
if index_is_reusable preview "$out/packages"; then
    build_preview=0
    find "$out/packages" -maxdepth 1 -type f -name '*.apk' -exec cp {} "$out/repository/armv7/" \;
    cp "$previous/preview/armv7/APKINDEX.tar.gz" "$out/repository/armv7/APKINDEX.tar.gz"
fi
# stable-packages stays empty: stable is deliberately an empty signed index.
if index_is_reusable stable "$out/stable-packages"; then
    build_stable=0
    cp "$previous/stable/armv7/APKINDEX.tar.gz" "$out/stable-build/armv7/APKINDEX.tar.gz"
fi
if [ "$build_preview$build_stable" != 00 ]; then
    docker run --rm --platform linux/arm/v7 \
        -v "$tooling:/src:ro" -v "$out:/out" \
        -v "$key:/couch-integrations.rsa:ro" \
        -v "$public_key:/couch-integrations.rsa.pub:ro" \
        alpine:3.21 sh -ec '
            apk add --no-cache alpine-sdk >/dev/null
            if [ "$1" = 1 ]; then
                /src/tools/integrations/build-repository.sh /couch-integrations.rsa /out/packages /out/repository
            fi
            if [ "$2" = 1 ]; then
                mkdir -p /out/stable-build/armv7
                apk index --rewrite-arch armv7 --output /out/stable-build/armv7/APKINDEX.tar.gz
                abuild-sign -k /couch-integrations.rsa /out/stable-build/armv7/APKINDEX.tar.gz
            fi
        ' sh "$build_preview" "$build_stable"
fi

rm -rf "$out/preview/armv7" "$out/stable/armv7"
mkdir -p "$out/preview" "$out/stable"
mv "$out/repository/armv7" "$out/preview/armv7"
mv "$out/stable-build/armv7" "$out/stable/armv7"
cp "$out/provenance"/*.provenance.json "$out/preview/armv7/"
cp "$root/keys/couch-integrations.rsa.pub" "$out/preview/couch-integrations.rsa.pub"
cp "$root/keys/couch-integrations.rsa.pub" "$out/stable/couch-integrations.rsa.pub"
cp "$root/source-pin.json" "$out/preview/SOURCE_PINS.json"
cp "$root/source-pin.json" "$out/stable/SOURCE_PINS.json"

# Pages receives only signed indexes/packages, public keys, provenance receipts,
# and static landing pages. Never upload unsigned build intermediates.
rm -rf "$out/packages" "$out/stable-packages" "$out/provenance" "$out/new" "$out/payload" \
    "$out/repository" "$out/stable-build" "$out/source-selected.tsv" "$out/selected.tsv"

# Last, describe and sign exactly the bytes that are about to be deployed.
python3 "$root/scripts/feed_metadata.py" write --site "$out" --previous "$previous" \
    --key "$key" --public-key "$public_key"
