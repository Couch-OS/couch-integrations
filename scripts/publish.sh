#!/bin/sh
# Sign only a payload built by an approved unprivileged admission run. The
# protected job never recompiles an integration binary.
set -eu

[ "$#" = 5 ] || { echo "Usage: $0 SOURCES_DIR PRIVATE_KEY PREVIOUS_SITE PAYLOAD_DIR OUTPUT_DIR" >&2; exit 64; }
sources=$(CDPATH= cd -- "$1" && pwd -P)
tooling="$sources/tooling"
key=$(CDPATH= cd -- "$(dirname "$2")" && printf '%s/%s' "$(pwd -P)" "$(basename "$2")")
previous=$(CDPATH= cd -- "$3" && pwd -P)
payload=$(CDPATH= cd -- "$4" && pwd -P)
case "$5" in /*) out=$5 ;; *) out=$PWD/$5 ;; esac
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)

python3 "$root/scripts/validate_feed.py" --sources "$sources"
python3 "$root/scripts/validate_payload.py" "$root" "$sources" "$payload"
[ -f "$key" ] || { echo "private signing key is missing" >&2; exit 1; }
[ -d "$previous" ] && [ ! -e "$out" ] || { echo "previous site or output is invalid" >&2; exit 1; }

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
mkdir -p "$out" "$out/packages" "$out/provenance" "$out/new" \
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

docker run --rm --platform linux/arm/v7 \
    -v "$tooling:/src:ro" -v "$out:/out" \
    -v "$key:/couch-integrations.rsa:ro" \
    -v "$root/keys/couch-integrations.rsa.pub:/couch-integrations.rsa.pub:ro" \
    alpine:3.21 sh -ec '
        apk add --no-cache alpine-sdk >/dev/null
        /src/tools/integrations/build-repository.sh /couch-integrations.rsa /out/packages /out/repository
        mkdir -p /out/stable-build/armv7
        apk index --rewrite-arch armv7 --output /out/stable-build/armv7/APKINDEX.tar.gz
        abuild-sign -k /couch-integrations.rsa /out/stable-build/armv7/APKINDEX.tar.gz
    '

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
rm -rf "$out/packages" "$out/provenance" "$out/new" "$out/payload" \
    "$out/repository" "$out/stable-build" "$out/source-selected.tsv" "$out/selected.tsv"
