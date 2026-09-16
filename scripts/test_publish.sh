#!/bin/sh
# Exercise the publisher with a disposable key and copied feed checkout. This
# never reads APK_SIGNING_KEY or modifies the real feed checkout.
set -eu

[ "$#" = 3 ] || { echo "Usage: $0 FEED_ROOT CORE_CHECKOUT PAYLOAD_DIR" >&2; exit 64; }
feed=$(CDPATH= cd -- "$1" && pwd -P)
core=$(CDPATH= cd -- "$2" && pwd -P)
payload=$(CDPATH= cd -- "$3" && pwd -P)
command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/couch-feed-publish.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
test_feed="$work/feed"
key="$work/couch-integrations.rsa"

# A private copy lets this test replace only its public key. The production
# trust key and protected signing secret never enter the smoke test.
cp -a "$feed" "$test_feed"
rm -rf "$test_feed/.git" "$test_feed/scripts/__pycache__" "$test_feed/tests/__pycache__"
openssl genrsa -out "$key" 4096 >/dev/null 2>&1
openssl pkey -in "$key" -pubout >"$test_feed/keys/couch-integrations.rsa.pub"

mkdir "$work/empty-history"
"$test_feed/scripts/publish.sh" "$core" "$key" "$work/empty-history" "$payload" "$work/first"

package=$(find "$work/first/preview/armv7" -maxdepth 1 -type f -name 'couch-integration-denon-*.apk' -print -quit)
[ -n "$package" ] || { echo "first publish emitted no Denon APK" >&2; exit 1; }
first_digest=$(sha256sum "$package" | awk '{print $1}')

# The signing key is made available under its real public basename exactly as
# a Couch installer uses it. Both indexes and the package must verify.
docker run --rm --platform linux/arm/v7 \
    -v "$work/first:/site:ro" \
    -v "$test_feed/keys/couch-integrations.rsa.pub:/keys/couch-integrations.rsa.pub:ro" \
    alpine:3.21 sh -ec '
        apk --arch armv7 --keys-dir /keys --repositories-file /dev/null --repository /site/preview --no-cache update
        apk --keys-dir /keys verify /site/preview/armv7/*.apk
        apk --arch armv7 --keys-dir /keys --repositories-file /dev/null --repository /site/stable --no-cache update
        test "$(tar -xOzf /site/stable/armv7/APKINDEX.tar.gz APKINDEX | wc -c)" -eq 0
    '

# A same-version run restores the published receipt and package rather than
# creating a timestamp-dependent replacement artifact.
"$test_feed/scripts/publish.sh" "$core" "$key" "$work/first" "$payload" "$work/second"
second_package="$work/second/preview/armv7/$(basename "$package")"
test "$(sha256sum "$second_package" | awk '{print $1}')" = "$first_digest"
cmp -s "$package" "$second_package"

# Model a payload whose binary and receipt were both modified after admission.
# Its self-consistent updated digest reaches the immutable-package guard, which
# must reject this same version instead of overwriting the published artifact.
cp -a "$payload" "$work/changed-payload"
binary=$(python3 - "$work/changed-payload/denon/provenance.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["binary"])
PY
)
printf x >>"$work/changed-payload/denon/$binary"
python3 - "$work/changed-payload/denon/provenance.json" "$work/changed-payload/denon/$binary" <<'PY'
import hashlib, json, sys
path, binary = map(__import__('pathlib').Path, sys.argv[1:])
record = json.loads(path.read_text(encoding="utf-8"))
record["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
if "$test_feed/scripts/publish.sh" "$core" "$key" "$work/first" "$work/changed-payload" "$work/rejected"; then
    echo "publisher accepted changed payload at an existing version" >&2
    exit 1
fi
test ! -e "$work/rejected/preview/armv7/$(basename "$package")"
echo "publisher smoke passed"
