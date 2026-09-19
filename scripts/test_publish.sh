#!/bin/sh
# Exercise the publisher with a disposable key and copied feed checkout. This
# never reads APK_SIGNING_KEY or modifies the real feed checkout.
set -eu

[ "$#" = 3 ] || { echo "Usage: $0 FEED_ROOT SOURCES_DIR PAYLOAD_DIR" >&2; exit 64; }
feed=$(CDPATH= cd -- "$1" && pwd -P)
sources=$(CDPATH= cd -- "$2" && pwd -P)
payload=$(CDPATH= cd -- "$3" && pwd -P)
command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

# A pull request payload has no build secrets. publish.sh accepts one only in
# review mode, and only because the key below is not the production key.
export COUCH_FEED_REVIEW_PAYLOAD=1

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
"$test_feed/scripts/publish.sh" "$sources" "$key" "$work/empty-history" "$payload" "$work/first"

package=$(find "$work/first/preview/armv7" -maxdepth 1 -type f -name 'couch-integration-denon-*.apk' -print -quit)
[ -n "$package" ] || { echo "first publish emitted no Denon APK" >&2; exit 1; }
first_digest=$(sha256sum "$package")
first_digest=${first_digest%% *}

# The signing key is made available under its real public basename exactly as
# a Couch installer uses it. Both indexes and the package must verify.
docker run --rm --platform linux/arm/v7 \
    -v "$work/first:/site:ro" \
    -v "$sources/tooling:/src:ro" \
    -v "$test_feed/keys/couch-integrations.rsa.pub:/keys/couch-integrations.rsa.pub:ro" \
    alpine:3.21 sh -ec '
        apk add --no-cache busybox-extras >/dev/null
        apk --arch armv7 --keys-dir /keys --repositories-file /dev/null --repository /site/preview --no-cache update
        apk --keys-dir /keys verify /site/preview/armv7/*.apk
        apk --arch armv7 --keys-dir /keys --repositories-file /dev/null --repository /site/stable --no-cache update
        tar -xOzf /site/stable/armv7/APKINDEX.tar.gz APKINDEX >/tmp/stable-index
        test ! -s /tmp/stable-index

        # Exercise the externally built package through the real pinned Couch
        # host, not only Alpine signature verification.
        confd=/src/daemon/target/armv7-unknown-linux-musleabihf/release/couch-confd
        test -x "$confd"
        package=$(find /site/preview/armv7 -maxdepth 1 -type f -name "couch-integration-denon-*.apk" -print -quit)
        test -n "$package"
        version=${package##*/couch-integration-denon-}
        version=${version%-r0.apk}
        store=/tmp/denon-home/integrations
        "$confd" integrations --root "$store" --keys-dir /keys install-sideload "$package"
        "$confd" integrations --root "$store" list | grep -Fx "denon $version"
        mkdir -p /tmp/denon-home/connections/denon-test
        printf "%s\n" "{\"schema_version\":1,\"connections\":[{\"id\":\"denon-test\",\"name\":\"Denon test\",\"provider\":{\"kind\":\"plugin\",\"id\":\"denon\",\"label\":\"Denon AVR\"}}]}" \
            >/tmp/denon-home/config.json
        printf "%s\n" "{\"host\":\"127.0.0.1\",\"port\":23}" \
            >/tmp/denon-home/connections/denon-test/plugin-connection.json
        before=$(sha256sum "$store/state/denon")
        "$confd" integrations --root "$store" --keys-dir /keys install-sideload "$package"
        after=$(sha256sum "$store/state/denon")
        test "$before" = "$after"

        mkdir /tmp/untrusted-keys
        if "$confd" integrations --root /tmp/untrusted-store --keys-dir /tmp/untrusted-keys install-sideload "$package"; then
            echo "unexpected successful untrusted external package install" >&2
            exit 1
        fi
        test ! -e /tmp/untrusted-store/state/denon

        cp "$package" /tmp/tampered.apk
        printf x >>/tmp/tampered.apk
        if "$confd" integrations --root /tmp/tampered-store --keys-dir /keys install-sideload /tmp/tampered.apk; then
            echo "unexpected successful tampered external package install" >&2
            exit 1
        fi
        test ! -e /tmp/tampered-store/state/denon

        busybox-extras httpd -p 18080 -h /site/preview
        "$confd" integrations --root /tmp/repository-store --keys-dir /keys \
            install-repository couch-integration-denon --repository http://127.0.0.1:18080
        "$confd" integrations --root /tmp/repository-store list | grep -Fx "denon $version"
        "$confd" integrations --root /tmp/repository-store remove denon
        repository_list=$("$confd" integrations --root /tmp/repository-store list)
        test -z "$repository_list"
        test ! -e /tmp/repository-store/slots/denon
        test -f /tmp/repository-store/state/denon
        test "$(cat /tmp/repository-store/state/denon)" = "{\"active\":null,\"previous\":null}"

        # Every other package the channel publishes gets the same journey
        # through the real host: found in the signed repository, installed,
        # listed at its version, removed without a trace of its slot.
        for package in /site/preview/armv7/couch-integration-*.apk; do
            name=${package##*/couch-integration-}
            name=${name%-r0.apk}
            id=${name%-*}
            version=${name##*-}
            [ "$id" != denon ] || continue
            "$confd" integrations --root "/tmp/$id-store" --keys-dir /keys \
                install-repository "couch-integration-$id" --repository http://127.0.0.1:18080
            "$confd" integrations --root "/tmp/$id-store" list | grep -Fx "$id $version"
            test -x "/tmp/$id-store/slots/$id/$version/$(sed -n "s/.*\"executable\": *\"\([^\"]*\)\".*/\1/p" "/tmp/$id-store/slots/$id/$version/manifest.json" | head -n 1)" \
                || { echo "$id $version: installed slot has no executable" >&2; ls -R "/tmp/$id-store/slots/$id" >&2; exit 1; }
            "$confd" integrations --root "/tmp/$id-store" remove "$id"
            test -z "$("$confd" integrations --root "/tmp/$id-store" list)"
            test ! -e "/tmp/$id-store/slots/$id"
            echo "install smoke passed: $id $version"
        done
    '

# A same-version run restores the published receipt and package rather than
# creating a timestamp-dependent replacement artifact.
"$test_feed/scripts/publish.sh" "$sources" "$key" "$work/first" "$payload" "$work/second"
second_package="$work/second/preview/armv7/$(basename "$package")"
second_digest=$(sha256sum "$second_package")
second_digest=${second_digest%% *}
test "$second_digest" = "$first_digest"
cmp -s "$package" "$second_package"

# A source pin may advance while an older Denon version remains in the feed.
# That historical receipt is valid only when every immutable payload identity
# field matches; publishing must retain its original source commit verbatim.
prior_commit=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
older_history="$work/older-receipt-history"
cp -a "$work/first" "$older_history"
old_receipt="$older_history/preview/armv7/$(basename "${package%.apk}").provenance.json"
python3 - "$old_receipt" "$prior_commit" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
record = json.loads(path.read_text(encoding="utf-8"))
record["source_commit"] = sys.argv[2]
path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
"$test_feed/scripts/publish.sh" "$sources" "$key" "$older_history" "$payload" "$work/third"
third_package="$work/third/preview/armv7/$(basename "$package")"
third_receipt="$work/third/preview/armv7/$(basename "${package%.apk}").provenance.json"
third_digest=$(sha256sum "$third_package")
third_digest=${third_digest%% *}
test "$third_digest" = "$first_digest"
cmp -s "$package" "$third_package"
cmp -s "$old_receipt" "$third_receipt"

# The Couch repositories move between the dangerouslaser and Couch-OS owners.
# A receipt written before a move names the same repositories under the other
# owner. Swap every recorded owner: publishing must still reuse the same APK and
# keep that original receipt byte for byte.
rewrite_receipt() {
    python3 - "$@" <<'PY'
import json, sys
from pathlib import Path
path, mode = Path(sys.argv[1]), sys.argv[2]
record = json.loads(path.read_text(encoding="utf-8"))
owners = {"https://github.com/dangerouslaser/": "https://github.com/Couch-OS/",
          "https://github.com/Couch-OS/": "https://github.com/dangerouslaser/"}
for field in ("source_repository", "sdk_repository", "tooling_repository"):
    prefix = next(prefix for prefix in owners if record[field].startswith(prefix))
    record[field] = owners[prefix] + record[field][len(prefix):]
if mode == "renamed":
    record["source_repository"] = record["source_repository"].removesuffix(".git") + "-fork.git"
path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
}
moved_history="$work/owner-moved-history"
cp -a "$work/first" "$moved_history"
moved_receipt="$moved_history/preview/armv7/$(basename "${package%.apk}").provenance.json"
rewrite_receipt "$moved_receipt" moved
if cmp -s "$moved_receipt" "$work/first/preview/armv7/$(basename "$moved_receipt")"; then
    echo "owner-move fixture did not change the receipt" >&2
    exit 1
fi
"$test_feed/scripts/publish.sh" "$sources" "$key" "$moved_history" "$payload" "$work/owner-moved"
cmp -s "$package" "$work/owner-moved/preview/armv7/$(basename "$package")"
cmp -s "$moved_receipt" "$work/owner-moved/preview/armv7/$(basename "$moved_receipt")"

# Owner equivalence is not a repository wildcard. A receipt for the same version
# from a differently named repository must still stop publication.
renamed_history="$work/renamed-history"
cp -a "$work/first" "$renamed_history"
rewrite_receipt "$renamed_history/preview/armv7/$(basename "$moved_receipt")" renamed
if "$test_feed/scripts/publish.sh" "$sources" "$key" "$renamed_history" "$payload" "$work/renamed"; then
    echo "publisher reused an APK whose receipt names another repository" >&2
    exit 1
fi
test ! -e "$work/renamed/preview/armv7/$(basename "$package")"

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
if "$test_feed/scripts/publish.sh" "$sources" "$key" "$work/third" "$work/changed-payload" "$work/rejected"; then
    echo "publisher accepted changed payload at an existing version" >&2
    exit 1
fi
test ! -e "$work/rejected/preview/armv7/$(basename "$package")"
echo "publisher smoke passed"
