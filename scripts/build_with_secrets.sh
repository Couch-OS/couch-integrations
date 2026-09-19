#!/bin/sh
# Compile the integrations that build-secrets.json grants a build-time secret,
# and nothing else. This is the only place a build secret meets a compiler.
#
#   fetch SOURCES_DIR           download their locked dependencies. Refuses to
#                               run while any build secret is in the environment.
#   compile SOURCES_DIR STAGE   compile each one offline with only its own
#                               secrets exported, and stage the unsigned binary.
#
# A pull request has no secrets: the integration then compiles with its own
# placeholder and records that no secret was used. A build that will be
# published sets COUCH_FEED_REQUIRE_BUILD_SECRETS=1 and fails without them.
set -eu

# A traced shell would print every value it handles.
case $- in *x*) echo "refusing to trace a script that handles build secrets" >&2; exit 1 ;; esac

usage() { echo "Usage: $0 fetch SOURCES_DIR | compile SOURCES_DIR STAGE_DIR" >&2; exit 64; }
[ "$#" -ge 2 ] || usage
mode=$1
case "$mode" in fetch) [ "$#" = 2 ] || usage ;; compile) [ "$#" = 3 ] || usage ;; *) usage ;; esac
sources=$(CDPATH= cd -- "$2" && pwd -P)
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
tooling="$sources/tooling"
guard="$root/scripts/build_secret_guard.py"
tab=$(printf '\t')

require=${COUCH_FEED_REQUIRE_BUILD_SECRETS:-0}
case "$require" in 0|1) ;; *) echo "COUCH_FEED_REQUIRE_BUILD_SECRETS must be 0 or 1" >&2; exit 64 ;; esac

work=$(mktemp -d "${TMPDIR:-/tmp}/couch-feed-secret-build.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
python3 "$root/scripts/validate_feed.py" --sources "$sources" --emit-build-secrets >"$work/secrets.tsv"
python3 "$root/scripts/validate_feed.py" --sources "$sources" --emit-selected >"$work/selected.tsv"

# Run one command with one held secret exported to it and to nothing else.
with_secret() {
    secret_name=$1
    shift
    (
        eval "secret_value=\${held_$secret_name}"
        export "$secret_name=$secret_value"
        exec "$@"
    )
}

# Take every allowlisted secret out of the environment before anything else
# runs. Names are validated by validate_feed.py, so they are safe to evaluate.
# A held value is an unexported shell variable: no child process inherits it.
missing=
while IFS="$tab" read -r integration_id name state binary; do
    eval "value=\${$name-}"
    unset "$name"
    if [ "$mode" = fetch ]; then
        [ -z "$value" ] || { echo "$name must not be set while dependencies are fetched" >&2; exit 1; }
        continue
    fi
    [ "$state" = selected ] || continue
    if [ -z "$value" ]; then
        missing="$missing $name"
        continue
    fi
    eval "held_$name=\$value"
    with_secret "$name" python3 "$guard" value "$name"
    # The runner already masks a secret; this covers any other source of it.
    [ "${GITHUB_ACTIONS:-}" != true ] || printf '::add-mask::%s\n' "$value"
done <"$work/secrets.tsv"
value=

if [ "$mode" = compile ]; then
    stage=$3
    [ ! -e "$stage" ] || { echo "stage already exists: $stage" >&2; exit 1; }
    if [ "$require" = 1 ] && [ -n "$missing" ]; then
        echo "a publishable build requires these build secrets, which are missing or empty:$missing" >&2
        exit 1
    fi
    mkdir -p "$stage"
fi

while IFS="$tab" read -r integration_id cargo_manifest package binary manifest repository commit sdk_commit; do
    names=$(awk -F '\t' -v id="$integration_id" '$1 == id && $3 == "selected" { print $2 }' "$work/secrets.tsv")
    [ -n "$names" ] || continue
    source="$sources/integrations/$integration_id"
    if [ "$mode" = fetch ]; then
        (cd "$source" && cargo fetch --locked --manifest-path "$cargo_manifest") </dev/null
        continue
    fi

    # Offline: nothing of this build reaches for the network while a secret is
    # exported. Its output is held back until it is known not to repeat one.
    log="$work/$integration_id.log"
    status=0
    (
        cd "$tooling"
        . tools/arm-cc-env.sh
        cd "$source"
        for name in $names; do
            eval "value=\${held_$name-}"
            [ -z "$value" ] || export "$name=$value"
        done
        value=
        exec cargo build --locked --offline --release --target armv7-unknown-linux-musleabihf \
            --manifest-path "$cargo_manifest" -p "$package" --bin "$binary"
    ) >"$log" 2>&1 </dev/null || status=$?
    for name in $names; do
        eval "value=\${held_$name-}"
        [ -n "$value" ] || continue
        with_secret "$name" python3 "$guard" absent "$name" "$log" </dev/null || {
            echo "$integration_id build output is withheld because it repeats $name" >&2
            exit 1
        }
    done
    value=
    cat "$log" >&2
    [ "$status" = 0 ] || { echo "$integration_id failed to compile" >&2; exit "$status"; }

    mkdir -p "$work/staged"
    cp "$source/target/armv7-unknown-linux-musleabihf/release/$binary" "$work/staged/$binary"
    # Cargo's dependency files under target/ record the environment a crate was
    # compiled with. Nothing but the binary leaves this build.
    rm -rf "$source/target"
    : >"$work/staged/built_with_secrets"
    for name in $names; do
        eval "value=\${held_$name-}"
        [ -n "$value" ] || continue
        with_secret "$name" python3 "$guard" present "$name" "$work/staged/$binary" </dev/null
        printf '%s\n' "$name" >>"$work/staged/built_with_secrets"
    done
    value=
    mv "$work/staged" "$stage/$integration_id"
done <"$work/selected.tsv"
