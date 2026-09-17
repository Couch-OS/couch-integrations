# Couch integration APK feed

This repository builds the public, signed Alpine APK feed for independently
installed Couch integrations. It is intentionally separate from the Couch
runtime source so a reviewed integration can ship without a complete runtime
release.

[`source-pin.json`](source-pin.json) records one immutable tooling pin and one
immutable repository and commit for each curated integration. Denon is sourced
from its own repository; Couch supplies the shared SDK, host protocol, package
builder, and package-store tests. Admission checks out every exact object,
validates each repository's `integration.json`, runs its locked test suite,
builds ARMv7 payloads, and exercises the native package path. Changing any pin
therefore requires the same reviewable evidence as a package change.

The Couch repositories are moving from `dangerouslaser` to the
[Couch-OS](https://github.com/Couch-OS) organization, and a pin may name either
owner with exactly that casing. Denon is pinned at
[`Couch-OS/couch-integration-denon`](https://github.com/Couch-OS/couch-integration-denon),
and the Couch tooling pin now names
[`Couch-OS/couch`](https://github.com/Couch-OS/couch) at the same commit. GitHub
redirects a transferred Git URL only until a repository exists again at the old
name, so a pin must not rely on that redirect. This feed repository itself has
not moved; its own workflow and Pages URLs still name `dangerouslaser`.

## Channels

`preview` currently publishes only the real Denon integration. Synthetic or
`test-only` sources are rejected even if a policy tries to select them.

`stable` is deliberately an empty signed index. It contains no integration
packages until a production-tier integration has validated hardware evidence.
The stable index is valid but has no installable packages.

The repository URLs are:

```text
https://packages.couch-os.dev/preview
https://packages.couch-os.dev/stable   # intentionally empty
```

`packages.couch-os.dev` goes live once its DNS record and this repository's
GitHub Pages custom domain are configured. Until then the same feed is served at
`https://dangerouslaser.github.io/couch-integrations/{preview,stable}`, which
redirects to `https://packages.couch-os.dev` afterwards. The published site uses
only relative links, so it works from either hostname.

The Couch installer appends `armv7` when it fetches `APKINDEX.tar.gz`.

## Trust setup

[`keys/couch-integrations.rsa.pub`](keys/couch-integrations.rsa.pub) is the
public half of the protected `APK_SIGNING_KEY` GitHub environment secret. The
publish job derives the public key from that secret and compares its DER form
before it signs anything. A key mismatch intentionally makes validation fail.

The published public key is available at
<https://packages.couch-os.dev/preview/couch-integrations.rsa.pub>.
Its PEM-file SHA-256 fingerprint is:

```text
80f3a73d86759cda103cb4f9a876cd4caee9d25c235c6d782b4be8a900b2696c
```

Provision this public key at
`/opt/couch/integration-keys/official/couch-integrations.rsa.pub` on an
integration-capable runtime before using the feed. Verify it against the
fingerprint above, obtained through a trusted source. Never put the private PEM in this
repository, an artifact, a pull-request workflow, or a package.

## CI and release flow

`Feed admission` has no secrets and runs on every pull request. Its final job
is exactly named `admission`, the check to require in this repository's branch
ruleset. It has three layers:

1. all source pins and channel policy;
2. each independent repository's locked admission tests plus the pinned shared
   host protocol and package-store tests;
3. ARMv7 builds, QEMU Alpine APK build/index/install, and immutable provenance
   and tamper rejection.

The unsigned ARM payload is uploaded only as a short-lived review artifact.
It cannot sign or deploy a feed.

`Publish signed feed` is manually dispatched from `main` only. Its
`package-signing` environment restricts its `APK_SIGNING_KEY` secret to `main`.
The workflow requires a successful `Feed admission` run for the exact main
commit and downloads that run’s unsigned payload artifact. It does not rebuild
or execute the integration while the signing key is present. The job
checks the public/private key match, preserves all previously published APKs,
re-signs the complete preview index, creates a GitHub Release archive for each feed revision, and uploads the complete site through GitHub's official Pages
artifact/deployment workflow.

Each existing `couch-integration-ID-VERSION-r0.apk` is treated as immutable:
publishing the same path with different bytes fails. Older packages remain in
the Pages package set and in the release archive so a Couch slot can roll back.

## Local review

Materialize the exact source graph, then validate it:

```sh
scripts/checkout_sources.sh ../integration-sources
python3 scripts/validate_feed.py --sources ../integration-sources
python3 -m unittest discover -s tests -v
sh -n scripts/checkout_sources.sh scripts/build_artifact.sh scripts/publish.sh
```

The signed build needs Docker with ARMv7 QEMU support, Alpine `abuild` tools,
and a private key that matches the committed public key. Use the protected
workflow for real publishing.

## Install or develop

The released `.170` runtime predates the package host. Install an
integration-capable runtime before running these commands inside Alpine
(the normal Couch SSH shell):

```sh
/opt/couch/runtime/current/couch-confd integrations \
  install-repository couch-integration-denon \
  --repository https://packages.couch-os.dev/preview
```

For your own feed, provision its public key in a separate directory and name
both explicitly:

```sh
/opt/couch/runtime/current/couch-confd integrations \
  --keys-dir /opt/couch/integration-keys/custom/my-feed \
  install-repository couch-integration-YOUR_ID \
  --repository https://packages.example.invalid/couch
```

For a local development build, copy the signed APK over SSH and use
`install-sideload /tmp/package.apk` with the development key directory.
Repository URLs are currently supplied per invocation; there is no saved
repository registry or repository-management UI. Direct `apk add` bypasses
Couch validation and activation and is not the integration installation path.
See the [developer packaging guide](https://couch-os.dev/developers/packaging.html).

Each integration owns its source, lock file, `integration.json`, runtime
manifest, and admission suite in its pinned repository. The
[Couch repository](https://github.com/Couch-OS/couch) owns the reusable
SDK, protocol, admission harness, and package tooling. This repository owns the
reviewed source graph, distribution policy, and publishing workflow.

## Publish an admitted revision

After merging a reviewed feed change and its main-branch admission run passes:

```sh
gh workflow run publish.yml --repo dangerouslaser/couch-integrations \
  --ref main -f admission_run_id=SUCCESSFUL_MAIN_ADMISSION_RUN_ID
```

Require `admission` from GitHub Actions (app ID `15368`) in branch protection,
with up-to-date branches and administrators included. Signing and Pages
environments permit `main` only. Repeating publication with the same admitted
artifact reuses existing APK bytes and regenerates signed indexes. Changed
binary or manifest bytes at an existing version require a version bump. A
retained historical package keeps its original source, SDK, and tooling receipt
even when a later feed revision advances those pins, or names the same
repository under the other allowed owner after a move from `dangerouslaser` to
`Couch-OS`. A receipt that names a differently named repository, or whose
package identity or bytes differ, still stops publication.
