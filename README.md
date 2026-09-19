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

The Couch repositories moved from `dangerouslaser` to the
[Couch-OS](https://github.com/Couch-OS) organization in September 2026, and a
pin may name either owner with exactly that casing. Denon is pinned at
[`Couch-OS/couch-integration-denon`](https://github.com/Couch-OS/couch-integration-denon),
and the Couch tooling pin now names
[`Couch-OS/couch`](https://github.com/Couch-OS/couch) at the same commit. GitHub
redirects a transferred Git URL only until a repository exists again at the old
name, so a pin must not rely on that redirect. This feed repository moved on
2026-09-18.

## Channels

`preview` currently publishes the Denon, Kodi and Sonos integrations. Synthetic or
`test-only` sources are rejected even if a policy tries to select them.

`stable` is deliberately an empty signed index. It contains no integration
packages until a production-tier integration has validated hardware evidence.
The stable index is valid but has no installable packages.

The repository URLs are:

```text
https://packages.couch-os.dev/preview
https://packages.couch-os.dev/stable   # intentionally empty
```

`packages.couch-os.dev` is this repository's GitHub Pages custom domain. Before
the move the same feed was served at
`https://dangerouslaser.github.io/couch-integrations/{preview,stable}`; that
address no longer exists, because a Pages address follows its owner and is not
forwarded. Couch fetches indexes with redirects off, so runtimes that know only
that address (up to `v0.1.0-alpha.20260918.175.dev`) cannot browse, install or
update packages until they update; their installed integrations keep working,
and the system updater is unaffected. Later runtimes try
`packages.couch-os.dev` first. The published site uses only relative links.

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

`Feed admission` runs on every pull request, and a pull request run has no
secrets at all. The one exception to "the build has no secrets" is narrow and
applies to `main` only; see [Build-time secrets](#build-time-secrets). Its final
job is exactly named `admission`, the check to require in this repository's
branch ruleset. It has three layers:

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

## Build-time secrets

Until September 2026 the rule was "the build job has no secrets". It is now:
**a build secret exists only if [`build-secrets.json`](build-secrets.json) names
it, only the `main` branch can read it, and only the compile of the one
integration it is granted to ever sees it.** The signing key is a different
secret in a different job and environment, and that has not changed: the job
that compiles never signs, and the job that signs never compiles.

The allowlist today is one entry. The Sonos package has the project's Sonos
developer API key compiled in, so a remote identifies itself to players without
a key file on the device:

```json
{ "schema": 1, "integrations": { "sonos": ["COUCH_SONOS_BUILT_IN_API_KEY"] } }
```

- **Only this repository grants a secret.** An integration repository cannot ask
  for one: `integration.json` keeps exactly nine keys and none of them is about
  secrets. A name must sit in its own integration's namespace
  (`COUCH_<ID>_...`), so an entry can never stand in for `PATH`, `RUSTFLAGS`, a
  token, or another integration's secret. Adding an entry is a reviewed change
  to this file and to the two `env:` blocks in `admission.yml` that map it; a
  test keeps the two in step.
- **Where it lives.** The value is a secret of the `package-build` GitHub
  environment, which admits the `main` branch only. The `build-artifact` job
  names that environment only for a `main` push or a `main` dispatch. A pull
  request, from a fork or from this repository, runs the same job with no
  environment, so the secret is empty whatever the pull request changes in the
  workflow or the scripts. It is not a repository secret, and it is not in
  `package-signing`.
- **What sees it.** `scripts/build_with_secrets.sh` first fetches the locked
  dependencies of the allowlisted integrations with no secret in the
  environment. A second step, the only build step given the secret, removes
  every allowlisted name from its environment, holds the values in unexported
  shell variables, and exports each one solely to
  `cargo build --locked --offline` of the integration it belongs to. Every other
  integration is compiled afterwards by `scripts/build_artifact.sh`, a step that
  is never given a secret and refuses to run if it finds one. Integration tests
  run in a different job (`source-admission`) that has no environment.
- **Never echoed.** No script traces its commands, and the secret-handling one
  refuses to run under `sh -x`. The value is registered with `::add-mask::`. The
  compiler output of the secret-bearing build is held back, searched for the
  value, and printed only if it is clean. Cargo's `target/` directory, whose
  dependency files record the build environment, is deleted as soon as the
  binary is copied out, and the job has no cache.
- **Checked afterwards.** The build fails unless a supplied secret is found
  verbatim in its integration's binary (so a misspelt name cannot ship a keyless
  package), and a last step, `scripts/build_secret_guard.py payload`, fails the
  job if the value appears in any other file of the payload: another
  integration's binary, a manifest, a provenance receipt, the pin snapshot or
  the checksum list. A value must be 16 to 512 printable ASCII characters with
  no whitespace, so it can be searched for exactly.
- **A pull request still passes; a publishable build cannot skip the key.** With
  no secret, the integration compiles its own placeholder and its receipt records
  `"built_with_secrets": []`. On `main` the job sets
  `COUCH_FEED_REQUIRE_BUILD_SECRETS=1`: a missing or empty secret fails the build
  before anything is compiled, so admission fails and nothing is published. The
  receipt of a publishable build records the names, never the values:
  `"built_with_secrets": ["COUCH_SONOS_BUILT_IN_API_KEY"]`. The signing job
  checks that list again (`scripts/validate_payload.py`) and refuses a payload
  whose allowlisted integration was built without every one of its secrets.
  Only `scripts/test_publish.sh` may sign a placeholder build, with a disposable
  key: `publish.sh` refuses that review mode whenever the checkout still trusts
  the production public key. Receipts of integrations that are not in the
  allowlist are unchanged and never carry the field.

### What this does not protect against

- **The key is in the published binary.** Anyone can download the signed APK, or
  the unsigned payload artefact of a `main` admission run, and read the key out
  of it. That is inherent in shipping a built-in key. The
  mechanism keeps the key out of repositories, pull requests, logs and every
  other artefact; it does not make the key confidential. Treat it as a project
  identifier that can be revoked, not as a credential that guards anything.
- **Pinned third-party build code runs with the secret.** The secret-bearing
  compile runs the build scripts and procedural macros of the integration and of
  every dependency in its `Cargo.lock`, with the secret in their environment. It
  is locked, pinned by commit, reviewed when the pin moves, and told to stay
  offline, but `--offline` binds Cargo, not a hostile build script, and the
  runner has a network. Review the lock file diff of an allowlisted integration
  with that in mind.
- **One job, one machine.** Other integrations are compiled later in the same
  job. They are not given the secret and no running process holds it by then,
  but a GitHub-hosted runner gives every process `sudo`, so deliberately hostile
  code in any integration pinned by this feed could still dig it out of the
  runner. Such code could already ship a malicious binary to every remote; the
  review of source pins is the defence against both.
- **Reviewed code on `main` is trusted.** Anyone who can merge a workflow change
  to `main` can read the environment's secrets. Branch protection is the control.

### Set, rotate or revoke the Sonos key

The `package-build` environment must exist, restricted to `main`, before an
allowlisted integration is pinned (GitHub otherwise creates it unrestricted the
first time the job names it). It has no required reviewers: a reviewer would
hold up every `main` admission run, and with it automatic publication.

```sh
gh api -X PUT repos/Couch-OS/couch-integrations/environments/package-build --input - <<'JSON'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
gh api -X POST repos/Couch-OS/couch-integrations/environments/package-build/deployment-branch-policies \
  -f name=main -f type=branch
```

Set the value without a trailing newline:

```sh
tr -d '[:space:]' < sonos-api-key | gh secret set COUCH_SONOS_BUILT_IN_API_KEY \
  --repo Couch-OS/couch-integrations --env package-build
```

Published bytes are immutable, and the key is part of the Sonos binary. A new
key therefore needs a new Sonos version: the `main` build with the new key no
longer matches the published receipt of the current version, and publication
stops with "immutable provenance differs" until the version moves. Rotate in
this order:

1. merge a version bump in the Sonos integration repository;
2. set the new secret value;
3. merge the feed pull request that moves the Sonos pin to that commit.

Between steps 2 and 3 any other feed merge fails to publish, harmlessly, and
step 3 repairs it. Packages already published keep the old key for as long as
remotes have them installed, so revoke the old key at Sonos only once the new
version has had time to reach them.

Each existing `couch-integration-ID-VERSION-r0.apk` is treated as immutable:
publishing the same path with different bytes fails. Older packages remain in
the Pages package set and in the release archive so a Couch slot can roll back.

## Local review

Materialize the exact source graph, then validate it:

```sh
scripts/checkout_sources.sh ../integration-sources
python3 scripts/validate_feed.py --sources ../integration-sources
python3 -m unittest discover -s tests -v
sh -n scripts/checkout_sources.sh scripts/build_with_secrets.sh scripts/build_artifact.sh scripts/publish.sh
```

To build the unsigned payload the way admission does, with no secrets (an
allowlisted integration then carries its placeholder and cannot be published):

```sh
scripts/build_with_secrets.sh fetch ../integration-sources
scripts/build_with_secrets.sh compile ../integration-sources ../secret-stage
scripts/build_artifact.sh ../integration-sources ../payload ../secret-stage
python3 scripts/build_secret_guard.py payload ../payload
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

Publication is automatic. When a reviewed feed change is merged and its
main-branch `Feed admission` run succeeds, `publish.yml` starts by itself, takes
the payload that run built, signs the indexes and deploys the site. A merge that
changes none of the published inputs (`source-pin.json`, `feed-policy.json`,
`build-secrets.json`, `feed/`, `keys/` and the build and publish scripts) is skipped, so a README or
test change does not re-sign anything. The automatic run uses this workflow as
it is on `main`, never a pull request's copy, and still refuses unless the
admission run passed for exactly the commit being published.

To republish a `main` commit by hand:

```sh
gh workflow run publish.yml --repo Couch-OS/couch-integrations \
  --ref main -f admission_run_id=SUCCESSFUL_MAIN_ADMISSION_RUN_ID
```

Merging to `main` is therefore the last human decision before the signing key is
used. For one more, add required reviewers to the `package-signing` environment
(Settings → Environments): each signing job then waits for an approval click.

Require `admission` from GitHub Actions (app ID `15368`) in branch protection,
with up-to-date branches and administrators included. The signing, build-secret
(`package-build`) and Pages environments permit `main` only. Repeating publication with the same admitted
artifact reuses existing APK bytes and regenerates signed indexes. Changed
binary or manifest bytes at an existing version require a version bump. A
retained historical package keeps its original source, SDK, and tooling receipt
even when a later feed revision advances those pins, or names the same
repository under the other allowed owner after a move from `dangerouslaser` to
`Couch-OS`. A receipt that names a differently named repository, or whose
package identity or bytes differ, still stops publication.
