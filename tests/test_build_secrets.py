#!/usr/bin/env python3
"""Build-time secrets: the allowlist, the confined compile, and the leak checks.

Every value here is fake. The fixture `cargo` stands in for the compiler: it
records which build secrets each invocation could see and writes a "binary"
that embeds the one it was given, as option_env! does.
"""
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).parents[1]
MODULE = REPOSITORY / "scripts" / "validate_feed.py"
SPEC = importlib.util.spec_from_file_location("validate_feed_for_build_secrets", MODULE)
feed = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(feed)

CORE = "https://github.com/Couch-OS/couch.git"
NAME = "COUCH_SONOS_BUILT_IN_API_KEY"
FAKE = "FAKE-0000-not-a-real-sonos-key-0000"

FAKE_CARGO = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
argv = sys.argv[1:]
seen = {key: value for key, value in os.environ.items() if key.startswith(("COUCH_SONOS_", "COUCH_DENON_"))}
with open(os.environ["FAKE_CARGO_RECORD"], "a", encoding="utf-8") as record:
    record.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "seen": seen}) + "\\n")
mode = os.environ.get("FAKE_CARGO_MODE", "")
if argv[0] == "build":
    value = seen.get("COUCH_SONOS_BUILT_IN_API_KEY", "")
    if mode == "leak-log" and value:
        print(f"warning: build script printed {value}", file=sys.stderr)
    if mode == "fail":
        print("error: could not compile", file=sys.stderr)
        raise SystemExit(101)
    binary = argv[argv.index("--bin") + 1]
    out = Path("target/armv7-unknown-linux-musleabihf/release")
    (out / "deps").mkdir(parents=True, exist_ok=True)
    embedded = "" if mode == "ignore-secret" else value
    (out / binary).write_bytes(b"\\x7fELF fixture " + binary.encode() + b" key=" + (embedded or "placeholder").encode())
    (out / "deps" / "fixture.d").write_text(f"# env-dep:COUCH_SONOS_BUILT_IN_API_KEY={value}\\n")
'''


def run(*argv, env=None, cwd=None):
    return subprocess.run(
        [str(item) for item in argv], env=env, cwd=cwd, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_root = feed.ROOT
        feed.ROOT = Path(self.temp.name)

    def tearDown(self):
        feed.ROOT = self.old_root
        self.temp.cleanup()

    def write(self, value):
        (feed.ROOT / "build-secrets.json").write_text(json.dumps(value), encoding="utf-8")

    def test_committed_allowlist_grants_only_the_sonos_key(self):
        feed.ROOT = self.old_root
        self.assertEqual(feed.build_secrets(), {"sonos": [NAME]})

    def test_names_are_parsed_per_integration(self):
        self.write({"schema": 1, "integrations": {
            "sonos": ["COUCH_SONOS_A", "COUCH_SONOS_B"], "my-tv": ["COUCH_MY_TV_TOKEN"]}})
        self.assertEqual(feed.build_secrets()["my-tv"], ["COUCH_MY_TV_TOKEN"])
        self.write({"schema": 1, "integrations": {}})
        self.assertEqual(feed.build_secrets(), {})

    def test_a_missing_or_misshapen_allowlist_is_rejected(self):
        with self.assertRaisesRegex(feed.InvalidFeed, "cannot read"):
            feed.build_secrets()
        for value in (
            {"schema": 2, "integrations": {}},
            {"schema": 1, "integrations": []},
            {"schema": 1, "integrations": {}, "extra": True},
            {"schema": 1, "integrations": {"../sonos": [NAME]}},
            {"schema": 1, "integrations": {"sonos": []}},
            {"schema": 1, "integrations": {"sonos": NAME}},
            {"schema": 1, "integrations": {"sonos": [NAME, NAME]}},
            {"schema": 1, "integrations": {"sonos": ["COUCH_SONOS_B", "COUCH_SONOS_A"]}},
            {"schema": 1, "integrations": {"a-b": ["COUCH_A_B_KEY"], "a_b": ["COUCH_A_B_OTHER"]}},
        ):
            with self.subTest(value=value):
                self.write(value)
                with self.assertRaises(feed.InvalidFeed):
                    feed.build_secrets()

    def test_a_secret_must_sit_in_its_own_integration_namespace(self):
        for name in (
            "PATH", "RUSTFLAGS", "CARGO_HOME", "GITHUB_TOKEN", "APK_SIGNING_KEY", "COUCH_DENON_KEY",
            "COUCH_SONOS", "COUCH_SONOS_", "couch_sonos_key", "COUCH_SONOS_key", "COUCH_SONOS_KEY=1",
            "COUCH_SONOS_KEY\n", "COUCH_SONOS__KEY", "X_COUCH_SONOS_KEY", 7,
        ):
            with self.subTest(name=name):
                self.write({"schema": 1, "integrations": {"sonos": [name]}})
                with self.assertRaises(feed.InvalidFeed):
                    feed.build_secrets()


class ReceiptTests(unittest.TestCase):
    ALLOWED = {"sonos": [NAME]}

    @staticmethod
    def receipt(integration_id="sonos", **changes):
        record = {
            "schema": 2, "source_repository": f"https://github.com/Couch-OS/couch-integration-{integration_id}.git",
            "source_commit": "b" * 40, "sdk_repository": CORE, "sdk_commit": "a" * 40,
            "tooling_repository": CORE, "tooling_commit": "a" * 40, "id": integration_id,
            "version": "0.1.0", "binary": f"couch-plugin-{integration_id}",
            "binary_sha256": "d" * 64, "manifest_sha256": "e" * 64,
        }
        record.update(changes)
        return record

    def test_a_published_receipt_keeps_its_secret_names(self):
        built = self.receipt(built_with_secrets=[NAME])
        feed.validate_retained_receipt(built, dict(built, source_commit="c" * 40), self.ALLOWED)
        with self.assertRaisesRegex(feed.InvalidFeed, "immutable provenance differs"):
            feed.validate_retained_receipt(self.receipt(built_with_secrets=[]), built, self.ALLOWED)
        with self.assertRaisesRegex(feed.InvalidFeed, "invalid shape"):
            feed.validate_retained_receipt(built, self.receipt(), self.ALLOWED)
        with self.assertRaisesRegex(feed.InvalidFeed, "invalid shape"):
            feed.validate_retained_receipt(self.receipt(), self.receipt(), self.ALLOWED)

    def test_other_receipts_never_carry_the_field(self):
        feed.validate_retained_receipt(self.receipt("denon"), self.receipt("denon"), self.ALLOWED)
        with self.assertRaisesRegex(feed.InvalidFeed, "invalid shape"):
            feed.validate_retained_receipt(
                self.receipt("denon", built_with_secrets=[]), self.receipt("denon", built_with_secrets=[]),
                self.ALLOWED)


class WorkflowTests(unittest.TestCase):
    def test_admission_maps_exactly_the_allowlisted_secrets_into_two_steps(self):
        workflow = (REPOSITORY / ".github/workflows/admission.yml").read_text(encoding="utf-8")
        names = sorted(name for names in feed.build_secrets().values() for name in names)
        mapped = re.findall(r"^ +([A-Z0-9_]+): \$\{\{ secrets\.([A-Z0-9_]+) \}\}$", workflow, re.MULTILINE)
        # Once for the confined compile, once for the final leak check.
        self.assertEqual(sorted(mapped), sorted((name, name) for name in names for _ in range(2)))
        self.assertEqual(len(re.findall(r"(?<![-\w])secrets\s*[.\[)]", workflow)), len(mapped))
        self.assertNotIn("package-signing", workflow.replace("never reuse package-signing here", ""))
        self.assertNotIn("actions/cache", workflow)
        self.assertNotIn("set -x", workflow)
        self.assertEqual(workflow.count("'package-build'"), 1)

    def test_the_signing_workflow_holds_no_build_secret(self):
        workflow = (REPOSITORY / ".github/workflows/publish.yml").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"secrets\.([A-Z0-9_]+)", workflow), ["APK_SIGNING_KEY"])
        self.assertNotIn("package-build", workflow)
        self.assertNotIn("--review", workflow)
        self.assertNotIn("COUCH_FEED_REVIEW_PAYLOAD", workflow)


class ReviewModeTests(unittest.TestCase):
    def test_the_production_key_refuses_a_review_payload(self):
        script = (REPOSITORY / "scripts/publish.sh").read_text(encoding="utf-8")
        recorded = re.search(r"^production_key_sha256=([0-9a-f]{64})$", script, re.MULTILINE)[1]
        der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(REPOSITORY / "keys/couch-integrations.rsa.pub"), "-outform", "DER"],
            stdout=subprocess.PIPE, check=True).stdout
        self.assertEqual(recorded, hashlib.sha256(der).hexdigest())
        with tempfile.TemporaryDirectory() as temp:
            env = dict(os.environ, COUCH_FEED_REVIEW_PAYLOAD="1")
            result = run(REPOSITORY / "scripts/publish.sh", temp, Path(temp) / "key", temp, temp, Path(temp) / "out", env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("never the production key", result.stderr)
            self.assertFalse((Path(temp) / "out").exists())


class ConfinedBuildTests(unittest.TestCase):
    """build_with_secrets.sh, build_artifact.sh and the guard, end to end."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.feed = self.root / "feed"
        self.sources = self.root / "sources"
        self.stage = self.root / "stage"
        self.payload = self.root / "payload"
        self.record = self.root / "cargo-record.jsonl"
        self.record.touch()
        shutil.copytree(REPOSITORY / "scripts", self.feed / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(REPOSITORY / "keys", self.feed / "keys")
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        cargo = bin_dir / "cargo"
        cargo.write_text(FAKE_CARGO, encoding="utf-8")
        cargo.chmod(cargo.stat().st_mode | stat.S_IXUSR)
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith("COUCH_") and key != "GITHUB_ACTIONS"
        }
        self.env.update(PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}", FAKE_CARGO_RECORD=str(self.record))
        self.tooling_commit = self.commit(self.sources / "tooling", {
            "tools/arm-cc-env.sh": ":\n", "tools/fetch-zig.sh": ":\n",
            "tools/integrations/build-apk.sh": ":\n", "tools/integrations/build-repository.sh": ":\n",
        })
        self.write_feed()

    def tearDown(self):
        self.temp.cleanup()

    def commit(self, path, files):
        for relative, content in files.items():
            target = path / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        git = ["git", "-C", str(path), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
               "-c", "commit.gpgsign=false"]
        subprocess.run(["git", "init", "-q", str(path)], check=True)
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "fixture"], check=True)
        return subprocess.run([*git, "rev-parse", "HEAD"], stdout=subprocess.PIPE, text=True, check=True).stdout.strip()

    def integration(self, integration_id, *, label="Fixture"):
        dependency = f'{{ git = "{CORE}", rev = "{self.tooling_commit}" }}'
        return self.commit(self.sources / "integrations" / integration_id, {
            "integration.json": json.dumps({
                "schema": 1, "protocol_version": 2, "id": integration_id, "tier": "preview", "synthetic": False,
                "cargo_manifest": "Cargo.toml", "cargo_package": f"couch-{integration_id}",
                "binary": f"couch-plugin-{integration_id}", "manifest": "plugin.json"}),
            "Cargo.toml": textwrap.dedent(f'''\
                [package]
                name = "couch-{integration_id}"
                version = "0.1.0"
                [dependencies]
                couch-plugin = {dependency}
                couch-sdk = {dependency}
                [dev-dependencies]
                couch-plugin = {dependency}
                couch-sdk = {dependency}
                '''),
            ".cargo/config.toml": '[target.armv7-unknown-linux-musleabihf]\nlinker = "rust-lld"\n',
            "tests/admission.rs": "\n".join(
                f"#[test]\nfn {case}() {{ {call} fixture); }}" for case, call in feed.REQUIRED_ADMISSION_CALLS.items()),
            "plugin.json": json.dumps({
                "protocol_version": 2, "min_core_protocol_version": 2, "id": integration_id, "label": label,
                "version": "0.1.0", "executable": f"bin/couch-plugin-{integration_id}"}),
        })

    def write_feed(self, *, sonos_label="Fixture", selected=("denon", "sonos")):
        pins = {"schema": 2, "tooling": {"repository": CORE, "commit": self.tooling_commit}, "integrations": {}}
        for integration_id in ("denon", "sonos"):
            label = sonos_label if integration_id == "sonos" else "Fixture"
            pins["integrations"][integration_id] = {
                "repository": f"https://github.com/Couch-OS/couch-integration-{integration_id}.git",
                "commit": self.integration(integration_id, label=label),
            }
        (self.feed / "source-pin.json").write_text(json.dumps(pins), encoding="utf-8")
        (self.feed / "feed-policy.json").write_text(json.dumps({"schema": 1, "channels": {
            "preview": {"ids": list(selected), "allowed_tiers": ["preview"]},
            "stable": {"ids": [], "allowed_tiers": ["production"]}}}), encoding="utf-8")
        (self.feed / "build-secrets.json").write_text(
            json.dumps({"schema": 1, "integrations": {"sonos": [NAME]}}), encoding="utf-8")

    def script(self, name, *argv, **env):
        return run(self.feed / "scripts" / name, *argv, env={**self.env, **env})

    def compile(self, **env):
        fetched = self.script("build_with_secrets.sh", "fetch", self.sources)
        self.assertEqual(fetched.returncode, 0, fetched.stderr)
        return self.script("build_with_secrets.sh", "compile", self.sources, self.stage, **env)

    def assemble(self):
        return self.script("build_artifact.sh", self.sources, self.payload, self.stage)

    def guard(self, **env):
        return run(sys.executable, self.feed / "scripts/build_secret_guard.py", "payload", self.payload,
                   env={**self.env, **env})

    def validate_payload(self, *flags):
        return run(sys.executable, self.feed / "scripts/validate_payload.py", *flags, self.feed, self.sources, self.payload)

    def invocations(self):
        return [json.loads(line) for line in self.record.read_text(encoding="utf-8").splitlines()]

    def provenance(self, integration_id):
        return json.loads((self.payload / integration_id / "provenance.json").read_text(encoding="utf-8"))

    def assert_no_fake(self, *results):
        for result in results:
            self.assertNotIn(FAKE, result.stdout)
            self.assertNotIn(FAKE, result.stderr)

    def test_pull_request_build_passes_with_the_placeholder(self):
        compiled = self.compile(**{NAME: ""})
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        assembled = self.assemble()
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        self.assertEqual(self.provenance("sonos")["built_with_secrets"], [])
        self.assertNotIn("built_with_secrets", self.provenance("denon"))
        self.assertIn(b"key=placeholder", (self.payload / "sonos/couch-plugin-sonos").read_bytes())
        # An empty secret is removed, not compiled in as an empty key.
        self.assertTrue(all(call["seen"] == {} for call in self.invocations()))
        self.assertEqual(self.guard().returncode, 0)
        # Reviewable with a disposable key, never publishable.
        self.assertEqual(self.validate_payload("--review").returncode, 0)
        strict = self.validate_payload()
        self.assertNotEqual(strict.returncode, 0)
        self.assertIn(f"sonos was not built with its required build secrets ({NAME})", strict.stderr)

    def test_publishable_build_fails_loudly_without_the_secret(self):
        for supplied in ({}, {NAME: ""}):
            with self.subTest(supplied=supplied):
                compiled = self.compile(COUCH_FEED_REQUIRE_BUILD_SECRETS="1", **supplied)
                self.assertNotEqual(compiled.returncode, 0)
                self.assertIn(f"missing or empty: {NAME}", compiled.stderr)
                self.assertFalse(self.stage.exists())
                self.assertFalse(any(call["argv"][0] == "build" for call in self.invocations()))
        # Without a staged binary there is no payload to upload at all.
        self.stage.mkdir()
        assembled = self.assemble()
        self.assertNotEqual(assembled.returncode, 0)
        self.assertIn("sonos receives build secrets", assembled.stderr)

    def test_secret_reaches_only_its_own_offline_compile(self):
        compiled = self.compile(COUCH_FEED_REQUIRE_BUILD_SECRETS="1", **{NAME: FAKE})
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        assembled = self.assemble()
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        checked = self.guard(COUCH_FEED_REQUIRE_BUILD_SECRETS="1", **{NAME: FAKE})
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assert_no_fake(compiled, assembled, checked)

        calls = self.invocations()
        sonos = str(self.sources / "integrations/sonos")
        with_secret = [call for call in calls if call["seen"]]
        self.assertEqual(len(with_secret), 1)
        self.assertEqual((with_secret[0]["cwd"], with_secret[0]["seen"]), (sonos, {NAME: FAKE}))
        self.assertEqual(with_secret[0]["argv"][0], "build")
        self.assertIn("--offline", with_secret[0]["argv"])
        self.assertIn("--locked", with_secret[0]["argv"])
        self.assertEqual([call["argv"][:2] for call in calls if call["argv"][0] == "fetch"], [["fetch", "--locked"]])
        self.assertEqual(sum(call["cwd"].endswith("/denon") for call in calls), 1)

        self.assertEqual(self.provenance("sonos")["built_with_secrets"], [NAME])
        self.assertNotIn("built_with_secrets", self.provenance("denon"))
        self.assertEqual(self.validate_payload().returncode, 0)
        # Cargo's dep-info records the environment; it must not outlive the build.
        self.assertFalse((self.sources / "integrations/sonos/target").exists())
        holders = [path.relative_to(self.root).as_posix() for path in self.root.rglob("*")
                   if path.is_file() and path != self.record and FAKE.encode() in path.read_bytes()]
        self.assertEqual(sorted(holders), ["payload/sonos/couch-plugin-sonos", "stage/sonos/couch-plugin-sonos"])

    def test_no_other_script_runs_with_a_secret_in_its_environment(self):
        fetched = self.script("build_with_secrets.sh", "fetch", self.sources, **{NAME: FAKE})
        self.assertNotEqual(fetched.returncode, 0)
        self.assertIn(f"{NAME} must not be set while dependencies are fetched", fetched.stderr)
        self.assertEqual(self.compile().returncode, 0)
        assembled = self.script("build_artifact.sh", self.sources, self.payload, self.stage, **{NAME: FAKE})
        self.assertNotEqual(assembled.returncode, 0)
        self.assertIn(f"{NAME} must not be set here", assembled.stderr)
        self.assert_no_fake(fetched, assembled)
        self.assertFalse((self.payload).exists())
        self.assertTrue(all(call["seen"] == {} for call in self.invocations()))

    def test_a_secret_of_an_unselected_integration_is_dropped(self):
        self.write_feed(selected=("denon",))
        compiled = self.compile(COUCH_FEED_REQUIRE_BUILD_SECRETS="1", **{NAME: FAKE})
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        self.assertEqual(self.assemble().returncode, 0)
        self.assertTrue(all(call["seen"] == {} for call in self.invocations()))
        self.assertEqual(self.guard(COUCH_FEED_REQUIRE_BUILD_SECRETS="1", **{NAME: FAKE}).returncode, 0)

    def test_unusable_secret_values_are_refused_unseen(self):
        for value in ("short", FAKE + "\n", "has a space in the middle of it", "tab\tseparated-value-0000", "é" * 20):
            with self.subTest(length=len(value)):
                compiled = self.compile(COUCH_FEED_REQUIRE_BUILD_SECRETS="1", **{NAME: value})
                self.assertNotEqual(compiled.returncode, 0)
                self.assertIn(f"{NAME} must be 16-512 printable ASCII", compiled.stderr)
                self.assertNotIn(value.strip(), compiled.stdout + compiled.stderr)
                self.assertFalse(any(call["argv"][0] == "build" for call in self.invocations()))

    def test_a_traced_shell_is_refused(self):
        traced = run("sh", "-x", self.feed / "scripts/build_with_secrets.sh", "compile", self.sources, self.stage,
                     env={**self.env, NAME: FAKE})
        self.assertNotEqual(traced.returncode, 0)
        self.assertIn("refusing to trace", traced.stderr)
        self.assert_no_fake(traced)

    def test_the_mask_is_registered_only_for_the_runner(self):
        compiled = self.compile(GITHUB_ACTIONS="true", **{NAME: FAKE})
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        self.assertEqual(compiled.stdout, f"::add-mask::{FAKE}\n")
        self.assertNotIn(FAKE, compiled.stderr)

    def test_build_output_that_repeats_the_secret_is_withheld(self):
        compiled = self.compile(FAKE_CARGO_MODE="leak-log", **{NAME: FAKE})
        self.assertNotEqual(compiled.returncode, 0)
        self.assertIn(f"sonos build output is withheld because it repeats {NAME}", compiled.stderr)
        self.assert_no_fake(compiled)
        self.assertFalse((self.stage / "sonos").exists())

    def test_a_failed_compile_stops_the_build_and_shows_its_log(self):
        compiled = self.compile(FAKE_CARGO_MODE="fail", **{NAME: FAKE})
        self.assertEqual(compiled.returncode, 101)
        self.assertIn("error: could not compile", compiled.stderr)
        self.assertFalse((self.stage / "sonos").exists())

    def test_a_supplied_secret_must_end_up_in_the_binary(self):
        compiled = self.compile(FAKE_CARGO_MODE="ignore-secret", **{NAME: FAKE})
        self.assertNotEqual(compiled.returncode, 0)
        self.assertIn(f"{NAME} was supplied but is not compiled into couch-plugin-sonos", compiled.stderr)
        self.assertFalse((self.stage / "sonos").exists())

    def test_leak_check_trips_on_a_planted_value(self):
        self.write_feed(sonos_label=f"Sonos {FAKE}")
        self.assertEqual(self.compile(**{NAME: FAKE}).returncode, 0)
        self.assertEqual(self.assemble().returncode, 0)
        leaked = self.guard(**{NAME: FAKE})
        self.assertNotEqual(leaked.returncode, 0)
        self.assertIn(f"{NAME} appears in sonos/manifest.json", leaked.stderr)
        self.assert_no_fake(leaked)

    def test_leak_check_covers_other_binaries_and_metadata(self):
        self.assertEqual(self.compile(**{NAME: FAKE}).returncode, 0)
        self.assertEqual(self.assemble().returncode, 0)
        for relative in ("denon/couch-plugin-denon", "SHA256SUMS", "sonos/provenance.json.bak"):
            with self.subTest(relative=relative):
                path = self.payload / relative
                original = path.read_bytes() if path.exists() else None
                path.write_bytes((original or b"") + b"\n" + FAKE.encode())
                leaked = self.guard(**{NAME: FAKE})
                self.assertNotEqual(leaked.returncode, 0)
                self.assertIn(f"{NAME} appears in {relative}", leaked.stderr)
                self.assert_no_fake(leaked)
                path.write_bytes(original) if original is not None else path.unlink()
        self.assertEqual(self.guard(**{NAME: FAKE}).returncode, 0)

    def test_final_check_requires_the_secret_it_has_to_look_for(self):
        self.assertEqual(self.compile(**{NAME: FAKE}).returncode, 0)
        self.assertEqual(self.assemble().returncode, 0)
        unchecked = self.guard()
        self.assertNotEqual(unchecked.returncode, 0)
        self.assertIn("is not available to check", unchecked.stderr)

    def test_final_check_refuses_a_placeholder_payload_on_a_publishable_build(self):
        self.assertEqual(self.compile().returncode, 0)
        self.assertEqual(self.assemble().returncode, 0)
        refused = self.guard(COUCH_FEED_REQUIRE_BUILD_SECRETS="1")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn(f"sonos is publishable only when built with {NAME}", refused.stderr)


if __name__ == "__main__":
    unittest.main()
