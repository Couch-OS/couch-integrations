#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE = Path(__file__).parents[1] / "scripts" / "validate_feed.py"
SPEC = importlib.util.spec_from_file_location("validate_feed", MODULE)
feed = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(feed)

LEGACY_CORE = "https://github.com/dangerouslaser/couch.git"
MOVED_CORE = "https://github.com/Couch-OS/couch.git"
DENON = "https://github.com/Couch-OS/couch-integration-denon.git"
LEGACY_DENON = "https://github.com/dangerouslaser/couch-integration-denon.git"


class FeedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_root = feed.ROOT
        feed.ROOT = self.root
        self.tooling_commit = "a" * 40
        self.source_commit = "b" * 40
        (self.root / "keys").mkdir()
        self.write_pins()
        self.write_policy([])
        self.write_json(self.root / "build-secrets.json", {"schema": 1, "integrations": {}})

    def tearDown(self):
        feed.ROOT = self.old_root
        self.temp.cleanup()

    @staticmethod
    def write_json(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def write_pins(self, *, include_denon=True, denon_changes=None, tooling_repository=LEGACY_CORE):
        integrations = {}
        if include_denon:
            pin = {
                "repository": DENON,
                "commit": self.source_commit,
            }
            pin.update(denon_changes or {})
            integrations["denon"] = pin
        self.write_json(
            self.root / "source-pin.json",
            {
                "schema": 2,
                "tooling": {
                    "repository": tooling_repository,
                    "commit": self.tooling_commit,
                },
                "integrations": integrations,
            },
        )

    def write_policy(self, stable, *, preview=None, preview_tiers=None, stable_tiers=None):
        self.write_json(
            self.root / "feed-policy.json",
            {
                "schema": 1,
                "channels": {
                    "preview": {
                        "ids": ["denon"] if preview is None else preview,
                        "allowed_tiers": ["preview"] if preview_tiers is None else preview_tiers,
                    },
                    "stable": {
                        "ids": stable,
                        "allowed_tiers": ["production"] if stable_tiers is None else stable_tiers,
                    },
                },
            },
        )

    def write_sources(self, *, metadata_changes=None, cargo=None, manifest_changes=None, core=LEGACY_CORE):
        sources = self.root / "sources"
        tooling = sources / "tooling"
        for required in (
            "tools/arm-cc-env.sh", "tools/fetch-zig.sh",
            "tools/integrations/build-apk.sh", "tools/integrations/build-repository.sh",
        ):
            path = tooling / required
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")
        denon = sources / "integrations/denon"
        metadata = {
            "schema": 1,
            "protocol_version": 1,
            "id": "denon",
            "tier": "preview",
            "synthetic": False,
            "cargo_manifest": "Cargo.toml",
            "cargo_package": "couch-denon",
            "binary": "couch-plugin-denon",
            "manifest": "plugin.json",
        }
        metadata.update(metadata_changes or {})
        self.write_json(denon / "integration.json", metadata)
        revision = self.tooling_commit
        if cargo is None:
            cargo = f'''[package]
name = "couch-denon"
version = "0.1.1"
[dependencies]
couch-plugin = {{ git = "{core}", rev = "{revision}" }}
couch-sdk = {{ git = "{core}", rev = "{revision}" }}
[dev-dependencies]
couch-plugin = {{ git = "{core}", rev = "{revision}" }}
couch-sdk = {{ git = "{core}", rev = "{revision}" }}
'''
        (denon / "Cargo.toml").write_text(cargo, encoding="utf-8")
        config = denon / ".cargo/config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            '[target.armv7-unknown-linux-musleabihf]\nlinker = "rust-lld"\n',
            encoding="utf-8",
        )
        admission = denon / "tests/admission.rs"
        admission.parent.mkdir(parents=True, exist_ok=True)
        required = (
            feed.CONCURRENT_ADMISSION
            if type(metadata["protocol_version"]) is int and metadata["protocol_version"] >= 3
            else feed.REQUIRED_ADMISSION_CALLS
        )
        admission.write_text(
            "\n".join(
                f"#[test]\nfn {case}() {{ {call} fixture); }}"
                for case, call in required.items()
            ),
            encoding="utf-8",
        )
        manifest = {
            "protocol_version": 1,
            "id": "denon",
            "version": "0.1.1",
            "executable": "bin/couch-plugin-denon",
        }
        manifest.update(manifest_changes or {})
        self.write_json(denon / "plugin.json", manifest)
        return sources

    def validate(self, sources):
        pins = feed.source_pins()
        policy = feed.policy()
        def head(path):
            return self.tooling_commit if path.name == "tooling" else self.source_commit
        with mock.patch.object(feed, "git_head", side_effect=head):
            return feed.validate_sources(sources, pins, policy)

    def test_independent_source_is_selected_with_immutable_provenance(self):
        selected = self.validate(self.write_sources())
        self.assertEqual(selected["denon"]["sdk_commit"], self.tooling_commit)
        self.assertEqual(feed.source_pins()["integrations"]["denon"]["commit"], self.source_commit)

    def test_zero_or_short_source_commit_is_rejected(self):
        for commit in ("0" * 40, "deadbeef"):
            with self.subTest(commit=commit):
                self.write_pins(denon_changes={"commit": commit})
                with self.assertRaisesRegex(feed.InvalidFeed, "full commit SHA"):
                    feed.source_pins()

    def test_selected_integration_must_have_its_own_pin(self):
        self.write_pins(include_denon=False)
        with self.assertRaisesRegex(feed.InvalidFeed, "unpinned integration"):
            self.validate(self.write_sources())

    def test_local_or_mixed_sdk_contract_is_rejected(self):
        revision = self.tooling_commit
        local = f'''[package]
name = "couch-denon"
[dependencies]
couch-plugin = {{ path = "../copied-protocol" }}
couch-sdk = {{ git = "{LEGACY_CORE}", rev = "{revision}" }}
[dev-dependencies]
couch-plugin = {{ git = "{LEGACY_CORE}", rev = "{revision}" }}
couch-sdk = {{ git = "{LEGACY_CORE}", rev = "{revision}" }}
'''
        with self.assertRaisesRegex(feed.InvalidFeed, "must pin the Couch repository"):
            self.validate(self.write_sources(cargo=local))

        mixed = local.replace('path = "../copied-protocol"', f'git = "{LEGACY_CORE}", rev = "{"c" * 40}"')
        with self.assertRaisesRegex(feed.InvalidFeed, "do not share one revision"):
            self.validate(self.write_sources(cargo=mixed))

    def test_either_couch_owner_is_an_allowed_source(self):
        for tooling, denon in ((LEGACY_CORE, LEGACY_DENON), (MOVED_CORE, DENON), (LEGACY_CORE, DENON)):
            with self.subTest(tooling=tooling, denon=denon):
                self.write_pins(tooling_repository=tooling, denon_changes={"repository": denon})
                pins = feed.source_pins()
                self.assertEqual(pins["tooling"]["repository"], tooling)
                self.assertEqual(pins["integrations"]["denon"]["repository"], denon)

    def test_other_or_lookalike_owners_are_rejected(self):
        for owner in (
            "someone-else", "couch-os", "COUCH-OS", "Couch-Os", "CouchOS", "Couch_OS",
            "Dangerouslaser", "dangerouslaser-fork", "Couch-OS-mirror", "Couch-OS/extra",
        ):
            repository = f"https://github.com/{owner}/couch-integration-denon.git"
            with self.subTest(owner=owner):
                self.write_pins(denon_changes={"repository": repository})
                with self.assertRaisesRegex(feed.InvalidFeed, "allowed repository"):
                    feed.source_pins()
                self.write_pins(tooling_repository=f"https://github.com/{owner}/couch.git")
                with self.assertRaisesRegex(feed.InvalidFeed, "allowed repository"):
                    feed.source_pins()

    def test_repository_url_must_be_one_canonical_git_url(self):
        for repository in (
            "https://github.com/Couch-OS/couch-integration-denon",
            "https://github.com/Couch-OS/couch-integration-denon/",
            "https://github.com/Couch-OS/couch-integration-denon.git/",
            "https://github.com/Couch-OS/couch-integration-denon.git.git",
            "https://github.com/Couch-OS/Couch-Integration-Denon.git",
            "https://github.com/Couch-OS/.git",
            "http://github.com/Couch-OS/couch-integration-denon.git",
            "https://www.github.com/Couch-OS/couch-integration-denon.git",
            "https://github.com.example/Couch-OS/couch-integration-denon.git",
            "git@github.com:Couch-OS/couch-integration-denon.git",
        ):
            with self.subTest(repository=repository):
                self.write_pins(denon_changes={"repository": repository})
                with self.assertRaisesRegex(feed.InvalidFeed, "allowed repository"):
                    feed.source_pins()

    def test_tooling_must_be_the_core_repository_under_an_allowed_owner(self):
        for repository in (
            DENON,
            "https://github.com/Couch-OS/couch",
            "https://github.com/Couch-OS/couch.git.git",
            "https://github.com/Couch-OS/couch-installer.git",
        ):
            with self.subTest(repository=repository):
                self.write_pins(tooling_repository=repository)
                with self.assertRaisesRegex(feed.InvalidFeed, "allowed repository"):
                    feed.source_pins()

    def test_sdk_may_use_either_core_url_but_only_one(self):
        self.assertEqual(self.validate(self.write_sources(core=MOVED_CORE))["denon"]["sdk_commit"], self.tooling_commit)
        mixed = self.write_sources(core=MOVED_CORE)
        cargo = mixed / "integrations/denon/Cargo.toml"
        text = cargo.read_text(encoding="utf-8")
        cargo.write_text(text.replace(MOVED_CORE, LEGACY_CORE, 1), encoding="utf-8")
        with self.assertRaisesRegex(feed.InvalidFeed, "one Couch repository URL"):
            self.validate(mixed)
        for repository in ("https://github.com/couch-os/couch.git", "https://github.com/someone-else/couch.git", DENON):
            with self.subTest(repository=repository):
                with self.assertRaisesRegex(feed.InvalidFeed, "must pin the Couch repository"):
                    self.validate(self.write_sources(core=repository))

    def test_a_protocol_v2_package_is_admitted_when_both_files_agree(self):
        v2 = {"protocol_version": 2, "min_core_protocol_version": 2}
        selected = self.validate(self.write_sources(
            metadata_changes={"protocol_version": 2}, manifest_changes=v2))
        self.assertEqual(selected["denon"]["manifest_data"]["protocol_version"], 2)

    def test_a_protocol_v3_package_reuses_children_pairing_and_concurrent_admission(self):
        v3 = {
            "protocol_version": 3,
            "min_core_protocol_version": 3,
            "children": [{"kind": "light"}],
            "pairing": {"required": True, "max_seconds": 120},
        }
        sources = self.write_sources(
            metadata_changes={"protocol_version": 3}, manifest_changes=v3)
        tests = sources / "integrations/denon/tests"
        (tests / "protocol3.rs").write_text(
            "testing_v3::children(fixture); testing_v3::pairing(fixture);",
            encoding="utf-8",
        )
        selected = self.validate(sources)
        self.assertEqual(selected["denon"]["manifest_data"]["protocol_version"], 3)

    def test_a_protocol_v4_package_is_admitted_with_concurrent_startup(self):
        v4 = {
            "protocol_version": 4,
            "min_core_protocol_version": 4,
            "children": [{"kind": "camera"}],
            "pairing": {"required": True, "max_seconds": 30},
        }
        selected = self.validate(self.write_sources(
            metadata_changes={"protocol_version": 4}, manifest_changes=v4))
        self.assertEqual(selected["denon"]["manifest_data"]["protocol_version"], 4)

    def test_a_protocol_v5_package_is_admitted_with_concurrent_startup(self):
        v5 = {
            "protocol_version": 5,
            "min_core_protocol_version": 5,
        }
        selected = self.validate(self.write_sources(
            metadata_changes={"protocol_version": 5}, manifest_changes=v5))
        self.assertEqual(selected["denon"]["manifest_data"]["protocol_version"], 5)

    def test_protocol_versions_must_be_known_and_agree(self):
        for metadata, manifest, message in (
            ({"protocol_version": 6}, {"protocol_version": 6, "min_core_protocol_version": 6}, "source metadata is invalid"),
            ({"protocol_version": 0}, {"protocol_version": 0}, "source metadata is invalid"),
            ({"protocol_version": True}, {}, "source metadata is invalid"),
            ({"protocol_version": "2"}, {"protocol_version": 2, "min_core_protocol_version": 2}, "source metadata is invalid"),
            # integration.json and plugin.json disagree, either way round.
            ({"protocol_version": 2}, {}, "plugin manifest does not match"),
            ({}, {"protocol_version": 2, "min_core_protocol_version": 2}, "plugin manifest does not match"),
            # A v2 manifest that a v1 core would wrongly be allowed to load.
            ({"protocol_version": 2}, {"protocol_version": 2}, "plugin manifest does not match"),
            ({"protocol_version": 2}, {"protocol_version": 2, "min_core_protocol_version": 1}, "plugin manifest does not match"),
            ({}, {"min_core_protocol_version": 2}, "plugin manifest does not match"),
        ):
            with self.subTest(metadata=metadata, manifest=manifest):
                with self.assertRaisesRegex(feed.InvalidFeed, message):
                    self.validate(self.write_sources(
                        metadata_changes=metadata, manifest_changes=manifest))

    def test_manifest_identity_and_paths_are_enforced(self):
        with self.assertRaisesRegex(feed.InvalidFeed, "plugin manifest does not match"):
            self.validate(self.write_sources(manifest_changes={"id": "other"}))
        with self.assertRaisesRegex(feed.InvalidFeed, "path is invalid"):
            self.validate(self.write_sources(metadata_changes={"manifest": "../plugin.json"}))

    def test_arm_build_requires_the_repository_linker_config(self):
        sources = self.write_sources()
        (sources / "integrations/denon/.cargo/config.toml").write_text(
            '[target.armv7-unknown-linux-musleabihf]\nlinker = "cc"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(feed.InvalidFeed, "must use rust-lld"):
            self.validate(sources)

    def test_shared_admission_cases_cannot_be_removed(self):
        sources = self.write_sources()
        path = sources / "integrations/denon/tests/admission.rs"
        path.write_text(path.read_text(encoding="utf-8").replace("testing::spike(", "local_spike("), encoding="utf-8")
        with self.assertRaisesRegex(feed.InvalidFeed, "reuse the shared spike case"):
            self.validate(sources)

    def test_synthetic_or_test_only_source_is_never_publishable(self):
        for changes in ({"synthetic": True}, {"tier": "test-only"}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(feed.InvalidFeed, "never publish"):
                    self.validate(self.write_sources(metadata_changes=changes))

    def test_stable_remains_production_only(self):
        self.write_policy([], stable_tiers=["preview", "production"])
        with self.assertRaisesRegex(feed.InvalidFeed, "production tier only"):
            feed.policy()

    def test_integration_cannot_appear_in_both_channels(self):
        self.write_policy(["denon"])
        with self.assertRaisesRegex(feed.InvalidFeed, "only one channel"):
            feed.policy()

    def test_checked_out_source_must_match_its_pin(self):
        sources = self.write_sources()
        pins = feed.source_pins()
        with mock.patch.object(feed, "git_head", return_value="c" * 40):
            with self.assertRaisesRegex(feed.InvalidFeed, "tooling source does not match"):
                feed.validate_sources(sources, pins, feed.policy())

    def receipt(self, **changes):
        record = {
            "schema": 2,
            "source_repository": DENON,
            "source_commit": self.source_commit,
            "sdk_repository": MOVED_CORE,
            "sdk_commit": self.tooling_commit,
            "tooling_repository": MOVED_CORE,
            "tooling_commit": self.tooling_commit,
            "id": "denon",
            "version": "0.1.1",
            "binary": "couch-plugin-denon",
            "binary_sha256": "d" * 64,
            "manifest_sha256": "e" * 64,
        }
        record.update(changes)
        return record

    def test_identical_retained_receipt_is_reused(self):
        feed.validate_retained_receipt(self.receipt(), self.receipt())

    def test_retained_receipt_may_predate_an_owner_move(self):
        legacy = {
            "source_repository": LEGACY_DENON,
            "sdk_repository": LEGACY_CORE,
            "tooling_repository": LEGACY_CORE,
        }
        for field, repository in legacy.items():
            with self.subTest(field=field):
                feed.validate_retained_receipt(self.receipt(), self.receipt(**{field: repository}))
                feed.validate_retained_receipt(self.receipt(**{field: repository}), self.receipt())
        feed.validate_retained_receipt(self.receipt(), self.receipt(**legacy))

    def test_retained_receipt_may_record_older_pin_commits(self):
        older = {field: "c" * 40 for field in feed.RECEIPT_COMMITS}
        feed.validate_retained_receipt(self.receipt(), self.receipt(**older))
        feed.validate_retained_receipt(
            self.receipt(), self.receipt(source_repository=LEGACY_DENON, tooling_repository=LEGACY_CORE, **older)
        )

    def test_retained_receipt_cannot_name_another_repository(self):
        for field, repository in (
            ("source_repository", "https://github.com/Couch-OS/couch-integration-denon-fork.git"),
            ("source_repository", "https://github.com/dangerouslaser/couch-integration-marantz.git"),
            ("source_repository", LEGACY_CORE),
            ("sdk_repository", "https://github.com/dangerouslaser/couch-sdk.git"),
            ("tooling_repository", "https://github.com/Couch-OS/couch-installer.git"),
        ):
            with self.subTest(field=field, repository=repository):
                with self.assertRaisesRegex(feed.InvalidFeed, "different repository"):
                    feed.validate_retained_receipt(self.receipt(), self.receipt(**{field: repository}))

    def test_retained_receipt_repository_must_use_an_allowed_owner(self):
        for repository in (
            "https://github.com/someone-else/couch-integration-denon.git",
            "https://github.com/couch-os/couch-integration-denon.git",
            "https://github.com/Couch-OS/couch-integration-denon",
            "https://github.com/Couch-OS/couch-integration-denon.git.git",
            None,
        ):
            with self.subTest(repository=repository):
                with self.assertRaisesRegex(feed.InvalidFeed, "invalid source_repository"):
                    feed.validate_retained_receipt(self.receipt(), self.receipt(source_repository=repository))
        with self.assertRaisesRegex(feed.InvalidFeed, "different repository"):
            feed.validate_retained_receipt(
                self.receipt(source_repository="https://github.com/couch-os/couch-integration-denon.git"),
                self.receipt(source_repository=LEGACY_DENON),
            )

    def test_retained_receipt_package_identity_is_immutable(self):
        for field, value in (
            ("schema", 3), ("id", "marantz"), ("version", "0.1.2"), ("binary", "other"),
            ("binary_sha256", "f" * 64), ("manifest_sha256", "f" * 64),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(feed.InvalidFeed, "immutable provenance differs"):
                    feed.validate_retained_receipt(self.receipt(), self.receipt(**{field: value}))
                with self.assertRaisesRegex(feed.InvalidFeed, "immutable provenance differs"):
                    feed.validate_retained_receipt(
                        self.receipt(), self.receipt(source_repository=LEGACY_DENON, **{field: value})
                    )

    def test_retained_receipt_shape_and_commits_are_checked(self):
        missing = self.receipt()
        del missing["tooling_commit"]
        for approved, existing in (
            (self.receipt(), missing),
            (missing, self.receipt()),
            (self.receipt(), self.receipt(extra=True)),
            (self.receipt(), []),
        ):
            with self.assertRaisesRegex(feed.InvalidFeed, "invalid shape"):
                feed.validate_retained_receipt(approved, existing)
        for commit in ("0" * 39, "C" * 40, None):
            with self.assertRaisesRegex(feed.InvalidFeed, "invalid sdk_commit"):
                feed.validate_retained_receipt(self.receipt(), self.receipt(sdk_commit=commit))

    def test_retained_receipt_command_reports_reuse_decision(self):
        approved = self.root / "approved.json"
        self.write_json(approved, self.receipt())
        cases = (
            (self.receipt(source_repository=LEGACY_DENON, tooling_repository=LEGACY_CORE), 0),
            (self.receipt(source_repository="https://github.com/Couch-OS/couch-integration-denon-fork.git"), 1),
        )
        for record, status in cases:
            with self.subTest(record=record):
                existing = self.root / "existing.json"
                self.write_json(existing, record)
                argv = ["validate_feed.py", "--retained-receipt", str(approved), str(existing)]
                with mock.patch.object(feed, "validate_key"), mock.patch.object(sys, "argv", argv):
                    with mock.patch.object(sys, "stderr"):
                        self.assertEqual(feed.main(), status)

    def test_placeholder_key_cannot_enable_feed(self):
        (self.root / "keys/couch-integrations.rsa.pub").write_text("REPLACE_WITH_PUBLIC_KEY\n")
        with self.assertRaisesRegex(feed.InvalidFeed, "replace keys"):
            feed.validate_key()


if __name__ == "__main__":
    unittest.main()
