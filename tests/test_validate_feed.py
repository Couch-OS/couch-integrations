#!/usr/bin/env python3
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE = Path(__file__).parents[1] / "scripts" / "validate_feed.py"
SPEC = importlib.util.spec_from_file_location("validate_feed", MODULE)
feed = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(feed)


class FeedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_root = feed.ROOT
        feed.ROOT = self.root
        self.core_count = 0
        (self.root / "keys").mkdir()
        (self.root / "source-pin.json").write_text(
            json.dumps(
                {
                    "schema": 1,
                    "repository": "https://github.com/dangerouslaser/couch.git",
                    "commit": "a" * 40,
                }
            )
        )

    def tearDown(self):
        feed.ROOT = self.old_root
        self.temp.cleanup()

    def write_policy(
        self,
        stable_ids,
        *,
        stable_tiers=None,
        preview_ids=None,
        preview_tiers=None,
    ):
        (self.root / "feed-policy.json").write_text(
            json.dumps(
                {
                    "schema": 1,
                    "channels": {
                        "preview": {
                            "ids": ["denon"] if preview_ids is None else preview_ids,
                            "allowed_tiers": ["preview"]
                            if preview_tiers is None
                            else preview_tiers,
                        },
                        "stable": {
                            "ids": stable_ids,
                            "allowed_tiers": ["production"]
                            if stable_tiers is None
                            else stable_tiers,
                        },
                    },
                }
            )
        )

    def write_core(self, entry, manifest=None):
        self.core_count += 1
        core = self.root / f"core-{self.core_count}"
        (core / "integrations").mkdir(parents=True)
        (core / "integrations/catalog.json").write_text(
            json.dumps(
                {
                    "schema": 1,
                    "protocol_version": 1,
                    "integrations": [entry],
                }
            )
        )
        manifest_name = entry.get("manifest")
        if manifest is not None and isinstance(manifest_name, str) and ".." not in manifest_name:
            manifest_path = core / manifest_name
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps(manifest))
        return core

    @staticmethod
    def denon_entry(**changes):
        entry = {
            "id": "denon",
            "tier": "preview",
            "manifest": "clients/couch-denon/plugin.json",
            "binary": "couch-plugin-denon",
        }
        entry.update(changes)
        return entry

    @staticmethod
    def denon_manifest(**changes):
        manifest = {
            "protocol_version": 1,
            "id": "denon",
            "version": "0.1.0",
            "executable": "bin/couch-plugin-denon",
        }
        manifest.update(changes)
        return manifest

    def validate(self, core, selected_policy=None):
        pin = feed.source_pin()
        selected_policy = feed.policy() if selected_policy is None else selected_policy
        with mock.patch.object(feed, "git_head", return_value=pin["commit"]):
            feed.validate_catalog(core, pin, selected_policy)

    def test_policy_can_name_a_future_stable_package(self):
        self.write_policy(["denon"])
        self.assertEqual(feed.policy()["channels"]["stable"]["ids"], ["denon"])

    def test_stable_policy_cannot_make_preview_publishable(self):
        self.write_policy([], stable_tiers=["production", "preview"])
        with self.assertRaisesRegex(feed.InvalidFeed, "production tier only"):
            feed.policy()

    def test_malformed_tier_values_fail_closed(self):
        self.write_policy([], preview_tiers=[{"tier": "preview"}])
        with self.assertRaisesRegex(feed.InvalidFeed, "invalid IDs or tiers"):
            feed.policy()

    def test_stable_rejects_preview_even_if_caller_supplies_relaxed_policy(self):
        core = self.write_core(self.denon_entry(), self.denon_manifest())
        selected_policy = {
            "channels": {
                "preview": {"ids": [], "allowed_tiers": ["preview"]},
                "stable": {"ids": ["denon"], "allowed_tiers": ["preview", "production"]},
            }
        }
        with self.assertRaisesRegex(feed.InvalidFeed, "stable selects non-production"):
            self.validate(core, selected_policy)

    def test_test_only_and_synthetic_catalog_entries_are_never_published(self):
        self.write_policy([], preview_ids=["denon"], preview_tiers=["preview", "production"])
        for entry in [
            self.denon_entry(tier="test-only"),
            self.denon_entry(synthetic=True),
        ]:
            with self.subTest(entry=entry):
                core = self.write_core(entry, self.denon_manifest())
                with self.assertRaisesRegex(feed.InvalidFeed, "never publish"):
                    self.validate(core)

    def test_catalog_manifest_path_and_identity_must_be_safe(self):
        self.write_policy([])
        escaping = self.write_core(
            self.denon_entry(manifest="../outside.json"), self.denon_manifest()
        )
        with self.assertRaisesRegex(feed.InvalidFeed, "catalog paths are invalid"):
            self.validate(escaping)

        mismatched = self.write_core(
            self.denon_entry(), self.denon_manifest(id="another-integration")
        )
        with self.assertRaisesRegex(feed.InvalidFeed, "manifest does not match"):
            self.validate(mismatched)

    def test_placeholder_key_cannot_enable_feed(self):
        self.write_policy([])
        (self.root / "keys/couch-integrations.rsa.pub").write_text(
            "REPLACE_WITH_THE_PUBLIC_HALF_OF_APK_SIGNING_KEY\n"
        )
        with self.assertRaisesRegex(feed.InvalidFeed, "replace keys"):
            feed.validate_key()

    def test_source_pin_requires_full_commit(self):
        (self.root / "source-pin.json").write_text(
            json.dumps(
                {
                    "schema": 1,
                    "repository": "https://github.com/dangerouslaser/couch.git",
                    "commit": "deadbeef",
                }
            )
        )
        with self.assertRaisesRegex(feed.InvalidFeed, "full commit SHA"):
            feed.source_pin()

    def test_checked_out_source_must_match_the_pin(self):
        core = self.root / "core"
        core.mkdir()
        pin = feed.source_pin()
        with mock.patch.object(feed, "git_head", return_value="b" * 40):
            with self.assertRaisesRegex(feed.InvalidFeed, "does not match source-pin"):
                feed.validate_catalog(core, pin, {"channels": {}})


if __name__ == "__main__":
    unittest.main()
