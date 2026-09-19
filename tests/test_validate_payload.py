#!/usr/bin/env python3
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "validate_payload.py"


class PayloadValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.feed = self.root / "feed"
        self.sources = self.root / "sources"
        self.payload = self.root / "artifact"
        self.tooling_commit = "a" * 40
        self.source_commit = "b" * 40
        self.integration_id = "denon"
        self.binary_name = "couch-plugin-denon"
        self.source = self.sources / "integrations" / self.integration_id
        self.manifest = {
            "protocol_version": 1,
            "id": self.integration_id,
            "label": "Denon AVR",
            "version": "0.1.1",
            "executable": f"bin/{self.binary_name}",
            "capabilities": [],
            "settings": [],
            "supports_inputs": True,
        }
        self.pins = {
            "schema": 2,
            "tooling": {
                "repository": "https://github.com/dangerouslaser/couch.git",
                "commit": self.tooling_commit,
            },
            "integrations": {
                self.integration_id: {
                    "repository": "https://github.com/Couch-OS/couch-integration-denon.git",
                    "commit": self.source_commit,
                }
            },
        }
        self.feed.mkdir()
        self.source.mkdir(parents=True)
        (self.payload / self.integration_id).mkdir(parents=True)
        self.write_json(self.feed / "source-pin.json", self.pins)
        self.write_json(
            self.feed / "feed-policy.json",
            {"channels": {"preview": {"ids": [self.integration_id]}}},
        )
        self.write_json(self.feed / "build-secrets.json", {"schema": 1, "integrations": {}})
        self.write_json(
            self.source / "integration.json",
            {
                "id": self.integration_id,
                "cargo_manifest": "Cargo.toml",
                "binary": self.binary_name,
                "manifest": "plugin.json",
            },
        )
        (self.source / "Cargo.toml").write_text(
            f'''[package]
name = "couch-denon"
[dependencies]
couch-sdk = {{ git = "https://github.com/dangerouslaser/couch.git", rev = "{self.tooling_commit}" }}
''',
            encoding="utf-8",
        )
        self.write_json(self.source / "plugin.json", self.manifest)
        self.write_json(self.payload / "SOURCE_PINS.json", self.pins)
        self.binary = self.payload / self.integration_id / self.binary_name
        self.binary.write_bytes(b"\x7fELF\x01armv7 fixture binary")
        self.artifact_manifest = self.payload / self.integration_id / "manifest.json"
        self.write_json(self.artifact_manifest, self.manifest)
        self.provenance = self.payload / self.integration_id / "provenance.json"
        self.write_provenance()

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_provenance(self, **changes):
        record = {
            "schema": 2,
            "source_repository": self.pins["integrations"][self.integration_id]["repository"],
            "source_commit": self.source_commit,
            "sdk_repository": self.pins["tooling"]["repository"],
            "sdk_commit": self.tooling_commit,
            "tooling_repository": self.pins["tooling"]["repository"],
            "tooling_commit": self.tooling_commit,
            "id": self.integration_id,
            "version": self.manifest["version"],
            "binary": self.binary_name,
            "binary_sha256": self.digest(self.binary),
            "manifest_sha256": self.digest(self.artifact_manifest),
        }
        record.update(changes)
        self.write_json(self.provenance, record)

    def validate(self, *flags):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *flags, str(self.feed), str(self.sources), str(self.payload)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def assert_rejected(self, result, message="manifest or provenance"):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)

    def test_matching_payload_is_accepted(self):
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "payload provenance valid")

    def test_corrupted_binary_is_rejected(self):
        self.binary.write_bytes(self.binary.read_bytes() + b"tampered")
        self.assert_rejected(self.validate())

    def test_changed_manifest_is_rejected_even_with_matching_receipt(self):
        changed = dict(self.manifest, version="9.9.9")
        self.write_json(self.artifact_manifest, changed)
        self.write_provenance(version=changed["version"], manifest_sha256=self.digest(self.artifact_manifest))
        self.assert_rejected(self.validate())

    def test_stale_source_pin_snapshot_is_rejected(self):
        stale = dict(self.pins)
        stale["integrations"] = {self.integration_id: dict(self.pins["integrations"][self.integration_id], commit="c" * 40)}
        self.write_json(self.payload / "SOURCE_PINS.json", stale)
        self.assert_rejected(self.validate(), "source pins do not match")

    def test_payload_built_before_an_owner_move_is_rejected(self):
        # Owner-move equivalence applies only to retained published receipts.
        # A new payload must be admitted for the exact reviewed repository URL.
        legacy = "https://github.com/dangerouslaser/couch-integration-denon.git"
        stale = dict(self.pins)
        stale["integrations"] = {self.integration_id: dict(self.pins["integrations"][self.integration_id], repository=legacy)}
        self.write_json(self.payload / "SOURCE_PINS.json", stale)
        self.assert_rejected(self.validate(), "source pins do not match")
        self.write_json(self.payload / "SOURCE_PINS.json", self.pins)
        self.write_provenance(source_repository=legacy)
        self.assert_rejected(self.validate())

    def test_altered_source_provenance_is_rejected(self):
        self.write_provenance(source_commit="c" * 40)
        self.assert_rejected(self.validate())

    def allow_build_secret(self, *names):
        self.write_json(self.feed / "build-secrets.json", {"schema": 1, "integrations": {self.integration_id: list(names)}})

    def test_payload_without_the_build_secret_allowlist_is_rejected(self):
        (self.feed / "build-secrets.json").unlink()
        self.assert_rejected(self.validate(), "cannot read")
        self.assert_rejected(self.validate("--review"), "cannot read")

    def test_allowlisted_integration_is_publishable_only_with_every_secret(self):
        self.allow_build_secret("COUCH_DENON_A", "COUCH_DENON_B")
        self.write_provenance(built_with_secrets=["COUCH_DENON_A", "COUCH_DENON_B"])
        self.assertEqual(self.validate().returncode, 0)
        self.assertEqual(self.validate("--review").returncode, 0)
        for recorded in ([], ["COUCH_DENON_A"], ["COUCH_DENON_B", "COUCH_DENON_A"], ["COUCH_OTHER"], None, "COUCH_DENON_A"):
            with self.subTest(recorded=recorded):
                self.write_provenance(built_with_secrets=recorded)
                self.assert_rejected(self.validate(), "was not built with its required build secrets")
        self.write_provenance()
        self.assert_rejected(self.validate(), "was not built with its required build secrets")

    def test_placeholder_build_is_accepted_for_review_only(self):
        self.allow_build_secret("COUCH_DENON_A")
        self.write_provenance(built_with_secrets=[])
        self.assertEqual(self.validate("--review").returncode, 0)
        self.assert_rejected(self.validate(), "only a main-branch admission build is publishable")
        # Review mode is not a wildcard: a partial or foreign record still fails.
        self.write_provenance(built_with_secrets=["COUCH_OTHER"])
        self.assert_rejected(self.validate("--review"), "was not built with its required build secrets")
        self.write_provenance()
        self.assert_rejected(self.validate("--review"), "was not built with its required build secrets")

    def test_unlisted_integration_cannot_claim_a_build_secret(self):
        self.write_provenance(built_with_secrets=[])
        self.assert_rejected(self.validate())
        self.assert_rejected(self.validate("--review"))

    def test_unselected_payload_directory_is_rejected(self):
        (self.payload / "unexpected").mkdir()
        self.assert_rejected(self.validate(), "unselected integration")


if __name__ == "__main__":
    unittest.main()
