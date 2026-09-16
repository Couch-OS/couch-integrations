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
        self.core = self.root / "core"
        self.payload = self.root / "artifact"
        self.commit = "a" * 40
        self.integration_id = "denon"
        self.binary_name = "couch-plugin-denon"
        self.manifest_name = "clients/couch-denon/plugin.json"
        self.manifest = {
            "protocol_version": 1,
            "id": self.integration_id,
            "label": "Denon AVR",
            "version": "0.1.0",
            "executable": f"bin/{self.binary_name}",
            "capabilities": [],
            "settings": [],
            "supports_inputs": True,
        }

        (self.feed).mkdir()
        (self.core / "integrations").mkdir(parents=True)
        (self.core / Path(self.manifest_name).parent).mkdir(parents=True)
        (self.payload / self.integration_id).mkdir(parents=True)
        self.write_json(self.feed / "source-pin.json", {"commit": self.commit})
        self.write_json(
            self.feed / "feed-policy.json",
            {"channels": {"preview": {"ids": [self.integration_id]}}},
        )
        self.write_json(
            self.core / "integrations/catalog.json",
            {
                "integrations": [
                    {
                        "id": self.integration_id,
                        "manifest": self.manifest_name,
                        "binary": self.binary_name,
                    }
                ]
            },
        )
        self.write_json(self.core / self.manifest_name, self.manifest)
        (self.payload / "CORE_COMMIT").write_text(f"{self.commit}\n", encoding="utf-8")
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
            "schema": 1,
            "core_commit": self.commit,
            "id": self.integration_id,
            "version": self.manifest["version"],
            "binary": self.binary_name,
            "binary_sha256": self.digest(self.binary),
            "manifest_sha256": self.digest(self.artifact_manifest),
        }
        record.update(changes)
        self.write_json(self.provenance, record)

    def validate(self):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(self.feed),
                str(self.core),
                str(self.payload),
            ],
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

    def test_changed_manifest_is_rejected_even_with_matching_artifact_receipt(self):
        changed = dict(self.manifest, version="9.9.9")
        self.write_json(self.artifact_manifest, changed)
        self.write_provenance(
            version=changed["version"],
            manifest_sha256=self.digest(self.artifact_manifest),
        )
        self.assert_rejected(self.validate())

    def test_stale_core_commit_is_rejected(self):
        (self.payload / "CORE_COMMIT").write_text(f"{'b' * 40}\n", encoding="utf-8")
        self.assert_rejected(self.validate(), "core commit does not match source pin")

    def test_altered_provenance_is_rejected(self):
        self.write_provenance(binary_sha256="0" * 64)
        self.assert_rejected(self.validate())


if __name__ == "__main__":
    unittest.main()
