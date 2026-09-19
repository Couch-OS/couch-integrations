#!/usr/bin/env python3
"""feed.json and feed.json.sig: exact bytes, the sequence rule, and re-signing.

Packages and indexes here are small stand-ins with the same layout as the real
ones: a gzip tar holding the manifest at its installed path, and a gzip tar
holding the APKINDEX text. The key is disposable.
"""
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).parents[1]
SCRIPT = REPOSITORY / "scripts" / "feed_metadata.py"
CLOCK = 1790000000  # 2026-09-21T14:13:20Z
WEEK = 7 * 86400


def run(*argv, clock=None, cwd=None):
    env = {key: value for key, value in os.environ.items() if key != "COUCH_FEED_NOW"}
    if clock is not None:
        env["COUCH_FEED_NOW"] = str(clock)
    return subprocess.run(
        [str(item) for item in argv], env=env, cwd=cwd, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def gzip_tar(path, members):
    with tarfile.open(path, "w:gz") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


def write_apk(directory, integration_id, version, manifest=None, body=b"binary"):
    if manifest is None:
        manifest = {"protocol_version": 1, "id": integration_id, "version": version}
    path = directory / f"couch-integration-{integration_id}-{version}-r0.apk"
    gzip_tar(path, [
        (".PKGINFO", b"pkgname = fixture\n"),
        (f"usr/lib/couch/integrations/{integration_id}/bin/couch-plugin-{integration_id}", body),
        (f"usr/lib/couch/integrations/{integration_id}/manifest.json", json.dumps(manifest).encode()),
    ])
    return path


def write_index(directory, names=None):
    """An index of NAMES, or of every package in DIRECTORY."""
    if names is None:
        names = sorted(path.name for path in directory.glob("*.apk"))
    records = []
    for name in names:
        package, version, release = name.removesuffix(".apk").rsplit("-", 2)
        records.append(f"C:Q1fixture=\nP:{package}\nV:{version}-{release}\nA:armv7\n")
    gzip_tar(directory / "APKINDEX.tar.gz", [
        (".SIGN.RSA.couch-integrations.rsa.pub", b"signature"),
        ("APKINDEX", "\n".join(records).encode()),
    ])


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.key = Path(cls.keys.name) / "couch-integrations.rsa"
        cls.public_key = Path(cls.keys.name) / "couch-integrations.rsa.pub"
        subprocess.run(["openssl", "genrsa", "-out", str(cls.key), "2048"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(cls.public_key, "wb") as output:
            subprocess.run(["openssl", "pkey", "-in", str(cls.key), "-pubout"], check=True, stdout=output)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.empty = self.root / "empty-history"
        self.empty.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def site(self, name, packages=(("denon", "0.2.1"),)):
        site = self.root / name
        for channel in ("preview", "stable"):
            (site / channel / "armv7").mkdir(parents=True)
        for integration_id, version in packages:
            write_apk(site / "preview" / "armv7", integration_id, version)
        write_index(site / "preview" / "armv7")
        write_index(site / "stable" / "armv7")
        return site

    def write(self, site, previous=None, clock=CLOCK):
        return run(SCRIPT, "write", "--site", site, "--previous", previous or self.empty,
                   "--key", self.key, "--public-key", self.public_key, clock=clock)

    def published(self, name, **options):
        site = self.site(name, **options)
        result = self.write(site)
        self.assertEqual(result.returncode, 0, result.stderr)
        return site

    def verify(self, site):
        return run(SCRIPT, "verify", "--site", site, "--public-key", self.public_key)

    def openssl_verifies(self, metadata, signature):
        return run("openssl", "dgst", "-sha256", "-verify", self.public_key,
                   "-signature", signature, metadata).returncode == 0


class FeedMetadataTests(Fixture):
    def test_a_fixed_clock_gives_exactly_these_bytes(self):
        site = self.published("site")
        preview = site / "preview" / "armv7"
        apk = preview / "couch-integration-denon-0.2.1-r0.apk"
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual((preview / "feed.json").read_text(encoding="utf-8"), f"""{{
  "schema": 1,
  "channel": "preview",
  "sequence": 1790000000,
  "issued": "2026-09-21T14:13:20Z",
  "expires": "2026-10-21T14:13:20Z",
  "index": {{
    "path": "APKINDEX.tar.gz",
    "size": {(preview / "APKINDEX.tar.gz").stat().st_size},
    "sha256": "{digest(preview / "APKINDEX.tar.gz")}"
  }},
  "packages": [
    {{
      "id": "denon",
      "version": "0.2.1",
      "apk": "couch-integration-denon-0.2.1-r0.apk",
      "size": {apk.stat().st_size},
      "sha256": "{digest(apk)}",
      "protocol_version": 1,
      "min_core_protocol_version": 1
    }}
  ]
}}
""")
        stable = site / "stable" / "armv7"
        self.assertEqual((stable / "feed.json").read_text(encoding="utf-8"), f"""{{
  "schema": 1,
  "channel": "stable",
  "sequence": 1790000000,
  "issued": "2026-09-21T14:13:20Z",
  "expires": "2026-10-21T14:13:20Z",
  "index": {{
    "path": "APKINDEX.tar.gz",
    "size": {(stable / "APKINDEX.tar.gz").stat().st_size},
    "sha256": "{digest(stable / "APKINDEX.tar.gz")}"
  }},
  "packages": []
}}
""")
        # Same clock, same input, same bytes: the signature scheme is deterministic too.
        again = self.site("again")
        shutil.copy(preview / "APKINDEX.tar.gz", again / "preview" / "armv7")
        shutil.copy(apk, again / "preview" / "armv7")
        shutil.copy(stable / "APKINDEX.tar.gz", again / "stable" / "armv7")
        self.assertEqual(self.write(again).returncode, 0)
        for channel in ("preview", "stable"):
            for name in ("feed.json", "feed.json.sig"):
                self.assertEqual((again / channel / "armv7" / name).read_bytes(),
                                 (site / channel / "armv7" / name).read_bytes())

    def test_the_signature_is_the_stock_openssl_one_and_tampering_breaks_it(self):
        site = self.published("site")
        for channel in ("preview", "stable"):
            directory = site / channel / "armv7"
            self.assertTrue(self.openssl_verifies(directory / "feed.json", directory / "feed.json.sig"))
            self.assertEqual((directory / "feed.json.sig").stat().st_size, 256)  # raw, not base64 or PEM
        preview = site / "preview" / "armv7"
        self.assertFalse(self.openssl_verifies(preview / "feed.json", site / "stable" / "armv7" / "feed.json.sig"))
        tampered = self.root / "tampered.json"
        tampered.write_text((preview / "feed.json").read_text().replace("1790000000", "1790000001"))
        self.assertFalse(self.openssl_verifies(tampered, preview / "feed.json.sig"))
        shutil.copy(tampered, preview / "feed.json")
        result = self.verify(site)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not signed by", result.stderr)

    def test_protocol_numbers_come_from_the_manifest_inside_each_package(self):
        site = self.site("site", packages=())
        preview = site / "preview" / "armv7"
        write_apk(preview, "denon", "0.1.1")
        write_apk(preview, "denon", "0.2.0", {
            "protocol_version": 2, "min_core_protocol_version": 2, "id": "denon", "version": "0.2.0"})
        # An absent minimum means 1, as couch-plugin reads it, never the protocol version.
        write_apk(preview, "kodi", "0.1.0", {"protocol_version": 2, "id": "kodi", "version": "0.1.0"})
        write_index(preview)
        self.assertEqual(self.write(site).returncode, 0)
        packages = json.loads((preview / "feed.json").read_text())["packages"]
        self.assertEqual(
            [(item["id"], item["version"], item["protocol_version"], item["min_core_protocol_version"])
             for item in packages],
            [("denon", "0.1.1", 1, 1), ("denon", "0.2.0", 2, 2), ("kodi", "0.1.0", 2, 1)])

    def test_packages_are_sorted_by_id_then_by_version_as_numbers(self):
        site = self.published("site", packages=(("sonos", "0.1.0"), ("denon", "0.10.0"), ("denon", "0.9.2")))
        packages = json.loads((site / "preview" / "armv7" / "feed.json").read_text())["packages"]
        self.assertEqual([(item["id"], item["version"]) for item in packages],
                         [("denon", "0.9.2"), ("denon", "0.10.0"), ("sonos", "0.1.0")])

    def test_a_manifest_that_disagrees_with_the_package_name_is_refused(self):
        for manifest in (
            {"protocol_version": 1, "id": "kodi", "version": "0.2.1"},
            {"protocol_version": 1, "id": "denon", "version": "0.2.2"},
            {"protocol_version": 0, "id": "denon", "version": "0.2.1"},
            {"protocol_version": True, "id": "denon", "version": "0.2.1"},
            {"protocol_version": 1, "min_core_protocol_version": "1", "id": "denon", "version": "0.2.1"},
            {"id": "denon", "version": "0.2.1"},
        ):
            with self.subTest(manifest=manifest):
                site = self.site(f"site-{len(list(self.root.iterdir()))}", packages=())
                write_apk(site / "preview" / "armv7", "denon", "0.2.1", manifest)
                write_index(site / "preview" / "armv7")
                result = self.write(site)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((site / "preview" / "armv7" / "feed.json.sig").exists())

    def test_the_index_and_the_package_files_must_name_the_same_packages(self):
        unlisted = self.site("unlisted")
        write_apk(unlisted / "preview" / "armv7", "kodi", "0.1.0")
        missing = self.site("missing")
        write_index(missing / "preview" / "armv7",
                    ["couch-integration-denon-0.2.1-r0.apk", "couch-integration-kodi-0.1.0-r0.apk"])
        in_stable = self.site("in-stable")
        write_apk(in_stable / "stable" / "armv7", "kodi", "0.1.0")
        for site in (unlisted, missing, in_stable):
            with self.subTest(site=site.name):
                result = self.write(site)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("do not name the same packages", result.stderr)

    def test_the_sequence_must_move_forward(self):
        first = self.published("first")
        for clock in (CLOCK, CLOCK - 1):
            with self.subTest(clock=clock):
                refused = run(SCRIPT, "check-sequence", "--previous", first,
                              "--public-key", self.public_key, clock=clock)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn("refusing to publish", refused.stderr)
                second = self.site(f"second-{clock}")
                self.assertNotEqual(self.write(second, previous=first, clock=clock).returncode, 0)
                self.assertFalse((second / "preview" / "armv7" / "feed.json").exists())
        later = self.site("later")
        self.assertEqual(run(SCRIPT, "check-sequence", "--previous", first,
                             "--public-key", self.public_key, clock=CLOCK + 1).returncode, 0)
        self.assertEqual(self.write(later, previous=first, clock=CLOCK + 1).returncode, 0)
        self.assertEqual(json.loads((later / "stable" / "armv7" / "feed.json").read_text())["sequence"], CLOCK + 1)
        # A first publication has nothing to compare with.
        self.assertEqual(run(SCRIPT, "check-sequence", "--previous", self.empty,
                             "--public-key", self.public_key, clock=1).returncode, 0)

    def test_the_real_clock_is_used_without_the_test_variable(self):
        site = self.site("site")
        self.assertEqual(self.write(site, clock=None).returncode, 0)
        feed = json.loads((site / "preview" / "armv7" / "feed.json").read_text())
        self.assertGreater(feed["sequence"], CLOCK - 365 * 86400)
        self.assertRegex(feed["issued"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        for clock in ("soon", "-5", "1.5", "0"):
            with self.subTest(clock=clock):
                self.assertNotEqual(self.write(self.site(f"site-{clock}"), clock=clock).returncode, 0)

    def test_damaged_previous_metadata_is_never_mistaken_for_a_first_publication(self):
        def damaged(name, damage):
            site = self.published(name)
            damage(site)
            return site
        cases = {
            "signature removed": lambda site: (site / "preview/armv7/feed.json.sig").unlink(),
            "one channel removed": lambda site: [
                (site / "stable/armv7" / name).unlink() for name in ("feed.json", "feed.json.sig")],
            "sequence lowered": lambda site: (site / "preview/armv7/feed.json").write_text(
                (site / "preview/armv7/feed.json").read_text().replace(str(CLOCK), "1")),
            "other channel's pair": lambda site: [
                shutil.copy(site / "stable/armv7" / name, site / "preview/armv7" / name)
                for name in ("feed.json", "feed.json.sig")],
        }
        for number, (label, damage) in enumerate(cases.items()):
            with self.subTest(label):
                previous = damaged(f"previous-{number}", damage)
                result = run(SCRIPT, "check-sequence", "--previous", previous,
                             "--public-key", self.public_key, clock=CLOCK + WEEK)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("refusing to publish", result.stderr)

    def test_an_index_is_reused_only_for_exactly_the_package_set_it_was_signed_with(self):
        previous = self.published("previous", packages=(("denon", "0.2.1"), ("kodi", "0.1.0")))
        packages = self.root / "packages"
        shutil.copytree(previous / "preview" / "armv7", packages)
        nothing = self.root / "no-packages"
        nothing.mkdir()

        def reusable(channel, directory, site=previous):
            return run(SCRIPT, "reusable-index", "--previous", site, "--public-key", self.public_key,
                       "--channel", channel, "--packages", directory).returncode

        self.assertEqual(reusable("preview", packages), 0)
        self.assertEqual(reusable("stable", nothing), 0)
        self.assertEqual(reusable("preview", packages, site=self.empty), 10)
        self.assertEqual(reusable("stable", packages), 10)
        write_apk(packages, "sonos", "0.1.0")
        self.assertEqual(reusable("preview", packages), 10)
        (packages / "couch-integration-sonos-0.1.0-r0.apk").unlink()
        write_apk(packages, "kodi", "0.1.0", body=b"other bytes")
        self.assertEqual(reusable("preview", packages), 10)
        # A previous site that no longer matches its own signed metadata is an
        # error, not a reason to quietly build over it.
        with open(previous / "preview" / "armv7" / "APKINDEX.tar.gz", "ab") as index:
            index.write(b"x")
        self.assertEqual(reusable("preview", packages), 1)

    def test_verify_requires_metadata_that_describes_the_exact_bytes_beside_it(self):
        self.assertEqual(self.verify(self.published("good")).returncode, 0)
        self.assertIn("has no feed.json", self.verify(self.site("unsigned")).stderr)
        swapped = self.published("swapped")
        write_apk(swapped / "preview" / "armv7", "denon", "0.2.1", body=b"another binary")
        result = self.verify(swapped)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("packages are not the ones", result.stderr)
        replayed = self.published("replayed", packages=(("denon", "0.2.1"), ("kodi", "0.1.0")))
        write_index(replayed / "preview" / "armv7", ["couch-integration-denon-0.2.1-r0.apk"])
        self.assertNotEqual(self.verify(replayed).returncode, 0)
        other_key = self.root / "other.rsa.pub"
        with tempfile.NamedTemporaryFile() as private:
            subprocess.run(["openssl", "genrsa", "-out", private.name, "2048"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(other_key, "wb") as output:
                subprocess.run(["openssl", "pkey", "-in", private.name, "-pubout"], check=True, stdout=output)
        good = self.root / "good"
        self.assertNotEqual(run(SCRIPT, "verify", "--site", good, "--public-key", other_key).returncode, 0)


class ResignTests(Fixture):
    """scripts/resign.sh against a copy of this checkout that trusts the disposable key."""

    def setUp(self):
        super().setUp()
        self.checkout = self.root / "checkout"
        (self.checkout / "keys").mkdir(parents=True)
        shutil.copytree(REPOSITORY / "feed", self.checkout / "feed")
        (self.checkout / "scripts").mkdir()
        for name in ("feed_metadata.py", "resign.sh"):
            shutil.copy(REPOSITORY / "scripts" / name, self.checkout / "scripts" / name)
        shutil.copy(self.public_key, self.checkout / "keys" / "couch-integrations.rsa.pub")

    def complete_site(self, name):
        site = self.published(name, packages=(("denon", "0.2.1"), ("kodi", "0.1.0")))
        for channel in ("preview", "stable"):
            shutil.copy(self.public_key, site / channel / "couch-integrations.rsa.pub")
            (site / channel / "SOURCE_PINS.json").write_text('{"schema": 2}\n')
            (site / channel / "index.html").write_text("an older landing page\n")
        (site / "preview" / "armv7" / "couch-integration-denon-0.2.1-r0.provenance.json").write_text("{}\n")
        return site

    def resign(self, previous, out, clock, key=None):
        return run(self.checkout / "scripts" / "resign.sh", key or self.key, previous, out, clock=clock)

    def test_only_the_metadata_is_renewed(self):
        previous = self.complete_site("previous")
        out = self.root / "out"
        result = self.resign(previous, out, CLOCK + WEEK)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.verify(out).returncode, 0)
        renewed = []
        for path in sorted(item for item in previous.rglob("*") if item.is_file()):
            relative = path.relative_to(previous)
            if relative.name == "index.html":
                self.assertEqual((out / relative).read_bytes(), (REPOSITORY / "feed" / relative).read_bytes())
            elif (out / relative).read_bytes() != path.read_bytes():
                renewed.append(str(relative))
        self.assertEqual(renewed, [f"{channel}/armv7/{name}" for channel in ("preview", "stable")
                                   for name in ("feed.json", "feed.json.sig")])
        self.assertEqual(sorted(str(item.relative_to(out)) for item in out.rglob("*") if item.is_file()),
                         sorted(["index.html"] + [str(item.relative_to(previous))
                                                  for item in previous.rglob("*") if item.is_file()]))
        feed = json.loads((out / "preview" / "armv7" / "feed.json").read_text())
        self.assertEqual((feed["sequence"], feed["issued"], feed["expires"]),
                         (CLOCK + WEEK, "2026-09-28T14:13:20Z", "2026-10-28T14:13:20Z"))

    def test_nothing_is_signed_unless_the_previous_site_is_vouched_for_and_older(self):
        previous = self.complete_site("previous")
        unsigned = self.site("unsigned")
        swapped = self.complete_site("swapped")
        write_apk(swapped / "preview" / "armv7", "kodi", "0.1.0", body=b"another binary")
        other_key = self.root / "other.rsa"
        subprocess.run(["openssl", "genrsa", "-out", str(other_key), "2048"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cases = {
            "same sequence": (previous, CLOCK, None, "refusing to publish"),
            "no metadata": (unsigned, CLOCK + WEEK, None, "Publish it in full instead"),
            "swapped package": (swapped, CLOCK + WEEK, None, "Publish it in full instead"),
            "wrong private key": (previous, CLOCK + WEEK, other_key, "does not match"),
        }
        for number, (label, (site, clock, key, message)) in enumerate(cases.items()):
            with self.subTest(label):
                out = self.root / f"out-{number}"
                result = self.resign(site, out, clock, key)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(out.exists())


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (REPOSITORY / ".github/workflows/publish.yml").read_text(encoding="utf-8")

    def test_the_feed_is_signed_again_every_week(self):
        schedule = re.search(r"^  schedule:\n    - cron: '(\S+ \S+) \* \* (\d)'$", self.workflow, re.MULTILINE)
        self.assertIsNotNone(schedule)
        self.assertIn("github.event_name == 'schedule' ||", self.workflow)
        # 30 days of validity must outlast several missed weekly runs.
        module = (REPOSITORY / "scripts/feed_metadata.py").read_text(encoding="utf-8")
        self.assertIn("VALIDITY_SECONDS = 30 * 24 * 60 * 60", module)

    def test_a_re_signing_needs_no_admission_run_but_a_full_publication_still_does(self):
        full = "        if: needs.decide.outputs.mode == 'full'\n"
        for step in (
            "      - name: Require a successful admission run for this exact main commit\n",
            "      - uses: actions/download-artifact@v4\n",
            "      - name: Check out every exact approved source pin\n",
            "      - name: Build signed indexes from the reviewed payload artifact\n",
        ):
            self.assertIn(step + full, self.workflow)
        self.assertIn("      - name: Re-sign the published feed without changing a package or an index\n"
                      "        if: needs.decide.outputs.mode == 'resign'\n", self.workflow)
        self.assertEqual(self.workflow.count("scripts/resign.sh \"$RUNNER_TEMP/couch-integrations.rsa\""), 1)
        # Both routes stay inside the one protected signing job on main.
        self.assertEqual(self.workflow.count("environment: package-signing"), 1)
        self.assertEqual(self.workflow.count("secrets.APK_SIGNING_KEY"), 1)
        self.assertIn("if: github.ref == 'refs/heads/main' && needs.decide.outputs.publish == 'true'", self.workflow)

    def test_the_archive_carries_both_channels_and_the_newest_one_is_restored(self):
        self.assertIn('couch-integrations-preview-armv7.tar.gz" preview stable\n', self.workflow)
        self.assertIn('startswith("feed-") or startswith("resigned-") or startswith("integration-")', self.workflow)
        # decide must keep reading only full feed releases as "inputs published".
        decide = self.workflow[self.workflow.index("  decide:"):self.workflow.index("  sign:")]
        self.assertNotIn("resigned-", decide)
        for script in ("scripts/publish.sh", "scripts/feed_metadata.py", "scripts/resign.sh"):
            self.assertIn(script, decide)


if __name__ == "__main__":
    unittest.main()
