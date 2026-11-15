"""Exercise synchronized release increments in independent temporary checkouts."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "bump_release_version.py"
SPEC = importlib.util.spec_from_file_location("bump_release_version", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
with patch.object(sys, "path", [str(SCRIPT_PATH.parent), *sys.path]):
    SPEC.loader.exec_module(MODULE)


class BumpReleaseVersionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.write_release()

    def write_release(self, version="1.2.3", newline="\n"):
        documents = {
            "Cargo.toml": (
                '# Release metadata\n[workspace.package]\n'
                f'version  = "{version}" # keep this comment\n'
                '[workspace.dependencies]\n'
                f'file-tidy-core = {{ version = "{version}", path = "crates/core" }}\n'
                f'file-tidy-platform = {{ path = "crates/platform", version = \'{version}\' }}\n'
                f'serde = {{ version = "{version}", features = ["derive"] }}\n'
                '[workspace.metadata]\n'
                f'note = "{version}"\n'
            ),
            "Cargo.lock": (
                '# Locked packages\nversion = 4\n\n'
                + "\n".join(
                    f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
                    for name in ("file-tidy-cli", "file-tidy-core", "file-tidy-gui", "file-tidy-platform")
                )
                + '\n[[package]]\nname = "serde"\n'
                f'version = "{version}"\nsource = "registry+https://example.com"\nchecksum = "unchanged"\n'
                '\n[[package]]\nname = "file-tidy-external"\n'
                f'version = "{version}"\nsource = "registry+https://example.com"\nchecksum = "unchanged-too"\n'
            ),
            "crates/gui/package.json": (
                '{\n  "name" : "file-tidy-gui",\n'
                f'  "version" : "{version}",\n  "description": "{version}"\n}}\n'
            ),
            "crates/gui/package-lock.json": (
                '{\n  "lockfileVersion": 3,\n'
                f'  "version": "{version}",\n'
                '  "packages": {\n'
                f'    "": {{ "version": "{version}", "note": "{version}" }},\n'
                f'    "node_modules/example": {{ "version": "{version}" }}\n'
                '  }\n}\n'
            ),
            "crates/gui/src-tauri/tauri.conf.json": (
                '{\n\t"bundle": { "active": true },\n'
                f'\t"version": "{version}",\n\t"productName": "{version}"\n}}\n'
            ),
        }
        for relative, text in documents.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(text.replace("\n", newline).encode("utf-8"))

    def snapshot(self):
        return {relative: (self.root / relative).read_bytes() for relative in MODULE.RELEASE_FILES}

    def read_json(self, relative):
        return json.loads((self.root / relative).read_bytes())

    def run_cli(self, *args, **kwargs):
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--root", str(self.root), *args],
            capture_output=True, text=True, **kwargs,
        )

    def test_major_minor_and_patch_reset_the_lower_components(self):
        for bump, version in (("major", "2.0.0"), ("minor", "1.3.0"), ("patch", "1.2.4")):
            with self.subTest(bump=bump):
                self.write_release()
                self.assertEqual(MODULE.bump_release_version(self.root, bump), ("1.2.3", version, f"v{version}"))
                self.assertEqual(MODULE.resolve_release(self.root), (f"v{version}", version))

    def test_all_project_versions_change_and_unrelated_data_stays_identical(self):
        unrelated = self.root / "notes.txt"
        unrelated.write_text("1.2.3", encoding="utf-8")
        MODULE.bump_release_version(self.root, "minor")
        cargo = tomllib.loads((self.root / "Cargo.toml").read_text())
        self.assertEqual(cargo["workspace"]["package"]["version"], "1.3.0")
        for name in ("file-tidy-core", "file-tidy-platform"):
            self.assertEqual(cargo["workspace"]["dependencies"][name]["version"], "1.3.0")
        self.assertEqual(cargo["workspace"]["dependencies"]["serde"], {"version": "1.2.3", "features": ["derive"]})
        self.assertEqual(cargo["workspace"]["metadata"]["note"], "1.2.3")
        packages = tomllib.loads((self.root / "Cargo.lock").read_text())["package"]
        self.assertEqual([package["version"] for package in packages[:4]], ["1.3.0"] * 4)
        self.assertEqual(packages[4], {"name": "serde", "version": "1.2.3", "source": "registry+https://example.com", "checksum": "unchanged"})
        self.assertEqual(packages[5]["version"], "1.2.3")
        self.assertEqual(packages[5]["checksum"], "unchanged-too")
        gui = self.read_json("crates/gui/package.json")
        self.assertEqual(gui["version"], "1.3.0")
        self.assertEqual(gui["description"], "1.2.3")
        lock = self.read_json("crates/gui/package-lock.json")
        self.assertEqual(lock["version"], "1.3.0")
        self.assertEqual(lock["packages"][""]["version"], "1.3.0")
        self.assertEqual(lock["packages"][""]["note"], "1.2.3")
        self.assertEqual(lock["packages"]["node_modules/example"]["version"], "1.2.3")
        tauri = self.read_json("crates/gui/src-tauri/tauri.conf.json")
        self.assertEqual(tauri["version"], "1.3.0")
        self.assertEqual(tauri["productName"], "1.2.3")
        self.assertEqual(unrelated.read_text(), "1.2.3")

    def test_comments_quotes_whitespace_key_order_and_line_endings_are_preserved(self):
        self.write_release(newline="\r\n")
        originals = self.snapshot()
        MODULE.bump_release_version(self.root, "patch")
        actual = self.snapshot()
        expected_cargo = originals["Cargo.toml"].replace(b'version  = "1.2.3"', b'version  = "1.2.4"').replace(
            b'file-tidy-core = { version = "1.2.3"', b'file-tidy-core = { version = "1.2.4"'
        ).replace(b"path = \"crates/platform\", version = '1.2.3'", b"path = \"crates/platform\", version = '1.2.4'")
        self.assertEqual(actual["Cargo.toml"], expected_cargo)
        expected_lock = originals["Cargo.lock"]
        for name in ("file-tidy-cli", "file-tidy-core", "file-tidy-gui", "file-tidy-platform"):
            expected_lock = expected_lock.replace(
                f'name = "{name}"\r\nversion = "1.2.3"'.encode(),
                f'name = "{name}"\r\nversion = "1.2.4"'.encode(),
            )
        self.assertEqual(actual["Cargo.lock"], expected_lock)
        self.assertEqual(actual["crates/gui/package.json"], originals["crates/gui/package.json"].replace(
            b'"version" : "1.2.3"', b'"version" : "1.2.4"'
        ))
        self.assertEqual(actual["crates/gui/package-lock.json"], originals["crates/gui/package-lock.json"].replace(
            b'"version": "1.2.3"', b'"version": "1.2.4"', 2
        ))
        self.assertEqual(actual["crates/gui/src-tauri/tauri.conf.json"], originals["crates/gui/src-tauri/tauri.conf.json"].replace(
            b'"version": "1.2.3"', b'"version": "1.2.4"'
        ))

    def test_prerelease_and_build_metadata_are_removed_before_increment(self):
        for bump, version in (("major", "2.0.0"), ("minor", "1.3.0"), ("patch", "1.2.4")):
            with self.subTest(bump=bump):
                previous = "1.2.3-rc.2+build.7"
                self.write_release(previous)
                self.assertEqual(MODULE.bump_release_version(self.root, bump), (previous, version, f"v{version}"))

    def test_internal_dependency_tables_are_supported(self):
        path = self.root / "Cargo.toml"
        text = path.read_text().replace(
            'file-tidy-core = { version = "1.2.3", path = "crates/core" }\n', ""
        )
        text += '\n[workspace.dependencies.file-tidy-core]\npath = "crates/core"\nversion = "1.2.3" # table version\n'
        path.write_text(text)
        self.assertEqual(MODULE.bump_release_version(self.root, "patch"), ("1.2.3", "1.2.4", "v1.2.4"))
        self.assertIn('version = "1.2.4" # table version', path.read_text())

    def test_invalid_bump_never_changes_the_checkout(self):
        originals = self.snapshot()
        with self.assertRaisesRegex(ValueError, "bump must be"):
            MODULE.bump_release_version(self.root, "automatic")
        self.assertEqual(self.snapshot(), originals)

    def test_inconsistent_input_does_not_partially_write_or_emit_outputs(self):
        path = self.root / "crates/gui/package.json"
        path.write_text(path.read_text().replace('"version" : "1.2.3"', '"version" : "0.1.0"'))
        originals = self.snapshot()
        output = self.root / "step-output"
        result = self.run_cli("--bump", "patch", "--github-output", str(output))
        self.assertEqual(result.returncode, 1)
        self.assertIn("package.json", result.stderr)
        self.assertEqual(self.snapshot(), originals)
        self.assertFalse(output.exists())

    def test_generation_failure_is_detected_before_any_manifest_is_written(self):
        path = self.root / "crates/gui/package.json"
        path.write_text('{"version": "1.2.3", "version": "1.2.3"}')
        originals = self.snapshot()
        with self.assertRaisesRegex(ValueError, "exactly one JSON member"):
            MODULE.bump_release_version(self.root, "patch")
        self.assertEqual(self.snapshot(), originals)

    def test_github_outputs_append_the_previous_version_new_version_and_tag(self):
        output = self.root / "step-output"
        output.write_text("existing=value\n")
        result = self.run_cli("--bump", "minor", "--github-output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), "existing=value\nprevious_version=1.2.3\nversion=1.3.0\ntag=v1.3.0\n")
        self.assertIn("1.2.3 -> 1.3.0", result.stdout)

    def test_bump_is_required_and_environment_outputs_are_not_implicit(self):
        originals = self.snapshot()
        missing = self.run_cli()
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(self.snapshot(), originals)
        output = self.root / "unexpected-output"
        result = self.run_cli("--bump", "patch", env=dict(os.environ, GITHUB_OUTPUT=str(output)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
