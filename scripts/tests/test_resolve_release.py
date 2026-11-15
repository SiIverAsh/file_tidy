"""Exercise release version resolution using independent temporary manifests."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "resolve_release.py"
SPEC = importlib.util.spec_from_file_location("resolve_release", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
resolve_release = MODULE.resolve_release


class ResolveReleaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.write_release("0.2.1")

    def write_json(self, relative, document):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document), encoding="utf-8")

    def update_json(self, relative, update):
        document = json.loads((self.root / relative).read_text(encoding="utf-8"))
        update(document)
        self.write_json(relative, document)

    def write_release(self, version):
        (self.root / "Cargo.toml").write_text(
            '[workspace.package]\nversion = ' + json.dumps(version) + '\n'
            '[workspace.dependencies]\n'
            'file-tidy-core = { version = ' + json.dumps(version) + ', path = "crates/core" }\n'
            'file-tidy-platform = { version = ' + json.dumps(version) + ', path = "crates/platform" }\n',
            encoding="utf-8",
        )
        (self.root / "Cargo.lock").write_text(
            "version = 4\n" + "".join(
                '[[package]]\nname = ' + json.dumps(name) + '\nversion = ' + json.dumps(version) + '\n'
                for name in ("file-tidy-cli", "file-tidy-core", "file-tidy-gui", "file-tidy-platform")
            ),
            encoding="utf-8",
        )
        self.write_json("crates/gui/src-tauri/tauri.conf.json", {"version": version, "bundle": {"active": True}})
        self.write_json("crates/gui/package.json", {"version": version})
        self.write_json("crates/gui/package-lock.json", {"version": version, "packages": {"": {"version": version}}})

    def run_cli(self, *args, **kwargs):
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--root", str(self.root), *args],
            capture_output=True, text=True, **kwargs,
        )

    def test_tag_is_derived_from_manifest_without_a_tag_input(self):
        self.assertEqual(resolve_release(self.root), ("v0.2.1", "0.2.1"))
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Release v0.2.1", result.stdout)

    def test_each_gui_version_must_match_the_cargo_version(self):
        for relative in (
            "crates/gui/src-tauri/tauri.conf.json",
            "crates/gui/package.json",
            "crates/gui/package-lock.json",
        ):
            with self.subTest(relative=relative):
                self.write_release("0.2.1")
                self.update_json(relative, lambda value: value.update(version="0.1.0"))
                with self.assertRaises(ValueError) as failure:
                    resolve_release(self.root)
                self.assertIn(relative, str(failure.exception))
                self.assertIn("expected '0.2.1'", str(failure.exception))

    def test_package_lock_root_version_is_checked_independently(self):
        self.update_json(
            "crates/gui/package-lock.json",
            lambda value: value["packages"][""].update(version="0.1.0"),
        )
        with self.assertRaisesRegex(ValueError, r"package-lock.json packages\[root\].*expected '0.2.1'"):
            resolve_release(self.root)

    def test_missing_gui_sources_fail_with_the_filename(self):
        path = self.root / "crates/gui/src-tauri/tauri.conf.json"
        path.unlink()
        with self.assertRaisesRegex(ValueError, "tauri.conf.json: required release source is missing"):
            resolve_release(self.root)

    def test_gui_bundling_must_be_explicitly_enabled(self):
        for active in (False, None, 1, "true"):
            with self.subTest(active=active):
                self.write_json("crates/gui/src-tauri/tauri.conf.json", {"version": "0.2.1", "bundle": {"active": active}})
                with self.assertRaisesRegex(ValueError, "bundle.active to be true"):
                    resolve_release(self.root)

    def test_internal_path_dependency_versions_are_checked(self):
        path = self.root / "Cargo.toml"
        path.write_text(path.read_text(encoding="utf-8").replace(
            'file-tidy-core = { version = "0.2.1"', 'file-tidy-core = { version = "0.1.0"'
        ), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Cargo.toml workspace.dependencies.file-tidy-core.*expected '0.2.1'"):
            resolve_release(self.root)

    def test_each_local_workspace_package_in_cargo_lock_is_checked(self):
        path = self.root / "Cargo.lock"
        for name in ("file-tidy-cli", "file-tidy-core", "file-tidy-gui", "file-tidy-platform"):
            with self.subTest(name=name):
                self.write_release("0.2.1")
                path.write_text(path.read_text(encoding="utf-8").replace(
                    f'name = "{name}"\nversion = "0.2.1"',
                    f'name = "{name}"\nversion = "0.1.0"',
                ), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, f"Cargo.lock package {name}.*expected '0.2.1'"):
                    resolve_release(self.root)

    def test_unrelated_locked_dependency_versions_are_not_release_versions(self):
        path = self.root / "Cargo.lock"
        with path.open("a", encoding="utf-8") as output:
            output.write('[[package]]\nname = "serde"\nversion = "1.0.0"\n')
            output.write('[[package]]\nname = "file-tidy-external"\nversion = "1.0.0"\nsource = "registry+https://example.com"\n')
        self.assertEqual(resolve_release(self.root), ("v0.2.1", "0.2.1"))

    def test_missing_workspace_package_in_lock_is_rejected(self):
        path = self.root / "Cargo.lock"
        path.write_text(path.read_text(encoding="utf-8").replace(
            '[[package]]\nname = "file-tidy-gui"\nversion = "0.2.1"\n', ""
        ), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Cargo.lock: missing local workspace packages: file-tidy-gui"):
            resolve_release(self.root)

    def test_invalid_semver_and_output_injection_are_rejected(self):
        for version in (
            "v0.2.1", "0.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01",
            "1.2.3-alpha.01", "1.2.3-", "1.2.3+", "1.2.3-a..b", "1.2.3+a..b",
            "1.2.3\ntag=v9.0.0", "1.2.3 ", "１.2.3",
        ):
            with self.subTest(version=version):
                self.write_release(version)
                with self.assertRaisesRegex(ValueError, "Cargo.toml workspace.package.version: expected a strict SemVer"):
                    resolve_release(self.root)

    def test_prerelease_and_build_metadata_are_preserved(self):
        for version in ("0.2.1-rc.1", "1.2.3+build.001", "1.2.3-alpha.0+sha.ab12", "1.2.3-0A.0-1"):
            with self.subTest(version=version):
                self.write_release(version)
                self.assertEqual(resolve_release(self.root), (f"v{version}", version))

    def test_github_output_is_explicit_appended_and_uses_step_output_protocol(self):
        output = self.root / "step-output"
        output.write_text("existing=value\n", encoding="utf-8")
        result = self.run_cli("--github-output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), "existing=value\ntag=v0.2.1\nversion=0.2.1\n")

    def test_environment_output_is_not_written_without_the_explicit_argument(self):
        output = self.root / "unexpected-output"
        result = self.run_cli(env=dict(os.environ, GITHUB_OUTPUT=str(output), RELEASE_TAG="v9.9.9"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Release v0.2.1", result.stdout)
        self.assertFalse(output.exists())

    def test_failed_validation_does_not_append_outputs(self):
        self.update_json("crates/gui/package.json", lambda value: value.update(version="0.1.0"))
        output = self.root / "step-output"
        result = self.run_cli("--github-output", str(output))
        self.assertEqual(result.returncode, 1)
        self.assertIn("crates/gui/package.json", result.stderr)
        self.assertIn("expected '0.2.1'", result.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
