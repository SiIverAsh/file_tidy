"""Verify release installer discovery, naming, and non-overwriting behavior."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "collect_gui_artifacts.py"
SPEC = importlib.util.spec_from_file_location("collect_gui_artifacts", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
collect_artifact = MODULE.collect_artifact


class CollectGuiArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.output = self.root / "artifacts"

    def installer(self, kind, filename="File Tidy installer", content=b"installer payload"):
        directory = self.bundle / kind
        directory.mkdir(exist_ok=True)
        source = directory / filename
        source.write_bytes(content)
        return source

    def test_collects_each_target_with_standard_name_and_checksum(self):
        cases = [
            ("aarch64-apple-darwin", "dmg", "File Tidy_0.2.0_aarch64.dmg", ".dmg"),
            ("x86_64-apple-darwin", "dmg", "File Tidy_0.2.0_x64.dmg", ".dmg"),
            ("x86_64-pc-windows-msvc", "nsis", "File Tidy_0.2.0_x64-setup.exe", "-setup.exe"),
            ("x86_64-unknown-linux-gnu", "deb", "File Tidy_0.2.0_amd64.deb", ".deb"),
        ]
        for target, kind, source_name, suffix in cases:
            with self.subTest(target=target):
                source = self.installer(kind, source_name)
                expected = f"file-tidy-gui-0.2.0-{target}{suffix}"
                destination = collect_artifact(self.bundle, self.output, target, "0.2.0")
                self.assertEqual(destination.name, expected)
                self.assertEqual(destination.read_bytes(), source.read_bytes())
                checksum = destination.with_name(destination.name + ".sha256")
                expected_digest = hashlib.sha256(source.read_bytes()).hexdigest()
                self.assertEqual(checksum.read_bytes(), f"{expected_digest}  {expected}\n".encode())
                self.assertTrue(source.exists())
                source.unlink()

    def test_missing_or_multiple_installers_fail(self):
        target = "aarch64-apple-darwin"
        with self.assertRaisesRegex(ValueError, "found 0"):
            collect_artifact(self.bundle, self.output, target, "0.2.0")
        self.installer("dmg", "one.dmg")
        self.installer("dmg", "two.dmg")
        with self.assertRaisesRegex(ValueError, "found 2"):
            collect_artifact(self.bundle, self.output, target, "0.2.0")
        self.assertFalse(self.output.exists())

    def test_windows_only_collects_nsis_installers(self):
        self.installer("debug", "file-tidy-gui.exe", b"debug executable")
        self.installer("msi", "other.exe", b"not NSIS")
        self.installer("nsis", "File Tidy_setup.exe", b"NSIS installer")
        destination = collect_artifact(
            self.bundle, self.output, "x86_64-pc-windows-msvc", "0.2.0"
        )
        self.assertEqual(destination.read_bytes(), b"NSIS installer")
        self.assertEqual(len(list(self.output.iterdir())), 2)

    def test_app_directory_is_not_a_dmg_installer(self):
        app = self.bundle / "macos" / "File Tidy.app"
        app.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "found 0"):
            collect_artifact(self.bundle, self.output, "aarch64-apple-darwin", "0.2.0")

    def test_refuses_existing_installer_or_checksum_without_overwriting(self):
        self.installer("deb", "app.deb")
        name = "file-tidy-gui-0.2.0-x86_64-unknown-linux-gnu.deb"
        self.output.mkdir()
        for filename in (name, name + ".sha256"):
            with self.subTest(filename=filename):
                occupied = self.output / filename
                occupied.write_bytes(b"existing asset")
                with self.assertRaises(FileExistsError):
                    collect_artifact(self.bundle, self.output, "x86_64-unknown-linux-gnu", "0.2.0")
                self.assertEqual(occupied.read_bytes(), b"existing asset")
                self.assertEqual(len(list(self.output.iterdir())), 1)
                occupied.unlink()

    def test_refuses_output_inside_bundle_tree(self):
        source = self.installer("dmg", "app.dmg")
        for output in (self.bundle, self.bundle / "dmg"):
            with self.subTest(output=output):
                with self.assertRaisesRegex(ValueError, "outside"):
                    collect_artifact(self.bundle, output, "aarch64-apple-darwin", "0.2.0")
        self.assertEqual(source.read_bytes(), b"installer payload")

    def test_rejects_versions_that_could_change_output_paths(self):
        self.installer("dmg", "app.dmg")
        for version in ("v0.2.0", "../0.2.0", "0.2.0/next", "0.2.0\nnext", "0.2.0 next"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ValueError, "version"):
                    collect_artifact(self.bundle, self.output, "aarch64-apple-darwin", version)
        self.assertFalse(self.output.exists())

    def test_prerelease_and_build_metadata_are_preserved(self):
        self.installer("dmg", "app.dmg")
        destination = collect_artifact(
            self.bundle, self.output, "aarch64-apple-darwin", "0.2.0-rc.1+build.3"
        )
        self.assertEqual(
            destination.name,
            "file-tidy-gui-0.2.0-rc.1+build.3-aarch64-apple-darwin.dmg",
        )


if __name__ == "__main__":
    unittest.main()
