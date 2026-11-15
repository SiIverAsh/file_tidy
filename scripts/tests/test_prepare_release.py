"""Verify automatic release preparation against temporary local Git remotes."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "prepare_release.py"
SPEC = importlib.util.spec_from_file_location("prepare_release", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(SCRIPT_PATH.parent))
try:
    SPEC.loader.exec_module(MODULE)
finally:
    sys.path.pop(0)


def run_git(root, *args, input=None):
    result = subprocess.run(
        ["git", *args], cwd=root, input=input,
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def write_manifests(root, version="0.2.1"):
    (root / "Cargo.toml").write_text(
        f'[workspace.package]\nversion = "{version}"\n'
        '[workspace.dependencies]\n'
        f'file-tidy-core = {{ version = "{version}", path = "crates/core" }}\n'
        f'file-tidy-platform = {{ version = "{version}", path = "crates/platform" }}\n',
        encoding="utf-8",
    )
    (root / "Cargo.lock").write_text(
        "version = 4\n" + "".join(
            f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
            for name in ("file-tidy-cli", "file-tidy-core", "file-tidy-gui", "file-tidy-platform")
        ),
        encoding="utf-8",
    )
    documents = {
        "crates/gui/package.json": {"version": version},
        "crates/gui/package-lock.json": {"version": version, "packages": {"": {"version": version}}},
        "crates/gui/src-tauri/tauri.conf.json": {"version": version, "bundle": {"active": True}},
    }
    for relative, document in documents.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


class PrepareReleaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.remote = self.directory / "origin.git"
        self.root = self.directory / "checkout"
        self.root.mkdir()
        run_git(self.directory, "init", "--bare", str(self.remote))
        run_git(self.root, "init", "--initial-branch=main")
        # All settings belong to this temporary repository, never the user's config.
        run_git(self.root, "config", "user.name", "Release Test")
        run_git(self.root, "config", "user.email", "release-test@example.invalid")
        run_git(self.root, "config", "commit.gpgsign", "false")
        run_git(self.root, "config", "core.autocrlf", "false")
        run_git(self.root, "remote", "add", "origin", str(self.remote))
        write_manifests(self.root)
        (self.root / "code.txt").write_text("original code\n", encoding="utf-8")
        run_git(self.root, "add", ".")
        run_git(self.root, "commit", "--message", "Initial source")
        self.source = run_git(self.root, "rev-parse", "HEAD")
        run_git(self.root, "push", "origin", "HEAD:refs/heads/main")

    def prepare(self, bump="patch", run_id="1001", source=None):
        return MODULE.prepare_release(self.root, bump, "main", source or self.source, run_id)

    def rewind_checkout(self):
        run_git(self.root, "checkout", "--detach", self.source)

    def remote_head(self):
        return run_git(self.remote, "rev-parse", "refs/heads/main")

    def assert_release(self, bump, version):
        release = self.prepare(bump)
        self.assertEqual(release["previous_version"], "0.2.1")
        self.assertEqual(release["version"], version)
        self.assertEqual(release["tag"], f"v{version}")
        self.assertEqual(release["commit"], self.remote_head())
        self.assertEqual(run_git(self.root, "rev-parse", "HEAD^"), self.source)
        changed = set(run_git(self.root, "diff", "--name-only", self.source, "HEAD").splitlines())
        self.assertEqual(changed, set(MODULE.RELEASE_FILES))
        self.assertEqual((self.root / "code.txt").read_text(encoding="utf-8"), "original code\n")
        self.assertEqual(run_git(self.root, "status", "--porcelain"), "")
        self.assertEqual(run_git(self.remote, "tag", "--list"), "")

    def test_patch_is_committed_pushed_and_synchronizes_only_version_files(self):
        self.assert_release("patch", "0.2.2")

    def test_minor_resets_patch(self):
        self.assert_release("minor", "0.3.0")

    def test_major_resets_minor_and_patch(self):
        self.assert_release("major", "1.0.0")

    def test_rerun_reuses_the_run_commit_without_pushing_or_incrementing(self):
        first = self.prepare()
        self.rewind_checkout()
        with patch.object(MODULE, "git", wraps=MODULE.git) as git:
            second = self.prepare()
        self.assertEqual(first, second)
        self.assertFalse(any(call.args[1] == "push" for call in git.call_args_list))
        self.assertEqual(run_git(self.remote, "rev-list", "--count", "refs/heads/main"), "2")
        self.assertEqual(run_git(self.root, "status", "--porcelain"), "")

    def test_rerun_keeps_the_fixed_release_sha_after_main_advances(self):
        first = self.prepare()
        (self.root / "code.txt").write_text("newer code\n", encoding="utf-8")
        run_git(self.root, "add", "code.txt")
        run_git(self.root, "commit", "--message", "Unrelated later change")
        run_git(self.root, "push", "origin", "HEAD:refs/heads/main")
        advanced = self.remote_head()
        self.rewind_checkout()
        second = self.prepare()
        self.assertEqual(second, first)
        self.assertNotEqual(second["commit"], advanced)
        self.assertEqual(self.remote_head(), advanced)

    def test_different_run_on_stale_source_fails_before_touching_manifests(self):
        self.prepare()
        self.rewind_checkout()
        before = (self.root / "Cargo.toml").read_bytes()
        with self.assertRaisesRegex(ValueError, "main has advanced"):
            self.prepare(run_id="1002")
        self.assertEqual((self.root / "Cargo.toml").read_bytes(), before)
        self.assertEqual(run_git(self.root, "status", "--porcelain"), "")

    def test_run_marker_with_wrong_version_tree_is_rejected(self):
        write_manifests(self.root, "0.2.9")
        run_git(self.root, "add", "--", *MODULE.RELEASE_FILES)
        run_git(self.root, "commit", "--message", MODULE.release_message("v0.2.2", "1001", "patch"))
        run_git(self.root, "push", "origin", "HEAD:refs/heads/main")
        self.rewind_checkout()
        with self.assertRaisesRegex(ValueError, "tree does not match"):
            self.prepare()
        self.assertEqual(run_git(self.root, "status", "--porcelain"), "")

    def test_run_marker_that_changes_code_is_rejected(self):
        (self.root / "code.txt").write_text("injected code\n", encoding="utf-8")
        run_git(self.root, "add", "code.txt")
        run_git(self.root, "commit", "--message", MODULE.release_message("v0.2.2", "1001", "patch"))
        run_git(self.root, "push", "origin", "HEAD:refs/heads/main")
        self.rewind_checkout()
        with self.assertRaisesRegex(ValueError, "outside the version files: code.txt"):
            self.prepare()

    def test_run_marker_with_the_wrong_parent_is_rejected(self):
        run_git(self.root, "commit", "--allow-empty", "--message", "Intermediate commit")
        run_git(self.root, "commit", "--allow-empty", "--message", MODULE.release_message("v0.2.2", "1001", "patch"))
        run_git(self.root, "push", "origin", "HEAD:refs/heads/main")
        self.rewind_checkout()
        with self.assertRaisesRegex(ValueError, "exactly the original source commit as its parent"):
            self.prepare()

    def test_multiple_matching_run_commits_are_rejected(self):
        self.prepare()
        run_git(self.root, "commit", "--allow-empty", "--message", MODULE.release_message("v0.2.2", "1001", "patch"))
        run_git(self.root, "push", "origin", "HEAD:refs/heads/main")
        self.rewind_checkout()
        with self.assertRaisesRegex(ValueError, "multiple commits for this release run"):
            self.prepare()

    def test_rerun_cannot_change_the_selected_increment(self):
        self.prepare()
        self.rewind_checkout()
        with self.assertRaisesRegex(ValueError, "message or requested bump does not match"):
            self.prepare("minor")

    def test_dirty_tracked_source_is_rejected(self):
        (self.root / "code.txt").write_text("uncommitted changes\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "checkout has tracked changes"):
            self.prepare()
        self.assertEqual(self.remote_head(), self.source)

    def test_untracked_files_are_not_included_in_the_release_commit(self):
        (self.root / "scratch.txt").write_text("local notes\n", encoding="utf-8")
        self.prepare()
        self.assertEqual(run_git(self.root, "ls-tree", "HEAD", "scratch.txt"), "")
        self.assertTrue((self.root / "scratch.txt").is_file())

    def test_incorrect_checkout_head_is_rejected(self):
        run_git(self.root, "commit", "--allow-empty", "--message", "Different checkout")
        with self.assertRaisesRegex(ValueError, "HEAD does not match"):
            self.prepare()
        self.assertEqual(self.remote_head(), self.source)

    def test_source_file_line_endings_are_preserved(self):
        for relative in MODULE.RELEASE_FILES:
            path = self.root / relative
            path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        run_git(self.root, "add", "--", *MODULE.RELEASE_FILES)
        run_git(self.root, "commit", "--message", "Use CRLF manifests")
        self.source = run_git(self.root, "rev-parse", "HEAD")
        run_git(self.root, "push", "origin", "HEAD:refs/heads/main")
        self.prepare()
        for relative in MODULE.RELEASE_FILES:
            with self.subTest(relative=relative):
                contents = (self.root / relative).read_bytes()
                self.assertIn(b"\r\n", contents)
                self.assertNotIn(b"\n", contents.replace(b"\r\n", b""))

    def test_retry_recovers_when_push_succeeded_but_its_response_was_lost(self):
        real_git = MODULE.git

        def lose_push_response(root, *args, **kwargs):
            result = real_git(root, *args, **kwargs)
            if args[0] == "push":
                raise ValueError("git push failed: connection closed before response")
            return result

        with patch.object(MODULE, "git", side_effect=lose_push_response):
            with self.assertRaisesRegex(ValueError, "connection closed before response"):
                self.prepare()
        pushed = self.remote_head()
        self.assertNotEqual(pushed, self.source)
        self.rewind_checkout()
        recovered = self.prepare()
        self.assertEqual(recovered["commit"], pushed)
        self.assertEqual(recovered["version"], "0.2.2")
        self.assertEqual(run_git(self.remote, "rev-list", "--count", "refs/heads/main"), "2")

    def test_concurrent_main_update_rejects_regular_push_without_overwriting(self):
        real_git = MODULE.git
        raced_commit = []

        def update_before_push(root, *args, **kwargs):
            if args[0] == "push":
                tree = run_git(self.remote, "rev-parse", f"{self.source}^{{tree}}")
                concurrent = run_git(
                    self.remote, "-c", "user.name=Concurrent Test", "-c",
                    "user.email=concurrent@example.invalid", "commit-tree", tree,
                    "-p", self.source, input="Concurrent main update\n",
                )
                run_git(self.remote, "update-ref", "refs/heads/main", concurrent, self.source)
                raced_commit.append(concurrent)
            return real_git(root, *args, **kwargs)

        with patch.object(MODULE, "git", side_effect=update_before_push):
            with self.assertRaisesRegex(ValueError, r"git push failed:.*|git push failed:") as failure:
                self.prepare()
        self.assertRegex(str(failure.exception), r"fetch first|non-fast-forward|rejected")
        self.assertEqual(self.remote_head(), raced_commit[0])

    def test_cli_outputs_the_fixed_sha_and_versions_after_push(self):
        output = self.directory / "github-output"
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT_PATH), "--root", str(self.root),
                "--bump", "patch", "--branch", "main", "--source-commit", self.source,
                "--run-id", "1001", "--github-output", str(output),
            ],
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            output.read_text(encoding="utf-8"),
            f"commit={self.remote_head()}\nprevious_version=0.2.1\nversion=0.2.2\ntag=v0.2.2\n",
        )

    def test_failed_preparation_does_not_write_step_outputs(self):
        (self.root / "code.txt").write_text("dirty\n", encoding="utf-8")
        output = self.directory / "github-output"
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT_PATH), "--root", str(self.root),
                "--bump", "patch", "--branch", "main", "--source-commit", self.source,
                "--run-id", "1001", "--github-output", str(output),
            ],
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("tracked changes", result.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
