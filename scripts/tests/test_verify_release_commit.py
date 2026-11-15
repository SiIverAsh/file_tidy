"""Verify the immutable release commit guard without making network requests."""

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "verify_release_commit.py"
SPEC = importlib.util.spec_from_file_location("verify_release_commit", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
verify_release_commit = MODULE.verify_release_commit
ensure_release_tag = MODULE.ensure_release_tag

REPOSITORY = "SiIverAsh/file_tidy"
COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40
TAG_SHA = "c" * 40
NESTED_TAG_SHA = "d" * 40
REFERENCE = f"repos/{REPOSITORY}/git/ref/tags/v0.2.0"


def target(kind, sha):
    return {"object": {"type": kind, "sha": sha}}


class VerifyReleaseCommitTests(unittest.TestCase):
    def test_lightweight_tag_matches_the_exact_checked_commit(self):
        reader = Mock(return_value=target("commit", COMMIT))
        self.assertEqual(
            verify_release_commit(REPOSITORY, "v0.2.0", COMMIT, read_json=reader), COMMIT
        )
        reader.assert_called_once_with(REFERENCE)

    def test_moved_lightweight_tag_is_rejected(self):
        reader = Mock(return_value=target("commit", OTHER_COMMIT))
        with self.assertRaisesRegex(ValueError, "no longer"):
            verify_release_commit(REPOSITORY, "v0.2.0", COMMIT, read_json=reader)

    def test_annotated_and_nested_tags_are_resolved(self):
        documents = {
            REFERENCE: target("tag", TAG_SHA),
            f"repos/{REPOSITORY}/git/tags/{TAG_SHA}": target("tag", NESTED_TAG_SHA),
            f"repos/{REPOSITORY}/git/tags/{NESTED_TAG_SHA}": target("commit", COMMIT),
        }
        reader = Mock(side_effect=documents.__getitem__)
        self.assertEqual(
            verify_release_commit(REPOSITORY, "v0.2.0", COMMIT, read_json=reader), COMMIT
        )
        self.assertEqual(reader.call_count, 3)

    def test_moved_annotated_tag_is_rejected(self):
        reader = Mock(side_effect=[target("tag", TAG_SHA), target("commit", OTHER_COMMIT)])
        with self.assertRaisesRegex(ValueError, "no longer"):
            verify_release_commit(REPOSITORY, "v0.2.0", COMMIT, read_json=reader)

    def test_unknown_object_type_is_rejected(self):
        for document in (target("tree", COMMIT), target("blob", COMMIT)):
            with self.subTest(document=document):
                reader = Mock(return_value=document)
                with self.assertRaisesRegex(ValueError, "must resolve to a commit"):
                    verify_release_commit(REPOSITORY, "v0.2.0", COMMIT, read_json=reader)

    def test_annotated_tag_cycle_is_rejected_without_another_read(self):
        reader = Mock(side_effect=[target("tag", TAG_SHA), target("tag", TAG_SHA)])
        with self.assertRaisesRegex(ValueError, "cycle"):
            verify_release_commit(REPOSITORY, "v0.2.0", COMMIT, read_json=reader)
        self.assertEqual(reader.call_count, 2)

    def test_depth_limit_is_rejected_before_requesting_an_extra_tag(self):
        reader = Mock(side_effect=[target("tag", TAG_SHA), target("tag", NESTED_TAG_SHA)])
        with self.assertRaisesRegex(ValueError, "maximum depth"):
            verify_release_commit(
                REPOSITORY, "v0.2.0", COMMIT, read_json=reader, max_tag_depth=1
            )
        self.assertEqual(reader.call_count, 2)

    def test_lightweight_tag_does_not_require_annotated_tag_depth(self):
        reader = Mock(return_value=target("commit", COMMIT))
        self.assertEqual(
            verify_release_commit(
                REPOSITORY, "v0.2.0", COMMIT, read_json=reader, max_tag_depth=0
            ),
            COMMIT,
        )

    def test_tag_name_is_encoded_as_one_endpoint_component(self):
        reader = Mock(return_value=target("commit", COMMIT))
        verify_release_commit(REPOSITORY, "gui/v0.2.0+build", COMMIT, read_json=reader)
        reader.assert_called_once_with(
            f"repos/{REPOSITORY}/git/ref/tags/gui%2Fv0.2.0%2Bbuild"
        )

    def test_read_failure_is_not_treated_as_a_verified_commit(self):
        reader = Mock(side_effect=ValueError("read failed"))
        with self.assertRaisesRegex(ValueError, "read failed"):
            verify_release_commit(REPOSITORY, "v0.2.0", COMMIT, read_json=reader)

    def test_malformed_api_responses_are_rejected(self):
        for document in ({}, {"object": None}, target("commit", "short"), []):
            with self.subTest(document=document):
                with self.assertRaises(ValueError):
                    verify_release_commit(
                        REPOSITORY, "v0.2.0", COMMIT, read_json=Mock(return_value=document)
                    )

    def test_api_reader_invokes_gh_without_a_shell(self):
        result = subprocess.CompletedProcess(
            ["gh", "api", REFERENCE], 0, stdout=json.dumps(target("commit", COMMIT))
        )
        with patch.object(MODULE.subprocess, "run", return_value=result) as run:
            self.assertEqual(MODULE.read_github_json(REFERENCE), target("commit", COMMIT))
        run.assert_called_once_with(
            ["gh", "api", REFERENCE], check=True, capture_output=True, text=True
        )

    def test_api_reader_rejects_command_failure_and_invalid_json(self):
        with patch.object(
            MODULE.subprocess,
            "run",
            side_effect=subprocess.CalledProcessError(1, ["gh", "api", REFERENCE]),
        ):
            with self.assertRaisesRegex(ValueError, "API request failed"):
                MODULE.read_github_json(REFERENCE)
        for stdout in ("not json", "[]"):
            with self.subTest(stdout=stdout):
                result = subprocess.CompletedProcess(["gh", "api"], 0, stdout=stdout)
                with patch.object(MODULE.subprocess, "run", return_value=result):
                    with self.assertRaises(ValueError):
                        MODULE.read_github_json(REFERENCE)

    def test_invalid_cli_values_are_rejected_before_reading(self):
        cases = [
            ("owner/../repository", "v0.2.0", COMMIT),
            (REPOSITORY, "", COMMIT),
            (REPOSITORY, "v0.2.0\n", COMMIT),
            (REPOSITORY, "v0.2.0", "short"),
        ]
        for repository, tag, commit in cases:
            with self.subTest(repository=repository, tag=tag, commit=commit):
                reader = Mock()
                with self.assertRaises(ValueError):
                    verify_release_commit(repository, tag, commit, read_json=reader)
                reader.assert_not_called()


class EnsureReleaseTagTests(unittest.TestCase):
    def test_new_tag_is_created_and_verified(self):
        creator = Mock()
        reader = Mock(return_value=target("commit", COMMIT))
        self.assertEqual(
            ensure_release_tag(
                REPOSITORY, "v0.2.0", COMMIT, create_ref=creator, read_json=reader
            ),
            COMMIT,
        )
        creator.assert_called_once_with(REPOSITORY, "v0.2.0", COMMIT)
        reader.assert_called_once_with(REFERENCE)

    def test_existing_and_concurrently_created_tags_are_verified(self):
        for reason in ("reference already exists", "concurrent creation"):
            with self.subTest(reason=reason):
                creator = Mock(side_effect=ValueError(reason))
                reader = Mock(return_value=target("commit", COMMIT))
                self.assertEqual(
                    ensure_release_tag(
                        REPOSITORY, "v0.2.0", COMMIT,
                        create_ref=creator, read_json=reader,
                    ),
                    COMMIT,
                )
                creator.assert_called_once_with(REPOSITORY, "v0.2.0", COMMIT)
                reader.assert_called_once_with(REFERENCE)

    def test_existing_annotated_tag_at_the_built_commit_is_reused(self):
        creator = Mock(side_effect=ValueError("reference already exists"))
        reader = Mock(side_effect=[target("tag", TAG_SHA), target("commit", COMMIT)])
        self.assertEqual(
            ensure_release_tag(
                REPOSITORY, "v0.2.0", COMMIT, create_ref=creator, read_json=reader
            ),
            COMMIT,
        )
        self.assertEqual(reader.call_count, 2)

    def test_conflicting_or_moved_tag_is_rejected_even_after_successful_creation(self):
        for creation_error in (None, ValueError("reference already exists")):
            with self.subTest(creation_error=creation_error):
                creator = Mock(side_effect=creation_error)
                reader = Mock(return_value=target("commit", OTHER_COMMIT))
                with self.assertRaisesRegex(ValueError, "no longer"):
                    ensure_release_tag(
                        REPOSITORY, "v0.2.0", COMMIT,
                        create_ref=creator, read_json=reader,
                    )
                creator.assert_called_once_with(REPOSITORY, "v0.2.0", COMMIT)

    def test_failed_creation_and_unverifiable_tag_fail_closed(self):
        for reason in ("network failure", "permission denied"):
            with self.subTest(reason=reason):
                creator = Mock(side_effect=ValueError(reason))
                reader = Mock(side_effect=ValueError("unable to read tag"))
                with self.assertRaisesRegex(ValueError, "unable to read tag"):
                    ensure_release_tag(
                        REPOSITORY, "v0.2.0", COMMIT,
                        create_ref=creator, read_json=reader,
                    )
                reader.assert_called_once_with(REFERENCE)

    def test_invalid_identity_never_reads_or_creates_a_ref(self):
        for repository, tag, commit in (
            ("owner/../repository", "v0.2.0", COMMIT),
            (REPOSITORY, "", COMMIT),
            (REPOSITORY, "v0.2.0\n", COMMIT),
            (REPOSITORY, "v0.2.0", "short"),
        ):
            with self.subTest(repository=repository, tag=tag, commit=commit):
                creator = Mock()
                reader = Mock()
                with self.assertRaises(ValueError):
                    ensure_release_tag(
                        repository, tag, commit, create_ref=creator, read_json=reader
                    )
                creator.assert_not_called()
                reader.assert_not_called()

    def test_creation_uses_post_without_force_or_a_shell(self):
        with patch.object(MODULE.subprocess, "run") as run:
            MODULE.create_github_tag(REPOSITORY, "v0.2.0", COMMIT)
        run.assert_called_once_with(
            [
                "gh", "api", "--method", "POST", f"repos/{REPOSITORY}/git/refs",
                "-f", "ref=refs/tags/v0.2.0", "-f", f"sha={COMMIT}",
            ],
            check=True, capture_output=True, text=True,
        )

    def test_creation_normalizes_command_and_os_errors(self):
        for error in (OSError("gh unavailable"), subprocess.CalledProcessError(1, ["gh"])):
            with self.subTest(error=error):
                with patch.object(MODULE.subprocess, "run", side_effect=error):
                    with self.assertRaisesRegex(ValueError, "creating the release tag"):
                        MODULE.create_github_tag(REPOSITORY, "v0.2.0", COMMIT)

    def test_cli_only_creates_when_explicitly_requested(self):
        for create in (False, True):
            with self.subTest(create=create):
                arguments = [
                    "verify_release_commit.py", "--repository", REPOSITORY,
                    "--tag", "v0.2.0", "--commit", COMMIT,
                ]
                if create:
                    arguments.append("--create-if-missing")
                with (
                    patch.object(MODULE.sys, "argv", arguments),
                    patch.object(MODULE, "ensure_release_tag", return_value=COMMIT) as ensure,
                    patch.object(MODULE, "verify_release_commit", return_value=COMMIT) as verify,
                    patch.object(MODULE.sys, "stdout", io.StringIO()),
                ):
                    self.assertEqual(MODULE.main(), 0)
                called, untouched = (ensure, verify) if create else (verify, ensure)
                called.assert_called_once_with(REPOSITORY, "v0.2.0", COMMIT)
                untouched.assert_not_called()


if __name__ == "__main__":
    unittest.main()
