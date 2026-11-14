"""Verify the immutable release commit guard without making network requests."""

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
