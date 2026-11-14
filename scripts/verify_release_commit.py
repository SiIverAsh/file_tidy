#!/usr/bin/env python3
"""Verify that a remote release tag still resolves to the checked commit."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Callable
from urllib.parse import quote


MAX_TAG_DEPTH = 16
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def read_github_json(endpoint: str) -> dict:
    """Read GitHub through gh, without putting credentials in command arguments."""
    try:
        result = subprocess.run(
            ["gh", "api", endpoint], check=True, capture_output=True, text=True
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("GitHub API request failed while resolving the release tag") from error
    try:
        document = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("GitHub returned an invalid JSON response") from error
    if not isinstance(document, dict):
        raise ValueError("GitHub response must be an object")
    return document


def _target_object(document: dict) -> tuple[str, str]:
    if not isinstance(document, dict) or not isinstance(document.get("object"), dict):
        raise ValueError("GitHub response does not contain a tag target object")
    target = document["object"]
    kind = target.get("type")
    sha = target.get("sha")
    if not isinstance(kind, str) or not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha):
        raise ValueError("GitHub returned an invalid tag target object")
    return kind, sha


def verify_release_commit(
    repository: str,
    tag: str,
    commit: str,
    *,
    read_json: Callable[[str], dict] = read_github_json,
    max_tag_depth: int = MAX_TAG_DEPTH,
) -> str:
    """Resolve lightweight or annotated tags and require the exact expected SHA."""
    if REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise ValueError("repository must have the form owner/name")
    if not tag or any(ord(character) < 32 or ord(character) == 127 for character in tag):
        raise ValueError("tag must be a nonempty tag name without control characters")
    if SHA_PATTERN.fullmatch(commit) is None:
        raise ValueError("commit must be a full lowercase commit SHA")
    if max_tag_depth < 0:
        raise ValueError("maximum tag depth cannot be negative")

    reference = f"repos/{repository}/git/ref/tags/{quote(tag, safe='')}"
    kind, sha = _target_object(read_json(reference))
    visited = set()
    while True:
        if kind == "commit":
            if sha != commit:
                raise ValueError("release tag no longer resolves to the checked commit")
            return sha
        if kind != "tag":
            raise ValueError("release tag must resolve to a commit")
        if sha in visited:
            raise ValueError("annotated tag chain contains a cycle")
        if len(visited) >= max_tag_depth:
            raise ValueError("annotated tag chain exceeds the maximum depth")
        visited.add(sha)
        kind, sha = _target_object(read_json(f"repos/{repository}/git/tags/{sha}"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        commit = verify_release_commit(args.repository, args.tag, args.commit)
    except (OSError, ValueError, subprocess.CalledProcessError):
        print(
            "Unable to verify release tag: it must still resolve to the checked commit.",
            file=sys.stderr,
        )
        return 1
    print(f"Verified release commit: {commit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
