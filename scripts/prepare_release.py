#!/usr/bin/env python3
"""Commit an explicit version increment and return the fixed release commit."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from bump_release_version import RELEASE_FILES, bump_release_version


SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
RUN_ID_PATTERN = re.compile(r"[0-9]+")
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"


def git(root: Path, *args: str, env: dict | None = None) -> str:
    """Run Git without a shell, retaining its rejection reason on failure."""
    environment = dict(os.environ)
    if env is not None:
        environment.update(env)
    try:
        result = subprocess.run(
            ["git", *args], cwd=root, env=environment,
            check=True, capture_output=True,
        )
    except OSError as error:
        raise ValueError(f"cannot run git {args[0]}: {error}") from error
    except subprocess.CalledProcessError as error:
        reason = (
            error.stderr.decode("utf-8", errors="replace").strip()
            or error.stdout.decode("utf-8", errors="replace").strip()
            or str(error)
        )
        raise ValueError(f"git {args[0]} failed: {reason}") from error
    # Decode explicitly so Git blobs retain CRLF instead of universal-newline
    # conversion silently changing the version files while preparing a release.
    return result.stdout.decode("utf-8")


def release_message(tag: str, run_id: str, bump: str) -> str:
    return f"chore(release): {tag}\n\nRelease-Run: {run_id}\nRelease-Bump: {bump}\n"


def expected_release(
    root: Path, source_commit: str, bump: str,
) -> tuple[dict[str, str], dict[str, bytes], str]:
    """Compute the exact allowed tree in a temporary worktree and Git index."""
    git_dir = git(root, "rev-parse", "--absolute-git-dir").strip()
    with tempfile.TemporaryDirectory(prefix="file-tidy-prepare-") as directory:
        staging = Path(directory)
        files = staging / "files"
        files.mkdir()
        for relative in RELEASE_FILES:
            path = files / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                git(root, "show", f"{source_commit}:{relative}").encode("utf-8")
            )
        previous, version, tag = bump_release_version(files, bump)
        contents = {relative: (files / relative).read_bytes() for relative in RELEASE_FILES}
        environment = {
            "GIT_DIR": git_dir,
            "GIT_WORK_TREE": str(files),
            "GIT_INDEX_FILE": str(staging / "index"),
        }
        git(files, "read-tree", source_commit, env=environment)
        git(files, "add", "--", *RELEASE_FILES, env=environment)
        tree = git(files, "write-tree", env=environment).strip()
    return {
        "previous_version": previous,
        "version": version,
        "tag": tag,
    }, contents, tree


def validate_prepared_commit(
    root: Path, candidate: str, source_commit: str,
    message: str, expected_tree: str,
) -> None:
    """Verify the commit itself; a matching run marker alone is insufficient."""
    parents = git(root, "rev-list", "--parents", "-n", "1", candidate).split()
    if parents != [candidate, source_commit]:
        raise ValueError("release run commit must have exactly the original source commit as its parent")
    commit_document = git(root, "cat-file", "commit", candidate)
    if commit_document.partition("\n\n")[2] != message:
        raise ValueError("release run commit message or requested bump does not match this run")
    changed = set(
        git(root, "diff", "--name-only", "--no-renames", "-z", source_commit, candidate, "--")
        .rstrip("\0").split("\0")
    )
    changed.discard("")
    unexpected = changed - set(RELEASE_FILES)
    if unexpected:
        raise ValueError(
            "release run commit changes files outside the version files: "
            + ", ".join(sorted(unexpected))
        )
    if git(root, "rev-parse", f"{candidate}^{{tree}}").strip() != expected_tree:
        raise ValueError("release run commit tree does not match the requested version increment")


def prepare_release(
    root: Path | str, bump: str, branch: str, source_commit: str, run_id: str,
) -> dict[str, str]:
    root = Path(root).resolve()
    if bump not in ("major", "minor", "patch"):
        raise ValueError("bump must be major, minor, or patch")
    if SHA_PATTERN.fullmatch(source_commit) is None:
        raise ValueError("source commit must be a full lowercase commit SHA")
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise ValueError("run ID must contain only digits")
    git(root, "check-ref-format", f"refs/heads/{branch}")
    if git(root, "status", "--porcelain", "--untracked-files=no").strip():
        raise ValueError("checkout has tracked changes; refusing to prepare a release")
    if git(root, "rev-parse", "HEAD").strip() != source_commit:
        raise ValueError("checkout HEAD does not match the original source commit")

    git(root, "fetch", "--no-tags", "origin", f"refs/heads/{branch}")
    remote_head = git(root, "rev-parse", "FETCH_HEAD").strip()
    candidates = git(
        root, "log", "--format=%H", f"--grep=^Release-Run: {run_id}$", "FETCH_HEAD", "--"
    ).splitlines()
    if len(candidates) > 1:
        raise ValueError("remote history contains multiple commits for this release run")
    if not candidates and remote_head != source_commit:
        raise ValueError(
            f"{branch} has advanced since this workflow started; start a new Run workflow"
        )

    release, contents, tree = expected_release(root, source_commit, bump)
    message = release_message(release["tag"], run_id, bump)
    if candidates:
        candidate = candidates[0]
        validate_prepared_commit(root, candidate, source_commit, message, tree)
        return {"commit": candidate, **release}

    for relative, contents_bytes in contents.items():
        (root / relative).write_bytes(contents_bytes)
    git(root, "add", "--", *RELEASE_FILES)
    if git(root, "write-tree").strip() != tree:
        raise ValueError("staged tree differs from the expected release version changes")
    git(
        root, "-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_EMAIL}",
        "commit", "--no-gpg-sign", "--message", message,
    )
    commit = git(root, "rev-parse", "HEAD").strip()
    validate_prepared_commit(root, commit, source_commit, message, tree)
    # A regular push rejects concurrent changes. Never force, rebase, or move tags.
    git(root, "push", "origin", f"HEAD:refs/heads/{branch}")
    return {"commit": commit, **release}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bump", required=True, choices=("major", "minor", "patch"))
    parser.add_argument("--branch", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        release = prepare_release(
            args.root, args.bump, args.branch, args.source_commit, args.run_id
        )
        if args.github_output is not None:
            with args.github_output.open("a", encoding="utf-8") as output:
                for name in ("commit", "previous_version", "version", "tag"):
                    output.write(f"{name}={release[name]}\n")
    except (OSError, ValueError) as error:
        print(f"Unable to prepare release: {error}", file=sys.stderr)
        return 1
    print(
        f"Prepared {release['tag']} from {release['previous_version']} "
        f"at {release['commit']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
