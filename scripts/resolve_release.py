#!/usr/bin/env python3
"""Derive the release tag from the checked commit and validate its versions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import tomllib


NUMBER = r"(?:0|[1-9][0-9]*)"
PRERELEASE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER_PATTERN = re.compile(
    rf"{NUMBER}\.{NUMBER}\.{NUMBER}"
    rf"(?:-{PRERELEASE_IDENTIFIER}(?:\.{PRERELEASE_IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
INTERNAL_DEPENDENCIES = ("file-tidy-core", "file-tidy-platform")
WORKSPACE_PACKAGES = frozenset(
    ("file-tidy-cli", "file-tidy-core", "file-tidy-gui", "file-tidy-platform")
)


def read_document(root: Path, relative: str) -> dict:
    """Read a release manifest, retaining its filename in any error."""
    path = root / relative
    try:
        contents = path.read_text(encoding="utf-8")
        if path.suffix == ".toml" or relative == "Cargo.lock":
            document = tomllib.loads(contents)
        else:
            document = json.loads(contents)
    except FileNotFoundError as error:
        raise ValueError(f"{relative}: required release source is missing") from error
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError(f"{relative}: cannot read release manifest: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"{relative}: expected a manifest object")
    return document


def nested(document: dict, *keys: str):
    value = document
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def require_version(label: str, value, expected: str) -> None:
    if value != expected:
        raise ValueError(f"{label}: version {value!r} does not match expected {expected!r}")


def resolve_release(root: Path | str = ".") -> tuple[str, str]:
    """Return (tag, version) only after the release sources agree."""
    root = Path(root)
    cargo = read_document(root, "Cargo.toml")
    version = nested(cargo, "workspace", "package", "version")
    if not isinstance(version, str) or SEMVER_PATTERN.fullmatch(version) is None:
        raise ValueError(
            f"Cargo.toml workspace.package.version: expected a strict SemVer version, got {version!r}"
        )

    dependencies = nested(cargo, "workspace", "dependencies")
    if not isinstance(dependencies, dict):
        raise ValueError(
            "Cargo.toml: expected workspace.dependencies with internal path dependencies"
        )
    for name in INTERNAL_DEPENDENCIES:
        dependency = dependencies.get(name)
        if not isinstance(dependency, dict) or not isinstance(dependency.get("path"), str):
            raise ValueError(
                f"Cargo.toml workspace.dependencies.{name}: expected an internal path dependency"
            )
    for name, dependency in dependencies.items():
        if isinstance(dependency, dict) and "path" in dependency:
            require_version(
                f"Cargo.toml workspace.dependencies.{name}", dependency.get("version"), version
            )

    lock = read_document(root, "Cargo.lock")
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ValueError("Cargo.lock: expected workspace package entries")
    local_packages = set()
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("Cargo.lock: expected package entries to be objects")
        name = package.get("name")
        if (
            isinstance(name, str)
            and name.startswith("file-tidy-")
            and "source" not in package
        ):
            require_version(f"Cargo.lock package {name}", package.get("version"), version)
            local_packages.add(name)
    missing = WORKSPACE_PACKAGES - local_packages
    if missing:
        raise ValueError(
            f"Cargo.lock: missing local workspace packages: {', '.join(sorted(missing))}"
        )

    for relative in (
        "crates/gui/src-tauri/tauri.conf.json",
        "crates/gui/package.json",
        "crates/gui/package-lock.json",
    ):
        document = read_document(root, relative)
        require_version(relative, document.get("version"), version)
        if relative.endswith("package-lock.json"):
            require_version(
                f"{relative} packages[root]", nested(document, "packages", "", "version"), version
            )
        if (
            relative.endswith("tauri.conf.json")
            and nested(document, "bundle", "active") is not True
        ):
            raise ValueError(f"{relative}: expected bundle.active to be true for GUI releases")
    return f"v{version}", version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--github-output", type=Path,
        help="Append tag and version to this Actions output file",
    )
    args = parser.parse_args()
    try:
        tag, version = resolve_release(args.root)
        if args.github_output is not None:
            with args.github_output.open("a", encoding="utf-8") as output:
                output.write(f"tag={tag}\nversion={version}\n")
    except (OSError, ValueError) as error:
        print(f"Unable to resolve release: {error}", file=sys.stderr)
        return 1
    print(f"Release {tag} (version {version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
