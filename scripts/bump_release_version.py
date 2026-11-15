#!/usr/bin/env python3
"""Increment and synchronize the Cargo and GUI release versions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import tempfile
import tomllib

from resolve_release import resolve_release


RELEASE_FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/gui/package.json",
    "crates/gui/package-lock.json",
    "crates/gui/src-tauri/tauri.conf.json",
)
TABLE_HEADER = re.compile(r"(?m)^[ \t]*(\[\[?[^\]\r\n]+\]\]?)[ \t]*(?:#[^\r\n]*)?(?:\r?\n|$)")


def next_version(previous: str, bump: str) -> str:
    """Apply an explicit major/minor/patch increment to a validated SemVer."""
    if bump not in ("major", "minor", "patch"):
        raise ValueError("bump must be major, minor, or patch")
    major, minor, patch = map(int, previous.split("-", 1)[0].split("+", 1)[0].split("."))
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def replace_assignment(text: str, key: str, previous: str, version: str, label: str) -> str:
    """Replace one TOML string assignment while preserving whitespace/comments."""
    pattern = re.compile(
        rf"(?m)^(?P<prefix>[ \t]*{re.escape(key)}[ \t]*=[ \t]*)(?P<quote>[\"'])"
        rf"{re.escape(previous)}(?P=quote)(?P<suffix>[ \t]*(?:#[^\r\n]*)?)(?=\r?$)"
    )
    updated, count = pattern.subn(
        lambda match: match["prefix"] + match["quote"] + version + match["quote"] + match["suffix"],
        text,
    )
    if count != 1:
        raise ValueError(f"{label}: cannot locate exactly one version assignment")
    return updated


def update_cargo(text: str, previous: str, version: str) -> str:
    document = tomllib.loads(text)
    dependencies = document["workspace"]["dependencies"]
    expected_dependencies = {
        name for name, dependency in dependencies.items()
        if isinstance(dependency, dict) and "path" in dependency
    }
    updated_dependencies = set()
    updates = []
    headers = list(TABLE_HEADER.finditer(text))
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        section = text[header.end():end]
        name = header.group(1)
        if name == "[workspace.package]":
            section = replace_assignment(section, "version", previous, version, "Cargo.toml workspace.package")
        elif name == "[workspace.dependencies]":
            for dependency in expected_dependencies:
                # Existing workspace manifests use one inline table per path dependency.
                pattern = re.compile(
                    rf"(?m)^(?P<prefix>[ \t]*{re.escape(dependency)}[ \t]*=[ \t]*\{{[^\r\n]*?\bversion[ \t]*=[ \t]*)"
                    rf"(?P<quote>[\"']){re.escape(previous)}(?P=quote)"
                )
                section, count = pattern.subn(
                    lambda match: match["prefix"] + match["quote"] + version + match["quote"], section
                )
                if count:
                    if count != 1:
                        raise ValueError(f"Cargo.toml: ambiguous dependency version for {dependency}")
                    updated_dependencies.add(dependency)
        elif name.startswith("[workspace.dependencies.") and name.endswith("]"):
            dependency = name[len("[workspace.dependencies."):-1].strip('"\'')
            if dependency in expected_dependencies:
                section = replace_assignment(section, "version", previous, version, f"Cargo.toml {dependency}")
                updated_dependencies.add(dependency)
        updates.append((header.end(), end, section))
    if updated_dependencies != expected_dependencies:
        missing = ", ".join(sorted(expected_dependencies - updated_dependencies))
        raise ValueError(f"Cargo.toml: cannot locate internal dependency versions: {missing}")
    for start, end, replacement in reversed(updates):
        text = text[:start] + replacement + text[end:]
    return text


def update_lock(text: str, previous: str, version: str) -> str:
    headers = list(TABLE_HEADER.finditer(text))
    updates = []
    for index, header in enumerate(headers):
        if header.group(1) != "[[package]]":
            continue
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        section = text[header.end():end]
        package = tomllib.loads(section)
        if package.get("name", "").startswith("file-tidy-") and "source" not in package:
            updates.append((header.end(), end, replace_assignment(
                section, "version", previous, version, f"Cargo.lock {package['name']}"
            )))
    for start, end, replacement in reversed(updates):
        text = text[:start] + replacement + text[end:]
    return text


def json_value_span(text: str, path: tuple[str, ...], start: int = 0) -> tuple[int, int]:
    """Locate a JSON member by its object path without reserializing the document."""
    decoder = json.JSONDecoder()

    def whitespace(position: int) -> int:
        while position < len(text) and text[position].isspace():
            position += 1
        return position

    position = whitespace(start)
    if text[position] != "{":
        raise ValueError(f"expected a JSON object at {'.'.join(path)}")
    position = whitespace(position + 1)
    matches = []
    while text[position] != "}":
        key, key_end = decoder.raw_decode(text, position)
        colon = whitespace(key_end)
        if text[colon] != ":":
            raise ValueError("expected a JSON member separator")
        value_start = whitespace(colon + 1)
        _, value_end = decoder.raw_decode(text, value_start)
        if key == path[0]:
            matches.append(
                json_value_span(text, path[1:], value_start) if len(path) > 1
                else (value_start, value_end)
            )
        position = whitespace(value_end)
        if text[position] == "}":
            break
        if text[position] != ",":
            raise ValueError("expected a JSON member separator")
        position = whitespace(position + 1)
    if len(matches) != 1:
        raise ValueError(f"cannot locate exactly one JSON member at {'.'.join(path)}")
    return matches[0]


def update_json(text: str, paths: tuple[tuple[str, ...], ...], version: str) -> str:
    updates = [(*json_value_span(text, path), json.dumps(version)) for path in paths]
    for start, end, replacement in sorted(updates, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


def bump_release_version(root: Path | str = ".", bump: str = "patch") -> tuple[str, str, str]:
    """Return (previous_version, version, tag) after synchronizing all manifests."""
    root = Path(root)
    _, previous = resolve_release(root)
    version = next_version(previous, bump)
    originals = {relative: (root / relative).read_bytes().decode("utf-8") for relative in RELEASE_FILES}
    updated = {
        "Cargo.toml": update_cargo(originals["Cargo.toml"], previous, version),
        "Cargo.lock": update_lock(originals["Cargo.lock"], previous, version),
    }
    for relative in RELEASE_FILES[2:]:
        paths = (("version",), ("packages", "", "version")) if relative.endswith("package-lock.json") else (("version",),)
        updated[relative] = update_json(originals[relative], paths, version)
    # Validate every generated manifest together before changing the checkout.
    with tempfile.TemporaryDirectory(prefix="file-tidy-release-") as staging:
        for relative, contents in updated.items():
            path = Path(staging) / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents.encode("utf-8"))
        tag, checked_version = resolve_release(staging)
        if checked_version != version:
            raise ValueError("generated release version did not match the requested increment")
    for relative, contents in updated.items():
        (root / relative).write_bytes(contents.encode("utf-8"))
    resolve_release(root)
    return previous, version, tag


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bump", required=True, choices=("major", "minor", "patch"))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        previous, version, tag = bump_release_version(args.root, args.bump)
        if args.github_output is not None:
            with args.github_output.open("a", encoding="utf-8") as output:
                output.write(f"previous_version={previous}\nversion={version}\ntag={tag}\n")
    except (OSError, ValueError) as error:
        print(f"Unable to bump release version: {error}", file=sys.stderr)
        return 1
    print(f"Release version {previous} -> {version} ({tag})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
