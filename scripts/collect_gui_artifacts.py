#!/usr/bin/env python3
"""Collect one Tauri installer and its checksum for a release target."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sys


TARGET_BUNDLES = {
    "aarch64-apple-darwin": ("dmg", "*.dmg", ".dmg"),
    "x86_64-apple-darwin": ("dmg", "*.dmg", ".dmg"),
    "x86_64-pc-windows-msvc": ("nsis", "*.exe", "-setup.exe"),
    "x86_64-unknown-linux-gnu": ("deb", "*.deb", ".deb"),
}
VERSION_PATTERN = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
)


def collect_artifact(
    bundle_dir: Path, output_dir: Path, target: str, version: str
) -> Path:
    """Copy the expected installer without replacing existing release files."""
    if target not in TARGET_BUNDLES:
        raise ValueError(f"unsupported target: {target}")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError("version must be a version number without a leading v")

    bundle_dir = bundle_dir.resolve(strict=True)
    output_dir = output_dir.resolve()
    if not bundle_dir.is_dir():
        raise ValueError(f"bundle directory is not a directory: {bundle_dir}")
    if output_dir == bundle_dir or output_dir.is_relative_to(bundle_dir):
        raise ValueError("output directory must be outside the bundle directory")

    package_kind, pattern, suffix = TARGET_BUNDLES[target]
    package_dir = bundle_dir / package_kind
    packages = sorted(path for path in package_dir.glob(pattern) if path.is_file())
    if len(packages) != 1:
        raise ValueError(
            f"expected exactly one {package_kind} installer in {package_dir}, "
            f"found {len(packages)}"
        )
    source = packages[0]
    if source.is_symlink():
        raise ValueError(f"installer must be a regular file, not a symlink: {source}")

    filename = f"file-tidy-gui-{version}-{target}{suffix}"
    destination = output_dir / filename
    checksum_path = output_dir / f"{filename}.sha256"
    for path in (destination, checksum_path):
        if os.path.lexists(path):
            raise FileExistsError(f"refusing to replace existing release file: {path}")
    if source.resolve() == destination:
        raise ValueError("source and output installer paths must differ")

    output_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        while chunk := incoming.read(1024 * 1024):
            outgoing.write(chunk)
            digest.update(chunk)
    with checksum_path.open("x", encoding="utf-8", newline="\n") as checksum:
        checksum.write(f"{digest.hexdigest()}  {filename}\n")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=TARGET_BUNDLES)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        destination = collect_artifact(
            args.bundle_dir, args.output_dir, args.target, args.version
        )
    except (OSError, ValueError) as error:
        print(f"Unable to collect GUI installer: {error}", file=sys.stderr)
        return 1
    print(f"Collected {destination}")
    print(f"Checksum: {destination}.sha256")
    return 0


if __name__ == "__main__":
    sys.exit(main())
