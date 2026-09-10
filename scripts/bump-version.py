#!/usr/bin/env python3
"""Verify or atomically update the workspace version and internal dependency pins."""

# pattern: Imperative Shell

from __future__ import annotations

import argparse
import os
import re
import tempfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_MANIFEST = ROOT / "Cargo.toml"
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
WORKSPACE_VERSION_RE = re.compile(r'(?m)^(version\s*=\s*")([^"]+)(")$')
INTERNAL_PATH_RE = re.compile(
    r'(?m)^(?P<prefix>\s*[A-Za-z0-9_-]+\s*=\s*\{[^\n]*?path\s*=\s*"\.\.[^\n]*?)(?P<suffix>\s*\})$'
)
VERSION_FIELD_RE = re.compile(r'(?P<before>\bversion\s*=\s*")(?P<version>[^"]+)(?P<after>")')


class VersionError(ValueError):
    """Raised when a workspace version proposal is invalid."""


def validate_version(version: str) -> str:
    if not VERSION_RE.fullmatch(version):
        raise VersionError(f"invalid semantic version: {version!r}")
    return version


def update_workspace_text(text: str, version: str) -> str:
    matches = list(WORKSPACE_VERSION_RE.finditer(text))
    if len(matches) != 1:
        raise VersionError("workspace version occurrence is not unique")
    match = matches[0]
    return text[: match.start(2)] + version + text[match.end(2) :]


def update_manifest_text(text: str, version: str) -> str:
    changed = False
    lines = []
    for line in text.splitlines(keepends=True):
        if "path = \".." not in line:
            lines.append(line)
            continue
        if "{" not in line or "}" not in line:
            raise VersionError("internal path dependency is not a complete inline table")
        matches = list(VERSION_FIELD_RE.finditer(line))
        if len(matches) > 1:
            raise VersionError("internal dependency has multiple version fields")
        if matches:
            match = matches[0]
            line = line[: match.start("version")] + f"={version}" + line[match.end("version") :]
        else:
            closing = line.rfind("}")
            if closing < 0:
                raise VersionError("internal path dependency has no closing brace")
            insertion = f', version = "={version}"'
            line = line[:closing] + insertion + line[closing:]
        changed = True
        lines.append(line)
    if not changed and "[package]" not in text:
        raise VersionError("manifest is not a Cargo package manifest")
    return "".join(lines)


def manifest_paths() -> list[Path]:
    return sorted(ROOT.glob("*/Cargo.toml"))


def proposed_contents(version: str) -> dict[Path, str]:
    version = validate_version(version)
    contents: dict[Path, str] = {}
    contents[WORKSPACE_MANIFEST] = update_workspace_text(
        WORKSPACE_MANIFEST.read_text(encoding="utf-8"), version
    )
    for path in manifest_paths():
        original = path.read_text(encoding="utf-8")
        updated = update_manifest_text(original, version)
        if updated != original:
            contents[path] = updated
    for path, text in contents.items():
        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            raise VersionError(f"proposed manifest is invalid: {path}: {error}") from error
    return contents


def verify() -> None:
    workspace_text = WORKSPACE_MANIFEST.read_text(encoding="utf-8")
    matches = list(WORKSPACE_VERSION_RE.finditer(workspace_text))
    if len(matches) != 1:
        raise VersionError("workspace version occurrence is not unique")
    version = validate_version(matches[0].group(2))
    expected = f'version = "={version}"'
    for path in manifest_paths():
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "path = \".." in line and expected not in line:
                raise VersionError(f"{path}:{line_number}: internal dependency version is not {expected}")


def atomic_replace(path: Path, text: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def set_version(version: str) -> None:
    updates = proposed_contents(version)
    for path, text in updates.items():
        atomic_replace(path, text)
    verify()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify", action="store_true", help="verify all workspace versions")
    group.add_argument("--set", dest="version", metavar="VERSION", help="set the workspace version")
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        if arguments.verify:
            verify()
        else:
            set_version(arguments.version)
    except (OSError, VersionError) as error:
        raise SystemExit(f"bump-version.py: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
