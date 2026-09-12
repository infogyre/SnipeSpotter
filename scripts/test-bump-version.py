#!/usr/bin/env python3
"""Contract tests for the canonical workspace version updater."""

# pattern: Imperative Shell

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "scripts" / "bump-version.py"


def make_repository(destination: Path, *, malformed: bool = False) -> None:
    scripts = destination / "scripts"
    member = destination / "member"
    scripts.mkdir(parents=True)
    member.mkdir()
    shutil.copy2(UPDATER, scripts / UPDATER.name)
    (destination / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["member"]\n\n[workspace.package]\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    dependency = 'shared = { path = "../shared" }'
    if malformed:
        dependency = 'shared = { path = "../shared", version = "*"'
    (member / "Cargo.toml").write_text(
        '[package]\nname = "member"\nversion.workspace = true\n\n[dependencies]\n'
        f"{dependency}\n",
        encoding="utf-8",
    )


def run(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(repository / "scripts" / UPDATER.name), *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )


def test_round_trip() -> None:
    with tempfile.TemporaryDirectory(prefix="bump-version-") as temporary:
        repository = Path(temporary)
        make_repository(repository)
        result = run(repository, "--set", "1.2.3")
        assert result.returncode == 0, result.stderr
        assert run(repository, "--verify").returncode == 0
        assert 'version = "1.2.3"' in (repository / "Cargo.toml").read_text()
        assert 'version = "=1.2.3"' in (repository / "member/Cargo.toml").read_text()


def test_existing_exact_pin_is_updated() -> None:
    with tempfile.TemporaryDirectory(prefix="bump-version-existing-") as temporary:
        repository = Path(temporary)
        make_repository(repository)
        member = repository / "member/Cargo.toml"
        member.write_text(
            member.read_text(encoding="utf-8").replace(
                'path = "../shared"', 'path = "../shared", version = "=0.1.0"'
            ),
            encoding="utf-8",
        )
        result = run(repository, "--set", "1.2.3")
        assert result.returncode == 0, result.stderr
        assert 'version = "=1.2.3"' in member.read_text(encoding="utf-8")


def test_invalid_input_has_no_partial_write() -> None:
    with tempfile.TemporaryDirectory(prefix="bump-version-invalid-") as temporary:
        repository = Path(temporary)
        make_repository(repository, malformed=True)
        before = {
            path: path.read_bytes()
            for path in [repository / "Cargo.toml", repository / "member/Cargo.toml"]
        }
        result = run(repository, "--set", "not-a-version")
        assert result.returncode != 0
        assert all(path.read_bytes() == content for path, content in before.items())
        result = run(repository, "--set", "1.2.3")
        assert result.returncode != 0
        assert all(path.read_bytes() == content for path, content in before.items())


def test_workflow_invokes_canonical_updater() -> None:
    workflow = (ROOT / ".github/workflows/bump.yml").read_text(encoding="utf-8")
    assert "python3 scripts/bump-version.py --set \"$next\"" in workflow
    assert "text.replace" not in workflow


if __name__ == "__main__":
    test_round_trip()
    test_existing_exact_pin_is_updated()
    test_invalid_input_has_no_partial_write()
    test_workflow_invokes_canonical_updater()
    print("bump-version tests passed")
