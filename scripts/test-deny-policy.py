#!/usr/bin/env python3
"""Exercise dependency policy with disposable Cargo graphs and cargo-deny."""

# pattern: Imperative Shell

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "deny-policy"


def run_fixture(name: str, *, extra_config: str = "") -> subprocess.CompletedProcess[str]:
    source = FIXTURE_ROOT / name
    with tempfile.TemporaryDirectory(prefix=f"deny-{name}-") as temporary:
        repository = Path(temporary) / name
        shutil.copytree(source, repository)
        deny_path = repository / "deny.toml"
        deny_path.write_text((ROOT / "deny.toml").read_text(encoding="utf-8"), encoding="utf-8")
        deny_text = deny_path.read_text(encoding="utf-8")
        deny_text = deny_text.replace(
            'db-urls = ["https://github.com/RustSec/advisory-db"]',
            "db-urls = []",
        )
        deny_path.write_text(deny_text + extra_config, encoding="utf-8")
        return subprocess.run(
            [
                "cargo",
                "deny",
                "--color",
                "never",
                "--config",
                str(deny_path),
                "--manifest-path",
                str(repository / "Cargo.toml"),
                "--offline",
                "check",
                "bans",
            ],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )


def assert_success(name: str) -> None:
    result = run_fixture(name)
    assert result.returncode == 0, (
        f"{name} should pass cargo-deny bans, got {result.returncode}:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def assert_failure(name: str, *, extra_config: str = "") -> None:
    result = run_fixture(name, extra_config=extra_config)
    assert result.returncode != 0, (
        f"{name} should fail cargo-deny bans, but exited 0:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def assert_policy_failure(name: str, expected: str, *, extra_config: str = "") -> None:
    result = run_fixture(name, extra_config=extra_config)
    output = result.stdout + result.stderr
    assert result.returncode != 0, (
        f"{name} should fail cargo-deny bans, but exited 0:\n{output}"
    )
    assert expected in output, f"{name} failed for an unexpected reason:\n{output}"


def test_internal_exact_path_dependency_succeeds() -> None:
    assert_success("internal-exact")


def test_external_wildcard_dependency_fails() -> None:
    assert_policy_failure("external-wildcard", "wildcard dependency")


def test_unlisted_duplicate_outside_exact_skip_fails() -> None:
    assert_policy_failure(
        "unlisted-duplicate",
        "found 2 duplicate entries for crate",
        extra_config=(
            '\n[[bans.skip]]\n'
            'name = "fixture-not-present"\n'
            'version = "=0.1.0"\n'
            'reason = "unrelated exact skip must not mask duplicates"\n'
        ),
    )


if __name__ == "__main__":
    test_internal_exact_path_dependency_succeeds()
    test_external_wildcard_dependency_fails()
    test_unlisted_duplicate_outside_exact_skip_fails()
    print("deny policy fixture tests passed")
