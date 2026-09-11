"""Contract tests for reproducible CI pins and workflow input boundaries."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
MODULE = ROOT / "scripts" / "TestSupport" / "WorkflowInputs.psm1"
INPUT_PROBE = ROOT / "scripts" / "test-workflow-inputs.ps1"

EXPECTED_TOOLCHAIN = "1.98.1"
EXPECTED_TOOLS = {
    "cargo-deny": "0.20.2",
    "cargo-llvm-cov": "0.9.1",
    "cargo-cyclonedx": "0.5.9",
    "cargo-mutants": "27.1.0",
}


def _workflow_text(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def _assert_full_sha_uses(text: str, path: Path) -> None:
    for line_number, line in enumerate(text.splitlines(), 1):
        if "uses:" not in line or "uses: ./" in line:
            continue
        assert re.search(r"uses:\s+[^\s@]+@[0-9a-f]{40}(?:\s|$)", line), (
            f"{path}:{line_number}: external action is not full-SHA pinned"
        )


def test_all_workflows_use_pinned_actions_and_toolchain() -> None:
    assert WORKFLOWS
    for path in WORKFLOWS:
        text = path.read_text(encoding="utf-8")
        _assert_full_sha_uses(text, path)
        assert "rustup toolchain install stable" not in text
        if "rustup toolchain install" in text:
            assert "rustup toolchain install 1.98.1" in text
    toolchain = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    assert 'channel = "1.98.1"' in toolchain
    assert 'profile = "minimal"' in toolchain
    assert '"rustfmt"' in toolchain and '"clippy"' in toolchain


def test_tool_install_commands_are_exact_and_assert_executed_versions() -> None:
    checks = _workflow_text("checks.yml")
    for package, version in EXPECTED_TOOLS.items():
        assert f"cargo install {package} --version {version} --locked" in checks or any(
            f"cargo install {package} --version {version} --locked" in path.read_text(encoding="utf-8")
            for path in WORKFLOWS
        )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in WORKFLOWS)
    assert "cargo deny --version" in combined and "0.20.2" in combined
    assert "cargo llvm-cov --version" in combined and "0.9.1" in combined
    assert "cargo cyclonedx --version" in combined and "0.5.9" in combined
    assert "cargo mutants --version" in combined and "27.1.0" in combined
    assert "dotnet tool install --global wix --version 6.0.0" in combined
    assert "wix --version" in combined and "6.0.0" in combined
    assert "RequiredVersion 1.25.0" in combined
    assert "PSScriptAnalyzer" in combined


def test_workflow_contract_rejects_mutated_unpinned_fixtures() -> None:
    source = _workflow_text("checks.yml")
    mutated = source.replace(
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
        "actions/checkout@v4",
        1,
    )
    assert mutated != source
    try:
        _assert_full_sha_uses(mutated, Path("checks-mutated.yml"))
    except AssertionError:
        pass
    else:
        raise AssertionError("removing an action pin was accepted")


def test_elevated_validation_is_before_side_effects_and_outputs_exact_four_values() -> None:
    text = _workflow_text("elevated-windows.yml")
    validate = text.index("- name: Validate workflow inputs")
    validate_step_id = text.index("id: validate_inputs", validate)
    checkout = text.index("- name: Check out source")
    download = text.index("- name: Download packaged MSI")
    build = text.index("- name: Build source MSI")
    assert checkout < validate < download
    assert validate < build
    block = text[validate:download]
    assert "Import-Module" in block
    assert "Get-ValidatedWorkflowInputs" in block
    assert "GITHUB_OUTPUT" in block
    assert block.count("artifact_name=") == 1
    assert block.count("log_artifact_name=") == 1
    assert block.count("run_identity=") == 1
    assert block.count("msi_name=") == 1
    consumers = text[download:]
    assert "name: ${{ inputs.artifact_name }}" not in consumers
    assert "name: ${{ inputs.log_artifact_name }}" not in consumers
    assert "RUN_IDENTITY: ${{ inputs.run_identity }}" not in consumers
    assert "MSI_NAME: ${{ inputs.msi_name }}" not in consumers
    assert "steps.validate_inputs.outputs.artifact_name" in text
    assert "steps.validate_inputs.outputs.log_artifact_name" in text
    assert "steps.validate_inputs.outputs.run_identity" in text
    assert "steps.validate_inputs.outputs.msi_name" in text
    assert "if: ${{ always() && steps.validate_inputs.outcome == 'success' }}" in text


def test_workflow_inputs_module_and_executable_probe_exist() -> None:
    assert MODULE.is_file()
    assert INPUT_PROBE.is_file()
    source = MODULE.read_text(encoding="utf-8")
    for symbol in (
        "Assert-RunIdentity",
        "Assert-MsiName",
        "Assert-ArtifactName",
        "Get-ValidatedWorkflowInputs",
    ):
        assert symbol in source
    paths_source = (ROOT / "scripts" / "TestSupport" / "WorkflowPaths.psm1").read_text(encoding="utf-8")
    for symbol in ("Resolve-ValidatedMsiPath", "ReparsePoint"):
        assert symbol in paths_source
    assert "# pattern: Functional Core" in source
    assert "# pattern: Imperative Shell" in paths_source
    assert "Set-StrictMode -Version Latest" in INPUT_PROBE.read_text(encoding="utf-8")


def test_executable_input_probe_passes_without_elevation() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for executable workflow-input probes"
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(INPUT_PROBE)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "workflow input contract: OK" in result.stdout


def test_workflow_input_probe_mutations_are_rejected() -> None:
    source = MODULE.read_text(encoding="utf-8")
    mutations = (
        source.replace("-not [string]::IsNullOrEmpty($Name)", "$false", 1),
        source.replace("[IO.FileAttributes]::ReparsePoint", "[IO.FileAttributes]::Normal", 1),
    )
    for index, mutation in enumerate(mutations):
        assert mutation != source
        with tempfile.TemporaryDirectory(prefix=f"workflow-input-mutation-{index}-") as directory:
            module = Path(directory) / "WorkflowInputs.psm1"
            module.write_text(mutation, encoding="utf-8")
            probe = INPUT_PROBE.read_text(encoding="utf-8").replace(
                "Join-Path $PSScriptRoot 'TestSupport/WorkflowInputs.psm1'",
                str(module).replace("'", "''"),
            )
            script = Path(directory) / "probe.ps1"
            script.write_text(probe, encoding="utf-8")
            pwsh = shutil.which("pwsh")
            assert pwsh
            result = subprocess.run(
                [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert result.returncode != 0, f"mutation {index} was accepted"


if __name__ == "__main__":
    failures = []
    for name, test in sorted(globals().items()):
        if name.startswith('test_'):
            try:
                test()
            except Exception as error:
                failures.append(f'{name}: {error}')
    if failures:
        raise SystemExit('\n'.join(failures))
    print(f'workflow contract: {len([name for name in globals() if name.startswith("test_")])} tests passed')
