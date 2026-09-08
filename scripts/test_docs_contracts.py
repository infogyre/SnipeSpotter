"""Documentation contracts cross-checked against executable workflow definitions."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKS = (ROOT / ".github" / "workflows" / "checks.yml").read_text(encoding="utf-8")
ELEVATED = (ROOT / ".github" / "workflows" / "elevated-windows.yml").read_text(encoding="utf-8")
RELEASE = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
CI_GUIDE = (ROOT / "docs" / "ci-guide.md").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
MSI_LIFECYCLE = (ROOT / "scripts" / "test-msi-lifecycle.ps1").read_text(encoding="utf-8")


def _job_ids(workflow: str) -> list[str]:
    jobs = workflow.split("\njobs:\n", maxsplit=1)[1]
    return re.findall(r"^  ([a-z][a-z0-9-]*):\s*$", jobs, re.MULTILINE)


def _step_names(workflow: str) -> list[str]:
    return re.findall(r"^\s+- name: (.+)$", workflow, re.MULTILINE)


class DocumentationWorkflowContracts(unittest.TestCase):
    def test_documented_quickstart_fresh_msi(self) -> None:
        quick_start = README[README.index("## Quick start") : README.index("## Documentation")]
        documented_markers = (
            "msiexec /i",
            "Start-Service -Name SnipeSpotter",
            "Wait-ServiceState",
            "SnipeSpotter named pipe",
            "SnipeSpotter status response",
            "config set snipeit.url",
        )
        harness_markers = (
            "Start-Service -Name $serviceName",
            "Wait-ServiceState -Name $serviceName",
            "Wait-Condition -Description 'SnipeSpotter named pipe'",
            "Wait-Condition -Description 'SnipeSpotter status response'",
            "Invoke-InstalledCli -Arguments @('config', 'set'",
        )

        self.assertEqual(
            [quick_start.index(marker) for marker in documented_markers],
            sorted(quick_start.index(marker) for marker in documented_markers),
        )
        self.assertEqual(
            [MSI_LIFECYCLE.index(marker) for marker in harness_markers],
            sorted(MSI_LIFECYCLE.index(marker) for marker in harness_markers),
        )
        for claim in (
            "TimeoutSeconds",
            "Unconfigured",
            "%ProgramFiles%\\infogyre\\SnipeSpotter\\bin",
            "new shell",
            "already-open shell",
        ):
            self.assertIn(claim, quick_start)
        self.assertIn("Get-MachinePathEntry", MSI_LIFECYCLE)

    def test_docs_workflow_topology_contract(self) -> None:
        checks_jobs = _job_ids(CHECKS)
        elevated_jobs = _job_ids(ELEVATED)
        elevated_steps = _step_names(ELEVATED)
        release_steps = _step_names(RELEASE)

        self.assertEqual(
            checks_jobs,
            ["linux-core", "windows-workspace", "package-contract", "ci-success"],
        )
        self.assertEqual(elevated_jobs, ["lifecycle"])
        self.assertIn("workflow_call:", CHECKS)
        self.assertIn("workflow_call:", ELEVATED)
        self.assertRegex(
            CHECKS,
            r"(?ms)^  ci-success:\n.*?^    needs: \[linux-core, windows-workspace, package-contract\]$",
        )
        self.assertIn("Validate MSI lifecycle", elevated_steps)
        self.assertIn("Validate direct CLI SCM lifecycle", elevated_steps)
        self.assertIn("Generate checksums and inventory", release_steps)
        self.assertIn("Publish release assets", release_steps)
        self.assertIn('gh release create "${GITHUB_REF_NAME}" dist/* --verify-tag --generate-notes --draft=false', RELEASE)

        for claim in (
            "`linux-core`, `windows-workspace`, and `package-contract`",
            "`ci-success`",
            "`lifecycle`",
            "Generate checksums and inventory",
            "Publish release assets",
            "directly creates the published release with `--draft=false`",
        ):
            self.assertIn(claim, CI_GUIDE)
        self.assertNotIn("actionlint", CI_GUIDE)
        self.assertNotIn("zizmor", CI_GUIDE)
        self.assertNotIn("Flips the draft release", CI_GUIDE)


if __name__ == "__main__":
    unittest.main()
