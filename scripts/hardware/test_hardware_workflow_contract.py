"""Static contract checks for hosted Windows service registration diagnostics."""

import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "hardware-experiment.yml"


class HardwareWorkflowContractTests(unittest.TestCase):
    """Keep temporary LocalSystem registration observable and correctly tokenized."""

    def test_local_system_registration_preserves_sc_diagnostics_and_argument_boundaries(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("$scOutput = & sc.exe create", workflow)
        self.assertIn("2>&1", workflow)
        self.assertIn("binPath=", workflow)
        self.assertIn("'obj=' 'LocalSystem'", workflow)
        self.assertIn("'start=' 'demand'", workflow)
        self.assertIn("'type=' 'own'", workflow)
        self.assertIn("$scOutput -join", workflow)
        self.assertNotIn(
            '& sc.exe create $serviceName "binPath= $binPath"',
            workflow,
        )

    def test_local_system_start_failure_keeps_native_scm_diagnostics(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("$startOutput = & sc.exe start $serviceName 2>&1", workflow)
        self.assertIn("$queryOutput = & sc.exe queryex $serviceName 2>&1", workflow)
        self.assertIn("$configOutput = & sc.exe qc $serviceName 2>&1", workflow)
        self.assertIn("$startOutput -join", workflow)
        self.assertIn("$queryOutput -join", workflow)
        self.assertIn("$configOutput -join", workflow)
        self.assertNotIn("Start-Service -Name $serviceName -ErrorAction Stop", workflow)


if __name__ == "__main__":
    unittest.main()
