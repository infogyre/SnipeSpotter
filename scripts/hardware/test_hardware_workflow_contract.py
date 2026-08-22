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


if __name__ == "__main__":
    unittest.main()
