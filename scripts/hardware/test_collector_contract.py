"""Regression checks for the PowerShell hardware collector contract."""

from pathlib import Path
import unittest


class CollectorContractTests(unittest.TestCase):
    """Verify collector accesses ordered dictionaries by key."""

    def test_collector_reads_ordered_dictionary_results_by_key(self) -> None:
        collector = (Path(__file__).resolve().parent / "collect_hardware.ps1").read_text(
            encoding="utf-8"
        )

        for result in ("smbiosResult", "wmiResult", "chassisResult"):
            self.assertIn(f"${result}['summary']", collector)
            self.assertNotIn(f"${result}.summary", collector)


if __name__ == "__main__":
    unittest.main()
