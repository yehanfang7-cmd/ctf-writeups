"""Regression checks for failed runs and stale results in automated research reports."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import run


class PipelineFailureTests(unittest.TestCase):
    def test_timeout_preserves_partial_output_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            timeout = subprocess.TimeoutExpired("worker", 600, output=b"partial output\n")
            with patch.object(run.subprocess, "run", side_effect=timeout):
                name, code, _ = run.run_step("worker", ["unused.py"], destination)
            self.assertEqual((name, code), ("worker", 124))
            self.assertIn("partial output", (destination / "worker.txt").read_text(encoding="utf-8"))

    def test_failure_report_does_not_publish_stale_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "generated/runs/current"
            (destination / "xor").mkdir(parents=True)
            (destination / "xor/verification.txt").write_text("STALE SUCCESS", encoding="utf-8")
            for name in ("PROJECT.md", "requirements.txt", "run.py", "native_verify.py", "start.ps1"):
                (root / name).write_text("placeholder", encoding="utf-8")
            with patch.object(run, "HERE", root):
                run.write_report(16, [("xor", 1, 0.5)], destination)
            report = (root / "RESULTS.md").read_text(encoding="utf-8")
            self.assertIn("失敗", report)
            self.assertNotIn("STALE SUCCESS", report)
            self.assertTrue((destination / "research_bundle.zip").is_file())


if __name__ == "__main__":
    unittest.main()
