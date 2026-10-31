"""Preserve distinct checkpoints when commands share the same clock reading."""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("construction_record", ROOT / "scripts/construction/record.py")
RECORD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECORD)


class RecordIdentityTests(unittest.TestCase):
    def test_equal_clock_readings_preserve_both_source_versions(self):
        with tempfile.TemporaryDirectory() as folder:
            previous = Path.cwd()
            try:
                os.chdir(folder)
                fixed = datetime(2026, 10, 24, 17, 33, 20, tzinfo=timezone.utc)
                records = []
                for value in ["first", "second"]:
                    Path("source.txt").write_text(value)
                    output = io.StringIO()
                    args = ["record.py", "checkpoint", "--actor", "construction", "--reason", "test",
                            "--label", value, "--paths", "source.txt"]
                    with patch.object(RECORD, "datetime") as clock, patch("sys.argv", args), redirect_stdout(output):
                        clock.now.return_value = fixed
                        RECORD.main()
                    path = Path(output.getvalue().strip())
                    record = json.loads(path.read_text())
                    records.append(path)
                    self.assertEqual((Path(record["checkpoint"]) / "source.txt").read_text(), value)
                self.assertNotEqual(*records)
                self.assertTrue(all(path.is_file() for path in records))
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
