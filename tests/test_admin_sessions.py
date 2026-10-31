"""Reject mismatched administration records before constructing authentication witnesses."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_admin_sessions import parse


class AdminSessionImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.paths = {}
        base = ROOT / "artifacts/snapshots/2026-10-24T014455Z"
        for key, name in [("deployment", "role-admin-deploy-v4"),
                          ("effective", "role-admin-effective-v3"),
                          ("matrix", "role-admin-matrix-v3")]:
            destination = Path(self.temporary.name) / key
            shutil.copytree(base / name, destination)
            self.paths[key] = destination

    def tearDown(self):
        self.temporary.cleanup()

    def read(self, key):
        return json.loads((self.paths[key] / "observations.json").read_text())

    def save(self, key, data):
        root = self.paths[key]
        source = root / "observations.json"
        source.write_text(json.dumps(data))
        manifest = json.loads((root / "manifest.json").read_text())
        entry = next(row for row in manifest["files"] if row["path"] == "observations.json")
        entry["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        if "bytes" in entry:
            entry["bytes"] = source.stat().st_size
        (root / "manifest.json").write_text(json.dumps(manifest))

    def run_import(self):
        return parse(**self.paths)

    def test_retained_requests(self):
        data = self.run_import()
        self.assertEqual(data["audit_outcomes"], 24)
        self.assertEqual(len(data["accepted"]), 10)
        self.assertEqual(data["rejected_outcomes"], 14)
        self.assertEqual(len(data["principals"]), 2)

    def test_listener_pid_mismatch(self):
        data = self.read("effective")
        record = next(row for row in data["records"] if row["command"][-2:] == ["ss", "-lntp"])
        record["stdout"] = record["stdout"].replace("pid=641", "pid=9999")
        self.save("effective", data)
        with self.assertRaisesRegex(ValueError, "Listener PID"):
            self.run_import()

    def test_listener_source_path_mismatch(self):
        data = self.read("effective")
        record = next(row for row in data["records"] if row["command"][-3:] == ["ps", "-eo", "pid,user,comm,args"])
        record["stdout"] = record["stdout"].replace("/root/role-admin-v4/service.py", "/root/unreviewed.py")
        self.save("effective", data)
        with self.assertRaisesRegex(ValueError, "Listener PID"):
            self.run_import()

    def test_missing_process_inventory(self):
        data = self.read("effective")
        data["records"] = [row for row in data["records"] if "ps" not in row["command"]]
        self.save("effective", data)
        with self.assertRaisesRegex(ValueError, "listener and process"):
            self.run_import()

    def test_missing_success_status(self):
        data = self.read("effective")
        del data["error"]
        self.save("effective", data)
        with self.assertRaisesRegex(ValueError, "Explicit successful"):
            self.run_import()

    def test_wrong_service_target(self):
        data = self.read("effective")
        record = next(row for row in data["records"] if row["command"][-1].endswith("audit.jsonl"))
        record["command"][2] = "different-service"
        self.save("effective", data)
        with self.assertRaisesRegex(ValueError, "service-local"):
            self.run_import()

    def test_missing_denied_event(self):
        data = self.read("effective")
        record = next(row for row in data["records"] if row["command"][-1].endswith("audit.jsonl"))
        events = [json.loads(line) for line in record["stdout"].splitlines()]
        events.remove(next(row for row in events if row["status"] == 403))
        record["stdout"] = "\n".join(json.dumps(row) for row in events)
        self.save("effective", data)
        with self.assertRaisesRegex(ValueError, "complete client outcome"):
            self.run_import()

    def test_wrong_audit_role(self):
        data = self.read("effective")
        record = next(row for row in data["records"] if row["command"][-1].endswith("audit.jsonl"))
        events = [json.loads(line) for line in record["stdout"].splitlines()]
        events[0]["role"] = "SecurityAdministrator"
        record["stdout"] = "\n".join(json.dumps(row) for row in events)
        self.save("effective", data)
        with self.assertRaisesRegex(ValueError, "Audit role"):
            self.run_import()

    def test_duplicate_audit_identity(self):
        data = self.read("effective")
        record = next(row for row in data["records"] if row["command"][-1].endswith("audit.jsonl"))
        events = [json.loads(line) for line in record["stdout"].splitlines()]
        events[1]["at"] = events[0]["at"]
        record["stdout"] = "\n".join(json.dumps(row) for row in events)
        self.save("effective", data)
        with self.assertRaisesRegex(ValueError, "Ambiguous audit"):
            self.run_import()

    def test_readback_omits_event(self):
        data = self.read("matrix")
        record = [row for row in data["records"] if row.get("command", [None])[0] == "curl"
                  and row["command"][-1] == "https://managed.nd.test:8443/audit"][-1]
        body, marker = record["stdout"].rsplit("HTTP_STATUS=", 1)
        value = json.loads(body.strip())
        value["events"].pop()
        record["stdout"] = json.dumps(value) + "\nHTTP_STATUS=" + marker
        self.save("matrix", data)
        with self.assertRaisesRegex(ValueError, "every earlier retained"):
            self.run_import()

    def test_missing_rotation(self):
        data = self.read("effective")
        data["records"] = [row for row in data["records"]
                           if not row["command"][-1].endswith("audit-0001.jsonl")]
        self.save("effective", data)
        with self.assertRaisesRegex(ValueError, "rotation sequence"):
            self.run_import()


if __name__ == "__main__":
    unittest.main()
