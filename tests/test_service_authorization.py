import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("service_import", ROOT / "scripts/construction/import_service_authorization.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
BASE = ROOT / "data/snapshots/2026-10-24T014455Z"


class ServiceAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "data/construction/2026-10-24T014455Z/experiments")
        self.root = Path(self.temp.name)
        self.paths = []
        for name in ["role-admin-deploy-v4", "role-admin-effective-v3", "role-admin-matrix-v3"]:
            destination = self.root / name
            shutil.copytree(BASE / name, destination)
            self.paths.append(destination)

    def tearDown(self):
        self.temp.cleanup()

    def parse(self):
        return MODULE.parse_authorization(*self.paths)

    def rewrite(self, directory, name, value):
        target = directory / name
        target.write_text(json.dumps(value, indent=2) + "\n")
        self.rehash(directory, name)

    def rehash(self, directory, name):
        manifest = json.loads((directory / "manifest.json").read_text())
        for item in manifest["files"]:
            if item["path"] == name:
                item["sha256"] = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        (directory / "manifest.json").write_text(json.dumps(manifest))

    def test_retained_bundle_parses(self):
        self.assertEqual(len(self.parse()["observed"]), 24)

    def test_self_consistent_export_omission_rejected(self):
        data = json.loads((self.paths[0] / "permissions.json").read_text())
        data["Auditor"]["GET"].remove("/audit")
        self.rewrite(self.paths[0], "permissions.json", data)
        with self.assertRaisesRegex(ValueError, "executable source"):
            self.parse()

    def test_export_broadening_rejected(self):
        data = json.loads((self.paths[0] / "permissions.json").read_text())
        data["Auditor"]["POST"].append("/filter")
        self.rewrite(self.paths[0], "permissions.json", data)
        with self.assertRaisesRegex(ValueError, "executable source"):
            self.parse()

    def test_source_mutation_rejected_after_rehash(self):
        source = self.paths[0] / "service.py"
        source.write_text(source.read_text().replace("roles.get(fingerprint,'Unmapped')", "'SecurityAdministrator'"))
        self.rehash(self.paths[0], "service.py")
        with self.assertRaisesRegex(ValueError, "reviewed implementation"):
            self.parse()

    def test_runtime_source_mismatch_rejected(self):
        data = json.loads((self.paths[1] / "observations.json").read_text())
        for record in data["records"]:
            if record["command"][:5] == ["docker", "exec", "ND_O_A1", "python3", "-c"]:
                record["stdout"] = "0" * 64 + "\n"
        self.rewrite(self.paths[1], "observations.json", data)
        with self.assertRaisesRegex(ValueError, "Effective service source"):
            self.parse()

    def test_runtime_role_mismatch_rejected(self):
        data = json.loads((self.paths[1] / "observations.json").read_text())
        for record in data["records"]:
            if record["command"][-2:] == ["cat", "/root/role-admin-v4/role-map.json"]:
                record["stdout"] = "{}"
        self.rewrite(self.paths[1], "observations.json", data)
        with self.assertRaisesRegex(ValueError, "Effective role map"):
            self.parse()

    def test_public_certificate_rebinding_rejected(self):
        shutil.copyfile(self.paths[0] / "unmapped.public.pem", self.paths[0] / "auditor.public.pem")
        self.rehash(self.paths[0], "auditor.public.pem")
        with self.assertRaisesRegex(ValueError, "certificate role binding"):
            self.parse()

    def test_manifest_omission_rejected(self):
        data = json.loads((self.paths[0] / "manifest.json").read_text())
        data["files"] = [item for item in data["files"] if item["path"] != "permissions.json"]
        (self.paths[0] / "manifest.json").write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "omits a public input"):
            self.parse()

    def test_observed_acceptance_disagreement_rejected(self):
        data = json.loads((self.paths[2] / "observations.json").read_text())
        for record in data["records"]:
            if record["command"][0] == "curl" and "HTTP_STATUS=403" in record["stdout"]:
                record["stdout"] = record["stdout"].replace("HTTP_STATUS=403", "HTTP_STATUS=200")
                break
        self.rewrite(self.paths[2], "observations.json", data)
        with self.assertRaisesRegex(ValueError, "disagrees"):
            self.parse()

    def test_missing_operation_case_rejected(self):
        data = json.loads((self.paths[2] / "observations.json").read_text())
        data["records"] = [record for record in data["records"]
                           if not ("--head" in record["command"]
                                   and any(value.endswith("/unmapped.pem") for value in record["command"]))]
        self.rewrite(self.paths[2], "observations.json", data)
        with self.assertRaisesRegex(ValueError, "Incomplete principal"):
            self.parse()


if __name__ == "__main__":
    unittest.main()
