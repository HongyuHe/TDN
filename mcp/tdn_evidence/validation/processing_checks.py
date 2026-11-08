"""Check processing queries, raw-record identity and rejection of altered captures."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from tdn_evidence.processing import query_processing, validated_processing
from tdn_evidence.service import EvidenceService


def expect_failure(action):
    try:
        action()
    except (ValueError, AssertionError):
        return
    raise AssertionError("Invalid input was accepted")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--collection", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--kind", default="xfrm-policy-main")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    service = EvidenceService(args.config)
    collection, device = args.collection, args.device
    capability = "processing." + args.kind
    checks = []
    try:
        assert capability in service.describe_capabilities(collection)["saved"]["capabilities"]
        checks.append("capability discovery")
        first = service.query_evidence(collection, capability, device, limit=1)
        assert first["total"] == 2 and first["next_offset"] == 1 and len(first["records"]) == 1
        second = service.query_evidence(collection, capability, device, offset=1, limit=1)
        assert second["next_offset"] is None and len(second["records"]) == 1
        assert {row["record"]["phase"] for page in [first, second] for row in page["records"]} == {"before", "after"}
        checks.append("device/kind filtering and complete pagination")
        record = first["records"][0]
        identifier = "supplement:" + record["observation"]
        assert json.loads(service.read_raw(collection, identifier)) == record["record"]
        assert service.read_stderr(collection, identifier) == record["record"]["stderr"]
        checks.append("raw record and stderr identity")
        expect_failure(lambda: service.query_evidence(collection, capability, "missing-device"))
        expect_failure(lambda: service.query_evidence(collection, "processing.unknown"))
        expect_failure(lambda: service.read_raw(collection, "supplement:missing-record"))
        expect_failure(lambda: service.query_evidence(collection, capability, device, limit=0))
        checks.append("unknown requests and invalid pagination rejected")
        snapshot = service.resolve(service.settings.saved_snapshots[collection])
        supplement = service.resolve(service.settings.saved_execution_supplements[collection])
        with tempfile.TemporaryDirectory(prefix="tdn-processing-check-") as temporary:
            copied = Path(temporary) / "capture"
            shutil.copytree(supplement, copied)
            observed = copied / "observations.json"
            original = observed.read_bytes()
            observed.write_bytes(original + b" ")
            expect_failure(lambda: validated_processing(snapshot, copied))
            checks.append("changed bytes rejected before query")
            document = json.loads(original)
            manifest = json.loads((copied / "manifest.json").read_text())

            def save_changed_document():
                observed.write_text(json.dumps(document) + "\n")
                for item in manifest["files"]:
                    if item["path"] == "observations.json":
                        item["sha256"] = hashlib.sha256(observed.read_bytes()).hexdigest()
                (copied / "manifest.json").write_text(json.dumps(manifest) + "\n")

            document["records"].append(document["records"][0])
            save_changed_document()
            expect_failure(lambda: validated_processing(snapshot, copied))
            checks.append("duplicate record rejected even with updated hashes")
            document = json.loads(original)
            document["expected_device_ids"] = ["wrong-device"]
            save_changed_document()
            expect_failure(lambda: validated_processing(snapshot, copied))
            checks.append("wrong inventory rejected even with updated hashes")
            document = json.loads(original)
            document["schema_version"] = "unsupported-format"
            save_changed_document()
            expect_failure(lambda: validated_processing(snapshot, copied))
            checks.append("unknown schema rejected even with updated hashes")
            document = json.loads(original)
            item = next(row for row in document["records"] if row["device_id"] == device and row["kind"] == args.kind)
            item["returncode"], item["stderr"] = 124, "test timeout"
            save_changed_document()
            result = query_processing(snapshot, copied, collection, capability, device, 0, 10)
            assert any(row["status"] == "failed" and row["exit_code"] == 124 for row in result["coverage"])
            checks.append("failed observations retained with exit status")
        with args.output.open("x") as stream:
            stream.write(json.dumps({"collection": collection, "checks": checks, "result": "PASS"}, indent=2) + "\n")
        print(json.dumps({"checks": len(checks), "result": "PASS"}))
    finally:
        service.pool.shutdown(wait=True)


if __name__ == "__main__":
    main()
