"""Preserve observed certificate-command order and worker execution boundaries."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path

from import_macsec_algorithms import LAUNCH_PIN
from import_macsec_key_servers import parse as parse_arrangements
from validate_evidence import require


def parse(cases):
    arrangements = parse_arrangements(cases)
    records = []
    for path, arrangement in zip(map(Path, cases), arrangements):
        require(hashlib.sha256((path / "collector.source.py").read_bytes()).hexdigest() == LAUNCH_PIN,
                "Unreviewed provisioning collector")
        case = json.loads((path / "case.json").read_text())
        rows = json.loads((path / "commands.json").read_text())
        found = []
        for kind, prefix, filename in [("generation", ["openssl", "genpkey"], "peer.key"),
                                      ("request", ["openssl", "req", "-new"], "peer.csr"),
                                      ("sign", ["openssl", "x509", "-req"], "peer.pem")]:
            matches = [(i, row) for i, row in enumerate(rows) if row["command"][:len(prefix)] == prefix and
                       "-out" in row["command"] and Path(row["command"][row["command"].index("-out") + 1]).name == filename]
            require(len(matches) == 1, "Missing or ambiguous provisioning operation: " + kind)
            i, row = matches[0]
            require(row["returncode"] == 0 and row["device_id"] is None,
                    "Provisioning operation failed or execution location changed")
            found.append((i, row))
        generation, request, signed = [row for _, row in found]
        key_path = generation["command"][-1]
        parent = str(Path(key_path).parent)
        csr_path, certificate_path = parent + "/peer.csr", parent + "/peer.pem"
        require(Path(parent).name == path.name and generation["command"] ==
                ["openssl", "genpkey", "-algorithm", "ML-DSA-87", "-out", key_path],
                "Unexpected key-generation command")
        require(request["command"] == ["openssl", "req", "-new", "-key", key_path, "-out", csr_path,
                                        "-subj", "/CN=peer.msc.test"], "CSR does not use the generated key path")
        require(signed["command"] == ["openssl", "x509", "-req", "-in", csr_path,
            "-CA", parent + "/ca.pem", "-CAkey", parent + "/ca.key", "-CAcreateserial", "-days", "1",
            "-extfile", parent + "/peer.ext", "-out", certificate_path], "Signing does not use the recorded CSR")
        indices = [i for i, row in found]
        require(indices[0] < indices[1] < indices[2], "Provisioning command order changed")
        require(datetime.fromisoformat(generation["ended_at"]) <= datetime.fromisoformat(request["started_at"]) and
                datetime.fromisoformat(request["ended_at"]) <= datetime.fromisoformat(signed["started_at"]),
                "Provisioning time order changed")
        conf = (path / (case["supplicant"] + ".conf.public")).read_text()
        require('private_key="' + key_path + '"' in conf and 'client_cert="' + certificate_path + '"' in conf,
                "Supplicant configuration uses different credential paths")
        records.append({"component_id": len(records), "component": path.name + "/" + case["supplicant"],
                        "executor": "worker", "orders": indices,
                        "commands": [row["id"] for _, row in found],
                        "key_path": key_path, "csr_path": csr_path, "certificate_path": certificate_path,
                        "manifest_sha256": arrangement["manifest_sha256"]})
    return {"records": records, "whole_RG048_established": False,
            "finding": "COORD-047", "scope": [
                "The two retained supplicant cases have successful worker-level generation, CSR and signing commands in order, with matching file paths and later configuration references.",
                "The collector explicitly records device_id=null and runs these commands outside the peer network namespace. The intended certificate subject does not change that execution location.",
                "The public records do not export generated-key or CSR contents. No per-stage public-key fingerprint is invented. Matching paths are an observed command dependency, subject to correct OpenSSL execution and unchanged files.",
                "Component-local key/CSR generation required by CP6.1 is not established for these cases. A deployment repair would generate the private key and CSR within the component boundary and export only the CSR for signing.",
                "Security Administrator appointment, secured physical area, authorized CA/chain, and complete pre-use configuration remain independent requirements."
            ]}


def generate(data):
    entries = ["(" + str(row["component_id"]) + ', ProvisioningExecutor.worker "experiment-worker")' for row in data["records"]]
    orders = ["(" + ", ".join(map(str, row["orders"])) + ")" for row in data["records"]]
    return """import TDN.Targets.Provisioning

namespace TDN.Imported.FreshProvisioningLocations
open Targets

def observedExecutors : List (Nat × ProvisioningExecutor) := [""" + ", ".join(entries) + """]
def observedOrder : List (Nat × Nat × Nat) := [""" + ", ".join(orders) + """]

lemma generation_request_signing_order : ∀ row ∈ observedOrder,
    row.1 < row.2.1 ∧ row.2.1 < row.2.2 := by decide

lemma generation_is_external : ∀ row ∈ observedExecutors,
    row.2 = .worker "experiment-worker" := by decide

/-- These observations cannot discharge the component-owned generation premise.
The theorem preserves the failed requirement instead of relabeling the worker. -/
theorem recorded_worker_generation_does_not_admit_component_request
    (row : Nat × ProvisioningExecutor) (member : row ∈ observedExecutors)
    (generation request : ProvisioningEvent) (location : generation.executor = row.2)
    (kind : request.kind = .requestCertificate) :
    ¬ CertificateProvisioningPredecessor generation request := by
  exact worker_generation_cannot_supply_component_request generation request "experiment-worker"
    (location.trans (generation_is_external row member)) kind

end TDN.Imported.FreshProvisioningLocations
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", nargs="+")
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.cases)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"cases": len(data["records"]), "whole_RG048_established": False}))


if __name__ == "__main__":
    main()
