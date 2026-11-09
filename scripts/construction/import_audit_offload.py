"""Check retained audit-copy coverage and one observed collector service restart."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re

from import_macsec_runtime import validate_files
from validate_evidence import require


PINS = {
    "audit-protected-offload-v5/audit_collector_v3.py": "e3fc837440beafa6d2712e94bb92db1214bab8875031ada0e0f42af29ba29ef6",
    "audit-protected-offload-v5/audit_export_client_v3.go": "5c74730b40525a30bce328828b720cdd8bf1b11a87c9d75689688e0eb1e028ce",
    "audit-protected-offload-v5/audit_offload_experiment_v5.py": "3caa0bd9bd69988199ccd68894e55aad4b556933cde066715afa3bad22758647",
    "audit-source-drain-v10/collector.source.py": "c0bd82e9fea1d58edb45e213f83d1c91c1439872012ee334699af94b5ab6ae22",
    "audit-collector-reliability-v8/collector.source.py": "f6765a691401dd13a49aa37ccfeacfd5affe24056fa990a72f4a341ca05bea5c",
    "audit-collector-readback-v7/collector.source.py": "5be3fa9b0ec7458ab3f3dd4be1cc2965f2f06bbaec38d7a7371ceb9fc943a3c9",
    "audit-collector-readback-v7/audit_collector_v3.py": "e3fc837440beafa6d2712e94bb92db1214bab8875031ada0e0f42af29ba29ef6",
}


def digest(text):
    require(isinstance(text, str) and re.fullmatch(r"[0-9a-f]{64}", text), "Invalid public fingerprint")
    return text


def record_by(rows, field, value):
    matches = [row for row in rows if row.get(field) == value]
    require(len(matches) == 1, "Missing or duplicate observation: " + str(value))
    return matches[0]



def source_guest_command(row, identity=None):
    command = row.get("command", [])
    require(command[:3] == ["ssh", "-o", "BatchMode=yes"] and
            len(command) in {9, 11}, "Wrong source guest command")
    offset = 3
    if len(command) == 11:
        require(command[3:5] == ["-o", "ConnectTimeout=5"], "Unreviewed source SSH options")
        offset = 5
    require(command[offset] == "-i" and
            command[offset + 2:-1] == ["-p", "22352", "root@127.0.0.1"] and
            isinstance(command[offset + 1], str) and command[offset + 1],
            "Wrong source guest command")
    require(identity is None or command[offset + 1] == identity,
            "Source guest identity path differs")
    require(row["returncode"] == 0, "Failed source command")
    return command[-1], command[offset + 1]


def parse(base):
    base = Path(base)
    inputs = {}
    manifests = {}
    for name in sorted({path.split("/")[0] for path in PINS}):
        manifests[name] = validate_files(base / name)
        data = json.loads((base / name / "observations.json").read_text())
        require("error" in data and data["error"] is None, "Incomplete collection: " + name)
        inputs[name] = data["records"]
        for row in data["records"]:
            if "returncode" in row and "probe" not in row:
                require(type(row["returncode"]) is int and row["returncode"] == 0,
                        "Failed collection command")
    for relative, expected in PINS.items():
        require(hashlib.sha256((base / relative).read_bytes()).hexdigest() == expected,
                "Reviewed audit source changed")

    initial = inputs["audit-protected-offload-v5"]
    source = record_by(initial, "id", "offload-0012")
    require(source["returncode"] == 0 and
            "cp /var/log/auth.log /var/db/tdn-audit-exporter/actual-audit-source.log" in source["command"][-1],
            "Actual source copy command missing")
    marker = source["stdout"].strip()
    require("owned-protected-offload-" in marker and len(marker.splitlines()) == 1,
            "Actual source marker missing")
    source_command, guest_identity = source_guest_command(source)
    marker_ids = re.findall(r"owned-protected-offload-[0-9]{8}T[0-9]{6}Z", marker)
    require(len(marker_ids) == 1, "Source marker identity is ambiguous")
    marker_id = marker_ids[0]
    source_file = "/var/db/tdn-audit-exporter/actual-audit-source.log"
    cursor_file = "/var/db/tdn-audit-exporter/cursor.json"
    require(source_command == "logger -p auth.notice -t tdn-audit " + marker_id +
            "; sleep 1; fsync /var/log/auth.log; cp /var/log/auth.log " + source_file +
            "; fsync " + source_file + "; grep -F " + marker_id + " " + source_file,
            "Wrong source copy operation")
    first_ack = record_by(initial, "id", "offload-0013")
    export_command, _ = source_guest_command(first_ack, guest_identity)
    expected_export = ("/var/db/tdn-audit-exporter/audit-export-client --url https://198.22.255.18:43463/v1/audit "
                       "--log /var/db/tdn-audit-exporter/actual-audit-source.log "
                       "--ca /var/db/tdn-audit-exporter/tls/ca.pem "
                       "--cert /var/db/tdn-audit-exporter/tls/client.pem "
                       "--key /var/db/tdn-audit-exporter/tls/client.key "
                       "--cursor /var/db/tdn-audit-exporter/cursor.json")
    require(export_command == expected_export, "Wrong source export operation")
    hash_row = record_by(initial, "id", "offload-0017")
    hash_command, _ = source_guest_command(hash_row, guest_identity)
    require(hash_command == "test ! -e /var/db/tdn-audit-exporter/denied-cursor.json; "
            "test ! -e /var/db/tdn-audit-exporter/untrusted-cursor.json; cat " + cursor_file +
            "; sha256 " + source_file, "Wrong original source hash operation")
    ack = re.fullmatch(r"acknowledged offset=(\d+) next=(\d+) bytes=(\d+) sha256=([0-9a-f]{64}) duplicate=false TLS=1\.3\n?",
                       first_ack["stdout"])
    require(first_ack["returncode"] == 0 and ack is not None, "First durable acknowledgement missing")
    raw_source_hash = record_by(initial, "id", "offload-0017")["stdout"].split(" = ")[-1].strip()
    digest(raw_source_hash)

    restart_rows = inputs["audit-collector-reliability-v8"]
    require(len(restart_rows) == 3, "Unexpected restart observation inventory")
    before = record_by(restart_rows, "label", "before-restart")
    after = record_by(restart_rows, "label", "after-restart")
    restarted = record_by(restart_rows, "operation", "owned-service-restart")
    process = record_by(inputs["audit-collector-readback-v7"], "label", "server-owned-process")
    require(restarted["old_pid"] == process["pid"] and restarted["new_pid"] != restarted["old_pid"] and
            restarted["command"] == process["argv"] and
            Path(restarted["command"][1]).name == "audit_collector_v3.py", "Collector restart identity mismatch")
    require(datetime.fromisoformat(process["at"]) < datetime.fromisoformat(before["at"]) <
            datetime.fromisoformat(after["at"]) <= datetime.fromisoformat(restarted["at"]),
            "Collector observation order mismatch")
    require(before["records"] == after["records"] and
            digest(before["journal_sha256"]) == digest(after["journal_sha256"]) and
            before["file_mode"] == after["file_mode"] == "0o600", "Journal changed across observed restart")
    require(before["actual_audit_markers"] == after["actual_audit_markers"] == [marker],
            "Full source marker absent from copied journal")
    journal = after["records"]
    require(journal, "Empty committed journal")
    next_offset = 0
    for batch in journal:
        require(set(batch) == {"device", "offset", "next", "bytes", "sha256", "peer_cn", "tls_version", "tls_cipher"},
                "Incomplete or unexpected public transaction fields")
        require(batch["device"] == batch["peer_cn"] == "NC-I-A" and
                batch["tls_version"] == "TLSv1.3" and batch["tls_cipher"] == "TLS_AES_256_GCM_SHA384",
                "Transaction identity or protected-channel metadata differs")
        require(all(type(batch[key]) is int for key in ["offset", "next", "bytes"]) and
                batch["offset"] == next_offset and 0 < batch["bytes"] <= 65536 and
                batch["next"] == batch["offset"] + batch["bytes"], "Journal has a gap, overlap or invalid range")
        digest(batch["sha256"])
        next_offset = batch["next"]
    require([int(ack[i]) for i in [1, 2, 3]] == [journal[0][k] for k in ["offset", "next", "bytes"]] and
            ack[4] == journal[0]["sha256"], "First acknowledged batch differs from retained journal")

    drain = inputs["audit-source-drain-v10"]
    require(len(drain) == 4, "Unexpected source drain inventory")
    command_rows = [row for row in drain if "command" in row]
    require(len(command_rows) == 3 and all(row["command"][:3] == ["ssh", "-o", "BatchMode=yes"] and
            row["command"][5:8] == ["-p", "22352", "root@127.0.0.1"] and row["returncode"] == 0
            for row in command_rows), "Wrong source guest or failed drain command")
    first, empty, final = command_rows
    for row in command_rows:
        source_guest_command(row, guest_identity)
    require(empty["command"][-1] == expected_export, "Wrong final export operation")
    require(final["command"][-1] == "cat " + cursor_file + "; stat -f %z " + source_file +
            "; sha256 " + source_file, "Wrong final source readback operation")
    require(first["command"][-1] == "stat -f %z /var/db/tdn-audit-exporter/actual-audit-source.log; cat /var/db/tdn-audit-exporter/cursor.json",
            "Wrong initial source size/cursor command")
    size_text, cursor_text = first["stdout"].split("\n", 1)
    require(size_text.isdecimal(), "Invalid source size")
    source_bytes = int(size_text)
    require(json.loads(cursor_text) == {"offset": source_bytes}, "Source cursor has not reached EOF")
    require(empty["stdout"] == "no new audit bytes\n" and
            "--log /var/db/tdn-audit-exporter/actual-audit-source.log" in empty["command"][-1] and
            "--cursor /var/db/tdn-audit-exporter/cursor.json" in empty["command"][-1],
            "No complete-source empty-read observation")
    final_match = re.fullmatch(r'\{"offset":(\d+)\}(\d+)\nSHA256 \(/var/db/tdn-audit-exporter/actual-audit-source\.log\) = ([0-9a-f]{64})\n', final["stdout"])
    require(final_match is not None and int(final_match[1]) == int(final_match[2]) == source_bytes == next_offset and
            final_match[3] == raw_source_hash, "Final source copy or complete cursor changed")
    require(datetime.fromisoformat(after["at"]) < datetime.fromisoformat(first["at"]) <
            datetime.fromisoformat(empty["at"]) < datetime.fromisoformat(final["at"]), "Source readback order mismatch")
    return {"source_bytes": source_bytes, "source_sha256": raw_source_hash, "journal": journal,
            "before": before, "after": after, "manifests": manifests, "source_pins": PINS,
            "whole_RG062_established": False,
            "scope": [
                "Complete byte-range coverage of one frozen source copy and unchanged public journal metadata/hash across one observed service restart.",
                "Source bodies remain private. Hash correctness, faithful collector output, source-to-runtime correspondence and proper TLS/filesystem implementation are explicit assumptions.",
                "Successful complete record writes are fsynced before server acknowledgement; client offset advances after matching acknowledgement. The Lean range theorem does not establish every crash interleaving or torn-write recovery.",
                "An explicitly run finite-batch transfer supplies the evidence. Automatic startup, source rotation, later log growth, power-loss behavior, calendar-year retention, quarterly reviews and organizational procedures remain separate.",
                "The journal stores TLS and peer identity metadata. The range proof does not itself prove cryptographic confidentiality or complete certificate conformance."
            ]}


def generate(data):
    def entries(rows):
        return "[" + ", ".join("⟨" + ", ".join([str(row["offset"]), str(row["next"]), str(row["bytes"]), json.dumps(row["sha256"])]) + "⟩" for row in rows) + "]"
    return """import TDN.Requirements.AuditOffload

namespace TDN.Deployments.FreshAuditOffload
open OffloadJournal Requirements

def sourceBytes : Nat := """ + str(data["source_bytes"]) + """
def beforeRestart : List Batch := """ + entries(data["before"]["records"]) + """
def afterRestart : List Batch := """ + entries(data["after"]["records"]) + """

lemma local_range_checks : Contiguous 0 beforeRestart := by decide
lemma local_complete_cursor : finish 0 beforeRestart = sourceBytes := by decide
lemma local_restart_identity : afterRestart = beforeRestart := by decide

/-- Three local range checks cover every byte position in the frozen source copy. -/
theorem all_recorded_source_positions_copied : RecordedAuditCopy sourceBytes beforeRestart :=
  complete_audit_copy_from_contiguous_batches sourceBytes beforeRestart
    local_range_checks local_complete_cursor

theorem observed_service_restart_keeps_copy : RecordedAuditCopy sourceBytes afterRestart :=
  observed_restart_preserves_audit_copy sourceBytes beforeRestart afterRestart
    all_recorded_source_positions_copied local_restart_identity

end TDN.Deployments.FreshAuditOffload
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.base)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"source_bytes": data["source_bytes"], "batches": len(data["journal"]), "whole_RG062_established": False}))


if __name__ == "__main__":
    main()
