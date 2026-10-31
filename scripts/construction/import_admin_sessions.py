"""Bind retained administration outcomes to source-derived authentication witnesses."""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import shlex

from import_service_authorization import parse_authorization, validate_public_bundle, require


def parse(deployment, effective, matrix):
    authorization = parse_authorization(deployment, effective, matrix)
    bundles = {name: Path(value) for name, value in
               [("deployment", deployment), ("effective", effective), ("matrix", matrix)]}
    observations = {name: validate_public_bundle(path) for name, path in bundles.items()}
    require(all("error" in value and value["error"] is None for value in observations.values()),
            "Explicit successful collection status required")
    effective_rows = observations["effective"]["records"]
    require(all(row["command"][:3] == ["docker", "exec", "ND_O_A1"] and
                row["returncode"] == 0 for row in effective_rows),
            "Successful service-local effective observations required")
    socket_rows = [row for row in effective_rows
                   if row["command"] == ["docker", "exec", "ND_O_A1", "ss", "-lntp"]]
    process_rows = [row for row in effective_rows
                    if row["command"] == ["docker", "exec", "ND_O_A1", "ps", "-eo", "pid,user,comm,args"]]
    require(len(socket_rows) == 1 and len(process_rows) == 1,
            "Complete listener and process observations required")
    listeners = [line for line in socket_rows[0]["stdout"].splitlines()
                 if len(line.split()) >= 5 and line.split()[3] == "172.28.96.2:8443"]
    require(len(listeners) == 1 and listeners[0].split()[0] == "LISTEN",
            "Unique administration listener required")
    identities = re.findall(r'\("([^"]+)",pid=(\d+),fd=\d+\)', listeners[0])
    require(len(identities) == 1 and identities[0][0] == "python3",
            "Listener must identify its Python process")
    pid = identities[0][1]
    processes = [line.split(None, 3) for line in process_rows[0]["stdout"].splitlines()
                 if line.split() and line.split()[0] == pid]
    require(len(processes) == 1 and len(processes[0]) == 4 and
            processes[0][2] == "python3" and shlex.split(processes[0][3]) ==
            ["python3", "-u", "/root/role-admin-v4/service.py", "/root/role-admin-v4"],
            "Listener PID must run the reviewed administration source path")
    audit_files = {}
    for row in effective_rows:
        command = row["command"]
        if command[3] == "cat" and command[-1].endswith(".jsonl"):
            require(len(command) == 5 and Path(command[-1]).parent == Path("/root/role-admin-v4"),
                    "Unexpected audit command")
            name = Path(command[-1]).name
            require(name not in audit_files, "Duplicate audit file observation")
            audit_files[name] = [json.loads(line) for line in row["stdout"].splitlines()]
    require("audit.jsonl" in audit_files, "Current audit file missing")
    rotated = sorted(name for name in audit_files if name != "audit.jsonl")
    require(rotated == ["audit-%04d.jsonl" % number for number in range(1, len(rotated) + 1)],
            "Audit rotation sequence has a gap")
    audit = [event for name in [*rotated, "audit.jsonl"] for event in audit_files[name]]
    require(audit, "Empty service audit")
    require(len({event["at"] for event in audit}) == len(audit), "Ambiguous audit event identity")
    for event in audit:
        timestamp = datetime.fromisoformat(event["at"])
        require(timestamp.tzinfo is not None and timestamp.utcoffset().total_seconds() == 0,
                "Audit timestamp must have a UTC offset")
        require(event["role"] == authorization["roles"].get(event["fingerprint"], "Unmapped"),
                "Audit role differs from the effective credential map")
        require(event["status"] in {200, 403}, "Unhandled operation outcome")
    observed = authorization["observed"]
    recorded_counts = Counter((row["fingerprint"], row["method"], row["path"], row["status"])
                              for row in audit)
    client_counts = Counter((row["fingerprint"], row["method"], row["path"],
                             200 if row["allowed"] else 403) for row in observed)
    require(recorded_counts == client_counts, "Server audit differs from the complete client outcome inventory")
    calls = [row for row in observations["matrix"]["records"]
             if row.get("command", [None])[0] == "curl" and
             row["command"][-1] == "https://managed.nd.test:8443/audit"]
    require(calls, "Final audit readback missing")
    last_call = calls[-1]
    body, marker = last_call["stdout"].rsplit("HTTP_STATUS=", 1)
    require(last_call["returncode"] == 0 and marker.strip() == "200", "Final audit readback failed")
    readback = json.loads(body.strip())["events"]
    require(readback == audit[:-1] and audit[-1]["method"] == "GET" and
            audit[-1]["path"] == "/audit" and audit[-1]["status"] == 200,
            "Final readback does not cover every earlier retained audit event")
    accepted = [row for row in audit if row["status"] == 200]
    require(accepted, "No successful administrative operation")
    principals = sorted(authorization["roles"])
    return {
        "bundles": {name: {"path": str(path), "manifest_sha256":
                            hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest()}
                    for name, path in bundles.items()},
        "service": "ND_O_A1 certificate-authenticated administration HTTP service",
        "source_sha256": authorization["source_sha256"],
        "listener_process": {"address": "172.28.96.2:8443", "pid": int(pid),
                             "source_path": "/root/role-admin-v4/service.py"},
        "principals": [{"id": index, "fingerprint": fingerprint,
                        "role": authorization["roles"][fingerprint]}
                       for index, fingerprint in enumerate(principals)],
        "audit_files": [*rotated, "audit.jsonl"], "audit_outcomes": len(audit),
        "accepted": accepted, "rejected_outcomes": len(audit) - len(accepted),
        "authentication_witness_basis": [
            "The pinned service source requires a client certificate at the TLS handshake before HTTP handling.",
            "Each handler reads the TLS peer certificate fingerprint and checks its role before executing an allowed operation.",
            "Each modeled request receives a distinct logical session name. The names and two causal phase numbers are generated proof witnesses, not exported TLS session identifiers or measured authentication timestamps.",
            "The operation token is the peer fingerprint used directly by this service. The source has no separately supplied bearer token.",
            "Accounts represent the two installed certificate identities. The numeric person field identifies those credentials; correspondence to individual humans is unprovided."
        ],
        "scope_limits": [
            "The application covers the retained successful requests and their matching server audit outcomes.",
            "TLS/OpenSSL, Python dispatch, unchanged loaded source and truth of collector records remain implementation assumptions.",
            "The per-request authentication witnesses describe each handler's local authorization interval. They do not assert completeness of external credential-revocation events or export an independent TLS connection history.",
            "No AW account roster is represented, and no CNSA-certificate or NIST objective is selected in this service-only application.",
            "Human ownership, other administration services, failed partially executed operations and all future executions remain separate obligations. Whole RG047 compliance is unproved."
        ]}


def generate(data):
    quote = json.dumps
    principals = {row["fingerprint"]: row["id"] for row in data["principals"]}
    lines = ["import TDN.Targets.Administration", "", "namespace TDN.Imported.FreshAdministratorSessions",
             "open Targets", "set_option maxRecDepth 100000", "set_option maxHeartbeats 0", "",
             "/-- Credential identities are modeled here. Human appointments and AW accounts remain external. -/",
             "def accounts : List AdministrativeAccount := [" + ", ".join(
                 "⟨" + str(row["id"]) + ", 0, " + quote(row["fingerprint"]) + ", false, false, 0⟩"
                 for row in data["principals"]) + "]", ""]
    session_rows = []
    actions = []
    for index, row in enumerate(data["accepted"]):
        person = principals[row["fingerprint"]]
        fingerprint = quote(row["fingerprint"])
        session = quote("audit-request-" + str(index))
        before, after = 2 * index + 1, 2 * index + 2
        session_rows.append("⟨" + ", ".join([session, str(person), "0", str(before),
                                              fingerprint, fingerprint]) + "⟩")
        for kind, order in [("authentication", before), ("operation", after)]:
            name = ("authentication" if kind == "authentication" else "operation") + str(index)
            lines.append("def " + name + " : AdminEvent := ⟨." + kind + ", " +
                         ", ".join([str(person), "0", str(order), fingerprint, "false", "false", session]) + "⟩")
            actions.append(name)
    lines += ["", "/-- Session names and causal orders are witnesses derived from the reviewed handler sequence. -/",
              "def sessions : List AdministrativeSession := [" + ", ".join(session_rows) + "]",
              "def events : List AdminEvent := [" + ", ".join(reversed(actions)) + "]",
              "def actions : List AdminEvent := [" + ", ".join(actions) + "]",
              "def needsAuthentication (event : AdminEvent) : Prop := event.kind = .operation",
              "def prerequisite := MatchingAdministratorAuthentication false false events accounts sessions", ""]
    for index, action in enumerate(actions):
        history = "[" + ", ".join(reversed(actions[:index])) + "]"
        result = "[" + ", ".join(reversed(actions[:index + 1])) + "]"
        lines += ["lemma step" + str(index) + " : (Admission.lts needsAuthentication prerequisite).Tr " +
                  history + " " + action + " " + result + " := by",
                  "  apply Admission.Step.record",
                  "  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, " + ", ".join(actions) + "]", ""]
    proof = "Cslib.LTS.MTr.refl"
    for index in reversed(range(len(actions))):
        proof = "Cslib.LTS.MTr.stepL step" + str(index) + " (" + proof + ")"
    lines += ["lemma admitted_history : (Admission.lts needsAuthentication prerequisite).MTr [] actions events := by",
              "  exact " + proof, "",
              "/-- The result is limited to the retained service requests. The import report records the source contract. -/",
              "theorem recorded_service_authentication :",
              "    msc_administrator_authentication false false events accounts sessions [] := by",
              "  apply administrator_authentication_from_admitted_operations false false events actions accounts sessions [] (fun _ => 0)",
              "  · exact admitted_history", "  · decide", "  · simp", "",
              "theorem successful_operations_are_present :",
              "    (events.filter (fun event => event.kind == .operation)).length = " + str(len(data["accepted"])) + " := by decide",
              "", "end TDN.Imported.FreshAdministratorSessions", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    for name in ["deployment", "effective", "matrix", "output", "report"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    data = parse(args.deployment, args.effective, args.matrix)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"audit_outcomes": data["audit_outcomes"], "successful_operations": len(data["accepted"]),
                      "whole_RG047_established": False}))


if __name__ == "__main__":
    main()
