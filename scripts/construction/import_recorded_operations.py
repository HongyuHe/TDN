"""Bind selected administrative and operational clauses to retained public records."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re

from import_management import import_management
from import_service_authorization import parse_authorization, validate_public_bundle
from import_supplemental import parse_ca
from validate_evidence import require


def one(rows, message):
    require(len(rows) == 1, message)
    return rows[0]


def management(path):
    path = Path(path)
    result = import_management(path)
    snapshot = json.loads((path / "snapshot.json").read_text())
    spec = json.loads((path / "spec.json").read_text())
    devices = {d["id"]: d for d in snapshot["devices"]}
    declared = {d["id"]: d for d in spec["devices"]}
    assignments = []
    for device in devices.values():
        if device["role"] not in {"inner", "outer", "gray-firewall"}:
            continue
        require(device["role"] == declared[device["id"]]["role"], "Managed role differs")
        sample = one([s for s in result["samples"] if s["target"] == device["id"] and s["certificate"]],
                     "Missing positive management attempt")
        aw = devices[sample["source"]]
        require(aw["role"] == "admin", "Management source is not an AW")
        addresses = [a["local"] for i in snapshot["interfaces"] if i["device_id"] == aw["id"]
                     for a in i["addresses"]]
        require(declared[device["id"]]["admin"] in addresses, "Configured AW address not observed")
        assignments.append({"component": device["id"], "workstation": aw["id"],
                            "inner": device["role"] == "inner"})
    require(assignments and {a["inner"] for a in assignments} == {True, False}, "Both layers required")
    partition = {}
    for a in assignments:
        require(a["workstation"] not in partition or partition[a["workstation"]] == a["inner"],
                "One AW is assigned to both layers")
        partition[a["workstation"]] = a["inner"]
    return {"assignments": assignments, "partition": partition, "tls": result,
            "snapshot": snapshot, "path": str(path)}


def power(path):
    path = Path(path)
    data = validate_public_bundle(path)
    source = (path / "collector.source.py").read_bytes()
    require(hashlib.sha256(source).hexdigest() == POWER_COLLECTOR, "Unreviewed power collector")
    require(data["error"] is None, "Power collector did not finish its process-exit assertions")
    probes = {r["probe"]: r for r in data["records"] if "probe" in r}
    names = ["AW-authenticated-management-before-power", "AW-unavailable-while-powered-off",
             "AW-authenticated-management-after-power", "AW-final-unused-state-powered-off"]
    states = []
    times = []
    for i, name in enumerate(names):
        row = probes[name]
        command = row["command"]
        require(command[0] == "ssh" and "-p" in command and
                command[command.index("-p") + 1] == "22224" and command[-2] == "freebsd@127.0.0.1",
                "Power observation names a different guest")
        active = i in {0, 2}
        require(row["observed_result"] == ("delivered" if active else "powered-off"), "Power outcome differs")
        if active:
            require("-connect 172.28.97.2:443" in command[-1] and "-tls1_2" in command[-1],
                    "AW management endpoint differs")
            require("HTTP/1.0 200 OK" in row["stdout"] and row["stdout"].endswith("ready"),
                    "AW management was not used successfully")
        else:
            require(command[-1] == "true", "Unexpected powered-off probe")
            require(row["returncode"] != 0, "Powered-off guest still answered")
        states.append([active, active])
        times.append(datetime.fromisoformat(row["at"]))
    require(all(a < b for a, b in zip(times, times[1:])), "Power observations reordered")
    return {"states": states, "collector_sha256": POWER_COLLECTOR,
            "use_declaration": "The recorded experiment declares use during its management/restart operations and ends use at each successful named-guest process termination.",
            "scope": "Four observed states only; no claim of future automatic idle detection or physical host shutdown."}


def responses(base):
    base = Path(base)
    authorization = parse_authorization(base / "role-admin-deploy-v4", base / "role-admin-effective-v3",
                                        base / "role-admin-matrix-v3")
    matrix = validate_public_bundle(base / "role-admin-matrix-v3")
    result = []
    for row in matrix["records"]:
        c = row["command"]
        if c[0] != "curl" or "--cert" not in c or "--head" in c:
            continue
        name = Path(c[c.index("--cert") + 1]).stem
        if name not in {"auditor", "security-admin"} or not any(v.endswith(":8443/state") for v in c):
            continue
        require(row["returncode"] == 0 and row["stdout"].endswith("HTTP_STATUS=200\n"),
                "Selected role did not obtain configuration")
        data = json.loads(row["stdout"].split("\nHTTP_STATUS=")[0])
        rules = data["diagnostic_filter_rules"]
        require(rules and rules[0] == "-N EVA3_INPUT" and rules[-1] == "-A EVA3_INPUT -j RETURN",
                "Unexpected configuration response shape")
        require(all(isinstance(r, str) for r in rules), "Malformed configuration response")
        role = authorization["roles"][authorization["certificates"][name]]
        result.append({"role": role, "status": 200, "settings": rules, "at": row["at"]})
    require({r["role"] for r in result} == {"Auditor", "SecurityAdministrator"}, "Both role readbacks required")
    return result


def issuances(path):
    path = Path(path)
    verified = parse_ca(path)
    events = json.loads((path / "events.json").read_text())
    rows = events["records"]
    result = []
    for name in ["inner-a", "inner-b", "outer-a", "outer-b"]:
        request_i, request = one([(i, r) for i, r in enumerate(rows) if r["command"][:3] ==
                                 ["openssl", "req", "-new"] and "/CN=" + name + ".msc.test" in r["command"]],
                                "Component CSR command missing")
        csr = request["command"][request["command"].index("-out") + 1]
        signing_i, signing = one([(i, r) for i, r in enumerate(rows) if r["command"][:3] ==
                                 ["openssl", "x509", "-req"] and csr in r["command"]], "CSR signing missing")
        certificate = signing["command"][signing["command"].index("-out") + 1]
        container = "tcv3-ca2-enterprise-" + name
        use_i, use = one([(i, r) for i, r in enumerate(rows) if r["command"] ==
                         ["docker", "exec", container, "swanctl", "--load-all"]], "Credential loading missing")
        startup = one([r for r in rows if r["command"][:3] == ["docker", "run", "-d"] and container in r["command"]],
                      "Component container mount missing")
        mount = startup["command"][startup["command"].index("-v") + 1]
        host, guest = mount.split(":")
        require(guest == "/etc/swanctl" and certificate == host + "/x509/cert.pem", "Signed file not mounted credential")
        conf = (path / (name + ".swanctl.conf")).read_text()
        require("certs = cert.pem" in conf and "id = " + name + ".msc.test" in conf, "Configured certificate differs")
        mapping = verified["peer_issuer_mapping"][name]
        for credential in ["x509/cert.pem", "x509ca/" + mapping["issuer"] + ".pem",
                           "x509ca/" + mapping["root"] + ".pem"]:
            require("loaded certificate from '/etc/swanctl/" + credential + "'" in use["stdout"],
                    "Signed certificate and issuer/root chain not loaded")
        require(all(r["returncode"] == 0 for r in [request, signing, use, startup]), "Provisioning operation failed")
        require(request_i < signing_i < use_i, "Provisioning order reversed")
        require(signing["command"][signing["command"].index("-CA") + 1].endswith(
            "/authorities/" + mapping["issuer"] + "/cert.pem"), "Wrong layer/site signer")
        result.append({"component": name, "request": csr, "signed_request": csr,
                       "certificate": certificate, "configured_certificate": host + "/x509/cert.pem",
                       "order": [request_i, signing_i, use_i], "issuer": mapping["issuer"], "root": mapping["root"],
                       "loaded_authorities": re.findall(r"loaded certificate from '/etc/swanctl/x509ca/([^']+)\.pem'", use["stdout"])})
    return result


def retained_tests(management_data):
    snapshot = management_data["snapshot"]
    observations = {o["id"]: o for o in snapshot["observations"]}
    result = []
    for probe in snapshot["probes"]:
        for oid in probe["observation_ids"]:
            observation = observations[oid]
            relative = observation["raw_path"]
            path = Path(management_data["path"]) / relative
            require(path.is_file(), "Test result file missing")
            raw = json.loads(path.read_text())
            require(observation["command"] == probe["command"] and observation["kind"] == "probe",
                    "Test result command differs")
            require(hashlib.sha256(path.read_bytes()).hexdigest() == observation["raw_sha256"],
                    "Retained test bytes differ")
            require(json.loads(raw["stdout"])["returncode"] == probe["returncode"], "Actual test status differs")
            result.append({"id": probe["id"], "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                           "expected": probe["expected_result"], "observed": probe["observed_result"]})
    require(result and len({r["id"] for r in result}) == len(result), "Test record selection empty or duplicated")
    return result


def parse(base):
    base = Path(base)
    m = management(base / "native-management-20261024T015900Z")
    return {"assignments": m["assignments"], "partition": m["partition"],
            "tls_versions": [s["version"] for s in m["tls"]["samples"] if s["certificate"]],
            "power": power(base / "aw-power-event-v5"), "responses": responses(base),
            "issuances": issuances(base / "ca-enterprise-v2"), "retained_tests": retained_tests(m)}


def generate(d):
    q = json.dumps
    b = lambda x: str(x).lower()
    lines = ["import TDN.Requirements.RecordedOperations", "", "namespace TDN.Deployments.FreshRecordedOperations",
             "open RecordedOperations", "", "/-- Actual configured assignments, with positive authenticated management attempts. -/",
             "def assignments : List Assignment := [" + ", ".join("⟨" + q(a["component"]) + ", " +
             q(a["workstation"]) + ", " + b(a["inner"]) + "⟩" for a in d["assignments"]) + "]",
             "def partition (aw : String) : Bool := " + " || ".join("aw == " + q(k) for k, v in d["partition"].items() if v),
             "lemma assignments_checked : AssignmentChecks assignments partition := by",
             "  unfold AssignmentChecks assignments partition; decide",
             "theorem assigned_workstations_do_not_cross_layers (a b : Assignment)",
             "    (ha : a ∈ assignments) (hb : b ∈ assignments) (different : a.inner ≠ b.inner) :",
             "    a.workstation ≠ b.workstation :=",
             "  administrative_assignments_do_not_share_layers assignments partition assignments_checked a b ha hb different",
             "", "def tlsVersions : List String := " + q(d["tls_versions"]),
             "lemma tls_versions_checked : ∀ v ∈ tlsVersions, tlsProtection v = some .tls13 := by",
             "  unfold tlsVersions tlsProtection; decide",
             "theorem observed_management_uses_allowed_protocol (v : String) (member : v ∈ tlsVersions) :",
             "    ∃ p, tlsProtection v = some p ∧ Requirements.ApprovedManagementProtocol p :=",
             "  ⟨.tls13, tls_versions_checked v member, recognized_tls_is_allowed v .tls13 (tls_versions_checked v member)⟩",
             "", "/-- Use windows are declarations from the recorded experiment; power state is observed. -/",
             "def powerStates : List PowerState := [" + ", ".join("⟨" + b(a) + ", " + b(c) + "⟩" for a, c in d["power"]["states"]) + "]",
             "lemma power_transitions_checked : PowerStep (powerStates[0]!) (powerStates[1]!) ∧",
             "    PowerStep (powerStates[1]!) (powerStates[2]!) ∧ PowerStep (powerStates[2]!) (powerStates[3]!) := by",
             "  unfold PowerStep powerStates; decide",
             "theorem recorded_use_finishes_powered_off : UnusedIsOff (powerStates[3]!) := by",
             "  apply power_trace_keeps_unused_guest_off (first := powerStates[0]!)",
             "  · unfold UnusedIsOff powerStates; decide",
             "  · exact ((Relation.ReflTransGen.single power_transitions_checked.1).tail",
             "      power_transitions_checked.2.1).tail power_transitions_checked.2.2",
             "lemma final_guest_is_unused : (powerStates[3]!).inUse = false := by native_decide",
             "theorem final_guest_is_off : (powerStates[3]!).poweredOn = false :=",
             "  recorded_use_finishes_powered_off final_guest_is_unused", ""]
    for role, name in [("Auditor", "auditor"), ("SecurityAdministrator", "administrator")]:
        r = next(r for r in d["responses"] if r["role"] == role)
        lines += ["def " + name + "Response : ConfigurationResponse := ⟨" + q(role) + ", 200, " + q(r["settings"]) + "⟩",
                  "def " + name + "Configuration : List String := " + q(r["settings"]),
                  "lemma " + name + "_readback_checked : " + name + "Response.settings = " + name + "Configuration := by native_decide",
                  "theorem " + name + "_obtained_configuration : AvailableThrough " + name + "Response " + q(role) + " " + name + "Configuration :=",
                  "  successful_readback_makes_settings_available _ _ _ rfl rfl " + name + "_readback_checked", ""]
    lines += ["def issuances : List Issuance := [" + ",\n  ".join("⟨" + ", ".join([q(r[k]) for k in ["request", "signed_request", "certificate", "configured_certificate"]] + [str(n) for n in r["order"]] + [q(r["issuer"]), q(r["root"]), q(r["loaded_authorities"])]) + "⟩" for r in d["issuances"]) + "]",
              "lemma issuance_checks : ∀ i ∈ issuances, IssuanceChecked i := by unfold issuances IssuanceChecked; decide",
              "theorem loaded_credentials_follow_signed_requests (i : Issuance) (member : i ∈ issuances) :",
              "    i.requestOutput = i.signedRequest ∧ i.certificateOutput = i.configuredCertificate ∧ i.requestOrder < i.useOrder ∧",
              "    i.signer ∈ i.loadedAuthorities ∧ i.trustAnchor ∈ i.loadedAuthorities :=",
              "  issued_credential_follows_request i (issuance_checks i member)", "",
              "def selectedTests : List String := " + q([r["id"] for r in d["retained_tests"]]),
              "def savedResults : List (String × String) := [" + ", ".join("(" + q(r["id"]) + ", " + q(r["path"]) + ")" for r in d["retained_tests"]) + "]",
              "def resultPath (id : String) : String := " + "".join("if id = " + q(r["id"]) + " then " + q(r["path"]) + " else " for r in d["retained_tests"]) + '""',
              "lemma result_lookup_checked : ∀ id ∈ selectedTests, (id, resultPath id) ∈ savedResults ∧ resultPath id ≠ \"\" := by",
              "  unfold selectedTests savedResults resultPath; decide",
              "theorem selected_network_test_results_are_retained : ResultsRetained selectedTests savedResults :=",
              "  retained_table_covers_selected_tests selectedTests savedResults resultPath",
              "    (fun id member => (result_lookup_checked id member).1)",
              "    (fun id member => (result_lookup_checked id member).2)",
              "", "end TDN.Deployments.FreshRecordedOperations", ""]
    return "\n".join(lines)


POWER_COLLECTOR = "91bc0af409f2786d658a30595aca169aaa937dab8b1b2a7f08c15de5c35aceb2"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--report", required=True)
    a = p.parse_args()
    d = parse(a.base)
    d["scope"] = [
        "RG044 covers configured Inner/Outer/Gray-Firewall AW assignments, not all possible administration paths or physical isolation.",
        "RG045 covers four observed states and declared experiment use windows, not future idle detection.",
        "RG046 covers fourteen positive observed TLS management sessions, not all traffic or Black transit.",
        "RG048 covers four CSR/signing/configuration-load chains. Worker generation remains noncompliant. Correct crypto/file execution, unchanged paths and accurate runtime logs are trusted; unique signed bytes, component generation and human authorization are not proved.",
        "RG058 covers the Auditor role's access to one saved configuration fragment. Maintaining every component baseline and actual human appointment remain unproved.",
        "RG068 covers the administrator role's actual monitoring readback of one security function. Complete ongoing personnel duties remain unproved.",
        "RG072 covers retained raw results for the declared network test selection, including their actual outcomes. The selection is not asserted to equal the missing Testing Annex.",
        "All snapshot collection, source-to-runtime matching and trusted implementation assumptions remain explicit; optional management does not gate data-path theorems."
    ]
    Path(a.output).write_text(generate(d))
    Path(a.report).write_text(json.dumps(d, indent=2) + "\n")
    print(json.dumps({"assignments": len(d["assignments"]), "positive_tls_sessions": len(d["tls_versions"]),
                      "issuances": len(d["issuances"]), "retained_tests": len(d["retained_tests"])}))


if __name__ == "__main__":
    main()
