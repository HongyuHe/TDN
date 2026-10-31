"""Bind native component roles to independently observed worker hardware identities."""
import argparse
import hashlib
import json
from pathlib import Path

from import_service_authorization import require, validate_public_bundle

ROLE = {"inner": "inner", "outer": "outer", "outer-firewall": "outerFirewall",
        "firewall": "outerFirewall", "gray-firewall": "grayFirewall", "inner-firewall": "innerFirewall",
        "host": "other", "switch": "other", "transport": "other"}


def one(records, command):
    found = [record for record in records if record.get("command") == command]
    require(len(found) == 1 and found[0]["returncode"] == 0, "Missing or duplicate observation: " + repr(command))
    return found[0]


def parse_worker(before_path, after_path, helper_path=None):
    before_path, after_path = Path(before_path), Path(after_path)
    before, after = validate_public_bundle(before_path), validate_public_bundle(after_path)
    require(before["error"] is None and after["error"] is None, "Worker collection failed")
    spec = json.loads((before_path / "spec.json").read_text())
    require(spec == json.loads((after_path / "spec.json").read_text()), "Before/after source specification changed")
    require(before["assignments"] == after["assignments"], "Before/after role assignment changed")
    require(before["selected_device_ids"] == after["selected_device_ids"], "Before/after device inventory changed")
    worker = before["worker"]
    require(after["worker"] == worker, "Worker identity changed")
    declared = {device["id"]: device for device in spec["devices"]}
    require(set(declared) == set(before["assignments"]), "Assignments omit declared devices")
    expected = {device for device, assigned in before["assignments"].items() if assigned == worker}
    require(expected == set(before["selected_device_ids"]), "Selected device inventory incomplete")
    helper_data = None
    helper_names = set()
    if helper_path is not None:
        helper_path = Path(helper_path)
        helper_observations = validate_public_bundle(helper_path)
        require(helper_observations["error"] is None, "Helper collection failed")
        helper_data = json.loads((helper_path / "bindings.json").read_text())
        require(helper_data["worker"] == worker, "Helper worker mismatch")
        helper_names = {binding["helper"]["name"] for binding in helper_data["bindings"]}
        observed_helpers = {name for name in one(helper_observations["records"],
            ["docker", "ps", "--format", "{{.Names}}"])["stdout"].splitlines()
            if name.startswith("MW_") and name.endswith("-frr")}
        require(helper_names == observed_helpers, "Helper identity inventory incomplete")
    phases = []
    for bundle in [before, after]:
        records = bundle["records"]
        hardware = one(records, ["cat", "/sys/class/dmi/id/product_uuid"])
        uuid = hardware["stdout"].strip().lower()
        require(len(uuid) == 36 and len(uuid.replace("-", "")) == 32, "Invalid physical hardware UUID")
        processes = one(records, ["docker", "ps", "--format", "{{.Names}} {{.Image}} {{.Status}}"])
        running = {line.split()[0] for line in processes["stdout"].splitlines() if line.startswith("MW_")}
        require(running == expected | helper_names, "Actual running scenario containers differ from selected inventory")
        devices = {}
        for device in sorted(expected):
            inspected = one(records, ["docker", "inspect", "--format", "{{json .}}", device])
            state = json.loads(inspected["stdout"])
            require(state["Name"] == "/" + device and state["State"]["Running"] is True, "Wrong or stopped container")
            pid = state["State"]["Pid"]
            require(isinstance(pid, int) and pid > 0, "Missing running namespace PID")
            namespace = one(records, ["readlink", "/proc/" + str(pid) + "/ns/net"])
            require(namespace["stdout"].strip().startswith("net:["), "Invalid network namespace identity")
            require(declared[device]["role"] in ROLE, "Unrecognized component role")
            devices[device] = {"role": ROLE[declared[device]["role"]], "physicalDevice": uuid,
                               "container_id": state["Id"], "pid": pid,
                               "namespace": namespace["stdout"].strip(),
                               "hardware_observation": hardware["id"], "container_observation": inspected["id"]}
        phases.append({"hardware": uuid, "devices": devices, "start": bundle["started_at"], "end": bundle["ended_at"]})
    require(phases[0]["hardware"] == phases[1]["hardware"], "Hardware identity changed across interval")
    for device in expected:
        require(phases[0]["devices"][device]["container_id"] == phases[1]["devices"][device]["container_id"],
                "Container replaced across interval")
    if helper_data is not None:
        require(helper_data["hardware_uuid"] == phases[0]["hardware"], "Helper hardware differs from parent worker")
        for binding in helper_data["bindings"]:
            helper, parent = binding["helper"], binding["parent"]
            require(parent["name"] in expected, "Helper targets an undeclared parent")
            previous = phases[0]["devices"][parent["name"]]
            require(parent["id"] == previous["container_id"] and parent["pid"] == previous["pid"] and
                    parent["network_namespace"] == previous["namespace"], "Parent identity changed before helper capture")
            require(helper["running"] and parent["running"], "Stopped helper or parent")
            require(helper["network_mode"] == "container:" + parent["id"], "Helper network-mode target mismatch")
            require(helper["network_namespace"] == parent["network_namespace"], "Helper has a distinct network namespace")
            require(helper["labels"].get("twinet.frr-control") == "true" and
                    helper["labels"].get("twinet.msc.device") == parent["name"], "Helper role binding mismatch")
    return {"worker": worker, "hardware": phases[0]["hardware"], "phases": phases,
            "spec": spec, "assignments": before["assignments"],
            "helper_bindings": helper_data,
            "bundles": [str(before_path), str(after_path)] + ([str(helper_path)] if helper_path else [])}


def generate(workers):
    q = json.dumps
    devices = {}
    for worker in workers:
        for name, value in worker["phases"][0]["devices"].items():
            require(name not in devices, "Device appears on multiple workers")
            devices[name] = value
    roles = {}
    for value in devices.values():
        if value["role"] != "other":
            roles.setdefault(value["role"], set()).add(value["physicalDevice"])
    require(set(devices) == {device["id"] for device in workers[0]["spec"]["devices"]},
            "Combined inventory omits declared devices")
    separated_pairs = [("inner", "outer"), ("outerFirewall", "outer"),
                       ("outerFirewall", "grayFirewall"), ("outerFirewall", "inner"),
                       ("grayFirewall", "outer"), ("grayFirewall", "inner"),
                       ("innerFirewall", "inner")]
    for left, right in separated_pairs:
        require(roles.get(left, set()).isdisjoint(roles.get(right, set())),
                "Required role classes share physical hardware")
    lines = ["import TDN.Targets.Components", "", "namespace TDN.Imported.FreshPhysicalPartition",
             "", "def components : List Targets.Component := ["]
    rows = []
    for name, value in sorted(devices.items()):
        if value["role"] == "other":
            continue
        rows.append("  { identity := " + q(name) + ', product := ⟨"", "", "", .other⟩, role := .' +
                    value["role"] + ", physicalDevice := " + q(value["physicalDevice"]) +
                    ', osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", ' +
                    'evaluatedConfiguration := "", installedConfiguration := "", modifications := [] }')
    lines.extend([",\n".join(rows) + "]", "",
                  "def hardwareForRole : Targets.ComponentRole → List String"])
    for role, hardware in sorted(roles.items()):
        lines.append("  | ." + role + " => [" + ", ".join(q(item) for item in sorted(hardware)) + "]")
    lines.extend(['  | _ => []', "",
                  "/-- Unknown product/approval fields are unused by this physical-separation result. -/",
                  "theorem captured_role_pairs_are_physically_distinct :",
                  "    Targets.msc_physically_distinct_security_components components := by",
                  "  apply Targets.physical_separation_from_disjoint_role_hardware components hardwareForRole",
                  "  · unfold components hardwareForRole; decide",
                  "  · intro a b; cases a <;> cases b <;> unfold Targets.SeparationRequired hardwareForRole <;> decide",
                  "", "end TDN.Imported.FreshPhysicalPartition", ""])
    return "\n".join(lines), devices


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    base = Path(args.snapshot_root)
    workers = [parse_worker(base / ("multiworker-" + worker + "-collect-before-v3"),
                            base / ("multiworker-" + worker + "-collect-after-v3"),
                            base / ("multiworker-" + worker + "-sidecar-bindings-v3") if worker in ["w176", "w008"] else None)
               for worker in ["w159", "w163", "w176", "w008"]]
    require(all(worker["spec"] == workers[0]["spec"] and
                worker["assignments"] == workers[0]["assignments"] for worker in workers), "Cross-worker declaration disagreement")
    source, devices = generate(workers)
    require(set(devices) == {device["id"] for device in workers[0]["spec"]["devices"]},
            "Combined worker inventory omits declared devices")
    Path(args.output).write_text(source)
    report = {"workers": workers, "devices": devices,
              "scope": "RG005 role-class physical separation for the complete captured native multiworker scenario at its before/after collection points.",
              "remaining_assumptions": ["Collector truth and hardware UUID-to-physical-machine interpretation",
                                       "Helper identity fields are direct structured collector observations; full Docker inspect output was not retained in the helper supplement, whose exact collector source is preserved",
                                       "No unrecorded movement between collection points is inferred",
                                       "Declared component roles accurately describe the selected scenario",
                                       "Inner Firewall is unselected in this captured inventory",
                                       "Physical NIC separation, facility protection, geographical site independence, component approval and OS diversity are separate obligations"]}
    for worker in report["workers"]:
        worker["manifest_hashes"] = {path: hashlib.sha256((Path(path) / "manifest.json").read_bytes()).hexdigest()
                                      for path in worker["bundles"]}
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"workers": len(workers), "devices": len(devices), "hardware_ids": len({w["hardware"] for w in workers})}))


if __name__ == "__main__":
    main()
