"""Expose observed FreeBSD/Linux gateway identities with separate capture intervals."""

import ipaddress
import json
from pathlib import Path
import re

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "gateway_identities", "phases", "observations", "coverage"]
LEAN_VIEW = "os_provider_identity"
SCOPE = "Observed ND FreeBSD Inner and Linux Outer identities; supplementary phases retain their own intervals and configurations"


def one(rows, predicate, message):
    matches = [row for row in rows if predicate(row)]
    require(len(matches) == 1, message)
    return matches[0]


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    context = json.loads((root / "context.json").read_text())
    require(context["schema"] == "tdn-os-provider-inputs/v1", "Unknown diversity input schema")
    captures = {}
    phases = []
    raw = []
    for phase in context["phases"]:
        name = phase["id"]
        require(name and name not in captures and ":" not in name, "Invalid or duplicate diversity phase")
        path = (root / phase["path"]).resolve()
        path.relative_to(root.resolve())
        digest = validate_files(path)
        document = json.loads((path / "observations.json").read_text())
        captures[name] = document
        phases.append({"id": name, "originalPath": phase["originalPath"], "manifestSha256": digest,
                       "startedAt": document.get("started_at", document.get("at")),
                       "endedAt": document.get("ended_at"), "error": document.get("error"),
                       "scope": document.get("scope", []), "role": phase["role"]})
        for index, row in enumerate(document["records"]):
            raw.append({"id": name + ":" + str(index), "phase": name, "record": row})
    require(len({row["id"] for row in raw}) == len(raw), "Duplicate diversity observation")
    inner_phase = one(context["phases"], lambda phase: phase["role"] == "inner", "Require one Inner capture")["id"]
    outer_phase = one(context["phases"], lambda phase: phase["role"] == "outer", "Require one Outer capture")["id"]
    inner, outer = captures[inner_phase], captures[outer_phase]
    require(inner.get("error") is None and outer.get("error") is None, "OS identity collection failed")
    declared = {device["id"]: device for device in inner["spec"]["devices"]
                if device["role"] in ["inner", "outer"]}
    require(len(declared) == 4 and all(name.startswith("ND_") for name in declared),
            "This diversity view requires the four ND gateways")

    def observation(phase, predicate):
        item = one(raw, lambda item: item["phase"] == phase and predicate(item["record"]["command"]),
                   "Missing or repeated exact diversity observation")
        require(item["record"]["returncode"] == 0, "Required diversity observation failed")
        return item

    identities = []
    guest_ports = {row["command"][row["command"].index("-p") + 1] for row in inner["records"]
                   if row["command"][0] == "ssh" and row["command"][-1] == "uname -a"}
    for port in sorted(guest_ports):
        def guest(command):
            return observation(inner_phase, lambda args: args[0] == "ssh" and "-p" in args
                               and args[args.index("-p") + 1] == port and args[-1] == command)
        kernel, interfaces = guest("uname -a"), guest("ifconfig -a")
        require(kernel["record"]["stdout"].startswith("FreeBSD "), "Inner family is not FreeBSD")
        actual = []
        for block in re.split(r"(?m)(?=^[A-Za-z0-9_.]+: flags=)", interfaces["record"]["stdout"]):
            match = re.match(r"([A-Za-z0-9_.]+): flags=", block)
            if match:
                actual.append({"name": match[1], "addresses": re.findall(r"\binet ([0-9.]+)", block)})
        addresses = {address for item in actual for address in item["addresses"]}
        device = one(list(declared.values()), lambda device: device["role"] == "inner" and
                     {str(ipaddress.ip_interface(interface["address"]).ip) for interface in device["interfaces"]} <= addresses,
                     "Guest does not uniquely bind to declared Inner interfaces")
        bound_interfaces = []
        for interface in device["interfaces"]:
            address = str(ipaddress.ip_interface(interface["address"]).ip)
            interface_owner = one(actual, lambda item: address in item["addresses"], "Ambiguous actual Inner interface")
            bound_interfaces.append({"declaredName": interface["name"], "actualName": interface_owner["name"],
                                     "address": address, "observation": interfaces["id"]})
        stats, algorithms = guest("/usr/local/sbin/swanctl --stats"), guest("/usr/local/sbin/swanctl --list-algs")
        linkage = guest("ldd /usr/local/lib/ipsec/plugins/libstrongswan-botan.so")
        package = guest("pkg info botan3")
        plugins = re.search(r"(?m)^loaded plugins: (.*)$", stats["record"]["stdout"])
        require(plugins and "botan" in plugins[1].split() and "openssl" not in plugins[1].split(), "Inner loaded provider differs")
        require("AES_GCM_16[botan]" in algorithms["record"]["stdout"] and
                "libbotan-3.so" in linkage["record"]["stdout"], "Inner AES-GCM/linkage differs")
        identities.append({"device": device["id"], "role": "inner", "osFamily": "FreeBSD",
                           "kernel": kernel["record"]["stdout"].strip(), "guestSSHPort": port,
                           "boundInterfaces": bound_interfaces, "loadedPlugins": plugins[1].split(),
                           "aesGCMProvider": "Botan", "linkedLibraries": linkage["record"]["stdout"],
                           "providerPackage": package["record"]["stdout"],
                           "observations": [row["id"] for row in [kernel, interfaces, stats, algorithms, linkage, package]],
                           "phase": inner_phase, "unavailable": ["daemonPID", "actualExecutableHash", "linkedLibraryHashes"]})
    for device in declared.values():
        if device["role"] != "outer":
            continue
        name = device["id"]
        def command(arguments):
            return observation(outer_phase, lambda args: args == ["docker", "exec", name] + arguments)
        inspected = observation(outer_phase, lambda args: args == ["docker", "inspect", "--format", "{{json .}}", name])
        container = json.loads(inspected["record"]["stdout"])
        require(container["Name"] == "/" + name and container["State"]["Running"], "Wrong or stopped Outer container")
        kernel, stats, algorithms = command(["uname", "-a"]), command(["swanctl", "--stats"]), command(["swanctl", "--list-algs"])
        linkage = command(["ldd", "/usr/lib/ipsec/plugins/libstrongswan-openssl.so"])
        plugin_hash = command(["sha256sum", "/usr/lib/ipsec/plugins/libstrongswan-openssl.so"])
        version, process, sessions = command(["openssl", "version", "-a"]), command(["ps", "-eo", "pid,comm,args"]), command(["swanctl", "--list-sas"])
        require(kernel["record"]["stdout"].startswith("Linux "), "Outer family is not Linux")
        plugins = re.search(r"(?m)^loaded plugins: (.*)$", stats["record"]["stdout"])
        require(plugins and "openssl" in plugins[1].split() and "botan" not in plugins[1].split(), "Outer loaded provider differs")
        require("AES_GCM_16[openssl]" in algorithms["record"]["stdout"] and
                "libcrypto.so.3" in linkage["record"]["stdout"], "Outer AES-GCM/linkage differs")
        require("'" + name + ".msc.test'" in sessions["record"]["stdout"] and
                device["tunnel"]["local"] + "[500]" in sessions["record"]["stdout"], "Outer IKE identity differs")
        digest = re.fullmatch(r"([a-f0-9]{64})\s+/usr/lib/ipsec/plugins/libstrongswan-openssl.so\s*", plugin_hash["record"]["stdout"])
        require(digest is not None, "Outer plugin hash malformed")
        processes = re.findall(r"(?m)^\s*(\d+)\s+charon\s+(.+)$", process["record"]["stdout"])
        require(len(processes) == 1, "Outer daemon process is ambiguous")
        identities.append({"device": name, "role": "outer", "osFamily": "Linux",
                           "kernel": kernel["record"]["stdout"].strip(), "containerId": container["Id"],
                           "containerInitHostPID": container["State"]["Pid"], "daemonNamespacePID": int(processes[0][0]),
                           "daemonProcessCommand": processes[0][1], "loadedPlugins": plugins[1].split(),
                           "aesGCMProvider": "OpenSSL", "linkedLibraries": linkage["record"]["stdout"],
                           "providerVersionCommand": version["record"]["stdout"], "pluginSHA256": digest[1],
                           "observations": [row["id"] for row in [inspected, kernel, stats, algorithms, linkage, plugin_hash, version, process, sessions]],
                           "phase": outer_phase, "unavailable": ["actualInterfaceAddressInventory", "actualExecutableHash", "linkedLibraryHashes"]})
    require({row["device"] for row in identities} == set(declared), "OS gateway inventory incomplete")
    coverage = [{"scope": "Separate historical observation intervals. No atomic snapshot or unchanged configuration is asserted.",
                 "physicalHost": "Shared laboratory host is explicit; physical separation is not established.",
                 "independence": "OS families and observed IKE providers differ. Product/manufacturer/NSA independence is not established.",
                 "supplements": "Raw phases retain their own errors, settings and session epochs. No cross-phase SA identity is inferred."}]
    report = {"devices": [{"id": row["device"], "role": row["role"]} for row in identities],
              "gateway_identities": identities, "phases": phases, "observations": raw, "coverage": coverage,
              "manifestSha256": manifest_hash, "scope": [SCOPE], "projectionVersion": "os-provider-identity-v1"}
    return {"runtime_backend": "captured-ND-FreeBSD-Linux"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    row = one(report["observations"], lambda row: row["id"] == observation, "Unknown diversity observation")
    return row["record"].get("stderr" if stderr else "stdout", "")


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
