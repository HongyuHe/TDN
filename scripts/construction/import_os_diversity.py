"""Import observed OS families and loaded IKE crypto providers for the ND case."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from import_service_authorization import require, validate_public_bundle
from import_physical_partition import one


def parse(inner_path, outer_path):
    inner, outer = validate_public_bundle(inner_path), validate_public_bundle(outer_path)
    require(inner["error"] is None and outer["error"] is None, "OS identity collection failed")
    declared = {device["id"]: device for device in inner["spec"]["devices"]
                if device["role"] in ["inner", "outer"]}
    identities = {}
    guest_ports = {record["command"][record["command"].index("-p") + 1]
                   for record in inner["records"] if record.get("command", [""])[0] == "ssh"
                   and record["command"][-1] == "uname -a"}
    for port in sorted(guest_ports):
        def guest(command):
            rows = [record for record in inner["records"] if record.get("command", [""])[0] == "ssh"
                    and "-p" in record["command"]
                    and record["command"][record["command"].index("-p") + 1] == port
                    and record["command"][-1] == command]
            require(len(rows) == 1 and rows[0]["returncode"] == 0, "Incomplete guest identity observation")
            return rows[0]
        kernel = guest("uname -a")
        require(kernel["stdout"].startswith("FreeBSD "), "Guest OS family is not FreeBSD")
        interfaces = guest("ifconfig -a")
        addresses = set(re.findall(r"\binet ([0-9.]+)", interfaces["stdout"]))
        matches = [device for device in declared.values() if device["role"] == "inner" and
                   {str(ipaddress.ip_interface(interface["address"]).ip) for interface in device["interfaces"]} <= addresses]
        require(len(matches) == 1, "Guest does not uniquely bind to declared Inner interface addresses")
        device = matches[0]
        statistics = guest("/usr/local/sbin/swanctl --stats")
        algorithms = guest("/usr/local/sbin/swanctl --list-algs")
        linkage = guest("ldd /usr/local/lib/ipsec/plugins/libstrongswan-botan.so")
        plugins = re.search(r"(?m)^loaded plugins: (.*)$", statistics["stdout"])
        require(plugins and "botan" in plugins[1].split() and "openssl" not in plugins[1].split(),
                "Guest loaded crypto provider differs")
        require("AES_GCM_16[botan]" in algorithms["stdout"] and "libbotan-3.so" in linkage["stdout"],
                "Guest crypto provider or actual linkage not observed")
        require(device["id"] not in identities, "Duplicate guest binding")
        identities[device["id"]] = {"role": "inner", "osFamily": "FreeBSD", "ikeCryptoProvider": "Botan",
                                    "kernel": kernel["stdout"].strip(), "guest_ssh_port": port,
                                    "observations": [row["id"] for row in [kernel, interfaces, statistics, algorithms, linkage]]}
    for device in declared.values():
        if device["role"] != "outer":
            continue
        name = device["id"]
        inspected = one(outer["records"], ["docker", "inspect", "--format", "{{json .}}", name])
        container = json.loads(inspected["stdout"])
        require(container["Name"] == "/" + name and container["State"]["Running"], "Wrong or stopped Outer container")
        prefix = ["docker", "exec", name]
        kernel = one(outer["records"], prefix + ["uname", "-a"])
        statistics = one(outer["records"], prefix + ["swanctl", "--stats"])
        algorithms = one(outer["records"], prefix + ["swanctl", "--list-algs"])
        linkage = one(outer["records"], prefix + ["ldd", "/usr/lib/ipsec/plugins/libstrongswan-openssl.so"])
        sessions = one(outer["records"], prefix + ["swanctl", "--list-sas"])
        require(kernel["stdout"].startswith("Linux "), "Outer OS family is not Linux")
        plugins = re.search(r"(?m)^loaded plugins: (.*)$", statistics["stdout"])
        require(plugins and "openssl" in plugins[1].split() and "botan" not in plugins[1].split(),
                "Outer loaded crypto provider differs")
        require("AES_GCM_16[openssl]" in algorithms["stdout"] and "libcrypto.so.3" in linkage["stdout"],
                "Outer crypto provider or actual linkage not observed")
        require("'" + name + ".msc.test'" in sessions["stdout"] and
                device["tunnel"]["local"] + "[500]" in sessions["stdout"], "Outer IKE identity differs from declaration")
        identities[name] = {"role": "outer", "osFamily": "Linux", "ikeCryptoProvider": "OpenSSL",
                            "kernel": kernel["stdout"].strip(), "container_id": container["Id"],
                            "pid": container["State"]["Pid"],
                            "observations": [row.get("at", row.get("id")) for row in
                                             [inspected, kernel, statistics, algorithms, linkage, sessions]]}
    require(set(identities) == set(declared), "OS identity inventory incomplete")
    return identities


def generate(identities):
    q = json.dumps
    lines = ["import TDN.Targets.Components", "", "namespace TDN.Imported.FreshOSDiversity", "",
             "def components : List Targets.Component := ["]
    rows = []
    for name, identity in sorted(identities.items()):
        rows.append("  { identity := " + q(name) + ', product := ⟨"", "", "", .vpn⟩, role := .' +
                    identity["role"] + ', physicalDevice := "SHARED-LAB-HOST", osFamily := ' +
                    q(identity["osFamily"]) + ', cryptoManufacturer := "", cryptoLibrary := ' +
                    q(identity["ikeCryptoProvider"]) +
                    ', evaluatedConfiguration := "", installedConfiguration := "", modifications := [] }')
    lines.extend([",\n".join(rows) + "]", "",
                  "/-- This is the OS-family clause for the captured selected Inner/Outer inventory. -/",
                  "theorem captured_OS_families_differ : ∀ inner ∈ components, ∀ outer ∈ components,",
                  "    inner.role = .inner → outer.role = .outer → inner.osFamily ≠ outer.osFamily := by",
                  "  decide", "",
                  "/-- Observed IKE provider names differ; manufacturer independence and every",
                  "ESP/kernel crypto implementation remain separate claims. -/",
                  "theorem observed_IKE_provider_names_differ : ∀ inner ∈ components, ∀ outer ∈ components,",
                  "    inner.role = .inner → outer.role = .outer → inner.cryptoLibrary ≠ outer.cryptoLibrary := by",
                  "  decide", "", "end TDN.Imported.FreshOSDiversity", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inners", required=True)
    parser.add_argument("--outers", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    identities = parse(args.inners, args.outers)
    Path(args.output).write_text(generate(identities))
    report = {"identities": identities, "input_manifests": {
        path: hashlib.sha256((Path(path) / "manifest.json").read_bytes()).hexdigest()
        for path in [args.inners, args.outers]},
        "scope": "Independent OS-family clause and observed IKE-provider difference for the selected ND case.",
        "assumptions": ["Collector truth and OS-family interpretation of actual uname results",
                        "Inner and Outer observations are from distinct recorded intervals; no atomic combined snapshot is asserted",
                        "Guest interface addresses and Outer IKE identities bind the declared component inventory",
                        "Product, manufacturer/subsidiary, NIAP configuration and NSA independence approval are not established",
                        "Shared physical host is explicit; this case does not establish RG005 physical separation"]}
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"components": len(identities), "os_families": sorted({item["osFamily"] for item in identities.values()})}))


if __name__ == "__main__":
    main()
