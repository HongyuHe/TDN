"""Bind EAP-only CAK creation to retained public configurations and reviewed source."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile

from import_macsec_algorithms import LAUNCH_PIN, parse_bindings
from import_macsec_key_servers import parse as parse_key_servers
from validate_evidence import require


#* These upstream archives contain the reviewed configuration parsers and caller inventory.
ARCHIVES = {
    "hostapd-2.12": "f43502561c28ba47ab77e18e1a973d07361c68cc8b14178e619bd5796b70eabd",
    "wpa_supplicant-2.12": "08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6",
}

AUTH_FIELDS = set("driver interface ssid ieee8021x use_pae_group_addr eap_server own_ip_addr "
                  "nas_identifier auth_server_addr auth_server_port auth_server_shared_secret "
                  "macsec_policy macsec_integ_only macsec_csindex macsec_replay_protect "
                  "macsec_replay_window mka_priority logger_stdout logger_stdout_level".split())
SUPP_FIELDS = set("ap_scan eapol_version key_mgmt eap phase1 openssl_ciphers identity ca_cert "
                  "client_cert private_key domain_match eapol_flags macsec_policy macsec_csindex "
                  "macsec_replay_protect macsec_replay_window mka_priority".split())


def public_config(text, role):
    fields = {}
    depth = 0
    networks = 0
    for original in text.splitlines():
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        if line == "network={":
            require(role == "supplicant" and depth == 0, "Unexpected network block")
            networks += 1
            depth = 1
            continue
        if line == "}":
            require(depth == 1, "Unmatched configuration block")
            depth = 0
            continue
        require("=" in line, "Unsupported configuration line")
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        require(key not in fields, "Duplicate configuration field")
        require(key in (AUTH_FIELDS if role == "authenticator" else SUPP_FIELDS),
                "Unreviewed configuration field, including pre-shared/fallback keys")
        if role == "supplicant":
            require(depth == (0 if key in {"ap_scan", "eapol_version"} else 1),
                    "Configuration field in wrong block")
        fields[key] = value
    require(depth == 0 and networks == (1 if role == "supplicant" else 0),
            "Exactly one complete supplicant network required")
    require(set(fields) == (AUTH_FIELDS if role == "authenticator" else SUPP_FIELDS),
            "Incomplete public configuration")
    if role == "authenticator":
        require(fields["driver"] == "macsec_linux" and fields["ieee8021x"] == "1" and
                fields["eap_server"] == "0", "Authenticator EAP source changed")
    else:
        require(fields["key_mgmt"] == "IEEE8021X" and fields["eap"] == "TLS",
                "Supplicant EAP source changed")
    require(fields["macsec_policy"] == "1", "MACsec policy changed")
    return {"has_pre_shared_cak": False, "has_pre_shared_ckn": False,
            "field_names": sorted(fields), "network_blocks": networks}


def source_inventory(source_dir):
    records = []
    for stem, expected in ARCHIVES.items():
        path = Path(source_dir) / (stem + ".tar.gz")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                "Reviewed upstream source archive changed")
        callers = []
        with tarfile.open(path) as archive:
            for member in archive.getmembers():
                if not member.isfile() or not member.name.endswith(".c"):
                    continue
                source = archive.extractfile(member).read().decode()
                for number, line in enumerate(source.splitlines(), 1):
                    if re.search(r"\bieee802_1x_kay_create_mka\s*\(", line):
                        callers.append({"path": member.name, "line": number})
        records.append({"path": str(path), "sha256": expected, "creation_mentions": callers})
    return records


def parse(cases, bindings, runtime, source_dir):
    sources = source_inventory(source_dir)
    identity = parse_bindings(Path(bindings), Path(runtime))
    arrangements = parse_key_servers(cases)
    ports = []
    for path, arrangement in zip(map(Path, cases), arrangements):
        case = json.loads((path / "case.json").read_text())
        require(case["script_sha256"] == LAUNCH_PIN, "Unreviewed configuration collector")
        commands = json.loads((path / "commands.json").read_text())
        for name in ["P0", "P1"]:
            role = "authenticator" if name == case["authenticator"] else "supplicant"
            conf = path / (name + ".conf.public")
            settings = public_config(conf.read_text(), role)
            logs = [row for row in commands if row["command"][0] == "cat" and
                    Path(row["command"][-1]).name == name + ".log"]
            require(len(logs) == 1 and logs[0]["returncode"] == 0, "Missing successful peer log")
            creations = re.findall(r"KaY: Create MKA \(ifname=(\S+) mode=(\S+) authenticator=(\S+)\)",
                                   logs[0]["stdout"])
            expected = ("eth0", "EAP", "Yes" if role == "authenticator" else "No")
            require(creations and set(creations) == {expected},
                    "Observed key creation differs from EAP-only source")
            ports.append({"device": path.name + "/" + name, "role": role,
                          "settings": settings, "config_sha256": hashlib.sha256(conf.read_bytes()).hexdigest(),
                          "creation_log_id": logs[0]["id"], "observed_creations": len(creations),
                          "manifest_sha256": arrangement["manifest_sha256"]})
    return {"ports": ports, "source_bindings": identity, "upstream_sources": sources,
            "interpretation": "INT-MD15-20261024", "whole_RG027_established": False,
            "implementation_assumptions": [
                "The pinned launch code copies the actual initial configuration before launching a fresh daemon. No later configuration/control-interface mutation or external memory/key injection is modeled.",
                "The retained exact wrappers/core and upstream configuration parser reading describe the compiled binaries. Correct compilation/execution and unchanged source outside retained patches are trusted, not proved by Lean or a reproducible build.",
                "A fresh configuration initializes mka_psk_set to zero. Only mka_cak/mka_ckn configuration enables the pre-shared creation guard; neither field is present in the checked complete EAP configurations.",
                "The two reviewed creation entry points map to authenticated EAP creation and guarded pre-shared creation. Other protocol operations preserve CAK origin or remove participants.",
                "Normal EAP reauthentication may create additional freshly derived CAKs. MD15 is interpreted as disabling configured fallback/preceding/rollover credentials, not all normal cryptographic renewal.",
                "NSA-approved KGS provenance, PSK-case configuration, and other RG027 clauses require their own evidence."
            ]}


def generate(data):
    entries = ["(" + json.dumps(port["device"]) + ", ⟨false, false⟩)" for port in data["ports"]]
    return """import TDN.Requirements.MacsecNoCleartextFallbackSpec

namespace TDN.Deployments.SnapshotMacsecKeySources
open KeySources Requirements

/-- Complete public configurations from both EAP role arrangements. The import
report records source bindings and the fresh-process/fixed-configuration assumptions. -/
def ifaces : List (String × Config) := [""" + ", ".join(entries) + """]

lemma no_configured_pre_shared_pair : ∀ iface ∈ ifaces,
    iface.2.preSharedEnabled = false := by native_decide

theorem eap_ifaces_have_no_pre_shared_fallback (iface : String × Config)
    (member : iface ∈ ifaces) : no_pre_shared_fallback_in_eap_mode iface.2 :=
  eap_key_sources_disable_pre_shared_fallback iface.2 (no_configured_pre_shared_pair iface member)

lemma all_four_ifaces_present : ifaces.length = 4 := by native_decide

end TDN.Deployments.SnapshotMacsecKeySources
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", nargs="+")
    parser.add_argument("--bindings", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.cases, args.bindings, args.runtime, args.source_dir)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"ports": len(data["ports"]), "whole_RG027_established": False}))


if __name__ == "__main__":
    main()
