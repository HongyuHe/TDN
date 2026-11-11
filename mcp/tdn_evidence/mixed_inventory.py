"""Join a captured mixed IPsec/MACsec data plane to its declared network roles."""
import hashlib
import json
from pathlib import Path

from . import mixed
from .eap import export_report, query_report
from .parsers.family import encode_address
from .parsers.snapshot import require


CAPABILITIES = ["devices", "components", "interfaces", "networks", "sourceEntries",
                "redNetworkAttachments", "sourceFlows", "installations", "macsecPeerEndpoints",
                "authentication", "phases", "componentRoleBindings", "interpretations"]
LEAN_VIEW = "mixed_deployment_inventory"
SCOPE = "Complete role/interface join for a captured, manually provisioned IPsec-Inner/MACsec-Outer laboratory network"


def parse(directory):
    directory = Path(directory)
    manifest, operational = mixed.validated_experiment(directory)
    execution = mixed.execution_values(operational)
    evidence = json.loads((directory / "evidence.json").read_text())
    devices = operational["devices"]
    require(len(devices) == len(evidence["devices"]), "Duplicate declared device identity")
    tunnels = evidence["tunnels"]
    require(len(tunnels) == 2 and {t["layer"] for t in tunnels} == {"inner", "outer"},
            "Expected one Inner and one Outer tunnel declaration")
    by_layer = {t["layer"]: t for t in tunnels}
    require(by_layer["inner"]["mechanism"] == "IPsec" and by_layer["outer"]["mechanism"] == "MACsec",
            "This inventory view supports IPsec Inner and MACsec Outer")
    require(by_layer["inner"]["authentication"] == "manual test SA provisioning; no IKE/authentication claim"
            and by_layer["outer"]["authentication"] ==
            "manual test SAK provisioning; MKA and CAK authentication not established",
            "Unsupported authentication interpretation")
    allowed_roles = {"host", "inner", "outer", "outer-firewall", "black-firewall", "outer-ethernet-firewall"}
    require(all(d["role"] in allowed_roles for d in devices.values()), "Unsupported mixed inventory role")
    for layer in ["inner", "outer"]:
        endpoints = by_layer[layer]["endpoints"]
        expected = {name for name, d in devices.items() if d["role"] == layer}
        require(len(endpoints) == 2 and len(set(endpoints)) == 2 and set(endpoints) == expected,
                "Declared tunnel endpoints omit or misclassify an encryptor")
    sites = {d["site"] for d in devices.values() if d["role"] in {"host", "inner", "outer"}}
    require(len(sites) == 2 and "" not in sites, "Expected two declared endpoint sites")
    for site in sites:
        require(all(sum(d["site"] == site and d["role"] == role for d in devices.values()) == 1
                    for role in ["host", "inner", "outer"]), "Each site needs one host, Inner and Outer")
    require(all(isinstance(d["security_level_id"], str) and d["security_level_id"] for d in devices.values()),
            "Missing declared security label")

    iface_ids, owner_ids = execution["portIds"], execution["deviceIds"]
    raw_ifaces = operational["operational"]["interfaces"]
    declared_zones = {key: set() for key in raw_ifaces}
    for link in operational["architecture_links"]:
        require(link["zone"] in {"red", "gray", "black"}, "Unsupported declared link zone")
        for key in link["endpoints"]:
            declared_zones[key].add(link["zone"])
    zones, reasons = {}, {}

    def zone(key, visiting=frozenset()):
        require(key not in visiting, "Cyclic interface-zone dependencies")
        if key in zones:
            return zones[key]
        raw = raw_ifaces[key]
        device = key.split(":", 1)[0]
        if declared_zones[key]:
            require(len(declared_zones[key]) == 1, "Interface has conflicting declared link zones")
            selected = next(iter(declared_zones[key]))
            reason = {"method": "declared-veth-link", "inputs": ["source-evidence"]}
        elif raw["link_type"] == "loopback":
            selected, reason = "local", {"method": "observed-loopback", "inputs": [key]}
        elif raw["kind"] == "macsec":
            lower = device + ":" + raw["link"]
            require(lower in raw_ifaces, "Missing MACsec lower interface")
            selected = zone(lower, visiting | {key})
            reason = {"method": "MACsec-lower-interface-zone", "inputs": [lower]}
        elif raw["kind"] == "bridge":
            members = [name for name, row in raw_ifaces.items()
                       if name.split(":", 1)[0] == device and row["master"] == raw["ifname"]]
            member_zones = {zone(name, visiting | {key}) for name in members}
            require(len(member_zones) == 1, "Missing or cross-zone bridge members")
            selected = next(iter(member_zones))
            reason = {"method": "bridge-member-zone", "inputs": members}
        else:
            raise ValueError("Interface has no supported zone interpretation: " + key)
        zones[key], reasons[key] = selected, reason
        return selected

    phase_values = {filename: json.loads((directory / filename).read_text())
                    for filename in operational["phase_files"]}
    components, role_bindings = [], []
    kinds = {"host": "other", "inner": "vpn", "outer": "macsec",
             "outer-firewall": "outerFirewall", "black-firewall": "outerFirewall",
             "outer-ethernet-firewall": "outerFirewall"}
    for name in sorted(devices):
        device = devices[name]
        infrastructure = device["role"] in {"inner", "outer"}
        forwarding_bindings = []
        if infrastructure:
            for filename, phase in phase_values.items():
                row = phase[name]["bridge_netfilter"]
                lines = [line for line in row["value"].splitlines() if line]
                fields = dict(line.split("=", 1) for line in lines)
                require(len(fields) == len(lines)
                        and fields.get("/proc/sys/net/ipv4/ip_forward") == "1"
                        and fields.get("/proc/sys/net/ipv6/conf/all/forwarding") == "1",
                        "Transit encryptor lacks observed IP forwarding in a captured phase")
                forwarding_bindings.append({"phase": filename, "observation": row["observation_id"],
                                             "ipv4Forwarding": True, "ipv6Forwarding": True})
        role_bindings.append({"device": name, "declaredRole": device["role"], "infrastructure": infrastructure,
                              "roleSource": "source-evidence", "forwardingObservations": forwarding_bindings})
        level = {"classification": device["security_level_id"], "compartments": [],
                 "dissemination": [], "otherControls": []}
        components.append({"id": name, "site": device["site"], "kind": kinds[device["role"]],
                           "layer": device["role"] if device["role"] in {"inner", "outer"} else None,
                           "level": level, "infrastructure": infrastructure})
    component_map = {d["id"]: d for d in components}
    interfaces, interface_bindings = [], []
    for key in sorted(raw_ifaces):
        raw = raw_ifaces[key]
        device = key.split(":", 1)[0]
        selected_zone = zone(key)
        addresses = sorted({encode_address(a[1]) for a in raw["addresses"]})
        physical = bool(declared_zones[key])
        external = physical and ((devices[device]["role"] == "inner" and selected_zone == "gray")
                                  or (devices[device]["role"] == "outer" and selected_zone == "black"))
        interfaces.append({"id": key, "device": device, "zone": selected_zone,
                           "address": addresses[0] if addresses else None, "namespaceAddresses": addresses,
                           "linkAddress": int(raw["address"].replace(":", ""), 16) if raw["address"] else None,
                           "physical": physical, "externalData": external,
                           "managementNetwork": False, "mtu": raw["mtu"]})
        interface_bindings.append({"interface": key, "iface": iface_ids[key], "owner": owner_ids[device],
                                   "device": device, "zoneInterpretation": reasons[key],
                                   "rawInterface": raw})

    networks, sources, attachments = [], [], []
    for ordinal, inner in enumerate(sorted(by_layer["inner"]["endpoints"]), 1):
        inner_ifaces = [key for key in raw_ifaces if key.split(":", 1)[0] == inner and zone(key) == "red"]
        require(len(inner_ifaces) == 1, "Ambiguous Inner Red interface")
        inner_iface = inner_ifaces[0]
        links = [link for link in operational["architecture_links"] if inner_iface in link["endpoints"]]
        require(len(links) == 1 and links[0]["zone"] == "red", "Missing unique Red attachment")
        host_iface = next(k for k in links[0]["endpoints"] if k != inner_iface)
        host = host_iface.split(":", 1)[0]
        require(devices[host]["role"] == "host" and devices[host]["site"] == devices[inner]["site"]
                and devices[host]["security_level_id"] == devices[inner]["security_level_id"],
                "Red host role, site or declared level differs from its Inner")
        require([iface_ids[host_iface], iface_ids[inner_iface]] in execution["links"],
                "Declared Red source attachment is absent from observed links")
        network = inner + "/red-network"
        networks.append({"id": network, "site": devices[inner]["site"], "level": component_map[inner]["level"],
                         "innerComponents": [inner]})
        sources.append({"iface": iface_ids[inner_iface], "network": network, "originDomain": ordinal,
                        "sourceHost": host, "hostIface": iface_ids[host_iface],
                        "arrivalPath": [iface_ids[host_iface], iface_ids[inner_iface]]})
        attachments.extend({"interface": key, "network": network} for key in [host_iface, inner_iface])
    require({s["hostIface"] for s in sources} == set(execution["redSources"]), "Red source inventory is incomplete")
    iface_names = [""] + sorted(raw_ifaces)
    source_flows = []
    for source in sources:
        peer = next(s for s in sources if s["originDomain"] != source["originDomain"])
        addresses = []
        for entry in [source, peer]:
            ipv4 = [a[1] for a in raw_ifaces[iface_names[entry["hostIface"]]]["addresses"] if a[0] == "inet"]
            require(len(ipv4) == 1, "Sample flow needs one observed IPv4 host address")
            addresses.append(encode_address(ipv4[0]))
        source_flows.append({"iface": source["iface"], "domain": source["originDomain"],
                             "source": addresses[0], "destination": addresses[1]})

    bindings = execution.get("ipsecKeyBindings", [])
    require(bool(bindings), "Missing directional public IPsec installation records")
    installations = []
    for binding in bindings:
        require(len(binding["portIds"]) == 1, "Ambiguous IPsec endpoint interface")
        require(binding["phase"] == operational["phase_files"][-1], "IPsec active installation is from another phase")
        installations.append({"installation": {"device": binding["deviceId"], "direction": binding["direction"],
             "association": binding["state"], "epoch": "mixed:" + operational["manifest_sha256"] + "/" + binding["phase"],
             "installation": binding["install_epoch"]}, "localIface": binding["portIds"][0],
             "materialReference": "sha256:" + binding["key_and_salt_sha256"]})
    require({b["device"] for b in bindings} == set(by_layer["inner"]["endpoints"]), "Incomplete IPsec device bindings")
    peers = []
    for binding in execution["macsecKeyBindings"]:
        require("peerGenerationIndex" in binding and "materialReference" in binding, "Missing MACsec peer/key binding")
        if binding["direction"] != "tx":
            continue
        peer = next(b for b in execution["macsecKeyBindings"] if b["generationIndex"] == binding["peerGenerationIndex"])
        require(peer["direction"] == "rx" and peer["materialReference"] == binding["materialReference"]
                and peer["association"]["sci"] == binding["association"]["sci"], "MACsec static peer binding differs")
        peers.append({"sourceIface": iface_ids[binding["device"] + ":" + binding["physicalInterface"]],
                      "destinationIface": iface_ids[peer["device"] + ":" + peer["physicalInterface"]],
                      "actorSCI": binding["association"]["sci"], "tunnel": by_layer["outer"]["id"]})
    require(len(peers) == 2, "Incomplete static MACsec peer endpoints")
    observations, _ = mixed.experiment_sources(directory, operational)
    phase_records = []
    for filename in operational["phase_files"]:
        phase = json.loads((directory / filename).read_text())
        phase_records.append({"file": filename, "sha256": hashlib.sha256((directory / filename).read_bytes()).hexdigest(),
                              "observations": {name: {kind: row["observation_id"] for kind, row in values.items()}
                                               for name, values in phase.items()}})
    raw_files = {"source-evidence": "evidence.json", "collector-source": "collector.source.py",
                 "phase-before": operational["phase_files"][0], "phase-after": operational["phase_files"][-1],
                 "ipsec-provisioning": "ipsec-provisioning.json", "macsec-provisioning": "macsec-provisioning.json"}
    report = {"devices": list(devices.values()), "components": components, "interfaces": interfaces,
              "networks": networks, "sourceEntries": sources, "sourceFlows": source_flows,
              "redNetworkAttachments": attachments, "installations": installations, "macsecPeerEndpoints": peers,
              "ownerNames": [""] + sorted(devices), "ifaceNames": iface_names, "execution": execution,
              "hostNetworkIdBindings": [{"owner": owner_ids[s["sourceHost"]], "device": s["sourceHost"],
                  "network": s["network"], "networkId": s["originDomain"]} for s in sources],
              "interfaceBindings": interface_bindings, "phases": phase_records, "componentRoleBindings": role_bindings,
              "authentication": [{"device": name, "layer": d["role"], "certificateAuth": False, "pskAuth": False,
                                  "evidenceStatus": "manual-SA-provisioning", "authenticationEstablished": False,
                                  "source": "source-evidence"} for name, d in devices.items() if d["role"] in {"inner", "outer"}],
              "interpretations": [
                  {"field": "components.kind", "meaning": "Ordinary Red hosts map to other while retaining their declared host role. The workstation constructor is reserved for administrative-workstation obligations."},
                  {"field": "components.infrastructure", "meaning": "Inner and Outer devices are transit encryption gateways, supported by their declared roles, interfaces and forwarding enabled in both phases. The field does not assert independent hardware; other component kinds retain false in this view."},
                  {"field": "components.level", "meaning": "Declared laboratory label in classification; empty other dimensions are the single-label model interpretation, not recovered classification markings."},
                  {"field": "interfaces.zone", "meaning": "Declared veth zones, observed loopback, and inherited MACsec-lower/bridge-member attachment zones. A logical MACsec interface can hold the pre-encryption frame in its lower link's zone."},
                  {"field": "interfaces.physical", "meaning": "Observed veth endpoint in this emulation; no claim of independent physical hardware."},
                  {"field": "macsecPeerEndpoints", "meaning": "Static installed SCI/key peer bindings for the model endpoint inventory; no MKA exchange, CAK establishment or authentication history."},
                  {"field": "sourceEntries.originDomain", "meaning": "Distinct ordinal for each connected Red network, independent of its security-level label. The original execution export retains its earlier single-label domain values; hostNetworkIdBindings supplies the separate endpoint-network interpretation."}],
              "observationBindings": observations, "rawObservationIds": [r["id"] for r in observations], "rawFiles": raw_files,
              "manifestSha256": operational["manifest_sha256"], "projectionVersion": "mixed-deployment-inventory-v1",
              "provenance": {"configurationId": manifest["configuration_id"], "runtimeBackend": manifest["runtime_backend"],
                             "started": manifest["started_at"], "finished": manifest["ended_at"],
                             "activeIpsecPhase": operational["phase_files"][-1]},
              "scope": [SCOPE, "Original packet-processing export is retained without changing routes, MTUs or filters.",
                        "The captured before/after phases remain separate; IPsec installation records select the final captured key epoch.",
                        "Roles, sites and the L1 security label are experiment declarations; no institutional approval or physical independence is inferred."]}
    return manifest, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    if observation in report["rawFiles"]:
        return "" if stderr else (Path(directory) / report["rawFiles"][observation]).read_text()
    require(observation in report["rawObservationIds"], "Observation is outside the joined deployment capture")
    return mixed.read_experiment_raw(directory, observation, stderr)


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
