"""Regenerate weakened evidence in isolation and require Lean to reject it."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("msc_mutation_import", ROOT / "scripts/import_msc_snapshot.py")
IMPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORTER)


class LeanContractMutationTests(unittest.TestCase):
    def test_required_proofs_survive_optional_management_variants(self):
        lake = shutil.which("lake") or str(Path.home() / ".elan/bin/lake")
        with tempfile.TemporaryDirectory(prefix="tdn-optional-management-") as temporary:
            work = Path(temporary)
            shutil.copytree(ROOT / "TDN", work / "TDN")
            for name in ["TDN.lean", "Main.lean", "lakefile.toml", "lean-toolchain"]:
                shutil.copy2(ROOT / name, work / name)
            env = dict(os.environ)
            env.pop("LEAN_PATH", None)
            modes = ["unavailable", "absent", "firewall-drift", "missing-status",
                     "inconsistent-subnets", "corrupt-optional-files", "missing-probes",
                     "retained-management-forward"]
            requested = {mode for mode in os.environ.get("TDN_MSC_MANAGEMENT_VARIANTS", "").split(",") if mode}
            self.assertFalse(requested - set(modes), "unknown management variant filter")
            if requested:
                modes = [mode for mode in modes if mode in requested]
            for mode in modes:
                with self.subTest(mode=mode):
                    snapshot = work / mode
                    shutil.copytree(IMPORTER.CURRENT_EVIDENCE / "snapshot", snapshot)
                    spec = json.loads((snapshot / "spec.json").read_text())
                    status = json.loads((snapshot / "status.json").read_text())
                    manifest = json.loads((snapshot / "manifest.json").read_text())
                    checks = json.loads((IMPORTER.CURRENT_EVIDENCE / "check.json").read_text())
                    excluded = {d["id"] for d in spec["devices"] if d["role"] == "admin" or
                                all(i["zone"] == "management" for i in d["interfaces"])}
                    if mode == "absent":
                        zones = {(d["id"], i["name"]): i["zone"] for d in spec["devices"] for i in d["interfaces"]}
                        management_ports = {d["id"]: {i["name"] for i in d["interfaces"] if i["zone"] == "management"}
                                            for d in spec["devices"]}
                        spec["links"] = [l for l in spec["links"] if zones[l["a"]["device"], l["a"]["interface"]] != "management"]
                        spec["devices"] = [d for d in spec["devices"] if d["id"] not in excluded]
                        for device in spec["devices"]:
                            device["interfaces"] = [i for i in device["interfaces"] if i["zone"] != "management"]
                            device.pop("admin", None)
                        status["devices"] = [d for d in status["devices"] if d["device"] not in excluded]
                        #* Remove the optional ports from observed state as well as intent.
                        #* The old fixture left live management ports in an absent-plane case.
                        for observed in status["devices"]:
                            ports = management_ports[observed["device"]]
                            for key, field in [("interfaces", "ifname"), ("routes", "dev")]:
                                if key in observed["facts"]:
                                    values = json.loads(observed["facts"][key])
                                    observed["facts"][key] = json.dumps([v for v in values if v.get(field) not in ports])
                            for kind in ["intended", "observed"]:
                                relative = f'devices/{observed["device"]}/{kind}.iptables'
                                path = snapshot / relative
                                lines = []
                                for line in path.read_text().splitlines():
                                    tokens = shlex.split(line)
                                    if not any(k in {"-i", "-o"} and v in ports for k, v in zip(tokens, tokens[1:])):
                                        lines.append(line)
                                path.write_text("\n".join(lines) + "\n")
                                manifest["sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                    elif mode == "unavailable":
                        for device in status["devices"]:
                            if device["device"] in excluded:
                                device["state"] = "stopped"
                                device["errors"] = {"status": "optional management plane unavailable"}
                                device["facts"] = {}
                                device.pop("deployed_spec_sha256", None)
                        for relative in list(manifest["sha256"]):
                            if relative.startswith("devices/") and relative.split("/")[1] in excluded:
                                (snapshot / relative).unlink()
                                del manifest["sha256"][relative]
                    elif mode == "retained-management-forward":
                        for kind in ["intended", "observed"]:
                            relative = f"devices/I_A1/{kind}.iptables"
                            path = snapshot / relative
                            path.write_text(path.read_text().replace(
                                "COMMIT", "-A FORWARD -i mgmt -o mgmt -j DROP\nCOMMIT"))
                            manifest["sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                    elif mode == "missing-status":
                        status["devices"] = [d for d in status["devices"] if d["device"] not in excluded]
                    elif mode == "inconsistent-subnets":
                        for device in spec["devices"]:
                            for interface in device["interfaces"]:
                                if interface["zone"] == "management" and interface.get("address"):
                                    interface["address"] = "invalid optional management address"
                    elif mode in {"firewall-drift", "corrupt-optional-files"}:
                        for device in excluded:
                            relative = f"devices/{device}/observed.iptables"
                            path = snapshot / relative
                            path.write_text("unsupported optional firewall configuration")
                            if mode == "firewall-drift":
                                manifest["sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                    for check in checks["checks"]:
                        if set(check["name"].split("/")) & excluded:
                            check["passed"] = False
                    checks["passed"] = False
                    digest = hashlib.sha256(json.dumps(spec, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
                    status["spec_sha256"] = checks["spec_sha256"] = digest
                    for device in status["devices"]:
                        if "deployed_spec_sha256" in device:
                            device["deployed_spec_sha256"] = digest
                    manifest["spec_sha256"] = digest
                    for name, value in [("spec.json", spec), ("status.json", status)]:
                        path = snapshot / name
                        path.write_text(json.dumps(value))
                        manifest["sha256"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
                    (snapshot / "manifest.json").write_text(json.dumps(manifest))
                    check_path = work / "checks.json"
                    check_path.write_text(json.dumps(checks))
                    if mode == "missing-probes":
                        check_path.unlink()
                    (work / "TDN/MSC/Deployment.lean").write_text(IMPORTER.translate(snapshot, check_path))
                    result = subprocess.run([lake, "build", "TDN"], cwd=work, env=env,
                                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
                    self.assertEqual(result.returncode, 0, result.stdout)

    def test_regenerated_security_mutations_fail_the_relevant_proof(self):
        lake = shutil.which("lake") or str(Path.home() / ".elan/bin/lake")
        mutations = [
            ("black-bypass", None, None, None, None, "outer_firewall_cut_edges"),
            ("duplicate-gray-address", None, None, None, None, "gray_addresses_unique"),
            ("selector-widen", None, None, None, None, "inner_selectors_match_red_prefixes"),
            ("selector-narrow", None, None, None, None, "inner_selectors_match_red_prefixes"),
            ("substituted-ca", None, None, None, None, "sampled_certificates_match_ca_metadata"),
            ("duplicated-ca-key-id", None, None, None, None, "sampled_distinct_trust_ca_identifiers"),
            ("duplicated-local-key-id", None, None, None, None, "sampled_local_certificate_identifiers_unique"),
            ("missing-certificates", None, None, None, None, "sampled_credentials_complete"),
            ("wrong-peer-certificate", None, None, None, None, "sampled_credentials_match_identities"),
            ("runtime-interfaces", None, None, None, None, "observed_interfaces_realize_declaration"),
            ("runtime-routes", None, None, None, None, "declared_static_routes_installed"),
            ("runtime-policies", None, None, None, None, "observed_policies_match_tunnels"),
            ("runtime-states", None, None, None, None, "observed_states_match_tunnels"),
            ("runtime-host-missing-policies", None, None, None, None, "operational_observations_complete"),
            ("runtime-host-extra-policy", None, None, None, None, "red_hosts_have_no_xfrm"),
            ("runtime-credential-key", None, None, None, None, "public_certificate_views_agree"),
            ("runtime-credential-expiry", None, None, None, None, "public_certificate_views_agree"),
            ("runtime-extra-session", None, None, None, None, "sampled_sessions_match_declared_peers"),
            ("runtime-child-weaker-cipher", None, None, None, None, "sampled_tunnels_established"),
            ("runtime-child-wrong-group", None, None, None, None, "sampled_sessions_match_declared_peers"),
            ("runtime-loaded-revocation", None, None, None, None, "loaded_connections_match_intent"),
            ("runtime-missing-reported-crl", None, None, None, None, "public_crl_views_agree"),
            ("runtime-missing-public-audit", None, None, None, None, "authentication_observations_complete"),
            ("runtime-credential-revoked", None, None, None, None, "sampled_public_credentials_usable"),
            ("runtime-credential-stale-crl", None, None, None, None, "sampled_public_credentials_usable"),
            ("runtime-credential-signature", None, None, None, None, "sampled_public_credentials_usable"),
            ("runtime-local-certificate-usage", None, None, None, None, "sampled_public_credentials_usable"),
            ("runtime-certificate-cdp", None, None, None, None, "revocation_retrieval_sets_are_observed_empty"),
            ("runtime-missing-retrieval-metadata", None, None, None, None, "revocation_retrieval_sets_are_observed_empty"),
            ("runtime-missing-authorities", None, None, None, None, "revocation_retrieval_sets_are_observed_empty"),
            ("runtime-new-authority", None, None, None, None, "revocation_retrieval_sets_are_observed_empty"),
            ("runtime-finite-address-lifetime", None, None, None, None, "retained_ipv4_addresses_are_permanent"),
            ("runtime-dhcp-process", None, None, None, None, "retained_namespaces_have_no_time_or_address_client"),
            ("runtime-forwarding", None, None, None, None, "observed_forwarding_matches_roles"),
            ("runtime-peer-index", None, None, None, None, "observed_links_have_reciprocal_peers"),
            ("runtime-mtu", None, None, None, None, "observed_interfaces_realize_declaration"),
            ("runtime-next-hop", None, None, None, None, "declared_static_routes_installed"),
            ("runtime-gray-return-route", None, None, None, None, "gray_interfaces_have_return_routes"),
            ("runtime-route-scope", None, None, None, None, "observed_route_scopes_supported"),
            ("runtime-gray-reverse-override", None, None, None, None, "gray_ingress_source_certificate"),
            ("runtime-policy-direction", None, None, None, None, "observed_policies_match_tunnels"),
            ("runtime-policy-selector", None, None, None, None, "observed_policies_match_tunnels"),
            ("runtime-policy-reqid", None, None, None, None, "observed_policies_match_tunnels"),
            ("runtime-policy-spi", None, None, None, None, "observed_policy_spis_select_states"),
            ("runtime-extra-switch-flow", None, None, None, None, "observed_switches_realize_ports"),
            ("runtime-extra-resolver", None, None, None, None, "resolver_settings_match_selected_policy"),
            ("runtime-remote-boot", None, None, None, None, "startup_programs_are_local"),
            ("runtime-ovs-boot-manager", None, None, None, None, "startup_programs_are_local"),
            ("runtime-outer-routing-daemon", None, None, None, None, "outer_namespaces_have_no_routing_daemon"),
            ("runtime-unknown-namespace-container", None, None, None, None, "appliance_observations_complete"),
            ("runtime-missing-appliance", None, None, None, None, "appliance_observations_complete"),
            ("runtime-empty-namespace-processes", None, None, None, None, "appliance_observations_complete"),
            ("runtime-unsynchronized-worker", None, None, None, None, "sampled_appliance_clocks_agree_with_synchronized_worker"),
            ("runtime-extra-active-interface", None, None, None, None, "observed_interfaces_covered"),
            ("wrong-policy-id", "I_A1", "iptables", "--reqid 101", "--reqid 999", "contract_lookup_matches"),
            ("wrong-policy-direction", "I_A1", "iptables", "--dir out", "--dir in", "contract_lookup_matches"),
            ("unrestricted-inner-protocol", "I_A1", "iptables", "-p tcp ", "", "contract_lookup_matches"),
            ("missing-outer-header-guard", "O_A1", "iptables", "--u32", "", "contract_lookup_matches"),
            ("broad-outer-allow", "O_A1", "iptables", "COMMIT", "-A FORWARD -m policy --dir out --pol ipsec --reqid 201 --mode tunnel -j ACCEPT\nCOMMIT", "contract_lookup_matches"),
            ("open-outer-firewall", "OF_B2", "iptables", "COMMIT", "-A FORWARD -j ACCEPT\nCOMMIT", "contract_lookup_matches"),
            ("broad-local-output", "O_A1", "iptables", "COMMIT", "-A OUTPUT -p tcp -j ACCEPT\nCOMMIT", "local_contract_tables_match"),
            ("broad-local-input", "I_A1", "iptables", "COMMIT", "-A INPUT -p udp -j ACCEPT\nCOMMIT", "local_contract_tables_match"),
            ("firewall-open-output", "OF_A1", "iptables", ":OUTPUT DROP", ":OUTPUT ACCEPT", "firewall_local_tables_match"),
            ("gray-open-output", "GF_A", "iptables", ":OUTPUT DROP", ":OUTPUT ACCEPT", "firewall_local_tables_match"),
            ("firewall-extra-service", "OF_A1", "iptables", "COMMIT", "-A OUTPUT -p tcp -j ACCEPT\nCOMMIT", "firewall_local_tables_match"),
            ("firewall-wrong-source", "OF_A1", "iptables", "-s 172.21.11.1", "-s 192.0.2.123", "firewall_local_tables_match"),
            ("firewall-wide-destination", "OF_A1", "iptables", "-d 224.0.0.5", None, "firewall_local_tables_match"),
            ("firewall-wrong-interface", "OF_A1", "iptables", "-o outside", None, "firewall_local_tables_match"),
            ("firewall-missing-control", "OF_A1", "iptables", "-p ospf", None, "firewall_local_tables_match"),
            ("missing-ike-allow", "OF_B2", "iptables", "--dports 500,4500", "--dports 4500", "contract_lookup_matches"),
            ("wrong-ike-version", "I_A1", "swanctl.conf", "version = 2", "version = 1", "intended_ikev2_tunnel_mode"),
            ("wrong-esp-mode", "I_A1", "swanctl.conf", "mode = tunnel", "mode = transport", "intended_ikev2_tunnel_mode"),
            ("wrong-gcm-proposal", "I_A1", "swanctl.conf", "esp_proposals = aes256gcm16-ecp384", "esp_proposals = aes128gcm16-ecp384", "intended_gcm_proposals"),
            ("excess-ike-lifetime", "I_A1", "swanctl.conf", "over_time = 10m", "over_time = 24h", "intended_ike_lifetime_bound"),
            ("excess-child-lifetime", "I_A1", "swanctl.conf", "life_time = 1h", "life_time = 9h", "intended_child_lifetime_bound"),
            ("weaken-authentication", "I_A1", "swanctl.conf", "auth = pubkey", "auth = psk", "intended_certificate_authentication"),
            ("wildcard-peer-identity", "I_A1", "swanctl.conf", "id = I_B1.msc.test", "id = %any", "intended_peer_identities"),
            ("wrong-local-identity", "I_A1", "swanctl.conf", "id = I_A1.msc.test", "id = unrelated.msc.test", "intended_peer_identities"),
            ("relaxed-revocation", "I_A1", "swanctl.conf", "revocation = strict", "revocation = relaxed", "intended_strict_revocation"),
            ("wrong-service-placement", "I_A1", "services.json", "local CRL files", "remote CRL server", "selected_service_mechanisms_are_declared"),
        ]
        requested = {name for name in os.environ.get("TDN_MSC_MUTATIONS", "").split(",") if name}
        if requested:
            self.assertFalse(requested - {case[0] for case in mutations}, "unknown mutation filter")
            mutations = [case for case in mutations if case[0] in requested]
        with tempfile.TemporaryDirectory(prefix="tdn-proof-mutations-") as temporary:
            work = Path(temporary)
            shutil.copytree(ROOT / "TDN", work / "TDN")
            for name in ["TDN.lean", "Main.lean", "lakefile.toml", "lean-toolchain"]:
                shutil.copy2(ROOT / name, work / name)
            env = dict(os.environ)
            env.pop("LEAN_PATH", None)
            for name, device, suffix, old, new, theorem in mutations:
                with self.subTest(mutation=name):
                    snapshot = work / "snapshot"
                    if snapshot.exists():
                        shutil.rmtree(snapshot)
                    shutil.copytree(IMPORTER.CURRENT_EVIDENCE / "snapshot", snapshot)
                    manifest_path = snapshot / "manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    checks_path = IMPORTER.CURRENT_EVIDENCE / "check.json"
                    if name.startswith("runtime-"):
                        status = json.loads((snapshot / "status.json").read_text())
                        observations = {d["device"]: d for d in status["devices"]}
                        facts = observations["O_A1"]["facts"]
                        credential_facts = observations["I_A1"]["facts"]
                        if name == "runtime-interfaces":
                            facts["interfaces"] = "[]"
                        elif name == "runtime-routes":
                            facts["routes"] = "[]"
                        elif name == "runtime-policies":
                            facts["policies"] = ""
                        elif name == "runtime-states":
                            facts["xfrm"] = ""
                        elif name == "runtime-host-missing-policies":
                            del observations["R_A1"]["facts"]["policies"]
                        elif name == "runtime-host-extra-policy":
                            observations["R_A1"]["facts"]["policies"] = observations["I_A1"]["facts"]["policies"]
                        elif name == "runtime-credential-key":
                            for observation in observations.values():
                                if "certificates" in observation["facts"]:
                                    observation["facts"]["certificates"] = observation["facts"]["certificates"].replace("ECDSA 384 bits", "RSA 512 bits")
                        elif name == "runtime-credential-expiry":
                            for observation in observations.values():
                                if "certificates" in observation["facts"]:
                                    observation["facts"]["certificates"] = re.sub(r"(not after\s+\w+\s+\d+\s+\d+:\d+:\d+\s+(?:UTC\s+)?)2026",
                                                                                r"\g<1>2025", observation["facts"]["certificates"])
                        elif name == "runtime-extra-session":
                            extra = re.sub(r": #(\d+),", lambda match: f": #{int(match[1]) + 1000},", credential_facts["sas"])
                            extra = extra.replace("I_B1.msc.test", "I_B2.msc.test")
                            credential_facts["sas"] += extra
                        elif name in {"runtime-child-weaker-cipher", "runtime-child-wrong-group"}:
                            proposal = "AES_GCM_16-128" if name == "runtime-child-weaker-cipher" else "AES_GCM_16-256/ECP_256"
                            changed, count = re.subn(r"(ESP:)AES_GCM_16-256(?:/ECP_384)?", r"\g<1>" + proposal, credential_facts["sas"])
                            self.assertGreater(count, 0)
                            credential_facts["sas"] = changed
                        elif name == "runtime-loaded-revocation":
                            credential_facts["connections-raw"] = credential_facts["connections-raw"].replace("revocation=GOOD", "revocation=SKIPPED")
                        elif name == "runtime-missing-reported-crl":
                            credential_facts["certificates"] = credential_facts["certificates"].split("List of X.509 CRLs")[0] + "List of X.509 CRLs\n"
                        elif name == "runtime-missing-public-audit":
                            del credential_facts["credential-audit"]
                        elif name in {"runtime-certificate-cdp", "runtime-missing-retrieval-metadata"}:
                            audit = json.loads(credential_facts["credential-audit"])
                            certificate = audit["certificates"][0]
                            if name == "runtime-certificate-cdp":
                                certificate["crl_distribution_points"] = ["http://crl.example.test/current"]
                            else:
                                for field in ["crl_distribution_points", "ocsp_servers", "issuing_certificate_urls"]:
                                    del certificate[field]
                            credential_facts["credential-audit"] = json.dumps(audit)
                        elif name == "runtime-missing-authorities":
                            del credential_facts["authorities-raw"]
                        elif name == "runtime-new-authority":
                            credential_facts["authorities-raw"] = (
                                "list-authority event {remote {cacert=CN=fixture crl_uris=[http://crl.example.test/current] "
                                "ocsp_uris=[] cert_uri_base=}}\nlist-authorities reply {}\n")
                        elif name == "runtime-finite-address-lifetime":
                            interfaces = json.loads(facts["interfaces"])
                            gray = next(port for port in interfaces if port["ifname"] == "gray")
                            gray["addr_info"][0]["valid_life_time"] = 3600
                            facts["interfaces"] = json.dumps(interfaces)
                        elif name == "runtime-dhcp-process":
                            appliance = json.loads(facts["appliance"])
                            appliance["processes"].append({"pid": 999998, "name": "dhclient", "executable": "/sbin/dhclient"})
                            facts["appliance"] = json.dumps(appliance)
                        elif name in {"runtime-credential-revoked", "runtime-credential-stale-crl", "runtime-credential-signature", "runtime-local-certificate-usage"}:
                            audit = json.loads(credential_facts["credential-audit"])
                            peer = next(c for c in audit["certificates"] if c["subject"] == "CN=I_B1.msc.test")
                            if name == "runtime-credential-revoked":
                                audit["crls"][0]["revoked_serials"] = [peer["serial"]]
                            elif name == "runtime-credential-stale-crl":
                                audit["crls"][0]["next_update"] = audit["at_epoch"]
                            elif name == "runtime-local-certificate-usage":
                                local = next(c for c in audit["certificates"] if c["subject"] == "CN=I_A1.msc.test")
                                local["key_usage"] = 0
                            else:
                                for verification in peer["verifications"]:
                                    verification.update(valid=False, error="mutation: invalid signature")
                            credential_facts["credential-audit"] = json.dumps(audit)
                        elif name == "runtime-forwarding":
                            facts["forwarding"] = "0"
                        elif name in {"runtime-peer-index", "runtime-mtu"}:
                            ports = json.loads(facts["interfaces"])
                            port = next(p for p in ports if p["ifname"] == "gray")
                            if name == "runtime-peer-index":
                                port["link_index"] += 1
                            else:
                                port["mtu"] -= 1
                            facts["interfaces"] = json.dumps(ports)
                        elif name == "runtime-next-hop":
                            routes = json.loads(facts["routes"])
                            next(r for r in routes if "gateway" in r)["gateway"] = "192.0.2.1"
                            facts["routes"] = json.dumps(routes)
                        elif name == "runtime-gray-return-route":
                            routes = json.loads(facts["routes"])
                            next(r for r in routes if r["dst"] == "10.100.1.0/24")["dev"] = "black"
                            facts["routes"] = json.dumps(routes)
                        elif name == "runtime-route-scope":
                            routes = json.loads(facts["routes"])
                            next(r for r in routes if r["dst"] == "10.100.1.0/24")["scope"] = "host"
                            facts["routes"] = json.dumps(routes)
                        elif name == "runtime-gray-reverse-override":
                            routes = json.loads(facts["routes"])
                            routes.append({"dst": "10.100.1.2/32", "dev": "black", "gateway": "172.20.11.2",
                                           "protocol": "static", "flags": []})
                            facts["routes"] = json.dumps(routes)
                        elif name == "runtime-policy-direction":
                            facts["policies"] = facts["policies"].replace("dir out", "dir in")
                        elif name == "runtime-policy-selector":
                            facts["policies"] = facts["policies"].replace("10.100.1.2/32", "10.100.1.0/24")
                        elif name == "runtime-policy-reqid":
                            facts["policies"] = facts["policies"].replace("reqid 201", "reqid 999")
                        elif name == "runtime-policy-spi":
                            facts["policies"], count = re.subn(r"spi 0x[0-9a-f]+", "spi 0x12345678", facts["policies"])
                            self.assertGreater(count, 0)
                        elif name == "runtime-extra-switch-flow":
                            observations["G_A1"]["facts"]["openflow"] += "cookie=0, table=0, priority=10,ip actions=output:2\n"
                        elif name == "runtime-extra-active-interface":
                            ports = json.loads(facts["interfaces"])
                            ports.append({**ports[0], "ifname": "unused0", "ifindex": 99999,
                                          "flags": ["UP", "LOWER_UP"], "addr_info": []})
                            facts["interfaces"] = json.dumps(ports)
                        elif name == "runtime-missing-appliance":
                            del facts["appliance"]
                        elif name == "runtime-ovs-boot-manager":
                            observations["G_A1"]["facts"]["ovs"] += '\n    Manager "tcp:192.0.2.1:6640"\n'
                        elif name in {"runtime-extra-resolver", "runtime-remote-boot", "runtime-outer-routing-daemon",
                                      "runtime-unknown-namespace-container", "runtime-unsynchronized-worker", "runtime-empty-namespace-processes"}:
                            appliance = json.loads(facts["appliance"])
                            if name == "runtime-extra-resolver":
                                appliance["containers"][0]["resolver"] += "nameserver\t192.0.2.1\n"
                            elif name == "runtime-remote-boot":
                                appliance["containers"][0]["command"] = ["tftp", "-g", "192.0.2.1"]
                            elif name == "runtime-outer-routing-daemon":
                                appliance["processes"].append({"pid": 999999, "name": "ospfd", "executable": "/usr/lib/frr/ospfd"})
                            elif name == "runtime-unknown-namespace-container":
                                appliance["containers"].append({**appliance["containers"][0], "name": "unapproved-sidecar"})
                            elif name == "runtime-empty-namespace-processes":
                                appliance["processes"] = []
                            else:
                                appliance["ntp_synchronized"] = False
                            facts["appliance"] = json.dumps(appliance)
                        path = snapshot / "status.json"
                        path.write_text(json.dumps(status))
                        manifest["sha256"]["status.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
                    if name in {"black-bypass", "duplicate-gray-address", "selector-widen", "selector-narrow"}:
                        spec = json.loads((snapshot / "spec.json").read_text())
                        status = json.loads((snapshot / "status.json").read_text())
                        if name == "black-bypass":
                            black = next(d for d in spec["devices"] if d["id"] == "BLACK")
                            port = next(p["name"] for p in black["interfaces"] if p["zone"] == "black")
                            spec["links"].append({"a": {"device": "O_A1", "interface": "black"}, "b": {"device": "BLACK", "interface": port}})
                        elif name == "duplicate-gray-address":
                            outer = next(d for d in spec["devices"] if d["id"] == "O_A2")
                            next(p for p in outer["interfaces"] if p["zone"] == "gray")["address"] = "10.100.1.2/24"
                        else:
                            changes = {"10.1.1.0/24": "10.1.0.0/16", "10.2.1.0/24": "10.2.0.0/16"}
                            if name == "selector-narrow":
                                changes = {old: old.replace("/24", "/25") for old in changes}

                            def altered(text):
                                for before, after in changes.items():
                                    text = text.replace(before, after)
                                return text

                            for declared in spec["devices"]:
                                if declared["id"] in {"I_A1", "I_B1"}:
                                    for field in ["local_ts", "remote_ts"]:
                                        declared["tunnel"][field] = altered(declared["tunnel"][field])
                            for observed in status["devices"]:
                                if observed["device"] in {"I_A1", "I_B1"}:
                                    observed["facts"] = {key: altered(value) for key, value in observed["facts"].items()}
                            for owner in ["I_A1", "I_B1"]:
                                for suffix_name in ["intended.iptables", "observed.iptables", "intended.swanctl.conf"]:
                                    relative = f"devices/{owner}/{suffix_name}"
                                    path = snapshot / relative
                                    path.write_text(altered(path.read_text()))
                                    manifest["sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                        digest = hashlib.sha256(json.dumps(spec, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
                        status["spec_sha256"] = digest
                        for device_status in status["devices"]:
                            device_status["deployed_spec_sha256"] = digest
                        manifest["spec_sha256"] = digest
                        for relative, value in [("spec.json", spec), ("status.json", status)]:
                            path = snapshot / relative
                            path.write_text(json.dumps(value))
                            manifest["sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                        report = json.loads(checks_path.read_text())
                        report["spec_sha256"] = digest
                        checks_path = work / "check.json"
                        checks_path.write_text(json.dumps(report))
                    if name in {"substituted-ca", "duplicated-ca-key-id", "duplicated-local-key-id", "missing-certificates", "wrong-peer-certificate"}:
                        status = json.loads((snapshot / "status.json").read_text())
                        facts = {d["device"]: d["facts"] for d in status["devices"]}
                        donor = facts["I_A1"]["certificates"]
                        target = facts["I_A2"]["certificates"]
                        if name == "missing-certificates":
                            del facts["I_A2"]["certificates"]
                        else:
                            donor_ca = donor.split("List of X.509 CA Certificates")[1].split("List of X.509 CRLs")[0]
                            target_ca = target.split("List of X.509 CA Certificates")[1].split("List of X.509 CRLs")[0]
                            if name == "substituted-ca":
                                target = target.replace(target_ca, donor_ca)
                            elif name == "duplicated-ca-key-id":
                                before = re.search(r"  keyid:\s*(\S+)", target_ca)[1]
                                after = re.search(r"  keyid:\s*(\S+)", donor_ca)[1]
                                target = target.replace(before, after)
                            elif name == "duplicated-local-key-id":
                                before = re.search(r"  keyid:\s*(\S+)", target)[1]
                                after = re.search(r"  keyid:\s*(\S+)", donor)[1]
                                target = target.replace(before, after)
                            else:
                                target = target.replace("I_B2.msc.test", "unrelated.msc.test")
                            facts["I_A2"]["certificates"] = target
                        path = snapshot / "status.json"
                        path.write_text(json.dumps(status))
                        manifest["sha256"]["status.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
                    kinds = [] if suffix is None else (["intended", "observed"] if suffix == "iptables" else ["intended"])
                    for kind in kinds:
                        relative = f"devices/{device}/{kind}.{suffix}"
                        path = snapshot / relative
                        text = path.read_text()
                        self.assertIn(old, text)
                        if name == "missing-outer-header-guard":
                            text = re.sub(r' -m u32 --u32 "[^"]+"', '', text)
                        elif name == "firewall-wide-destination":
                            text = re.sub(r"-d 224\.0\.0\.5(?:/32)?", "-d 224.0.0.0/24", text)
                        elif name == "firewall-wrong-interface":
                            text = "\n".join(line.replace("-o outside", "-o inside")
                                             if line.startswith("-A OUTPUT ") and "-p ospf" in line else line
                                             for line in text.splitlines()) + "\n"
                        elif name == "firewall-missing-control":
                            text = "\n".join(line for line in text.splitlines()
                                             if not (line.startswith("-A OUTPUT ") and "-p ospf" in line)) + "\n"
                        else:
                            text = text.replace(old, new)
                        path.write_text(text)
                        manifest["sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                    manifest_path.write_text(json.dumps(manifest))
                    generated = IMPORTER.translate(snapshot, checks_path)
                    (work / "TDN/MSC/Deployment.lean").write_text(generated)
                    result = subprocess.run([lake, "build", "TDN"], cwd=work, env=env,
                                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
                    self.assertNotEqual(result.returncode, 0, name + " unexpectedly passed")
                    spans = []
                    for path in (work / "TDN/MSC").glob("*.lean"):
                        text = path.read_text()
                        start = re.search(rf"(?m)^theorem {theorem}\b", text)
                        if start:
                            following = re.search(r"(?m)^(?:theorem |end )", text[start.end():])
                            end = start.end() + following.start() if following else len(text)
                            spans.append((path.stem, text[:start.start()].count("\n") + 1, text[:end].count("\n") + 1))
                    errors = re.findall(r"error: TDN/MSC/(\w+)\.lean:(\d+):", result.stdout)
                    self.assertTrue(any(module == file and low <= int(line) <= high
                                        for module, line in errors for file, low, high in spans), result.stdout)


if __name__ == "__main__":
    unittest.main()
