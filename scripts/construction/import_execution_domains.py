"""Check full declared labels and instantiate the generic packet-domain proof."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
from import_snapshot import lean_list
from import_trust_partition import lean_level
from validate_evidence import require


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("execution_report")
    parser.add_argument("--declaration", required=True)
    parser.add_argument("--base-module", required=True)
    parser.add_argument("--base-namespace", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    report = json.loads(Path(args.execution_report).read_text())
    bundle = Path(report["snapshot"])
    snapshot = json.loads((bundle / "snapshot.json").read_text())
    manifest = json.loads((bundle / "manifest.json").read_text())
    declaration = json.loads(Path(args.declaration).read_text())
    declared = next(c for c in declaration["configurations"] if c["configuration_id"] == manifest["configuration_id"])
    require(declared["spec_sha256"] == manifest["configuration_hashes"]["spec"], "Fresh configuration differs from source-linked declaration")
    require(set(declared["source_case_ids"]) == set(manifest["source_case_ids"]), "Source alternatives differ from declaration")
    bindings = {b["interface_id"]: b for b in declared["device_port_bindings"]}
    red_interfaces = {i["id"]: i for i in snapshot["interfaces"] if i["zone"] == "red"}
    require(set(bindings) == set(red_interfaces), "Declared Red attachment inventory mismatch")
    devices = {d["id"]: d for d in snapshot["devices"]}
    for interface, binding in bindings.items():
        observed = red_interfaces[interface]
        require(observed["device_id"] == binding["device_id"], "Declared owner differs")
        require(devices[binding["device_id"]]["security_level_id"] == binding["security_level_id"], "Full-level identifier differs")
    labels = {}
    canonical = {}
    full_levels = {}
    for level in declared["security_levels"]:
        value = {k: sorted(level[k]) if isinstance(level[k], list) else level[k] for k in ["classification", "compartments", "dissemination_controls", "other_controls"]}
        key = json.dumps(value, sort_keys=True)
        if key not in canonical:
            canonical[key] = len(canonical) + 1
            full_levels[canonical[key]] = value
        labels[level["id"]] = canonical[key]
    owner_domains = {report["device_ids"][d["id"]]: labels[d["security_level_id"]] for d in devices.values() if d["role"] in {"inner", "host"}}
    owner_tags = {report["device_ids"][d["id"]]: labels[d["security_level_id"]] + 10 if d["role"] == "inner" else 2 for d in devices.values() if d["role"] in {"inner", "outer"}}
    domains = sorted(full_levels)
    base = "TDN.Imported." + args.base_namespace
    declarations = [f"import {args.base_module}", "import TDN.Targets.DeliveryIsolation", "import TDN.Targets.Architecture", "", "namespace TDN.Imported." + args.namespace, "open Execution", "", "set_option maxRecDepth 1000000", "set_option maxHeartbeats 0", "set_option linter.unusedSimpArgs false", "", "def ownerDomain : Nat → Option Nat"]
    declarations += ["  | " + str(owner) + " => some " + str(domain) for owner, domain in sorted(owner_domains.items())] + ["  | _ => none", "", "def ownerTag : Nat → Nat"]
    declarations += ["  | " + str(owner) + " => " + str(tag) for owner, tag in sorted(owner_tags.items())] + ["  | _ => 0", "", "def fullLevel : Nat → SecurityLevel"]
    declarations += ["  | " + str(domain) + " => " + lean_level(value) for domain, value in full_levels.items()]
    declarations += ['  | _ => ⟨"", {}, {}, {}⟩', "", f"def taggedDevices : List DeviceData := {base}.devices.zipIdx.map fun pair =>", "  { pair.1 with", "    outbound := pair.1.outbound.map (fun a => { a with tag := ownerTag pair.2 })", "    inbound := pair.1.inbound.map (fun a => { a with tag := ownerTag pair.2 })", "    recipientDomain := pair.1.recipientDomain.bind (fun _ => ownerDomain pair.2) }", "", "def stackFor (domain : Nat) (port : PortData) : List Nat :=", "  if port.stack = [] then [] else if port.stack = [1] then [domain + 10] else [2, domain + 10]", "def allowedRecord (domain : Nat) (port : PortData) : Bool :=", "  !port.stack.isEmpty || decide (ownerDomain port.owner = some domain)", "", f"def config : Execution.Config := finiteConfig taggedDevices {base}.ports {base}.routes {base}.links {base}.switches", f"def redSources : List Nat := {base}.redSources", "def domains : List Nat := " + lean_list([str(d) for d in domains]), "", "lemma peer_tag_checks : FinitePeerTagAgreement taggedDevices := by", f"  unfold FinitePeerTagAgreement taggedDevices {base}.devices ownerTag ownerDomain StateBindsPolicy SameWireAssociation; decide", "lemma peer_tags_justified_by_wire_SAs : PeerTagAgreement config :=", f"  finite_peer_tag_agreement_sound taggedDevices {base}.ports {base}.routes {base}.links {base}.switches peer_tag_checks", ""]
    for domain in domains:
        n = str(domain)
        port_name = "domainPorts" + n
        layout_name = "domainLayout" + n
        allow_name = "domainAllowed" + n
        expand = f"{port_name} withPortStacks stackFor allowedRecord taggedDevices ownerTag ownerDomain {base}.ports {base}.devices"
        declarations += [
            f"def {port_name} : List PortData := withPortStacks {base}.ports (stackFor {n})",
            f"def {layout_name} : Nat → List Nat := finiteLayout {port_name}",
            f"def {allow_name} (p : Nat) : Prop := allowedRecord {n} (portAt {port_name} p) = true",
            f"lemma config_same{n} : finiteConfig taggedDevices {port_name} {base}.routes {base}.links {base}.switches = config :=",
            f"  finite_config_ignores_port_stack_annotations taggedDevices {base}.ports (stackFor {n}) {base}.routes {base}.links {base}.switches",
            f"lemma route_owner_checks{n} : ∀ r ∈ {base}.routes, (portAt {port_name} r.egress).owner = (portAt {port_name} r.ingress).owner := by",
            f"  unfold {base}.routes {expand}; decide",
            f"lemma link_checks{n} : ∀ edge ∈ {base}.links, allowedRecord {n} (portAt {port_name} edge.1) = true → (portAt {port_name} edge.1).stack = (portAt {port_name} edge.2).stack ∧ allowedRecord {n} (portAt {port_name} edge.2) = true := by",
            f"  unfold {base}.links {expand}; decide",
            f"lemma switch_checks{n} : ∀ edge ∈ {base}.switches, allowedRecord {n} (portAt {port_name} edge.1) = true → ((portAt {port_name} edge.1).stack = (portAt {port_name} edge.2).stack ∧ (deviceAt taggedDevices (portAt {port_name} edge.1).owner).inbound = []) ∧ allowedRecord {n} (portAt {port_name} edge.2) = true := by",
            f"  unfold {base}.switches {expand}; decide",
            f"lemma forward_default_checks{n} : ∀ d ∈ ({{}} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by",
            f"  unfold {expand}; decide",
            f"lemma forward_checks{n} : FiniteDomainForwardChecks taggedDevices {port_name} (allowedRecord {n}) := by",
            f"  unfold FiniteDomainForwardChecks {expand}; decide",
            f"lemma output_checks{n} : FiniteDomainOutputChecks taggedDevices {port_name} (allowedRecord {n}) := by",
            f"  unfold FiniteDomainOutputChecks {expand}; decide",
            f"lemma outer_route_checks{n} : FiniteDomainOuterRoutes taggedDevices {port_name} {base}.routes (allowedRecord {n}) := by",
            f"  unfold FiniteDomainOuterRoutes {base}.routes {expand}; decide",
            f"lemma local_domain_conditions{n} : LocalDomainConditions config {layout_name} {allow_name} := by",
            f"  have checked := local_domain_conditions_of_finite_checks taggedDevices {port_name} {base}.routes {base}.links {base}.switches (allowedRecord {n})",
            f"    route_owner_checks{n} link_checks{n} switch_checks{n} forward_default_checks{n} forward_checks{n} output_checks{n} outer_route_checks{n}",
            f"  rw [config_same{n}] at checked",
            "  exact checked",
            f"lemma source_checks{n} : ∀ p ∈ redSources, config.recipientDomain p = some {n} → {layout_name} p = [] ∧ config.payloadOrigin p ∧ {allow_name} p := by",
            f"  unfold redSources {base}.redSources config finiteConfig {layout_name} finiteLayout {allow_name} {expand}; decide",
            f"lemma recipient_records{n} : ∀ p ∈ ({{}} : PortData) :: {port_name}, allowedRecord {n} p = true → (deviceAt taggedDevices p.owner).recipientDomain = none ∨ (deviceAt taggedDevices p.owner).recipientDomain = some {n} := by",
            f"  unfold {expand}; decide",
            f"lemma recipient_checks{n} : ∀ p, {allow_name} p → config.recipientDomain p = none ∨ config.recipientDomain p = some {n} := by",
            "  intro p permitted",
            f"  have checked := recipient_records{n} (portAt {port_name} p) (port_at_member_or_default {port_name} p) permitted",
            f"  change (finiteConfig taggedDevices {port_name} {base}.routes {base}.links {base}.switches).recipientDomain p = none ∨ (finiteConfig taggedDevices {port_name} {base}.routes {base}.links {base}.switches).recipientDomain p = some {n} at checked",
            f"  rw [config_same{n}] at checked",
            "  exact checked",
            ""
        ]
    declarations += [
        "lemma source_domains_checked : ∀ p ∈ redSources, config.recipientDomain p ∈ domains.map some := by",
        f"  unfold redSources {base}.redSources config finiteConfig taggedDevices ownerTag ownerDomain domains {base}.devices {base}.ports; decide",
        "theorem snapshot_RG008_IPv4_ESP_delivery : Targets.msc_same_domain_plaintext_delivery config redSources := by",
        "  intro start finish actions sourceDomain recipientDomain origin sourceLevel run delivered recipientLevel",
        "  have member : some sourceDomain ∈ domains.map some := by",
        "    rw [← sourceLevel]",
        "    exact source_domains_checked start.port origin.1",
        "  have domainMember : sourceDomain ∈ domains := by simpa using member",
        "  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at domainMember",
        "  rcases domainMember with " + " | ".join("rfl" for _ in domains)
    ]
    for domain in domains:
        n = str(domain)
        declarations += [f"  · exact Targets.delivered_domain_from_local_checks config domainLayout{n} domainAllowed{n} redSources {n}",
                         f"      local_domain_conditions{n} source_checks{n} recipient_checks{n} origin sourceLevel run delivered recipientLevel"]
    declarations += [
        "",
        "theorem snapshot_RG008_full_label_delivery {start finish : Execution.State} {actions : List Execution.Action} {source recipient : Nat}",
        "    (origin : Targets.RedPayloadOrigin config redSources start) (sourceLevel : config.recipientDomain start.port = some source)",
        "    (run : (lts config).MTr start actions finish) (delivered : finish.phase = .delivered)",
        "    (recipientLevel : config.recipientDomain finish.port = some recipient) : fullLevel source = fullLevel recipient :=",
        "  congrArg fullLevel (snapshot_RG008_IPv4_ESP_delivery start finish actions source recipient origin sourceLevel run delivered recipientLevel)",
        "",
        "def layout : Nat → List Nat := domainLayout" + str(domains[0]),
        "",
        "end TDN.Imported." + args.namespace,
        ""
    ]
    declarations = [
        "  (try simp only [" + ", ".join(line.removeprefix("  unfold ").removesuffix("; decide").split()) + "]); all_goals decide"
        if line.startswith("  unfold ") and line.endswith("; decide") else line
        for line in declarations
    ]
    Path(args.output).write_text("\n".join(declarations))
    output_report = copy.deepcopy(report)
    output_report["levels"] = labels
    for identifier, policies in output_report["policies"].items():
        for direction in ["in", "out", "fwd"]:
            for policy in policies[direction]:
                policy[1] = owner_tags[report["device_ids"][identifier]]
    output_report["domain_interpretation"] = {"source_declaration": args.declaration, "sha256": hashlib.sha256(Path(args.declaration).read_bytes()).hexdigest(), "captured_spec_matches_declaration": True, "declared_red_attachments": len(bindings), "full_labels": full_levels, "canonical_domain_ids": labels, "owner_domains": owner_domains, "scope": "Wrong-domain plaintext delivery from each declared Red-host origin; every shared Gray/Black port remains allowed. Canonical identities compare all four full-label dimensions."}
    Path(args.report).write_text(json.dumps(output_report, indent=2) + "\n")
    print(json.dumps({"domains": len(domains), "red_attachments": len(bindings), "tagged_policies": sum(len(p["in"]) + len(p["out"]) for p in report["policies"].values())}))


if __name__ == "__main__":
    main()
