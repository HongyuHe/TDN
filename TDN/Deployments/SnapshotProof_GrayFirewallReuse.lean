import TDN.Deployments.SnapshotProof_GrayFirewall

namespace TDN.Deployments.SnapshotProof_GrayFirewallReuse
open Compliance Requirements Requirements.Msc Requirements.DeriveEndpointInputOutputRules

abbrev low := SnapshotProof_GrayFirewall.low
abbrev high := SnapshotProof_GrayFirewall.high
def interface (name owner : String) (address : Nat) : Interface :=
  { id := name, device := owner, zone := .gray, address := some address,
    physical := true, managementNetwork := false }

def devices : List Device :=
  [⟨"node-IA", "A", .vpn, some .inner, low, true⟩,
   ⟨"node-IB", "B", .vpn, some .inner, low, true⟩,
   ⟨"node-IC", "C", .vpn, some .inner, high, true⟩,
   ⟨"node-G", "B", .grayFirewall, none, high, true⟩,
   ⟨"node-O", "B", .vpn, some .outer, high, true⟩]

def interfaces : List Interface :=
  [interface "port-IA" "node-IA" 10, interface "port-IB" "node-IB" 20,
   interface "port-IC" "node-IC" 40, interface "port-G" "node-G" 90,
   interface "port-O" "node-O" 80]

def rules : List PacketPolicy.Rule :=
  [⟨[.sourceRange 10 10, .destinationRange 20 20, .protocol "esp"], .allow⟩,
   ⟨[.sourceRange 20 20, .destinationRange 10 10, .protocol "esp"], .allow⟩]

def policies : List InterfacePolicy :=
  interfaces.flatMap fun iface =>
    [⟨iface.id, .inbound, rules, .deny, .input⟩,
     ⟨iface.id, .outbound, rules, .deny, .output⟩,
     ⟨iface.id, .inbound, rules, .deny, .forward⟩,
     ⟨iface.id, .outbound, rules, .deny, .forward⟩]

def inventory (base : PacketProcessing.Inventory) : PacketProcessing.Inventory :=
  { SnapshotProof_GrayFirewall.inventory base with
    ifaces := [0, 1, 2, 3, 4]
    ifaceName := fun iface => if iface = 0 then "port-IA" else if iface = 1 then "port-IB"
      else if iface = 2 then "port-IC" else if iface = 3 then "port-G" else "port-O" }

def deployment (base : Deployment) (processing : PacketProcessing.Inventory) : Deployment :=
  { SnapshotProof_GrayFirewall.deployment base processing with
    devices := devices, interfaces := interfaces, policies := policies,
    grayWorkstation := fun _ => False, processing := some (inventory processing) }

def edges : List (String × String) :=
  [("node-IA", "node-IB"), ("node-IB", "node-IA"),
   ("node-IB", "node-G"), ("node-G", "node-IB"),
   ("node-IC", "node-G"), ("node-G", "node-IC"),
   ("node-G", "node-O"), ("node-O", "node-G")]

def topology : GrayTopology :=
  { SnapshotProof_GrayFirewall.topology with
    edge := fun first second => (first, second) ∈ edges
    workstation := fun _ => False }

def pairs : List EndpointPair :=
  [⟨.internet, "node-IA", "node-IB", 10, 20⟩,
   ⟨.internet, "node-IB", "node-IA", 20, 10⟩]

def paths : List GrayPathWitness :=
  [⟨"node-G", "node-IB", "node-O", ["node-IB", "node-G"], ["node-G", "node-O"]⟩]

theorem management_free_chain_model_RG013 (base : Deployment)
    (processing : PacketProcessing.Inventory)
    (physicalFact : base.authority.protectsAsClassified "node-G") :
    msc_gray_firewall_path_coverage (deployment base processing) topology := by
  apply gray_firewall_path_coverage_from_edge_inventory_and_rule_atoms
    (deployment base processing) topology (inventory processing) rfl
    (by rfl) ?_ (by rfl) ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_
    edges (by intro _ _; rfl) ?_ ?_ ?_ ?_ ?_ pairs ?_ ?_ paths ?_ ?_
  · funext component
    simp [deployment, SnapshotProof_GrayFirewall.deployment, grayWorkstationRole,
      Deployment.IsDevice, devices]
  · intro node
    simp [topology, SnapshotProof_GrayFirewall.topology, deployment,
      Deployment.IsLayer, devices, eq_comm]
  · intro node
    simp [topology, SnapshotProof_GrayFirewall.topology, deployment,
      Deployment.IsDevice, devices, eq_comm]
  · intro node
    simp [topology, SnapshotProof_GrayFirewall.topology, deployment,
      Deployment.IsLayer, devices, eq_comm]
  · intro node
    rfl
  · intro node
    simp [topology, SnapshotProof_GrayFirewall.topology]
  · intro node
    simp [topology, SnapshotProof_GrayFirewall.topology, deployment,
      Deployment.IsDevice, devices, eq_comm]
  · intro node
    simp [topology, SnapshotProof_GrayFirewall.topology, deployment,
      Deployment.IsDevice, devices, eq_comm]
  · intro device member
    simp only [deployment, devices, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl <;>
      simp [topology, SnapshotProof_GrayFirewall.topology]
  · change ∀ first ∈ devices, ∀ second ∈ devices, first.id = second.id → first = second
    simp [devices]
  · change ∀ device ∈ devices, device.layer = some .inner → device.kind ≠ .grayFirewall
    native_decide
  · simp [edges, topology, SnapshotProof_GrayFirewall.topology]
  · intro device member manager
    simp [GrayManagement, topology, SnapshotProof_GrayFirewall.topology] at manager
  · intro device member inner
    simp only [deployment, devices, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl <;>
      simp_all [topology, SnapshotProof_GrayFirewall.topology]
  · intro device member kind
    simp only [deployment, devices, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl <;>
      simp_all [deployment, SnapshotProof_GrayFirewall.deployment]
  · intro first firstMember second secondMember firstInner secondInner different
    exact ⟨⟨"node-G", "B", .grayFirewall, none, high, true⟩, by simp [deployment, devices], rfl⟩
  · simp [pairs, EndpointPair.Bound, AddressView.read, deployment, interfaces, interface,
      GrayEndpointRelation, SameLevelComponents, GrayManagement, topology,
      SnapshotProof_GrayFirewall.topology, Deployment.IsLayer, devices,
      SnapshotProof_GrayFirewall.deployment]
  · intro iface member _
    simp only [deployment, interfaces, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl <;>
      simp [admissionPrograms, deployment, policies, inventory, SnapshotProof_GrayFirewall.inventory,
        interfaces, ProgramRuleChecks, rules, RuleEndpointGuard, pairs,
        AddressView.RuleGuard, DeriveDataPlaneFromDeviceRecords.RuleIPGuard, DeriveDataPlaneFromDeviceRecords.IPProtocolAtom,
        EthernetTypeAtom, interface, LinkAdmission.lookup]
  · simp [paths, GrayPathWitness.Checked, topology, SnapshotProof_GrayFirewall.topology,
      edges, List.isChainFromTo_pair_iff]
  · intro device member kind
    simp only [deployment, devices, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl <;> simp_all [paths]

lemma management_free_and_topology_differs :
    (∀ device ∈ devices, device.kind ≠ .workstation) ∧
    ("node-IA", "node-IB") ∈ edges ∧ ("node-IA", "node-G") ∉ edges := by
  native_decide
lemma same_level_chain_packet_is_admitted (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (deployment base processing).Accepts "port-O" .outbound
      ((deployment base processing).Observe
        { SnapshotProof_GrayFirewall.packet with ingress := "port-O", egress := "port-O" }) := by
  refine ⟨.forward, ⟨rfl, ?_⟩, ?_, ?_⟩
  · change (deployment base processing).ManagementMetadataBound
      { SnapshotProof_GrayFirewall.packet with ingress := "port-O", egress := "port-O" }
    simp [Deployment.ManagementMetadataBound, SnapshotProof_GrayFirewall.packet,
      PacketClass, PacketService, PacketIKE, PacketMKA, PacketARP]
  · refine ⟨inventory processing, rfl, 4,
      by simp [inventory], rfl, interface "port-O" "node-O" 80,
      by simp [deployment, interfaces], rfl, rfl, ?_⟩
    simp [PacketAtHook, HookDirection, inventory, SnapshotProof_GrayFirewall.inventory,
      SnapshotProof_GrayFirewall.ifaceName, SnapshotProof_GrayFirewall.packet, Deployment.Observe]
  · simp [deployment, policies, interfaces, interface, SnapshotProof_GrayFirewall.packet,
      InterfacePolicy.Accepts, rules, PacketPolicy.Rule.toFilter, Filter.evaluate,
      Deployment.Observe, PacketPolicy.MatchCondition.matchesPacket]

end TDN.Deployments.SnapshotProof_GrayFirewallReuse
