import TDN.Targets.CompleteGrayFirewall

namespace TDN.Imported.CompleteGrayFirewall
open Compliance Targets Targets.Complete Targets.EndpointRuleDerivation

def low : SecurityLevel := ⟨"secret", ∅, ∅, ∅⟩
def high : SecurityLevel := ⟨"top-secret", ∅, ∅, ∅⟩

def devices : List Device :=
  [⟨"node-IA", "A", .vpn, some .inner, low, true⟩,
   ⟨"node-IB", "B", .vpn, some .inner, low, true⟩,
   ⟨"node-IC", "C", .vpn, some .inner, high, true⟩,
   ⟨"node-G", "A", .grayFirewall, none, high, true⟩,
   ⟨"node-O", "A", .vpn, some .outer, high, true⟩,
   ⟨"node-M", "A", .workstation, none, high, true⟩]

def interface (name owner : String) (address : Nat) (management : Bool := false) : Interface :=
  { id := name, device := owner, zone := .gray, address := some address,
    physical := true, managementNetwork := management }

def interfaces : List Interface :=
  [interface "port-IA" "node-IA" 10, interface "port-IB" "node-IB" 20,
   interface "port-IC" "node-IC" 40, interface "port-G" "node-G" 90,
   interface "port-O" "node-O" 80, interface "port-M" "node-M" 100 true]

def rules : List PacketPolicy.Rule :=
  [⟨[.sourceRange 10 10, .destinationRange 20 20, .protocol "esp"], .allow⟩,
   ⟨[.sourceRange 20 20, .destinationRange 10 10, .protocol "esp"], .allow⟩,
   ⟨[.sourceRange 100 100, .destinationRange 80 80, .protocol "tcp"], .allow⟩]

def policies : List InterfacePolicy :=
  interfaces.flatMap fun port =>
    [⟨port.id, .inbound, rules, .deny, .input⟩,
     ⟨port.id, .outbound, rules, .deny, .output⟩,
     ⟨port.id, .inbound, rules, .deny, .forward⟩,
     ⟨port.id, .outbound, rules, .deny, .forward⟩]

def inventory (base : PacketProcessing.Inventory) : PacketProcessing.Inventory :=
  { base with
    ports := [0, 1, 2, 3, 4, 5]
    portName := fun port => if port = 0 then "port-IA" else if port = 1 then "port-IB"
      else if port = 2 then "port-IC" else if port = 3 then "port-G"
      else if port = 4 then "port-O" else "port-M"
    configuration := { base.configuration with
      macPorts := [], bridge := fun _ _ => False, carriers := [], linkPolicies := [] }
    mkaPeers := [] }

def deployment (base : Deployment) (processing : PacketProcessing.Inventory) : Deployment :=
  { base with
    devices := devices, interfaces := interfaces, policies := policies,
    services := [], udpBindings := [], managementExchanges := [], managementHistory := [],
    grayWorkstation := fun component => component = "node-M",
    processing := some (inventory processing),
    intendedPeer := fun source destination =>
      (source = "node-IA" ∧ destination = "node-IB") ∨
      (source = "node-IB" ∧ destination = "node-IA") }

def edges : List (String × String) :=
  [("node-IA", "node-G"), ("node-G", "node-IA"),
   ("node-IB", "node-G"), ("node-G", "node-IB"),
   ("node-IC", "node-G"), ("node-G", "node-IC"),
   ("node-M", "node-G"), ("node-G", "node-M"),
   ("node-G", "node-O"), ("node-O", "node-G")]

def topology : GrayTopology :=
  { edge := fun first second => (first, second) ∈ edges,
    inner := fun node => node ∈ ["node-IA", "node-IB", "node-IC"],
    grayFirewall := fun node => node = "node-G",
    outer := fun node => node = "node-O",
    workstation := fun node => node = "node-M",
    localCA := fun _ => False, certificationAuthority := fun _ => False,
    revocationService := fun _ => False,
    level := fun node => if node ∈ ["node-IC", "node-G", "node-O", "node-M"] then high else low,
    highest := high, dominates := fun first second => first = high ∧ (second = low ∨ second = high) }

def pairs : List EndpointPair :=
  [⟨.internet, "node-IA", "node-IB", 10, 20⟩,
   ⟨.internet, "node-IB", "node-IA", 20, 10⟩,
   ⟨.internet, "node-M", "node-O", 100, 80⟩]

def paths : List GrayPathWitness :=
  [⟨"node-G", "node-IA", "node-O", ["node-IA", "node-G"], ["node-G", "node-O"]⟩]

theorem complete_model_RG013 (base : Deployment) (processing : PacketProcessing.Inventory)
    (physicalFact : base.authority.protectsAsClassified "node-G") :
    msc_gray_firewall_path_coverage (deployment base processing) topology := by
  apply gray_firewall_path_coverage_from_edge_inventory_and_rule_atoms
    (deployment base processing) topology (inventory processing) rfl
    (by rfl) ?_ (by rfl) ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_
    edges (by intro _ _; rfl) ?_ ?_ ?_ ?_ ?_ pairs ?_ ?_ paths ?_ ?_
  · funext component
    apply propext
    constructor
    · intro same
      change component = "node-M" at same
      subst component
      refine ⟨⟨⟨"node-M", "A", .workstation, none, high, true⟩,
        by simp [deployment, devices], rfl, rfl⟩, ?_⟩
      exact ⟨interface "port-M" "node-M" 100 true, by simp [deployment, interfaces], rfl, rfl, rfl⟩
    · rintro ⟨⟨device, member, same, kind⟩, _⟩
      simp only [deployment, devices, List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl | rfl | rfl | rfl | rfl <;> simp_all [deployment]
  · intro node
    simp [topology, deployment, Deployment.IsLayer, devices, eq_comm]
  · intro node
    simp [topology, deployment, Deployment.IsDevice, devices, eq_comm]
  · intro node
    simp [topology, deployment, Deployment.IsLayer, devices, eq_comm]
  · intro node
    rfl
  · intro node
    simp [topology]
  · intro node
    simp [topology, deployment, Deployment.IsDevice, devices, eq_comm]
  · intro node
    simp [topology, deployment, Deployment.IsDevice, devices, eq_comm]
  · intro device member
    simp only [deployment, devices, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl <;> simp [topology]
  · change ∀ first ∈ devices, ∀ second ∈ devices, first.id = second.id → first = second
    simp [devices]
  · change ∀ device ∈ devices, device.layer = some .inner → device.kind ≠ .grayFirewall
    decide
  · simp [edges, topology]
  · intro device member manager
    simp only [deployment, devices, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl <;>
      simp_all [GrayManagement, topology]
  · intro device member inner
    simp only [deployment, devices, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl <;> simp_all [topology]
  · intro device member kind
    simp only [deployment, devices, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl <;> simp_all [deployment]
  · intro first firstMember second secondMember firstInner secondInner different
    exact ⟨⟨"node-G", "A", .grayFirewall, none, high, true⟩, by simp [deployment, devices], rfl⟩
  · simp [pairs, EndpointPair.Bound, AddressView.read, deployment, interfaces, interface,
      GrayEndpointRelation, SameLevelComponents, GrayManagement, topology, Deployment.IsLayer,
      devices]
  · intro port member _
    simp only [deployment, interfaces, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl <;>
      simp [admissionPrograms, deployment, policies, inventory, interfaces, ProgramRuleChecks,
      rules, RuleEndpointGuard, pairs, AddressView.RuleGuard, PolicyDerivation.RuleIPGuard,
      PolicyDerivation.IPProtocolAtom, EthernetTypeAtom, interface, LinkAdmission.lookup]
  · simp [paths, GrayPathWitness.Checked, topology, edges, List.isChainFromTo_pair_iff]
  · intro device member kind
    simp only [deployment, devices, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl <;>
      simp_all [paths]

end TDN.Imported.CompleteGrayFirewall

namespace TDN.Imported.CompleteGrayFirewall
open Compliance Targets Targets.Complete Targets.EndpointRuleDerivation

def packet : PacketPolicy.Packet :=
  { source := 10, destination := 20, protocol := "esp", ingress := "port-IA", egress := "port-O",
    sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 5, inboundPolicies := [],
    outboundPolicies := [], connectionState := "new" }

lemma same_level_inner_traffic_is_admitted (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (deployment base processing).Accepts "port-G" .inbound
      ((deployment base processing).Observe packet) := by
  refine ⟨.forward, ⟨rfl, ?_⟩, ?_⟩
  · change (deployment base processing).ManagementMetadataBound packet
    simp [Deployment.ManagementMetadataBound, packet, PacketClass, PacketService, PacketIKE,
      PacketMKA, PacketARP]
  · simp [deployment, policies, interfaces, interface, InterfacePolicy.Accepts, rules,
      PacketPolicy.Rule.toFilter, Filter.evaluate, packet, Deployment.Observe, PacketPolicy.Atom.holds]

lemma wrong_level_inner_traffic_is_rejected (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    ¬ (deployment base processing).Accepts "port-G" .inbound
      ((deployment base processing).Observe {packet with destination := 40}) := by
  rintro ⟨hook, _, admitted⟩
  cases hook with
  | link =>
    exact PolicyDerivation.routed_port_has_no_link_operation (deployment base processing)
      (inventory processing) rfl "port-G"
      (by intro _ _ _; simp [PolicyDerivation.RoutedPort, inventory]) .inbound _ admitted
  | input | output | forward =>
    simp [deployment, policies, interfaces, interface, InterfacePolicy.Accepts, rules,
      PacketPolicy.Rule.toFilter, Filter.evaluate, packet, Deployment.Observe,
      PacketPolicy.Atom.holds] at admitted

lemma lower_level_workstation_traffic_is_rejected (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    ¬ (deployment base processing).Accepts "port-G" .outbound
      ((deployment base processing).Observe {packet with source := 100, destination := 10}) := by
  rintro ⟨hook, _, admitted⟩
  cases hook with
  | link =>
    exact PolicyDerivation.routed_port_has_no_link_operation (deployment base processing)
      (inventory processing) rfl "port-G"
      (by intro _ _ _; simp [PolicyDerivation.RoutedPort, inventory]) .outbound _ admitted
  | input | output | forward =>
    simp [deployment, policies, interfaces, interface, InterfacePolicy.Accepts, rules,
      PacketPolicy.Rule.toFilter, Filter.evaluate, packet, Deployment.Observe,
      PacketPolicy.Atom.holds] at admitted

lemma cross_level_path_really_exists :
    Relation.ReflTransGen topology.edge "node-IA" "node-IC" := by
  apply List.IsChainFromTo.reflTransGen (chain := ["node-IA", "node-G", "node-IC"])
  apply List.IsChainFromTo.cons (b := "node-G")
  · simp [topology, edges]
  · simp [List.isChainFromTo_pair_iff, topology, edges]

lemma direct_cross_level_bypass_fails_local_edge_check :
    ¬ (∀ edge ∈ edges ++ [("node-IA", "node-IC")],
      ¬ topology.grayFirewall edge.1 → ¬ topology.grayFirewall edge.2 →
      topology.level edge.1 = topology.level edge.2) := by
  intro checked
  have impossible := checked ("node-IA", "node-IC") (by simp)
    (by simp [topology]) (by simp [topology])
  change low = high at impossible
  cases (by decide : low ≠ high) impossible

end TDN.Imported.CompleteGrayFirewall
