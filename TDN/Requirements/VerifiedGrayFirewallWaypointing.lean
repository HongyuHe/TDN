import TDN.Requirements.MasterMscRequirementSpecs
import TDN.Requirements.DeriveEndpointInputOutputRules
import Cslib.Foundations.Data.List.IsChainFromTo

namespace TDN.Requirements.Msc
open Compliance DeriveEndpointInputOutputRules

def GrayEndpointNode (d : Deployment) (topology : GrayTopology) (node : String) : Prop :=
  d.IsLayer node .inner ∨ topology.workstation node ∨
    topology.certificationAuthority node ∨ topology.revocationService node

def GrayEndpointRelation (d : Deployment) (topology : GrayTopology)
    (source destination : String) : Prop :=
  (d.IsLayer source .inner → d.IsLayer destination .inner →
    SameLevelComponents d source destination) ∧
  (GrayManagement topology source → topology.inner destination →
    topology.level destination ≠ topology.highest → False) ∧
  (GrayManagement topology destination → topology.inner source →
    topology.level source ≠ topology.highest → False)

lemma bound_gray_endpoint_rules_filter_inner_peers (d : Deployment)
    (topology : GrayTopology) (inventory : PacketProcessing.Inventory)
    (present : d.processing = some inventory) (coherent : d.AddressInventoryCoherent)
    (pairs : List EndpointPair)
    (bindings : ∀ pair ∈ pairs, pair.Bound d ∧
      GrayEndpointRelation d topology pair.source pair.destination)
    (interface : Interface) (indices : policyIndicesChecked d = true)
    (member : interface ∈ d.interfaces)
    (checks : ∀ program ∈ admissionPrograms d inventory interface.id,
      ProgramRuleChecks (RuleEndpointGuard d (GrayEndpointNode d topology) pairs) program) :
    d.PolicyCoverage interface ∧ ∀ direction traffic,
      d.Accepts interface.id direction traffic → InnerEndpoints d traffic →
      d.SameLevelInner traffic := by
  refine ⟨policy_coverage_from_checked_indices d indices interface member, ?_⟩
  intro direction traffic accepted endpoints
  obtain ⟨source, destination, sourceMetadata, destinationMetadata, sourceInner, destinationInner⟩ := endpoints
  obtain ⟨pair, pairMember, rule, guard, sourceAtom, destinationAtom, matched⟩ :=
    accepted_endpoints_have_named_pair d inventory present (GrayEndpointNode d topology) pairs
      interface.id checks direction traffic accepted source destination
      sourceMetadata destinationMetadata (Or.inl sourceInner) (Or.inl destinationInner)
  have records := bindings pair pairMember
  obtain ⟨sourceId, destinationId, firstInterface, secondInterface⟩ :=
    matched_bound_pair_recovers_metadata d coherent pair records.1 rule guard sourceAtom
      destinationAtom traffic (accepted_traffic_supported d interface.id direction traffic accepted) matched
  have sourceEq : source = pair.source := Option.some.inj (sourceMetadata.symm.trans sourceId)
  have destinationEq : destination = pair.destination :=
    Option.some.inj (destinationMetadata.symm.trans destinationId)
  obtain ⟨first, firstMember, second, secondMember, firstId, secondId,
      firstLayer, secondLayer, sameLevel, peer⟩ :=
    records.2.1 (sourceEq ▸ sourceInner) (destinationEq ▸ destinationInner)
  refine ⟨first, firstMember, second, secondMember, firstLayer, secondLayer,
    sameLevel, ?_, Or.inl ?_⟩
  · simpa [firstId, secondId] using peer
  · rw [firstId, secondId]
    exact ⟨sourceId, destinationId, firstInterface, secondInterface⟩

lemma bound_gray_endpoint_rules_reject_lower_management (d : Deployment)
    (topology : GrayTopology) (inventory : PacketProcessing.Inventory)
    (present : d.processing = some inventory) (coherent : d.AddressInventoryCoherent)
    (innerBinding : ∀ node, topology.inner node ↔ d.IsLayer node .inner)
    (localCABinding : ∀ node, topology.localCA node → topology.certificationAuthority node)
    (pairs : List EndpointPair)
    (bindings : ∀ pair ∈ pairs, pair.Bound d ∧
      GrayEndpointRelation d topology pair.source pair.destination)
    (interface : Interface)
    (checks : ∀ program ∈ admissionPrograms d inventory interface.id,
      ProgramRuleChecks (RuleEndpointGuard d (GrayEndpointNode d topology) pairs) program)
    (direction : Direction) (traffic : Traffic)
    (accepted : d.Accepts interface.id direction traffic)
    (manager component : String) (managed : GrayManagement topology manager)
    (inner : topology.inner component) (lower : topology.level component ≠ topology.highest) :
    ¬ ((traffic.sourceDevice = some manager ∧ traffic.destinationDevice = some component) ∨
      (traffic.sourceDevice = some component ∧ traffic.destinationDevice = some manager)) := by
  have managerNode : GrayEndpointNode d topology manager := by
    rcases managed with workstation | localCA
    · exact Or.inr (Or.inl workstation)
    · exact Or.inr (Or.inr (Or.inl (localCABinding manager localCA)))
  have componentNode : GrayEndpointNode d topology component := Or.inl ((innerBinding component).mp inner)
  rintro (⟨source, destination⟩ | ⟨source, destination⟩)
  · have relation := accepted_endpoints_preserve_local_relation d inventory present coherent
      (GrayEndpointNode d topology) (GrayEndpointRelation d topology) pairs bindings interface.id
      checks direction traffic accepted manager component source destination managerNode componentNode
    exact relation.2.1 managed inner lower
  · have relation := accepted_endpoints_preserve_local_relation d inventory present coherent
      (GrayEndpointNode d topology) (GrayEndpointRelation d topology) pairs bindings interface.id
      checks direction traffic accepted component manager source destination componentNode managerNode
    exact relation.2.2 managed inner lower

structure GrayPathWitness where
  firewall : String
  inner : String
  outer : String
  toFirewall : List String
  fromFirewall : List String

def GrayPathWitness.Checked (witness : GrayPathWitness) (topology : GrayTopology) : Prop :=
  topology.grayFirewall witness.firewall ∧ topology.inner witness.inner ∧ topology.outer witness.outer ∧
  witness.toFirewall.IsChainFromTo topology.edge witness.inner witness.firewall ∧
  witness.fromFirewall.IsChainFromTo topology.edge witness.firewall witness.outer

lemma device_kinds_unique (d : Deployment)
    (identifiers : ∀ first ∈ d.devices, ∀ second ∈ d.devices,
      first.id = second.id → first = second)
    (node : String) (first second : DeviceKind)
    (firstKind : d.IsDevice node first) (secondKind : d.IsDevice node second) :
    first = second := by
  obtain ⟨a, aMember, aId, aKind⟩ := firstKind
  obtain ⟨b, bMember, bId, bKind⟩ := secondKind
  have same := identifiers a aMember b bMember (aId.trans bId.symm)
  exact aKind.symm.trans ((congrArg Device.kind same).trans bKind)

lemma inner_nodes_are_not_gray_firewalls (d : Deployment) (topology : GrayTopology)
    (identifiers : ∀ first ∈ d.devices, ∀ second ∈ d.devices,
      first.id = second.id → first = second)
    (innerBinding : ∀ node, topology.inner node ↔ d.IsLayer node .inner)
    (firewallBinding : ∀ node, topology.grayFirewall node ↔ d.IsDevice node .grayFirewall)
    (kinds : ∀ device ∈ d.devices, device.layer = some .inner → device.kind ≠ .grayFirewall)
    (node : String) (inner : topology.inner node) : ¬ topology.grayFirewall node := by
  obtain ⟨device, member, deviceId, layer⟩ := (innerBinding node).mp inner
  intro firewall
  obtain ⟨other, otherMember, otherId, otherKind⟩ := (firewallBinding node).mp firewall
  have same := identifiers device member other otherMember (deviceId.trans otherId.symm)
  exact kinds device member layer ((congrArg Device.kind same).trans otherKind)

lemma service_nodes_are_not_gray_firewalls (d : Deployment) (topology : GrayTopology)
    (identifiers : ∀ first ∈ d.devices, ∀ second ∈ d.devices,
      first.id = second.id → first = second)
    (workstationBinding : ∀ node, topology.workstation node ↔ d.grayWorkstation node)
    (workstations : d.grayWorkstation = grayWorkstationRole d)
    (caBinding : ∀ node, topology.certificationAuthority node ↔
      d.IsDevice node .certificationAuthority ∧
        ∃ interface ∈ d.interfaces, interface.device = node ∧ interface.zone = .gray)
    (revocationBinding : ∀ node, topology.revocationService node ↔
      d.IsDevice node .revocationService ∧
        ∃ interface ∈ d.interfaces, interface.device = node ∧ interface.zone = .gray)
    (firewallBinding : ∀ node, topology.grayFirewall node ↔ d.IsDevice node .grayFirewall)
    (node : String)
    (service : topology.workstation node ∨ topology.certificationAuthority node ∨
      topology.revocationService node) : ¬ topology.grayFirewall node := by
  intro firewall
  have firewallKind := (firewallBinding node).mp firewall
  rcases service with workstation | ca | revocation
  · have actual := (workstationBinding node).mp workstation
    rw [workstations] at actual
    have wrong := device_kinds_unique d identifiers node .workstation .grayFirewall actual.1 firewallKind
    cases wrong
  · have wrong := device_kinds_unique d identifiers node .certificationAuthority .grayFirewall
      ((caBinding node).mp ca).1 firewallKind
    cases wrong
  · have wrong := device_kinds_unique d identifiers node .revocationService .grayFirewall
      ((revocationBinding node).mp revocation).1 firewallKind
    cases wrong

end TDN.Requirements.Msc

namespace TDN.Requirements.Msc
open Compliance DeriveEndpointInputOutputRules

theorem gray_firewall_path_coverage_from_edge_inventory_and_rule_atoms
    (d : Deployment) (topology : GrayTopology) (inventory : PacketProcessing.Inventory)
    (present : d.processing = some inventory)
    (addressChecked : addressRecordsChecked d = true)
    (workstations : d.grayWorkstation = grayWorkstationRole d)
    (indices : policyIndicesChecked d = true)
    (innerBinding : ∀ node, topology.inner node ↔ d.IsLayer node .inner)
    (firewallBinding : ∀ node, topology.grayFirewall node ↔ d.IsDevice node .grayFirewall)
    (outerBinding : ∀ node, topology.outer node ↔ d.IsLayer node .outer)
    (workstationBinding : ∀ node, topology.workstation node ↔ d.grayWorkstation node)
    (localCABinding : ∀ node, topology.localCA node → topology.certificationAuthority node)
    (caBinding : ∀ node, topology.certificationAuthority node ↔
      d.IsDevice node .certificationAuthority ∧
        ∃ interface ∈ d.interfaces, interface.device = node ∧ interface.zone = .gray)
    (revocationBinding : ∀ node, topology.revocationService node ↔
      d.IsDevice node .revocationService ∧
        ∃ interface ∈ d.interfaces, interface.device = node ∧ interface.zone = .gray)
    (levelBinding : ∀ device ∈ d.devices, topology.level device.id = device.level)
    (identifiers : ∀ first ∈ d.devices, ∀ second ∈ d.devices,
      first.id = second.id → first = second)
    (innerKinds : ∀ device ∈ d.devices, device.layer = some .inner →
      device.kind ≠ .grayFirewall)
    (edges : List (String × String))
    (edgeBinding : ∀ first second, topology.edge first second ↔ (first, second) ∈ edges)
    (edgeChecks : ∀ edge ∈ edges, ¬ topology.grayFirewall edge.1 →
      ¬ topology.grayFirewall edge.2 → topology.level edge.1 = topology.level edge.2)
    (managementLevels : ∀ device ∈ d.devices,
      GrayManagement topology device.id → device.level = topology.highest)
    (highestLevels : ∀ device ∈ d.devices, device.layer = some .inner →
      topology.dominates topology.highest device.level)
    (physicalProtection : ∀ device ∈ d.devices, device.kind = .grayFirewall →
      d.authority.protectsAsClassified device.id)
    (firewallPresence : ∀ first ∈ d.devices, ∀ second ∈ d.devices,
      first.layer = some .inner → second.layer = some .inner →
      first.level ≠ second.level → ∃ firewall ∈ d.devices, firewall.kind = .grayFirewall)
    (pairs : List EndpointPair)
    (pairChecks : ∀ pair ∈ pairs, pair.Bound d ∧
      GrayEndpointRelation d topology pair.source pair.destination)
    (ruleChecks : ∀ interface ∈ d.interfaces,
      ((d.IsLayer interface.device .outer ∧ interface.zone = .gray) ∨
        d.IsDevice interface.device .grayFirewall) →
      ∀ program ∈ admissionPrograms d inventory interface.id,
        ProgramRuleChecks (RuleEndpointGuard d (GrayEndpointNode d topology) pairs) program)
    (paths : List GrayPathWitness)
    (pathChecks : ∀ witness ∈ paths, witness.Checked topology)
    (pathCoverage : ∀ device ∈ d.devices, device.kind = .grayFirewall →
      ∃ witness ∈ paths, witness.firewall = device.id) :
    msc_gray_firewall_path_coverage d topology := by
  have coherent := address_inventory_from_checked_records d addressChecked workstations
  have localEdges : ∀ first second, topology.edge first second →
      ¬ topology.grayFirewall first → ¬ topology.grayFirewall second →
      topology.level first = topology.level second := by
    intro first second edge
    exact edgeChecks (first, second) ((edgeBinding first second).mp edge)
  have innerClear := inner_nodes_are_not_gray_firewalls d topology identifiers
    innerBinding firewallBinding innerKinds
  have serviceClear := service_nodes_are_not_gray_firewalls d topology identifiers
    workstationBinding workstations caBinding revocationBinding firewallBinding
  have managerClear : ∀ node, GrayManagement topology node → ¬ topology.grayFirewall node := by
    intro node manager
    apply serviceClear node
    rcases manager with workstation | localCA
    · exact Or.inl workstation
    · exact Or.inr (Or.inl (localCABinding node localCA))
  have managerHighest : ∀ node, GrayManagement topology node →
      topology.level node = topology.highest := by
    intro node manager
    have actual : ∃ device ∈ d.devices, device.id = node := by
      rcases manager with workstation | localCA
      · have role := (workstationBinding node).mp workstation
        rw [workstations] at role
        obtain ⟨device, member, same, _⟩ := role.1
        exact ⟨device, member, same⟩
      · obtain ⟨device, member, same, _⟩ := ((caBinding node).mp (localCABinding node localCA)).1
        exact ⟨device, member, same⟩
    obtain ⟨device, member, same⟩ := actual
    rw [← same, levelBinding device member]
    exact managementLevels device member (same ▸ manager)
  have innerDominated : ∀ node, topology.inner node →
      topology.dominates topology.highest (topology.level node) := by
    intro node inner
    obtain ⟨device, member, same, layer⟩ := (innerBinding node).mp inner
    rw [← same, levelBinding device member]
    exact highestLevels device member layer
  have filters : ∀ node, topology.outer node ∨ topology.grayFirewall node →
      FiltersIntendedPeers {d with focus := none} node := by
    intro node role interface member _ owner gray
    apply bound_gray_endpoint_rules_filter_inner_peers d topology inventory present coherent
      pairs pairChecks interface indices member
    apply ruleChecks interface member
    rcases role with outer | firewall
    · exact Or.inl ⟨owner ▸ (outerBinding node).mp outer, gray⟩
    · exact Or.inr (owner ▸ (firewallBinding node).mp firewall)
  have firewallChecks : ∀ node, topology.grayFirewall node →
      FiltersIntendedPeers {d with focus := none} node ∧
        d.authority.protectsAsClassified node := by
    intro node firewall
    refine ⟨filters node (Or.inr firewall), ?_⟩
    obtain ⟨device, member, same, kind⟩ := (firewallBinding node).mp firewall
    exact same ▸ physicalProtection device member kind
  have presentFirewall : (∃ first second, topology.inner first ∧ topology.inner second ∧
      topology.level first ≠ topology.level second) → ∃ firewall, topology.grayFirewall firewall := by
    rintro ⟨first, second, firstInner, secondInner, different⟩
    obtain ⟨a, aMember, aId, aLayer⟩ := (innerBinding first).mp firstInner
    obtain ⟨b, bMember, bId, bLayer⟩ := (innerBinding second).mp secondInner
    have differentLevels : a.level ≠ b.level := by
      rw [← levelBinding a aMember, ← levelBinding b bMember, aId, bId]
      exact different
    obtain ⟨firewall, member, kind⟩ :=
      firewallPresence a aMember b bMember aLayer bLayer differentLevels
    exact ⟨firewall.id, (firewallBinding firewall.id).mpr ⟨firewall, member, rfl, kind⟩⟩
  have core := TDN.Requirements.gray_firewall_paths_from_local_separation topology.edge
    topology.grayFirewall topology.inner (GrayManagement topology) topology.level topology.highest
    topology.dominates (FiltersIntendedPeers {d with focus := none}) d.authority.protectsAsClassified
    localEdges innerClear managerClear managerHighest innerDominated firewallChecks presentFirewall
  change CoreReq_msc_gray_firewall_path_coverage {d with focus := none} topology
  refine ⟨coherent, innerBinding, firewallBinding, outerBinding, workstationBinding,
    localCABinding, caBinding, revocationBinding, ?_, core, ?_, ?_, ?_, ?_⟩
  · intro device member _
    exact levelBinding device member
  · intro service component role _ different
    exact Waypointing.waypointing_of_edge_invariant topology.edge topology.grayFirewall topology.level
      localEdges (serviceClear service role) different
  · intro outer role
    exact filters outer (Or.inl role)
  · intro firewall role interface member _ owner direction traffic accepted manager component managed inner lower
    apply bound_gray_endpoint_rules_reject_lower_management d topology inventory present coherent
      innerBinding localCABinding pairs pairChecks interface
      (ruleChecks interface member (Or.inr (owner ▸ (firewallBinding firewall).mp role)))
      direction traffic accepted manager component managed inner lower
  · intro firewall role
    obtain ⟨device, member, same, kind⟩ := (firewallBinding firewall).mp role
    obtain ⟨witness, witnessMember, witnessId⟩ := pathCoverage device member kind
    obtain ⟨_, inner, outer, toFirewall, fromFirewall⟩ := pathChecks witness witnessMember
    have equal : witness.firewall = firewall := witnessId.trans same
    refine ⟨witness.outer, witness.inner, outer, inner, ?_, ?_⟩
    · exact equal ▸ toFirewall.reflTransGen
    · exact equal ▸ fromFirewall.reflTransGen

end TDN.Requirements.Msc
