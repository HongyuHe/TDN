import TDN.Requirements.MscRequirements
import TDN.Requirements.IpsecNestedFlowEvents

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding LayeredFrame StandardDataPlaneBridge

def ConnectivityEvent (networks : List RedNetworkIdentity) (source : String) : NetworkEvent → Prop
  | .inject _ name => name = source
  | .deliver _ destination _ =>
    ∃ first ∈ networks, ∃ second ∈ networks,
      first.id = source ∧ second.id = destination ∧ first.level = second.level
  | _ => True

lemma source_events_identify_network {S A : Type} (binding : DeviceExecutionBinding S A)
    (networks : List RedNetworkIdentity) (state : TunnelForwardingState) (source : String)
    (origin : binding.origin state.frame.originDomain = .red source) :
    ∀ event ∈ (packetBinding binding).SourceEvents state, ConnectivityEvent networks source event := by
  intro event member
  dsimp only [DeviceExecutionBinding.SourceEvents] at member
  change event ∈ (if state.initialEntry then
    match binding.origin state.frame.originDomain with
    | .red network => if binding.sourceEntry state.iface = some network ∧
        (packetBinding binding).LayerIds state.frame.body = [] then
          [.inject ⟨state.frame.originDomain, state.frame.payload⟩ network,
           .receive ⟨state.frame.originDomain, state.frame.payload⟩ (binding.ifaceName state.iface) [] .protectedData]
      else []
    | _ => []
    else []) at member
  rw [packet_binding_layer_ids] at member
  simp only [origin] at member
  split at member
  · split at member
    · rcases List.mem_cons.mp member with rfl | tail
      · rfl
      · obtain rfl := List.mem_singleton.mp tail
        trivial
    · simp at member
  · simp at member

lemma ipsec_delivery_events_preserve_level {S A : Type} (binding : DeviceExecutionBinding S A)
    (networks : List RedNetworkIdentity) (selected : IpsecFlowEndpoints) (layout : Nat → List Nat)
    {before after : TunnelForwardingState} {operation : TunnelForwardingAction}
    (step : TunnelForwardingStep binding.configuration before operation after)
    (safe : IPsecFlowInvariant binding selected.flow selected.RemoteHeader selected.AllowedStamp
      (selected.PlainAllowed binding.configuration.ip.owner) layout before)
    (ends : ∀ domain, binding.configuration.ip.ifaceSecurityDomain before.iface = some domain →
      (selected.SourceSide (binding.configuration.ip.owner before.iface) ∨
        selected.DestinationSide (binding.configuration.ip.owner before.iface)) →
      ∃ first ∈ networks, ∃ second ∈ networks, first.id = selected.flow.sourceNetwork ∧
        second.id = binding.domainName domain ∧ first.level = second.level) :
    ∀ event ∈ (packetBinding binding).OperationEvents before operation after,
      ConnectivityEvent networks selected.flow.sourceNetwork event := by
  intro event member
  cases step <;>
    simp only [packetBinding, DeviceExecutionBinding.withProjection, DeviceExecutionBinding.OperationEvents] at member
  case deliver domain stage body recipient =>
    simp only [recipient, List.mem_singleton] at member
    subst event
    have owners := safe.2.2 (by simp [body, Body.protectionLayers])
    exact ends domain recipient (owners.imp_right And.left)
  case deliverEthernet header domain stage body recipient =>
    simp only [recipient, List.mem_singleton] at member
    subst event
    have owners := safe.2.2 (by simp [body, Body.protectionLayers])
    exact ends domain recipient (owners.imp_right And.left)
  all_goals try split at member
  all_goals simp only [List.mem_cons, List.not_mem_nil, or_false] at member
  all_goals rcases member with rfl | rfl | rfl | rfl <;> trivial

lemma forwarding_events_preserve_level {S A : Type} (model : ForwardingModel S A)
    (networks : List RedNetworkIdentity) (source : S → String) (invariant : S → Prop)
    (initialized : ∀ state, model.initial state → invariant state)
    (advance : ∀ before action after, invariant before → model.system.Tr before action after →
      invariant after ∧ source after = source before ∧
      ∀ event ∈ model.events action, ConnectivityEvent networks (source before) event)
    (valid : model.history.Valid) :
    model.AllTraces (fun events => ∀ payload first last layers,
      Before events (.inject payload first) (.deliver payload last layers) →
      ∃ a ∈ networks, ∃ b ∈ networks, a.id = first ∧ b.id = last ∧ a.level = b.level) := by
  intro start actions finish initial run payload first last layers order
  have traffic : ∀ event ∈ actions.flatMap model.events, ConnectivityEvent networks (source start) event := by
    have safe := initialized start initial
    clear initial order
    induction run with
    | refl => simp
    | stepL step tail ih =>
      obtain ⟨next, same, checks⟩  := advance _ _ _ safe step
      intro event member
      rcases List.mem_append.mp member with here | later
      · exact checks event here
      · exact same ▸ ih next event later
  have allEvents : ∀ event ∈ model.TraceEvents actions, ConnectivityEvent networks (source start) event := by
    intro event member
    rcases List.mem_append.mp member with setup | current
    · obtain ⟨record, found, rfl⟩ := List.mem_map.mp setup
      have ok := (valid.2.1 record found).2.2.2.2
      cases record with
      | mk _ _ _ _ _ _ _ event =>
        cases event <;> simp_all [HistoricalEvent.SetupOnly, ConnectivityEvent]
    · exact traffic event current
  obtain ⟨earlier, middle, later, split⟩ := order
  have injected := allEvents (.inject payload first) (by rw [split]; simp)
  have delivered := allEvents (.deliver payload last layers) (by rw [split]; simp)
  exact (show first = source start from injected) ▸ delivered

def intendedNetworkPairs (networks : List RedNetworkIdentity) : List (String × String) :=
  networks.flatMap fun first => (networks.filterMap fun last =>
    if first.id ≠ last.id ∧ first.level = last.level then some (first.id, last.id) else none)

def unclassifiedNetworkIds (networks : List RedNetworkIdentity) : List String :=
  (networks.filter fun n => n.level.classification == "unclassified").map RedNetworkIdentity.id

lemma unclassified_networks_are_included (networks : List RedNetworkIdentity) (id : String)
    (member : id ∈ unclassifiedNetworkIds networks) :
    ∃ network ∈ networks, network.id = id ∧ network.level.classification = "unclassified" := by
  obtain ⟨network, listed, rfl⟩ := List.mem_map.mp member
  have checked := List.mem_filter.mp listed
  exact ⟨network, checked.1, rfl, beq_iff_eq.mp checked.2⟩

theorem scoped_connectivity_from_forwarding {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (authenticated established required : List (String × String)) (unclassified : List String)
    (source : S → String) (invariant : S → Prop)
    (covered : model.CoversDeployment d)
    (dedicated : DedicatedInnerAssignments d.networks)
    (devices : ∀ network ∈ d.networks, ∀ inner ∈ network.innerComponents,
      ∃ device ∈ d.devices, device.id = inner ∧ device.layer = some .inner ∧
        device.level = network.level)
    (peers : ∀ pair ∈ authenticated ++ established,
      ∃ first ∈ d.devices, ∃ last ∈ d.devices,
        first.id = pair.1 ∧ last.id = pair.2 ∧ first.layer = some .inner ∧
        last.layer = some .inner ∧ first.level = last.level)
    (initialized : ∀ state, model.initial state → invariant state)
    (steps : ∀ before action after, invariant before → model.system.Tr before action after →
      invariant after ∧ source after = source before ∧
      ∀ event ∈ model.events action, ConnectivityEvent d.networks (source before) event)
    (paths : ∀ pair ∈ required, ∃ start actions finish payload,
      model.initial start ∧ model.ForwardsAlongTrace start actions finish ∧
      Before (model.TraceEvents actions) (.inject payload pair.1) (.deliver payload pair.2 []))
    (inventory : unclassified = unclassifiedNetworkIds d.networks) :
    scoped_security_level_connectivity d model authenticated established required unclassified :=
  ⟨covered, dedicated, devices, peers,
    forwarding_events_preserve_level model _ source invariant initialized steps covered.validHistory,
    paths, fun id member => unclassified_networks_are_included _ _ (inventory ▸ member)⟩

theorem security_level_connectivity_from_forwarding {S A : Type} (context : ComplianceContext S A)
    (source : S → String) (invariant : S → Prop)
    (covered : context.model.CoversDeployment {context.deployment with deviceScope := none})
    (dedicated : DedicatedInnerAssignments context.deployment.networks)
    (devices : ∀ network ∈ context.deployment.networks, ∀ inner ∈ network.innerComponents,
      ∃ device ∈ context.deployment.devices, device.id = inner ∧ device.layer = some .inner ∧
        device.level = network.level)
    (peers : ∀ pair ∈ context.authenticatedInnerPairs ++ context.establishedInnerTunnels,
      ∃ first ∈ context.deployment.devices, ∃ last ∈ context.deployment.devices,
        first.id = pair.1 ∧ last.id = pair.2 ∧ first.layer = some .inner ∧
        last.layer = some .inner ∧ first.level = last.level)
    (initialized : ∀ state, context.model.initial state → invariant state)
    (steps : ∀ before action after, invariant before → context.model.system.Tr before action after →
      invariant after ∧ source after = source before ∧
      ∀ event ∈ context.model.events action, ConnectivityEvent context.deployment.networks (source before) event)
    (paths : ∀ pair ∈ context.requiredConnectivity, ∃ start actions finish payload,
      context.model.initial start ∧ context.model.ForwardsAlongTrace start actions finish ∧
      Before (context.model.TraceEvents actions) (.inject payload pair.1) (.deliver payload pair.2 []))
    (inventory : context.includedUnclassified = unclassifiedNetworkIds context.deployment.networks)
    (roster : List (ComplianceContext S A)) (listed : context ∈ roster)
    (references : List (String × String))
    (declared : ∀ solution ∈ roster, ∀ id,
      solution.conformingMSC id ↔ (solution.solution, id) ∈ references)
    (verified : ∀ edge ∈ references, ∃ target ∈ roster, target.solution = edge.2 ∧
      target.AllApplicableDuties (.entireSolution edge.2))
    (unclassified : ∀ id ∈ context.includedUnclassified,
      context.KnownSubject (.enclaveNetwork id) ∧ context.records.InventoryComplete context.deployment ∧
      context.EnterpriseGrayMeaning (.enclaveNetwork id) ∧
      ∀ group : Fin 76, group.val + 1 ≠ 8 → context.RequirementGroupSpec (.enclaveNetwork id) group) :
    security_level_connectivity context := by
  have completeConnectivity : scoped_security_level_connectivity {context.deployment with deviceScope := none}
      context.model context.authenticatedInnerPairs context.establishedInnerTunnels
      context.requiredConnectivity context.includedUnclassified :=
    scoped_connectivity_from_forwarding _ _ _ _ _ _ source invariant covered dedicated devices peers
      initialized steps paths inventory
  have closed : ReferencesClosed roster := by
    intro solution member id referenced
    exact verified (solution.solution, id) ((declared solution member id).mp referenced)
  refine ⟨completeConnectivity, ⟨roster, listed, closed⟩, ?_⟩
  intro id member
  obtain ⟨known, complete, enterprise, duties⟩ := unclassified id member
  refine ⟨known, complete, enterprise, ?_⟩
  intro group _
  by_cases connectivity : group.val + 1 = 8
  · have same : group = (7 : Fin 76) := Fin.ext (by change group.val = 7; omega)
    subst group
    exact completeConnectivity
  · exact duties group connectivity

lemma checked_ipsec_step_events {S A : Type} (prototype : DeviceExecutionBinding S A)
    (ifaces : List Nat) (d : Deployment) (networks : List RedNetworkIdentity)
    (layout : Nat → List Nat) (selected : IpsecFlowEndpoints) {before after : State ifaces}
    {action : Action ifaces} (step : (model prototype ifaces d {}).system.Tr before action after)
    (origin : prototype.origin before.deviceState.frame.originDomain = .red selected.flow.sourceNetwork)
    (safe : IPsecFlowInvariant prototype selected.flow selected.RemoteHeader selected.AllowedStamp
      (selected.PlainAllowed prototype.configuration.ip.owner) layout before.deviceState)
    (ends : ∀ domain, prototype.configuration.ip.ifaceSecurityDomain before.deviceState.iface = some domain →
      (selected.SourceSide (prototype.configuration.ip.owner before.deviceState.iface) ∨
        selected.DestinationSide (prototype.configuration.ip.owner before.deviceState.iface)) →
      ∃ first ∈ networks, ∃ second ∈ networks, first.id = selected.flow.sourceNetwork ∧
        second.id = prototype.domainName domain ∧ first.level = second.level) :
    ∀ event ∈ (model prototype ifaces d {}).events action,
      ConnectivityEvent networks selected.flow.sourceNetwork event := by
  obtain ⟨first, last, _, accepted⟩ := step
  subst before
  subst after
  intro event member
  change event ∈ (binding prototype ifaces).RequiredEvents _ _ _ at member
  rw [packet_binding_required_events] at member
  rcases List.mem_append.mp member with injected | sent
  · exact source_events_identify_network prototype networks _ _ origin event injected
  · exact ipsec_delivery_events_preserve_level prototype networks selected layout accepted.1 safe ends event sent

theorem cohosted_encryptors_violate_unclassified_duty {S A : Type} (context : ComplianceContext S A)
    (included inner outer : String) (member : included ∈ context.includedUnclassified)
    (different : inner ≠ outer) (innerRole : context.deployment.IsLayer inner .inner)
    (outerRole : context.deployment.IsLayer outer .outer)
    (cohosted : ∀ first ∈ context.records.components, first.component = inner →
      ∀ last ∈ context.records.components, last.component = outer → first.physicalDevice = last.physicalDevice) :
    ¬ security_level_connectivity context := by
  intro whole
  have duties := whole.2.2 included member
  obtain ⟨_, inventory, _, checked⟩ := duties
  have separation : PhysicalRoleSeparation context.records
      (context.ScopedDeployment (.enclaveNetwork included)) := checked (4 : Fin 76) trivial
  obtain ⟨innerDevice, innerMember, innerId, _⟩ := innerRole
  obtain ⟨outerDevice, outerMember, outerId, _⟩ := outerRole
  obtain ⟨first, firstMember, firstId⟩ := inventory.1 innerDevice innerMember
  obtain ⟨second, secondMember, secondId⟩ := inventory.1 outerDevice outerMember
  have id1 := firstId.trans innerId
  have id2 := secondId.trans outerId
  have apart := separation first firstMember second secondMember
    (fun equal => different (id1.symm.trans (equal.trans id2))) (Or.inl (Or.inl rfl))
    (Or.inl ⟨⟨innerDevice, innerMember, firstId.symm, by assumption⟩,
      ⟨outerDevice, outerMember, secondId.symm, by assumption⟩⟩)
  exact apart (cohosted first firstMember id1 second secondMember id2)

end TDN.Requirements.Msc
