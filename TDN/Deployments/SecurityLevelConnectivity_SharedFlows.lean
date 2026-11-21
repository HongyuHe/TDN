import TDN.Deployments.SecurityLevelConnectivity_SharedPaths

namespace TDN.Deployments.SecurityLevelConnectivity_Shared
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame
  OuterTunnelNoBypass_Shared MtuSizing_Records

set_option maxRecDepth 1000000

load_network_records contexts : List IpsecFlowEndpoints from "../../data/evidence/nestedProtection/SharedIPsec.json" ["contexts"]

def contextFor (domain : Nat) :=
  (contexts.find? (fun selected => selected.originDomain == domain)).getD (contexts.head (by native_decide))

lemma selected_context_is_recorded (domain : Nat) : contextFor domain ∈ contexts := by
  unfold contextFor
  cases chosen : contexts.find? (fun selected => selected.originDomain == domain) with
  | none => exact List.head_mem (by native_decide)
  | some found => exact List.mem_of_find?_eq_some chosen

lemma policy_iface_is_listed (iface : Nat) (policy : DataPlaneForwarding.IpsecPolicy)
    (used : policy ∈ capturedConfiguration.ip.egressPolicies iface ∨ policy ∈ capturedConfiguration.ip.ingressPolicies iface) :
    iface ∈ records.inventory.ifaces := by
  by_contra outside
  have missing : records.nativeIfaces[iface]? = none :=
    List.getElem?_eq_none (Nat.le_of_not_gt (fun inside => outside (List.mem_range.mpr inside)))
  have fallback : (DataPlaneForwarding.deviceAt records.nativeDevices 0).egressPolicies = [] ∧
      (DataPlaneForwarding.deviceAt records.nativeDevices 0).ingressPolicies = [] := by native_decide
  change policy ∈ (DataPlaneForwarding.deviceAt records.nativeDevices
    (DataPlaneForwarding.ifaceAt records.nativeIfaces iface).owner).egressPolicies ∨
    policy ∈ (DataPlaneForwarding.deviceAt records.nativeDevices
      (DataPlaneForwarding.ifaceAt records.nativeIfaces iface).owner).ingressPolicies at used
  simp only [DataPlaneForwarding.ifaceAt, missing, Option.getD_none,
    show ({} : DataPlaneForwarding.IfaceData).owner = 0 from rfl, fallback.1, fallback.2,
    List.not_mem_nil, or_self] at used

lemma shared_inner_and_outer_policy_checks (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (selected : IpsecFlowEndpoints) (member : selected ∈ contexts) :
    IpsecFlowPolicyChecks (deviceBinding primitive) selected expectedEncapStack := by
  have names : ∀ s ∈ contexts, s.innerStamp.tag = 1 ∧ s.outerStamp.tag = 2 ∧
      ipsecTunnel records s.innerStamp = s.flow.innerTunnel ∧ ipsecTunnel records s.outerStamp = s.flow.outerTunnel := by native_decide
  have outbound : ∀ s ∈ contexts, ∀ i ∈ records.inventory.ifaces, ∀ p ∈ capturedConfiguration.ip.egressPolicies i,
      ∀ a ∈ capturedConfiguration.ip.egressSAs i, DataPlaneForwarding.saMatchesPolicy a p →
        (expectedEncapStack i).head? = some p.tag →
        s.OutgoingPolicy (capturedConfiguration.ip.owner i) (expectedEncapStack i) p a := by
    unfold IpsecFlowEndpoints.OutgoingPolicy IpsecFlowEndpoints.SourceSide IpsecFlowEndpoints.DestinationSide
    native_decide
  have inbound : ∀ s ∈ contexts, ∀ i ∈ records.inventory.ifaces, ∀ p ∈ capturedConfiguration.ip.ingressPolicies i,
      ∀ a ∈ capturedConfiguration.ip.ingressSAs i, DataPlaneForwarding.saMatchesPolicy a p →
        (expectedEncapStack i).head? = some p.tag →
        s.IncomingPolicy (capturedConfiguration.ip.owner i) (expectedEncapStack i) p a := by
    unfold IpsecFlowEndpoints.IncomingPolicy IpsecFlowEndpoints.DestinationSide
    native_decide
  obtain ⟨inner, outer, first, second⟩ := names selected member
  exact ⟨inner, outer, first, second,
    fun i p a hp => outbound selected member i (policy_iface_is_listed i p (Or.inl hp)) p hp a,
    fun i p a hp => inbound selected member i (policy_iface_is_listed i p (Or.inr hp)) p hp a⟩

lemma shared_flow_tunnel_checks (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (selected : IpsecFlowEndpoints) (member : selected ∈ contexts) :
    IpsecFlowTunnelChecks (deviceBinding primitive) selected.flow selected.RemoteHeader selected.AllowedStamp
      (selected.PlainAllowed (configuration primitive).ip.owner) expectedEncapStack := by
  have links : ∀ s ∈ contexts, ∀ edge ∈ records.links, expectedEncapStack edge.1 = [] →
      (s.SourceSide (capturedConfiguration.ip.owner edge.1) ↔ s.SourceSide (capturedConfiguration.ip.owner edge.2)) ∧
      (s.DestinationSide (capturedConfiguration.ip.owner edge.1) ↔ s.DestinationSide (capturedConfiguration.ip.owner edge.2)) := by
    unfold IpsecFlowEndpoints.SourceSide IpsecFlowEndpoints.DestinationSide
    native_decide
  have bridges : ∀ edge ∈ records.bridges, expectedEncapStack edge.1 ≠ [] := by native_decide
  have policies := shared_inner_and_outer_policy_checks primitive selected member
  refine ⟨rfl, rfl, route_owners, ?_, ?_, ?_, ?_, ?_⟩
  · intro first last body same allowed
    change (configuration primitive).ip.owner first = (configuration primitive).ip.owner last at same
    unfold IpsecFlowEndpoints.PlainAllowed at allowed ⊢
    simpa only [same] using allowed
  · intro first last body linked plain allowed
    obtain ⟨src, dst⟩ := links selected member (first, last) linked plain
    exact allowed.imp src.mp (fun h => ⟨dst.mp h.1, h.2⟩)
  · intro first last body linked plain _
    exact False.elim (bridges (first,last) linked plain)
  · exact ipsec_flow_outgoing_policy_named _ _ _ policies ⟨fun _ => 64, fun _ => 64⟩ rfl
  · exact ipsec_flow_incoming_plain_destination _ _ _ policies

def FlowInvariant (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (state : State records.inventory.ifaces) : Prop :=
  let selected := contextFor state.deviceState.frame.originDomain
  selected ∈ contexts ∧ selected.originDomain = state.deviceState.frame.originDomain ∧
  IPsecFlowInvariant (deviceBinding primitive) selected.flow selected.RemoteHeader selected.AllowedStamp
    (selected.PlainAllowed (configuration primitive).ip.owner) expectedEncapStack state.deviceState

lemma initial_flow_invariant (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (state : State records.inventory.ifaces) (initial : (interpretedForwarding primitive).initial state) :
    FlowInvariant primitive state := by
  obtain ⟨req, datagrams, datagram, _, allowed, _, _, same⟩ := initial.2
  have source := allowed.2.2
  change sourceEntry entries req.iface = some (redNetwork req.originDomain) ∧ _ at source
  obtain ⟨entry, listed, iface, named⟩ := source_entry_is_recorded entries req.iface _ source.1
  have nonempty : ∀ row ∈ entries, row.network ≠ "" := by native_decide
  have found : ∃ row ∈ entries, row.originDomain = req.originDomain ∧ row.network = entry.network := by
    unfold redNetwork at named
    cases lookup : entries.find? (fun row => row.originDomain == req.originDomain) with
    | none => exact False.elim (nonempty entry listed (by simpa [lookup] using named))
    | some row =>
      exact ⟨row, List.mem_of_find?_eq_some lookup, beq_iff_eq.mp (List.find?_some (p := fun row : SourceEntry => row.originDomain == req.originDomain) lookup),
        (by simpa [lookup] using named.symm)⟩
  have table : ∀ row ∈ entries, ∀ entry ∈ entries, row.network = entry.network →
      (contextFor row.originDomain).originDomain = row.originDomain ∧
      (contextFor row.originDomain).SourceSide (capturedConfiguration.ip.owner entry.iface) := by
    unfold IpsecFlowEndpoints.SourceSide
    native_decide
  obtain ⟨row, present, domain, name⟩ := found
  have selected := table row present entry listed name
  rw [domain, iface] at selected
  have sourceStacks : ∀ i n, sourceEntry entries i = some n → expectedEncapStack i = [] := by
    have allRows : ∀ row ∈ entries, expectedEncapStack row.iface = [] := by native_decide
    intro i n chosen
    obtain ⟨row, included, rfl, _⟩ := source_entry_is_recorded entries i n chosen
    exact allRows row included
  have stack := (binding (deviceBinding primitive) records.inventory.ifaces).source_initial_red_stack
    (interpretedDeployment primitive) expectedEncapStack sourceStacks state.deviceState initial.1 _ rfl
  refine ⟨selected_context_is_recorded _, by simpa only [same, DeviceExecutionBinding.SourceState] using selected.1,
    stack, ?_, ?_⟩
  · rcases initial.1.2.1 with ⟨h, body⟩ | ⟨h, body⟩ <;> simp only [body, FlowIPsecBody]
  · intro _
    apply Or.inl
    have owner : (configuration primitive).ip.owner = capturedConfiguration.ip.owner := rfl
    rw [owner]
    simpa only [same, DeviceExecutionBinding.SourceState] using selected.2

lemma shared_step_preserves_flow (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    {first last : State records.inventory.ifaces} {action : Action records.inventory.ifaces}
    (invariant : FlowInvariant primitive first) (step : (interpretedForwarding primitive).system.Tr first action last) :
    FlowInvariant primitive last := by
  have native := step.2.2.2.1
  have origin := (MultiProtocolForwarding.step_preserves_payload native).2
  unfold FlowInvariant
  rw [origin]
  refine ⟨invariant.1, invariant.2.1, ?_⟩
  exact ipsec_step_preserves_flow_tunnel_names _ _ _ _ _ _
    (shared_flow_tunnel_checks primitive _ invariant.1) (headered_stack_conditions (codec primitive))
    ⟨fun _ => 64, fun _ => 64⟩ rfl (fun _ => ⟨by change 64 ≤ 255; decide, by change 64 ≤ 255; decide⟩) native invariant.2.2

end TDN.Deployments.SecurityLevelConnectivity_Shared
