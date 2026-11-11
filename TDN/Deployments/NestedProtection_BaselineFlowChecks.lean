import TDN.Deployments.NestedProtection_BaselineFlowData
import TDN.Requirements.IPsecNestedFlowEvents

namespace TDN.Deployments.NestedProtection_Baseline
open Compliance Requirements Requirements.Msc MtuSizing_Records LayeredFrame MultiProtocolForwarding

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma recorded_plain_links : ∀ selected ∈ contexts, ∀ edge ∈ records.links,
    expectedEncapStack edge.1 = [] →
    (selected.SourceSide (capturedConfiguration.ip.owner edge.1) ↔ selected.SourceSide (capturedConfiguration.ip.owner edge.2)) ∧
    (selected.DestinationSide (capturedConfiguration.ip.owner edge.1) ↔ selected.DestinationSide (capturedConfiguration.ip.owner edge.2)) := by
  unfold IPsecFlowEndpoints.SourceSide IPsecFlowEndpoints.DestinationSide
  decide

lemma recorded_plain_bridges : ∀ edge ∈ records.bridges, expectedEncapStack edge.1 ≠ [] := by decide

lemma flow_tunnel_checks (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (selected : IPsecFlowEndpoints) (member : selected ∈ contexts) :
    IPsecFlowTunnelChecks (deviceBinding primitive) selected.flow selected.RemoteHeader selected.AllowedStamp
      (selected.PlainAllowed (configuration primitive).ip.owner) expectedEncapStack := by
  refine ⟨rfl, rfl, OuterTunnelNoBypass_Baseline.route_owners, ?_, ?_, ?_, ?_, ?_⟩
  · intro first last body same allowed
    change (configuration primitive).ip.owner first = (configuration primitive).ip.owner last at same
    unfold IPsecFlowEndpoints.PlainAllowed at allowed ⊢
    rw [same] at allowed
    exact allowed
  · intro first last body linked empty allowed
    have names := recorded_plain_links selected member (first, last) linked empty
    rcases allowed with source | ⟨destination, remote⟩
    · exact Or.inl (names.1.mp source)
    · exact Or.inr ⟨names.2.mp destination, remote⟩
  · intro first last body linked empty allowed
    exact False.elim (recorded_plain_bridges (first, last) linked empty)
  · exact ipsec_flow_outgoing_policy_named (deviceBinding primitive) selected expectedEncapStack
      (flow_policy_checks primitive selected member) ⟨fun _ => 64, fun _ => 64⟩ rfl
  · exact ipsec_flow_incoming_plain_destination (deviceBinding primitive) selected expectedEncapStack
      (flow_policy_checks primitive selected member)

lemma step_preserves_selected_flow (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (selected : IPsecFlowEndpoints) (member : selected ∈ contexts)
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step (configuration primitive) before operation after)
    (safe : IPsecFlowInvariant (deviceBinding primitive) selected.flow selected.RemoteHeader selected.AllowedStamp
      (selected.PlainAllowed (configuration primitive).ip.owner) expectedEncapStack before) :
    IPsecFlowInvariant (deviceBinding primitive) selected.flow selected.RemoteHeader selected.AllowedStamp
      (selected.PlainAllowed (configuration primitive).ip.owner) expectedEncapStack after := by
  exact ipsec_step_preserves_flow_tunnel_names (deviceBinding primitive) selected.flow selected.RemoteHeader
    selected.AllowedStamp (selected.PlainAllowed (configuration primitive).ip.owner) expectedEncapStack
    (flow_tunnel_checks primitive selected member)
    (OuterTunnelNoBypass_Baseline.headered_stack_conditions (OuterTunnelNoBypass_Baseline.codec primitive))
    ⟨fun _ => 64, fun _ => 64⟩ rfl (fun _ => ⟨by change 64 ≤ 255; decide, by change 64 ≤ 255; decide⟩) step safe

lemma recorded_source_contexts : ∀ entry ∈ entries,
    contextFor entry.originDomain ∈ contexts ∧
    (contextFor entry.originDomain).flow.sourceNetwork = entry.network ∧
    (contextFor entry.originDomain).originDomain = entry.originDomain ∧
    (contextFor entry.originDomain).SourceSide (capturedConfiguration.ip.owner entry.iface) := by
  unfold IPsecFlowEndpoints.SourceSide
  decide

lemma recorded_context_networks : ∀ selected ∈ contexts,
    ∃ network ∈ networks, selected.flow.sourceNetwork = network.id := by decide

lemma source_encap_stacks (iface : Nat) (network : String)
    (source : sourceEntry entries iface = some network) : expectedEncapStack iface = [] := by
  have checked : ∀ entry ∈ entries, expectedEncapStack entry.iface = [] := by decide
  obtain ⟨entry, member, same, _⟩ := source_entry_is_recorded entries iface network source
  rw [← same]
  exact checked entry member

end TDN.Deployments.NestedProtection_Baseline
