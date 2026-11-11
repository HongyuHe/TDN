import TDN.Deployments.NestedProtection_MixedStackChecks

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma recorded_plain_links : ∀ selected ∈ contexts, ∀ edge ∈ records.links,
    expectedEncapStack edge.1 = [] →
    (selected.SourceSide (configuration.ip.owner edge.1) ↔ selected.SourceSide (configuration.ip.owner edge.2)) ∧
    (selected.DestinationSide (configuration.ip.owner edge.1) ↔ selected.DestinationSide (configuration.ip.owner edge.2)) := by
  unfold MixedFlowEndpoints.SourceSide MixedFlowEndpoints.DestinationSide
  decide

lemma recorded_plain_bridges : ∀ edge ∈ records.bridges, expectedEncapStack edge.1 ≠ [] := by decide

lemma flow_tunnel_checks (selected : MixedFlowEndpoints) (member : selected ∈ contexts) :
    MixedFlowTunnelChecks deviceBinding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation)
      (selected.PlainAllowed configuration.ip.owner) expectedEncapStack selected.destinationLogicalIface := by
  refine ⟨rfl, route_owners, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro first last body same allowed
    change configuration.ip.owner first = configuration.ip.owner last at same
    unfold MixedFlowEndpoints.PlainAllowed at allowed ⊢
    rw [same] at allowed
    exact allowed
  · intro first last body linked empty allowed
    have names := recorded_plain_links selected member (first,last) linked empty
    rcases allowed with source | ⟨destination, remote⟩
    · exact Or.inl (names.1.mp source)
    · exact Or.inr ⟨names.2.mp destination, remote⟩
  · intro first last body linked empty allowed
    exact False.elim (recorded_plain_bridges (first,last) linked empty)
  · exact mixed_flow_routes_preserve_direction deviceBinding selected expectedEncapStack
      (flow_policy_checks selected member) ⟨fun _ => 64, fun _ => 64⟩ rfl
  · have checked : ∀ selected ∈ contexts, ∀ edge ∈ records.bridges, edge.2 ≠ selected.destinationLogicalIface := by decide
    intro first last bridge
    exact checked selected member (first,last) bridge
  · intro iface configured
    rw [(flow_policy_checks selected member).macLogicalStack iface configured]
    decide
  · exact mixed_flow_outgoing_policy_named deviceBinding selected expectedEncapStack
      (flow_policy_checks selected member) ⟨fun _ => 64, fun _ => 64⟩ rfl
  · exact mixed_flow_incoming_plain_destination deviceBinding selected expectedEncapStack (flow_policy_checks selected member)
  · exact mixed_flow_macsec_transmit_is_selected deviceBinding selected expectedEncapStack (flow_policy_checks selected member)

lemma step_preserves_selected_flow (selected : MixedFlowEndpoints) (member : selected ∈ contexts)
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step configuration before operation after)
    (safe : MixedFlowInvariant deviceBinding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation)
      (selected.PlainAllowed configuration.ip.owner) expectedEncapStack selected.destinationLogicalIface before) :
    MixedFlowInvariant deviceBinding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation)
      (selected.PlainAllowed configuration.ip.owner) expectedEncapStack selected.destinationLogicalIface after :=
  mixed_step_preserves_flow_tunnel_names deviceBinding selected.flow selected.RemoteHeader
    (· = selected.innerStamp) (· = selected.outerAssociation)
    (selected.PlainAllowed configuration.ip.owner) expectedEncapStack selected.destinationLogicalIface
    (flow_tunnel_checks selected member) headered_stack_conditions
    ⟨fun _ => 64, fun _ => 64⟩ rfl (fun _ => ⟨by change 64 ≤ 255; decide, by change 64 ≤ 255; decide⟩) step safe

lemma recorded_source_contexts : ∀ entry ∈ records.entries,
    contextFor entry.originDomain ∈ contexts ∧
    (contextFor entry.originDomain).flow.sourceNetwork = entry.network ∧
    (contextFor entry.originDomain).originDomain = entry.originDomain ∧
    (contextFor entry.originDomain).SourceSide (configuration.ip.owner entry.iface) := by
  unfold MixedFlowEndpoints.SourceSide
  decide

lemma recorded_context_networks : ∀ selected ∈ contexts,
    ∃ network ∈ records.networks, selected.flow.sourceNetwork = network.id := by decide

lemma source_encap_stacks (iface : Nat) (network : String)
    (source : sourceEntry records.entries iface = some network) : expectedEncapStack iface = [] := by
  have checked : ∀ entry ∈ records.entries, expectedEncapStack entry.iface = [] := by decide
  obtain ⟨entry, member, same, _⟩ := source_entry_is_recorded records.entries iface network source
  rw [← same]
  exact checked entry member

end TDN.Deployments.NestedProtection_Mixed
