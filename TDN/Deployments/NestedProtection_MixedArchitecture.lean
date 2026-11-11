import TDN.Deployments.NestedProtection_MixedData

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option synthInstance.maxSize 2048

def FlowInventory (selected : MixedFlowEndpoints) : Prop :=
  ∃ inner ∈ records.tunnels, ∃ outer ∈ records.tunnels,
    inner.id = selected.flow.innerTunnel ∧ outer.id = selected.flow.outerTunnel ∧
    inner.layer = .inner ∧ outer.layer = .outer ∧
    (∀ tunnel ∈ [inner, outer], ∃ sender ∈ records.components, ∃ receiver ∈ records.components,
      sender.id = tunnel.sender ∧ receiver.id = tunnel.receiver ∧
      sender.infrastructure = true ∧ receiver.infrastructure = true ∧
      sender.layer = some tunnel.layer ∧ receiver.layer = some tunnel.layer ∧
      sender.site ≠ receiver.site ∧
      (tunnel.mechanism = .ipsec → sender.kind = .vpn ∧ receiver.kind = .vpn) ∧
      (tunnel.mechanism = .macsec → sender.kind = .macsec ∧ receiver.kind = .macsec)) ∧
    (∃ source ∈ records.networks, ∃ destination ∈ records.networks,
      source.id = selected.flow.sourceNetwork ∧ destination.id = selected.flow.destinationNetwork ∧
      inner.sender ∈ source.innerComponents ∧ inner.receiver ∈ destination.innerComponents ∧
      (∃ sender ∈ records.components, sender.id = outer.sender ∧ sender.site = source.site) ∧
      ∃ receiver ∈ records.components, receiver.id = outer.receiver ∧ receiver.site = destination.site) ∧
    (outer.mechanism = .macsec → ∀ device ∈ records.components,
      device.layer = some .outer → device.site = "A" ∨ device.site = "B")

lemma recorded_flow_inventory : ∀ selected ∈ contexts, FlowInventory selected := by
  unfold FlowInventory
  decide

def flowKeyContexts (selected : MixedFlowEndpoints) : String × String :=
  (((records.tunnels.find? (fun tunnel => tunnel.id == selected.flow.innerTunnel)).map Tunnel.keyContext).getD "",
    ((records.tunnels.find? (fun tunnel => tunnel.id == selected.flow.outerTunnel)).map Tunnel.keyContext).getD "")

def IndependentLayerKeys (independent : String → String → Prop) : Prop :=
  ∀ selected ∈ contexts, independent (flowKeyContexts selected).1 (flowKeyContexts selected).2

lemma recorded_key_contexts : ∀ selected ∈ contexts, ∀ inner ∈ records.tunnels, ∀ outer ∈ records.tunnels,
    inner.id = selected.flow.innerTunnel → outer.id = selected.flow.outerTunnel →
    flowKeyContexts selected = (inner.keyContext, outer.keyContext) := by decide

lemma flows_valid (independentKeys : String → String → Prop)
    (independent : IndependentLayerKeys independentKeys) :
    ∀ flow ∈ flows, flow.Valid deployment independentKeys := by
  intro flow listed
  obtain ⟨selected, member, rfl⟩ := List.mem_map.mp listed
  obtain ⟨inner, innerMember, outer, outerMember, innerName, outerName, innerLayer, outerLayer,
    endpoints, networks, sites⟩ := recorded_flow_inventory selected member
  have keys := independent selected member
  rw [recorded_key_contexts selected member inner innerMember outer outerMember innerName outerName] at keys
  refine ⟨inner, innerMember, outer, outerMember, innerName, outerName, innerLayer, outerLayer,
    keys, endpoints, networks, ?_⟩
  intro macsec
  exact ⟨"A", "B", by decide, fun device member relevant layer => sites macsec device member layer⟩

lemma recorded_authentication_flags : ∀ component ∈ records.components,
    deployment.certificateAuthenticated component.id = false ∧
    deployment.preSharedCAKAuthenticated component.id = false := by decide

lemma architecture_services : ArchitectureServices deployment := by
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · intro component member relevant authenticated
    have disabled := (recorded_authentication_flags component member).1
    simp [disabled] at authenticated
  · intro component member relevant authenticated
    have disabled := (recorded_authentication_flags component member).2
    simp [disabled] at authenticated
  · have sameLevel : ∀ first ∈ records.components, ∀ second ∈ records.components,
        first.level = second.level := by decide
    intro first firstMember second secondMember innerFirst innerSecond different common
    exact False.elim (different (sameLevel first firstMember second secondMember))

lemma endpoint_network_ids_checked : ∀ entry ∈ records.entries,
    configuration.ip.ifaceSecurityDomain entry.hostIface = some entry.originDomain ∧
    records.redNetwork entry.originDomain = entry.network := by decide

end TDN.Deployments.NestedProtection_Mixed
