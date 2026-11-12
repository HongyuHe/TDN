import TDN.Deployments.NestedProtection_MixedFlowChecks
import TDN.Requirements.MixedLinkFrameCoverage

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def linkIfaces : List Nat :=
  records.macIfaces.map MACIface.physicalIface ++ records.bridges.flatMap (fun edge => [edge.1,edge.2])

lemma link_path_is_recorded (iface : Nat) (path : configuration.LinkPath iface) : iface ∈ linkIfaces := by
  rcases path with ⟨mac, member, same⟩ | ⟨next, forward | reverse⟩ | ⟨carrier, member, same⟩
  · exact List.mem_append_left _ (List.mem_map.mpr ⟨mac, member, same⟩)
  · apply List.mem_append_right
    exact List.mem_flatMap.mpr ⟨(iface,next), forward, by simp⟩
  · apply List.mem_append_right
    exact List.mem_flatMap.mpr ⟨(next,iface), reverse, by simp⟩
  · cases member

lemma recorded_iface_is_link_path (iface : Nat) (member : iface ∈ linkIfaces) : configuration.LinkPath iface := by
  rcases List.mem_append.mp member with mac | bridge
  · obtain ⟨mac, listed, same⟩ := List.mem_map.mp mac
    exact Or.inl ⟨mac, listed, same⟩
  · obtain ⟨edge, listed, endpoint⟩ := List.mem_flatMap.mp bridge
    simp only [List.mem_cons, List.not_mem_nil, or_false] at endpoint
    rcases endpoint with rfl | rfl
    · exact Or.inr (Or.inl ⟨edge.2, Or.inl listed⟩)
    · exact Or.inr (Or.inl ⟨edge.1, Or.inr listed⟩)

lemma recorded_plain_link_exclusions : ∀ selected ∈ contexts, ∀ iface ∈ linkIfaces,
    ¬ selected.SourceSide (configuration.ip.owner iface) ∧
      ¬ selected.DestinationSide (configuration.ip.owner iface) := by
  unfold MixedFlowEndpoints.SourceSide MixedFlowEndpoints.DestinationSide
  native_decide
lemma recorded_link_route_selectors : ∀ selected ∈ contexts, ∀ route ∈ records.routes,
    route.egress ∈ linkIfaces → selected.innerStamp.receiver < route.destPrefixLow ∨
      route.destPrefixHigh < selected.innerStamp.receiver := by native_decide

lemma routed_frame_avoids_link_path (selected : MixedFlowEndpoints) (member : selected ∈ contexts)
    (frame : LayeredFrame.Frame) (header : PacketPolicy.Packet) (route : DataPlaneForwarding.FibRoute)
    (coherent : frame.HeadersCoherent) (visible : configuration.visibleHeader frame = some header)
    (valid : FlowMixedBody deviceBinding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation) frame.body)
    (plain : frame.body.protectionLayers = [] → selected.PlainAllowed configuration.ip.owner route.egress frame.body)
    (chosen : DataPlaneForwarding.SelectedFibRoute configuration.ip.routes route header) :
    ¬ configuration.LinkPath route.egress := by
  intro path
  have recorded := link_path_is_recorded route.egress path
  cases body : frame.body with
  | datagram | ethernet =>
    have allowed := plain (by simp only [body, Body.protectionLayers])
    have excluded := recorded_plain_link_exclusions selected member route.egress recorded
    rcases allowed with source | ⟨destination, remote⟩
    · exact excluded.1 source
    · exact excluded.2 destination
  | ipsec association contents =>
    have current : FlowMixedBody deviceBinding selected.flow selected.RemoteHeader
        (· = selected.innerStamp) (· = selected.outerAssociation) (.ipsec association contents) := by simpa only [body] using valid
    have same := current.1.1
    have mode : configuration.headerProcessing = some ⟨fun _ => 64, fun _ => 64⟩ := rfl
    have actual : frame.visibleHeader = some header := by simpa only [Config.visibleHeader, mode] using visible
    obtain ⟨nominal, nominalVisible, identity⟩ := frame.coherent_visible coherent header actual
    have packet : outerHeader association.sender association.receiver "esp" 0 0 = nominal := by
      simpa only [body, Body.visibleHeader, Option.some.injEq] using nominalVisible
    have destination : header.destination = selected.innerStamp.receiver := by
      rw [identity.destination, ← packet, same]
      rfl
    have matched := chosen.2.1
    have disjoint := recorded_link_route_selectors selected member route chosen.1 recorded
    rcases disjoint with lower | upper <;>
      simp only [DataPlaneForwarding.FibRoute.matches, destination] at matched <;> omega
  | macsec association contents =>
    simp [Config.visibleHeader, Records.configuration, Frame.visibleHeader, body, Body.visibleHeader] at visible
  | macsecPdu | carrier => simp only [body, FlowMixedBody] at valid

lemma flow_link_checks (selected : MixedFlowEndpoints) (member : selected ∈ contexts) :
    MixedFlowLinkChecks deviceBinding selected expectedEncapStack := by
  refine ⟨rfl, ?_, ?_, ?_, ?_, routed_frame_avoids_link_path selected member⟩
  · native_decide
  · have checked : ∀ iface ∈ linkIfaces, expectedEncapStack iface = [2,1] := by native_decide
    intro iface path
    exact checked iface (link_path_is_recorded iface path)
  · have checked : ∀ iface ∈ records.macIfaces, iface.logicalIface ∉ linkIfaces := by native_decide
    intro iface listed path
    exact checked iface listed (link_path_is_recorded _ path)
  · have checked : ∀ edge ∈ records.links, edge.2 ∈ linkIfaces → edge.1 ∈ linkIfaces := by native_decide
    intro first last linked path
    exact recorded_iface_is_link_path first (checked (first,last) linked (link_path_is_recorded last path))

lemma source_entries_avoid_link_path : ∀ entry ∈ records.entries, entry.iface ∉ linkIfaces := by native_decide

end TDN.Deployments.NestedProtection_Mixed
