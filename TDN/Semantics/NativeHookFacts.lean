import TDN.Semantics.PacketProcessing
import TDN.Semantics.MultiProtocolHeaders

namespace TDN.MultiProtocolExecution

lemma ingress_has_native_ifaces {configuration : Config} {before after : State}
    (ingress : PacketProcessing.Ingress configuration before after) :
    after.iface = before.iface ∧ after.enteredIface = before.iface ∧ after.datapathStage = .ingress := by
  rcases ingress with received | decrypted
  · cases received
    exact ⟨rfl, rfl, rfl⟩
  · cases decrypted
    exact ⟨rfl, rfl, rfl⟩

lemma route_from_ingress_preserves_local_state {configuration : Config} {before after : State}
    (datapathStage : before.datapathStage = .ingress) (step : Step configuration before .route after) :
    after.frame.body = before.frame.body ∧ after.enteredIface = before.enteredIface ∧
      after.authenticated = before.authenticated ∧ after.datapathStage = .routed := by
  cases step with
  | route =>
    refine ⟨?_, rfl, rfl, rfl⟩
    simp only [Config.forwardedFrame]
    split
    · rfl
    · exact LayeredFrame.Frame.forwarded_body _
  | routeLocalOutput route impossible => simp [impossible] at datapathStage
  | routeOuterPacket route impossible => simp [impossible] at datapathStage

lemma association_matches_depends_on_addresses (association : Execution.Association)
    (first second : PacketPolicy.Packet)
    (source : first.source = second.source) (destination : first.destination = second.destination) :
    association.matches first = association.matches second := by
  simp only [Execution.Association.matches, source, destination]

lemma selected_associations_depend_on_addresses (associations : List Execution.Association)
    (first second : PacketPolicy.Packet)
    (source : first.source = second.source) (destination : first.destination = second.destination) :
    Execution.selectedAssociations associations first = Execution.selectedAssociations associations second := by
  unfold Execution.selectedAssociations
  simp only [association_matches_depends_on_addresses _ first second source destination]

lemma selected_route_depends_on_destination (routes : List Execution.Route)
    (route : Execution.Route) (first second : PacketPolicy.Packet)
    (destination : first.destination = second.destination) :
    Execution.SelectedRoute routes route first ↔ Execution.SelectedRoute routes route second := by
  simp only [Execution.SelectedRoute, Execution.Route.matches, destination]

def addressPoint (source destination : Nat) : PacketPolicy.Packet :=
  { source := source, destination := destination, protocol := "esp", ingress := "", egress := "",
    sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 5,
    inboundPolicies := [], outboundPolicies := [], connectionState := "" }

lemma decrypted_route_has_authentication {configuration : Config} {entry entered final : State}
    (decrypted : Step configuration entry .decryptIPsec entered)
    (routed : Step configuration entered .route final) : final.authenticated ≠ [] := by
  cases decrypted
  have preserved := route_from_ingress_preserves_local_state rfl routed
  rw [preserved.2.2.1]
  simp

lemma ingress_route_authentication {configuration : Config} (processing : HeaderProcessing)
    (mode : configuration.headerProcessing = some processing) (bounds : HeaderBounds processing)
    {entry entered final : State} {header : PacketPolicy.Packet}
    (coherent : entry.frame.HeadersCoherent)
    (ingress : PacketProcessing.Ingress configuration entry entered)
    (routed : Step configuration entered .route final)
    (visible : final.frame.visibleHeader = some header) :
    final.enteredIface = entry.iface ∧
      (final.authenticated = [] ∨ ∃ policy ∈ configuration.ip.inbound entry.iface,
        policy.matches header = true ∧ final.authenticated = [policy.id]) := by
  have ingressIfaces := ingress_has_native_ifaces ingress
  have preserved := route_from_ingress_preserves_local_state ingressIfaces.2.2 routed
  refine ⟨preserved.2.1.trans ingressIfaces.2.1, ?_⟩
  rcases ingress with received | decrypted
  · cases received
    exact Or.inl preserved.2.2.1
  · cases decrypted with
    | decryptIPsec policy association body nominal datapathStage encrypted configured installed bound bodyVisible selected tracking =>
      have enteredCoherent := step_preserves_headers processing mode bounds
        (Step.decryptIPsec policy association body nominal datapathStage encrypted configured installed bound
          bodyVisible selected tracking) coherent
      have finalCoherent := step_preserves_headers processing mode bounds routed enteredCoherent
      obtain ⟨actualNominal, finalBodyVisible, identity⟩ :=
        LayeredFrame.Frame.coherent_visible finalCoherent header visible
      have finalBody : final.frame.body = body := by
        simpa only [Config.restoredFrame, mode, LayeredFrame.Frame.popHeader] using preserved.1
      have sameNominal : actualNominal = nominal := by
        rw [finalBody, bodyVisible] at finalBodyVisible
        exact Option.some.inj finalBodyVisible.symm
      subst actualNominal
      have source : header.source = nominal.source := by
        simpa only using congrArg (fun packet : PacketPolicy.Packet => packet.source) identity.1
      have destination : header.destination = nominal.destination := by
        simpa only using congrArg (fun packet : PacketPolicy.Packet => packet.destination) identity.1
      exact Or.inr ⟨policy, configured,
        (association_matches_depends_on_addresses policy header nominal source destination).trans selected,
        preserved.2.2.1⟩

end TDN.MultiProtocolExecution
