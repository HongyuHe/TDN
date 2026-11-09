import TDN.Requirements.PerimeterInterfaceSlice
import TDN.Requirements.OuterToGrayInterfaceAllowlist

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding

lemma IPsec_packet_at_native_policy_header (configuration : Config) (state : MultiProtocolForwarding.State)
    (header : PacketPolicy.Packet) :
    IPsecPacket (policyHeader configuration state header) ↔ IPsecPacket header := by
  rfl

lemma IPsec_packet_at_boundary_header (configuration : Config) (iface : Nat)
    (outbound : Bool) (header : PacketPolicy.Packet) :
    IPsecPacket (BoundaryPacket configuration iface outbound header) ↔ IPsecPacket header := by
  rfl

lemma IPsec_packet_at_context_header (configuration : Config) (context : PacketProcessing.Context) :
    IPsecPacket (context.Packet configuration) ↔ IPsecPacket context.header := by
  cases hook : context.hook <;> simp only [PacketProcessing.Context.Packet, hook] <;> rfl

lemma IPsec_packet_under_header_identity (actual nominal : PacketPolicy.Packet)
    (identity : LayeredFrame.HeaderIdentity actual nominal) :
    IPsecPacket actual ↔ IPsecPacket nominal := by
  have same := congrArg IPsecPacket identity.1
  exact Iff.of_eq same

lemma boundary_filter_preserves_frame_and_iface (configuration : Config)
    (context : PacketProcessing.Context) (filtered : MultiProtocolForwarding.State)
    (step : BoundaryFilterStep configuration context filtered) :
    filtered.frame = context.state.frame ∧ filtered.iface = context.state.iface ∧
      filtered.datapathStage = .filtered := by
  rcases step with ⟨_, forward⟩ | ⟨_, output⟩
  · cases forward
    exact ⟨rfl, rfl, rfl⟩
  · cases output
    exact ⟨rfl, rfl, rfl⟩

lemma boundary_filter_preserves_outbound_annotation (configuration : Config)
    (context : PacketProcessing.Context) (filtered : MultiProtocolForwarding.State)
    (step : BoundaryFilterStep configuration context filtered) (requestId : Nat)
    (required : requestId ∈ (context.Packet configuration).matchedOutboundPolicyIds) :
    requestId ∈ (policyHeader configuration filtered context.header).matchedOutboundPolicyIds := by
  have same := (boundary_filter_preserves_frame_and_iface configuration context filtered step).2.1
  rcases step with ⟨hook, _⟩ | ⟨hook, _⟩
  · simpa only [PacketProcessing.Context.Packet, hook, policyHeader, same] using required
  · simpa only [PacketProcessing.Context.Packet, hook, policyHeader, same] using required

lemma configured_IPsec_suffix_has_IPsec_boundary_header (configuration : Config)
    {filtered encrypted ready : MultiProtocolForwarding.State}
    (protect : MultiProtocolForwarding.Step configuration filtered .encryptIPsec encrypted)
    (route : MultiProtocolForwarding.Step configuration encrypted .route ready)
    (header : PacketPolicy.Packet) (visible : configuration.visibleHeader ready.frame = some header) :
    IPsecPacket header := by
  obtain ⟨policy, _, association, _, _, actual, actualVisible, _, _, protocol⟩ :=
    IPsec_suffix_boundary_packet_uses_installed_policy configuration protect route
  have same : actual = header := Option.some.inj (actualVisible.symm.trans visible)
  subst actual
  exact Or.inl protocol

theorem outbound_boundary_IPsec_from_raw_protocol_or_required_transform
    (configuration : Config) (context : PacketProcessing.Context)
    (iface : Nat) (packet : PacketPolicy.Packet)
    (visible : configuration.visibleHeader context.state.frame = some context.header)
    (view : DeviceBoundaryView configuration context .outbound iface packet)
    (permitted : IPsecPacket (context.Packet configuration) ∨
      ∃ requestId, requestId ∈ (context.Packet configuration).matchedOutboundPolicyIds) :
    IPsecPacket packet := by
  cases view with
  | outbound filtered ready afterWire filter run wire header boundaryVisible =>
    have preserved := boundary_filter_preserves_frame_and_iface configuration context filtered filter
    have filteredVisible : configuration.visibleHeader filtered.frame = some context.header := by
      simpa only [preserved.1] using visible
    apply (IPsec_packet_at_boundary_header configuration ready.iface true header).mpr
    rcases permitted with protocol | ⟨requestId, required⟩
    · have suffix := first_ready_run_from_filtered_is_native_suffix configuration preserved.2.2 run
      cases suffix with
      | forwardWithoutEncap step datapathStage =>
        have frameSame : ready.frame = filtered.frame := by
          cases step <;> simp_all
        have actualVisible : configuration.visibleHeader ready.frame = some context.header :=
          (congrArg configuration.visibleHeader frameSame).trans filteredVisible
        have same : header = context.header :=
          Option.some.inj (boundaryVisible.symm.trans actualVisible)
        rw [same]
        exact (IPsec_packet_at_context_header configuration context).mp protocol
      | IPsec protect route =>
        exact configured_IPsec_suffix_has_IPsec_boundary_header configuration protect route header boundaryVisible
    · have annotation := boundary_filter_preserves_outbound_annotation configuration context filtered filter requestId required
      obtain ⟨encrypted, protect, route⟩ :=
        outbound_policy_annotation_forces_actual_IPsec configuration preserved.2.2
          filteredVisible requestId annotation run
      exact configured_IPsec_suffix_has_IPsec_boundary_header configuration protect route header boundaryVisible


lemma receive_preserves_frame_and_clears_authentication (configuration : Config)
    {before after : MultiProtocolForwarding.State}
    (received : MultiProtocolForwarding.Step configuration before .receive after) :
    after.frame = before.frame ∧ after.authenticated = [] := by
  cases received
  exact ⟨rfl, rfl⟩

lemma coherent_same_body_has_same_IPsec_protocol
    (first second : LayeredFrame.Frame) (firstHeader secondHeader : PacketPolicy.Packet)
    (firstCoherent : first.HeadersCoherent) (secondCoherent : second.HeadersCoherent)
    (body : first.body = second.body)
    (firstVisible : first.visibleHeader = some firstHeader)
    (secondVisible : second.visibleHeader = some secondHeader) :
    IPsecPacket firstHeader ↔ IPsecPacket secondHeader := by
  obtain ⟨nominal, firstBody, firstIdentity⟩ :=
    LayeredFrame.Frame.coherent_visible firstCoherent firstHeader firstVisible
  obtain ⟨other, secondBody, secondIdentity⟩ :=
    LayeredFrame.Frame.coherent_visible secondCoherent secondHeader secondVisible
  have same : nominal = other := Option.some.inj
    (firstBody.symm.trans ((congrArg LayeredFrame.Body.visibleHeader body).trans secondBody))
  subst other
  exact (IPsec_packet_under_header_identity _ _ firstIdentity).trans
    (IPsec_packet_under_header_identity _ _ secondIdentity).symm

lemma inbound_annotation_is_native_authentication (configuration : Config)
    (context : PacketProcessing.Context)
    (direction : HookDirection context.hook .inbound) :
    (context.Packet configuration).matchedInboundPolicyIds = context.state.authenticated := by
  cases hook : context.hook <;> simp_all [HookDirection, PacketProcessing.Context.Packet, policyHeader]

theorem inbound_boundary_IPsec_from_raw_protocol_or_authentication
    (configuration : Config) (processing : HeaderProcessing)
    (mode : configuration.headerProcessing = some processing) (bounds : HeaderBounds processing)
    (context : PacketProcessing.Context) (iface : Nat) (packet : PacketPolicy.Packet)
    (atHook : context.AtHook configuration)
    (direction : HookDirection context.hook .inbound)
    (coherent : context.entry.frame.HeadersCoherent)
    (view : DeviceBoundaryView configuration context .inbound iface packet)
    (permitted : IPsecPacket (context.Packet configuration) ∨
      (context.Packet configuration).matchedInboundPolicyIds ≠ []) :
    IPsecPacket packet := by
  cases view with
  | inbound header visible =>
    apply (IPsec_packet_at_boundary_header configuration context.entry.iface false header).mpr
    have entryVisible : context.entry.frame.visibleHeader = some header := by
      simpa [Config.visibleHeader, mode] using visible
    have rawProtocol := IPsec_packet_at_context_header configuration context
    have rawAuthentication := inbound_annotation_is_native_authentication configuration context direction
    have entryEncrypted : ∀ entered,
        MultiProtocolForwarding.Step configuration context.entry .decryptIPsec entered →
        IPsecPacket header := by
      intro entered decrypted
      obtain ⟨policy, _, association, _, _, actual, actualVisible, _, _, protocol⟩ :=
        IPsec_input_has_configured_outer_header configuration processing mode coherent decrypted
      have same : actual = header := Option.some.inj (actualVisible.symm.trans visible)
      subst actual
      exact Or.inl protocol
    cases hook : context.hook with
    | input =>
      simp only [PacketProcessing.Context.AtHook, hook] at atHook
      obtain ⟨stateVisible, ingress, addressed⟩ := atHook
      rcases ingress with received | decrypted
      · have preserved := receive_preserves_frame_and_clears_authentication configuration received
        have same : context.header = header := Option.some.inj
          (stateVisible.symm.trans ((congrArg LayeredFrame.Frame.visibleHeader preserved.1).trans entryVisible))
        rcases permitted with raw | authenticated
        · exact same ▸ rawProtocol.mp raw
        · exact False.elim (authenticated (rawAuthentication.trans preserved.2))
      · exact entryEncrypted _ decrypted
    | forward =>
      simp only [PacketProcessing.Context.AtHook, hook] at atHook
      obtain ⟨stateVisible, entered, route, ingress, forwardable, routed, datapathStage,
        routedPhase, selected, entry, exit⟩ := atHook
      rcases ingress with received | decrypted
      · have receivedState := receive_preserves_frame_and_clears_authentication configuration received
        have routedState := route_from_ingress_preserves_local_state datapathStage routed
        have enteredCoherent := step_preserves_headers processing mode bounds received coherent
        have finalCoherent := step_preserves_headers processing mode bounds routed enteredCoherent
        rcases permitted with raw | authenticated
        · exact (coherent_same_body_has_same_IPsec_protocol context.state.frame context.entry.frame
            context.header header finalCoherent coherent
            (routedState.1.trans (congrArg LayeredFrame.Frame.body receivedState.1))
            stateVisible entryVisible).mp (rawProtocol.mp raw)
        · exact False.elim (authenticated (rawAuthentication.trans
            (routedState.2.2.1.trans receivedState.2)))
      · exact entryEncrypted _ decrypted
    | output => simp [HookDirection, hook] at direction
    | link => simp [PacketProcessing.Context.AtHook, hook] at atHook

end TDN.Requirements.Msc
