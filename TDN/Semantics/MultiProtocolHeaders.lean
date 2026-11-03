import TDN.Semantics.MultiProtocolExecution

namespace TDN.LayeredFrame

lemma HeaderIdentity.decrement {actual nominal : PacketPolicy.Packet}
    (identity : HeaderIdentity actual nominal) :
    HeaderIdentity { actual with hopLimit := actual.hopLimit - 1 } nominal := by
  refine ⟨?_, Nat.le_trans (Nat.sub_le _ _) identity.2⟩
  change { actual with hopLimit := nominal.hopLimit } = nominal
  exact identity.1

lemma Body.coherent_visible {body : Body} {active : Option PacketPolicy.Packet}
    {hidden : List (Option PacketPolicy.Packet)}
    (coherent : body.HeadersCoherent active hidden) (nominal : PacketPolicy.Packet)
    (visible : body.visibleHeader = some nominal) :
    HeaderIdentity (active.getD nominal) nominal := by
  cases body <;> simp_all [Body.HeadersCoherent, Body.visibleHeader]

lemma Body.coherent_set_active {body : Body} {active : Option PacketPolicy.Packet}
    {hidden : List (Option PacketPolicy.Packet)}
    (coherent : body.HeadersCoherent active hidden)
    (nominal actual : PacketPolicy.Packet) (visible : body.visibleHeader = some nominal)
    (identity : HeaderIdentity actual nominal) :
    body.HeadersCoherent (some actual) hidden := by
  cases body <;> simp_all [Body.HeadersCoherent, Body.visibleHeader]

lemma Frame.coherent_visible {frame : Frame} (coherent : frame.HeadersCoherent)
    (actual : PacketPolicy.Packet) (visible : frame.visibleHeader = some actual) :
    ∃ nominal, frame.body.visibleHeader = some nominal ∧ HeaderIdentity actual nominal := by
  cases nominal : frame.body.visibleHeader with
  | none => simp [Frame.visibleHeader, nominal] at visible
  | some header =>
    have same : frame.activeHeader.getD header = actual := by
      simpa [Frame.visibleHeader, nominal] using visible
    refine ⟨header, rfl, ?_⟩
    rw [← same]
    exact Body.coherent_visible coherent header nominal

lemma Frame.forwarded_headers {frame : Frame} (coherent : frame.HeadersCoherent) :
    frame.forwarded.HeadersCoherent := by
  cases visible : frame.visibleHeader with
  | none => simpa [Frame.forwarded, visible] using coherent
  | some actual =>
    obtain ⟨nominal, bodyVisible, identity⟩ := frame.coherent_visible coherent actual visible
    simpa [Frame.HeadersCoherent, Frame.forwarded, visible] using
      Body.coherent_set_active coherent nominal
        { actual with hopLimit := actual.hopLimit - 1 } bodyVisible identity.decrement

lemma Frame.push_ipsec_headers {frame : Frame} (coherent : frame.HeadersCoherent)
    (association : Execution.Seal) (hopLimit : Nat) (bound : hopLimit ≤ 255) :
    (frame.pushHeader (.ipsec association frame.body)
      (some { outerHeader association.sender association.receiver "esp" 0 0 with
        hopLimit := hopLimit })).HeadersCoherent := by
  refine ⟨⟨rfl, bound⟩, frame.activeHeader, frame.hiddenHeaders, rfl, coherent⟩

lemma Frame.push_carrier_headers {frame : Frame} (coherent : frame.HeadersCoherent)
    (endpoint : Carrier) (hopLimit : Nat) (bound : hopLimit ≤ 255) :
    (frame.pushHeader (.carrier endpoint frame.body)
      (some { outerHeader endpoint.source endpoint.destination endpoint.networkProtocol
        endpoint.sourcePort endpoint.destinationPort with hopLimit := hopLimit })).HeadersCoherent := by
  refine ⟨⟨rfl, bound⟩, frame.activeHeader, frame.hiddenHeaders, rfl, coherent⟩

lemma Frame.push_macsec_headers {frame : Frame} (coherent : frame.HeadersCoherent)
    (association : MACsecAssociation) :
    (frame.pushHeader (.macsec association frame.body) none).HeadersCoherent :=
  ⟨rfl, frame.activeHeader, frame.hiddenHeaders, rfl, coherent⟩

lemma Frame.pop_ipsec_headers {frame : Frame} (coherent : frame.HeadersCoherent)
    (association : Execution.Seal) (body : Body) (shape : frame.body = .ipsec association body) :
    (frame.popHeader body).HeadersCoherent := by
  change frame.body.HeadersCoherent frame.activeHeader frame.hiddenHeaders at coherent
  rw [shape] at coherent
  obtain ⟨_, inner, rest, hidden, coherent⟩ := coherent
  simpa [Frame.HeadersCoherent, Frame.popHeader, hidden] using coherent

lemma Frame.pop_macsec_headers {frame : Frame} (coherent : frame.HeadersCoherent)
    (association : MACsecAssociation) (body : Body) (shape : frame.body = .macsec association body) :
    (frame.popHeader body).HeadersCoherent := by
  change frame.body.HeadersCoherent frame.activeHeader frame.hiddenHeaders at coherent
  rw [shape] at coherent
  obtain ⟨_, inner, rest, hidden, coherent⟩ := coherent
  simpa [Frame.HeadersCoherent, Frame.popHeader, hidden] using coherent

lemma Frame.pop_carrier_headers {frame : Frame} (coherent : frame.HeadersCoherent)
    (endpoint : Carrier) (body : Body) (shape : frame.body = .carrier endpoint body) :
    (frame.popHeader body).HeadersCoherent := by
  change frame.body.HeadersCoherent frame.activeHeader frame.hiddenHeaders at coherent
  rw [shape] at coherent
  obtain ⟨_, inner, rest, hidden, coherent⟩ := coherent
  simpa [Frame.HeadersCoherent, Frame.popHeader, hidden] using coherent

lemma unwrap_carrier_has_body {localAddress remote sourcePort destinationPort localSession : Nat}
    {before after : Body} {protocol networkProtocol : String}
    (unwrapped : unwrapCarrier localAddress remote sourcePort destinationPort localSession
      before protocol networkProtocol = some after) :
    ∃ endpoint, before = .carrier endpoint after := by
  cases before <;> simp only [unwrapCarrier] at unwrapped
  all_goals try cases unwrapped
  case carrier endpoint body =>
    split at unwrapped
    · cases unwrapped
      exact ⟨endpoint, rfl⟩
    · cases unwrapped

end TDN.LayeredFrame

namespace TDN.MultiProtocolExecution
open LayeredFrame

def HeaderBounds (processing : HeaderProcessing) : Prop :=
  ∀ port, processing.ipsecHopLimit port ≤ 255 ∧ processing.carrierHopLimit port ≤ 255

lemma step_preserves_headers {c : Config} (processing : HeaderProcessing)
    (mode : c.headerProcessing = some processing) (bounds : HeaderBounds processing)
    {before after : State} {action : Action}
    (step : Step c before action after) (coherent : before.frame.HeadersCoherent) :
    after.frame.HeadersCoherent := by
  cases step with
  | receive => exact coherent
  | route =>
    simpa [Config.forwardedFrame, mode] using Frame.forwarded_headers coherent
  | outputRoute => exact coherent
  | forwardFilter => exact coherent
  | outputFilter => exact coherent
  | encryptIPsec policy association =>
    simpa [Config.ipsecFrame, mode] using
      Frame.push_ipsec_headers coherent (policy.seal association) _
        (bounds before.port).1
  | outerRoute => exact coherent
  | plain => exact coherent
  | decryptIPsec policy association body header phase encrypted =>
    simpa [Config.restoredFrame, mode] using
      Frame.pop_ipsec_headers coherent (policy.seal association) body encrypted
  | inputFilter => exact coherent
  | deliver => exact coherent
  | deliverEthernet => exact coherent
  | wire => exact coherent
  | bridge => exact coherent
  | bridgeOutput => exact coherent
  | encryptMACsec port association =>
    simpa [Config.macsecFrame, mode] using Frame.push_macsec_headers coherent association
  | unprotectedMACsec => exact coherent
  | decryptMACsec port association transmitted body configured phase physical encrypted =>
    simpa [Config.restoredFrame, mode] using
      Frame.pop_macsec_headers coherent transmitted body encrypted
  | uncheckedMACsec => exact coherent
  | encapsulate port =>
    simpa [Config.carrierFrame, mode] using
      Frame.push_carrier_headers coherent port.transmit _ (bounds port.routingPort).2
  | decapsulate port body configured phase owner unwrapped =>
    obtain ⟨endpoint, shape⟩ := unwrap_carrier_has_body unwrapped
    simpa [Config.restoredFrame, mode] using
      Frame.pop_carrier_headers coherent endpoint body shape
  | drop => exact coherent

theorem all_executions_preserve_headers (c : Config) (processing : HeaderProcessing)
    (mode : c.headerProcessing = some processing) (bounds : HeaderBounds processing)
    {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after) (coherent : before.frame.HeadersCoherent) :
    after.frame.HeadersCoherent := by
  have preserved : (lts c).TrInv (fun state => state.frame.HeadersCoherent) := by
    intro first action last step valid
    exact step_preserves_headers processing mode bounds step valid
  exact Cslib.LTS.mtrInv_of_trInv preserved before actions after run coherent

end TDN.MultiProtocolExecution

namespace TDN.PacketSource

lemma field_byte_bound (bytes : List UInt8) (offset : Nat) :
    field bytes offset 1 ≤ 255 := by
  unfold field
  cases bytes.drop offset with
  | nil => decide
  | cons byte rest =>
    simp only [List.take_succ_cons, List.take_zero, unsigned,
      List.foldl_cons, List.foldl_nil, Nat.zero_mul, Nat.zero_add]
    have bound := byte.toNat_lt
    omega

lemma matched_network_hop_bound {packet : PacketPolicy.Packet} {bytes : List UInt8}
    {dataBytes : Nat} (matched : NetworkHeaderMatches packet bytes dataBytes) :
    packet.hopLimit ≤ 255 := by
  rcases matched with ipv4 | ipv6
  · obtain ⟨_, _, _, _, _, _, _, _, _, _, same, _⟩ := ipv4
    rw [← same]
    exact field_byte_bound bytes 8
  · obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, same⟩ := ipv6
    rw [same]
    exact field_byte_bound bytes 7

lemma decoded_source_headers (datagram : Datagram) (decoded : datagram.Decoded) :
    ({ payload := 0, originDomain := 0,
       body := datagram.body } : LayeredFrame.Frame).HeadersCoherent := by
  cases shape : datagram.body with
  | datagram packet =>
    simp only [Datagram.Decoded, shape] at decoded
    exact ⟨⟨rfl, matched_network_hop_bound decoded.2.2.1⟩, rfl⟩
  | ethernet header => exact ⟨rfl, rfl⟩
  | ipsec => simp [Datagram.Decoded, shape] at decoded
  | macsec => simp [Datagram.Decoded, shape] at decoded
  | carrier => simp [Datagram.Decoded, shape] at decoded

end TDN.PacketSource
