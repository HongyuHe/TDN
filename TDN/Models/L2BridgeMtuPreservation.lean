import TDN.Models.PerStageMtuInvariants
import TDN.Models.PayloadToNatEncoding

namespace TDN.MultiProtocolForwarding
open LayeredFrame PacketSource IPsecFrameEncoding


def EthernetSizeBound (mtu : Nat → Nat) (state : State) : Prop :=
  ∀ header, state.frame.body = .ethernet header →
    (LinkAdmission.decodePayload state.frame.payload).length ≤ mtu state.iface

structure EthernetMTUChecks (configuration : Config) (mtu : Nat → Nat) : Prop where
  physical : ∀ first last, configuration.physicalLink first last → mtu first ≤ mtu last
  bridge : ∀ first last, configuration.bridge first last → mtu first ≤ mtu last

lemma Ethernet_no_visible (configuration : Config) (frame : Frame) (header : EthernetHeader)
    (body : frame.body = .ethernet header) : configuration.visibleHeader frame = none := by
  cases mode : configuration.headerProcessing <;>
    simp only [Config.visibleHeader, mode, Frame.visibleHeader, body, Body.visibleHeader]


theorem device_step_preserves_Ethernet_size {configuration : Config}
    {required : Nat → Bool} {mtu plaintextLimit authenticationLimit : Nat → Nat}
    (checks : SizeChecks configuration required mtu plaintextLimit authenticationLimit)
    (links : EthernetMTUChecks configuration mtu)
    {before after : State} {action : Action} (step : Step configuration before action after)
    (invariant : EthernetSizeBound mtu before) : EthernetSizeBound mtu after := by
  intro header plain
  cases step with
  | receive => exact invariant header plain
  | route route datapathStage visible chosen entry =>
    have previous : before.frame.body = .ethernet header := by simpa only [Config.forwardedFrame_body] using plain
    rw [Ethernet_no_visible configuration before.frame header previous] at visible
    cases visible
  | routeLocalOutput route datapathStage visible chosen entry =>
    rw [Ethernet_no_visible configuration before.frame header plain] at visible
    cases visible
  | forwardFilter => exact invariant header plain
  | outputFilter => exact invariant header plain
  | encryptIPsec => simp only [Config.ipsecFrame_body] at plain; cases plain
  | routeOuterPacket route datapathStage visible chosen entry =>
    rw [Ethernet_no_visible configuration before.frame header plain] at visible
    cases visible
  | forwardWithoutEncap => exact invariant header plain
  | decryptIPsec policy association contents packet datapathStage encrypted configured installed bound visible selected tracking =>
    have contentBody : contents = .ethernet header := by simpa only [Config.restoredFrame_body] using plain
    rw [contentBody, Body.visibleHeader] at visible
    cases visible
  | inputFilter => exact invariant header plain
  | deliver => exact invariant header plain
  | deliverEthernet => exact invariant header plain
  | linkTransmit next datapathStage linked => exact (invariant header plain).trans (links.physical _ _ linked)
  | bridge next datapathStage member => exact (invariant header plain).trans (links.bridge _ _ member)
  | bridgeOutput next datapathStage member => exact (invariant header plain).trans (links.bridge _ _ member)
  | encryptMACsec iface association configured => simp only [checks.noMAC, List.not_mem_nil] at configured
  | unprotectedMACsec iface configured => simp only [checks.noMAC, List.not_mem_nil] at configured
  | decryptMACsec iface association transmitted contents configured => simp only [checks.noMAC, List.not_mem_nil] at configured
  | uncheckedMACsec iface configured => simp only [checks.noMAC, List.not_mem_nil] at configured
  | encapsulate iface configured => simp only [checks.noCarriers, List.not_mem_nil] at configured
  | decapsulate iface contents configured => simp only [checks.noCarriers, List.not_mem_nil] at configured
  | drop => exact invariant header plain

end TDN.MultiProtocolForwarding

namespace TDN.PacketSource

lemma Ethernet_reassembly_size (datagram : Datagram) (header : LayeredFrame.EthernetHeader)
    (body : datagram.body = .ethernet header) (mtu : Nat) (reassembles : datagram.Reassembles mtu)
    (decoded : datagram.Decoded) : datagram.application.length ≤ mtu := by
  have lengths : datagram.fragments.length = 1 := by
    have rest := reassembles.2.2
    rw [body] at rest
    exact rest.1
  obtain ⟨fragment, fragments⟩ := List.length_eq_one_iff.mp lengths
  have bounded := (reassembles.2.1 fragment (by simp [fragments])).2
  have data := reassembles.1.2.2.2
  rw [fragments] at data
  have payload : fragment.data = datagram.application := by
    rw [Datagram.Decoded, body] at decoded
    simpa only [List.map_singleton, List.flatten_singleton, Fragment.AsPiece, Datagram.Data,
      decoded.1, List.nil_append] using data
  simpa only [Fragment.MtuBytes, body, payload] using bounded

end TDN.PacketSource
