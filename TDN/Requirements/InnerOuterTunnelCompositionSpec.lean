import TDN.Requirements.TwoLayerOverlayArchitecture
import TDN.Requirements.DoubleEncryptionOnBlackLinks
import TDN.Requirements.PacketEnclaveIsolation
import TDN.Models.EncapDecapBalance
import TDN.Models.TunnelEncryptionEvents

namespace TDN.Requirements

structure TunnelBoundaryView (State Action : Type) where
  system : Cslib.LTS State Action
  outboundEntry : State → Prop
  outboundExit : State → Prop
  inboundEntry : State → Prop
  inboundExit : State → Prop
  outboundProtected : State → Prop
  inboundDecryptionOccurred : State → List Action → State → Prop
  splitTunnelExit : State → Prop

structure EncryptionComponentConfiguration where
  id : String
  protocol : EncryptionProtocol
  espTunnelMode : Bool
  associatedIPTunnel : Bool
  outboundMACPolicy : Bool
  inboundMACPolicy : Bool

def BoundaryNoBypass {S A : Type} (view : TunnelBoundaryView S A) : Prop :=
  (∀ start finish actions, view.outboundEntry start → view.system.MTr start actions finish →
    view.outboundExit finish → view.outboundProtected finish) ∧
  (∀ start finish actions, view.inboundEntry start → view.system.MTr start actions finish →
    view.inboundExit finish → view.inboundDecryptionOccurred start actions finish) ∧
  ∀ start finish actions, view.outboundEntry start → view.system.MTr start actions finish →
    ¬ view.splitTunnelExit finish

def state_level_inner_no_bypass {S A : Type} (view : TunnelBoundaryView S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool) : Prop :=
  BoundaryNoBypass view ∧ ∀ component ∈ components,
    (component.protocol = .ipsec → component.espTunnelMode = true ∧ component.associatedIPTunnel = true) ∧
    (outboundMACObjective = true → component.outboundMACPolicy = true) ∧
    (inboundMACObjective = true → component.inboundMACPolicy = true)

def state_level_outer_no_bypass {S A : Type} (view : TunnelBoundaryView S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool)
    (receivedGrayNonControl : S → Prop) (alreadyEncrypted : S → Prop) : Prop :=
  BoundaryNoBypass view ∧
  (∀ state, receivedGrayNonControl state → alreadyEncrypted state) ∧
  ∀ component ∈ components,
    (component.protocol = .ipsec → component.espTunnelMode = true) ∧
    (outboundMACObjective = true → component.outboundMACPolicy = true) ∧
    (inboundMACObjective = true → component.inboundMACPolicy = true)

theorem protected_black_forwarding_has_two_encryptions (c : DataPlaneForwarding.DataPlaneModel)
    (sources blackIfaces : List Nat) (protection : red_traffic_is_doubly_encrypted_on_black_links c sources blackIfaces)
    {start finish : DataPlaneForwarding.ForwardingState} {actions : List DataPlaneForwarding.ForwardingAction}
    (origin : RedPayloadOrigin c sources start) (run : (DataPlaneForwarding.lts c).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    2 ≤ (actions.map DataPlaneForwarding.encapsulationCount).sum := by
  have stack := protection start finish actions origin run ready black
  have length : finish.frame.encapLayers.length = 2 := by
    have mapped := congrArg List.length stack
    simpa [DataPlaneForwarding.IpsecFrame.encapLayerIds] using mapped
  have growth := DataPlaneForwarding.stack_growth_requires_encryptions c run
  rw [origin.2.2.2.1, List.length_nil, length] at growth
  simpa using growth

theorem two_layer_plaintext_restoration_has_two_decryptions (c : DataPlaneForwarding.DataPlaneModel)
    {start finish : DataPlaneForwarding.ForwardingState} {actions : List DataPlaneForwarding.ForwardingAction}
    (run : (DataPlaneForwarding.lts c).MTr start actions finish)
    (initial : start.frame.encapLayers.length = 2) (plaintext : finish.frame.encapLayers = []) :
    2 ≤ (actions.map DataPlaneForwarding.decapsulationCount).sum := by
  have removed := DataPlaneForwarding.stack_removal_requires_decryptions c run
  simpa [initial, plaintext] using removed

end TDN.Requirements
