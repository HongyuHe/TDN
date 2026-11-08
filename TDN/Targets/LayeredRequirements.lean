import TDN.Targets.Architecture
import TDN.Targets.PacketExecution
import TDN.Targets.DeliveryIsolation
import TDN.Semantics.ExecutionHistory
import TDN.Semantics.ExecutionEvents

namespace TDN.Targets

structure PacketExecutionView (State Action : Type) where
  system : Cslib.LTS State Action
  source : State → Prop
  transmittedGray : State → Prop
  transmittedBlack : State → Prop
  plaintextDelivered : State → Prop
  layers : State → List Layer
  network : State → String

structure ProtectionPair where
  innerComponent : String
  outerComponent : String
  innerMechanism : Mechanism
  outerMechanism : Mechanism
  innerKeyContext : String
  outerKeyContext : String
  communicatingSites : List String
  infrastructureComponents : Bool

def msc_nested_layer_protection {S A : Type} (view : PacketExecutionView S A)
    (pairs : List ProtectionPair) (independentContexts : String → String → Prop) : Prop :=
  (∀ pair ∈ pairs, pair.infrastructureComponents = true ∧
    independentContexts pair.innerKeyContext pair.outerKeyContext ∧
    (pair.outerMechanism = .macsec → pair.communicatingSites.length = 2)) ∧
  ∀ start finish actions, view.source start → view.system.MTr start actions finish →
    (view.transmittedGray finish → view.layers finish = [.inner]) ∧
    (view.transmittedBlack finish → view.layers finish = [.outer, .inner]) ∧
    (view.plaintextDelivered finish → view.layers finish = [])

def ProtectionRegions {S A : Type} (view : PacketExecutionView S A) (state : S) : Prop :=
  (view.transmittedGray state → view.layers state = [.inner]) ∧
  (view.transmittedBlack state → view.layers state = [.outer, .inner]) ∧
  (view.plaintextDelivered state → view.layers state = [])

theorem nested_layers_from_operational_invariant {S A : Type}
    (view : PacketExecutionView S A) (pairs : List ProtectionPair)
    (independentContexts : String → String → Prop) (invariant : S → Prop)
    (initial : ∀ state, view.source state → invariant state)
    (preserved : view.system.TrInv invariant)
    (observations : ∀ state, invariant state → ProtectionRegions view state)
    (configuration : ∀ pair ∈ pairs, pair.infrastructureComponents = true ∧
      independentContexts pair.innerKeyContext pair.outerKeyContext ∧
      (pair.outerMechanism = .macsec → pair.communicatingSites.length = 2)) :
    msc_nested_layer_protection view pairs independentContexts := by
  refine ⟨configuration, ?_⟩
  intro start finish actions source run
  exact observations finish (Cslib.LTS.mtrInv_of_trInv preserved start actions finish run (initial start source))

def NetworkHasLevel (networks : List RedNetworkIdentity) (id : String) (level : SecurityLevel) : Prop :=
  ∃ network ∈ networks, network.id = id ∧ network.level = level

def ModelDelivers {S A : Type} (view : PacketExecutionView S A) (source destination : String) : Prop :=
  ∃ start finish actions, view.source start ∧ view.network start = source ∧
    view.system.MTr start actions finish ∧ view.plaintextDelivered finish ∧
    view.network finish = destination

def msc_security_level_connectivity {S A : Type} (view : PacketExecutionView S A)
    (networks : List RedNetworkIdentity) (authenticatedInnerPairs requiredConnectivity : List (String × String))
    (innerLevel : String → SecurityLevel) : Prop :=
  DedicatedInnerAssignments networks ∧
  (∀ pair ∈ authenticatedInnerPairs, innerLevel pair.1 = innerLevel pair.2) ∧
  (∀ source destination, ModelDelivers view source destination →
    ∃ level, NetworkHasLevel networks source level ∧ NetworkHasLevel networks destination level) ∧
  ∀ pair ∈ requiredConnectivity,
    (∃ level, NetworkHasLevel networks pair.1 level ∧ NetworkHasLevel networks pair.2 level) ∧
    ModelDelivers view pair.1 pair.2

theorem security_connectivity_from_delivery_and_peer_checks {S A : Type}
    (view : PacketExecutionView S A) (networks : List RedNetworkIdentity)
    (authenticatedInnerPairs requiredConnectivity : List (String × String))
    (innerLevel : String → SecurityLevel)
    (dedicated : DedicatedInnerAssignments networks)
    (peerChecks : ∀ pair ∈ authenticatedInnerPairs, innerLevel pair.1 = innerLevel pair.2)
    (deliveryCheck : ∀ start finish actions,
      view.source start → view.system.MTr start actions finish → view.plaintextDelivered finish →
      ∃ level, NetworkHasLevel networks (view.network start) level ∧
        NetworkHasLevel networks (view.network finish) level)
    (positive : ∀ pair ∈ requiredConnectivity, ModelDelivers view pair.1 pair.2) :
    msc_security_level_connectivity view networks authenticatedInnerPairs requiredConnectivity innerLevel := by
  have isolated : ∀ source destination, ModelDelivers view source destination →
      ∃ level, NetworkHasLevel networks source level ∧ NetworkHasLevel networks destination level := by
    intro source destination delivered
    obtain ⟨start, finish, actions, originated, sourceIdentity, run, done, destinationIdentity⟩ := delivered
    simpa [sourceIdentity, destinationIdentity] using deliveryCheck start finish actions originated run done
  exact ⟨dedicated, peerChecks, isolated,
    fun pair member => ⟨isolated pair.1 pair.2 (positive pair member), positive pair member⟩⟩

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
  mechanism : Mechanism
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

def msc_inner_tunnel_no_bypass {S A : Type} (view : TunnelBoundaryView S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool) : Prop :=
  BoundaryNoBypass view ∧ ∀ component ∈ components,
    (component.mechanism = .ipsec → component.espTunnelMode = true ∧ component.associatedIPTunnel = true) ∧
    (outboundMACObjective = true → component.outboundMACPolicy = true) ∧
    (inboundMACObjective = true → component.inboundMACPolicy = true)

def msc_outer_tunnel_no_bypass {S A : Type} (view : TunnelBoundaryView S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool)
    (receivedGrayNonControl : S → Prop) (alreadyEncrypted : S → Prop) : Prop :=
  BoundaryNoBypass view ∧
  (∀ state, receivedGrayNonControl state → alreadyEncrypted state) ∧
  ∀ component ∈ components,
    (component.mechanism = .ipsec → component.espTunnelMode = true) ∧
    (outboundMACObjective = true → component.outboundMACPolicy = true) ∧
    (inboundMACObjective = true → component.inboundMACPolicy = true)

theorem protected_black_execution_has_two_encryptions (c : Execution.Environment)
    (sources blackIfaces : List Nat) (protection : msc_protected_red_payload_stack c sources blackIfaces)
    {start finish : Execution.State} {actions : List Execution.Action}
    (origin : RedPayloadOrigin c sources start) (run : (Execution.lts c).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    2 ≤ (actions.map Execution.encryptionCredit).sum := by
  have stack := protection start finish actions origin run ready black
  have length : finish.frame.envelopes.length = 2 := by
    have mapped := congrArg List.length stack
    simpa [Execution.Frame.tags] using mapped
  have growth := Execution.stack_growth_requires_encryptions c run
  rw [origin.2.2.2.1, List.length_nil, length] at growth
  simpa using growth

theorem two_layer_plaintext_restoration_has_two_decryptions (c : Execution.Environment)
    {start finish : Execution.State} {actions : List Execution.Action}
    (run : (Execution.lts c).MTr start actions finish)
    (initial : start.frame.envelopes.length = 2) (plaintext : finish.frame.envelopes = []) :
    2 ≤ (actions.map Execution.decryptionDebit).sum := by
  have removed := Execution.stack_removal_requires_decryptions c run
  simpa [initial, plaintext] using removed

end TDN.Targets
