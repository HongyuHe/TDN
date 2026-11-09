import TDN.Models.TableDrivenDataPlane

namespace TDN.DataPlaneForwarding

def ProducedSeal (c : DataPlaneModel) (token : TunnelSAStamp) : Prop :=
  ∃ iface association, association ∈ c.egressPolicies iface ∧
    ∃ state, state ∈ c.egressSAs iface ∧ saMatchesPolicy state association ∧
      token = association.seal state

def ProducedEnvelopes (c : DataPlaneModel) (frame : Frame) : Prop :=
  ∀ envelope ∈ frame.encapLayers, ProducedSeal c envelope.authentication

lemma step_preserves_envelope_provenance {c : DataPlaneModel} {a b : State} {action : Action}
    (step : Step c a action b) (before : ProducedEnvelopes c a.frame) :
    ProducedEnvelopes c b.frame := by
  cases step with
  | @encrypt iface frame authenticated association sa selected installed bound =>
    intro envelope member
    rcases List.mem_cons.mp member with first | rest
    · subst envelope
      exact ⟨iface, association, (matched_policy_is_configured selected).1,
        sa, installed, bound, rfl⟩
    · exact before envelope rest
  | decrypt association sa header rest tracking configured installed bound received outerSource outerDestination esp selected =>
    intro envelope member
    apply before envelope
    rw [received]
    exact List.mem_cons_of_mem _ member
  | receive => exact before
  | route => exact before
  | routeLocalOutput => exact before
  | filter => exact before
  | outputFilter => exact before
  | routeOuterPacket => exact before
  | bridge => exact before
  | forwardWithoutEncap => exact before
  | linkTransmit => exact before
  | deliverToLocalHost => exact before
  | deliver => exact before
  | drop => exact before

theorem forwarding_envelopes_have_configured_provenance (c : DataPlaneModel)
    {a b : State} {actions : List Action} (run : (lts c).MTr a actions b)
    (initial : a.frame.encapLayers = []) : ProducedEnvelopes c b.frame := by
  have preservation : (lts c).TrInv (fun s => ProducedEnvelopes c s.frame) :=
    fun _ _ _ step before => step_preserves_envelope_provenance step before
  apply Cslib.LTS.mtrInv_of_trInv preservation a actions b run
  intro envelope member
  simp [initial] at member

def SameWireAssociation (a b : InstalledSA) : Prop :=
  a.spi = b.spi ∧ a.sender = b.sender ∧ a.receiver = b.receiver

def PeerTagAgreement (c : DataPlaneModel) : Prop :=
  ∀ sender outgoing, outgoing ∈ c.egressPolicies sender →
    ∀ sendState, sendState ∈ c.egressSAs sender → saMatchesPolicy sendState outgoing →
    ∀ receiver incoming, incoming ∈ c.ingressPolicies receiver →
    ∀ receiveState, receiveState ∈ c.ingressSAs receiver →
      saMatchesPolicy receiveState incoming → SameWireAssociation sendState receiveState →
      outgoing.tag = incoming.tag

def WireMatchesSeal (token : TunnelSAStamp) (state : InstalledSA) : Prop :=
  token.association = state.spi ∧ token.sender = state.sender ∧ token.receiver = state.receiver

theorem wire_match_determines_annotated_seal {c : DataPlaneModel}
    (agreement : PeerTagAgreement c) {token : TunnelSAStamp} (produced : ProducedSeal c token)
    (receiver : Nat) (incoming : IpsecPolicy) (configured : incoming ∈ c.ingressPolicies receiver)
    (state : InstalledSA) (installed : state ∈ c.ingressSAs receiver)
    (bound : saMatchesPolicy state incoming) (wire : WireMatchesSeal token state) :
    token = incoming.seal state := by
  obtain ⟨sender, outgoing, member, sendState, existsState, boundSend, equal⟩ := produced
  subst token
  have same : SameWireAssociation sendState state := wire
  have tags := agreement sender outgoing member sendState existsState boundSend
    receiver incoming configured state installed bound same
  cases outgoing
  cases incoming
  cases sendState
  cases state
  simp_all [IpsecPolicy.seal, SameWireAssociation]

def TableDrivenPeerTagAgreement (devices : List DeviceData) : Prop :=
  ∀ sending ∈ ({} : DeviceData) :: devices, ∀ outgoing ∈ sending.egressPolicies,
    ∀ sendState ∈ sending.states, saMatchesPolicy sendState outgoing →
    ∀ receiving ∈ ({} : DeviceData) :: devices, ∀ incoming ∈ receiving.ingressPolicies,
    ∀ receiveState ∈ receiving.states, saMatchesPolicy receiveState incoming →
      SameWireAssociation sendState receiveState → outgoing.tag = incoming.tag

instance (devices : List DeviceData) : Decidable (TableDrivenPeerTagAgreement devices) := by
  unfold TableDrivenPeerTagAgreement saMatchesPolicy SameWireAssociation
  infer_instance

theorem table_driven_peer_tag_agreement_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (links switches : List (Nat × Nat))
    (checked : TableDrivenPeerTagAgreement devices) :
    PeerTagAgreement (dataPlaneModelFromRecords devices ifaces routes links switches) := by
  intro sender outgoing member sendState installed bound receiver incoming configured receiveState present boundReceive same
  exact checked _ (device_at_member_or_default devices (ifaceAt ifaces sender).owner)
    outgoing member sendState installed bound
    _ (device_at_member_or_default devices (ifaceAt ifaces receiver).owner)
    incoming configured receiveState present boundReceive same

end TDN.DataPlaneForwarding
