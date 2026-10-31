import TDN.Semantics.FiniteExecution

namespace TDN.Execution

def ProducedSeal (c : Config) (token : Seal) : Prop :=
  ∃ port association, association ∈ c.outbound port ∧
    ∃ state, state ∈ c.outboundStates port ∧ StateBindsPolicy state association ∧
      token = association.seal state

def ProducedEnvelopes (c : Config) (frame : Frame) : Prop :=
  ∀ envelope ∈ frame.envelopes, ProducedSeal c envelope.authentication

lemma step_preserves_envelope_provenance {c : Config} {a b : State} {action : Action}
    (step : Step c a action b) (before : ProducedEnvelopes c a.frame) :
    ProducedEnvelopes c b.frame := by
  cases step with
  | @encrypt port frame authenticated association sa selected installed bound =>
    intro envelope member
    rcases List.mem_cons.mp member with first | rest
    · subst envelope
      exact ⟨port, association, (matched_policy_is_configured selected).1,
        sa, installed, bound, rfl⟩
    · exact before envelope rest
  | decrypt association sa header rest tracking configured installed bound received outerSource outerDestination esp selected =>
    intro envelope member
    apply before envelope
    rw [received]
    exact List.mem_cons_of_mem _ member
  | receive => exact before
  | route => exact before
  | outputRoute => exact before
  | filter => exact before
  | outputFilter => exact before
  | outerRoute => exact before
  | switch => exact before
  | plain => exact before
  | wire => exact before
  | «local» => exact before
  | deliver => exact before
  | drop => exact before

theorem execution_envelopes_have_configured_provenance (c : Config)
    {a b : State} {actions : List Action} (run : (lts c).MTr a actions b)
    (initial : a.frame.envelopes = []) : ProducedEnvelopes c b.frame := by
  have preservation : (lts c).TrInv (fun s => ProducedEnvelopes c s.frame) :=
    fun _ _ _ step before => step_preserves_envelope_provenance step before
  apply Cslib.LTS.mtrInv_of_trInv preservation a actions b run
  intro envelope member
  simp [initial] at member

def SameWireAssociation (a b : SecurityAssociation) : Prop :=
  a.wireIdentity = b.wireIdentity ∧ a.sender = b.sender ∧ a.receiver = b.receiver

def PeerTagAgreement (c : Config) : Prop :=
  ∀ sender outgoing, outgoing ∈ c.outbound sender →
    ∀ sendState, sendState ∈ c.outboundStates sender → StateBindsPolicy sendState outgoing →
    ∀ receiver incoming, incoming ∈ c.inbound receiver →
    ∀ receiveState, receiveState ∈ c.inboundStates receiver →
      StateBindsPolicy receiveState incoming → SameWireAssociation sendState receiveState →
      outgoing.tag = incoming.tag

def WireMatchesSeal (token : Seal) (state : SecurityAssociation) : Prop :=
  token.association = state.wireIdentity ∧ token.sender = state.sender ∧ token.receiver = state.receiver

theorem wire_match_determines_annotated_seal {c : Config}
    (agreement : PeerTagAgreement c) {token : Seal} (produced : ProducedSeal c token)
    (receiver : Nat) (incoming : Association) (configured : incoming ∈ c.inbound receiver)
    (state : SecurityAssociation) (installed : state ∈ c.inboundStates receiver)
    (bound : StateBindsPolicy state incoming) (wire : WireMatchesSeal token state) :
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
  simp_all [Association.seal, SameWireAssociation]

def FinitePeerTagAgreement (devices : List DeviceData) : Prop :=
  ∀ sending ∈ ({} : DeviceData) :: devices, ∀ outgoing ∈ sending.outbound,
    ∀ sendState ∈ sending.states, StateBindsPolicy sendState outgoing →
    ∀ receiving ∈ ({} : DeviceData) :: devices, ∀ incoming ∈ receiving.inbound,
    ∀ receiveState ∈ receiving.states, StateBindsPolicy receiveState incoming →
      SameWireAssociation sendState receiveState → outgoing.tag = incoming.tag

instance (devices : List DeviceData) : Decidable (FinitePeerTagAgreement devices) := by
  unfold FinitePeerTagAgreement StateBindsPolicy SameWireAssociation
  infer_instance

theorem finite_peer_tag_agreement_sound (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (checked : FinitePeerTagAgreement devices) :
    PeerTagAgreement (finiteConfig devices ports routes links switches) := by
  intro sender outgoing member sendState installed bound receiver incoming configured receiveState present boundReceive same
  exact checked _ (device_at_member_or_default devices (portAt ports sender).owner)
    outgoing member sendState installed bound
    _ (device_at_member_or_default devices (portAt ports receiver).owner)
    incoming configured receiveState present boundReceive same

end TDN.Execution
