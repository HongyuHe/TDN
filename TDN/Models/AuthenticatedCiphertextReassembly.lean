import TDN.Models.ReassemblyBufferDomainSafety

namespace TDN.AuthenticatedReassembly

structure Context (Secret Principal Epoch : Type) where
  secret : Secret
  receiver : Principal
  protocolDomain : Nat
  direction : Nat
  epoch : Epoch
  deriving DecidableEq

def Compatible {Secret Principal Epoch : Type}
    (epochAccepted : Epoch → Epoch → Prop)
    (sent received : Context Secret Principal Epoch) : Prop :=
  sent.secret = received.secret ∧ sent.receiver = received.receiver ∧
  sent.protocolDomain = received.protocolDomain ∧ sent.direction = received.direction ∧
  epochAccepted sent.epoch received.epoch

structure Message (Key Producer Wire Annotation : Type) where
  context : Key
  producer : Producer
  wire : List Wire
  annotation : Annotation
  deriving DecidableEq

structure Decoded (Key Wire Plain : Type) where
  context : Key
  wire : List Wire
  plaintext : Plain
  deriving DecidableEq

def Matches {Key Producer Wire Annotation Plain : Type}
    (compatible : Key → Key → Prop) (project : Annotation → Plain)
    (message : Message Key Producer Wire Annotation) (decoded : Decoded Key Wire Plain) : Prop :=
  compatible message.context decoded.context ∧ message.wire = decoded.wire ∧
    project message.annotation = decoded.plaintext

structure ReassemblyState (Key Producer Header Wire Annotation Plain : Type) where
  published : List (Message Key Producer Wire Annotation)
  fragments : List (Fragmentation.PayloadFragment Header Wire)
  accepted : List (Decoded Key Wire Plain)

inductive ReassemblyAction where
  | publish | receive | discard | clear | accept

def AuthenticationSound {Key Producer Wire Annotation Plain : Type}
    (compatible : Key → Key → Prop) (project : Annotation → Plain)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop) : Prop :=
  ∀ published decoded, authenticates published decoded →
    ∃ message ∈ published, Matches compatible project message decoded

inductive ReassemblyStep {Key Producer Header Wire Annotation Plain : Type} [DecidableEq Header]
    (produces : Message Key Producer Wire Annotation → Prop)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop) :
    ReassemblyState Key Producer Header Wire Annotation Plain → ReassemblyAction →
      ReassemblyState Key Producer Header Wire Annotation Plain → Prop where
  | publish {before message} (produced : produces message) :
      ReassemblyStep produces authenticates before .publish
        { before with published := before.published ++ [message] }
  | receive {before fragment} :
      ReassemblyStep produces authenticates before .receive
        { before with fragments := before.fragments ++ [fragment] }
  | discard {before retained} (subset : retained.Sublist before.fragments) :
      ReassemblyStep produces authenticates before .discard { before with fragments := retained }
  | clear {before} :
      ReassemblyStep produces authenticates before .clear { before with fragments := [] }
  | accept {before header packet context plaintext}
      (assembled : ReassemblyOrigins.assemble header before.fragments = some packet)
      (verified : authenticates before.published ⟨context, packet.bytes, plaintext⟩) :
      ReassemblyStep produces authenticates before .accept
        { before with fragments := []
                      accepted := before.accepted ++ [⟨context, packet.bytes, plaintext⟩] }

def system {Key Producer Header Wire Annotation Plain : Type} [DecidableEq Header]
    (produces : Message Key Producer Wire Annotation → Prop)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop) :
    Cslib.LTS (ReassemblyState Key Producer Header Wire Annotation Plain) ReassemblyAction :=
  ⟨ReassemblyStep produces authenticates⟩

def Safe {Key Producer Header Wire Annotation Plain : Type}
    (compatible : Key → Key → Prop) (project : Annotation → Plain)
    (property : Message Key Producer Wire Annotation → Prop)
    (state : ReassemblyState Key Producer Header Wire Annotation Plain) : Prop :=
  (∀ message ∈ state.published, property message) ∧
  (∀ decoded ∈ state.accepted, ∃ message ∈ state.published,
    Matches compatible project message decoded)

lemma local_publication_preserves
    {Key Producer Header Wire Annotation Plain : Type} [DecidableEq Header]
    (produces : Message Key Producer Wire Annotation → Prop)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop)
    (compatible : Key → Key → Prop) (project : Annotation → Plain)
    (sound : AuthenticationSound compatible project authenticates)
    (property : Message Key Producer Wire Annotation → Prop)
    (publication : ∀ message, produces message → property message) :
    (system (Header := Header) produces authenticates).TrInv
      (Safe compatible project property) := by
  intro before action after step safe
  cases step with
  | publish produced =>
    refine ⟨?_, ?_⟩
    · intro message member
      rcases List.mem_append.mp member with old | added
      · exact safe.1 message old
      · have equal := List.mem_singleton.mp added
        subst message
        exact publication _ produced
    · intro decoded member
      obtain ⟨message, old, matching⟩ := safe.2 decoded member
      exact ⟨message, List.mem_append_left _ old, matching⟩
  | receive => exact safe
  | discard => exact safe
  | clear => exact safe
  | accept assembled verified =>
    refine ⟨safe.1, ?_⟩
    intro decoded member
    rcases List.mem_append.mp member with old | added
    · exact safe.2 decoded old
    · have equal := List.mem_singleton.mp added
      subst decoded
      exact sound _ _ verified

theorem all_accepted_messages_inherit_publication_property
    {Key Producer Header Wire Annotation Plain : Type} [DecidableEq Header]
    (produces : Message Key Producer Wire Annotation → Prop)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop)
    (compatible : Key → Key → Prop) (project : Annotation → Plain)
    (sound : AuthenticationSound compatible project authenticates)
    (property : Message Key Producer Wire Annotation → Prop)
    (publication : ∀ message, produces message → property message)
    {after : ReassemblyState Key Producer Header Wire Annotation Plain} {actions : List ReassemblyAction}
    (run : (system produces authenticates).MTr ⟨[], [], []⟩ actions after) :
    ∀ decoded ∈ after.accepted,
      (∃ message ∈ after.published, Matches compatible project message decoded) ∧
      (∀ message ∈ after.published, Matches compatible project message decoded → property message) := by
  have initial : Safe compatible project property
      (⟨[], [], []⟩ : ReassemblyState Key Producer Header Wire Annotation Plain) := by
    simp [Safe]
  have preserved := Cslib.LTS.mtrInv_of_trInv
    (local_publication_preserves produces authenticates compatible project sound property publication)
    _ actions after run initial
  exact fun decoded member =>
    ⟨preserved.2 decoded member, fun message present _ => preserved.1 message present⟩

theorem accepted_messages_from_seeded_history
    {Key Producer Header Wire Annotation Plain : Type} [DecidableEq Header]
    (produces : Message Key Producer Wire Annotation → Prop)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop)
    (compatible : Key → Key → Prop) (project : Annotation → Plain)
    (sound : AuthenticationSound compatible project authenticates)
    (property : Message Key Producer Wire Annotation → Prop)
    (publication : ∀ message, produces message → property message)
    {before after : ReassemblyState Key Producer Header Wire Annotation Plain} {actions : List ReassemblyAction}
    (initial : Safe compatible project property before)
    (run : (system produces authenticates).MTr before actions after) :
    ∀ decoded ∈ after.accepted,
      (∃ message ∈ after.published, Matches compatible project message decoded) ∧
      (∀ message ∈ after.published, Matches compatible project message decoded → property message) := by
  have preserved := Cslib.LTS.mtrInv_of_trInv
    (local_publication_preserves produces authenticates compatible project sound property publication)
    before actions after run initial
  exact fun decoded member =>
    ⟨preserved.2 decoded member, fun message present _ => preserved.1 message present⟩

theorem published_messages_were_produced
    {Key Producer Header Wire Annotation Plain : Type} [DecidableEq Header]
    (produces : Message Key Producer Wire Annotation → Prop)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop)
    {after : ReassemblyState Key Producer Header Wire Annotation Plain} {actions : List ReassemblyAction}
    (run : (system produces authenticates).MTr ⟨[], [], []⟩ actions after) :
    ∀ message ∈ after.published, produces message := by
  have preserved : (system (Header := Header) produces authenticates).TrInv
      (fun state => ∀ message ∈ state.published, produces message) := by
    intro before action after step old
    cases step with
    | publish produced =>
      intro message member
      rcases List.mem_append.mp member with present | added
      · exact old message present
      · have equal := List.mem_singleton.mp added
        subst message
        exact produced
    | receive => exact old
    | discard => exact old
    | clear => exact old
    | accept => exact old
  exact Cslib.LTS.mtrInv_of_trInv preserved _ actions after run (by simp)

end TDN.AuthenticatedReassembly
