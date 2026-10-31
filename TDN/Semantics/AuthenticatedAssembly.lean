import TDN.Semantics.ReassemblyOrigins

namespace TDN.AuthenticatedAssembly

/-- Secret denotes actual cryptographic key identity. It is not an SPI, reqid,
SCI or local key label. Epoch identifies an observed key-use interval; equality
of epoch labels alone cannot make two contexts cryptographically compatible. -/
structure Context (Secret Principal Epoch : Type) where
  secret : Secret
  receiver : Principal
  protocolDomain : Nat
  direction : Nat
  epoch : Epoch
  deriving DecidableEq

/-- A concrete backend supplies the complete epoch acceptance relation. Reused
key material may permit an older epoch, so equality of synthetic generation
labels is deliberately not an implicit wire authentication condition. -/
def Compatible {Secret Principal Epoch : Type}
    (epochAccepted : Epoch → Epoch → Prop)
    (sent received : Context Secret Principal Epoch) : Prop :=
  sent.secret = received.secret ∧ sent.receiver = received.receiver ∧
  sent.protocolDomain = received.protocolDomain ∧ sent.direction = received.direction ∧
  epochAccepted sent.epoch received.epoch

/-- An annotated publication records the real producer and semantic provenance.
Only project annotation is plaintext seen by the cryptographic decoder. -/
structure Message (Key Producer Wire Annotation : Type) where
  context : Key
  producer : Producer
  wire : List Wire
  annotation : Annotation
  deriving DecidableEq

/-- A decoder returns wire-visible plaintext, never source/domain annotations. -/
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

structure State (Key Producer Header Wire Annotation Plain : Type) where
  published : List (Message Key Producer Wire Annotation)
  fragments : List (Fragmentation.Fragment Header Wire)
  accepted : List (Decoded Key Wire Plain)

inductive Action where
  | publish | receive | discard | clear | accept

/-- This cryptographic contract supplies a prior publication witness for actual
decoded plaintext. The decoder cannot recover annotations or identify a unique
producer from indistinguishable plaintext. Safety below covers all matching
publications, not a conveniently selected witness.

The implementation must include every producer able to authenticate under the
receiving context, including other domains sharing a key. Completeness of that
producer scope, correct key/direction/epoch binding and exclusion of successful
forgeries remain explicit implementation assumptions. A local identifier or
empty publication set cannot establish the contract. -/
def AuthenticationSound {Key Producer Wire Annotation Plain : Type}
    (compatible : Key → Key → Prop) (project : Annotation → Plain)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop) : Prop :=
  ∀ published decoded, authenticates published decoded →
    ∃ message ∈ published, Matches compatible project message decoded

/-- The history parameter in authenticates is ghost state for the no-forgery
contract. A concrete decoder sees only receiving context, ciphertext and
plaintext. Its implementation correspondence must justify that history relation.
Receive and ordinary reassembly never inspect proof annotations. -/
inductive Step {Key Producer Header Wire Annotation Plain : Type} [DecidableEq Header]
    (produces : Message Key Producer Wire Annotation → Prop)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop) :
    State Key Producer Header Wire Annotation Plain → Action →
      State Key Producer Header Wire Annotation Plain → Prop where
  | publish {before message} (produced : produces message) :
      Step produces authenticates before .publish
        { before with published := before.published ++ [message] }
  | receive {before fragment} :
      Step produces authenticates before .receive
        { before with fragments := before.fragments ++ [fragment] }
  | discard {before retained} (subset : retained.Sublist before.fragments) :
      Step produces authenticates before .discard { before with fragments := retained }
  | clear {before} :
      Step produces authenticates before .clear { before with fragments := [] }
  | accept {before header packet context plaintext}
      (assembled : ReassemblyOrigins.assemble header before.fragments = some packet)
      (verified : authenticates before.published ⟨context, packet.bytes, plaintext⟩) :
      Step produces authenticates before .accept
        { before with fragments := []
                      accepted := before.accepted ++ [⟨context, packet.bytes, plaintext⟩] }

def system {Key Producer Header Wire Annotation Plain : Type} [DecidableEq Header]
    (produces : Message Key Producer Wire Annotation → Prop)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop) :
    Cslib.LTS (State Key Producer Header Wire Annotation Plain) Action :=
  ⟨Step produces authenticates⟩

def Safe {Key Producer Header Wire Annotation Plain : Type}
    (compatible : Key → Key → Prop) (project : Annotation → Plain)
    (property : Message Key Producer Wire Annotation → Prop)
    (state : State Key Producer Header Wire Annotation Plain) : Prop :=
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

/-- Every accepted plaintext has a real prior publication witness. All matching
publication annotations satisfy the source property, even when different
producers publish identical ciphertext/plaintext under an accepted context. -/
theorem all_accepted_messages_inherit_publication_property
    {Key Producer Header Wire Annotation Plain : Type} [DecidableEq Header]
    (produces : Message Key Producer Wire Annotation → Prop)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop)
    (compatible : Key → Key → Prop) (project : Annotation → Plain)
    (sound : AuthenticationSound compatible project authenticates)
    (property : Message Key Producer Wire Annotation → Prop)
    (publication : ∀ message, produces message → property message)
    {after : State Key Producer Header Wire Annotation Plain} {actions : List Action}
    (run : (system produces authenticates).MTr ⟨[], [], []⟩ actions after) :
    ∀ decoded ∈ after.accepted,
      (∃ message ∈ after.published, Matches compatible project message decoded) ∧
      (∀ message ∈ after.published, Matches compatible project message decoded → property message) := by
  have initial : Safe compatible project property
      (⟨[], [], []⟩ : State Key Producer Header Wire Annotation Plain) := by
    simp [Safe]
  have preserved := Cslib.LTS.mtrInv_of_trInv
    (local_publication_preserves produces authenticates compatible project sound property publication)
    _ actions after run initial
  exact fun decoded member =>
    ⟨preserved.2 decoded member, fun message present _ => preserved.1 message present⟩

/-- A captured deployment can start with a nonempty prior history. The caller
must justify all seeded publication properties and the provenance of any seeded
accepted messages. The theorem does not infer an empty history from a snapshot. -/
theorem accepted_messages_from_seeded_history
    {Key Producer Header Wire Annotation Plain : Type} [DecidableEq Header]
    (produces : Message Key Producer Wire Annotation → Prop)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop)
    (compatible : Key → Key → Prop) (project : Annotation → Plain)
    (sound : AuthenticationSound compatible project authenticates)
    (property : Message Key Producer Wire Annotation → Prop)
    (publication : ∀ message, produces message → property message)
    {before after : State Key Producer Header Wire Annotation Plain} {actions : List Action}
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

/-- Publication records require actual publication steps. Arbitrary fragments and
successful decodes cannot add a producer to the ledger. -/
theorem published_messages_were_produced
    {Key Producer Header Wire Annotation Plain : Type} [DecidableEq Header]
    (produces : Message Key Producer Wire Annotation → Prop)
    (authenticates : List (Message Key Producer Wire Annotation) →
      Decoded Key Wire Plain → Prop)
    {after : State Key Producer Header Wire Annotation Plain} {actions : List Action}
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

end TDN.AuthenticatedAssembly
