import TDN.Semantics.KernelResponses

namespace TDN.HistoricalResponses

structure State (S : Type) where
  current : S
  retained : List S

inductive Action (A : Type) where
  | network (action : A)
  | selectRetained

inductive Step {S A : Type} (network : Cslib.LTS S A) :
    State S → Action A → State S → Prop where
  | network {before after : S} {action : A} {retained : List S}
      (step : network.Tr before action after) :
      Step network ⟨before, retained⟩ (.network action) ⟨after, before :: retained⟩
  | select {current saved : S} {retained : List S} (present : saved ∈ retained) :
      Step network ⟨current, retained⟩ .selectRetained ⟨saved, retained⟩

def lts {S A : Type} (network : Cslib.LTS S A) : Cslib.LTS (State S) (Action A) :=
  ⟨Step network⟩

def Safe {S : Type} (safe : S → Prop) (state : State S) : Prop :=
  safe state.current ∧ ∀ saved ∈ state.retained, safe saved

lemma network_preserves_retained_safety {S A : Type}
    (network : Cslib.LTS S A) (safe : S → Prop) (preserves : network.TrInv safe) :
    (lts network).TrInv (Safe safe) := by
  intro before action after step valid
  cases step with
  | network step =>
    refine ⟨preserves _ _ _ step valid.1, ?_⟩
    intro saved member
    rcases List.mem_cons.mp member with same | old
    · simpa [same] using valid.1
    · exact valid.2 saved old
  | select present => exact ⟨valid.2 _ present, valid.2⟩

def responseConfig {S : Type} (config : KernelResponses.Config S) :
    KernelResponses.Config (State S) where
  generates state := config.generates state.current
  selectedRoute state := config.selectedRoute state.current
  outputRules state := config.outputRules state.current
  outputFallback state := config.outputFallback state.current
  interfaceName := config.interfaceName
  emit state header port :=
    ⟨config.emit state.current header port, state.current :: state.retained⟩

theorem all_historical_responses_preserve_safety {S A : Type}
    (network : Cslib.LTS S A) (config : KernelResponses.Config S) (safe : S → Prop)
    (preserves : network.TrInv safe)
    (replyPreserves : ∀ source header port,
      safe source → config.generates source → KernelResponses.ResponseProtocol header.protocol →
      config.selectedRoute source header port →
      Filter.evaluate ((config.outputRules source port).map PacketPolicy.Rule.toFilter)
        (config.outputFallback source port) (KernelResponses.outputPacket config header port) = .allow →
      config.interfaceName port ≠ "lo" → safe (config.emit source header port))
    {before after : State S}
    {actions : List (KernelResponses.Action (Action A))}
    (run : (KernelResponses.lts (lts network) (responseConfig config)).MTr
      (.network before) actions (.network after))
    (initial : Safe safe before) : Safe safe after := by
  apply KernelResponses.copied_response_executions_remain_safe
    (lts network) (responseConfig config) (Safe safe)
    (network_preserves_retained_safety network safe preserves) _ run initial
  intro source header port valid enabled protocol selected accepted external
  refine ⟨replyPreserves source.current header port valid.1 enabled protocol selected accepted external, ?_⟩
  intro saved member
  rcases List.mem_cons.mp member with same | old
  · simpa [same] using valid.1
  · exact valid.2 saved old

theorem lift_network_trace {S A : Type} (network : Cslib.LTS S A)
    {before after : S} {actions : List A} (run : network.MTr before actions after)
    (retained : List S) :
    ∃ saved, (lts network).MTr ⟨before, retained⟩
      (actions.map Action.network) ⟨after, saved⟩ := by
  induction run generalizing retained with
  | refl => exact ⟨retained, .refl⟩
  | @stepL first action middle actions last step tail ih =>
    obtain ⟨saved, rest⟩ := ih (first :: retained)
    exact ⟨saved, .stepL (.network step) rest⟩

end TDN.HistoricalResponses
