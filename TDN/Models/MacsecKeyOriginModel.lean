import Cslib.Foundations.Semantics.LTS.Basic
import Mathlib.Data.List.Basic

namespace TDN.KeySources

structure Config where
  hasPreSharedCAK : Bool
  hasPreSharedCKN : Bool
  deriving DecidableEq, Repr

def Config.preSharedEnabled (config : Config) : Bool :=
  config.hasPreSharedCAK && config.hasPreSharedCKN

inductive Origin where
  | authenticatedExchange
  | preSharedConfiguration
  deriving DecidableEq, Repr

structure Participant where
  identifier : Nat
  origin : Origin
  deriving DecidableEq, Repr

abbrev State := List Participant

inductive Action where
  | authenticated (identifier : Nat)
  | preShared (identifier : Nat)
  | remove (identifier : Nat)
  | progress

inductive Step (config : Config) : State → Action → State → Prop where
  | authenticated (state : State) (identifier : Nat) :
      Step config state (.authenticated identifier)
        (⟨identifier, .authenticatedExchange⟩ :: state)
  | preShared (state : State) (identifier : Nat)
      (enabled : config.preSharedEnabled = true) :
      Step config state (.preShared identifier)
        (⟨identifier, .preSharedConfiguration⟩ :: state)
  | remove (state : State) (identifier : Nat) :
      Step config state (.remove identifier)
        (state.filter (fun participant => participant.identifier != identifier))
  | progress (state : State) : Step config state .progress state

def system (config : Config) : Cslib.LTS State Action := ⟨Step config⟩

def OnlyAuthenticatedSources (state : State) : Prop :=
  ∀ participant ∈ state, participant.origin = .authenticatedExchange

lemma creation_preserves_authenticated_sources {config : Config}
    (disabled : config.preSharedEnabled = false) :
    (system config).TrInv OnlyAuthenticatedSources := by
  intro before action after step checked
  cases step with
  | authenticated identifier =>
    intro participant member
    rcases List.mem_cons.mp member with new | old
    · subst participant
      rfl
    · exact checked participant old
  | preShared identifier enabled => simp [disabled] at enabled
  | remove identifier =>
    intro participant member
    exact checked participant (List.mem_filter.mp member).1
  | progress => exact checked

theorem executions_have_only_authenticated_sources {config : Config}
    (disabled : config.preSharedEnabled = false) {actions : List Action} {state : State}
    (execution : (system config).MTr [] actions state) : OnlyAuthenticatedSources state := by
  exact Cslib.LTS.mtrInv_of_trInv (creation_preserves_authenticated_sources disabled)
    _ _ _ execution (by simp [OnlyAuthenticatedSources])

end TDN.KeySources
