import TDN.Semantics.Filter
import Cslib.Foundations.Semantics.LTS.Basic

namespace TDN.StatefulFilter

/-- A state cache can bypass the ordered filter. State creation is a separate
operation, controlled by the selected rule and any translation or normalization.
The packet-to-key and cached-match functions include reverse-direction matching. -/
structure Config (Packet Key : Type) where
  rules : List (Filter.Rule Packet)
  fallback : Filter.Verdict
  key : Packet → Key
  cachedMatch : Key → Packet → Bool
  createsState : Packet → Bool

def verdict {Packet Key : Type} (config : Config Packet Key) (cache : List Key)
    (packet : Packet) : Filter.Verdict :=
  if cache.any (fun key => config.cachedMatch key packet) then .allow
  else Filter.evaluate config.rules config.fallback packet

def afterPacket {Packet Key : Type} (config : Config Packet Key) (cache : List Key)
    (packet : Packet) : List Key :=
  if verdict config cache packet = .allow ∧ config.createsState packet = true
  then config.key packet :: cache else cache

/-- Expiration may remove arbitrary entries. Packet processing may create an
entry only under the explicit state-creation condition. Administrative rule
changes, imported states and synchronization are outside a fixed configuration. -/
inductive Step {Packet Key : Type} (config : Config Packet Key) :
    List Key → Option Packet → List Key → Prop
  | packet (cache : List Key) (packet : Packet) :
      Step config cache (some packet) (afterPacket config cache packet)
  | expire (before after : List Key) (onlyRemovals : after.Sublist before) :
      Step config before none after

def lts {Packet Key : Type} (config : Config Packet Key) :
    Cslib.LTS (List Key) (Option Packet) := ⟨Step config⟩

lemma empty_step {Packet Key : Type} (config : Config Packet Key)
    (noCreation : ∀ packet, config.createsState packet = false)
    {before after : List Key} {event : Option Packet}
    (step : Step config before event after) (empty : before = []) : after = [] := by
  subst before
  cases step with
  | packet packet => simp [afterPacket, noCreation]
  | expire after onlyRemovals => simpa using onlyRemovals

/-- A local prohibition on all state-creation paths preserves an empty cache
through every finite packet sequence, including arbitrary expiration steps. -/
theorem empty_cache_preserved {Packet Key : Type} (config : Config Packet Key)
    (noCreation : ∀ packet, config.createsState packet = false)
    {events : List (Option Packet)} {cache : List Key}
    (run : (lts config).MTr [] events cache) : cache = [] := by
  have preserved : (lts config).TrInv (fun state => state = []) :=
    fun _ _ _ step empty => empty_step config noCreation step empty
  exact Cslib.LTS.mtrInv_of_trInv preserved [] events cache run rfl

theorem fixed_stateless_policy_is_effective {Packet Key : Type}
    (config : Config Packet Key)
    (noCreation : ∀ packet, config.createsState packet = false)
    {events : List (Option Packet)} {cache : List Key}
    (run : (lts config).MTr [] events cache) (packet : Packet) :
    verdict config cache packet = Filter.evaluate config.rules config.fallback packet := by
  rw [empty_cache_preserved config noCreation run]
  simp [verdict]

end TDN.StatefulFilter
