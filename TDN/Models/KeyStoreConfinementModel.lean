import Cslib.Foundations.Semantics.LTS.Basic

namespace TDN.KeyInterface

structure Object (Key : Type) where
  handle : Nat
  key : Key
  sensitive : Bool
  extractable : Bool
  deriving DecidableEq

def Object.Restricted {Key : Type} (object : Object Key) : Prop :=
  object.sensitive = true ∧ object.extractable = false

def StoreSafe {Key : Type} (confidential : Key → Prop) (store : List (Object Key)) : Prop :=
  ∀ object ∈ store, confidential object.key → object.Restricted

inductive Event (Key Principal Interface : Type) where
  | export (key : Key) (interface : Interface)
  | read (key : Key) (principal : Principal)
  deriving DecidableEq

inductive Action (Key Principal Interface : Type) where
  | provision (object : Object Key)
  | duplicate (source destination : Object Key)
  | sign (object : Object Key) (principal : Principal)
  | digest (object : Object Key) (principal : Principal)
  | value (object : Object Key) (interface : Interface)
  | wrap (object : Object Key) (interface : Interface)
  | reject (request : String)
  | unrelated
  deriving DecidableEq

def Action.events {Key Principal Interface : Type} :
    Action Key Principal Interface → List (Event Key Principal Interface)
  | .sign object principal | .digest object principal => [.read object.key principal]
  | .value object interface => [.export object.key interface]
  | .wrap object interface => [.export object.key interface]
  | _ => []

inductive Step {Key Principal Interface : Type}
    (confidential : Key → Prop) (permits : Key → Principal → Prop) :
    List (Object Key) → Action Key Principal Interface → List (Object Key) → Prop where
  | provision (before : List (Object Key)) (object : Object Key)
      (attributes : confidential object.key → object.Restricted) :
      Step confidential permits before (.provision object) (object :: before)
  | duplicate (before : List (Object Key)) (source destination : Object Key)
      (installed : source ∈ before) (sameKey : destination.key = source.key)
      (sensitivity : source.sensitive = true → destination.sensitive = true)
      (extractability : source.extractable = false → destination.extractable = false) :
      Step confidential permits before (.duplicate source destination) (destination :: before)
  | sign (before : List (Object Key)) (object : Object Key) (principal : Principal)
      (installed : object ∈ before) (authorized : permits object.key principal) :
      Step confidential permits before (.sign object principal) before
  | digest (before : List (Object Key)) (object : Object Key) (principal : Principal)
      (installed : object ∈ before) (authorized : permits object.key principal) :
      Step confidential permits before (.digest object principal) before
  | value (before : List (Object Key)) (object : Object Key) (interface : Interface)
      (installed : object ∈ before) (readable : object.sensitive = false) :
      Step confidential permits before (.value object interface) before
  | wrap (before : List (Object Key)) (object : Object Key) (interface : Interface)
      (installed : object ∈ before) (extractable : object.extractable = true) :
      Step confidential permits before (.wrap object interface) before
  | reject (before : List (Object Key)) (request : String) :
      Step confidential permits before (.reject request) before
  | unrelated (before : List (Object Key)) :
      Step confidential permits before .unrelated before

def system {Key Principal Interface : Type}
    (confidential : Key → Prop) (permits : Key → Principal → Prop) :
    Cslib.LTS (List (Object Key)) (Action Key Principal Interface) :=
  ⟨Step confidential permits⟩

lemma step_preserves_store {Key Principal Interface : Type}
    {confidential : Key → Prop} {permits : Key → Principal → Prop}
    {before after : List (Object Key)} {action : Action Key Principal Interface}
    (step : Step confidential permits before action after) (safe : StoreSafe confidential before) :
    StoreSafe confidential after := by
  cases step with
  | provision object attributes =>
    intro target member protectedTarget
    rcases List.mem_cons.mp member with equal | old
    · subst target
      exact attributes protectedTarget
    · exact safe target old protectedTarget
  | duplicate source destination installed sameKey sensitivity extractability =>
    intro target member protectedTarget
    rcases List.mem_cons.mp member with equal | old
    · subst target
      have sourceProtected : confidential source.key := sameKey ▸ protectedTarget
      have old := safe source installed sourceProtected
      exact ⟨sensitivity old.1, extractability old.2⟩
    · exact safe target old protectedTarget
  | sign => exact safe
  | digest => exact safe
  | value => exact safe
  | wrap => exact safe
  | reject => exact safe
  | unrelated => exact safe

lemma step_export_impossible {Key Principal Interface : Type}
    {confidential : Key → Prop} {permits : Key → Principal → Prop}
    {before after : List (Object Key)} {action : Action Key Principal Interface}
    (step : Step confidential permits before action after) (safe : StoreSafe confidential before)
    {key : Key} (protectedKey : confidential key) (interface : Interface) :
    Event.export key interface ∉ action.events := by
  cases step with
  | value object output installed readable =>
    simp only [Action.events, List.mem_singleton]
    intro equal
    have sameKey : key = object.key := (Event.export.inj equal).1
    have attributes := safe object installed (sameKey ▸ protectedKey)
    exact Bool.noConfusion (attributes.1.symm.trans readable)
  | wrap object output installed extractable =>
    simp only [Action.events, List.mem_singleton]
    intro equal
    have sameKey : key = object.key := (Event.export.inj equal).1
    have attributes := safe object installed (sameKey ▸ protectedKey)
    exact Bool.noConfusion (attributes.2.symm.trans extractable)
  | provision => simp [Action.events]
  | duplicate => simp [Action.events]
  | sign => simp [Action.events]
  | digest => simp [Action.events]
  | reject => simp [Action.events]
  | unrelated => simp [Action.events]

lemma step_read_authorized {Key Principal Interface : Type}
    {confidential : Key → Prop} {permits : Key → Principal → Prop}
    {before after : List (Object Key)} {action : Action Key Principal Interface}
    (step : Step confidential permits before action after) {key : Key} {principal : Principal}
    (read : Event.read key principal ∈ action.events) : permits key principal := by
  cases step with
  | sign object reader installed authorized | digest object reader installed authorized =>
    have equal := List.mem_singleton.mp read
    have fields := Event.read.inj equal
    simpa only [fields.1, fields.2] using authorized
  | provision => simp [Action.events] at read
  | duplicate => simp [Action.events] at read
  | value => simp [Action.events] at read
  | wrap => simp [Action.events] at read
  | reject => simp [Action.events] at read
  | unrelated => simp [Action.events] at read

theorem protected_exports_impossible {Key Principal Interface : Type}
    {confidential : Key → Prop} {permits : Key → Principal → Prop}
    {before after : List (Object Key)} {actions : List (Action Key Principal Interface)}
    (run : (system confidential permits).MTr before actions after)
    (safe : StoreSafe confidential before) {key : Key} (protectedKey : confidential key)
    (interface : Interface) :
    Event.export key interface ∉ actions.flatMap Action.events := by
  revert safe
  induction run with
  | refl => simp
  | stepL step rest ih =>
    intro safe member
    rcases List.mem_append.mp (by simpa only [List.flatMap_cons] using member) with first | later
    · exact step_export_impossible step safe protectedKey interface first
    · exact ih (step_preserves_store step safe) later

theorem all_reads_authorized {Key Principal Interface : Type}
    {confidential : Key → Prop} {permits : Key → Principal → Prop}
    {before after : List (Object Key)} {actions : List (Action Key Principal Interface)}
    (run : (system confidential permits).MTr before actions after)
    {key : Key} {principal : Principal}
    (read : Event.read key principal ∈ actions.flatMap Action.events) : permits key principal := by
  induction run with
  | refl => simp at read
  | stepL step rest ih =>
    rcases List.mem_append.mp (by simpa only [List.flatMap_cons] using read) with first | later
    · exact step_read_authorized step first
    · exact ih later

end TDN.KeyInterface
