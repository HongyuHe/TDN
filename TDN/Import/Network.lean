import TDN.Import.Command

/-! Records shared by vendor adapters. A declared role is supplied by the network
owner; collection does not infer that role from a daemon's name. Routing-daemon
candidates remain separate from these kernel forwarding entries. -/
namespace TDN.Import

structure Device where
  id : String
  worker : String
  container : String
  adapters : List String
  declaredRole : Option String
  deriving DecidableEq, Repr, Lean.ToJson, Lean.FromJson, Lean.ToExpr

structure Observation where
  id : String
  device : String
  worker : String
  status : String
  sha256 : String
  started : String
  finished : String
  adapter : String
  capability : String
  parserVersion : String
  deriving DecidableEq, Repr, Lean.ToJson, Lean.FromJson, Lean.ToExpr

structure ObservedRoute where
  device : String
  family : Nat
  destinationLow : Nat
  destinationHigh : Nat
  prefixLength : Nat
  gateway : Option Nat
  output : Option String
  table : Nat
  kind : String
  protocol : String
  metric : Nat
  scope : String
  observationId : String
  deriving DecidableEq, Repr, Lean.ToJson, Lean.FromJson, Lean.ToExpr

structure NetworkSnapshot where
  schemaVersion : Nat
  id : String
  network : String
  manifestSha256 : String
  consistency : String
  devices : List Device
  observations : List Observation
  routes : List ObservedRoute
  deriving DecidableEq, Repr, Lean.ToJson, Lean.FromJson, Lean.ToExpr

def RoutesHaveSources (snapshot : NetworkSnapshot) : Prop :=
  ∀ route ∈ snapshot.routes, ∃ observation ∈ snapshot.observations,
    observation.id = route.observationId ∧ observation.device = route.device ∧
    observation.status = "observed" ∧
    (observation.capability = "fib4" ∨ observation.capability = "fib6")

instance (s : NetworkSnapshot) : Decidable (RoutesHaveSources s) := by
  unfold RoutesHaveSources
  infer_instance

syntax "tdn_snapshot " ident " from " str : command
macro_rules
  | `(tdn_snapshot $ns:ident from $file:str) => do
    let name := Lean.mkIdent (ns.getId ++ `snapshot)
    `(tdn_data $name : TDN.Import.NetworkSnapshot from $file ["snapshot"])
end TDN.Import
