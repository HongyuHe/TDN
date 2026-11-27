import TDN.Import.SnapshotLoader
import TDN.Models.OrderedAclFilter

namespace TDN.Benchmark.ServicePolicy

abbrev Band := Nat × Nat
abbrev Region := List Band

structure Rule where
  region : Region
  permit : Bool

structure Query where
  clause : String
  scope : Region
  exceptions : List Region
  mustPermit : Bool

structure Chain where
  device : String
  hook : String
  fallback : Bool
  rules : List Rule
  queries : List Query

def overlaps (a b : Region) : Bool :=
  a.length == b.length && (a.zip b).all fun (x, y) => x.1 ≤ y.2 && y.1 ≤ x.2

def subtract (a b : Region) : List Region :=
  match a, b with
  | x :: xs, y :: ys =>
    if !overlaps a b then [a] else
      let lo := max x.1 y.1
      let hi := min x.2 y.2
      (if x.1 < lo then [(x.1, lo - 1) :: xs] else []) ++
      (if hi < x.2 then [(hi + 1, x.2) :: xs] else []) ++
      (subtract xs ys).map ((lo, hi) :: ·)
  | [], [] => []
  | _, _ => [a]

def firstDisagreement (expected fallback : Bool) :
    List Rule → List Region → Option (List Nat)
  | _, [] => none
  | [], left => if fallback == expected then none else left.head?.map (·.map Prod.fst)
  | r :: rest, left =>
    if r.permit != expected then
      match left.find? (overlaps r.region) with
      | some piece => some ((piece.zip r.region).map fun (x,y) => max x.1 y.1)
      | none => firstDisagreement expected fallback rest left
    else firstDisagreement expected fallback rest (left.flatMap (subtract · r.region))

def contains (region : Region) (p : List Nat) : Bool :=
  region.length == p.length && (region.zip p).all fun (r,x) => r.1 ≤ x && x ≤ r.2

def permits (c : Chain) (p : List Nat) : Bool :=
  let verdict (b : Bool) := if b then Filter.Verdict.allow else .deny
  Filter.evaluate (c.rules.map fun r => ⟨contains r.region, verdict r.permit⟩)
    (verdict c.fallback) p == .allow

def agrees (c : Chain) (q : Query) : Bool :=
  let tested := q.exceptions.foldl (fun pieces exc => pieces.flatMap (subtract · exc)) [q.scope]
  match firstDisagreement q.mustPermit c.fallback c.rules tested with
  | none => true
  | some p => !(contains q.scope p && !(q.exceptions.any (contains · p)) && permits c p != q.mustPermit)

load_network_records chains : List Chain from "evidence.json" ["chains"]
load_network_records registeredPanel : Bool from "evidence.json" ["registeredPanel"]
load_network_records checkIPv4Options : Bool from "evidence.json" ["checkIPv4Options"]

def checks (clause : String) : Bool :=
  let items := chains.flatMap fun c => (c.queries.filter (·.clause == clause)).map (agrees c)
  !items.isEmpty && items.all id

set_option Elab.async false
run_cmd do Lean.logInfo m!"TDN_BEGIN {← IO.monoNanosNow}"

lemma gray_http_only_for_inner_revocation : checks "MSC-PF-25" = true := by native_decide
lemma gray_permits_required_ike : checks "MSC-PF-23" = true := by native_decide
lemma inner_gray_admits_only_approved_services : checks "MSC-PF-5" = true := by native_decide
lemma outer_gray_checks_source_interface : checks "MSC-PF-18" = true := by native_decide
lemma outer_black_uses_intended_peers : checks "MSC-OR-10" = true := by native_decide
lemma selected_outer_ipv4_options_are_dropped : checkIPv4Options → checks "MSC-PF-10" = true := by native_decide
lemma outer_gray_denies_unapproved_traffic : registeredPanel → checks "MSC-PF-20" = true := by native_decide
lemma gray_management_requires_management_interface : registeredPanel → checks "MSC-PF-27" = true := by native_decide

run_cmd do Lean.logInfo m!"TDN_END {← IO.monoNanosNow}"

end TDN.Benchmark.ServicePolicy
