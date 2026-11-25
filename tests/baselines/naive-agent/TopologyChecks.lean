import TDN.Import.SnapshotLoader
import TDN.Requirements.MscFirewallWaypointingTheorems

namespace TDN.Benchmark.Topology
set_option Elab.async false
set_option maxRecDepth 100000

load_network_records deviceCount : Nat from "evidence.json" ["count"]
abbrev Node := Fin deviceCount

load_network_records edges : List (Node × Node) from "evidence.json" ["edges"]
load_network_records grayEdges : List (Node × Node) from "evidence.json" ["gray_edges"]
load_network_records inside : List (Node × Node) from "evidence.json" ["inside"]
load_network_records outside : List (Node × Node) from "evidence.json" ["outside"]
load_network_records outers : List Node from "evidence.json" ["outer"]
load_network_records inners : List Node from "evidence.json" ["inner"]
load_network_records black : List Node from "evidence.json" ["black"]
load_network_records firewalls : List Node from "evidence.json" ["firewall"]
load_network_records grayFirewalls : List Node from "evidence.json" ["gray_fw"]
load_network_records grayFirewallRequired : Bool from "evidence.json" ["gray_firewall_required"]
load_network_records regions : List Nat from "evidence.json" ["outer_sides"]
load_network_records grayRegions : List Nat from "evidence.json" ["gray_sides"]
load_network_records levels : List Nat from "evidence.json" ["levels"]
load_network_records grayPaths : List (Node × List Node) from "evidence.json" ["gray_paths"]

def edge (a b : Node) := (a,b) ∈ edges
def grayEdge (a b : Node) := (a,b) ∈ grayEdges
def firewall (a : Node) := a ∈ firewalls
def side (a : Node) := regions[a.val]!
def graySide (a : Node) := grayRegions[a.val]!
def level (a : Node) := levels[a.val]!

def grayDestinations : List Node := if grayFirewallRequired then grayFirewalls else inners

def reachesGrayDevice (start : Node) : List Node → Bool
  | [] => grayDestinations.contains start
  | next :: tail => grayEdges.contains (start,next) && reachesGrayDevice next tail

private theorem gray_path_sound (start : Node) (path : List Node) (ok : reachesGrayDevice start path = true) :
    ∃ g ∈ grayDestinations, Relation.ReflTransGen grayEdge start g := by
  induction path generalizing start with
  | nil => exact ⟨start,by simpa [reachesGrayDevice] using ok,.refl⟩
  | cons v tail ih =>
    obtain ⟨edgeOK, rest⟩ := Bool.and_eq_true_iff.mp ok
    obtain ⟨g, member, walk⟩ := ih v rest
    exact ⟨g,member,(Relation.ReflTransGen.single (by simpa [grayEdge] using edgeOK : grayEdge start v)).trans walk⟩

run_cmd do Lean.logInfo m!"TDN_BEGIN {← IO.monoNanosNow}"

lemma attached : ∀ a b : Node, (a,b) ∈ inside ∨ (a,b) ∈ outside ∨ False → edge a b := by
  unfold edge
  native_decide

lemma publicPlacement : ∀ o ∈ outers, ∃ f ∈ firewalls, ∃ b ∈ black, (o,f) ∈ inside ∧ (f,b) ∈ outside := by
  native_decide

lemma grayPathsPresent : ∀ o ∈ outers, ∃ path ∈ grayPaths, path.1 = o ∧ reachesGrayDevice o path.2 = true := by
  native_decide

lemma cut : ∀ a b : Node, edge a b → ¬ firewall a → ¬ firewall b → side a = side b := by
  unfold edge firewall side
  native_decide

lemma clear : ∀ o ∈ outers, ¬ firewall o := by unfold firewall; native_decide

lemma separated : ∀ o ∈ outers, ∀ b ∈ black, side o ≠ side b := by unfold side; native_decide

theorem current_outer_placement : Requirements.graph_outer_firewall_placement true true grayFirewallRequired edge
    (Relation.ReflTransGen grayEdge) (· ∈ outers) firewall (· ∈ black) (· ∈ grayFirewalls) (· ∈ inners)
    (fun a b => (a,b) ∈ inside) (fun a b => (a,b) ∈ outside) (fun _ _ => False) := by
  apply Requirements.outer_firewall_placement_from_local_checks side (fun _ => rfl)
  · exact fun a b h => Relation.ReflTransGen.single (attached a b h)
  · intro o listed
    obtain ⟨f,hf,b,hb,hi,ho⟩ := publicPlacement o listed
    exact ⟨f,b,hf,hb,hi,ho⟩
  · have reaches : ∀ o ∈ outers, ∃ dest ∈ grayDestinations, Relation.ReflTransGen grayEdge o dest := by
      intro o listed
      obtain ⟨path, _, _, ok⟩ := grayPathsPresent o listed
      exact gray_path_sound o path.2 ok
    by_cases required : grayFirewallRequired = true <;> simpa [grayDestinations, required] using reaches
  · exact fun _ => cut
  · exact fun _ => clear
  · exact fun _ o b ho hb => separated o ho b hb

lemma grayCut : ∀ a b : Node, grayEdge a b → a ∉ grayFirewalls → b ∉ grayFirewalls → graySide a = graySide b := by
  unfold grayEdge graySide
  native_decide

lemma innerClear : ∀ a ∈ inners, a ∉ grayFirewalls := by native_decide

lemma crossLevel : ∀ a ∈ inners, ∀ b ∈ inners, level a ≠ level b → graySide a ≠ graySide b := by
  unfold level graySide
  native_decide

theorem current_gray_waypointing (a b : Node) (ha : a ∈ inners) (hb : b ∈ inners) (different : level a ≠ level b) :
    ¬ Waypointing.ReachableWithoutWaypoint grayEdge (· ∈ grayFirewalls) a b :=
  Waypointing.waypointing_of_edge_invariant grayEdge (· ∈ grayFirewalls) graySide grayCut
    (innerClear a ha) (crossLevel a ha b hb different)

run_cmd do Lean.logInfo m!"TDN_END {← IO.monoNanosNow}"
end TDN.Benchmark.Topology
