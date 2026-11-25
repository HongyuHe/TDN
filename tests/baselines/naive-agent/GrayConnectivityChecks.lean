import TDN.Import.SnapshotLoader
import TDN.Requirements.VerifiedGrayFirewallWaypointing

namespace TDN.Benchmark.GrayConnectivity
open TDN.Requirements.Msc
set_option Elab.async false

structure Region where
  firewall : String
  members : List String

load_network_records edges : List (String × String) from "evidence.json" ["edges"]
load_network_records inners : List String from "evidence.json" ["inners"]
load_network_records outers : List String from "evidence.json" ["outers"]
load_network_records firewalls : List String from "evidence.json" ["firewalls"]
load_network_records paths : List GrayPathWitness from "evidence.json" ["paths"]
load_network_records regions : List Region from "evidence.json" ["regions"]

def follows (links : List (String × String)) (start finish : String) : List String → Bool
  | [] => decide (start = finish)
  | next :: rest => links.contains (start, next) && follows links next finish rest

def validPath (links : List (String × String)) (start finish : String) : List String → Bool
  | [] => false
  | first :: rest => decide (first = start) && follows links first finish rest

lemma follows_sound {rel : String → String → Prop} {links : List (String × String)}
    (edge : ∀ a b, (a, b) ∈ links → rel a b) (start finish : String) (rest : List String)
    (ok : follows links start finish rest = true) : (start :: rest).IsChainFromTo rel start finish := by
  induction rest generalizing start with
  | nil =>
    have same : start = finish := by simpa [follows] using ok
    subst finish
    simp
  | cons next rest ih =>
    obtain ⟨adjacent, tail⟩ := Bool.and_eq_true_iff.mp ok
    exact List.IsChainFromTo.cons (edge _ _ (by simpa using adjacent)) (ih next tail)

lemma valid_path_sound {rel : String → String → Prop} {links : List (String × String)}
    (edge : ∀ a b, (a,b) ∈ links → rel a b) (start finish : String) (chain : List String)
    (ok : validPath links start finish chain = true) : chain.IsChainFromTo rel start finish := by
  cases chain with
  | nil => simp [validPath] at ok
  | cons first rest =>
    obtain ⟨start_ok, tail_ok⟩ := Bool.and_eq_true_iff.mp ok
    have same : first = start := by simpa using start_ok
    subst first
    exact follows_sound edge start finish rest tail_ok

def WitnessChecked (w : GrayPathWitness) : Prop :=
  w.firewall ∈ firewalls ∧ w.inner ∈ inners ∧ w.outer ∈ outers ∧
  validPath edges w.inner w.firewall w.toFirewall = true ∧
  validPath edges w.firewall w.outer w.fromFirewall = true

instance (w : GrayPathWitness) : Decidable (WitnessChecked w) := by unfold WitnessChecked; infer_instance

theorem matches_document_witness (topology : GrayTopology)
    (edge : ∀ a b, (a,b) ∈ edges → topology.edge a b)
    (inner : ∀ d ∈ inners, topology.inner d) (outer : ∀ d ∈ outers, topology.outer d)
    (firewall : ∀ d ∈ firewalls, topology.grayFirewall d)
    (w : GrayPathWitness) (checked : WitnessChecked w) : w.Checked topology := by
  obtain ⟨fw, i, o, first, second⟩ := checked
  exact ⟨firewall _ fw, inner _ i, outer _ o, valid_path_sound edge _ _ _ first, valid_path_sound edge _ _ _ second⟩

def IsolatedFromInners (r : Region) : Prop :=
  r.firewall ∈ firewalls ∧ r.firewall ∈ r.members ∧
  (∀ i ∈ inners, i ∉ r.members) ∧
  ∀ edge ∈ edges, edge.2 ∈ r.members → edge.1 ∈ r.members

instance (r : Region) : Decidable (IsolatedFromInners r) := by unfold IsolatedFromInners; infer_instance

lemma no_path_into_region (r : Region) (closed : IsolatedFromInners r) (i : String) (inner : i ∈ inners) :
    ¬Waypointing.ReachableByLinks (fun a b => (a,b) ∈ edges) i r.firewall := by
  obtain ⟨_, member, disjoint, backward⟩ := closed
  have backward_path : ∀ {a b : String}, Relation.ReflTransGen (fun x y => (x,y) ∈ edges) a b →
      b ∈ r.members → a ∈ r.members := by
    intro a b path
    induction path with
    | refl => exact fun h => h
    | tail _ edge ih => exact fun h => ih (backward _ edge h)
  exact fun path => disjoint i inner (backward_path path member)

run_cmd do Lean.logInfo m!"TDN_BEGIN {← IO.monoNanosNow}"

lemma captured_chains : ∀ w ∈ paths, WitnessChecked w := by native_decide

lemma captured_regions : ∀ r ∈ regions, IsolatedFromInners r := by native_decide

theorem captured_disconnections (r : Region) (listed : r ∈ regions) (i : String) (inner : i ∈ inners) :
    ¬ Waypointing.ReachableByLinks (fun a b => (a,b) ∈ edges) i r.firewall :=
  no_path_into_region r (captured_regions r listed) i inner

lemma every_firewall_connected : ∀ f ∈ firewalls, ∃ w ∈ paths, w.firewall = f := by native_decide

run_cmd do Lean.logInfo m!"TDN_END {← IO.monoNanosNow}"
end TDN.Benchmark.GrayConnectivity
