import TDN.Import.SnapshotLoader
import TDN.Requirements.MscFirewallWaypointingTheorems

namespace TDN.Benchmark.Attachments
set_option Elab.async false

def PublicAttachments (outers firewalls black : List String) (inside outside : List (String × String)) : Prop :=
  ∀ o ∈ outers, ∃ f ∈ firewalls, ∃ b ∈ black, (o,f) ∈ inside ∧ (f,b) ∈ outside

instance (outers firewalls black : List String) (inside outside : List (String × String)) :
    Decidable (PublicAttachments outers firewalls black inside outside) := by unfold PublicAttachments; infer_instance

theorem required_by_rg034 (outers firewalls black : List String) (inside outside : List (String × String))
    (edge gray external : String → String → Prop) (grayFw inner : String → Prop) (grayRequired : Bool)
    (claim : Requirements.graph_outer_firewall_placement true true grayRequired edge gray (· ∈ outers)
      (· ∈ firewalls) (· ∈ black) grayFw inner (fun a b => (a,b) ∈ inside) (fun a b => (a,b) ∈ outside) external) :
    PublicAttachments outers firewalls black inside outside := by
  intro o ho
  obtain ⟨f,b,hf,hb,hi,hh⟩ := claim.2.2.1 o ho
  exact ⟨f,hf,b,hb,hi,hh⟩

load_network_records outers : List String from "evidence.json" ["outer"]
load_network_records firewalls : List String from "evidence.json" ["firewall"]
load_network_records black : List String from "evidence.json" ["black"]
load_network_records inside : List (String × String) from "evidence.json" ["inside"]
load_network_records outside : List (String × String) from "evidence.json" ["outside"]

run_cmd do Lean.logInfo m!"TDN_BEGIN {← IO.monoNanosNow}"
example : PublicAttachments outers firewalls black inside outside := by native_decide
run_cmd do Lean.logInfo m!"TDN_END {← IO.monoNanosNow}"
end TDN.Benchmark.Attachments
