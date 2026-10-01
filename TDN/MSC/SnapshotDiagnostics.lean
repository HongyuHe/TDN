import TDN.MSC.Topology
import TDN.MSC.HistoricalDeployment

/-!
# Optional full-export and management diagnostics

Import this module explicitly to check historical totals, management topology,
and the full observation/probe report. The required `TDN`/`TDN.MSC` imports do
not import this module. None of these diagnostics is a premise of the retained
MSC data-path proofs or a condition for the independent review verdict.
-/
namespace TDN.MSC
open HistoricalDeployment

/-- Optional diagnostics read a separate full-export data module. Required
proofs never import that module or require its regeneration to succeed. -/
def managementDomain (id : String) : Option String :=
  (HistoricalDeployment.devices.find? (fun d => d.id == id)).bind Device.managementDomain

def managementEdges : List (String × String) :=
  (HistoricalDeployment.links.filter (fun l => l.zone == .management)).flatMap
    (fun l => [(l.a, l.b), (l.b, l.a)])

theorem device_count : devices.length = 35 := by decide

theorem link_count : links.length = 44 := by decide

theorem management_edges_preserve_domain : ∀ e ∈ managementEdges,
    managementDomain e.1 = managementDomain e.2 := by decide

theorem no_cross_domain_management_cable_path (a b : String)
    (different : managementDomain a ≠ managementDomain b) :
    ¬ Walk managementEdges a b := by
  intro path
  exact different (walk_preserves managementDomain managementEdges
    management_edges_preserve_domain path)

theorem inner_outer_admin_separate : ¬ Walk managementEdges "AW_A1" "O_A1" :=
  no_cross_domain_management_cable_path _ _ (by decide)

theorem sampled_devices_running : ∀ o ∈ observations,
    o.running = true ∧ o.errors = [] ∧ o.deployedSpecHash = specHash := by decide

theorem sampled_probe_report_passed : sampledChecksPassed = true ∧ probeCount = 273 := by
  decide

end TDN.MSC
