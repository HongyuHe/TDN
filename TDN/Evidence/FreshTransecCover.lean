import TDN.Import.Command
import TDN.Targets.Transec

namespace TDN.Imported.FreshTransecCover
open Targets CoverTraffic
set_option maxRecDepth 100000
set_option maxHeartbeats 0

/-- Parameters come from both recorded sender invocations and their settings readback. -/
def sender : CoverTraffic.Config := ⟨512, 24, 64, 20000000⟩
lemma valid_parameters : sender.Valid := by decide

tdn_data installations : List CoverInstallation from "../../evidence/lean/FreshTransecCover.json" ["TDN.Imported.FreshTransecCover.installations"]

/-- The declared laboratory scope selects the MACsec-to-firewall objective. -/
theorem selected_cover_enablement :
    msc_transec_conditions (installations.map CoverInstallation.use) := by
  exact (transec_conditions_from_cover_installations installations (by decide) (by decide)).1

/-- Arbitrary arrivals and link failures preserve the size and capacity guarantee. -/
theorem all_sender_executions_obey_size_and_capacity : ScheduledCoverGuarantee sender :=
  scheduled_cover_guarantee_from_parameters sender valid_parameters

/-- Every exported attempt is retained, including failed send calls. -/
tdn_data attemptsOA : List (Nat × Nat × Nat) from "../../evidence/lean/FreshTransecCover.json" ["TDN.Imported.FreshTransecCover.attemptsOA"]

theorem recorded_attemptsOA :
    ∀ row ∈ attemptsOA, row.1 = sender.recordBytes ∧
      row.2.1 ≤ sender.queueLimit ∧ row.2.2 ≤ 142957 := by decide
lemma recorded_attempt_countOA : attemptsOA.length = 1411 := by decide

/-- Every exported attempt is retained, including failed send calls. -/
tdn_data attemptsOB : List (Nat × Nat × Nat) from "../../evidence/lean/FreshTransecCover.json" ["TDN.Imported.FreshTransecCover.attemptsOB"]

theorem recorded_attemptsOB :
    ∀ row ∈ attemptsOB, row.1 = sender.recordBytes ∧
      row.2.1 ≤ sender.queueLimit ∧ row.2.2 ≤ 201497 := by decide
lemma recorded_attempt_countOB : attemptsOB.length = 1416 := by decide

end TDN.Imported.FreshTransecCover
