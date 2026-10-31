import TDN.Import.Command
import TDN.Evidence.SupplementalTypes

namespace TDN.Imported.Management

tdn_data samples : List Evidence.TLSSample from "../../evidence/lean/Management.json" ["TDN.Imported.Management.samples"]

theorem recorded_tls_outcomes : Evidence.TLSRecordedOutcomes samples := by unfold Evidence.TLSRecordedOutcomes samples; decide

theorem both_test_branches_present : (∃ s ∈ samples, s.clientCertificate = true) ∧ (∃ s ∈ samples, s.clientCertificate = false) := by unfold samples; decide

end TDN.Imported.Management
