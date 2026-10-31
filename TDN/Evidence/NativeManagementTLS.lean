import TDN.Import.Command
import TDN.Evidence.SupplementalTypes

namespace TDN.Imported.NativeManagementTLS

tdn_data samples : List Evidence.TLSSample from "../../evidence/lean/NativeManagementTLS.json" ["TDN.Imported.NativeManagementTLS.samples"]

theorem recorded_tls_outcomes : Evidence.TLSRecordedOutcomes samples := by unfold Evidence.TLSRecordedOutcomes samples; decide

theorem both_test_branches_present : (∃ s ∈ samples, s.clientCertificate = true) ∧ (∃ s ∈ samples, s.clientCertificate = false) := by unfold samples; decide

end TDN.Imported.NativeManagementTLS
