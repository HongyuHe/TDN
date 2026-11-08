import TDN.Evidence.OuterGraySharedData

namespace TDN.Imported.OuterGrayShared
open Compliance Targets Targets.Complete OuterGrayNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma native_program_atoms_checked :
    ∀ iface ∈ records.inventory.ifaces, NativeProgramAtoms records.inventory iface := by exact of_decide_eq_true rfl

end TDN.Imported.OuterGrayShared
