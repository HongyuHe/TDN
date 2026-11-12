import TDN.Models.UniformStackDeviceReplies
import TDN.Models.DelayedPacketReplySafety

namespace UniformResponseRegression
open TDN TDN.DataPlaneForwarding

/-- A component with differently protected interfaces cannot use the uniform shortcut. -/
example : ¬ UniformResponseRegions.TableDrivenUniform []
    [⟨1, "red", [], false⟩, ⟨1, "black", [2, 1], false⟩] [1] := by
  unfold UniformResponseRegions.TableDrivenUniform
  native_decide
/-- Multiple interfaces in the same region pass without assuming response headers. -/
example : UniformResponseRegions.TableDrivenUniform []
    [⟨1, "left", [2, 1], false⟩, ⟨1, "right", [2, 1], false⟩] [1] := by
  unfold UniformResponseRegions.TableDrivenUniform
  native_decide
/-- Retained context selection uses an actually stored state. -/
example (network : Cslib.LTS Nat Unit) :
    HistoricalResponses.Step network ⟨20, [7, 10]⟩ .selectRetained ⟨7, [7, 10]⟩ :=
  .select (by simp)

/-- A saved unsafe packet cannot be hidden by a safe current packet. -/
example : ¬ HistoricalResponses.Safe (fun value : Nat => value ≤ 10) ⟨7, [20]⟩ := by
  simp [HistoricalResponses.Safe]

end UniformResponseRegression
