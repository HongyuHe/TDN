import TDN
open TDN.Network TDN.Network.Execution TDN.Network.Protection
open TDN.MSC.Execution TDN.MSC.ExecutionTrace TDN.MSC.Protection

namespace MSCProtectionRegression

def root : WirePacket Unit := (start "R_A1" "R_B1").packet

def outerSA : XfrmState :=
  ((model.states "O_A1").find? (fun sa => sa.source == 0xac140b01)).getD
    { source := 0, destination := 0, spi := 0, reqid := 0, mode := "", protocol := "",
      algorithm := "", integrityBits := 0, replayWindow := 0, hardLifetimeSeconds := 0,
      udpEncapsulation := false, udpSourcePort := none, udpDestinationPort := none, tfcPadding := 0 }

/-- Two wrappers from an outer SA satisfy the old count bound but fail the
required order. Layer provenance and stack shape are separate obligations. -/
example : ((root.seal outerSA).seal outerSA).depth = 2 ∧
    layerLabels roleOfTag ((root.seal outerSA).seal outerSA) ≠ requiredStack ⟨"O_A1", "black"⟩ := by decide

/-- Every selected data direction reaches Black with the exact ordered stack. -/
example : ∀ choice ∈ witnessedPairs,
    let source := "R_" ++ choice.1 ++ choice.2.2
    let target := "R_" ++ choice.2.1 ++ choice.2.2
    let reached := run (start source target) ((dataCommands choice.1 choice.2.1 choice.2.2).take 6)
    reached.isSome = true ∧ reached.all (fun state =>
      decide (layerLabels roleOfTag state.packet = [some TDN.MSC.Role.outer, some .inner])) = true := by decide

/-- The permitted inner-IKE control has one outer layer and no Red payload. -/
example :
    let reached := run innerIKE
      [.wire ⟨"G_A1", "inner"⟩, .switch "outer", .wire ⟨"O_A1", "gray"⟩, .forward]
    reached.isSome = true ∧ reached.all (fun state => state.packet.message.isNone &&
      decide (layerLabels roleOfTag state.packet = [some TDN.MSC.Role.outer])) = true := by decide

/-- The inbound rule's interface/tag signature alone permits this abstract
combination. Its source/destination selectors exclude an outgoing policy. -/
def inboundRule : TDN.MSC.ForwardRule :=
  (((TDN.MSC.forwardingTable? "I_A1").map TDN.MSC.ForwardTable.rules).getD []).find?
    (fun rule => rule.output == some "red") |>.getD {}

example : ruleSignature inboundRule "gray" "red" (some 101) (some 101) = true ∧
    outputTagPossible "I_A1" inboundRule (some 101) = false := by decide

example : requiredStack ⟨"I_A1", "gray"⟩ ≠
    transformed (fun _ => some TDN.MSC.Role.outer) none (some 101) (requiredStack ⟨"I_A1", "red"⟩) := by decide

end MSCProtectionRegression
