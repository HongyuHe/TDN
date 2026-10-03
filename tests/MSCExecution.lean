import TDN
open TDN.Network TDN.Network.Execution
open TDN.MSC.Execution TDN.MSC.ExecutionTrace

namespace MSCExecutionRegression

def redPacket : WirePacket Unit := (start "R_A1" "R_B1").packet
def innerPacket : WirePacket Unit :=
  ((model.forward "I_A1" "red" redPacket).map ForwardResult.packet).getD redPacket
def outerPacket : WirePacket Unit :=
  ((model.forward "O_A1" "gray" innerPacket).map ForwardResult.packet).getD redPacket

def changeObservation (node : String) (change : OperationalSnapshot → OperationalSnapshot) : Model String :=
  { model with observed := fun id =>
      (model.observed id).map (fun observation => if id == node then change observation else observation) }

example : (model.forward "I_A1" "red" redPacket).isSome = true := by decide
example : innerPacket.depth = 1 ∧ outerPacket.depth = 2 := by decide
example : (model.forward "O_B1" "black" outerPacket).isSome = true := by decide

example : (changeObservation "I_A1" (fun o => { o with states := some [] })).forward
    "I_A1" "red" redPacket = none := by decide
example : (changeObservation "I_A1" (fun o => { o with policies := some [] })).forward
    "I_A1" "red" redPacket = none := by decide
example : (changeObservation "I_A1" (fun o => { o with forwarding := some false })).forward
    "I_A1" "red" redPacket = none := by decide
example : (changeObservation "O_A1" (fun o => { o with routes := some [] })).forward
    "O_A1" "gray" innerPacket = none := by decide
example : (changeObservation "O_A1" (fun o => { o with policies := some [] })).forward
    "O_A1" "gray" innerPacket = none := by decide
example : (changeObservation "O_A1" (fun o => { o with states := some [] })).forward
    "O_A1" "gray" innerPacket = none := by decide
example : (changeObservation "O_B1" (fun o => { o with states := some [] })).forward
    "O_B1" "black" outerPacket = none := by decide

/-- A stale pinned template cannot fall back to another SA with the same
request ID and endpoints. The observed SPI participates in actual selection. -/
example : (changeObservation "I_A1" (fun o =>
    { o with policies := o.policies.map (fun ps => ps.map (fun p => { p with spi := 305419896 })) })).forward
    "I_A1" "red" redPacket = none := by decide

example : (changeObservation "I_A1" (fun o =>
    { o with states := o.states.map (fun states => states.map (fun state => { state with flags := 4 })) })).forward
    "I_A1" "red" redPacket = none := by decide
example : (changeObservation "O_B1" (fun o => { o with policies := some [] })).forward
    "O_B1" "black" outerPacket = none := by decide

def misbound : Model String := changeObservation "I_A1" fun observation =>
  { observation with
    states := observation.states.map (fun states => states.map (fun s => { s with reqid := 999 })),
    policies := observation.policies.map (fun policies => policies.map (fun p => { p with reqid := 999 })) }

example : misbound.forward "I_A1" "red" redPacket = none := by decide

example : (changeObservation "I_A1" (fun o =>
    { o with states := o.states.map (fun states => states.map (fun sa => { sa with algorithm := "cipher_null" })) })).forward
    "I_A1" "red" redPacket = none := by decide

/-- Spoofed source ranges fail the first inner's actual forwarding check. -/
example : model.forward "I_A1" "red"
    (.clear { source := hostAddress "R_A2", destination := hostAddress "R_B1",
              protocol := 1, bytes := 100 } (some ())) = none := by decide

/-- A legitimate source cannot redirect its data to the other security level. -/
example : model.forward "I_A1" "red"
    (.clear { source := hostAddress "R_A1", destination := hostAddress "R_B2",
              protocol := 1, bytes := 100 } (some ())) = none := by decide

/-- Delivery at an ordinary host cannot silently strip an IPsec wrapper. -/
example : model.deliver "R_B1" "red" innerPacket = none := by decide

/-- The source-policy certificate detects a widened incoming rule separately
from contract-equality checks. Removing that source condition cannot be hidden
by retaining its interface and IPsec requirements. -/
def widenedTable : TDN.MSC.ForwardTable :=
  let baseline := (TDN.MSC.forwardingTable? "I_B1").getD
    { device := "I_B1", defaultAccept := false, rules := [] }
  { baseline with rules := baseline.rules.map fun rule =>
      if rule.output == some "red" then { rule with source := none } else rule }

example : ¬ (∀ rule ∈ widenedTable.rules, TDN.MSC.optionalMatch rule.output "red" = true →
      rule.source = TDN.MSC.Isolation.requiredSource ⟨"I_B1", "red"⟩ .output) := by decide

end MSCExecutionRegression
