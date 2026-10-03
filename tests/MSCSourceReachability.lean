import TDN

namespace MSCSourceReachabilityRegression
open TDN.MSC TDN.MSC.Deployment TDN.MSC.SourceReachability
open TDN.Network TDN.Network.Execution
open TDN.MSC.Execution TDN.MSC.ExecutionTrace

def address (text : String) : UInt32 := (TDN.Network.ipv4? text).getD 0

def outbound : RoutedPacket :=
  { input := "gray", output := "black", source := address "10.100.1.2",
    destination := address "10.200.1.2", protocol := 50, outPolicy := some 201 }

example : knownSource "O_A1" "gray" (address "10.100.1.2") = true := by decide
example : decision .forward "O_A1" outbound = some true := by decide
example : knownSource "O_A1" "gray" (address "10.100.2.2") = false := by decide
example : decision .forward "O_A1" { outbound with source := address "10.100.2.2" } = some false := by decide
example : knownSource "O_A1" "black" (address "10.100.1.2") = false := by decide
example : decision .forward "O_A1" { outbound with input := "black" } = some false := by decide
example : knownSource "GF_A" "s1" (address "10.100.1.2") = true := by decide
example : knownSource "GF_A" "s2" (address "10.100.1.2") = false := by decide
example : decision .input "GF_A" { outbound with input := "s2" } = some false := by decide

/-- A reachable source can still be denied by a more selective peer policy.
The reachability property is a necessary condition, not an allow-all rule. -/
example : knownSource "O_A1" "gray" (address "10.100.1.77") = true := by decide
example : decision .forward "O_A1" { outbound with source := address "10.100.1.77" } = some false := by decide

def innerPacket : WirePacket Unit :=
  ((model.forward "I_A1" "red" (start "R_A1" "R_B1").packet).map ForwardResult.packet).getD
    (start "R_A1" "R_B1").packet

example : (model.forward "O_A1" "gray" innerPacket).isSome = true ∧
    knownSource "O_A1" "gray" innerPacket.header.source = true := by decide

end MSCSourceReachabilityRegression
