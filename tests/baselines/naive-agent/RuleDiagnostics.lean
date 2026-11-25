import TDN.Import.SnapshotLoader
import TDN.Requirements.DoubleEncryptionOnBlackLinks
import TDN.Models.IpHeaderAclGuards

/-! Locate failed premises in the unchanged snapshot checks. The resulting JSON
is diagnostic output; separate positive theorem attempts verify each reported failure. -/
namespace TDN.BlindDiagnostics
open DataPlaneForwarding PacketPolicy
load_network_records devices : List DeviceData from "input.json" ["devices"]
load_network_records ifaces : List IfaceData from "input.json" ["ports"]
load_network_records vpnIndices : List Nat from "input.json" ["vpnIndices"]
load_network_records outerIndices : List Nat from "input.json" ["outerIndices"]

def forwardRuleHolds (index ordinal : Nat) : Bool :=
  let device := deviceAt devices index
  match device.forwardRules[ordinal]? with
  | none => false
  | some rule => decide (∀ entry ∈ ({} : IfaceData) :: ifaces,
      ∀ output ∈ ({} : IfaceData) :: ifaces,
      entry.owner = index → output.owner = index →
      ∀ auth ∈ possibleAuthentications device entry,
        rule.verdict = .allow → RecordRuleCheck entry output device auth rule)

def diagnostics : Lean.Json := Id.run do
  let mut result : Array Lean.Json := #[]
  for index in List.range devices.length do
    let device := deviceAt devices index
    for ordinal in List.range device.forwardRules.length do
      if !forwardRuleHolds index ordinal then
        result := result.push (Lean.Json.mkObj [("kind", Lean.toJson "forward"),
          ("deviceIndex", Lean.toJson index), ("ordinal", Lean.toJson ordinal),
          ("chain", Lean.toJson "FORWARD")])
    if index ∈ vpnIndices then
      for (chain, rules) in [("INPUT", device.inputRules), ("FORWARD", device.forwardRules), ("OUTPUT", device.outputRules)] do
        for (rule, ordinal) in rules.zipIdx do
          if rule.verdict == .allow && !decide (ProtocolGuard ["tcp", "udp", "esp", "icmp"] rule) then
            result := result.push (Lean.Json.mkObj [("kind", Lean.toJson "protocol"),
              ("deviceIndex", Lean.toJson index), ("ordinal", Lean.toJson ordinal),
              ("chain", Lean.toJson chain)])
          if index ∈ outerIndices && chain != "OUTPUT" && rule.verdict == .allow &&
              !decide (UnicastGuard "black" 3758096384 4026531839 rule) then
            result := result.push (Lean.Json.mkObj [("kind", Lean.toJson "unicast"),
              ("deviceIndex", Lean.toJson index), ("ordinal", Lean.toJson ordinal),
              ("chain", Lean.toJson chain)])
  return Lean.toJson result

#eval IO.println diagnostics.compress
end TDN.BlindDiagnostics
