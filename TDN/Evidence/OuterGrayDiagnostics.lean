import TDN.Import.Command
import TDN.Semantics.Execution
import TDN.Targets.CompleteSpecifications

namespace TDN.Imported.OuterGrayDiagnostics
open Compliance

tdn_data devices : List Execution.DeviceData
  from "../../data/evidence/continuation/v31-native-baseline-options-refreshed-multi_protocol_execution.json" ["devices"]

def ike : List UInt8 := List.replicate 17 0 ++ [32] ++ List.replicate 9 0 ++ [28]

def reply : PacketPolicy.Packet :=
  { source := 174326018, destination := 180879618, protocol := "udp",
    ingress := "gray", egress := "black", sourcePort := 500, destinationPort := 9999,
    ipv4HeaderWords := 5, inboundPolicies := [], outboundPolicies := [201],
    connectionState := "new", payloadBytes := some ike, networkBytes := some 56,
    ipv4FragmentOffset := some 0, hopLimit := 64 }

def serviceCollision : PacketPolicy.Packet :=
  { reply with sourcePort := 1812, destinationPort := 500 }

lemma reply_is_IKE : PacketIKE reply := by decide

lemma reply_is_denied_by_Outer_A1_forward_program :
    Filter.evaluate ((Execution.deviceAt devices 16).forwardRules.map PacketPolicy.Rule.toFilter)
      (Execution.deviceAt devices 16).forwardFallback reply = .deny := by decide

lemma service_collision_is_IKE : PacketIKE serviceCollision := by decide

lemma service_collision_is_admitted_by_Outer_A1_forward_program :
    Filter.evaluate ((Execution.deviceAt devices 16).forwardRules.map PacketPolicy.Rule.toFilter)
      (Execution.deviceAt devices 16).forwardFallback serviceCollision = .allow := by decide

lemma service_collision_previously_guessed_authentication :
    PacketPortService serviceCollision = "authentication" := by decide

lemma service_collision_is_classified_as_IKE_control :
    PacketService serviceCollision = "ike" ∧ PacketClass serviceCollision = .control := by decide

end TDN.Imported.OuterGrayDiagnostics
