import TDN.Evidence.BoundaryHookCounterexamples
import TDN.Targets.NativeBoundarySpecification

namespace TDN.Imported.BoundaryICMPMetadataCounterexample
open Compliance BoundaryHookCounterexamples

tdn_data packet : PacketPolicy.Packet from "../../data/evidence/continuation/BoundaryICMPMetadataCounterexample.json" ["packet"]

lemma raw_ICMP_rule_does_not_constrain_unused_ports :
    Filter.evaluate (innerPolicy.rules.map PacketPolicy.Rule.toFilter)
      innerPolicy.defaultVerdict packet = .allow := by
  exact of_decide_eq_true rfl

lemma source_and_destination_transport_fields_are_noncanonical :
    packet.sourcePort ≠ 0 ∧ packet.destinationPort ≠ 0 := by decide

lemma no_decoded_transport_has_these_unused_port_fields (header payload : List UInt8) :
    ¬ PacketSource.TransportHeaderMatches packet header payload := by
  intro decoded
  rcases decoded with udp | tcp | control
  · simp [packet] at udp
  · simp [packet] at tcp
  · simp [packet] at control

lemma ICMP_service_lookup_has_no_transport_port :
    TransportServicePort packet true = 0 ∧ TransportServicePort packet false = 0 := by decide

end TDN.Imported.BoundaryICMPMetadataCounterexample
