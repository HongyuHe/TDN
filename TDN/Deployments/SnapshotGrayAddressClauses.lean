import TDN.Import.SnapshotLoader
import TDN.Requirements.GraySubnetSeparationSpec
import TDN.Deployments.ProfileShared_Addressing
import TDN.Deployments.ProfileShared_DataPlane

namespace TDN.Deployments.ProfileShared_Addressing
set_option maxRecDepth 100000
set_option maxHeartbeats 0

theorem outer_accepted_addresses_share_full_level (rules : List PacketPolicy.Rule)
    (member : rules ∈ policies) (packet : PacketPolicy.Packet)
    (accepted : PacketPolicy.Accepts rules packet) :
    ∃ level, Addressing.Owns ranges packet.source level ∧
      Addressing.Owns ranges packet.destination level :=
  Requirements.accepted_named_peer_addresses_share_level ranges pairs rules
    peers_share_full_level (rules_name_intended_peers rules member) packet accepted

load_network_records grayFirewallDevices : List Nat from "../../data/evidence/SnapshotGrayAddressClauses.json" ["TDN.Deployments.ProfileShared_Addressing.grayFirewallDevices"]

def grayFirewallRules (device : Nat) : List PacketPolicy.Rule :=
  (DataPlaneForwarding.deviceAt ProfileShared_DataPlane.devices device).forwardRules

lemma gray_firewall_defaults : ∀ device ∈ grayFirewallDevices,
    (DataPlaneForwarding.deviceAt ProfileShared_DataPlane.devices device).forwardFallback = .deny := by native_decide

lemma gray_firewall_peer_rules : ∀ device ∈ grayFirewallDevices,
    ∀ rule ∈ grayFirewallRules device, rule.verdict = .allow → Requirements.RuleNamesPair pairs rule := by
  native_decide
theorem gray_firewall_rejects_cross_level_addresses (device : Nat)
    (member : device ∈ grayFirewallDevices) (packet : PacketPolicy.Packet)
    (sourceLevel destinationLevel : SecurityLevel)
    (source : Addressing.Owns ranges packet.source sourceLevel)
    (destination : Addressing.Owns ranges packet.destination destinationLevel)
    (different : sourceLevel ≠ destinationLevel) :
    Filter.evaluate ((grayFirewallRules device).map PacketPolicy.Rule.toFilter)
      (DataPlaneForwarding.deviceAt ProfileShared_DataPlane.devices device).forwardFallback packet = .deny := by
  rw [gray_firewall_defaults device member]
  exact Requirements.different_level_addresses_are_denied ranges pairs (grayFirewallRules device)
    ranges_separated peers_share_full_level (gray_firewall_peer_rules device member)
    packet sourceLevel destinationLevel source destination different

theorem both_gray_firewalls_allow_selected_peer_esp :
    PacketPolicy.Accepts (grayFirewallRules 2)
      { source := 174326018, destination := 180879618, ingress := "s1", egress := "g1", protocol := "esp", sourcePort := 0, destinationPort := 0,
        ipv4HeaderWords := 5, matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "NEW" } ∧
    PacketPolicy.Accepts (grayFirewallRules 3)
      { source := 180879618, destination := 174326018, ingress := "s1", egress := "g1", protocol := "esp", sourcePort := 0, destinationPort := 0,
        ipv4HeaderWords := 5, matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "NEW" } := by
  native_decide
end TDN.Deployments.ProfileShared_Addressing
