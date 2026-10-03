import TDN

/-! PF-9's address boundary and retained arrival-path regression cases. -/
namespace TDN.MSC.MulticastRegression
open TDN.Network (ipv4Multicast IPv4Header WirePacket)
open TDN.MSC.Execution
open TDN.MSC.Multicast

example : ipv4Multicast 0xdfffffff = false := by decide
example : ipv4Multicast 0xe0000000 = true := by decide
example : ipv4Multicast 0xefffffff = true := by decide
example : ipv4Multicast 0xf0000000 = false := by decide

def multicastHeader : IPv4Header :=
  { source := 0xac141501, destination := 0xe0000005, protocol := 89, bytes := 100 }

def multicastPacket : WirePacket Unit := .clear multicastHeader none

example : model.forward "O_A1" "black" multicastPacket = none :=
  outer_black_multicast_forward_rejected "O_A1" (by decide) multicastPacket (by decide)

example : model.deliver "O_A1" "black" multicastPacket = none :=
  outer_black_multicast_delivery_rejected "O_A1" (by decide) multicastPacket (by decide)

/-- Peer IKE remains a positive control on the same receiving interface. -/
example : model.inputFilter "O_A1" "black"
    { source := 0xac141501, destination := 0xac140b01, protocol := 17,
      destinationPort := 500, bytes := 100 } = true := by decide

/-- The generic matcher can accept multicast under a widened rule. The
rejection result therefore depends on the actual checked rule restrictions. -/
example : ForwardTable.accepts
    { device := "example", defaultAccept := false, rules := [{ input := some "black" }] }
    (packetView "black" "gray" multicastHeader none none) = true := by decide

end TDN.MSC.MulticastRegression
