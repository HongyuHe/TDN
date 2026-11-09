import TDN.Deployments.MtuSizing_Path

namespace TDN.Deployments.MtuSizing_Records
open Compliance Requirements OuterToGray_DeviceModel PacketSource

structure CapturedSizingFrame where
  id : String
  iface : Nat
  interface : String
  bytes : List UInt8
  source : Nat
  destination : Nat
  protocol : Nat
  networkBytes : Nat
  headerBytes : Nat
  fragmentOffset : Nat
  moreFragments : Bool
  dontFragment : Bool
  outboundIndex : Option Nat
  inboundIndex : Option Nat


def CapturedSizingFrame.Checked (frame : CapturedSizingFrame) (records : Records)
    (installations : List PublicSARecord) (roles : List SizingRole) : Prop :=
  frame.iface ∈ records.inventory.ifaces ∧ records.ifaceName frame.iface = frame.interface ∧
  frame.bytes.length = 14 + frame.networkBytes ∧ field frame.bytes 12 2 = 2048 ∧
  frame.bytes[14]?.map (fun byte => byte.toNat / 16) = some 4 ∧
  frame.bytes[14]?.map (fun byte => byte.toNat % 16 * 4) = some frame.headerBytes ∧
  field frame.bytes 16 2 = frame.networkBytes ∧ field frame.bytes 23 1 = frame.protocol ∧
  field frame.bytes 26 4 = frame.source ∧ field frame.bytes 30 4 = frame.destination ∧
  field frame.bytes 20 2 % 8192 * 8 = frame.fragmentOffset ∧
  (field frame.bytes 20 2 / 8192 % 2 = 1 ↔ frame.moreFragments = true) ∧
  (field frame.bytes 20 2 / 16384 % 2 = 1 ↔ frame.dontFragment = true) ∧
  frame.networkBytes ≤ sourceMtu roles frame.iface ∧
  (frame.protocol = 50 → frame.fragmentOffset = 0 ∧ frame.moreFragments = false ∧
    ∃ outbound ∈ installations, ∃ inbound ∈ installations,
      installations[frame.outboundIndex.getD installations.length]? = some outbound ∧
      installations[frame.inboundIndex.getD installations.length]? = some inbound ∧
      outbound.installation.direction = .outbound ∧ inbound.installation.direction = .inbound ∧
      outbound.materialReference = inbound.materialReference ∧
      outbound.installation.association.sender = frame.source ∧
      outbound.installation.association.receiver = frame.destination ∧
      outbound.installation.association.spi = field frame.bytes (14 + frame.headerBytes) 4 ∧
      SAWireKey inbound.installation.association = SAWireKey outbound.installation.association)

instance (frame : CapturedSizingFrame) (records : Records) (installations : List PublicSARecord)
    (roles : List SizingRole) : Decidable (frame.Checked records installations roles) := by
  unfold CapturedSizingFrame.Checked
  infer_instance


def SizingPath.oversizeRequest (sample : SizingPath) (bytes : Nat) (df : Bool) : Request :=
  let application : List UInt8 := List.replicate (bytes - 28) 165
  { sample.flow.request with
    body := .datagram { sample.template with
      protocol := "icmp", sourcePort := 0, destinationPort := 0, icmpType := 8, icmpCode := 0,
      payloadBytes := some application }
    application := application, transportHeaderBytes := 8, mode := .datagram df }


def SizingPath.oversizeHeader (sample : SizingPath) (bytes : Nat) : PacketPolicy.Packet :=
  { sample.header with
    protocol := "icmp", sourcePort := 0, destinationPort := 0, icmpType := 8, icmpCode := 0,
    payloadBytes := some (List.replicate (bytes - 28) 165), networkBytes := some bytes, hopLimit := 63 }


def SizingPath.oversizeRouted (sample : SizingPath) (records : Records) (bytes : Nat) : MultiProtocolForwarding.State :=
  { sample.routed records with
    frame := {
      body := .datagram (sample.oversizeHeader bytes)
      payload := PayloadCode (List.replicate (bytes - 28) 165), originDomain := sample.flow.domain } }


def emittedFragmentCount (outcome : Outcome) : Nat := match outcome with
  | .error _ => 0
  | .emitted datagrams => (datagrams.map (fun datagram => datagram.fragments.length)).sum

end TDN.Deployments.MtuSizing_Records
