import TDN.Requirements.PacketEnclaveIsolation
import TDN.Models.ReassemblyBufferDomainSafety

namespace TDN.Requirements

def msc_same_domain_plaintext_reception (c : DataPlaneForwarding.DataPlaneModel) (sources : List Nat) : Prop :=
  ∀ start finish actions sourceDomain destinationDomain,
    RedPayloadOrigin c sources start → c.ifaceSecurityDomain start.iface = some sourceDomain →
    (DataPlaneForwarding.lts c).MTr start actions finish → finish.datapathStage = .received →
    finish.frame.encapLayerIds = [] →
    c.ifaceSecurityDomain finish.iface = some destinationDomain → sourceDomain = destinationDomain

theorem received_domain_from_local_checks
    (c : DataPlaneForwarding.DataPlaneModel) (expectedEncapStack : Nat → List Nat) (allowed : Nat → Prop)
    (sources : List Nat) (domain : Nat)
    (conditions : DataPlaneForwarding.LocalDomainConditions c expectedEncapStack allowed)
    (sourceCheck : ∀ iface ∈ sources, c.ifaceSecurityDomain iface = some domain →
      expectedEncapStack iface = [] ∧ c.canOriginateTraffic iface ∧ allowed iface)
    (recipientCheck : ∀ iface, allowed iface →
      c.ifaceSecurityDomain iface = none ∨ c.ifaceSecurityDomain iface = some domain)
    {start finish : DataPlaneForwarding.State} {actions : List DataPlaneForwarding.Action} {recipient : Nat}
    (origin : RedPayloadOrigin c sources start)
    (domainAtSource : c.ifaceSecurityDomain start.iface = some domain)
    (run : (DataPlaneForwarding.lts c).MTr start actions finish)
    (received : finish.datapathStage = .received)
    (recipientAtEnd : c.ifaceSecurityDomain finish.iface = some recipient) :
    domain = recipient := by
  have initial := red_origin_has_domain_invariant c expectedEncapStack allowed sources domain sourceCheck
    origin domainAtSource
  have preserved := DataPlaneForwarding.forwarding_preserves_enclave_invariant c expectedEncapStack allowed
    conditions run initial
  simp only [DataPlaneForwarding.DomainInvariant, received] at preserved
  rcases recipientCheck finish.iface preserved.2 with absent | same
  · simp [recipientAtEnd] at absent
  · exact Option.some.inj (same.symm.trans recipientAtEnd)

structure FragmentArrival where
  start : DataPlaneForwarding.State
  finish : DataPlaneForwarding.State
  actions : List DataPlaneForwarding.Action

def ArrivedFragment {Header Byte : Type}
    (c : DataPlaneForwarding.DataPlaneModel) (sources : List Nat) (recipientIface : Nat)
    (arrival : FragmentArrival)
    (piece : Fragmentation.Fragment Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat)) : Prop :=
  RedPayloadOrigin c sources arrival.start ∧
  (DataPlaneForwarding.lts c).MTr arrival.start arrival.actions arrival.finish ∧
  arrival.finish.datapathStage = .received ∧ arrival.finish.frame.encapLayerIds = [] ∧
  arrival.finish.iface = recipientIface ∧
  ∀ byte ∈ piece.bytes,
    c.ifaceSecurityDomain arrival.start.iface = some byte.domain ∧
    byte.packet = arrival.start.frame.payload

lemma arrived_fragment_bytes_match_recipient {Header Byte : Type}
    (c : DataPlaneForwarding.DataPlaneModel) (sources : List Nat)
    (reception : msc_same_domain_plaintext_reception c sources)
    (recipientIface destinationDomain : Nat)
    (recipient : c.ifaceSecurityDomain recipientIface = some destinationDomain)
    (arrival : FragmentArrival)
    (piece : Fragmentation.Fragment Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (arrived : ArrivedFragment c sources recipientIface arrival piece) :
    ReassemblyOrigins.PieceSafe (fun byte => byte.domain = destinationDomain) piece := by
  obtain ⟨origin, run, received, plain, iface, provenance⟩ := arrived
  intro byte member
  have source := (provenance byte member).1
  exact reception arrival.start arrival.finish arrival.actions byte.domain destinationDomain
    origin source run received plain (iface ▸ recipient)

theorem reassembled_delivery_domain_from_checked_reception {Header Byte : Type}
    [DecidableEq Header]
    (c : DataPlaneForwarding.DataPlaneModel) (sources : List Nat)
    (reception : msc_same_domain_plaintext_reception c sources)
    (recipientIface destinationDomain : Nat)
    (recipient : c.ifaceSecurityDomain recipientIface = some destinationDomain)
    {actions : List ReassemblyOrigins.Action}
    {pieces : List (Fragmentation.Fragment Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {header : Header}
    {result : Fragmentation.Datagram Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat)}
    (run : (ReassemblyOrigins.system
      (ArrivedFragment c sources recipientIface)).MTr [] actions pieces)
    (accepted : ReassemblyOrigins.assemble header pieces = some result) :
    ∀ byte ∈ result.bytes, byte.domain = destinationDomain :=
  ReassemblyOrigins.every_reassembly_history_preserves_byte_safety
    (ArrivedFragment c sources recipientIface) (fun byte => byte.domain = destinationDomain)
    (arrived_fragment_bytes_match_recipient c sources reception recipientIface destinationDomain recipient)
    run accepted

end TDN.Requirements
