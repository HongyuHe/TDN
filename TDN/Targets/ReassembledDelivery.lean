import TDN.Targets.DeliveryIsolation
import TDN.Semantics.ReassemblyOrigins

namespace TDN.Targets

def msc_same_domain_plaintext_reception (c : Execution.Config) (sources : List Nat) : Prop :=
  ∀ start finish actions sourceDomain recipientDomain,
    RedPayloadOrigin c sources start → c.recipientDomain start.port = some sourceDomain →
    (Execution.lts c).MTr start actions finish → finish.phase = .received →
    finish.frame.tags = [] →
    c.recipientDomain finish.port = some recipientDomain → sourceDomain = recipientDomain

theorem received_domain_from_local_checks
    (c : Execution.Config) (layout : Nat → List Nat) (allowed : Nat → Prop)
    (sources : List Nat) (domain : Nat)
    (conditions : Execution.LocalDomainConditions c layout allowed)
    (sourceCheck : ∀ port ∈ sources, c.recipientDomain port = some domain →
      layout port = [] ∧ c.payloadOrigin port ∧ allowed port)
    (recipientCheck : ∀ port, allowed port →
      c.recipientDomain port = none ∨ c.recipientDomain port = some domain)
    {start finish : Execution.State} {actions : List Execution.Action} {recipient : Nat}
    (origin : RedPayloadOrigin c sources start)
    (domainAtSource : c.recipientDomain start.port = some domain)
    (run : (Execution.lts c).MTr start actions finish)
    (received : finish.phase = .received)
    (recipientAtEnd : c.recipientDomain finish.port = some recipient) :
    domain = recipient := by
  have initial := red_origin_has_domain_invariant c layout allowed sources domain sourceCheck
    origin domainAtSource
  have preserved := Execution.execution_preserves_domain_invariant c layout allowed
    conditions run initial
  simp only [Execution.DomainInvariant, received] at preserved
  rcases recipientCheck finish.port preserved.2 with absent | same
  · simp [recipientAtEnd] at absent
  · exact Option.some.inj (same.symm.trans recipientAtEnd)

structure FragmentArrival where
  start : Execution.State
  finish : Execution.State
  actions : List Execution.Action

def ArrivedFragment {Header Byte : Type}
    (c : Execution.Config) (sources : List Nat) (recipientPort : Nat)
    (arrival : FragmentArrival)
    (piece : Fragmentation.Fragment Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat)) : Prop :=
  RedPayloadOrigin c sources arrival.start ∧
  (Execution.lts c).MTr arrival.start arrival.actions arrival.finish ∧
  arrival.finish.phase = .received ∧ arrival.finish.frame.tags = [] ∧
  arrival.finish.port = recipientPort ∧
  ∀ byte ∈ piece.bytes,
    c.recipientDomain arrival.start.port = some byte.domain ∧
    byte.packet = arrival.start.frame.payload

lemma arrived_fragment_bytes_match_recipient {Header Byte : Type}
    (c : Execution.Config) (sources : List Nat)
    (reception : msc_same_domain_plaintext_reception c sources)
    (recipientPort recipientDomain : Nat)
    (recipient : c.recipientDomain recipientPort = some recipientDomain)
    (arrival : FragmentArrival)
    (piece : Fragmentation.Fragment Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (arrived : ArrivedFragment c sources recipientPort arrival piece) :
    ReassemblyOrigins.PieceSafe (fun byte => byte.domain = recipientDomain) piece := by
  obtain ⟨origin, run, received, plain, port, provenance⟩ := arrived
  intro byte member
  have source := (provenance byte member).1
  exact reception arrival.start arrival.finish arrival.actions byte.domain recipientDomain
    origin source run received plain (port ▸ recipient)

theorem reassembled_delivery_domain_from_checked_reception {Header Byte : Type}
    [DecidableEq Header]
    (c : Execution.Config) (sources : List Nat)
    (reception : msc_same_domain_plaintext_reception c sources)
    (recipientPort recipientDomain : Nat)
    (recipient : c.recipientDomain recipientPort = some recipientDomain)
    {actions : List ReassemblyOrigins.Action}
    {pieces : List (Fragmentation.Fragment Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {header : Header}
    {result : Fragmentation.Datagram Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat)}
    (run : (ReassemblyOrigins.system
      (ArrivedFragment c sources recipientPort)).MTr [] actions pieces)
    (accepted : ReassemblyOrigins.assemble header pieces = some result) :
    ∀ byte ∈ result.bytes, byte.domain = recipientDomain :=
  ReassemblyOrigins.every_reassembly_history_preserves_byte_safety
    (ArrivedFragment c sources recipientPort) (fun byte => byte.domain = recipientDomain)
    (arrived_fragment_bytes_match_recipient c sources reception recipientPort recipientDomain recipient)
    run accepted

end TDN.Targets
