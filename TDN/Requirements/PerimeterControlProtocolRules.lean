import TDN.Requirements.DerivePerimeterContext

namespace TDN.Requirements.Msc
open Compliance

structure BoundaryControlFlow where
  device : String
  interface : String
  nativeName : String
  direction : Direction
  hook : PacketProcessing.Hook
  source : Nat
  destination : Nat
  protocol : String
  deriving DecidableEq

def BoundaryControlFlow.Matches (record : BoundaryControlFlow)
    (device : String) (packet : PacketPolicy.Packet) : Prop :=
  record.device = device ∧ packet.protocol = record.protocol ∧ packet.source = record.source ∧
    packet.destination = record.destination ∧ PacketAtHook record.nativeName record.direction record.hook packet

instance (record : BoundaryControlFlow) (device : String) (packet : PacketPolicy.Packet) :
    Decidable (record.Matches device packet) := by
  unfold BoundaryControlFlow.Matches
  cases hook : record.hook <;> simp only [hook, PacketAtHook, HookDirection] <;> infer_instance

def BoundaryControlApproval (records : List BoundaryControlFlow) (device : String)
    (traffic : Traffic) : Prop :=
  ∃ record ∈ records, record.Matches device traffic.packet

instance (records : List BoundaryControlFlow) (device : String) (traffic : Traffic) :
    Decidable (BoundaryControlApproval records device traffic) := by
  unfold BoundaryControlApproval
  infer_instance

def BoundaryControlRule (records : List BoundaryControlFlow)
    (device name : String) (direction : Direction) (hook : PacketProcessing.Hook)
    (rule : PacketPolicy.Rule) : Prop :=
  ∃ record ∈ records, record.device = device ∧ record.nativeName = name ∧
    record.direction = direction ∧ record.hook = hook ∧
    .protocol record.protocol ∈ rule.atoms ∧
    .sourceRange record.source record.source ∈ rule.atoms ∧
    .destinationRange record.destination record.destination ∈ rule.atoms

instance (records : List BoundaryControlFlow) (device name : String) (direction : Direction)
    (hook : PacketProcessing.Hook) (rule : PacketPolicy.Rule) :
    Decidable (BoundaryControlRule records device name direction hook rule) := by
  unfold BoundaryControlRule
  infer_instance

def BoundaryControlObservationChecks (d : Deployment) (records : List BoundaryControlFlow) : Prop :=
  (∀ record ∈ records, record.protocol = "ospf") ∧
    (∀ service ∈ d.services, service.protocol ≠ "ospf") ∧
    (∀ device ∈ d.devices, device.kind ≠ .revocationService)

instance (d : Deployment) (records : List BoundaryControlFlow) :
    Decidable (BoundaryControlObservationChecks d records) := by
  unfold BoundaryControlObservationChecks
  infer_instance

lemma ospf_packet_class (packet : PacketPolicy.Packet) (protocol : packet.protocol = "ospf") :
    PacketClass packet = .control := by
  simp [PacketClass, PacketService, PacketPortService, PacketIKE, PacketUDPESP, PacketMKA,
    PacketARP, PacketIsEthernet, protocol]

lemma ospf_observation_is_control (d : Deployment) (packet : PacketPolicy.Packet)
    (protocol : packet.protocol = "ospf")
    (packetClass : PacketClass packet = .control)
    (services : ∀ service ∈ d.services, service.protocol ≠ "ospf")
    (devices : ∀ device ∈ d.devices, device.kind ≠ .revocationService) :
    (d.Observe packet).trafficClass = .control := by
  have noService : d.RegisteredService packet = none := by
    unfold Deployment.RegisteredService
    have absent : d.services.find? (fun service =>
        service.protocol == packet.protocol &&
          ((d.PacketOwner packet packet.destination == some service.device &&
            packet.destinationPort == service.port) ||
          (d.PacketOwner packet packet.source == some service.device &&
            packet.sourcePort == service.port))) = none := by
      apply List.find?_eq_none.mpr
      intro service member
      simp [protocol, services service member]
    rw [absent]
    rfl
  have noRevocation : d.RevocationEndpoint packet = false := by
    unfold Deployment.RevocationEndpoint
    apply Bool.eq_false_iff.mpr
    intro hit
    obtain ⟨device, member, matched⟩ := List.any_eq_true.mp hit
    simp only [Bool.and_eq_true, beq_iff_eq] at matched
    exact devices device member matched.1.2
  have notIKE : ¬ PacketIKE packet := by simp [PacketIKE, protocol]
  have notUDPESP : ¬ PacketUDPESP packet := by simp [PacketUDPESP, protocol]
  simp only [Deployment.Observe, noRevocation, Bool.false_eq_true, ↓reduceIte]
  simp only [Deployment.ObservedClass, notIKE, notUDPESP, ↓reduceIte]
  split
  · rfl
  · simp [noService, packetClass]

lemma matching_boundary_control_rule_is_approved (d : Deployment)
    (records : List BoundaryControlFlow)
    (approval : d.policyApproved = BoundaryControlApproval records)
    (checks : BoundaryControlObservationChecks d records)
    (device name : String) (direction : Direction) (hook : PacketProcessing.Hook)
    (traffic : Traffic) (supported : d.Supported traffic)
    (context : PacketAtHook name direction hook traffic.packet)
    (rule : PacketPolicy.Rule)
    (guard : BoundaryControlRule records device name direction hook rule)
    (matched : rule.toFilter.accepts traffic.packet = true) :
    ApprovedControl d device traffic := by
  obtain ⟨record, member, owner, sameName, sameDirection, sameHook, protocolAtom, sourceAtom, destinationAtom⟩ := guard
  have protocol : traffic.packet.protocol = record.protocol := PacketPolicy.matching_atom matched protocolAtom
  have source : traffic.packet.source = record.source := by
    have interval := PacketPolicy.matching_atom matched sourceAtom
    change record.source ≤ traffic.packet.source ∧ traffic.packet.source ≤ record.source at interval
    omega
  have destination : traffic.packet.destination = record.destination := by
    have interval := PacketPolicy.matching_atom matched destinationAtom
    change record.destination ≤ traffic.packet.destination ∧ traffic.packet.destination ≤ record.destination at interval
    omega
  have ospf := protocol.trans (checks.1 record member)
  have control := ospf_observation_is_control d traffic.packet ospf
    (ospf_packet_class traffic.packet ospf) checks.2.1 checks.2.2
  refine ⟨(congrArg Traffic.trafficClass supported.1).trans control, ?_⟩
  rw [approval]
  exact ⟨record, member, owner, protocol, source, destination,
    by simpa only [sameName, sameDirection, sameHook] using context⟩

end TDN.Requirements.Msc
