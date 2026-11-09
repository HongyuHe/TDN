import TDN.Requirements.MscComplianceSchema

namespace TDN.Requirements
open Compliance

def AddressRecordChecks (d : Deployment) : Prop :=
  (∀ exchange ∈ d.managementExchanges, exchange.Valid d) ∧
  (∀ first ∈ d.managementExchanges, ∀ second ∈ d.managementExchanges,
    first.id = second.id → first = second) ∧
  (∀ first ∈ d.managementHistory, ∀ second ∈ d.managementHistory,
    first.observer = second.observer → first.order = second.order → first = second) ∧
  (∀ first ∈ d.interfaces, ∀ second ∈ d.interfaces,
    first.linkAddress.isSome = true → first.linkAddress = second.linkAddress →
      first.device = second.device) ∧
  (∀ first ∈ d.interfaces, ∀ second ∈ d.interfaces,
    first.address.isSome = true → first.address = second.address → first.device = second.device) ∧
  (∀ service ∈ d.services, ∃ device ∈ d.devices, device.id = service.device) ∧
  (∀ first ∈ d.services, ∀ second ∈ d.services,
    first.device = second.device → first.protocol = second.protocol →
      first.port = second.port → first.kind = second.kind)

deriving instance DecidableEq for ManagementExchange
deriving instance DecidableEq for ManagementPacketObservation

instance (d : Deployment) : Decidable (AddressRecordChecks d) := by
  unfold AddressRecordChecks
  infer_instance

def addressRecordsChecked (d : Deployment) : Bool := decide (AddressRecordChecks d)

def grayWorkstationRole (d : Deployment) (component : String) : Prop :=
  d.IsDevice component .workstation ∧
    ∃ interface ∈ d.interfaces, interface.device = component ∧ interface.zone = .gray ∧
      interface.managementNetwork = true

theorem address_inventory_from_checked_records (d : Deployment)
    (checked : addressRecordsChecked d = true)
    (workstations : d.grayWorkstation = grayWorkstationRole d) :
    d.AddressInventoryCoherent := by
  obtain ⟨exchanges, exchangeIds, historyIds, linkOwners, ipOwners, services, serviceKinds⟩ :
    AddressRecordChecks d := of_decide_eq_true checked
  refine ⟨⟨exchanges, exchangeIds, historyIds⟩, ?_, ?_, ?_, services, serviceKinds⟩
  · intro first memberFirst second memberSecond address firstAddress secondAddress
    apply linkOwners first memberFirst second memberSecond
    · simp [firstAddress]
    · exact firstAddress.trans secondAddress.symm
  · intro first memberFirst second memberSecond address firstAddress secondAddress
    apply ipOwners first memberFirst second memberSecond
    · simp [firstAddress]
    · exact firstAddress.trans secondAddress.symm
  · intro component
    rw [workstations]
    rfl

lemma packet_owner_of_interface (d : Deployment) (packet : PacketPolicy.Packet)
    (interface : Interface) (member : interface ∈ d.interfaces)
    (address : Nat) (assigned : interface.PacketAddress packet = some address)
    (owners : ∀ first ∈ d.interfaces, ∀ second ∈ d.interfaces,
      first.PacketAddress packet = some address → second.PacketAddress packet = some address →
      first.device = second.device) :
    d.PacketOwner packet address = some interface.device := by
  unfold Deployment.PacketOwner
  generalize found : d.interfaces.find?
    (fun entry => entry.PacketAddress packet == some address) = result
  cases result with
  | none =>
    have absent := List.find?_eq_none.mp found interface member
    have matchesEntry : (interface.PacketAddress packet == some address) = true := by
      simp [assigned]
    exact False.elim (absent matchesEntry)
  | some actual =>
    have actualMember := List.mem_of_find?_eq_some found
    have actualMatches := List.find?_some found
    have actualAddress : actual.PacketAddress packet = some address := by
      simpa using actualMatches
    simp only [Option.map_some]
    congr 1
    exact owners actual actualMember interface member actualAddress assigned

end TDN.Requirements

namespace TDN.Requirements
open Compliance

deriving instance DecidableEq for InterfacePolicy

instance (interface : Interface) (hook : PacketProcessing.Hook) (direction : Direction) :
    Decidable (interface.HookApplies hook direction) := by
  unfold Interface.HookApplies HookDirection
  infer_instance

def PolicyIndexChecks (d : Deployment) : Prop :=
  ∀ interface ∈ d.interfaces, ∀ direction ∈ [Direction.inbound, .outbound],
    ∀ hook ∈ [PacketProcessing.Hook.input, .output, .forward, .link],
      interface.HookApplies hook direction → ∃ policy ∈ d.policies,
        policy.interface = interface.id ∧ policy.direction = direction ∧ policy.hook = hook ∧
        ∀ other ∈ d.policies, other.interface = interface.id → other.direction = direction →
          other.hook = hook → other = policy

instance (d : Deployment) : Decidable (PolicyIndexChecks d) := by
  unfold PolicyIndexChecks
  infer_instance

def policyIndicesChecked (d : Deployment) : Bool := decide (PolicyIndexChecks d)

lemma policy_coverage_from_checked_indices (d : Deployment)
    (checked : policyIndicesChecked d = true) (interface : Interface)
    (member : interface ∈ d.interfaces) : d.PolicyCoverage interface := by
  have checks : PolicyIndexChecks d := of_decide_eq_true checked
  intro direction hook applicable
  exact checks interface member direction (by cases direction <;> simp)
    hook (by cases hook <;> simp) applicable

lemma accepted_traffic_supported (d : Deployment) (interface : String) (direction : Direction)
    (traffic : Traffic) (accepted : d.Accepts interface direction traffic) :
    d.Supported traffic := by
  obtain ⟨_, supported, _⟩ := accepted
  exact supported

lemma packet_owner_has_interface (d : Deployment) (packet : PacketPolicy.Packet)
    (address : Nat) (component : String) (owned : d.PacketOwner packet address = some component) :
    ∃ interface ∈ d.interfaces, interface.device = component ∧
      interface.PacketAddress packet = some address := by
  unfold Deployment.PacketOwner at owned
  cases found : d.interfaces.find?
      (fun entry => entry.PacketAddress packet == some address) with
  | none => simp [found] at owned
  | some actual =>
    have owner : actual.device = component := by simpa [found] using owned
    exact ⟨actual, List.mem_of_find?_eq_some found, owner,
      by simpa using List.find?_some found⟩

end TDN.Requirements
