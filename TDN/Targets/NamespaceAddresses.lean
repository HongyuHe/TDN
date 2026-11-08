import TDN.Targets.ComplianceModel
import TDN.Semantics.FiniteExecution

namespace TDN.Targets
open Compliance

def interfaceLocalAddresses (interface : Interface) : List Nat :=
  interface.address.toList ++ interface.namespaceAddresses

lemma interface_local_address_member (interface : Interface) (address : Nat) :
    address ∈ interfaceLocalAddresses interface ↔ interface.HasLocalAddress address := by
  simp [interfaceLocalAddresses, Interface.HasLocalAddress, Option.mem_toList]

def namespaceLocalAddress (interfaces : List Interface) (owner : String) (address : Nat) : Prop :=
  ∃ interface ∈ interfaces, interface.device = owner ∧ interface.HasLocalAddress address

instance (interfaces : List Interface) (owner : String) (address : Nat) :
    Decidable (namespaceLocalAddress interfaces owner address) := by
  unfold namespaceLocalAddress
  infer_instance

def NamespaceAddressChecks (interfaces : List Interface) (names : Nat → String)
    (devices : List Execution.DeviceData) : Prop :=
  ∀ owner ∈ List.range devices.length,
    (∀ address ∈ (Execution.deviceAt devices owner).localAddresses,
      namespaceLocalAddress interfaces (names owner) address) ∧
    (∀ interface ∈ interfaces, interface.device = names owner →
      ∀ address ∈ interfaceLocalAddresses interface,
        address ∈ (Execution.deviceAt devices owner).localAddresses)

instance (interfaces : List Interface) (names : Nat → String)
    (devices : List Execution.DeviceData) : Decidable (NamespaceAddressChecks interfaces names devices) := by
  unfold NamespaceAddressChecks
  infer_instance

theorem namespace_local_addresses_exact (interfaces : List Interface) (names : Nat → String)
    (devices : List Execution.DeviceData) (checked : NamespaceAddressChecks interfaces names devices)
    (owner : Nat) (present : owner < devices.length) (address : Nat) :
    namespaceLocalAddress interfaces (names owner) address ↔
      address ∈ (Execution.deviceAt devices owner).localAddresses := by
  have conditions := checked owner (List.mem_range.mpr present)
  constructor
  · rintro ⟨interface, member, sameOwner, localAddress⟩
    exact conditions.2 interface member sameOwner address
      ((interface_local_address_member interface address).mpr localAddress)
  · exact conditions.1 address

lemma namespace_local_address_owner_is_required (interface : Interface) (owner : String)
    (address : Nat) (different : interface.device ≠ owner) :
    ¬ namespaceLocalAddress [interface] owner address := by
  rintro ⟨candidate, member, sameOwner, _⟩
  have same := List.mem_singleton.mp member
  subst candidate
  exact different sameOwner

end TDN.Targets
