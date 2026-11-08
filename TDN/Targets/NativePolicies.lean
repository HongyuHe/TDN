import TDN.Targets.ProcessingInventoryDerivation

namespace TDN.Targets
open Compliance

deriving instance DecidableEq for Interface

def nativePoliciesAt (inventory : PacketProcessing.Inventory) (interface : Interface)
    (iface : Nat) : List InterfacePolicy :=
  if interface.address.isSome then
    [⟨interface.id, .inbound, inventory.configuration.ip.inputRules iface,
       inventory.configuration.ip.inputFallback iface, .input⟩,
     ⟨interface.id, .outbound, inventory.configuration.ip.outputRules iface,
       inventory.configuration.ip.outputFallback iface, .output⟩,
     ⟨interface.id, .inbound, inventory.configuration.ip.forwardRules iface,
       inventory.configuration.ip.forwardFallback iface, .forward⟩,
     ⟨interface.id, .outbound, inventory.configuration.ip.forwardRules iface,
       inventory.configuration.ip.forwardFallback iface, .forward⟩]
  else []

def nativePolicies (inventory : PacketProcessing.Inventory) (interfaces : List Interface)
    (ifaceOf : Interface → Nat) : List InterfacePolicy :=
  interfaces.flatMap fun interface => nativePoliciesAt inventory interface (ifaceOf interface)

def InterfaceIDsUnique (interfaces : List Interface) : Prop :=
  ∀ first ∈ interfaces, ∀ second ∈ interfaces, first.id = second.id → first = second

instance (interfaces : List Interface) : Decidable (InterfaceIDsUnique interfaces) := by
  unfold InterfaceIDsUnique
  infer_instance

lemma native_policy_has_interface (inventory : PacketProcessing.Inventory) (interface : Interface)
    (iface : Nat) (policy : InterfacePolicy) (member : policy ∈ nativePoliciesAt inventory interface iface) :
    policy.interface = interface.id := by
  unfold nativePoliciesAt at member
  split at member
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl <;> rfl
  · simp at member

lemma native_policy_keys_unique (inventory : PacketProcessing.Inventory) (interface : Interface)
    (iface : Nat) (first second : InterfacePolicy)
    (firstMember : first ∈ nativePoliciesAt inventory interface iface)
    (secondMember : second ∈ nativePoliciesAt inventory interface iface)
    (direction : first.direction = second.direction) (hook : first.hook = second.hook) :
    first = second := by
  unfold nativePoliciesAt at firstMember secondMember
  split at firstMember
  · simp_all only [Bool.true_eq, ↓reduceIte, List.mem_cons, List.not_mem_nil, or_false]
    rcases firstMember with rfl | rfl | rfl | rfl <;>
      rcases secondMember with rfl | rfl | rfl | rfl <;> simp_all
  · simp_all

lemma native_policies_cover_hooks (inventory : PacketProcessing.Inventory)
    (interfaces : List Interface) (ifaceOf : Interface → Nat)
    (unique : InterfaceIDsUnique interfaces) (interface : Interface) (member : interface ∈ interfaces)
    (direction : Direction) (hook : PacketProcessing.Hook)
    (applies : interface.HookApplies hook direction) :
    ∃ policy ∈ nativePolicies inventory interfaces ifaceOf,
      policy.interface = interface.id ∧ policy.direction = direction ∧ policy.hook = hook ∧
        ∀ other ∈ nativePolicies inventory interfaces ifaceOf, other.interface = interface.id →
          other.direction = direction → other.hook = hook → other = policy := by
  have selectedPolicy : ∃ policy ∈ nativePoliciesAt inventory interface (ifaceOf interface),
      policy.direction = direction ∧ policy.hook = hook := by
    obtain ⟨allowed, notLink, addressed⟩ := applies
    cases hook <;> cases direction <;>
      simp_all [HookDirection, nativePoliciesAt]
  obtain ⟨policy, policyMember, policyDirection, policyHook⟩ := selectedPolicy
  refine ⟨policy, List.mem_flatMap.mpr ⟨interface, member, policyMember⟩,
    native_policy_has_interface inventory interface _ policy policyMember, policyDirection, policyHook, ?_⟩
  intro other otherMember name directionEq hookEq
  obtain ⟨owner, ownerMember, ownerPolicy⟩ := List.mem_flatMap.mp otherMember
  have ownerName := native_policy_has_interface inventory owner _ other ownerPolicy
  have ownerEq := unique owner ownerMember interface member (ownerName.symm.trans name)
  subst owner
  exact native_policy_keys_unique inventory interface _ other policy ownerPolicy policyMember
    (directionEq.trans policyDirection.symm) (hookEq.trans policyHook.symm)

theorem native_policies_have_checked_indices (d : Deployment) (inventory : PacketProcessing.Inventory)
    (ifaceOf : Interface → Nat) (policies : d.policies = nativePolicies inventory d.interfaces ifaceOf)
    (unique : InterfaceIDsUnique d.interfaces) : policyIndicesChecked d = true := by
  apply decide_eq_true
  intro interface member direction _ hook _ applies
  rw [policies]
  exact native_policies_cover_hooks inventory d.interfaces ifaceOf unique interface member direction hook applies

lemma native_policy_projects_raw_program (inventory : PacketProcessing.Inventory) (interface : Interface)
    (iface : Nat) (policy : InterfacePolicy) (member : policy ∈ nativePoliciesAt inventory interface iface) :
    interface.HookApplies policy.hook policy.direction ∧ PolicyNativeProjection inventory policy iface := by
  unfold nativePoliciesAt at member
  split at member
  next addressed =>
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl <;>
      simp [Interface.HookApplies, HookDirection, PolicyNativeProjection, addressed]
  next => simp_all

end TDN.Targets

namespace TDN.Targets
open Compliance

def NativeProgramAtoms (inventory : PacketProcessing.Inventory) (iface : Nat) : Prop :=
  (∀ rule ∈ inventory.configuration.ip.inputRules iface, ∀ atom ∈ rule.atoms, AtomAtHook .input atom) ∧
  (∀ rule ∈ inventory.configuration.ip.outputRules iface, ∀ atom ∈ rule.atoms, AtomAtHook .output atom) ∧
  (∀ rule ∈ inventory.configuration.ip.forwardRules iface, ∀ atom ∈ rule.atoms, AtomAtHook .forward atom)

instance (inventory : PacketProcessing.Inventory) (iface : Nat) :
    Decidable (NativeProgramAtoms inventory iface) := by
  unfold NativeProgramAtoms
  infer_instance

lemma native_policy_uses_hook_atoms (inventory : PacketProcessing.Inventory) (interface : Interface)
    (iface : Nat) (atoms : NativeProgramAtoms inventory iface) (policy : InterfacePolicy)
    (member : policy ∈ nativePoliciesAt inventory interface iface) :
    ∀ rule ∈ policy.rules, ∀ atom ∈ rule.atoms, AtomAtHook policy.hook atom := by
  unfold nativePoliciesAt at member
  split at member
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl
    · exact atoms.1
    · exact atoms.2.1
    · exact atoms.2.2
    · exact atoms.2.2
  · simp at member

lemma native_policies_have_processing_projection (d : Deployment)
    (inventory : PacketProcessing.Inventory) (ifaceOf : Interface → Nat)
    (policies : d.policies = nativePolicies inventory d.interfaces ifaceOf)
    (ifaces : ∀ interface ∈ d.interfaces, ifaceOf interface ∈ inventory.ifaces ∧
      inventory.ifaceName (ifaceOf interface) = interface.id)
    (atoms : ∀ iface ∈ inventory.ifaces, NativeProgramAtoms inventory iface) :
    ∀ policy ∈ d.policies, ∃ interface ∈ d.interfaces, ∃ iface ∈ inventory.ifaces,
      interface.id = policy.interface ∧ inventory.ifaceName iface = interface.id ∧
      interface.HookApplies policy.hook policy.direction ∧
      (∀ rule ∈ policy.rules, ∀ atom ∈ rule.atoms, AtomAtHook policy.hook atom) ∧
      PolicyNativeProjection inventory policy iface := by
  intro policy member
  rw [policies] at member
  obtain ⟨interface, interfaceMember, policyMember⟩ := List.mem_flatMap.mp member
  have iface := ifaces interface interfaceMember
  have projection := native_policy_projects_raw_program inventory interface (ifaceOf interface) policy policyMember
  exact ⟨interface, interfaceMember, ifaceOf interface, iface.1,
    (native_policy_has_interface inventory interface _ policy policyMember).symm, iface.2, projection.1,
    native_policy_uses_hook_atoms inventory interface _ (atoms _ iface.1) policy policyMember, projection.2⟩

end TDN.Targets

namespace TDN.Targets
open Compliance

def ProcessingStructuralChecks (d : Deployment) (inventory : PacketProcessing.Inventory) : Prop :=
  (∀ endpoint ∈ inventory.mkaPeers,
    endpoint.sourceIface ∈ inventory.ifaces ∧ endpoint.destinationIface ∈ inventory.ifaces ∧
    (∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = endpoint.sourceIface) ∧
    (∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = endpoint.destinationIface) ∧
    ∃ interface ∈ d.interfaces, interface.id = inventory.ifaceName endpoint.sourceIface ∧
      interface.linkAddress = some (endpoint.actorSCI / 65536)) ∧
  (∀ tunnel ∈ d.tunnels, tunnel.mechanism = .macsec →
    ∃ endpoint ∈ inventory.mkaPeers, endpoint.tunnel = tunnel.id ∧
      inventory.componentName (inventory.configuration.ip.owner endpoint.sourceIface) = tunnel.sender ∧
      inventory.componentName (inventory.configuration.ip.owner endpoint.destinationIface) = tunnel.receiver) ∧
  (∀ iface ∈ inventory.ifaces, ∃ interface ∈ d.interfaces,
    interface.id = inventory.ifaceName iface ∧
    interface.device = inventory.componentName (inventory.configuration.ip.owner iface)) ∧
  (∀ interface ∈ d.interfaces, ∃ iface ∈ inventory.ifaces,
    inventory.ifaceName iface = interface.id ∧
    inventory.componentName (inventory.configuration.ip.owner iface) = interface.device) ∧
  (∀ first ∈ inventory.ifaces, ∀ second ∈ inventory.ifaces,
    inventory.ifaceName first = inventory.ifaceName second → first = second) ∧
  (∀ interface ∈ d.interfaces, InterfaceMtuCheck interface) ∧
  (∀ iface ∈ inventory.ifaces, ∀ policy ∈ inventory.configuration.ip.outbound iface,
    ∃ size ∈ inventory.ipsecSizes, size.iface = iface ∧ size.policy = policy) ∧
  (∀ size ∈ inventory.ipsecSizes, size.Valid ∧ size.iface ∈ inventory.ifaces ∧
    size.policy ∈ inventory.configuration.ip.outbound size.iface) ∧
  (∀ route ∈ inventory.configuration.ip.routes,
    route.ingress ∈ inventory.ifaces ∧ route.egress ∈ inventory.ifaces ∧
    inventory.configuration.ip.owner route.ingress = inventory.configuration.ip.owner route.egress)

instance (d : Deployment) (inventory : PacketProcessing.Inventory) :
    Decidable (ProcessingStructuralChecks d inventory) := by
  unfold ProcessingStructuralChecks
  infer_instance

theorem native_policy_inventory_checks_from_structure (d : Deployment)
    (inventory : PacketProcessing.Inventory) (ifaceOf : Interface → Nat)
    (policies : d.policies = nativePolicies inventory d.interfaces ifaceOf)
    (structureChecked : ProcessingStructuralChecks d inventory)
    (ifaces : ∀ interface ∈ d.interfaces, ifaceOf interface ∈ inventory.ifaces ∧
      inventory.ifaceName (ifaceOf interface) = interface.id)
    (atoms : ∀ iface ∈ inventory.ifaces, NativeProgramAtoms inventory iface)
    (programs : ∀ first second,
      inventory.configuration.ip.owner first = inventory.configuration.ip.owner second →
      inventory.configuration.ip.forwardRules first = inventory.configuration.ip.forwardRules second ∧
      inventory.configuration.ip.forwardFallback first = inventory.configuration.ip.forwardFallback second) :
    processingInventoryChecked d inventory = true := by
  apply decide_eq_true
  obtain ⟨mka, macsec, ifaceBindings, interfaceBindings, names, mtus, sizesCover, sizes, routes⟩ := structureChecked
  exact ⟨mka, macsec, ifaceBindings, interfaceBindings, names, mtus, sizesCover, sizes, routes,
    fun first _ second _ owner => programs first second owner,
    native_policies_have_processing_projection d inventory ifaceOf policies ifaces atoms⟩

end TDN.Targets
