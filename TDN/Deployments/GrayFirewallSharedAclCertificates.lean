import TDN.Deployments.GrayFirewallSharedRouteCertificates
import TDN.Deployments.GrayFirewallIptablesChecks
import TDN.Models.AclPermitCertificates

namespace TDN.Deployments.GrayFirewallShared
open Compliance Certificates PacketPolicy OuterToGray_DeviceModel

set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

structure GrayAclTable where
  index : AclRuleIndex
  witnesses : OrderedIndex AclPermitWitness
  deriving DecidableEq

load_network_records aclTables : WitnessTree GrayAclTable from "../../data/evidence/certificates/GrayFirewallSharedAcls.json" ["tables"]
load_network_records aclBindings : NatIndex (List Bool) from "../../data/evidence/certificates/GrayFirewallSharedAcls.json" ["bindings"]

def aclTableFor (interface : Interface) (direction : Direction) : Option GrayAclTable :=
  (aclBindings.lookup (2 * records.ifaceIndex interface + if direction = .inbound then 0 else 1)).bind aclTables.lookup

def aclWitnessKey (mask : AclFlowSelector) : Nat :=
  mask.source * 3 + if mask.protocol = "esp" then 0 else if mask.requestFraming then 1 else 2

def indexedAclPermit (interface : Interface) (direction : Direction) (mask : AclFlowSelector) : Bool :=
  match aclTableFor interface direction with
  | none => false
  | some table => match table.witnesses.lookup (aclWitnessKey mask) with
    | none => false
    | some witness => checkAclPermit table.index mask witness

lemma acl_tables_valid : ∀ table ∈ aclTables.values, table.index.Valid := by decide

lemma acl_table_is_captured (base : Deployment) :
    ∀ interface ∈ records.interfaces, (deployment base).IsDevice interface.device .grayFirewall →
    ∀ direction ∈ [Direction.inbound, .outbound], ∀ policy ∈ records.policies,
      policy.interface = interface.id → policy.direction = direction → policy.hook = .forward →
      ∃ table, aclTableFor interface direction = some table ∧ table.index.rules = policy.rules := by
  exact of_decide_eq_true rfl

lemma indexed_acl_permit_sound (base : Deployment) (interface : Interface)
    (member : interface ∈ records.interfaces)
    (role : (deployment base).IsDevice interface.device .grayFirewall)
    (direction : Direction) (listed : direction ∈ [Direction.inbound, .outbound])
    (policy : InterfacePolicy) (present : policy ∈ (deployment base).policies)
    (name : policy.interface = interface.id) (flow : policy.direction = direction) (hook : policy.hook = .forward)
    (mask : AclFlowSelector) (checked : indexedAclPermit interface direction mask = true) :
    mask.IsPermittedByAclChain policy.rules := by
  obtain ⟨table, found, bound⟩ := acl_table_is_captured base interface member role direction listed policy present name flow hook
  have tableMember : table ∈ aclTables.values := by
    unfold aclTableFor at found
    cases lookup : aclBindings.lookup (2 * records.ifaceIndex interface + if direction = .inbound then 0 else 1) with
    | none => simp [lookup] at found
    | some path => exact aclTables.lookup_mem path table (by simpa [lookup] using found)
  simp only [indexedAclPermit, found] at checked
  cases witness : table.witnesses.lookup (aclWitnessKey mask) with
  | none => simp [witness] at checked
  | some selected =>
    rw [← bound]
    exact table_driven_acl_certificate_sound table.index (acl_tables_valid table tableMember)
      mask selected (by simpa [witness] using checked)

end TDN.Deployments.GrayFirewallShared
