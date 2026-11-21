import TDN.Import.CompiledDecide
import TDN.Deployments.GrayFirewall_SharedRouteHints
import TDN.Deployments.GrayFirewall_IptablesChecks
import TDN.Models.AclPermitLookupHints

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.GrayFirewall_Shared
open Compliance LookupHints PacketPolicy OuterToGray_DeviceModel

set_option maxRecDepth 100000

structure GrayAclTable where
  index : AclRuleIndex
  permitHints : OrderedIndex AclPermitLookupHint
  deriving DecidableEq

load_network_records aclTables : LookupTree GrayAclTable from "../../data/evidence/lookup-hints/GrayFirewallSharedAcls.json" ["tables"]
load_network_records aclBindings : NatIndex (List Bool) from "../../data/evidence/lookup-hints/GrayFirewallSharedAcls.json" ["bindings"]

def aclTableFor (interface : Interface) (direction : Direction) : Option GrayAclTable :=
  (aclBindings.lookup (2 * records.ifaceIndex interface + if direction = .inbound then 0 else 1)).bind aclTables.lookup

def aclHintKey (mask : AclFlowSelector) : Nat :=
  mask.source * 3 + if mask.protocol = "esp" then 0 else if mask.requestFraming then 1 else 2

def indexedAclPermit (interface : Interface) (direction : Direction) (mask : AclFlowSelector) : Bool :=
  match aclTableFor interface direction with
  | none => false
  | some table => match table.permitHints.lookup (aclHintKey mask) with
    | none => false
    | some hint => checkAclPermit table.index mask hint

lemma acl_tables_valid : ∀ table ∈ aclTables.values, table.index.Valid := by native_decide

lemma acl_table_is_captured (base : Deployment) :
    ∀ interface ∈ records.interfaces, (deployment base).IsDevice interface.device .grayFirewall →
    ∀ direction ∈ [Direction.inbound, .outbound], ∀ policy ∈ records.policies,
      policy.interface = interface.id → policy.direction = direction → policy.hook = .forward →
      ∃ table, aclTableFor interface direction = some table ∧ table.index.rules = policy.rules := by
  unfold_check_parameters; native_decide

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
  cases hint : table.permitHints.lookup (aclHintKey mask) with
  | none => simp [hint] at checked
  | some selected =>
    rw [← bound]
    exact checked_acl_hint_proves_permit table.index (acl_tables_valid table tableMember)
      mask selected (by simpa [hint] using checked)

end TDN.Deployments.GrayFirewall_Shared
