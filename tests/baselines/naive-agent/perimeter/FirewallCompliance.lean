import TDN.Deployments.DeviceCheckDefaults
import TDN.Deployments.Perimeter_DeviceModel
import TDN.Requirements.PerimeterDeviceAclChecks

namespace TDN.Experiments.FirewallSnapshot
open Compliance Requirements Requirements.Msc Deployments.OuterToGray_DeviceModel
open Deployments.Perimeter_DeviceModel

set_option maxRecDepth 100000
set_option maxHeartbeats 2000000
set_option synthInstance.maxSize 16384

load_network_records records : Records from "input.json" ["records"]
load_network_records controls : List BoundaryControlFlow from "input.json" ["controls"]
load_network_records firewalls : List FirewallBinding from "input.json" ["firewalls"]
load_network_records internalIfaces : List String from "input.json" ["internalIfaces"]

def localServiceView (d : Deployment) : Deployment :=
  { d with policies := d.policies.filter fun policy => policy.hook == .input || policy.hook == .output }

lemma local_service_admission_preserved (d : Deployment) (interface : String)
    (direction : Direction) (hook : PacketProcessing.Hook)
    (localHook : hook = .input ∨ hook = .output) (traffic : Traffic)
    (accepted : d.PermitsAtHook interface direction hook traffic) :
    (localServiceView d).PermitsOnInterface interface direction traffic := by
  have noLink : hook ≠ .link := by rcases localHook with rfl | rfl <;> decide
  obtain ⟨supported, context, admission⟩ := accepted
  rw [if_neg noLink] at admission
  obtain ⟨policy, member, name, side, atHook, unique, allowed⟩ := admission
  refine ⟨hook, supported, context, ?_⟩
  rw [if_neg noLink]
  refine ⟨policy, ?_, name, side, atHook, ?_, allowed⟩
  · apply List.mem_filter.mpr
    refine ⟨member, ?_⟩
    rcases localHook with localHook | localHook <;> simp [atHook, localHook]
  · intro other memberOther sameName sameDirection sameHook
    exact unique other (List.mem_filter.mp memberOther).1 sameName sameDirection sameHook

def fullDeployment (base : Deployment) : Deployment :=
  registeredDeployment records [] [] base controls

def deployment (base : Deployment) : Deployment := localServiceView (fullDeployment base)

def firewallIfaces : List Interface := records.interfaces.filter fun interface =>
  interface.zone == .black && records.components.any fun device =>
    device.id == interface.device && device.kind == .outerFirewall

lemma firewall_inventory_checked (base : Deployment) :
    firewallIfaces ≠ [] ∧ ∀ interface ∈ firewallIfaces,
      interface.address.isSome = true ∧
      (deployment base).IsDevice interface.device .outerFirewall ∧
      (deployment base).IsLayer (localOuter firewalls interface.device) .outer := by
  unfold_check_parameters
  native_decide

lemma routed_ifaces_checked : ∀ interface ∈ firewallIfaces,
    ∀ iface ∈ records.inventory.ifaces, records.inventory.ifaceName iface = interface.id →
      DeriveDataPlaneFromDeviceRecords.RoutedIface records.inventory iface := by
  native_decide

lemma control_observations_checked (base : Deployment) :
    BoundaryControlObservationChecks (deployment base) controls := by
  unfold_check_parameters
  native_decide

lemma firewall_rules_checked (base : Deployment) :
    ∀ interface ∈ firewallIfaces,
      BoundaryFirewallChecks (deployment base) records.inventory controls interface
        (localOuter firewalls interface.device) (internalIfaces.contains interface.id) := by
  unfold_check_parameters
  native_decide

theorem checked_local_view_admission (base : Deployment)
    (interface : Interface) (member : interface ∈ firewallIfaces)
    (direction : Direction) (traffic : Traffic)
    (accepted : (deployment base).PermitsOnInterface interface.id direction traffic) :
    (IPsecPacket traffic.packet ∧
      (direction = .inbound →
        if internalIfaces.contains interface.id then
          LocalOuterAddress (deployment base) interface.device
            (localOuter firewalls interface.device) traffic.packet.source
        else LocalOuterAddress (deployment base) interface.device
            (localOuter firewalls interface.device) traffic.packet.destination)) ∨
      ApprovedControl (deployment base) interface.device traffic := by
  obtain ⟨_, firewallRole, outerRole⟩ := (firewall_inventory_checked base).2 interface member
  exact firewall_control_admission_from_local_rule_checks
    (deployment base) records.inventory rfl controls rfl (control_observations_checked base)
    interface (localOuter firewalls interface.device) (internalIfaces.contains interface.id)
    firewallRole outerRole (routed_ifaces_checked interface member)
    (firewall_rules_checked base interface member) direction traffic accepted

theorem snapshot_outer_firewall_local_service_admission (base : Deployment)
    (interface : Interface) (member : interface ∈ firewallIfaces)
    (direction : Direction) (hook : PacketProcessing.Hook)
    (localHook : hook = .input ∨ hook = .output) (traffic : Traffic)
    (accepted : (fullDeployment base).PermitsAtHook interface.id direction hook traffic) :
    (IPsecPacket traffic.packet ∧
      (direction = .inbound →
        if internalIfaces.contains interface.id then
          LocalOuterAddress (fullDeployment base) interface.device
            (localOuter firewalls interface.device) traffic.packet.source
        else LocalOuterAddress (fullDeployment base) interface.device
            (localOuter firewalls interface.device) traffic.packet.destination)) ∨
      ApprovedControl (fullDeployment base) interface.device traffic := by
  exact checked_local_view_admission base interface member direction traffic
    (local_service_admission_preserved (fullDeployment base) interface.id direction hook localHook traffic accepted)

def rejectedFirewallRules (localOnly : Bool) : List (String × String × String × PacketPolicy.PacketAclRule) :=
  let original := fullDeployment Deployments.emptyDeploymentForChecks
  let d := if localOnly then localServiceView original else original
  firewallIfaces.flatMap fun interface =>
    d.policies.flatMap fun policy =>
      if policy.interface = interface.id then
        policy.rules.filterMap fun rule =>
          if rule.verdict = .allow ∧
              ¬ FirewallControlBoundaryRule d controls interface.device
                (localOuter firewalls interface.device) (internalIfaces.contains interface.id)
                (records.inventory.configuration.ip.interfaceName (records.ifaceIndex interface))
                policy.direction policy.hook rule then
            some (interface.id, if policy.direction = .inbound then "inbound" else "outbound",
              match policy.hook with
              | .input => "input"
              | .output => "output"
              | .forward => "forward"
              | .link => "link", rule)
          else none
      else []

#eval IO.println ("TDN_FIREWALL_DIAGNOSTICS:" ++ (Lean.toJson (rejectedFirewallRules true)).compress)

#eval IO.println ("TDN_FIREWALL_FULL_DIAGNOSTICS:" ++ (Lean.toJson (rejectedFirewallRules false)).compress)

end TDN.Experiments.FirewallSnapshot
