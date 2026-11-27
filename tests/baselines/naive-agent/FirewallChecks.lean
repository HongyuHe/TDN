import TDN.Import.SnapshotLoader
import TDN.Deployments.DeviceCheckDefaults
import TDN.Deployments.Perimeter_DeviceModel
import TDN.Requirements.PerimeterDeviceAclChecks

namespace TDN.Benchmark.Firewall
open Compliance Requirements Requirements.Msc Deployments.OuterToGray_DeviceModel Deployments.Perimeter_DeviceModel

set_option Elab.async false
set_option maxRecDepth 100000

load_network_records records : Records from "evidence.json" ["records"]
load_network_records controls : List BoundaryControlFlow from "evidence.json" ["controls"]
load_network_records firewalls : List FirewallBinding from "evidence.json" ["firewalls"]
load_network_records internalIfaces : List String from "evidence.json" ["internalIfaces"]
load_network_records requiredBlackIfaces : List String from "evidence.json" ["requiredBlackIfaces"]

def net := registeredDeployment records [] [] Deployments.emptyDeploymentForChecks controls
def blackFirewallIfaces := records.interfaces.filter fun iface =>
  iface.zone == .black && records.components.any fun device =>
    device.id == iface.device && device.kind == .outerFirewall

def LocalFirewallChecks : Prop :=
  blackFirewallIfaces ≠ [] ∧ ∀ iface ∈ blackFirewallIfaces, ∀ policy ∈ net.policies,
    policy.interface = iface.id → (policy.hook = .input ∨ policy.hook = .output) →
      policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
        FirewallControlBoundaryRule net controls iface.device (localOuter firewalls iface.device)
          (internalIfaces.contains iface.id) (records.inventory.configuration.ip.interfaceName (records.ifaceIndex iface))
          policy.direction policy.hook rule

instance : Decidable LocalFirewallChecks := by unfold LocalFirewallChecks; infer_instance

run_cmd do Lean.logInfo m!"TDN_BEGIN {← IO.monoNanosNow}"
example : requiredBlackIfaces ≠ [] ∧ ∀ name ∈ requiredBlackIfaces,
    ∃ iface ∈ blackFirewallIfaces, iface.id = name := by native_decide
example : LocalFirewallChecks := by native_decide
run_cmd do Lean.logInfo m!"TDN_END {← IO.monoNanosNow}"
end TDN.Benchmark.Firewall
