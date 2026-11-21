import TDN.Import.CompiledDecide
import TDN.Deployments.Perimeter_BaselineInventory
import TDN.Deployments.GrayFirewall_IptablesChecks

namespace TDN.Deployments.Perimeter_Baseline
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel GrayFirewall_IptablesChecks
set_option maxRecDepth 1000000
set_option synthInstance.maxSize 8192

instance instDecidableBaselineGrayPeer (base : Deployment) : DecidableRel (deployment base).intendedPeer := by
  change DecidableRel (fun source destination => ∃ tunnel ∈ records.tunnels,
    tunnel.sender = source ∧ tunnel.receiver = destination)
  infer_instance

instance instDecidableBaselineGraySource (base : Deployment) (name : String) :
    DecidablePred ((deployment base).reachableSource name) := by
  change DecidablePred (records.reachableSource name)
  infer_instance

lemma gray_core_checked (base : Deployment) :
    GrayCoreChecks (deployment base) records.inventory records.pairs controls := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  all_goals unfold_check_parameters; native_decide

lemma gray_interfaces_checked (base : Deployment) :
    ∀ interface ∈ records.interfaces,
      GrayInterfaceChecks (deployment base) records.inventory records.pairs interface := by
  unfold_check_parameters; native_decide

lemma gray_permissions_checked (base : Deployment) :
    ∀ interface ∈ records.interfaces,
      GrayPermitChecks (deployment base) records.inventory records.pairs interface := by
  unfold_check_parameters; native_decide

end TDN.Deployments.Perimeter_Baseline
