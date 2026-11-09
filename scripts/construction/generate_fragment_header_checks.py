"""Check all native ordered rule lists for the noninitial-fragment bridge."""
from pathlib import Path


def generate():
    text = """import TDN.Models.NonInitialFragmentFilterLemmas
import TDN.Deployments.ProfileShared_EnclaveIsolation
import TDN.Deployments.ProfileBaseline_EnclaveIsolation

"""
    for name in ["Shared", "Baseline"]:
        base = "TDN.Deployments.Profile" + name + "_DataPlane"
        text += f"""namespace TDN.Deployments.Profile{name}_EnclaveIsolation
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma device_all_hooks_only_allow : ∀ device ∈ ({{}} : DeviceData) :: taggedDevices,
    ∀ rules ∈ [device.inputRules, device.forwardRules, device.outputRules],
      ∀ rule ∈ rules, rule.verdict = .allow := by
  decide

"""
        for hook in ["input", "forward", "output"]:
            text += f"""theorem noninitial_{hook}_accepted_by_header_completion (iface : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.{hook}Rules iface).map FragmentHeaders.rule)
      (config.{hook}Fallback iface) packet = .allow) :
    accepts (config.{hook}Rules iface) (config.{hook}Fallback iface) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.{hook}Rules iface) ?_ (config.{hook}Fallback iface) packet accepted
  exact device_all_hooks_only_allow (deviceAt taggedDevices (ifaceAt {base}.ifaces iface).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, dataPlaneModelFromRecords])

"""
        text += f"end TDN.Deployments.Profile{name}_EnclaveIsolation\n\n"
    return text


if __name__ == "__main__":
    Path("TDN/Deployments/SnapshotFragmentHeaders.lean").write_text(generate())
