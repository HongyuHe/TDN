"""Apply the unchanged strict-response theorem to both current native domain checks."""
from pathlib import Path


def generate():
    text = """import TDN.Requirements.KernelReplyEnclaveIsolation
import TDN.Deployments.ProfileShared_EnclaveIsolation
import TDN.Deployments.ProfileBaseline_EnclaveIsolation
import TDN.Deployments.SnapshotDeviceResponseGuards

"""
    for name in ["Shared", "Baseline"]:
        namespace = "Profile" + name + "_EnclaveIsolation"
        base = "TDN.Deployments.Profile" + name + "_DataPlane"
        text += f"""namespace TDN.Deployments.{namespace}
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma tagged_gateway_response_guards :
    Requirements.GatewayResponseGuards config {base}.responseGateways := by
  have checks : ∀ device ∈ {base}.responseGateways,
      (deviceAt taggedDevices device).outputFallback = .deny ∧
      ∀ rule ∈ (deviceAt taggedDevices device).outputRules, rule.verdict = .allow →
        KernelResponses.SafeResponseRule rule := by
    simp only [{base}.responseGateways, taggedDevices,
      {base}.devices, ownerTag, ownerDomain]
    decide
  intro iface member
  exact checks (config.owner iface) member

theorem gateway_response_delivery_preserves_full_label
    {{start finish : DataPlaneForwarding.State}}
    {{actions : List (KernelResponses.Action DataPlaneForwarding.Action)}}
    {{source recipient : Nat}}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (sourceLevel : config.ifaceSecurityDomain start.iface = some source)
    (run : (KernelResponses.lts (lts config)
      (Requirements.nativeKernelResponses config {base}.responseGateways)).MTr
      (.network start) actions (.network finish))
    (delivered : finish.datapathStage = .delivered)
    (recipientLevel : config.ifaceSecurityDomain finish.iface = some recipient) :
    fullLevel source = fullLevel recipient := by
  exact congrArg fullLevel (Requirements.same_domain_delivery_with_strict_gateway_responses
    config redSources {base}.responseGateways snapshot_RG008_IPv4_ESP_delivery
    tagged_gateway_response_guards origin sourceLevel run delivered recipientLevel)

end TDN.Deployments.{namespace}

"""
    return text


if __name__ == "__main__":
    Path("TDN/Deployments/SnapshotDeviceResponseIsolation.lean").write_text(generate())
