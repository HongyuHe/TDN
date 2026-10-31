"""Apply the unchanged strict-response theorem to both current native domain checks."""
from pathlib import Path


def generate():
    text = """import TDN.Targets.ResponseIsolation
import TDN.Evidence.FreshSharedIsolation
import TDN.Evidence.FreshBaselineIsolation
import TDN.Evidence.FreshNativeResponseGuards

"""
    for name in ["Shared", "Baseline"]:
        namespace = "Fresh" + name + "Isolation"
        base = "TDN.Imported.Fresh" + name + "Execution"
        text += f"""namespace TDN.Imported.{namespace}
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma tagged_gateway_response_guards :
    Targets.GatewayResponseGuards config {base}.responseGateways := by
  have checks : ∀ device ∈ {base}.responseGateways,
      (deviceAt taggedDevices device).outputFallback = .deny ∧
      ∀ rule ∈ (deviceAt taggedDevices device).outputRules, rule.verdict = .allow →
        KernelResponses.SafeResponseRule rule := by
    simp only [{base}.responseGateways, taggedDevices,
      {base}.devices, ownerTag, ownerDomain]
    decide
  intro port member
  exact checks (config.owner port) member

theorem gateway_response_delivery_preserves_full_label
    {{start finish : Execution.State}}
    {{actions : List (KernelResponses.Action Execution.Action)}}
    {{source recipient : Nat}}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (sourceLevel : config.recipientDomain start.port = some source)
    (run : (KernelResponses.lts (lts config)
      (Targets.nativeKernelResponses config {base}.responseGateways)).MTr
      (.network start) actions (.network finish))
    (delivered : finish.phase = .delivered)
    (recipientLevel : config.recipientDomain finish.port = some recipient) :
    fullLevel source = fullLevel recipient := by
  exact congrArg fullLevel (Targets.same_domain_delivery_with_strict_gateway_responses
    config redSources {base}.responseGateways snapshot_RG008_IPv4_ESP_delivery
    tagged_gateway_response_guards origin sourceLevel run delivered recipientLevel)

end TDN.Imported.{namespace}

"""
    return text


if __name__ == "__main__":
    Path("TDN/Evidence/FreshNativeResponseIsolation.lean").write_text(generate())
