"""Combine checked native gateway OUTPUT and byte-domain applications."""
from pathlib import Path


def generate():
    text = """import TDN.Targets.ByteResponseDelivery
import TDN.Evidence.FreshByteDomains
import TDN.Evidence.FreshNativeResponseIsolation

"""
    for name in ["Shared", "Baseline"]:
        namespace = "Fresh" + name + "Isolation"
        base = "TDN.Imported.Fresh" + name + "Execution"
        text += f"""namespace TDN.Imported.{namespace}
open Execution

theorem all_assembled_gateway_response_bytes_keep_domains {{Byte : Type}}
    {{after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}}
    {{actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}}
    (run : (ResponseByteFlows.system (lts config)
      (Targets.nativeKernelResponses config {base}.responseGateways)
      (Targets.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.Invariant
      (Targets.nativeKernelResponses config {base}.responseGateways)
      (Targets.ByteDomainInvariant config domains byteLayout byteAllowed byte)) after :=
  Targets.bytes_with_plaintext_assembly_and_gateway_responses_keep_domains
    config redSources domains {base}.responseGateways byteLayout byteAllowed
    all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    tagged_gateway_response_guards run

theorem assembled_gateway_response_delivery_keeps_full_labels {{Byte : Type}}
    {{after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}}
    {{actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}}
    (run : (ResponseByteFlows.system (lts config)
      (Targets.nativeKernelResponses config {base}.responseGateways)
      (Targets.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : Execution.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (delivered : finish.datapathStage = .delivered)
    (recipientDomain : Nat) (recipient : config.recipientDomain finish.iface = some recipientDomain) :
    ∀ byte ∈ bytes, fullLevel byte.domain = fullLevel recipientDomain := by
  intro byte member
  have preserved := all_assembled_gateway_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Targets.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, delivered] at safe
  have permitted : byteAllowed byte.domain finish.iface := by simpa [safe.2] using safe.1.2
  rcases all_byte_recipient_checks byte.domain supported finish.iface permitted with absent | same
  · simp [recipient] at absent
  · exact congrArg fullLevel (Option.some.inj (same.symm.trans recipient))

theorem assembled_gateway_response_black_bytes_keep_both_layers {{Byte : Type}}
    {{after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}}
    {{actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}}
    (run : (ResponseByteFlows.system (lts config)
      (Targets.nativeKernelResponses config {base}.responseGateways)
      (Targets.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : Execution.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ {base}.blackIfaces) :
    ∀ byte ∈ bytes, finish.frame.tags = [2, byte.domain + 10] := by
  intro byte member
  have preserved := all_assembled_gateway_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Targets.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, ready] at safe
  exact safe.1.trans (all_byte_black_checks byte.domain supported finish.iface black)

end TDN.Imported.{namespace}

"""
    return text


if __name__ == "__main__":
    Path("TDN/Evidence/FreshByteResponses.lean").write_text(generate())
