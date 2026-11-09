"""Combine checked native gateway OUTPUT and byte-domain applications."""
from pathlib import Path


def generate():
    text = """import TDN.Requirements.ByteLevelReplyEnclaveIsolation
import TDN.Deployments.SnapshotByteEnclaveIsolation
import TDN.Deployments.SnapshotDeviceResponseIsolation

"""
    for name in ["Shared", "Baseline"]:
        namespace = "Profile" + name + "_EnclaveIsolation"
        base = "TDN.Deployments.Profile" + name + "_DataPlane"
        text += f"""namespace TDN.Deployments.{namespace}
open DataPlaneForwarding

theorem all_assembled_gateway_response_bytes_keep_domains {{Byte : Type}}
    {{after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}}
    {{actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}}
    (run : (ResponseByteFlows.system (lts config)
      (Requirements.nativeKernelResponses config {base}.responseGateways)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.Invariant
      (Requirements.nativeKernelResponses config {base}.responseGateways)
      (Requirements.ByteDomainInvariant config domains byteLayout byteAllowed byte)) after :=
  Requirements.bytes_with_plaintext_assembly_and_gateway_responses_keep_domains
    config redSources domains {base}.responseGateways byteLayout byteAllowed
    all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    tagged_gateway_response_guards run

theorem assembled_gateway_response_delivery_keeps_full_labels {{Byte : Type}}
    {{after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}}
    {{actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}}
    (run : (ResponseByteFlows.system (lts config)
      (Requirements.nativeKernelResponses config {base}.responseGateways)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : DataPlaneForwarding.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (delivered : finish.datapathStage = .delivered)
    (destinationDomain : Nat) (recipient : config.ifaceSecurityDomain finish.iface = some destinationDomain) :
    ∀ byte ∈ bytes, fullLevel byte.domain = fullLevel destinationDomain := by
  intro byte member
  have preserved := all_assembled_gateway_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Requirements.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, delivered] at safe
  have permitted : byteAllowed byte.domain finish.iface := by simpa [safe.2] using safe.1.2
  rcases all_byte_recipient_checks byte.domain supported finish.iface permitted with absent | same
  · simp [recipient] at absent
  · exact congrArg fullLevel (Option.some.inj (same.symm.trans recipient))

theorem assembled_gateway_response_black_bytes_keep_both_layers {{Byte : Type}}
    {{after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}}
    {{actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}}
    (run : (ResponseByteFlows.system (lts config)
      (Requirements.nativeKernelResponses config {base}.responseGateways)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : DataPlaneForwarding.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ {base}.blackIfaces) :
    ∀ byte ∈ bytes, finish.frame.encapLayerIds = [2, byte.domain + 10] := by
  intro byte member
  have preserved := all_assembled_gateway_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Requirements.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, ready] at safe
  exact safe.1.trans (all_byte_black_checks byte.domain supported finish.iface black)

end TDN.Deployments.{namespace}

"""
    return text


if __name__ == "__main__":
    Path("TDN/Deployments/SnapshotByteReplyChecks.lean").write_text(generate())
