"""Apply byte-specific encryption order to checked native component histories."""
from pathlib import Path


def generate():
    text = """import TDN.Requirements.ByteLevelDoubleEncryptionOrder
import TDN.Deployments.SnapshotComponentByteResponses

"""
    for name, count in [("Shared", 4), ("Baseline", 2)]:
        base = "TDN.Deployments.Profile" + name + "_DataPlane"
        text += f"""namespace TDN.Deployments.Profile{name}_EnclaveIsolation
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

"""
        for domain in range(1, count + 1):
            text += f"""lemma byte_outer_placement{domain} : ∀ iface,
    (domainLayout{domain} iface).head? = some 2 →
      domainLayout{domain} iface = [2, {domain + 10}] := by
  have checked : ∀ record ∈ ({{}} : IfaceData) :: domainIfaces{domain},
      record.stack.head? = some 2 → record.stack = [2, {domain + 10}] := by native_decide
  intro iface head
  exact checked (ifaceAt domainIfaces{domain} iface) (iface_at_member_or_default domainIfaces{domain} iface) head

"""
        text += """lemma all_byte_outer_placement : ∀ d ∈ domains, ∀ iface,
    (byteLayout d iface).head? = some 2 → byteLayout d iface = [2, d + 10] := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with """ + " | ".join(["rfl"] * count) + "\n"
        text += "".join(f"  · exact byte_outer_placement{d}\n" for d in range(1, count + 1))
        text += f"""
theorem every_assembled_black_byte_has_inner_before_outer {{Byte : Type}}
    {{after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}}
    {{actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config {base}.responseGateways uniformResponseOwners)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : DataPlaneForwarding.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (packetPresent : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ {base}.blackIfaces)
    (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) (bytePresent : byte ∈ bytes) :
    ∃ start labels, Requirements.RedByteOrigin config redSources start byte ∧
      Requirements.BytePathOrderedEncryptions config {base}.responseGateways uniformResponseOwners
        (byte.domain + 10) 2 (.network start) labels (.network finish) :=
  Requirements.every_black_byte_has_ordered_encryption_path config redSources domains
    {base}.responseGateways uniformResponseOwners {base}.blackIfaces
    byteLayout byteAllowed all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    tagged_gateway_response_guards all_uniform_domain_responses (fun d => d + 10) 2
    all_byte_black_checks all_byte_outer_placement run finish bytes packetPresent ready black byte bytePresent

end TDN.Deployments.Profile{name}_EnclaveIsolation

"""
    return text


if __name__ == "__main__":
    Path("TDN/Deployments/SnapshotByteEncryptionOrder.lean").write_text(generate())
