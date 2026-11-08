"""Extend native byte proofs to all retained component owners."""
from pathlib import Path
import generate_byte_response_checks


def generate():
    text = generate_byte_response_checks.generate()
    text = text.replace("KernelResponses.Invariant", "KernelResponses.ProvenanceInvariant")
    text = text.replace("all_assembled_gateway_response_bytes_keep_domains", "all_assembled_component_response_bytes_keep_domains")
    text = text.replace("assembled_gateway_response_delivery_keeps_full_labels", "assembled_component_response_delivery_keeps_full_labels")
    text = text.replace("assembled_gateway_response_black_bytes_keep_both_layers", "assembled_component_response_black_bytes_keep_both_layers")
    text = text.replace("bytes_with_plaintext_assembly_and_gateway_responses_keep_domains", "bytes_with_plaintext_assembly_and_component_responses_keep_domains")
    for name, count in [("Shared", 4), ("Baseline", 2)]:
        base = "TDN.Imported.Fresh" + name + "Execution"
        text = text.replace(f"Targets.nativeKernelResponses config {base}.responseGateways",
                            f"UniformDomainResponses.responseConfig config {base}.responseGateways uniformResponseOwners")
        text = text.replace(f"config redSources domains {base}.responseGateways byteLayout byteAllowed",
                            f"config redSources domains {base}.responseGateways uniformResponseOwners byteLayout byteAllowed")
        header = f"namespace TDN.Imported.Fresh{name}Isolation\nopen Execution\n"
        extra = f"""
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def uniformResponseOwners : List Nat :=
  (List.range {base}.devices.length).filter (fun owner => !(owner ∈ {base}.responseGateways))

lemma every_retained_owner_has_response_case :
    ∀ iface ∈ ({{}} : IfaceData) :: {base}.ifaces,
      iface.owner ∈ {base}.responseGateways ∨ iface.owner ∈ uniformResponseOwners := by
  decide

lemma every_active_component_can_generate (state : Execution.State)
    (active : state.datapathStage ≠ .dropped) :
    (UniformDomainResponses.responseConfig config {base}.responseGateways
      uniformResponseOwners).generates state := by
  exact ⟨active, every_retained_owner_has_response_case (ifaceAt {base}.ifaces state.iface)
    (iface_at_member_or_default {base}.ifaces state.iface)⟩

"""
        for domain in range(1, count + 1):
            extra += f"""lemma uniform_domain_response_checks{domain} :
    UniformDomainResponses.FiniteUniform taggedDevices domainIfaces{domain}
      (allowedRecord {domain}) uniformResponseOwners := by
  decide

lemma uniform_domain_responses{domain} : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout{domain} domainAllowed{domain} owner := by
  intro owner member
  have checked := UniformDomainResponses.finite_uniform_sound taggedDevices domainIfaces{domain}
    {base}.routes {base}.links {base}.switches
    (allowedRecord {domain}) uniformResponseOwners uniform_domain_response_checks{domain} owner member
  rw [config_same{domain}] at checked
  exact checked

"""
        extra += """lemma all_uniform_domain_responses : ∀ d ∈ domains, ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config (byteLayout d) (byteAllowed d) owner := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with """ + " | ".join(["rfl"] * count) + "\n"
        extra += "".join(f"  · exact uniform_domain_responses{d}\n" for d in range(1, count + 1))
        text = text.replace(header, header + extra)
    text = text.replace("tagged_gateway_response_guards run", "tagged_gateway_response_guards all_uniform_domain_responses run")
    return text


if __name__ == "__main__":
    Path("TDN/Evidence/FreshComponentByteResponses.lean").write_text(generate())
