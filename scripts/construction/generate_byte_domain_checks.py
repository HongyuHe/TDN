"""Apply byte-flow preservation to each current native security-domain inventory."""
from pathlib import Path


def generate():
    text = """import TDN.Requirements.ByteLevelEnclaveIsolation
import TDN.Deployments.ProfileShared_EnclaveIsolation
import TDN.Deployments.ProfileBaseline_EnclaveIsolation

"""
    for name, count in [("Shared", 4), ("Baseline", 2)]:
        namespace = "Profile" + name + "_EnclaveIsolation"
        text += "namespace TDN.Deployments." + namespace + "\nopen DataPlaneForwarding\n\n"
        text += "def byteLayout : Nat → Nat → List Nat\n"
        text += "".join("  | " + str(d) + " => domainLayout" + str(d) + "\n" for d in range(1, count + 1))
        text += "  | _ => domainLayout1\n\n"
        text += "def byteAllowed : Nat → Nat → Prop\n"
        text += "".join("  | " + str(d) + " => domainAllowed" + str(d) + "\n" for d in range(1, count + 1))
        text += "  | _ => domainAllowed1\n\n"
        cases = """  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with """ + " | ".join(["rfl"] * count) + "\n"
        text += """lemma all_byte_domain_conditions : ∀ d ∈ domains,
    LocalDomainConditions config (byteLayout d) (byteAllowed d) := by
""" + cases
        text += "".join("  · exact local_domain_conditions" + str(d) + "\n" for d in range(1, count + 1))
        text += """
lemma all_byte_source_checks : ∀ d ∈ domains, ∀ iface ∈ redSources,
    config.ifaceSecurityDomain iface = some d →
    byteLayout d iface = [] ∧ config.canOriginateTraffic iface ∧ byteAllowed d iface := by
""" + cases
        text += "".join("  · exact source_checks" + str(d) + "\n" for d in range(1, count + 1))
        text += """
lemma all_byte_recipient_checks : ∀ d ∈ domains, ∀ iface, byteAllowed d iface →
    config.ifaceSecurityDomain iface = none ∨ config.ifaceSecurityDomain iface = some d := by
""" + cases
        text += "".join("  · exact recipient_checks" + str(d) + "\n" for d in range(1, count + 1))
        text += """
lemma all_byte_source_domains : ∀ iface ∈ redSources, ∀ d,
    config.ifaceSecurityDomain iface = some d → d ∈ domains := by
  intro iface member d assigned
  have present := source_domains_checked iface member
  rw [assigned] at present
  simpa using present


theorem every_assembled_delivered_byte_preserves_full_label {Byte : Type}
    {after : List (ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action DataPlaneForwarding.Action)}
    (run : (ByteFlows.lts (lts config) (Requirements.RedByteOrigin config redSources)
      PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (delivered : packet.state.datapathStage = .delivered)
    (destinationDomain : Nat) (recipient : config.ifaceSecurityDomain packet.state.iface = some destinationDomain) :
    ∀ byte ∈ packet.bytes, fullLevel byte.domain = fullLevel destinationDomain := by
  have checked := Requirements.assembled_packet_delivery_preserves_each_byte_domain
    config redSources domains byteLayout byteAllowed all_byte_domain_conditions all_byte_source_domains
    all_byte_source_checks all_byte_recipient_checks run packet present delivered destinationDomain recipient
  exact fun byte member => congrArg fullLevel (checked byte member)

"""
        base = "TDN.Deployments.Profile" + name + "_DataPlane"
        text += f"""
lemma all_byte_black_checks : ∀ d ∈ domains, ∀ iface ∈ {base}.blackIfaces,
    byteLayout d iface = [2, d + 10] := by
""" + cases
        for d in range(1, count + 1):
            text += f"""  · simp only [{base}.blackIfaces, List.mem_cons, List.not_mem_nil,
      or_false, forall_eq, or_imp, forall_and]
    all_goals native_decide
"""
        text += f"""
theorem every_assembled_black_byte_has_both_layers {{Byte : Type}}
    {{after : List (ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}}
    {{actions : List (ByteFlows.Action DataPlaneForwarding.Action)}}
    (run : (ByteFlows.lts (lts config) (Requirements.RedByteOrigin config redSources)
      PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (ready : packet.state.datapathStage = .egressReady)
    (black : packet.state.iface ∈ {base}.blackIfaces) :
    ∀ byte ∈ packet.bytes, packet.state.frame.encapLayerIds = [2, byte.domain + 10] :=
  Requirements.assembled_packet_at_black_keeps_each_byte_protected config redSources domains
    {base}.blackIfaces byteLayout byteAllowed (fun d => d + 10) 2
    all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    all_byte_black_checks run packet present ready black

"""
        text += "end TDN.Deployments." + namespace + "\n\n"
    return text


if __name__ == "__main__":
    Path("TDN/Deployments/SnapshotByteEnclaveIsolation.lean").write_text(generate())
