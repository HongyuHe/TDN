"""Apply byte-flow preservation to each current native security-domain inventory."""
from pathlib import Path


def generate():
    text = """import TDN.Targets.ByteDomainDelivery
import TDN.Evidence.FreshSharedIsolation
import TDN.Evidence.FreshBaselineIsolation

"""
    for name, count in [("Shared", 4), ("Baseline", 2)]:
        namespace = "Fresh" + name + "Isolation"
        text += "namespace TDN.Imported." + namespace + "\nopen Execution\n\n"
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
    config.recipientDomain iface = some d →
    byteLayout d iface = [] ∧ config.payloadOrigin iface ∧ byteAllowed d iface := by
""" + cases
        text += "".join("  · exact source_checks" + str(d) + "\n" for d in range(1, count + 1))
        text += """
lemma all_byte_recipient_checks : ∀ d ∈ domains, ∀ iface, byteAllowed d iface →
    config.recipientDomain iface = none ∨ config.recipientDomain iface = some d := by
""" + cases
        text += "".join("  · exact recipient_checks" + str(d) + "\n" for d in range(1, count + 1))
        text += """
lemma all_byte_source_domains : ∀ iface ∈ redSources, ∀ d,
    config.recipientDomain iface = some d → d ∈ domains := by
  intro iface member d assigned
  have present := source_domains_checked iface member
  rw [assigned] at present
  simpa using present

/-- Every source byte retains its full domain label through arbitrary simultaneous
packet execution, splitting and intermediate plaintext reassembly. Actual kernel
reassembly/hook and authenticated-envelope correspondence remain explicit. -/
theorem every_assembled_delivered_byte_preserves_full_label {Byte : Type}
    {after : List (ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action Execution.Action)}
    (run : (ByteFlows.lts (lts config) (Targets.RedByteOrigin config redSources)
      PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (delivered : packet.state.datapathStage = .delivered)
    (recipientDomain : Nat) (recipient : config.recipientDomain packet.state.iface = some recipientDomain) :
    ∀ byte ∈ packet.bytes, fullLevel byte.domain = fullLevel recipientDomain := by
  have checked := Targets.assembled_packet_delivery_preserves_each_byte_domain
    config redSources domains byteLayout byteAllowed all_byte_domain_conditions all_byte_source_domains
    all_byte_source_checks all_byte_recipient_checks run packet present delivered recipientDomain recipient
  exact fun byte member => congrArg fullLevel (checked byte member)

"""
        base = "TDN.Imported.Fresh" + name + "Execution"
        text += f"""
lemma all_byte_black_checks : ∀ d ∈ domains, ∀ iface ∈ {base}.blackIfaces,
    byteLayout d iface = [2, d + 10] := by
""" + cases
        for d in range(1, count + 1):
            text += f"""  · simp only [{base}.blackIfaces, List.mem_cons, List.not_mem_nil,
      or_false, forall_eq, or_imp, forall_and]
    all_goals decide
"""
        text += f"""
theorem every_assembled_black_byte_has_both_layers {{Byte : Type}}
    {{after : List (ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}}
    {{actions : List (ByteFlows.Action Execution.Action)}}
    (run : (ByteFlows.lts (lts config) (Targets.RedByteOrigin config redSources)
      PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (ready : packet.state.datapathStage = .ready)
    (black : packet.state.iface ∈ {base}.blackIfaces) :
    ∀ byte ∈ packet.bytes, packet.state.frame.tags = [2, byte.domain + 10] :=
  Targets.assembled_packet_at_black_keeps_each_byte_protected config redSources domains
    {base}.blackIfaces byteLayout byteAllowed (fun d => d + 10) 2
    all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    all_byte_black_checks run packet present ready black

"""
        text += "end TDN.Imported." + namespace + "\n\n"
    return text


if __name__ == "__main__":
    Path("TDN/Evidence/FreshByteDomains.lean").write_text(generate())
