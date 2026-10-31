"""Derive pre-reassembly reception and byte-domain results from checked native policies."""
from pathlib import Path


def generate():
    text = """import TDN.Targets.ReassembledDelivery
import TDN.Evidence.FreshSharedIsolation
import TDN.Evidence.FreshBaselineIsolation

"""
    for name, count in [("Shared", 4), ("Baseline", 2)]:
        namespace = "Fresh" + name + "Isolation"
        text += f"""namespace TDN.Imported.{namespace}
open Execution

theorem snapshot_received_domain :
    Targets.msc_same_domain_plaintext_reception config redSources := by
  intro start finish actions sourceDomain recipientDomain origin sourceLevel run received plain recipientLevel
  have member : some sourceDomain ∈ domains.map some := by
    rw [← sourceLevel]
    exact source_domains_checked start.port origin.1
  have domainMember : sourceDomain ∈ domains := by simpa using member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at domainMember
  rcases domainMember with """ + " | ".join(["rfl"] * count) + "\n"
        for domain in range(1, count + 1):
            text += f"""  · exact Targets.received_domain_from_local_checks config domainLayout{domain}
      domainAllowed{domain} redSources {domain} local_domain_conditions{domain} source_checks{domain}
      recipient_checks{domain} origin sourceLevel run received recipientLevel
"""
        text += """
/-- Fragment keys and packet identities can collide. The separate implementation
correspondence must map each received piece to its byte source and admitted path. -/
theorem reassembled_bytes_have_recipient_full_label {Header Byte : Type}
    [DecidableEq Header] (recipientPort recipientDomain : Nat)
    (recipient : config.recipientDomain recipientPort = some recipientDomain)
    {actions : List ReassemblyOrigins.Action}
    {pieces : List (Fragmentation.Fragment Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {header : Header}
    {result : Fragmentation.Datagram Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat)}
    (run : (ReassemblyOrigins.system
      (Targets.ArrivedFragment config redSources recipientPort)).MTr [] actions pieces)
    (accepted : ReassemblyOrigins.assemble header pieces = some result) :
    ∀ byte ∈ result.bytes, fullLevel byte.domain = fullLevel recipientDomain := by
  have domainsMatch := Targets.reassembled_delivery_domain_from_checked_reception
    config redSources snapshot_received_domain recipientPort recipientDomain recipient run accepted
  exact fun byte member => congrArg fullLevel (domainsMatch byte member)

"""
        text += "end TDN.Imported." + namespace + "\n\n"
    return text


if __name__ == "__main__":
    Path("TDN/Evidence/FreshReassembledDomains.lean").write_text(generate())
