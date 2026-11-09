"""Derive pre-reassembly reception and byte-domain results from checked native policies."""
from pathlib import Path


def generate():
    text = """import TDN.Requirements.ReassembledDatagramEnclaveIsolation
import TDN.Deployments.ProfileShared_EnclaveIsolation
import TDN.Deployments.ProfileBaseline_EnclaveIsolation

"""
    for name, count in [("Shared", 4), ("Baseline", 2)]:
        namespace = "Profile" + name + "_EnclaveIsolation"
        text += f"""namespace TDN.Deployments.{namespace}
open DataPlaneForwarding

theorem snapshot_received_domain :
    Requirements.msc_same_domain_plaintext_reception config redSources := by
  intro start finish actions sourceDomain destinationDomain origin sourceLevel run received plain recipientLevel
  have member : some sourceDomain ∈ domains.map some := by
    rw [← sourceLevel]
    exact source_domains_checked start.iface origin.1
  have domainMember : sourceDomain ∈ domains := by simpa using member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at domainMember
  rcases domainMember with """ + " | ".join(["rfl"] * count) + "\n"
        for domain in range(1, count + 1):
            text += f"""  · exact Requirements.received_domain_from_local_checks config domainLayout{domain}
      domainAllowed{domain} redSources {domain} local_domain_conditions{domain} source_checks{domain}
      recipient_checks{domain} origin sourceLevel run received recipientLevel
"""
        text += """

theorem reassembled_bytes_have_recipient_full_label {Header Byte : Type}
    [DecidableEq Header] (recipientIface destinationDomain : Nat)
    (recipient : config.ifaceSecurityDomain recipientIface = some destinationDomain)
    {actions : List ReassemblyOrigins.Action}
    {pieces : List (Fragmentation.Fragment Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {header : Header}
    {result : Fragmentation.Datagram Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat)}
    (run : (ReassemblyOrigins.system
      (Requirements.ArrivedFragment config redSources recipientIface)).MTr [] actions pieces)
    (accepted : ReassemblyOrigins.assemble header pieces = some result) :
    ∀ byte ∈ result.bytes, fullLevel byte.domain = fullLevel destinationDomain := by
  have domainsMatch := Requirements.reassembled_delivery_domain_from_checked_reception
    config redSources snapshot_received_domain recipientIface destinationDomain recipient run accepted
  exact fun byte member => congrArg fullLevel (domainsMatch byte member)

"""
        text += "end TDN.Deployments." + namespace + "\n\n"
    return text


if __name__ == "__main__":
    Path("TDN/Deployments/SnapshotReassembledDomains.lean").write_text(generate())
