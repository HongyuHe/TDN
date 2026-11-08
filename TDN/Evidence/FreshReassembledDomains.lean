import TDN.Targets.ReassembledDelivery
import TDN.Evidence.FreshSharedIsolation
import TDN.Evidence.FreshBaselineIsolation

namespace TDN.Imported.FreshSharedIsolation
open Execution

theorem snapshot_received_domain :
    Targets.msc_same_domain_plaintext_reception config redSources := by
  intro start finish actions sourceDomain recipientDomain origin sourceLevel run received plain recipientLevel
  have member : some sourceDomain ∈ domains.map some := by
    rw [← sourceLevel]
    exact source_domains_checked start.iface origin.1
  have domainMember : sourceDomain ∈ domains := by simpa using member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at domainMember
  rcases domainMember with rfl | rfl | rfl | rfl
  · exact Targets.received_domain_from_local_checks config domainLayout1
      domainAllowed1 redSources 1 local_domain_conditions1 source_checks1
      recipient_checks1 origin sourceLevel run received recipientLevel
  · exact Targets.received_domain_from_local_checks config domainLayout2
      domainAllowed2 redSources 2 local_domain_conditions2 source_checks2
      recipient_checks2 origin sourceLevel run received recipientLevel
  · exact Targets.received_domain_from_local_checks config domainLayout3
      domainAllowed3 redSources 3 local_domain_conditions3 source_checks3
      recipient_checks3 origin sourceLevel run received recipientLevel
  · exact Targets.received_domain_from_local_checks config domainLayout4
      domainAllowed4 redSources 4 local_domain_conditions4 source_checks4
      recipient_checks4 origin sourceLevel run received recipientLevel

theorem reassembled_bytes_have_recipient_full_label {Header Byte : Type}
    [DecidableEq Header] (recipientIface recipientDomain : Nat)
    (recipient : config.recipientDomain recipientIface = some recipientDomain)
    {actions : List ReassemblyOrigins.Action}
    {pieces : List (Fragmentation.Fragment Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {header : Header}
    {result : Fragmentation.Datagram Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat)}
    (run : (ReassemblyOrigins.system
      (Targets.ArrivedFragment config redSources recipientIface)).MTr [] actions pieces)
    (accepted : ReassemblyOrigins.assemble header pieces = some result) :
    ∀ byte ∈ result.bytes, fullLevel byte.domain = fullLevel recipientDomain := by
  have domainsMatch := Targets.reassembled_delivery_domain_from_checked_reception
    config redSources snapshot_received_domain recipientIface recipientDomain recipient run accepted
  exact fun byte member => congrArg fullLevel (domainsMatch byte member)

end TDN.Imported.FreshSharedIsolation

namespace TDN.Imported.FreshBaselineIsolation
open Execution

theorem snapshot_received_domain :
    Targets.msc_same_domain_plaintext_reception config redSources := by
  intro start finish actions sourceDomain recipientDomain origin sourceLevel run received plain recipientLevel
  have member : some sourceDomain ∈ domains.map some := by
    rw [← sourceLevel]
    exact source_domains_checked start.iface origin.1
  have domainMember : sourceDomain ∈ domains := by simpa using member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at domainMember
  rcases domainMember with rfl | rfl
  · exact Targets.received_domain_from_local_checks config domainLayout1
      domainAllowed1 redSources 1 local_domain_conditions1 source_checks1
      recipient_checks1 origin sourceLevel run received recipientLevel
  · exact Targets.received_domain_from_local_checks config domainLayout2
      domainAllowed2 redSources 2 local_domain_conditions2 source_checks2
      recipient_checks2 origin sourceLevel run received recipientLevel

theorem reassembled_bytes_have_recipient_full_label {Header Byte : Type}
    [DecidableEq Header] (recipientIface recipientDomain : Nat)
    (recipient : config.recipientDomain recipientIface = some recipientDomain)
    {actions : List ReassemblyOrigins.Action}
    {pieces : List (Fragmentation.Fragment Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {header : Header}
    {result : Fragmentation.Datagram Header (ReassemblyOrigins.ByteOrigin Byte Nat Nat)}
    (run : (ReassemblyOrigins.system
      (Targets.ArrivedFragment config redSources recipientIface)).MTr [] actions pieces)
    (accepted : ReassemblyOrigins.assemble header pieces = some result) :
    ∀ byte ∈ result.bytes, fullLevel byte.domain = fullLevel recipientDomain := by
  have domainsMatch := Targets.reassembled_delivery_domain_from_checked_reception
    config redSources snapshot_received_domain recipientIface recipientDomain recipient run accepted
  exact fun byte member => congrArg fullLevel (domainsMatch byte member)

end TDN.Imported.FreshBaselineIsolation

