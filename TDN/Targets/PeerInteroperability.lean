import TDN.Semantics.MultiProtocolEvents

namespace TDN.Targets
open MultiProtocolExecution LayeredFrame

/-- Successful decoding at the peer restores the exact original Ethernet data
header. The trace premise includes the actual sender and receiver operations;
the conclusion covers protected VLAN fields as well as addresses and EtherType. -/
theorem successful_ethernet_peer_restores_header (config : Config)
    {first last : State} {actions : List Action} {sent received : EthernetHeader}
    (execution : (lts config).MTr first actions last)
    (sourceBody : first.frame.body = .ethernet sent)
    (destinationBody : last.frame.body = .ethernet received) :
    received = sent := by
  have equal := all_executions_preserve_original_ethernet config execution
  rw [sourceBody, destinationBody] at equal
  exact Option.some.inj equal

/-- A complete checked inclusion table makes every required peer issuer
available. Issuer names denote the loaded CA objects bound by the importer;
the theorem does not confer authority approval or human independence. -/
theorem peer_issuers_available_from_loaded_coverage
    {Peer Issuer : Type} (peers : List Peer) (issuer : Peer → Issuer)
    [DecidableEq Issuer] (loaded : List Issuer) (coverage : (peers.map issuer).toFinset ⊆ loaded.toFinset) :
    ∀ peer ∈ peers, issuer peer ∈ loaded := by
  intro peer member
  apply List.mem_toFinset.mp
  apply coverage
  exact List.mem_toFinset.mpr (List.mem_map.mpr ⟨peer, member, rfl⟩)

end TDN.Targets
