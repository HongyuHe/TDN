import TDN.Deployments.NestedProtection_MixedData

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def capturedBridgeChain (owner : Nat) : LinkAdmission.Program :=
  { rules := (records.bridgeRules.filter (fun record => record.owner == owner)).map BridgeRule.rule,
    fallback := .deny }

def SplitBridgeAdmitted (first last : Nat) (frame : LinkAdmission.Frame) : Prop :=
  (∃ policy, LinkAdmission.lookup records.linkPolicies first = some policy ∧
    policy.inbound.Accepts (frame.Packet (configuration.ip.interfaceName first) "")) ∧
  (∃ policy, LinkAdmission.lookup records.linkPolicies last = some policy ∧
    policy.outbound.Accepts (frame.Packet "" (configuration.ip.interfaceName last)))

lemma split_bridge_policies_match_captured_chain (first last : Nat)
    (edge : (first,last) ∈ records.bridges) (frame : LinkAdmission.Frame) :
    SplitBridgeAdmitted first last frame ↔
      (capturedBridgeChain (configuration.ip.owner first)).Accepts
        (frame.Packet (configuration.ip.interfaceName first) (configuration.ip.interfaceName last)) := by
  have edges : records.bridges = [(3,4),(4,3),(3,1),(1,3),(4,1),(1,4)] := rfl
  rw [edges] at edge
  simp only [List.mem_cons, List.not_mem_nil, or_false, Prod.mk.injEq] at edge
  rcases edge with ⟨rfl,rfl⟩ | ⟨rfl,rfl⟩ | ⟨rfl,rfl⟩ | ⟨rfl,rfl⟩ | ⟨rfl,rfl⟩ | ⟨rfl,rfl⟩
  all_goals simp [SplitBridgeAdmitted, capturedBridgeChain, LinkAdmission.lookup,
    LinkAdmission.Program.Accepts, LinkAdmission.Frame.Packet, configuration,
    Records.configuration, dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords,
    DataPlaneForwarding.ifaceAt, records, Filter.evaluate, PacketPolicy.Rule.toFilter,
    PacketPolicy.MatchCondition.matchesPacket, Bool.and_eq_true]

end TDN.Deployments.NestedProtection_Mixed
