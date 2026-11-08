import TDN.Semantics.MultiProtocolExecution
import TDN.Semantics.ExecutionProvenance

namespace TDN.MultiProtocolExecution
open LayeredFrame

def ProducedIPBodies (c : Config) : Body → Prop
  | .datagram _ | .ethernet _ => True
  | .ipsec token body => Execution.ProducedSeal c.ip token ∧ ProducedIPBodies c body
  | .macsec _ body | .carrier _ body => ProducedIPBodies c body

lemma unwrap_preserves_ip_provenance (c : Config)
    (localAddress remote sourcePort destinationPort localSession : Nat) {protocol networkProtocol : String} (before after : Body)
    (valid : ProducedIPBodies c before)
    (unwrapped : unwrapCarrier localAddress remote sourcePort destinationPort localSession before protocol networkProtocol = some after) :
    ProducedIPBodies c after := by
  cases before <;> simp only [unwrapCarrier] at unwrapped
  all_goals try cases unwrapped
  case carrier endpoint body =>
    split at unwrapped
    next matched => cases unwrapped; exact valid
    next missed => cases unwrapped

lemma step_preserves_ip_provenance {c : Config} {before after : State} {action : Action}
    (step : Step c before action after) (valid : ProducedIPBodies c before.frame.body) :
    ProducedIPBodies c after.frame.body := by
  cases step <;>
    simp only [Config.forwardedFrame_body, Config.ipsecFrame_body, Config.macsecFrame_body,
      Config.carrierFrame_body, Config.restoredFrame_body] <;> try exact valid
  case encryptIPsec policy association datapathStage visible selected installed bound =>
    exact ⟨⟨before.iface, policy, (Execution.matched_policy_is_configured selected).1,
      association, installed, bound, rfl⟩, valid⟩
  case decryptIPsec policy association body header datapathStage encrypted configured installed bound visible selected tracking =>
    rw [encrypted] at valid
    exact valid.2
  case decryptMACsec iface association transmitted body configured datapathStage physical encrypted installed wireIdentity =>
    simpa only [encrypted, ProducedIPBodies] using valid
  case decapsulate iface body configured datapathStage owner unwrapped =>
    exact unwrap_preserves_ip_provenance c _ _ _ _ _ _ _ valid unwrapped

theorem all_executions_preserve_ip_provenance (c : Config)
    {before after : State} {actions : List Action} (run : (lts c).MTr before actions after)
    (initial : ProducedIPBodies c before.frame.body) : ProducedIPBodies c after.frame.body := by
  have preservation : (lts c).TrInv (fun state => ProducedIPBodies c state.frame.body) :=
    fun _ _ _ step valid => step_preserves_ip_provenance step valid
  exact Cslib.LTS.mtrInv_of_trInv preservation before actions after run initial

theorem wire_matching_ipsec_decryption_is_admitted (c : Config)
    (agreement : Execution.PeerTagAgreement c.ip) (state : State)
    (policy : Execution.Association) (association : Execution.SecurityAssociation)
    (transmitted : Execution.Seal) (body : Body) (header : PacketPolicy.Packet)
    (datapathStage : state.datapathStage = .received)
    (encrypted : state.frame.body = .ipsec transmitted body)
    (provenance : ProducedIPBodies c state.frame.body)
    (configured : policy ∈ c.ip.inbound state.iface)
    (installed : association ∈ c.ip.inboundStates state.iface)
    (bound : Execution.StateBindsPolicy association policy)
    (wire : Execution.WireMatchesSeal transmitted association)
    (visible : body.visibleHeader = some header)
    (selected : policy.matches header = true) (tracking : String) :
    Step c state .decryptIPsec
      { state with initialEntry := false, datapathStage := .ingress, enteredIface := state.iface, frame := c.restoredFrame state.frame body, authenticated := [policy.id], tracking := tracking } := by
  have produced : Execution.ProducedSeal c.ip transmitted := by
    rw [encrypted] at provenance
    exact provenance.1
  have same := Execution.wire_match_determines_annotated_seal agreement produced state.iface
    policy configured association installed bound wire
  exact Step.decryptIPsec policy association body header datapathStage (same ▸ encrypted)
    configured installed bound visible selected tracking

end TDN.MultiProtocolExecution
