import TDN.Semantics.ByteFlows
import TDN.Semantics.KernelResponses

namespace TDN.ResponseByteFlows

def source {S B : Type} (origin : S → B → Prop) :
    KernelResponses.State S → B → Prop
  | .network state, byte => origin state byte
  | _, _ => False

def assembly {S : Type} (canAssemble : S → S → Prop) :
    KernelResponses.State S → KernelResponses.State S → Prop
  | .network before, .network after => canAssemble before after
  | _, _ => False

def system {S B A : Type} (network : Cslib.LTS S A) (responses : KernelResponses.Config S)
    (origin : S → B → Prop) (canAssemble : S → S → Prop) :=
  ByteFlows.lts (KernelResponses.lts network responses) (source origin) (assembly canAssemble)

lemma assembled_response_state_preserves {S B : Type} (responses : KernelResponses.Config S)
    (canAssemble : S → S → Prop) (property : B → S → Prop)
    (preserved : ∀ before after byte, canAssemble before after →
      property byte before → property byte after)
    {before after : KernelResponses.State S} (byte : B)
    (compatible : assembly canAssemble before after)
    (safe : KernelResponses.Invariant responses (property byte) before) :
    KernelResponses.Invariant responses (property byte) after := by
  cases before <;> cases after <;> simp only [assembly] at compatible <;> try contradiction
  exact preserved _ _ byte compatible safe

theorem all_fragment_and_response_histories_preserve_bytes {S B A : Type}
    (network : Cslib.LTS S A) (responses : KernelResponses.Config S)
    (origin : S → B → Prop) (canAssemble : S → S → Prop)
    (property : B → S → Prop)
    (injection : ∀ state byte, origin state byte → property byte state)
    (forwarding : ∀ byte, network.TrInv (property byte))
    (reassembly : ∀ before after byte, canAssemble before after →
      property byte before → property byte after)
    (guards : ∀ state, responses.generates state → ∀ iface,
      responses.outputFallback state iface = .deny ∧
      ∀ rule ∈ responses.outputRules state iface,
        rule.verdict = .allow → KernelResponses.SafeResponseRule rule)
    {after : List (ByteFlows.Carrier (KernelResponses.State S) B)}
    {actions : List (ByteFlows.Action (KernelResponses.Action A))}
    (run : (system network responses origin canAssemble).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.Invariant responses (property byte)) after := by
  refine ByteFlows.all_executions_preserve_byte_properties
    (KernelResponses.lts network responses) (source origin) (assembly canAssemble)
    (fun byte => KernelResponses.Invariant responses (property byte)) ?_ ?_ ?_ run ?_
  · intro state byte starts
    cases state <;> simp only [source] at starts <;> try contradiction
    exact injection _ byte starts
  · intro byte
    exact KernelResponses.response_output_guards_preserve_network_invariant
      network responses (property byte) (forwarding byte) guards
  · intro before after byte compatible safe
    exact assembled_response_state_preserves responses canAssemble property reassembly
      byte compatible safe
  · simp [ByteFlows.Safe]

theorem all_fragment_and_permitted_response_histories_preserve_bytes {S B A : Type}
    (network : Cslib.LTS S A) (responses : KernelResponses.Config S)
    (origin : S → B → Prop) (canAssemble : S → S → Prop)
    (property : B → S → Prop)
    (injection : ∀ state byte, origin state byte → property byte state)
    (forwarding : ∀ byte, network.TrInv (property byte))
    (reassembly : ∀ before after byte, canAssemble before after →
      property byte before → property byte after)
    (reply : ∀ byte state header iface,
      property byte state → responses.generates state →
      KernelResponses.ResponseProtocol header.protocol →
      responses.selectedRoute state header iface →
      Filter.evaluate ((responses.outputRules state iface).map PacketPolicy.Rule.toFilter)
        (responses.outputFallback state iface) (KernelResponses.outputPacket responses header iface) = .allow →
      responses.interfaceName iface ≠ "lo" → property byte (responses.emit state header iface))
    {after : List (ByteFlows.Carrier (KernelResponses.State S) B)}
    {actions : List (ByteFlows.Action (KernelResponses.Action A))}
    (run : (system network responses origin canAssemble).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.ProvenanceInvariant responses (property byte)) after := by
  refine ByteFlows.all_executions_preserve_byte_properties
    (KernelResponses.lts network responses) (source origin) (assembly canAssemble)
    (fun byte => KernelResponses.ProvenanceInvariant responses (property byte)) ?_ ?_ ?_ run ?_
  · intro state byte starts
    cases state <;> simp only [source] at starts <;> try contradiction
    exact injection _ byte starts
  · intro byte
    exact KernelResponses.local_reply_checks_preserve_network_safety
      network responses (property byte) (forwarding byte) (reply byte)
  · intro before after byte compatible safe
    cases before <;> cases after <;> simp only [assembly] at compatible <;> try contradiction
    exact reassembly _ _ byte compatible safe
  · simp [ByteFlows.Safe]

end TDN.ResponseByteFlows
