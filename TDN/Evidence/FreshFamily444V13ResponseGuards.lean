import TDN.Import.Command
import TDN.Evidence.FreshFamily444V13Witness
import TDN.Semantics.SourceResponseGuards
import TDN.Evidence.FreshFamily444V13

namespace TDN.Imported.Family444V13

tdn_data responseSourceGuards : List (Nat × List PacketPolicy.Rule) from "../../data/evidence/FreshFamily444V13ResponseGuards.json" ["TDN.Imported.Family444V13.responseSourceGuards"]

lemma all_input_interfaces_covered :
    SourceResponseGuards.FiniteGuardCoverage ifaces responseSourceGuards := by decide

lemma all_source_output_reply_pairs_checked :
    SourceResponseGuards.FiniteReplyChecks devices ifaces responseSourceGuards := by decide

theorem source_output_reply_layers
    {guard : Nat × List PacketPolicy.Rule} (guardMember : guard ∈ responseSourceGuards)
    {entry output : Execution.IfaceData} (entryMember : entry ∈ ifaces)
    (entryOwner : entry.owner = guard.1) (inputExternal : entry.name ≠ "lo")
    (outputMember : output ∈ ifaces) (owner : output.owner = entry.owner)
    (outputExternal : output.name ≠ "lo") {auth : List Nat}
    (authenticated : auth ∈ Execution.possibleAuthentications
      (Execution.deviceAt devices entry.owner) entry)
    (original reply : PacketPolicy.Packet)
    (inputName : original.ingress = entry.name) (outputName : reply.egress = output.name)
    (inputAuth : original.inboundPolicies = auth)
    (selectorBound : ∀ id ∈ auth, ∃ association ∈ (Execution.deviceAt devices entry.owner).inbound,
      association.id = id ∧ association.matches original = true)
    (address : SourceResponseGuards.ValidSourceAddress original.source)
    (inputAccepted : Filter.evaluate (guard.2.map PacketPolicy.Rule.toFilter) .allow original = .allow)
    (outputAccepted : Filter.evaluate
      ((Execution.deviceAt devices output.owner).outputRules.map PacketPolicy.Rule.toFilter) .deny reply = .allow)
    (returnsToSource : reply.destination = original.source)
    (protocol : KernelResponses.ResponseProtocol reply.protocol) :
    (if auth = [] then entry.stack else entry.stack.tail) = output.stack :=
  SourceResponseGuards.finite_reply_checks_preserve_layers
    devices ifaces responseSourceGuards all_source_output_reply_pairs_checked
    guardMember entryMember entryOwner inputExternal outputMember owner outputExternal authenticated
    original reply inputName outputName inputAuth selectorBound
    (SourceResponseGuards.finite_guard_coverage_excludes_fallback ifaces responseSourceGuards
      all_input_interfaces_covered guardMember entryMember entryOwner inputExternal original inputName address)
    inputAccepted outputAccepted returnsToSource protocol

lemma positive_source_guard_4 : Filter.evaluate ((responseSourceGuards[0]'(by decide)).2.map PacketPolicy.Rule.toFilter) .allow ({ witnessState4.frame.packet with ingress := "red", inboundPolicies := witnessState4.authenticated }) = .allow := by decide
lemma positive_source_guard_5 : Filter.evaluate ((responseSourceGuards[0]'(by decide)).2.map PacketPolicy.Rule.toFilter) .allow ({ witnessState5.frame.packet with ingress := "red", inboundPolicies := witnessState5.authenticated }) = .allow := by decide
lemma positive_source_guard_10 : Filter.evaluate ((responseSourceGuards[2]'(by decide)).2.map PacketPolicy.Rule.toFilter) .allow ({ witnessState10.frame.packet with ingress := "gray", inboundPolicies := witnessState10.authenticated }) = .allow := by decide
lemma positive_source_guard_11 : Filter.evaluate ((responseSourceGuards[2]'(by decide)).2.map PacketPolicy.Rule.toFilter) .allow ({ witnessState11.frame.packet with ingress := "gray", inboundPolicies := witnessState11.authenticated }) = .allow := by decide
lemma positive_source_guard_26 : Filter.evaluate ((responseSourceGuards[3]'(by decide)).2.map PacketPolicy.Rule.toFilter) .allow ({ witnessState26.frame.packet with ingress := "black", inboundPolicies := witnessState26.authenticated }) = .allow := by decide
lemma positive_source_guard_27 : Filter.evaluate ((responseSourceGuards[3]'(by decide)).2.map PacketPolicy.Rule.toFilter) .allow ({ witnessState27.frame.packet with ingress := "black", inboundPolicies := witnessState27.authenticated }) = .allow := by decide
lemma positive_source_guard_31 : Filter.evaluate ((responseSourceGuards[1]'(by decide)).2.map PacketPolicy.Rule.toFilter) .allow ({ witnessState31.frame.packet with ingress := "gray", inboundPolicies := witnessState31.authenticated }) = .allow := by decide
lemma positive_source_guard_32 : Filter.evaluate ((responseSourceGuards[1]'(by decide)).2.map PacketPolicy.Rule.toFilter) .allow ({ witnessState32.frame.packet with ingress := "gray", inboundPolicies := witnessState32.authenticated }) = .allow := by decide

end TDN.Imported.Family444V13
