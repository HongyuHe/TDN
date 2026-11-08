import TDN.Semantics.KernelResponses
import TDN.Semantics.FiniteExecution
import TDN.Semantics.AuthenticationSelectors

namespace TDN.SourceResponseGuards

lemma fallback_irrelevant {Packet : Type} (rules : List (Filter.Rule Packet))
    (packet : Packet) (covered : ∃ rule ∈ rules, rule.accepts packet = true)
    (first second : Filter.Verdict) :
    Filter.evaluate rules first packet = Filter.evaluate rules second packet := by
  induction rules with
  | nil => simp at covered
  | cons rule rest ih =>
    simp only [Filter.evaluate]
    split
    · rfl
    · apply ih
      obtain ⟨chosen, member, matched⟩ := covered
      rcases List.mem_cons.mp member with same | tail
      · subst chosen
        contradiction
      · exact ⟨chosen, tail, matched⟩

def WrongIngress (rule : PacketPolicy.Rule) (name : String) : Prop :=
  ∃ atom ∈ rule.atoms, match atom with
    | .ingress expected => expected ≠ name
    | _ => False

def WrongEgress (rule : PacketPolicy.Rule) (name : String) : Prop :=
  ∃ atom ∈ rule.atoms, match atom with
    | .egress expected => expected ≠ name
    | _ => False

def NonResponseProtocol (rule : PacketPolicy.Rule) : Prop :=
  ∃ atom ∈ rule.atoms, match atom with
    | .protocol name => ¬ KernelResponses.ResponseProtocol name
    | _ => False

def DisjointReplyAddress (source output : PacketPolicy.Rule) : Prop :=
  ∃ a ∈ source.atoms, ∃ b ∈ output.atoms, match a, b with
    | .sourceRange low high, .destinationRange otherLow otherHigh =>
        high < otherLow ∨ otherHigh < low
    | _, _ => False

instance (rule : PacketPolicy.Rule) (name : String) : Decidable (WrongIngress rule name) := by
  unfold WrongIngress
  letI (a : PacketPolicy.Atom) : Decidable (match a with
    | .ingress expected => expected ≠ name | _ => False) := by cases a <;> infer_instance
  infer_instance

instance (rule : PacketPolicy.Rule) (name : String) : Decidable (WrongEgress rule name) := by
  unfold WrongEgress
  letI (a : PacketPolicy.Atom) : Decidable (match a with
    | .egress expected => expected ≠ name | _ => False) := by cases a <;> infer_instance
  infer_instance

instance (rule : PacketPolicy.Rule) : Decidable (NonResponseProtocol rule) := by
  unfold NonResponseProtocol
  letI (a : PacketPolicy.Atom) : Decidable (match a with
    | .protocol name => ¬ KernelResponses.ResponseProtocol name | _ => False) := by
      cases a <;> infer_instance
  infer_instance

instance (source output : PacketPolicy.Rule) : Decidable (DisjointReplyAddress source output) := by
  unfold DisjointReplyAddress
  letI (a b : PacketPolicy.Atom) : Decidable (match a, b with
    | .sourceRange low high, .destinationRange otherLow otherHigh =>
        high < otherLow ∨ otherHigh < low
    | _, _ => False) := by cases a <;> cases b <;> infer_instance
  infer_instance

def PairCheck (ingress egress : String) (authenticated sourceLayers outputLayers : List Nat)
    (source output : PacketPolicy.Rule) : Prop :=
  sourceLayers = outputLayers ∨ WrongIngress source ingress ∨ WrongEgress output egress ∨
    Execution.ImpossibleAuthentication source authenticated ∨ NonResponseProtocol output ∨
    DisjointReplyAddress source output

instance (ingress egress : String) (authenticated sourceLayers outputLayers : List Nat)
    (source output : PacketPolicy.Rule) :
    Decidable (PairCheck ingress egress authenticated sourceLayers outputLayers source output) := by
  unfold PairCheck
  infer_instance

lemma checked_pair_preserves_layers
    {source output : PacketPolicy.Rule} {original reply : PacketPolicy.Packet}
    {sourceLayers outputLayers : List Nat}
    (checked : PairCheck original.ingress reply.egress original.inboundPolicies
      sourceLayers outputLayers source output)
    (inputMatched : source.toFilter.accepts original = true)
    (outputMatched : output.toFilter.accepts reply = true)
    (returnsToSource : reply.destination = original.source)
    (protocol : KernelResponses.ResponseProtocol reply.protocol) :
    sourceLayers = outputLayers := by
  rcases checked with same | wrongInput | wrongOutput | wrongAuth | wrongProtocol | disjoint
  · exact same
  · obtain ⟨atom, member, wrong⟩ := wrongInput
    have holds := PacketPolicy.matching_atom inputMatched member
    cases atom <;> simp_all [PacketPolicy.Atom.holds]
  · obtain ⟨atom, member, wrong⟩ := wrongOutput
    have holds := PacketPolicy.matching_atom outputMatched member
    cases atom <;> simp_all [PacketPolicy.Atom.holds]
  · exact False.elim (Execution.matching_authentication_possible inputMatched wrongAuth)
  · obtain ⟨atom, member, wrong⟩ := wrongProtocol
    have holds := PacketPolicy.matching_atom outputMatched member
    cases atom <;> simp_all [PacketPolicy.Atom.holds]
  · obtain ⟨a, memberA, b, memberB, conflict⟩ := disjoint
    have holdsA := PacketPolicy.matching_atom inputMatched memberA
    have holdsB := PacketPolicy.matching_atom outputMatched memberB
    cases a <;> cases b <;> simp only at conflict <;> try contradiction
    simp only [PacketPolicy.Atom.holds] at holdsA holdsB
    omega

theorem ordered_reply_checks_preserve_layers
    (sourceRules outputRules : List PacketPolicy.Rule) (sourceFallback : Filter.Verdict)
    (original reply : PacketPolicy.Packet) (sourceLayers outputLayers : List Nat)
    (checked : ∀ source ∈ sourceRules, source.verdict = .allow →
      ∀ output ∈ outputRules, output.verdict = .allow →
      PairCheck original.ingress reply.egress original.inboundPolicies
        sourceLayers outputLayers source output)
    (covered : ∃ rule ∈ sourceRules, rule.toFilter.accepts original = true)
    (inputAccepted : Filter.evaluate (sourceRules.map PacketPolicy.Rule.toFilter)
      sourceFallback original = .allow)
    (outputAccepted : Filter.evaluate (outputRules.map PacketPolicy.Rule.toFilter) .deny reply = .allow)
    (returnsToSource : reply.destination = original.source)
    (protocol : KernelResponses.ResponseProtocol reply.protocol) :
    sourceLayers = outputLayers := by
  have converted := fallback_irrelevant (sourceRules.map PacketPolicy.Rule.toFilter) original
    (by obtain ⟨rule, member, matched⟩ := covered
        exact ⟨rule.toFilter, List.mem_map.mpr ⟨rule, member, rfl⟩, matched⟩)
    sourceFallback .deny
  rw [converted] at inputAccepted
  obtain ⟨source, inSource, sourceMatches, sourceAllows⟩ :=
    Filter.allowed_has_matching_allow _ _ inputAccepted
  obtain ⟨sourceRule, memberSource, rfl⟩ := List.mem_map.mp inSource
  obtain ⟨output, inOutput, outputMatches, outputAllows⟩ :=
    Filter.allowed_has_matching_allow _ _ outputAccepted
  obtain ⟨outputRule, memberOutput, rfl⟩ := List.mem_map.mp inOutput
  exact checked_pair_preserves_layers
    (checked sourceRule memberSource sourceAllows outputRule memberOutput outputAllows)
    sourceMatches outputMatches returnsToSource protocol

def ReplyExcludesSelector (output : PacketPolicy.Rule) (association : Execution.Association) : Prop :=
  ∃ atom ∈ output.atoms, match atom with
    | .destinationRange low high => high < association.sourceLow ∨ association.sourceHigh < low
    | _ => False

instance (output : PacketPolicy.Rule) (association : Execution.Association) :
    Decidable (ReplyExcludesSelector output association) := by
  unfold ReplyExcludesSelector
  letI (a : PacketPolicy.Atom) : Decidable (match a with
    | .destinationRange low high => high < association.sourceLow ∨ association.sourceHigh < low
    | _ => False) := by cases a <;> infer_instance
  infer_instance

def AuthenticationReplyConflict (device : Execution.DeviceData) (auth : List Nat)
    (output : PacketPolicy.Rule) : Prop :=
  ∃ id ∈ auth, ∀ association ∈ device.inbound, association.id = id →
    ReplyExcludesSelector output association

instance (device : Execution.DeviceData) (auth : List Nat) (output : PacketPolicy.Rule) :
    Decidable (AuthenticationReplyConflict device auth output) := by
  unfold AuthenticationReplyConflict
  infer_instance

lemma authenticated_reply_cannot_match
    {device : Execution.DeviceData} {auth : List Nat} {output : PacketPolicy.Rule}
    {original reply : PacketPolicy.Packet}
    (conflict : AuthenticationReplyConflict device auth output)
    (bound : ∀ id ∈ auth, ∃ association ∈ device.inbound,
      association.id = id ∧ association.matches original = true)
    (returnsToSource : reply.destination = original.source)
    (matched : output.toFilter.accepts reply = true) : False := by
  obtain ⟨id, member, excludes⟩ := conflict
  obtain ⟨association, configured, same, selected⟩ := bound id member
  obtain ⟨atom, inRule, disjoint⟩ := excludes association configured same
  have holds := PacketPolicy.matching_atom matched inRule
  cases atom <;> simp only at disjoint <;> try contradiction
  simp only [PacketPolicy.Atom.holds] at holds
  unfold Execution.Association.matches at selected
  have interval := of_decide_eq_true selected
  omega

def FiniteReplyChecks (devices : List Execution.DeviceData) (ifaces : List Execution.IfaceData)
    (guards : List (Nat × List PacketPolicy.Rule)) : Prop :=
  ∀ guard ∈ guards, ∀ entry ∈ ifaces, entry.owner = guard.1 → entry.name ≠ "lo" →
    ∀ output ∈ ifaces, output.owner = entry.owner → output.name ≠ "lo" →
      ∀ auth ∈ Execution.possibleAuthentications (Execution.deviceAt devices entry.owner) entry,
      ∀ source ∈ guard.2, source.verdict = .allow →
      ∀ rule ∈ (Execution.deviceAt devices output.owner).outputRules, rule.verdict = .allow →
        PairCheck entry.name output.name auth
          (if auth = [] then entry.stack else entry.stack.tail) output.stack source rule ∨
        AuthenticationReplyConflict (Execution.deviceAt devices entry.owner) auth rule

instance (devices : List Execution.DeviceData) (ifaces : List Execution.IfaceData)
    (guards : List (Nat × List PacketPolicy.Rule)) :
    Decidable (FiniteReplyChecks devices ifaces guards) := by
  unfold FiniteReplyChecks
  infer_instance

theorem finite_reply_checks_preserve_layers
    (devices : List Execution.DeviceData) (ifaces : List Execution.IfaceData)
    (guards : List (Nat × List PacketPolicy.Rule))
    (checked : FiniteReplyChecks devices ifaces guards)
    {guard : Nat × List PacketPolicy.Rule} (guardMember : guard ∈ guards)
    {entry output : Execution.IfaceData} (entryMember : entry ∈ ifaces)
    (entryOwner : entry.owner = guard.1) (inputExternal : entry.name ≠ "lo")
    (outputMember : output ∈ ifaces) (owner : output.owner = entry.owner)
    (outputExternal : output.name ≠ "lo")
    {auth : List Nat}
    (authenticated : auth ∈ Execution.possibleAuthentications
      (Execution.deviceAt devices entry.owner) entry)
    (original reply : PacketPolicy.Packet)
    (inputName : original.ingress = entry.name) (outputName : reply.egress = output.name)
    (inputAuth : original.inboundPolicies = auth)
    (selectorBound : ∀ id ∈ auth, ∃ association ∈ (Execution.deviceAt devices entry.owner).inbound,
      association.id = id ∧ association.matches original = true)
    (covered : ∃ rule ∈ guard.2, rule.toFilter.accepts original = true)
    (inputAccepted : Filter.evaluate (guard.2.map PacketPolicy.Rule.toFilter) .allow original = .allow)
    (outputAccepted : Filter.evaluate
      ((Execution.deviceAt devices output.owner).outputRules.map PacketPolicy.Rule.toFilter) .deny reply = .allow)
    (returnsToSource : reply.destination = original.source)
    (protocol : KernelResponses.ResponseProtocol reply.protocol) :
    (if auth = [] then entry.stack else entry.stack.tail) = output.stack := by
  have converted := fallback_irrelevant (guard.2.map PacketPolicy.Rule.toFilter) original
    (by obtain ⟨rule, member, matched⟩ := covered
        exact ⟨rule.toFilter, List.mem_map.mpr ⟨rule, member, rfl⟩, matched⟩) .allow .deny
  rw [converted] at inputAccepted
  obtain ⟨source, inSource, sourceMatches, sourceAllows⟩ :=
    Filter.allowed_has_matching_allow _ _ inputAccepted
  obtain ⟨sourceRule, memberSource, rfl⟩ := List.mem_map.mp inSource
  obtain ⟨rule, inOutput, outputMatches, outputAllows⟩ :=
    Filter.allowed_has_matching_allow _ _ outputAccepted
  obtain ⟨outputRule, memberOutput, rfl⟩ := List.mem_map.mp inOutput
  rcases checked guard guardMember entry entryMember entryOwner inputExternal
    output outputMember owner outputExternal auth authenticated
    sourceRule memberSource sourceAllows outputRule memberOutput outputAllows with pair | conflict
  · apply checked_pair_preserves_layers ?_ sourceMatches outputMatches returnsToSource protocol
    simpa [inputName, outputName, inputAuth] using pair
  · exact False.elim
      (authenticated_reply_cannot_match conflict selectorBound returnsToSource outputMatches)

def CoverageRule (rule : PacketPolicy.Rule) (ingress : String) (low high : Nat) : Prop :=
  ∀ atom ∈ rule.atoms, match atom with
    | .ingress name => name = ingress
    | .sourceRange first last => first ≤ low ∧ high ≤ last
    | _ => False

instance (rule : PacketPolicy.Rule) (ingress : String) (low high : Nat) :
    Decidable (CoverageRule rule ingress low high) := by
  unfold CoverageRule
  letI (a : PacketPolicy.Atom) : Decidable (match a with
    | .ingress name => name = ingress
    | .sourceRange first last => first ≤ low ∧ high ≤ last
    | _ => False) := by cases a <;> infer_instance
  infer_instance

lemma coverage_rule_matches {rule : PacketPolicy.Rule} {packet : PacketPolicy.Packet}
    {low high : Nat} (checked : CoverageRule rule packet.ingress low high)
    (bounds : low ≤ packet.source ∧ packet.source ≤ high) :
    rule.toFilter.accepts packet = true := by
  apply List.all_eq_true.mpr
  intro atom member
  apply decide_eq_true
  have condition := checked atom member
  cases atom <;> simp only at condition <;> try contradiction
  · simp only [PacketPolicy.Atom.holds]
    omega
  · simpa [PacketPolicy.Atom.holds] using condition.symm

def ValidSourceAddress (source : Nat) : Prop :=
  source ≤ 2^32 - 1 ∨ (2^128 ≤ source ∧ source ≤ 2 * 2^128 - 1)

def FiniteGuardCoverage (ifaces : List Execution.IfaceData)
    (guards : List (Nat × List PacketPolicy.Rule)) : Prop :=
  ∀ guard ∈ guards, ∀ entry ∈ ifaces, entry.owner = guard.1 → entry.name ≠ "lo" →
    (∃ rule ∈ guard.2, CoverageRule rule entry.name 0 (2^32 - 1)) ∧
    (∃ rule ∈ guard.2, CoverageRule rule entry.name (2^128) (2 * 2^128 - 1))

instance (ifaces : List Execution.IfaceData) (guards : List (Nat × List PacketPolicy.Rule)) :
    Decidable (FiniteGuardCoverage ifaces guards) := by
  unfold FiniteGuardCoverage
  infer_instance

theorem finite_guard_coverage_excludes_fallback
    (ifaces : List Execution.IfaceData) (guards : List (Nat × List PacketPolicy.Rule))
    (checked : FiniteGuardCoverage ifaces guards)
    {guard : Nat × List PacketPolicy.Rule} (guardMember : guard ∈ guards)
    {entry : Execution.IfaceData} (entryMember : entry ∈ ifaces)
    (owner : entry.owner = guard.1) (external : entry.name ≠ "lo")
    (packet : PacketPolicy.Packet) (inputName : packet.ingress = entry.name)
    (address : ValidSourceAddress packet.source) :
    ∃ rule ∈ guard.2, rule.toFilter.accepts packet = true := by
  have coverage := checked guard guardMember entry entryMember owner external
  rcases address with ipv4 | ipv6
  · obtain ⟨rule, member, covers⟩ := coverage.1
    exact ⟨rule, member, coverage_rule_matches (by simpa [inputName] using covers)
      ⟨Nat.zero_le _, ipv4⟩⟩
  · obtain ⟨rule, member, covers⟩ := coverage.2
    exact ⟨rule, member, coverage_rule_matches (by simpa [inputName] using covers) ipv6⟩

end TDN.SourceResponseGuards
