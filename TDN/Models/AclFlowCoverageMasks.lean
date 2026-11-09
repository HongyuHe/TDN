import TDN.Models.L2FrameFilter

namespace TDN.PacketPolicy

structure AclFlowSelector where
  source : Nat
  destination : Nat
  protocol : String
  ingress : String
  egress : String
  sourcePort : Option Nat
  destinationPort : Option Nat
  ipv4HeaderWords : Option Nat
  matchedInboundPolicyIds : List Nat
  matchedOutboundPolicyIds : List Nat
  minimumBytes : Nat
  maximumBytes : Nat
  requestFraming : Bool
  replyFraming : Bool
  deriving DecidableEq

def AclFlowSelector.Matches (mask : AclFlowSelector) (packet : Packet) : Prop :=
  packet.source = mask.source ∧ packet.destination = mask.destination ∧
  packet.protocol = mask.protocol ∧ packet.ingress = mask.ingress ∧ packet.egress = mask.egress ∧
  (∀ port, mask.sourcePort = some port → packet.sourcePort = port) ∧
  (∀ port, mask.destinationPort = some port → packet.destinationPort = port) ∧
  (∀ words, mask.ipv4HeaderWords = some words → packet.ipv4HeaderWords = words) ∧
  (∀ id ∈ mask.matchedInboundPolicyIds, id ∈ packet.matchedInboundPolicyIds) ∧
  (∀ id ∈ mask.matchedOutboundPolicyIds, id ∈ packet.matchedOutboundPolicyIds) ∧
  (∃ bytes, packet.networkBytes = some bytes ∧ mask.minimumBytes ≤ bytes ∧ bytes ≤ mask.maximumBytes) ∧
  (mask.requestFraming = true → packet.IPsecUDPFramingWithOptions) ∧
  (mask.replyFraming = true → packet.IPsecUDPReplyFramingWithOptions)

def AclFlowSelector.Allows (mask : AclFlowSelector) : MatchCondition → Prop
  | .sourceRange low high => low ≤ mask.source ∧ mask.source ≤ high
  | .destinationRange low high => low ≤ mask.destination ∧ mask.destination ≤ high
  | .protocol name => mask.protocol = name
  | .ingress name => mask.ingress = name
  | .egress name => mask.egress = name
  | .sourcePorts ports => ∃ port ∈ mask.sourcePort.toList, port ∈ ports
  | .destinationPorts ports => ∃ port ∈ mask.destinationPort.toList, port ∈ ports
  | .ipv4HeaderWords words => mask.ipv4HeaderWords = some words
  | .inboundPolicy id => id ∈ mask.matchedInboundPolicyIds
  | .outboundPolicy id => id ∈ mask.matchedOutboundPolicyIds
  | .networkBytesRange low high => low ≤ mask.minimumBytes ∧ mask.maximumBytes ≤ high
  | .ipsecUDPFramingWithOptions => mask.requestFraming = true
  | .ipsecUDPReplyFramingWithOptions => mask.replyFraming = true
  | _ => False

instance (mask : AclFlowSelector) (atom : MatchCondition) : Decidable (mask.Allows atom) := by
  cases atom <;> unfold AclFlowSelector.Allows <;> infer_instance

lemma AclFlowSelector.allowed_atom_holds (mask : AclFlowSelector) (packet : Packet) (matched : mask.Matches packet)
    (atom : MatchCondition) (allowed : mask.Allows atom) : atom.matchesPacket packet := by
  obtain ⟨source, destination, protocol, ingress, egress, sourcePort, destinationPort,
    words, inbound, outbound, bytes, request, reply⟩ := matched
  cases atom <;> simp only [AclFlowSelector.Allows] at allowed
  case sourceRange low high => simpa only [MatchCondition.matchesPacket, source] using allowed
  case destinationRange low high => simpa only [MatchCondition.matchesPacket, destination] using allowed
  case protocol name => exact protocol.trans allowed
  case ingress name => exact ingress.trans allowed
  case egress name => exact egress.trans allowed
  case sourcePorts ports =>
    obtain ⟨port, selected, present⟩ := allowed
    change packet.sourcePort ∈ ports
    rw [sourcePort port (by simpa using selected)]
    exact present
  case destinationPorts ports =>
    obtain ⟨port, selected, present⟩ := allowed
    change packet.destinationPort ∈ ports
    rw [destinationPort port (by simpa using selected)]
    exact present
  case ipv4HeaderWords value => exact words value allowed
  case inboundPolicy id => exact inbound id allowed
  case outboundPolicy id => exact outbound id allowed
  case networkBytesRange low high =>
    obtain ⟨size, selected, lower, upper⟩ := bytes
    exact ⟨size, selected, allowed.1.trans lower, upper.trans allowed.2⟩
  case ipsecUDPFramingWithOptions => exact request allowed
  case ipsecUDPReplyFramingWithOptions => exact reply allowed

def AclFlowSelector.Rejects (mask : AclFlowSelector) : MatchCondition → Prop
  | .sourceRange low high => mask.source < low ∨ high < mask.source
  | .destinationRange low high => mask.destination < low ∨ high < mask.destination
  | .protocol name => mask.protocol ≠ name
  | .ingress name => mask.ingress ≠ name
  | .egress name => mask.egress ≠ name
  | .sourcePorts ports => ∃ port ∈ mask.sourcePort.toList, port ∉ ports
  | .destinationPorts ports => ∃ port ∈ mask.destinationPort.toList, port ∉ ports
  | .ipv4HeaderWords words => ∃ actual ∈ mask.ipv4HeaderWords.toList, actual ≠ words
  | .networkBytesRange low high => mask.maximumBytes < low ∨ high < mask.minimumBytes
  | _ => False

instance (mask : AclFlowSelector) (atom : MatchCondition) : Decidable (mask.Rejects atom) := by
  cases atom <;> unfold AclFlowSelector.Rejects <;> infer_instance

lemma AclFlowSelector.rejected_atom_fails (mask : AclFlowSelector) (packet : Packet) (matched : mask.Matches packet)
    (atom : MatchCondition) (rejected : mask.Rejects atom) : ¬ atom.matchesPacket packet := by
  obtain ⟨source, destination, protocol, ingress, egress, sourcePort, destinationPort,
    words, _, _, bytes, _, _⟩ := matched
  cases atom <;> simp only [AclFlowSelector.Rejects] at rejected
  case sourceRange low high => simp only [MatchCondition.matchesPacket, source]; omega
  case destinationRange low high => simp only [MatchCondition.matchesPacket, destination]; omega
  case protocol name => simpa only [MatchCondition.matchesPacket, protocol] using rejected
  case ingress name => simpa only [MatchCondition.matchesPacket, ingress] using rejected
  case egress name => simpa only [MatchCondition.matchesPacket, egress] using rejected
  case sourcePorts ports =>
    obtain ⟨port, selected, missing⟩ := rejected
    change packet.sourcePort ∉ ports
    rw [show packet.sourcePort = port from sourcePort port (by simpa using selected)]
    exact missing
  case destinationPorts ports =>
    obtain ⟨port, selected, missing⟩ := rejected
    change packet.destinationPort ∉ ports
    rw [show packet.destinationPort = port from destinationPort port (by simpa using selected)]
    exact missing
  case ipv4HeaderWords value =>
    obtain ⟨actual, selected, different⟩ := rejected
    change packet.ipv4HeaderWords ≠ value
    rw [show packet.ipv4HeaderWords = actual from words actual (by simpa using selected)]
    exact different
  case networkBytesRange low high =>
    obtain ⟨size, selected, lower, upper⟩ := bytes
    rintro ⟨actual, same, lowerActual, upperActual⟩
    have equal := Option.some.inj (selected.symm.trans same)
    omega

def AclFlowSelector.IsPermittedByAclChain (mask : AclFlowSelector) : List Rule → Prop
  | [] => False
  | rule :: rest =>
      (rule.verdict = .allow ∧ ∀ atom ∈ rule.atoms, mask.Allows atom) ∨
      ((rule.verdict = .allow ∨ ∃ atom ∈ rule.atoms, mask.Rejects atom) ∧ mask.IsPermittedByAclChain rest)

def AclFlowSelector.checkPermittedByAclChain (mask : AclFlowSelector) : List Rule → Bool
  | [] => false
  | rule :: rest =>
      (decide (rule.verdict = .allow) && rule.atoms.all (fun atom => decide (mask.Allows atom))) ||
      ((decide (rule.verdict = .allow) || rule.atoms.any (fun atom => decide (mask.Rejects atom))) &&
        mask.checkPermittedByAclChain rest)

lemma AclFlowSelector.finiteCovers_correct (mask : AclFlowSelector) (rules : List Rule) :
    mask.checkPermittedByAclChain rules = true ↔ mask.IsPermittedByAclChain rules := by
  induction rules with
  | nil => simp [AclFlowSelector.checkPermittedByAclChain, AclFlowSelector.IsPermittedByAclChain]
  | cons rule rest ih =>
    simp only [AclFlowSelector.checkPermittedByAclChain, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq,
      List.all_eq_true, List.any_eq_true, ih, AclFlowSelector.IsPermittedByAclChain]

instance (mask : AclFlowSelector) (rules : List Rule) : Decidable (mask.IsPermittedByAclChain rules) :=
  decidable_of_iff (mask.checkPermittedByAclChain rules = true) (mask.finiteCovers_correct rules)

theorem AclFlowSelector.covered_packets_are_allowed (mask : AclFlowSelector) (rules : List Rule)
    (covered : mask.IsPermittedByAclChain rules) (fallback : Filter.Verdict) (packet : Packet)
    (matched : mask.Matches packet) :
    Filter.evaluate (rules.map Rule.toFilter) fallback packet = .allow := by
  induction rules with
  | nil => exact False.elim covered
  | cons rule rest ih =>
    rcases covered with ⟨allow, atoms⟩ | ⟨earlier, later⟩
    · have ruleMatches : rule.toFilter.accepts packet = true := by
        apply List.all_eq_true.mpr
        intro atom member
        exact decide_eq_true (mask.allowed_atom_holds packet matched atom (atoms atom member))
      simp only [List.map_cons, Filter.evaluate, ruleMatches, ↓reduceIte]
      exact allow
    · simp only [List.map_cons, Filter.evaluate]
      split
      next ruleMatches =>
        rcases earlier with allow | ⟨atom, member, excluded⟩
        · exact allow
        · exact False.elim (mask.rejected_atom_fails packet matched atom excluded
            (matching_atom ruleMatches member))
      next missed => exact ih later

end TDN.PacketPolicy
