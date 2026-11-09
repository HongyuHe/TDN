import TDN.Models.PerHopForwardingChecks

namespace TDN.DataPlaneForwarding

def EarlierSizeGuard (rule : PacketPolicy.Rule) (egress : String) (limit : Nat) : Prop :=
  rule.verdict = .deny ∧ match rule.atoms with
  | [.egress name, .networkBytesRange low high] => name = egress ∧ low ≤ limit + 1 ∧ high = 65535
  | _ => False

instance (rule : PacketPolicy.Rule) (egress : String) (limit : Nat) :
    Decidable (EarlierSizeGuard rule egress limit) := by
  unfold EarlierSizeGuard
  split <;> infer_instance


def SizeBoundAtom (authenticationLimit : Nat → Nat) (limit : Nat) : PacketPolicy.MatchCondition → Prop
  | .networkBytesRange _ high => high ≤ limit
  | .inboundPolicy requestId => authenticationLimit requestId ≤ limit
  | _ => False

instance (authenticationLimit : Nat → Nat) (limit : Nat) (atom : PacketPolicy.MatchCondition) :
    Decidable (SizeBoundAtom authenticationLimit limit atom) := by
  cases atom <;> unfold SizeBoundAtom <;> infer_instance


def RuleSizeBound (earlier : List PacketPolicy.Rule) (rule : PacketPolicy.Rule)
    (egress : String) (authenticationLimit : Nat → Nat) (limit : Nat) : Prop :=
  (∃ atom ∈ rule.atoms, SizeBoundAtom authenticationLimit limit atom) ∨
  ∃ guard ∈ earlier, EarlierSizeGuard guard egress limit

instance (earlier : List PacketPolicy.Rule) (rule : PacketPolicy.Rule)
    (egress : String) (authenticationLimit : Nat → Nat) (limit : Nat) :
    Decidable (RuleSizeBound earlier rule egress authenticationLimit limit) := by
  unfold RuleSizeBound
  infer_instance


def RouteExcludesPolicy (route : FibRoute) (policy : IpsecPolicy) : Prop :=
  route.destPrefixHigh < policy.destinationLow ∨ policy.destinationHigh < route.destPrefixLow

instance (route : FibRoute) (policy : IpsecPolicy) : Decidable (RouteExcludesPolicy route policy) := by
  unfold RouteExcludesPolicy
  infer_instance

lemma route_and_policy_overlap {route : FibRoute} {policy : IpsecPolicy} {packet : PacketPolicy.Packet}
    (routed : route.matches packet) (selected : policy.matches packet = true) :
    ¬ RouteExcludesPolicy route policy := by
  simp only [RouteExcludesPolicy, FibRoute.matches, IpsecPolicy.matches, decide_eq_true_eq] at *
  omega

lemma checked_rule_size_bound (earlier : List PacketPolicy.Rule) (rule : PacketPolicy.Rule)
    (packet : PacketPolicy.Packet) (authenticationLimit : Nat → Nat) (limit bytes : Nat)
    (bound : RuleSizeBound earlier rule packet.egress authenticationLimit limit)
    (matched : rule.toFilter.accepts packet = true)
    (misses : ∀ prior ∈ earlier, prior.toFilter.accepts packet = false)
    (length : packet.networkBytes = some bytes) (maximum : bytes ≤ 65535)
    (authenticated : ∀ requestId ∈ packet.matchedInboundPolicyIds, bytes ≤ authenticationLimit requestId) :
    bytes ≤ limit := by
  rcases bound with ⟨atom, member, kind⟩ | ⟨guard, member, kind⟩
  · have holds := PacketPolicy.matching_atom matched member
    cases atom <;> simp only [SizeBoundAtom] at kind <;> try contradiction
    case networkBytesRange low high =>
      obtain ⟨actual, same, _, upper⟩ := holds
      have equal := Option.some.inj (length.symm.trans same)
      omega
    case inboundPolicy requestId => exact (authenticated requestId holds).trans kind
  · by_contra oversized
    have guardMatches : guard.toFilter.accepts packet = true := by
      obtain ⟨deny, guardShape⟩ := kind
      cases atoms : guard.atoms with
      | nil => simp [atoms] at guardShape
      | cons first rest =>
        cases rest with
        | nil => simp [atoms] at guardShape
        | cons second rest =>
          cases rest with
          | cons third rest => simp [atoms] at guardShape
          | nil =>
            cases first <;> cases second <;> simp only [atoms] at guardShape <;> try contradiction
            obtain ⟨name, lower, upper⟩ := guardShape
            simp only [PacketPolicy.Rule.toFilter, atoms, List.all_cons, List.all_nil,
              Bool.and_true, Bool.and_eq_true, PacketPolicy.MatchCondition.matchesPacket, decide_eq_true_eq]
            exact ⟨decide_eq_true name.symm,
              decide_eq_true ⟨bytes, length, by omega, by simpa [upper] using maximum⟩⟩
    rw [misses guard member] at guardMatches
    contradiction


def SizedRuleCheck (earlier : List PacketPolicy.Rule) (rule : PacketPolicy.Rule)
    (route : FibRoute) (ingress egress : String) (required : Bool)
    (mtu : Nat) (outbound : List IpsecPolicy) (authenticationLimit plaintextLimit : Nat → Nat) : Prop :=
  ¬ IfaceCompatible rule ingress egress ∨
  ((required = true → RuleSizeBound earlier rule egress authenticationLimit mtu) ∧
    ∀ policy ∈ outbound,
      ExcludesSelector rule policy ∨ RouteExcludesPolicy route policy ∨
        RuleSizeBound earlier rule egress authenticationLimit (plaintextLimit policy.tag))


def SizedProgramChecks (earlier : List PacketPolicy.Rule) : List PacketPolicy.Rule →
    FibRoute → String → String → Bool → Nat → List IpsecPolicy → (Nat → Nat) → (Nat → Nat) → Prop
  | [], _, _, _, _, _, _, _, _ => True
  | rule :: rest, route, ingress, egress, required, mtu, outbound, authenticationLimit, plaintextLimit =>
      (rule.verdict = .allow → SizedRuleCheck earlier rule route ingress egress required mtu outbound
        authenticationLimit plaintextLimit) ∧
      SizedProgramChecks (earlier ++ [rule]) rest route ingress egress required mtu outbound
        authenticationLimit plaintextLimit

instance (earlier : List PacketPolicy.Rule) (rule : PacketPolicy.Rule)
    (route : FibRoute) (ingress egress : String) (required : Bool)
    (mtu : Nat) (outbound : List IpsecPolicy) (authenticationLimit plaintextLimit : Nat → Nat) :
    Decidable (SizedRuleCheck earlier rule route ingress egress required mtu outbound authenticationLimit plaintextLimit) := by
  unfold SizedRuleCheck
  infer_instance

instance (earlier rules : List PacketPolicy.Rule) (route : FibRoute) (ingress egress : String)
    (required : Bool) (mtu : Nat) (outbound : List IpsecPolicy)
    (authenticationLimit plaintextLimit : Nat → Nat) :
    Decidable (SizedProgramChecks earlier rules route ingress egress required mtu outbound
      authenticationLimit plaintextLimit) := by
  induction rules generalizing earlier with
  | nil => exact isTrue True.intro
  | cons rule rest ih =>
    change Decidable ((_ → _) ∧ _)
    exact instDecidableAnd


theorem checked_program_size_bounds (earlier rules : List PacketPolicy.Rule)
    (route : FibRoute) (ingress egress : String) (required : Bool)
    (mtu : Nat) (outbound : List IpsecPolicy) (authenticationLimit plaintextLimit : Nat → Nat)
    (checked : SizedProgramChecks earlier rules route ingress egress required mtu outbound
      authenticationLimit plaintextLimit)
    (packet : PacketPolicy.Packet) (bytes : Nat)
    (entry : packet.ingress = ingress) (exit : packet.egress = egress)
    (routed : route.matches packet) (length : packet.networkBytes = some bytes)
    (maximum : bytes ≤ 65535)
    (authenticated : ∀ requestId ∈ packet.matchedInboundPolicyIds, bytes ≤ authenticationLimit requestId)
    (misses : ∀ prior ∈ earlier, prior.toFilter.accepts packet = false)
    (accepted : accepts rules .deny packet) :
    (required = true → bytes ≤ mtu) ∧
    ∀ policy ∈ outbound, policy.matches packet = true → bytes ≤ plaintextLimit policy.tag := by
  induction rules generalizing earlier with
  | nil => cases accepted
  | cons rule rest ih =>
    change (if rule.toFilter.accepts packet then rule.verdict else
      Filter.evaluate (rest.map PacketPolicy.Rule.toFilter) .deny packet) = .allow at accepted
    split at accepted
    next matched =>
      rcases checked.1 accepted with incompatible | bounds
      · exact False.elim (incompatible (by simpa only [entry, exit] using matched_ifaces_compatible matched))
      · refine ⟨?_, ?_⟩
        · intro needed
          have bound := bounds.1 needed
          rw [← exit] at bound
          exact checked_rule_size_bound earlier rule packet authenticationLimit mtu bytes
            bound matched misses length maximum authenticated
        · intro policy member selected
          rcases bounds.2 policy member with excluded | excluded | bound
          · exact False.elim (by have fails := excluded_selector_cannot_match excluded matched; rw [selected] at fails; contradiction)
          · exact False.elim (route_and_policy_overlap routed selected excluded)
          · rw [← exit] at bound
            exact checked_rule_size_bound earlier rule packet authenticationLimit (plaintextLimit policy.tag) bytes
              bound matched misses length maximum authenticated
    next missed =>
      apply ih (earlier ++ [rule]) checked.2
      · intro prior member
        rcases List.mem_append.mp member with old | last
        · exact misses prior old
        · have same := List.mem_singleton.mp last
          subst prior
          exact Bool.eq_false_iff.mpr missed
      · exact accepted


end TDN.DataPlaneForwarding
