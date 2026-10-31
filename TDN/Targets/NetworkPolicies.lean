import TDN.Semantics.Filter
import TDN.Targets.Architecture

namespace TDN.Targets

inductive BoundaryProtocol where
  | ike | esp | mka | macsec | control | redService | other
  deriving DecidableEq, Repr

inductive BoundaryRole where
  | outerVPNBlack | outerMACsecBlack | innerGray | innerRed | outerFirewall
  deriving DecidableEq, Repr

inductive TrafficDirection where
  | inbound | outbound
  deriving DecidableEq, Repr

/-- Packet projections are supplied by the implementation interpretation. They can describe
IPv4, IPv6 or Ethernet frames; applicability does not depend on one address-family encoding. -/
structure BoundaryPolicy (Packet Interface : Type) where
  interfaces : List Interface
  role : Interface → BoundaryRole
  rules : Interface → TrafficDirection → List (Filter.Rule Packet)
  protocol : Packet → BoundaryProtocol
  approvedControl : Interface → Packet → Prop
  organizationApproved : Interface → Packet → Prop
  intendedRemote : Interface → Packet → Prop
  outerSourceAddress : Packet → Prop
  outerDestinationAddress : Packet → Prop
  externalFirewallSide : Interface → Bool
  redServiceAddressAndPort : Packet → Prop

def BoundaryPermitted {P I : Type} (policy : BoundaryPolicy P I)
    (interface : I) (direction : TrafficDirection) (packet : P) : Prop :=
  policy.organizationApproved interface packet ∧
  (match policy.role interface with
    | .outerVPNBlack =>
        policy.protocol packet ∈ [.ike, .esp] ∨ policy.approvedControl interface packet
    | .outerMACsecBlack =>
        policy.protocol packet = .macsec ∨ policy.approvedControl interface packet
    | .innerGray | .outerFirewall =>
        policy.protocol packet ∈ [.ike, .esp, .mka, .macsec] ∨ policy.approvedControl interface packet
    | .innerRed => policy.redServiceAddressAndPort packet) ∧
  ((policy.role interface = .outerVPNBlack ∨ policy.role interface = .outerMACsecBlack) →
    direction = .outbound → policy.intendedRemote interface packet) ∧
  (policy.role interface = .outerFirewall →
    policy.approvedControl interface packet ∨
    (if policy.externalFirewallSide interface then
      direction = .inbound → policy.outerDestinationAddress packet
     else direction = .inbound → policy.outerSourceAddress packet))

/-- Both directions of every applicable interface use the actual ordered rule list.
Control-plane exceptions are explicit policy predicates, not an unrestricted bypass. -/
def msc_boundary_interface_filtering {P I : Type} (policy : BoundaryPolicy P I) : Prop :=
  ∀ interface ∈ policy.interfaces, ∀ direction packet,
    Filter.evaluate (policy.rules interface direction) .deny packet = .allow →
      BoundaryPermitted policy interface direction packet

theorem boundary_filtering_from_rule_checks {P I : Type} (policy : BoundaryPolicy P I)
    (checked : ∀ interface ∈ policy.interfaces, ∀ direction rule,
      rule ∈ policy.rules interface direction → rule.verdict = .allow →
      ∀ packet, rule.accepts packet = true → BoundaryPermitted policy interface direction packet) :
    msc_boundary_interface_filtering policy := by
  intro interface member direction packet accepted
  exact Filter.default_deny_sound _ _ (checked interface member direction) packet accepted

/-- Each category is defined by header, endpoint and policy facts in an application.
The required-traffic predicate is independently supplied from the applicable source clauses. -/
structure GrayPolicy (Packet Interface : Type) where
  interfaces : List Interface
  rules : Interface → List (Filter.Rule Packet)
  sameLevelInnerProtection : Packet → Prop
  grayManagementProtection : Packet → Prop
  revocationHTTP : Packet → Prop
  http : Packet → Prop
  management : Packet → Prop
  approvedManagement : Packet → Prop
  approvedControl : Packet → Prop
  initiatedByGrayAW : Packet → Prop
  outerLoggingOrAuthentication : Packet → Prop
  sourceReachableFrom : Interface → Packet → Prop
  managementPhysicalPort : Interface → Prop
  requiredTraffic : Interface → Packet → Prop
  crossesDifferentInnerLevels : Packet → Prop

def GrayAllowedCategory {P I : Type} (policy : GrayPolicy P I) (packet : P) : Prop :=
  policy.sameLevelInnerProtection packet ∨ policy.grayManagementProtection packet ∨
  policy.revocationHTTP packet ∨ policy.approvedManagement packet ∨ policy.approvedControl packet

def GrayCommonPermitted {P I : Type} (policy : GrayPolicy P I)
    (interface : I) (packet : P) : Prop :=
  GrayAllowedCategory policy packet ∧ policy.sourceReachableFrom interface packet ∧
  (policy.http packet → policy.revocationHTTP packet) ∧
  ¬ policy.crossesDifferentInnerLevels packet

/-- PF17's same-level addressing condition applies to Inner data traffic, with the explicit
PF8/PF15/PF19 management, revocation and control exceptions retained. See INT014. -/
def msc_outer_gray_interface_policy {P I : Type} (policy : GrayPolicy P I) : Prop :=
  (∀ interface ∈ policy.interfaces, ∀ packet,
    Filter.evaluate (policy.rules interface) .deny packet = .allow →
      GrayCommonPermitted policy interface packet ∧
      (policy.management packet →
        policy.initiatedByGrayAW packet ∨ policy.outerLoggingOrAuthentication packet)) ∧
  ∀ interface ∈ policy.interfaces, ∀ packet, policy.requiredTraffic interface packet →
    Filter.evaluate (policy.rules interface) .deny packet = .allow

def msc_gray_firewall_allowlist {P I : Type} (required : Bool) (policy : GrayPolicy P I) : Prop :=
  required = true →
  (∀ interface ∈ policy.interfaces, ∀ packet,
    Filter.evaluate (policy.rules interface) .deny packet = .allow →
      GrayCommonPermitted policy interface packet ∧
      (policy.management packet → policy.managementPhysicalPort interface)) ∧
  ∀ interface ∈ policy.interfaces, ∀ packet, policy.requiredTraffic interface packet →
    Filter.evaluate (policy.rules interface) .deny packet = .allow

def FirstAllowWitness {P : Type} (rules : List (Filter.Rule P)) (packet : P) : Prop :=
  ∃ earlierRules rule suffix, rules = earlierRules ++ rule :: suffix ∧
    (∀ earlier ∈ earlierRules, earlier.accepts packet = false) ∧
    rule.accepts packet = true ∧ rule.verdict = .allow

lemma first_allow_witness_accepts {P : Type} {rules : List (Filter.Rule P)} {packet : P}
    (witness : FirstAllowWitness rules packet) :
    Filter.evaluate rules .deny packet = .allow := by
  obtain ⟨earlierRules, rule, suffix, rfl, misses, matched, allows⟩ := witness
  exact Filter.accepts_at_first_matching_rule earlierRules suffix rule packet misses matched allows

/-- Safety comes from every allow rule; availability comes from a first-match witness
for each required traffic class. Neither half is inferred from the other. -/
theorem outer_gray_policy_from_local_rules {P I : Type} (policy : GrayPolicy P I)
    (safe : ∀ interface ∈ policy.interfaces, ∀ rule ∈ policy.rules interface,
      rule.verdict = .allow → ∀ packet, rule.accepts packet = true →
        GrayCommonPermitted policy interface packet ∧
        (policy.management packet →
          policy.initiatedByGrayAW packet ∨ policy.outerLoggingOrAuthentication packet))
    (complete : ∀ interface ∈ policy.interfaces, ∀ packet,
      policy.requiredTraffic interface packet → FirstAllowWitness (policy.rules interface) packet) :
    msc_outer_gray_interface_policy policy := by
  constructor
  · intro interface member packet accepted
    exact Filter.default_deny_sound _ _ (safe interface member) packet accepted
  · intro interface member packet required
    exact first_allow_witness_accepts (complete interface member packet required)

theorem gray_firewall_policy_from_local_rules {P I : Type} (required : Bool) (policy : GrayPolicy P I)
    (safe : required = true → ∀ interface ∈ policy.interfaces, ∀ rule ∈ policy.rules interface,
      rule.verdict = .allow → ∀ packet, rule.accepts packet = true →
        GrayCommonPermitted policy interface packet ∧
        (policy.management packet → policy.managementPhysicalPort interface))
    (complete : required = true → ∀ interface ∈ policy.interfaces, ∀ packet,
      policy.requiredTraffic interface packet → FirstAllowWitness (policy.rules interface) packet) :
    msc_gray_firewall_allowlist required policy := by
  intro selected
  constructor
  · intro interface member packet accepted
    exact Filter.default_deny_sound _ _ (safe selected interface member) packet accepted
  · intro interface member packet requiredPacket
    exact first_allow_witness_accepts (complete selected interface member packet requiredPacket)

inductive ControlLayer where
  | layer2 | layer3
  deriving DecidableEq, Repr

structure ControlProtocolUse where
  component : Nat
  protocol : String
  layer : ControlLayer
  enabled : Bool
  blocked : Bool
  publicStandardConformant : Bool
  necessary : Bool
  ownerApproved : Bool
  aoPolicyApproved : Bool
  explicitlyEnabled : Bool
  deriving DecidableEq, Repr

structure ControlService where
  client : Nat
  server : Nat
  clientIsInner : Bool
  clientIsOuter : Bool
  serverInRed : Bool
  serverInGray : Bool
  deriving DecidableEq, Repr

def msc_control_plane_policy_and_services (uses : List ControlProtocolUse)
    (services : List ControlService) : Prop :=
  (∀ use ∈ uses,
    (use.ownerApproved = false → use.enabled = false ∨ use.blocked = true) ∧
    (use.enabled = true → use.blocked = false →
      use.publicStandardConformant = true ∧ use.necessary = true ∧ use.aoPolicyApproved = true ∧
      (use.layer = .layer3 → use.explicitlyEnabled = true))) ∧
  ∀ service ∈ services,
    (service.clientIsInner = true → service.serverInRed = true) ∧
    (service.clientIsOuter = true → service.serverInGray = true)

/-- Disabling every unapproved protocol is preserved by a configuration normalizer.
This proves the policy-enforcement clause, not necessity or standard conformance. -/
def restrictUnapprovedControl (use : ControlProtocolUse) : ControlProtocolUse :=
  { use with enabled := use.enabled && use.ownerApproved }

theorem control_normalizer_disables_unapproved (uses : List ControlProtocolUse) :
    ∀ use ∈ uses.map restrictUnapprovedControl, use.ownerApproved = false → use.enabled = false := by
  intro use member unapproved
  obtain ⟨original, originalMember, rfl⟩ := List.mem_map.mp member
  change original.ownerApproved = false at unapproved
  simp [restrictUnapprovedControl, unapproved]

end TDN.Targets
