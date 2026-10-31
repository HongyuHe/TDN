import TDN.Targets.EnterpriseGrayFiltering

open TDN.PacketPolicy TDN.Targets.EnterpriseGray

/-- Synthetic regression addresses: range 10–19 belongs to one input only. -/
def ranges : List SourceRange := [⟨"management", 10, 19⟩, ⟨"transport", 20, 29⟩]
def managementRule : Rule := ⟨[.ingress "management", .sourceRange 10 19], .allow⟩
def rules : List Rule := [managementRule]

example : ∀ rule ∈ rules, rule.verdict = .allow → RuleSourceCheck ranges rule := by decide

example : ingress_source_filtering ranges rules :=
  source_filtering_from_rule_checks ranges rules (by decide)

/-- The same address range attached to the wrong port must fail the certificate. -/
example : ¬ RuleSourceCheck ranges ⟨[.ingress "transport", .sourceRange 10 19], .allow⟩ := by decide
example : ¬ RuleSourceCheck ranges ⟨[.sourceRange 10 19], .allow⟩ := by decide
example : ¬ RuleSourceCheck ranges ⟨[.ingress "management", .sourceRange 10 20], .allow⟩ := by decide

def arriving : Packet :=
  { source := 11, destination := 42, protocol := "tcp", ingress := "management",
    egress := "transport", sourcePort := 40000, destinationPort := 22,
    ipv4HeaderWords := 5, inboundPolicies := [], outboundPolicies := [], connectionState := "NEW" }

example : Accepts rules arriving := by decide
example : TDN.Filter.evaluate (rules.map Rule.toFilter) .deny
    { arriving with ingress := "transport" } = .deny := by decide
example : TDN.Filter.evaluate (rules.map Rule.toFilter) .deny
    { arriving with source := 20 } = .deny := by decide

/-- An explicit earlier denial can suppress a permitted rule; safety still holds. -/
def denyFirst : List Rule := ⟨[], .deny⟩ :: rules
example : ingress_source_filtering ranges denyFirst :=
  source_filtering_from_rule_checks ranges denyFirst (by decide)
example : ¬ Accepts denyFirst arriving := by decide

example : arriving.ingress ∈ ["management"] :=
  management_ingress_from_rule_checks ["management"] rules (by decide) arriving (by decide)
