import TDN.Targets.PolicyDerivation
import TDN.Targets.CompleteSpecifications

namespace TDN.Targets.Complete
open Compliance

theorem third_party_services_from_disabled_features_and_rule_checks
    (d : Deployment) (objectiveSelected : String → Bool) (features : List ThirdPartyFeature)
    (disabled : ∀ feature ∈ features, d.IsLayer feature.device .outer →
      feature.canContactThirdParty = true → objectiveSelected feature.device = true →
      feature.enabled = false)
    (ipFeatures : ∀ feature ∈ features, d.IsLayer feature.device .outer →
      feature.canContactThirdParty = true → objectiveSelected feature.device = false →
      ∀ traffic, feature.emittedTraffic traffic → traffic.packet.protocol ≠ "ethernet")
    (defaultDeny : ∀ policy ∈ d.policies, policy.direction = .outbound →
      policy.defaultVerdict = .deny)
    (ruleChecks : ∀ feature ∈ features, d.IsLayer feature.device .outer →
      feature.canContactThirdParty = true → objectiveSelected feature.device = false →
      ∀ interface ∈ d.interfaces, interface.device = feature.device →
      ∀ policy ∈ d.policies, policy.interface = interface.id → policy.direction = .outbound →
      ∀ rule ∈ policy.rules, rule.verdict = .allow →
      ∀ traffic, feature.emittedTraffic traffic → rule.toFilter.accepts traffic.packet = false) :
    msc_outer_third_party_services d objectiveSelected features := by
  intro feature member _ outer canContact
  cases selected : objectiveSelected feature.device with
  | true =>
    simp only [↓reduceIte]
    exact disabled feature member outer canContact selected
  | false =>
    simp only [Bool.false_eq_true, ↓reduceIte]
    intro interface port _ owner traffic emitted accepted
    obtain ⟨policy, present, samePort, outgoing, allows⟩ :=
      PolicyDerivation.ip_acceptance_has_policy { d with focus := none } interface.id
        .outbound traffic (ipFeatures feature member outer canContact selected traffic emitted) accepted
    exact PolicyDerivation.policy_denies_if_allow_rules_miss policy traffic
      (defaultDeny policy present outgoing)
      (fun rule matchRule allow =>
        ruleChecks feature member outer canContact selected interface port owner
          policy present samePort outgoing rule matchRule allow traffic emitted) allows

end TDN.Targets.Complete
