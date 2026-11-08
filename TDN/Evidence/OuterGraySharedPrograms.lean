import TDN.Evidence.OuterGraySharedData

namespace TDN.Imported.OuterGrayShared
open Compliance Targets Targets.Complete OuterGrayNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma Outer_gray_allow_rules_checked (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        ∀ iface ∈ records.inventory.ifaces, records.inventory.ifaceName iface = interface.id →
          ∀ policy ∈ (records.deployment base).policies, policy.interface = interface.id →
            policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
              OuterGrayRuleChecks (records.deployment base) interface
                (records.inventory.configuration.ip.interfaceName iface) policy.direction records.pairs rule := by
  exact of_decide_eq_true rfl

end TDN.Imported.OuterGrayShared
