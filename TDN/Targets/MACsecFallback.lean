import TDN.Semantics.KeySources

namespace TDN.Targets
open KeySources

/-- MD-15's selected interpretation prohibits alternate configured CAKs used as
fallback or rollover credentials. INT-MD15-20261024 explains the source review.
Fresh EAP-derived CAKs remain permitted when authentication is renewed. -/
def no_pre_shared_fallback_in_eap_mode (config : Config) : Prop :=
  ∀ actions state, (system config).MTr [] actions state →
    OnlyAuthenticatedSources state

/-- An absent pre-shared CAK/CKN pair disables the only modeled pre-shared creation
entry point. The general execution proof then excludes pre-shared fallback keys
at every reachable state, even when several renewed EAP participants coexist. -/
theorem eap_key_sources_disable_pre_shared_fallback (config : Config)
    (checked : config.preSharedEnabled = false) :
    no_pre_shared_fallback_in_eap_mode config := by
  intro actions state execution
  exact executions_have_only_authenticated_sources checked execution

end TDN.Targets
