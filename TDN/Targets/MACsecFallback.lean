import TDN.Semantics.KeySources

namespace TDN.Targets
open KeySources

def no_pre_shared_fallback_in_eap_mode (config : Config) : Prop :=
  ∀ actions state, (system config).MTr [] actions state →
    OnlyAuthenticatedSources state

theorem eap_key_sources_disable_pre_shared_fallback (config : Config)
    (checked : config.preSharedEnabled = false) :
    no_pre_shared_fallback_in_eap_mode config := by
  intro actions state execution
  exact executions_have_only_authenticated_sources checked execution

end TDN.Targets
