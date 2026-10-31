import TDN.Targets.MACsecFallback

namespace TDN.Imported.FinalMACsecKeySources
open KeySources Targets

def ports : List (String × Config) := [("eap-tls-forward-v18/P0", ⟨false, false⟩), ("eap-tls-forward-v18/P1", ⟨false, false⟩), ("eap-tls-reverse-v18/P0", ⟨false, false⟩), ("eap-tls-reverse-v18/P1", ⟨false, false⟩)]

lemma no_configured_pre_shared_pair : ∀ port ∈ ports,
    port.2.preSharedEnabled = false := by decide

theorem eap_ports_have_no_pre_shared_fallback (port : String × Config)
    (member : port ∈ ports) : no_pre_shared_fallback_in_eap_mode port.2 :=
  eap_key_sources_disable_pre_shared_fallback port.2 (no_configured_pre_shared_pair port member)

lemma all_four_ports_present : ports.length = 4 := by decide

end TDN.Imported.FinalMACsecKeySources
