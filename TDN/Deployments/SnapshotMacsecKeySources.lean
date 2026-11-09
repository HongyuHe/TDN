import TDN.Requirements.MacsecNoCleartextFallbackSpec

namespace TDN.Deployments.SnapshotMacsecKeySources
open KeySources Requirements

def ifaces : List (String × Config) := [("eap-tls-forward-v18/P0", ⟨false, false⟩), ("eap-tls-forward-v18/P1", ⟨false, false⟩), ("eap-tls-reverse-v18/P0", ⟨false, false⟩), ("eap-tls-reverse-v18/P1", ⟨false, false⟩)]

lemma no_configured_pre_shared_pair : ∀ iface ∈ ifaces,
    iface.2.preSharedEnabled = false := by decide

theorem eap_ifaces_have_no_pre_shared_fallback (iface : String × Config)
    (member : iface ∈ ifaces) : no_pre_shared_fallback_in_eap_mode iface.2 :=
  eap_key_sources_disable_pre_shared_fallback iface.2 (no_configured_pre_shared_pair iface member)

lemma all_four_ifaces_present : ifaces.length = 4 := by decide

end TDN.Deployments.SnapshotMacsecKeySources
