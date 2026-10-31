import TDN.Targets.ComponentAttributes
import TDN.Evidence.FreshOSDiversity
import TDN.Evidence.FinalMACsecRuntime

namespace TDN.Imported.FreshOSDiversity

/-- The complete imported inventory binds each role to its observed OS family.
The same reusable argument permits several distinct families within either role. -/
theorem captured_OS_separation_from_family_partition :
    ∀ inner ∈ components, ∀ outer ∈ components,
      inner.role = .inner → outer.role = .outer →
      inner.osFamily ≠ outer.osFamily := by
  apply Targets.os_separation_from_role_family_sets components ["FreeBSD"] ["Linux"]
  · decide
  · decide
  · decide

end TDN.Imported.FreshOSDiversity

namespace TDN.Imported.FinalMACsecRuntime

/-- RG026's selected algorithm subclause uses the recorded negotiated EAP suite.
The imported observation is the selected suite, not a claim about all possible
future offers or complete EAP profile conformance. -/
theorem observed_eap_choice_inherits_checked_profile :
    Targets.CNSA2 negotiatedSuite := by
  apply Targets.negotiated_suite_inherits_profile [negotiatedSuite] Targets.CNSA2
  · intro suite member
    have same : suite = negotiatedSuite := by simpa using member
    exact same ▸ negotiated_suite_cnsa2
  · simp

end TDN.Imported.FinalMACsecRuntime
