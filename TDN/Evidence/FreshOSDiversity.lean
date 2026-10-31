import TDN.Import.Command
import TDN.Targets.Components

namespace TDN.Imported.FreshOSDiversity

tdn_data components : List Targets.Component from "../../evidence/lean/FreshOSDiversity.json" ["TDN.Imported.FreshOSDiversity.components"]

/-- This is the OS-family clause for the captured selected Inner/Outer inventory. -/
theorem captured_OS_families_differ : ∀ inner ∈ components, ∀ outer ∈ components,
    inner.role = .inner → outer.role = .outer → inner.osFamily ≠ outer.osFamily := by
  decide

/-- Observed IKE provider names differ; manufacturer independence and every
ESP/kernel crypto implementation remain separate claims. -/
theorem observed_IKE_provider_names_differ : ∀ inner ∈ components, ∀ outer ∈ components,
    inner.role = .inner → outer.role = .outer → inner.cryptoLibrary ≠ outer.cryptoLibrary := by
  decide

end TDN.Imported.FreshOSDiversity
