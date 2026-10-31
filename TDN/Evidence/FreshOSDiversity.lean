import TDN.Targets.Components

namespace TDN.Imported.FreshOSDiversity

def components : List Targets.Component := [
  { identity := "ND_I_A1", product := ⟨"", "", "", .vpn⟩, role := .inner, physicalDevice := "SHARED-LAB-HOST", osFamily := "FreeBSD", cryptoManufacturer := "", cryptoLibrary := "Botan", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "ND_I_B1", product := ⟨"", "", "", .vpn⟩, role := .inner, physicalDevice := "SHARED-LAB-HOST", osFamily := "FreeBSD", cryptoManufacturer := "", cryptoLibrary := "Botan", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "ND_O_A1", product := ⟨"", "", "", .vpn⟩, role := .outer, physicalDevice := "SHARED-LAB-HOST", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "OpenSSL", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "ND_O_B1", product := ⟨"", "", "", .vpn⟩, role := .outer, physicalDevice := "SHARED-LAB-HOST", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "OpenSSL", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] }]

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
