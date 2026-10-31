import TDN.Targets.Components

namespace TDN.Imported.FreshPhysicalPartition

def components : List Targets.Component := [
  { identity := "MW_GF_A", product := ⟨"", "", "", .other⟩, role := .grayFirewall, physicalDevice := "4c4c4544-004a-4310-8042-b4c04f563532", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_GF_B", product := ⟨"", "", "", .other⟩, role := .grayFirewall, physicalDevice := "4c4c4544-004a-4310-8042-b4c04f563532", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_I_A1", product := ⟨"", "", "", .other⟩, role := .inner, physicalDevice := "4c4c4544-0036-3110-8042-b6c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_I_A2", product := ⟨"", "", "", .other⟩, role := .inner, physicalDevice := "4c4c4544-0036-3110-8042-b6c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_I_B1", product := ⟨"", "", "", .other⟩, role := .inner, physicalDevice := "4c4c4544-0036-3110-8042-b6c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_I_B2", product := ⟨"", "", "", .other⟩, role := .inner, physicalDevice := "4c4c4544-0036-3110-8042-b6c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_OF_A1", product := ⟨"", "", "", .other⟩, role := .outerFirewall, physicalDevice := "4c4c4544-0059-3110-8037-c3c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_OF_A2", product := ⟨"", "", "", .other⟩, role := .outerFirewall, physicalDevice := "4c4c4544-0059-3110-8037-c3c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_OF_B1", product := ⟨"", "", "", .other⟩, role := .outerFirewall, physicalDevice := "4c4c4544-0059-3110-8037-c3c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_OF_B2", product := ⟨"", "", "", .other⟩, role := .outerFirewall, physicalDevice := "4c4c4544-0059-3110-8037-c3c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_O_A1", product := ⟨"", "", "", .other⟩, role := .outer, physicalDevice := "4c4c4544-0036-3110-8036-b6c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_O_A2", product := ⟨"", "", "", .other⟩, role := .outer, physicalDevice := "4c4c4544-0036-3110-8036-b6c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_O_B1", product := ⟨"", "", "", .other⟩, role := .outer, physicalDevice := "4c4c4544-0036-3110-8036-b6c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] },
  { identity := "MW_O_B2", product := ⟨"", "", "", .other⟩, role := .outer, physicalDevice := "4c4c4544-0036-3110-8036-b6c04f333832", osFamily := "Linux", cryptoManufacturer := "", cryptoLibrary := "", evaluatedConfiguration := "", installedConfiguration := "", modifications := [] }]

def hardwareForRole : Targets.ComponentRole → List String
  | .grayFirewall => ["4c4c4544-004a-4310-8042-b4c04f563532"]
  | .inner => ["4c4c4544-0036-3110-8042-b6c04f333832"]
  | .outer => ["4c4c4544-0036-3110-8036-b6c04f333832"]
  | .outerFirewall => ["4c4c4544-0059-3110-8037-c3c04f333832"]
  | _ => []

/-- Unknown product/approval fields are unused by this physical-separation result. -/
theorem captured_role_pairs_are_physically_distinct :
    Targets.msc_physically_distinct_security_components components := by
  apply Targets.physical_separation_from_disjoint_role_hardware components hardwareForRole
  · unfold components hardwareForRole; decide
  · intro a b; cases a <;> cases b <;> unfold Targets.SeparationRequired hardwareForRole <;> decide

end TDN.Imported.FreshPhysicalPartition
