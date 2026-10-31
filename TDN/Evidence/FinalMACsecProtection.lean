import TDN.Targets.Protocol

namespace TDN.Imported.FinalMACsecProtection
open Targets
def devices : List MACsecProtection := [
  { device := 0,
    dataDelayProtection := true, lifetimeMilliseconds := 6000,
    helloMilliseconds := 2000, activeHelloMilliseconds := 500,
    replayWindow := 0, feasibleReplayWindow := fun n => n < 2 ^ 32,
    confidentialityOffset := 0, mustSecure := true,
    dataPort := ⟨true, true, true, 0⟩ },
  { device := 1,
    dataDelayProtection := true, lifetimeMilliseconds := 6000,
    helloMilliseconds := 2000, activeHelloMilliseconds := 500,
    replayWindow := 0, feasibleReplayWindow := fun n => n < 2 ^ 32,
    confidentialityOffset := 0, mustSecure := true,
    dataPort := ⟨true, true, true, 0⟩ },
  { device := 2,
    dataDelayProtection := true, lifetimeMilliseconds := 6000,
    helloMilliseconds := 2000, activeHelloMilliseconds := 500,
    replayWindow := 0, feasibleReplayWindow := fun n => n < 2 ^ 32,
    confidentialityOffset := 0, mustSecure := true,
    dataPort := ⟨true, true, true, 0⟩ },
  { device := 3,
    dataDelayProtection := true, lifetimeMilliseconds := 6000,
    helloMilliseconds := 2000, activeHelloMilliseconds := 500,
    replayWindow := 0, feasibleReplayWindow := fun n => n < 2 ^ 32,
    confidentialityOffset := 0, mustSecure := true,
    dataPort := ⟨true, true, true, 0⟩ }
]

theorem selected_protection_configuration : msc_macsec_protection_parameters devices := by
  apply macsec_protection_from_local_checks devices
  · simp [devices]
  · simp [devices]
  · simp [devices]
  · simp [devices]

lemma runtime_inventory_nonempty : devices.length = 4 := by decide

end TDN.Imported.FinalMACsecProtection
