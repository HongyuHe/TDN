import TDN.Targets.Protocol

namespace TDN.Imported.MKASource

def helloMs : Nat := 2000

def lifetimeMs : Nat := 6000

def boundedHelloMs : Nat := 500

def sourceDelayFlag (hello : Nat) : Bool := decide (hello ≤ boundedHelloMs)

theorem source_timer_constants : helloMs = 2000 ∧ lifetimeMs = 6000 := by decide

theorem required_hello_disables_source_delay_flag : sourceDelayFlag 2000 = false := by decide

def declaredTestCakBits : Nat := 256

def sourceDerivedKekBits := declaredTestCakBits

theorem source_derived_test_kek_width : sourceDerivedKekBits = 256 := by decide

theorem full_RG028_fails_under_source_flag_correspondence (devices : List Targets.MACsecProtection) (d : Targets.MACsecProtection) (hd : d ∈ devices) (hhello : d.helloMilliseconds = 2000) (hflag : d.dataDelayProtection = sourceDelayFlag d.helloMilliseconds) : ¬ Targets.msc_macsec_protection_parameters devices := by
  intro h
  have bad : false = true := by simpa [hflag, hhello, sourceDelayFlag, boundedHelloMs] using (h d hd).1
  cases bad

end TDN.Imported.MKASource
