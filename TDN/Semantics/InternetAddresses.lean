import Mathlib.Data.Fin.Basic
import Lean.Elab.Tactic.Omega

namespace TDN.InternetAddresses

/-- The existing packet model uses natural-number address keys. IPv4 keeps its ordinary
numeric value; IPv6 receives a disjoint tagged range. These are model keys, not wire integers. -/
def encode4 (address : Fin (2^32)) : Nat := address.val
def encode6 (address : Fin (2^128)) : Nat := 2^128 + address.val

theorem families_have_disjoint_keys (ipv4 : Fin (2^32)) (ipv6 : Fin (2^128)) :
    encode4 ipv4 ≠ encode6 ipv6 := by
  have bound := ipv4.isLt
  simp only [encode4, encode6]
  omega

theorem ipv4_encoding_injective (a b : Fin (2^32)) (same : encode4 a = encode4 b) :
    a = b := Fin.ext same

theorem ipv6_encoding_injective (a b : Fin (2^128)) (same : encode6 a = encode6 b) :
    a = b := by
  apply Fin.ext
  simp only [encode6] at same
  omega

/-- Only IPv4 has an IHL field. A zero value records its absence in the IPv6 header model. -/
def headerWords (addressKey : Nat) : Nat := if addressKey < 2^32 then 5 else 0

theorem ipv6_has_no_ipv4_ihl (address : Fin (2^128)) :
    headerWords (encode6 address) = 0 := by
  have notSmall : ¬ (2^128 + address.val < 2^32) := by omega
  simp [headerWords, encode6, notSmall]

end TDN.InternetAddresses
