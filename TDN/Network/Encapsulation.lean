import Std

/-!
IPv4 ESP sizing for AES-GCM with a 16-byte authentication tag.
RFC 4303 supplies the 8-byte ESP header and two trailer bytes. RFC 4106
supplies the 8-byte explicit IV and permits minimum padding below four bytes.
The outer IPv4 header has 20 bytes. Optional UDP encapsulation adds 8 bytes.
The formula assumes no IPv4 options or extra traffic-flow-confidentiality
padding in the new outer header. An instantiation must justify those premises.
-/
namespace TDN.Network.Encapsulation

/-- Pad the payload and two trailer bytes to the next four-byte boundary. -/
def padding (bytes : Nat) : Nat := (4 - (bytes + 2) % 4) % 4

def espIPv4Size (bytes : Nat) (udp : Bool) : Nat :=
  bytes + 20 + 8 + 8 + padding bytes + 2 + 16 + if udp then 8 else 0

theorem padding_bound (bytes : Nat) : padding bytes ≤ 3 := by
  have bound := Nat.mod_lt (4 - (bytes + 2) % 4) (by decide : 0 < 4)
  unfold padding
  omega

/-- A uniform bound covers native ESP and ESP carried inside UDP. -/
theorem one_layer_bound (bytes : Nat) (udp : Bool) : espIPv4Size bytes udp ≤ bytes + 65 := by
  have bound := padding_bound bytes
  cases udp <;> simp only [espIPv4Size, Bool.false_eq_true, ↓reduceIte] <;> omega

theorem two_layer_bound (bytes : Nat) (innerUDP outerUDP : Bool) :
    espIPv4Size (espIPv4Size bytes innerUDP) outerUDP ≤ bytes + 130 := by
  have first := one_layer_bound bytes innerUDP
  have second := one_layer_bound (espIPv4Size bytes innerUDP) outerUDP
  omega

/-- Per-stage MTU headroom rules out enlargement beyond either link MTU.
The statement covers every admitted original IPv4 packet length. -/
theorem fits_two_layers (redMTU grayMTU blackMTU bytes : Nat)
    (firstBudget : redMTU + 65 ≤ grayMTU) (secondBudget : grayMTU + 65 ≤ blackMTU)
    (admitted : bytes ≤ redMTU) (innerUDP outerUDP : Bool) :
    espIPv4Size bytes innerUDP ≤ grayMTU ∧
      espIPv4Size (espIPv4Size bytes innerUDP) outerUDP ≤ blackMTU := by
  have first := one_layer_bound bytes innerUDP
  have second := one_layer_bound (espIPv4Size bytes innerUDP) outerUDP
  constructor <;> omega

end TDN.Network.Encapsulation
