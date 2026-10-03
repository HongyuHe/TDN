import TDN.MSC.Operational
import TDN.Network.Encapsulation

/-!
SR-23 requires an MTU choice that accounts for both encryption layers.
The snapshot now records Red MTU 1370, Gray MTU 1435, and Black MTU 1500.
The generic ESP size theorem includes worst-case alignment padding and optional
UDP encapsulation at both layers. The checked premises below bind that theorem
to every declared and observed data interface, rather than one sample path.

The sizing result concerns an admitted, complete IPv4 datagram and the stated
AES-GCM encoding with ordinary outer IPv4 headers. Input fragmentation and PMTU
control behavior require separate packet-processing rules. Kernel enforcement
of the imported MTU and XFRM settings remains an implementation assumption.
-/
namespace TDN.MSC
open Deployment TDN.Network.Encapsulation

def zoneMTU : Zone → Nat
  | .red => 1370
  | .gray => 1435
  | .black => 1500
  | .management => 1500

def protectedWireSize (zone : Zone) (bytes : Nat) (innerUDP outerUDP : Bool) : Nat :=
  match zone with
  | .red => bytes
  | .gray => espIPv4Size bytes innerUDP
  | .black => espIPv4Size (espIPv4Size bytes innerUDP) outerUDP
  | .management => bytes

theorem declared_data_mtus : ∀ d ∈ devices, ∀ port ∈ d.interfaces,
    port.zone ≠ .management ∧ port.mtu = zoneMTU port.zone := by decide

theorem observed_link_mtus_agree : ∀ link ∈ links,
    ∃ a ∈ liveInterfaces link.a, ∃ b ∈ liveInterfaces link.b,
      a.name = link.aPort ∧ b.name = link.bPort ∧
      a.mtu = zoneMTU link.zone ∧ b.mtu = zoneMTU link.zone := by decide

theorem observed_sa_sizing_profile : ∀ t ∈ tunnels,
    (liveStates t.owner).isEmpty = false ∧ ∀ sa ∈ liveStates t.owner,
      sa.protocol = "esp" ∧ sa.mode = "tunnel" ∧
      sa.algorithm = "rfc4106(gcm(aes))" ∧ sa.integrityBits = 128 ∧ sa.tfcPadding = 0 ∧
      (sa.udpEncapsulation = true → sa.udpSourcePort = some 4500 ∧ sa.udpDestinationPort = some 4500) := by decide

theorem protected_size_within_zone_mtu (zone : Zone) (bytes : Nat)
    (admitted : bytes ≤ zoneMTU .red) (innerUDP outerUDP : Bool) :
    protectedWireSize zone bytes innerUDP outerUDP ≤ zoneMTU zone := by
  have bounds := fits_two_layers 1370 1435 1500 bytes (by decide) (by decide) admitted innerUDP outerUDP
  cases zone <;> simp only [protectedWireSize, zoneMTU] at * <;> omega

/-- Every observed endpoint of every retained link can carry the modeled
protected packet for its zone. The argument is uniform over payload lengths
and both choices of native ESP or UDP-encapsulated ESP. -/
theorem protected_size_fits_every_observed_link (link : Link) (member : link ∈ links)
    (bytes : Nat) (admitted : bytes ≤ 1370) (innerUDP outerUDP : Bool) :
    ∃ a ∈ liveInterfaces link.a, ∃ b ∈ liveInterfaces link.b,
      a.name = link.aPort ∧ b.name = link.bPort ∧
      protectedWireSize link.zone bytes innerUDP outerUDP ≤ a.mtu ∧
      protectedWireSize link.zone bytes innerUDP outerUDP ≤ b.mtu := by
  obtain ⟨a, am, b, bm, an, bn, aMTU, bMTU⟩ := observed_link_mtus_agree link member
  have fits := protected_size_within_zone_mtu link.zone bytes admitted innerUDP outerUDP
  exact ⟨a, am, b, bm, an, bn, aMTU ▸ fits, bMTU ▸ fits⟩

end TDN.MSC
