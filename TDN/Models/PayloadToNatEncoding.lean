import TDN.Models.L2FrameFilter
import Mathlib.Data.Nat.Digits.Defs

namespace TDN.LinkAdmission

lemma payload_code_concat (bytes : List UInt8) (byte : UInt8) :
    payloadCode (bytes ++ [byte]) = 256 * payloadCode bytes + byte.toNat := by
  simp [payloadCode, List.foldl_append, Nat.mul_comm]

lemma payload_code_as_digits (bytes : List UInt8) :
    payloadCode bytes = Nat.ofDigits 256 (bytes.reverse.map UInt8.toNat ++ [1]) := by
  induction bytes using List.reverseRecOn with
  | nil => rfl
  | append_singleton bytes byte ih =>
    simp [payload_code_concat, List.reverse_append, Nat.ofDigits, ih, Nat.add_comm]

lemma digits_payload_code (bytes : List UInt8) :
    Nat.digits 256 (payloadCode bytes) = bytes.reverse.map UInt8.toNat ++ [1] := by
  rw [payload_code_as_digits]
  apply Nat.digits_ofDigits 256 (by decide)
  · intro digit member
    simp only [List.mem_append, List.mem_map, List.mem_singleton] at member
    rcases member with ⟨byte, _, rfl⟩ | rfl
    · exact byte.toNat_lt
    · decide
  · intro nonempty
    simp

theorem payload_code_injective : Function.Injective payloadCode := by
  intro first second equal
  have digits := congrArg (Nat.digits 256) equal
  rw [digits_payload_code, digits_payload_code] at digits
  have mapped : first.reverse.map UInt8.toNat = second.reverse.map UInt8.toNat :=
    List.append_cancel_right digits
  have reversed : first.reverse = second.reverse :=
    List.map_injective_iff.mpr (fun a b same => UInt8.toNat_inj.mp same) mapped
  exact List.reverse_injective reversed

end TDN.LinkAdmission

namespace TDN.LinkAdmission

lemma EthernetFrame.Describes.plain_ethernet_payload (encoded : EthernetFrame) (native : LayeredFrame.TunnelFrame)
    (header : LayeredFrame.EthernetHeader) (plain : native.body = .ethernet header)
    (describes : encoded.Describes native) :
    native.payload = payloadCode encoded.payload := by
  unfold EthernetFrame.Describes LayeredFrame.TunnelFrame.visibleHeader at describes
  rw [plain] at describes
  exact describes.2 header rfl

lemma EthernetFrame.Describes.plain_ip_payload (encoded : EthernetFrame) (native : LayeredFrame.TunnelFrame)
    (header : PacketPolicy.Packet) (plain : native.body = .datagram header)
    (describes : encoded.Describes native) :
    ∃ network transport payload,
      encoded.payload = network ++ transport ++ payload ∧ native.payload = payloadCode payload := by
  unfold EthernetFrame.Describes LayeredFrame.TunnelFrame.visibleHeader at describes
  rw [plain] at describes
  obtain ⟨_, _, network, transport, payload, bytes, _, bound, _⟩ := describes
  exact ⟨network, transport, payload, bytes, (bound header rfl).2⟩

end TDN.LinkAdmission

namespace TDN.LinkAdmission

def decodePayload (code : Nat) : List UInt8 :=
  ((Nat.digits 256 code).dropLast.reverse).map UInt8.ofNat

lemma decode_payload_payload_code (bytes : List UInt8) :
    decodePayload (payloadCode bytes) = bytes := by
  simp [decodePayload, digits_payload_code, List.map_reverse, List.map_map, Function.comp_def]

end TDN.LinkAdmission
