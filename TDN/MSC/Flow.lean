import TDN.MSC.Policy

/-!
# Symbolic protected-data processing for the deployed host pairs

This module describes one packet at a time under fixed readiness assumptions.
It does not model OSPF convergence, timers, spoofed host identities, or changes
during a packet's journey. `healthy` supplies example assumptions; a successful
ping does not prove those assumptions for every future execution.

The wrapper records are idealized encryption constructors. Their fields remain
readable in Lean, so wrapper shape proves processing order, not computational
confidentiality. Control traffic is outside this protected-Red-data type.
-/
namespace TDN.MSC

/-- Four representative Red hosts are present on node-1. -/
inductive RedHost where
  | a1 | a2 | b1 | b2
  deriving DecidableEq, BEq, Repr

def RedHost.deviceId : RedHost → String
  | .a1 => "R_A1" | .a2 => "R_A2" | .b1 => "R_B1" | .b2 => "R_B2"

def RedHost.level : RedHost → SecurityLevel
  | .a1 | .b1 => .s1
  | .a2 | .b2 => .s2

/-- The host labels are checked against imported declarations. Correctly
attributing an actual packet to a host remains an external premise. -/
theorem host_labels_match_snapshot : ∀ host ∈ [RedHost.a1, .a2, .b1, .b2],
    ((device? host.deviceId).bind Device.level) = some host.level := by decide

structure Packet where
  source : RedHost
  destination : RedHost
  payload : String
  deriving DecidableEq, BEq, Repr

/-- Peer authorization comes from imported inner tunnels and their attached
Red hosts. Label equality alone does not authorize a new peer. -/
def authorized (packet : Packet) : Bool :=
  Deployment.authorizedHostPairs.contains
    (packet.source.deviceId, packet.destination.deviceId)

/-- Readiness summarizes the encryptors and the chosen path for one packet.
SA means usable encryption state; policy means the expected XFRM policy exists.
Baseline firewall guards are a separate assumption supported by Policy.lean.
Authentication summarizes identity, trust, expiry, and revocation acceptance.
Transport includes installed routes and usable links. Filter readiness means
the selected packet is allowed on its declared path. None of these Booleans
prove strongSwan, FRR, or the kernel correct. Sender and receiver have separate
states in `deliver`, so a receive-side failure is not hidden by sender success. -/
structure GatewayState where
  innerSA : Bool
  outerSA : Bool
  innerPeerAuthenticated : Bool
  outerPeerAuthenticated : Bool
  innerPolicy : Bool
  outerPolicy : Bool
  transportReady : Bool
  outerFirewallReady : Bool
  grayPathReady : Bool
  deriving Repr

structure InnerPacket where
  protectedPayload : Packet
  deriving DecidableEq, BEq, Repr

structure BlackPacket where
  protectedInner : InnerPacket
  deriving DecidableEq, BEq, Repr

/-- `some` carries a transformed packet; `none` means blocked in the model.
Unknown observations use `DeviceObservation` and must not be confused with a
known false readiness flag. The caller must justify the flags it supplies. -/
def innerEncrypt (state : GatewayState) (packet : Packet) : Option InnerPacket :=
  if authorized packet = true ∧ state.innerSA = true ∧
      state.innerPeerAuthenticated = true ∧ state.innerPolicy = true then
    some ⟨packet⟩
  else none

def outerEncrypt (state : GatewayState) (inner : InnerPacket) : Option BlackPacket :=
  if state.outerSA = true ∧ state.outerPeerAuthenticated = true ∧
      state.outerPolicy = true ∧ state.transportReady = true ∧
      state.outerFirewallReady = true ∧ state.grayPathReady = true then
    some ⟨inner⟩
  else none

/-- `bind` stops on `none`; otherwise it passes the inner ciphertext to the
outer operation. The type prevents the outer step from taking raw Red data. -/
def transmit (state : GatewayState) (packet : Packet) : Option BlackPacket :=
  (innerEncrypt state packet).bind (outerEncrypt state)

/-- Outer decryption retains the inner wrapper and checks receiver readiness. -/
def outerDecrypt (state : GatewayState) (packet : BlackPacket) : Option InnerPacket :=
  if state.outerSA = true ∧ state.outerPeerAuthenticated = true ∧ state.outerPolicy = true then
    some packet.protectedInner
  else none

def innerDecrypt (state : GatewayState) (packet : InnerPacket) : Option Packet :=
  if state.innerSA = true ∧ state.innerPeerAuthenticated = true ∧ state.innerPolicy = true then
    some packet.protectedPayload
  else none

def deliver (sender receiver : GatewayState) (packet : Packet) : Option Packet :=
  (transmit sender packet).bind fun black =>
    (outerDecrypt receiver black).bind (innerDecrypt receiver)

/-- Case analysis covers all sixteen endpoint pairs, independent of payload. -/
theorem authorized_same_level (packet : Packet) (allowed : authorized packet = true) :
    packet.source.level = packet.destination.level := by
  cases packet with
  | mk source destination payload =>
    cases source <;> cases destination <;>
      simp_all [authorized, Deployment.authorizedHostPairs, RedHost.deviceId, RedHost.level]

/-- The state is universally quantified: the result holds even if every flag
is true. Different security labels never create an authorized peer pair. -/
theorem cross_level_blocked (state : GatewayState) (packet : Packet)
    (different : packet.source.level ≠ packet.destination.level) :
    transmit state packet = none := by
  have denied : authorized packet = false := by
    cases h : authorized packet with
    | false => rfl
    | true => exact False.elim (different (authorized_same_level packet h))
  simp [transmit, innerEncrypt, denied]

theorem unauthorized_peer_blocked (state : GatewayState) (packet : Packet)
    (denied : authorized packet = false) : transmit state packet = none := by
  simp [transmit, innerEncrypt, denied]

theorem inner_failure_closed (state : GatewayState) (packet : Packet)
    (down : state.innerSA = false) : transmit state packet = none := by
  simp [transmit, innerEncrypt, down]

theorem inner_policy_loss_closed (state : GatewayState) (packet : Packet)
    (missing : state.innerPolicy = false) : transmit state packet = none := by
  simp [transmit, innerEncrypt, missing]

theorem inner_authentication_failure_closed (state : GatewayState) (packet : Packet)
    (untrusted : state.innerPeerAuthenticated = false) : transmit state packet = none := by
  simp [transmit, innerEncrypt, untrusted]

theorem outer_failure_closed (state : GatewayState) (packet : Packet)
    (down : state.outerSA = false) : transmit state packet = none := by
  simp [transmit, outerEncrypt, down]

theorem outer_policy_loss_closed (state : GatewayState) (packet : Packet)
    (missing : state.outerPolicy = false) : transmit state packet = none := by
  simp [transmit, outerEncrypt, missing]

theorem outer_authentication_failure_closed (state : GatewayState) (packet : Packet)
    (untrusted : state.outerPeerAuthenticated = false) : transmit state packet = none := by
  simp [transmit, outerEncrypt, untrusted]

/-- The model promises no automatic route recovery or convergence time. -/
theorem transport_failure_blocks (state : GatewayState) (packet : Packet)
    (down : state.transportReady = false) : transmit state packet = none := by
  simp [transmit, outerEncrypt, down]

/-- The existential witness identifies the intermediate encrypted packet.
Inspecting the partial inner result rules out its blocked case. -/
theorem forwarded_has_both_steps (state : GatewayState) (packet : Packet)
    (output : BlackPacket) (h : transmit state packet = some output) :
    ∃ inner, innerEncrypt state packet = some inner ∧
      outerEncrypt state inner = some output := by
  unfold transmit at h
  cases first : innerEncrypt state packet with
  | none => simp [first] at h
  | some inner => exact ⟨inner, rfl, by simpa [first] using h⟩

theorem forwarded_same_level (state : GatewayState) (packet : Packet)
    (output : BlackPacket) (h : transmit state packet = some output) :
    packet.source.level = packet.destination.level := by
  by_cases same : packet.source.level = packet.destination.level
  · exact same
  · rw [cross_level_blocked state packet same] at h
    cases h

/-- A successful receive witnesses outer decryption before inner decryption. -/
theorem delivered_has_decryption_steps (sender receiver : GatewayState)
    (packet result : Packet) (h : deliver sender receiver packet = some result) :
    ∃ black inner, transmit sender packet = some black ∧
      outerDecrypt receiver black = some inner ∧ innerDecrypt receiver inner = some result := by
  unfold deliver at h
  cases first : transmit sender packet with
  | none => simp [first] at h
  | some black =>
    cases second : outerDecrypt receiver black with
    | none => simp [first, second] at h
    | some inner => exact ⟨black, inner, rfl, second, by simpa [first, second] using h⟩

theorem cross_level_not_delivered (sender receiver : GatewayState) (packet : Packet)
    (different : packet.source.level ≠ packet.destination.level) :
    deliver sender receiver packet = none := by
  simp [deliver, cross_level_blocked sender packet different]

theorem receiver_inner_failure_closed (sender receiver : GatewayState) (packet : Packet)
    (down : receiver.innerSA = false) : deliver sender receiver packet = none := by
  simp [deliver, innerDecrypt, down]

theorem receiver_outer_failure_closed (sender receiver : GatewayState) (packet : Packet)
    (down : receiver.outerSA = false) : deliver sender receiver packet = none := by
  simp [deliver, outerDecrypt, down]

/-- Assumptions for runnable examples, kept separate from sampled evidence. -/
def healthy : GatewayState := ⟨true, true, true, true, true, true, true, true, true⟩

theorem ready_authorized_forwards (packet : Packet) (allowed : authorized packet = true) :
    transmit healthy packet = some ⟨⟨packet⟩⟩ := by
  simp [transmit, innerEncrypt, outerEncrypt, healthy, allowed]

theorem ready_authorized_delivers (packet : Packet) (allowed : authorized packet = true) :
    deliver healthy healthy packet = some packet := by
  unfold deliver
  rw [ready_authorized_forwards packet allowed]
  simp [outerDecrypt, innerDecrypt, healthy]

def sameLevelPacket : Packet := ⟨.a1, .b1, "Hello from R_A1"⟩
def crossLevelPacket : Packet := ⟨.a1, .b2, "Must be blocked"⟩

end TDN.MSC
