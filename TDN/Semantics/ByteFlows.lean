import Cslib.Foundations.Semantics.LTS.Basic
import Mathlib.Data.List.Basic

namespace TDN.ByteFlows

/-- Bytes retain their source annotations when packets split or are reassembled.
Those annotations are not wire fields or reassembly matching conditions. -/
structure Carrier (State Byte : Type) where
  state : State
  bytes : List Byte

inductive Action (NetworkAction : Type) where
  | inject | split | assemble | copy | discard | permute
  | network (label : NetworkAction)

/-- Any number of packets and fragments may coexist. Splitting permits arbitrary
finite partitions. Copying retains any subset of a packet's bytes in a saved
context while the original packet can continue. Permutation lets assembly select pieces interleaved with unrelated
packets. Assembly uses the supplied operational state relation and can
combine different source packets. Actual key/offset restrictions can narrow this
relation without weakening the preservation result. -/
inductive Step {S B A : Type} (network : Cslib.LTS S A)
    (origin : S → B → Prop) (canAssemble : S → S → Prop) :
    List (Carrier S B) → Action A → List (Carrier S B) → Prop where
  | inject {before state bytes} (source : ∀ byte ∈ bytes, origin state byte) :
      Step network origin canAssemble before .inject (before ++ [⟨state, bytes⟩])
  | network {earlier later state after bytes label} (step : network.Tr state label after) :
      Step network origin canAssemble (earlier ++ ⟨state, bytes⟩ :: later)
        (.network label) (earlier ++ ⟨after, bytes⟩ :: later)
  | split {earlier later state bytes} {chunks : List (List B)} (partition : chunks.flatten = bytes) :
      Step network origin canAssemble (earlier ++ ⟨state, bytes⟩ :: later) .split
        ((earlier ++ chunks.map (fun chunk => ⟨state, chunk⟩)) ++ later)
  | assemble {earlier later} {packets : List (Carrier S B)} {after}
      (nonempty : packets ≠ [])
      (compatible : ∀ packet ∈ packets, canAssemble packet.state after) :
      Step network origin canAssemble ((earlier ++ packets) ++ later) .assemble
        (earlier ++ ⟨after, (packets.map Carrier.bytes).flatten⟩ :: later)
  | permute {before after} (reordered : before.Perm after) :
      Step network origin canAssemble before .permute after
  | copy {before packet bytes} (present : packet ∈ before)
      (selected : ∀ byte ∈ bytes, byte ∈ packet.bytes) :
      Step network origin canAssemble before .copy (before ++ [⟨packet.state, bytes⟩])
  | discard {before after} (retained : after.Sublist before) :
      Step network origin canAssemble before .discard after

def lts {S B A : Type} (network : Cslib.LTS S A)
    (origin : S → B → Prop) (canAssemble : S → S → Prop) :
    Cslib.LTS (List (Carrier S B)) (Action A) := ⟨Step network origin canAssemble⟩

def Safe {S B : Type} (property : B → S → Prop) (packets : List (Carrier S B)) : Prop :=
  ∀ packet ∈ packets, ∀ byte ∈ packet.bytes, property byte packet.state

lemma step_preserves_bytes {S B A : Type} (network : Cslib.LTS S A)
    (origin : S → B → Prop) (canAssemble : S → S → Prop)
    (property : B → S → Prop)
    (injection : ∀ state byte, origin state byte → property byte state)
    (forwarding : ∀ byte, network.TrInv (property byte))
    (assembly : ∀ before after byte, canAssemble before after →
      property byte before → property byte after) :
    (lts network origin canAssemble).TrInv (Safe property) := by
  intro before label after step initial
  cases step with
  | inject source =>
    intro packet member byte contains
    rcases List.mem_append.mp member with old | added
    · exact initial packet old byte contains
    · have same := List.mem_singleton.mp added
      subst packet
      exact injection _ byte (source byte contains)
  | @network earlier later state after bytes label step =>
    intro packet member byte contains
    rcases List.mem_append.mp member with old | tail
    · exact initial packet (List.mem_append_left _ old) byte contains
    · rcases List.mem_cons.mp tail with same | old
      · subst packet
        exact forwarding byte state label after step
          (initial ⟨state, bytes⟩ (by simp) byte contains)
      · exact initial packet (List.mem_append_right _ (List.mem_cons_of_mem _ old)) byte contains
  | @split earlier later state bytes chunks partition =>
    intro packet member byte contains
    rcases List.mem_append.mp member with front | old
    · rcases List.mem_append.mp front with old | mapped
      · exact initial packet (List.mem_append_left _ old) byte contains
      · obtain ⟨chunk, included, equal⟩ := List.mem_map.mp mapped
        subst packet
        have inOriginal : byte ∈ bytes := by
          rw [← partition]
          exact List.mem_flatten.mpr ⟨chunk, included, contains⟩
        exact initial ⟨state, bytes⟩ (by simp) byte inOriginal
    · exact initial packet (List.mem_append_right _ (List.mem_cons_of_mem _ old)) byte contains
  | @assemble earlier later packets after nonempty compatible =>
    intro packet member byte contains
    rcases List.mem_append.mp member with old | tail
    · exact initial packet (List.mem_append_left _ (List.mem_append_left _ old)) byte contains
    · rcases List.mem_cons.mp tail with same | old
      · subst packet
        obtain ⟨bytes, mapped, included⟩ := List.mem_flatten.mp contains
        obtain ⟨source, sourceMember, equal⟩ := List.mem_map.mp mapped
        subst bytes
        exact assembly source.state after byte (compatible source sourceMember)
          (initial source (List.mem_append_left _ (List.mem_append_right _ sourceMember)) byte included)
      · exact initial packet (List.mem_append_right _ old) byte contains
  | permute reordered =>
    exact fun packet member byte contains =>
      initial packet (reordered.mem_iff.mpr member) byte contains
  | copy present selected =>
    intro packet member byte contains
    rcases List.mem_append.mp member with old | copied
    · exact initial packet old byte contains
    · have equal := List.mem_singleton.mp copied
      subst packet
      exact initial _ present byte (selected byte contains)
  | discard retained =>
    exact fun packet member byte contains => initial packet (retained.subset member) byte contains

/-- CSLib lifts the local injection, packet-processing and assembly rules across
arbitrary interleavings, repeated splitting and mixed-packet reassembly. -/
theorem all_executions_preserve_byte_properties {S B A : Type}
    (network : Cslib.LTS S A) (origin : S → B → Prop) (canAssemble : S → S → Prop)
    (property : B → S → Prop)
    (injection : ∀ state byte, origin state byte → property byte state)
    (forwarding : ∀ byte, network.TrInv (property byte))
    (assembly : ∀ before after byte, canAssemble before after →
      property byte before → property byte after)
    {before after : List (Carrier S B)} {actions : List (Action A)}
    (run : (lts network origin canAssemble).MTr before actions after)
    (initial : Safe property before) : Safe property after :=
  Cslib.LTS.mtrInv_of_trInv
    (step_preserves_bytes network origin canAssemble property injection forwarding assembly)
    before actions after run initial


/-- Every ordinary packet path remains possible with any retained source-byte list. -/
theorem network_trace_on_one_carrier {S B A : Type}
    (network : Cslib.LTS S A) (origin : S → B → Prop) (canAssemble : S → S → Prop)
    (bytes : List B) {before after : S} {actions : List A}
    (run : network.MTr before actions after) :
    (lts network origin canAssemble).MTr [⟨before, bytes⟩]
      (actions.map Action.network) [⟨after, bytes⟩] := by
  induction run with
  | refl => exact Cslib.LTS.MTr.refl
  | stepL step rest ih =>
    exact Cslib.LTS.MTr.stepL
      (Step.network (earlier := []) (later := []) step) ih

end TDN.ByteFlows
