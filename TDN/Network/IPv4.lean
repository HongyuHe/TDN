import Std

/-! Reusable IPv4 addresses, prefixes, and strict text parsing. -/
namespace TDN.Network

/-- IPv4 addresses are unsigned 32-bit values. A prefix length is generated
from a validated IPv4 CIDR, so the snapshot contains only lengths 0 through 32. -/
structure Prefix where
  address : UInt32
  length : Nat
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def Prefix.contains (cidr : Prefix) (address : UInt32) : Bool :=
  address.toNat / 2 ^ (32 - cidr.length) ==
    cidr.address.toNat / 2 ^ (32 - cidr.length)

theorem Prefix.host_contains (address candidate : UInt32) :
    (Prefix.mk address 32).contains candidate = (address == candidate) := by
  apply Bool.eq_iff_iff.mpr
  simp only [Prefix.contains, Nat.sub_self, Nat.pow_zero, Nat.div_one,
    beq_iff_eq, UInt32.toNat_inj]
  exact eq_comm

def Prefix.networkIndex (cidr : Prefix) : Nat :=
  cidr.address.toNat / 2 ^ (32 - cidr.length)

/-- Equal-width CIDRs with different network indices have no common address.
The width is a parameter; the lemma is not tied to the MSC /24 allocation. -/
def Prefix.sameWidthApart (a b : Prefix) : Bool :=
  a.length == b.length && a.networkIndex != b.networkIndex

theorem Prefix.same_width_apart_disjoint (a b : Prefix)
    (separated : a.sameWidthApart b = true) (address : UInt32)
    (inA : a.contains address = true) (inB : b.contains address = true) : False := by
  simp only [Prefix.sameWidthApart, Bool.and_eq_true, beq_iff_eq, bne_iff_ne] at separated
  simp only [Prefix.contains, beq_iff_eq] at inA inB
  apply separated.2
  unfold Prefix.networkIndex
  rw [← inA, ← inB, separated.1]

/-- Different-width prefixes are conservatively compatible. Equal-width
prefixes are compatible exactly when their network indices agree. The check
can over-approximate overlap, which makes its use in safety certificates sound. -/
def Prefix.compatible (a b : Prefix) : Bool := !a.sameWidthApart b

theorem Prefix.shared_address_implies_compatible (a b : Prefix) (address : UInt32)
    (inA : a.contains address = true) (inB : b.contains address = true) :
    a.compatible b = true := by
  cases apart : a.sameWidthApart b with
  | false => simp [Prefix.compatible, apart]
  | true => exact False.elim (a.same_width_apart_disjoint b apart address inA inB)

structure LabeledPrefix (Label : Type) where
  label : Label
  network : Prefix
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

theorem labeled_prefix_members_share_label {Label : Type} (domains : List (LabeledPrefix Label))
    (separated : ∀ a ∈ domains, ∀ b ∈ domains, a.label ≠ b.label → a.network.sameWidthApart b.network = true)
    (a b : LabeledPrefix Label) (memberA : a ∈ domains) (memberB : b ∈ domains)
    (address : UInt32) (inA : a.network.contains address = true)
    (inB : b.network.contains address = true) : a.label = b.label := by
  apply Classical.byContradiction
  intro different
  exact Prefix.same_width_apart_disjoint a.network b.network (separated a memberA b memberB different) address inA inB

/-- Parse a concrete IPv4 address inside Lean, so policy contracts can derive
addresses from tunnel declarations independently of the Python rule parser.
Malformed or out-of-range values return `none`; no truncation is accepted. -/
def splitChars (separator : Char) (value : List Char) : List (List Char) :=
  value.foldr (fun c parts =>
    if c = separator then [] :: parts
    else match parts with
      | [] => [[c]]
      | first :: rest => (c :: first) :: rest) [[]]

def decimalChars? (value : List Char) : Option Nat :=
  if value.isEmpty then none else
    value.foldlM (fun n c =>
      if 48 ≤ c.toNat ∧ c.toNat ≤ 57 then some (10 * n + c.toNat - 48) else none) 0

def ipv4Chars? (value : List Char) : Option UInt32 :=
  match splitChars '.' value with
  | [a, b, c, d] => do
    let a ← decimalChars? a
    let b ← decimalChars? b
    let c ← decimalChars? c
    let d ← decimalChars? d
    if a < 256 ∧ b < 256 ∧ c < 256 ∧ d < 256 then
      some (UInt32.ofNat (a * 16777216 + b * 65536 + c * 256 + d))
    else none
  | _ => none

def ipv4? (value : String) : Option UInt32 := ipv4Chars? value.toList

/-- A tunnel selector must explicitly include its IPv4 prefix length. -/
def Prefix.parse? (value : String) : Option Prefix :=
  match splitChars '/' value.toList with
  | [address, length] => do
    let address ← ipv4Chars? address
    let length ← decimalChars? length
    if length ≤ 32 then some ⟨address, length⟩ else none
  | _ => none

/-- IPv4 multicast destinations occupy the complete 224.0.0.0/4 range. -/
def ipv4Multicast (address : UInt32) : Bool :=
  (Prefix.mk 0xe0000000 4).contains address

end TDN.Network
