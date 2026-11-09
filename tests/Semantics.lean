import TDN

namespace TDN.Tests

def level : SecurityLevel := ⟨"Secret", {"Compartment-A"}, {"US-only"}, {}⟩
def otherCompartment : SecurityLevel := ⟨"Secret", {"Compartment-B"}, {"US-only"}, {}⟩

def coalitionLevel : SecurityLevel := ⟨"Secret", {"Compartment-A"}, {"Coalition"}, {}⟩
def otherControlLevel : SecurityLevel := ⟨"Secret", {"Compartment-A"}, {"US-only"}, {"Export-control"}⟩
def redOne : RedNetworkIdentity := ⟨"network-one", "A", level, {"I-1"}⟩
def redTwo : RedNetworkIdentity := ⟨"network-two", "A", level, {"I-2"}⟩
example : level.classification = coalitionLevel.classification ∧ level ≠ coalitionLevel := by decide
example : level ≠ otherControlLevel := by decide
example : redOne.level = redTwo.level ∧ redOne.id ≠ redTwo.id := by decide
example : DedicatedInnerAssignments [redOne, redTwo] := by
  unfold DedicatedInnerAssignments redOne redTwo
  decide

theorem full_labels_differ : level ≠ otherCompartment := by decide

def network : Network where
  innerLevel := fun _ => level
  innerPeer := fun a b => a = 1 ∧ b = 2
  outerPeer := fun a b => a = 3 ∧ b = 4
  linked := fun a b => (a = 1 ∧ b = 3) ∨ (a = 3 ∧ b = 4) ∨ (a = 4 ∧ b = 2)
  allowedPair := fun _ _ => True

def inner : TunnelHeader := ⟨.inner, 1, 2, .ipsec⟩
def outer : TunnelHeader := ⟨.outer, 3, 4, .ipsec⟩
def start : State := ⟨.red, 1, level, []⟩
def graySource : State := ⟨.gray, 1, level, [inner]⟩
def grayOuter : State := ⟨.gray, 3, level, [inner]⟩
def blackSource : State := ⟨.black, 3, level, [outer, inner]⟩
def blackDestination : State := ⟨.black, 4, level, [outer, inner]⟩
def grayRemote : State := ⟨.gray, 4, level, [inner]⟩
def grayDestination : State := ⟨.gray, 2, level, [inner]⟩
def finish : State := ⟨.red, 2, level, []⟩

/-- A nonempty seven-step useful delivery rules out an empty-transition-model test. -/
theorem useful_delivery : Relation.ReflTransGen (Step network) start finish := by
  have s1 : Step network start graySource := .innerEncrypt 1 2 level .ipsec ⟨rfl, rfl⟩ rfl
  have s2 : Step network graySource grayOuter := .grayTransit 1 3 level inner (Or.inl ⟨rfl, rfl⟩)
  have s3 : Step network grayOuter blackSource := .outerEncrypt 3 4 level inner .ipsec ⟨rfl, rfl⟩ trivial
  have s4 : Step network blackSource blackDestination := .blackTransit 3 4 level outer inner (Or.inr (Or.inl ⟨rfl, rfl⟩))
  have s5 : Step network blackDestination grayRemote := .outerDecrypt level outer inner rfl ⟨rfl, rfl⟩
  have s6 : Step network grayRemote grayDestination := .grayTransit 4 2 level inner (Or.inr (Or.inr ⟨rfl, rfl⟩))
  have s7 : Step network grayDestination finish := .innerDecrypt level inner rfl ⟨rfl, rfl⟩ rfl
  exact ((((((Relation.ReflTransGen.single s1).tail s2).tail s3).tail s4).tail s5).tail s6).tail s7

theorem no_inner_plaintext_bypass (n : Network) (a b : Nat) (l : SecurityLevel) :
    ¬ Step n ⟨.red, a, l, []⟩ ⟨.gray, b, l, []⟩ := by
  intro h
  cases h

open Filter

def policy : List (Rule Nat) := [⟨fun p => p == 7, .allow⟩]

theorem useful_filter : HasUsefulTraffic policy (fun p => p = 7) := by
  exact ⟨7, rfl, rfl⟩

theorem rejects_other : evaluate policy .deny 8 = .deny := rfl

theorem empty_filter_has_no_useful_traffic : ¬ HasUsefulTraffic ([] : List (Rule Nat)) (fun _ => True) := by
  intro ⟨p, _, hp⟩
  cases hp

theorem ordered_deny_precedes_allow :
    evaluate ([⟨fun _ : Nat => true, .deny⟩, ⟨fun _ => true, .allow⟩]) .deny 7 = .deny := rfl

example : ¬ PacketPolicy.ImmediateHeaderGuard [6, 17, 50, 58]
    ⟨[], .allow⟩ := by decide
example : ¬ PacketPolicy.UnicastGuard "black" 3758096384 4026531839
    ⟨[.ingress "black", .destinationRange 0 4294967295], .allow⟩ := by decide
example : ¬ PacketPolicy.ProtocolGuard ["tcp", "udp", "esp", "icmp"]
    ⟨[.protocol "gre"], .allow⟩ := by decide

end TDN.Tests
