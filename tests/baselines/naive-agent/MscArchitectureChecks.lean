import TDN.Import.SnapshotLoader
import TDN.Requirements.TwoLayerOverlayArchitecture
import TDN.Models.Waypointing
import TDN.Models.OrderedAclFilter
import TDN.Requirements.MscRequirements

namespace TDN.Benchmark.Architecture
set_option Elab.async false

load_network_records reds : List RedNetworkIdentity from "evidence.json" ["reds"]
load_network_records nodeCount : Nat from "evidence.json" ["nodeCount"]
abbrev Node := Fin nodeCount
load_network_records edges : List (Node × Node) from "evidence.json" ["edges"]
load_network_records firewalls : List Node from "evidence.json" ["firewalls"]
load_network_records inners : List Node from "evidence.json" ["inners"]
load_network_records levels : Array String from "evidence.json" ["levels"]
load_network_records regions : Array Nat from "evidence.json" ["regions"]

structure EspPacket where
  source : Nat
  destination : Nat
  ingress : String
  egress : String
  spi : Nat

structure EspRule where
  source : Nat × Nat
  destination : Nat × Nat
  ingress : Option String
  egress : Option String
  spi : Nat × Nat
  permit : Bool

def EspRule.matchesFlow (r : EspRule) (p : EspPacket) : Bool :=
  decide (r.source.1 ≤ p.source ∧ p.source ≤ r.source.2 ∧
    r.destination.1 ≤ p.destination ∧ p.destination ≤ r.destination.2 ∧
    (r.ingress = none ∨ r.ingress = some p.ingress) ∧ (r.egress = none ∨ r.egress = some p.egress))

def EspRule.rule (r : EspRule) : Filter.FirstMatchRule EspPacket :=
  ⟨fun p => r.matchesFlow p && decide (r.spi.1 ≤ p.spi ∧ p.spi ≤ r.spi.2),
    if r.permit then .allow else .deny⟩

structure GrayAcl where
  ifaces : List String
  rules : List EspRule
  defaultAllow : Bool

structure InnerAddress where
  address : Nat
  level : String

load_network_records policies : List GrayAcl from "evidence.json" ["grayAcls"]
load_network_records addresses : List InnerAddress from "evidence.json" ["innerAddresses"]

def deniesRange (p : EspPacket) (fallback : Bool) : List EspRule → Nat → Nat → Bool
  | [], _, _ => !fallback
  | r :: rs, low, high =>
    if r.matchesFlow p && decide (low ≤ r.spi.2 ∧ r.spi.1 ≤ high) then
      !r.permit &&
        (if low < r.spi.1 then deniesRange p fallback rs low (r.spi.1 - 1) else true) &&
        (if r.spi.2 < high then deniesRange p fallback rs (r.spi.2 + 1) high else true)
    else deniesRange p fallback rs low high

theorem range_check_denies_each_spi (p : EspPacket) (fallback : Bool) (rules : List EspRule)
    (low high spi : Nat) (bounds : low ≤ spi ∧ spi ≤ high)
    (checked : deniesRange p fallback rules low high = true) :
    Filter.evaluate (rules.map EspRule.rule) (if fallback then .allow else .deny) {p with spi} = .deny := by
  induction rules generalizing low high with
  | nil => cases fallback <;> simp_all [deniesRange, Filter.evaluate]
  | cons r rs ih =>
    simp only [deniesRange] at checked
    simp only [List.map_cons, Filter.evaluate, EspRule.rule]
    have same : r.matchesFlow { p with spi } = r.matchesFlow p := rfl
    rw [same]
    split at checked
    · rename_i intersects
      simp only [Bool.and_eq_true, Bool.not_eq_true'] at checked
      have flow := (Bool.and_eq_true_iff.mp intersects).1
      rw [flow]
      by_cases left : spi < r.spi.1
      · have lower : low < r.spi.1 := by omega
        simpa [show ¬ r.spi.1 ≤ spi by omega] using
          ih low (r.spi.1 - 1) (by omega) (by simpa [lower] using checked.1.2)
      · by_cases right : r.spi.2 < spi
        · have upper : r.spi.2 < high := by omega
          simpa [show ¬ spi ≤ r.spi.2 by omega] using
            ih (r.spi.2 + 1) high (by omega) (by simpa [upper] using checked.2)
        · simp [show r.spi.1 ≤ spi by omega, show spi ≤ r.spi.2 by omega, checked.1.1]
    · rename_i misses
      have noMatch : ¬ (r.matchesFlow p = true ∧ (r.spi.1 ≤ spi ∧ spi ≤ r.spi.2)) := by
        rintro ⟨flow, h⟩
        have overlap : low ≤ r.spi.2 ∧ r.spi.1 ≤ high := by omega
        simp [flow, overlap] at misses
      simpa [noMatch] using ih low high bounds checked

def edge (a b : Node) : Prop := (a, b) ∈ edges
def region (a : Node) : Nat := regions[a.val]!

def sameLevelOnPermit (permit : Prop) (sourceLevel destinationLevel : String) : Prop :=
  permit → sourceLevel = destinationLevel

theorem sameLevelOnPermit_of_gray_restrictions (net : _)
    (iface : Compliance.Interface) (dir : Compliance.Direction) (traffic : Compliance.Traffic)
    (permit : Prop) (label : SecurityLevel → String) (sourceLevel destinationLevel : String)
    (payload : traffic.trafficClass = .protectedData)
    (ordinary : ¬ Requirements.Msc.RevocationHTTP traffic)
    (restricts : permit → Requirements.Msc.GrayFirewallRestrictions net iface dir traffic)
    (boundEndpoints : ∀ src ∈ net.devices, ∀ dst ∈ net.devices,
      src.layer = some .inner → dst.layer = some .inner → net.InnerPair traffic src.id dst.id →
      label src.level = sourceLevel ∧ label dst.level = destinationLevel) :
    sameLevelOnPermit permit sourceLevel destinationLevel := by
  intro accepted
  obtain ⟨src, hs, dst, hd, sl, dl, eqLevel, _, pair⟩ := (restricts accepted).2.2.1 payload ordinary
  obtain ⟨srcLabel, dstLabel⟩ := boundEndpoints src hs dst hd sl dl pair
  exact srcLabel.symm.trans ((congrArg label eqLevel).trans dstLabel)

run_cmd do Lean.logInfo m!"TDN_BEGIN {← IO.monoNanosNow}"

lemma dedicated_inner_gateways : DedicatedInnerAssignments reds := by
  unfold DedicatedInnerAssignments
  native_decide

lemma gray_edges_preserve_region : ∀ a b : Node, (a,b) ∈ edges →
    a ∉ firewalls → b ∉ firewalls → region a = region b := by
  native_decide

lemma inner_gateways_are_outside_firewalls : ∀ a ∈ inners, a ∉ firewalls := by
  native_decide

lemma different_levels_have_different_regions : ∀ a ∈ inners, ∀ b ∈ inners,
    levels[a.val]! ≠ levels[b.val]! → region a ≠ region b := by
  native_decide

theorem gray_waypointing (a b : Node) (ha : a ∈ inners) (hb : b ∈ inners)
    (different : levels[a.val]! ≠ levels[b.val]!) :
    ¬ Waypointing.ReachableWithoutWaypoint edge (· ∈ firewalls) a b :=
  Waypointing.waypointing_of_edge_invariant edge (· ∈ firewalls) region
    gray_edges_preserve_region (inner_gateways_are_outside_firewalls a ha)
    (different_levels_have_different_regions a ha b hb different)

def espFlow (src dst : InnerAddress) (ingress egress : String) : EspPacket :=
  ⟨src.address, dst.address, ingress, egress, 0⟩

lemma protected_gray_forwarding_respects_levels :
    ∀ acl ∈ policies, ∀ src ∈ addresses, ∀ dst ∈ addresses, src.level ≠ dst.level →
    ∀ ingress ∈ acl.ifaces, ∀ egress ∈ acl.ifaces,
      deniesRange (espFlow src dst ingress egress) acl.defaultAllow acl.rules 1 4294967295 = true := by
  native_decide

theorem admitted_gray_esp_has_same_level (acl : GrayAcl) (ha : acl ∈ policies)
    (src dst : InnerAddress) (hs : src ∈ addresses) (hd : dst ∈ addresses)
    (i o : String) (hi : i ∈ acl.ifaces) (ho : o ∈ acl.ifaces)
    (spi : Nat) (valid : 1 ≤ spi ∧ spi ≤ 4294967295) :
    sameLevelOnPermit (Filter.evaluate (acl.rules.map EspRule.rule)
      (if acl.defaultAllow then .allow else .deny) {espFlow src dst i o with spi} = .allow) src.level dst.level := by
  intro allowed
  by_contra different
  have blocked := range_check_denies_each_spi (espFlow src dst i o) acl.defaultAllow acl.rules
    1 4294967295 spi valid (protected_gray_forwarding_respects_levels acl ha src hs dst hd different i hi o ho)
  rw [blocked] at allowed
  contradiction

run_cmd do Lean.logInfo m!"TDN_END {← IO.monoNanosNow}"
end TDN.Benchmark.Architecture
