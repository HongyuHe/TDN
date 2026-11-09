import TDN.Requirements.NamespaceLocalIpOwnership

namespace TDN.Deployments.NamespaceLocalIpChecks
open Compliance Requirements

def localIface (owner : String) : Interface :=
  { id := owner ++ ":lo", device := owner, zone := .local, address := none,
    namespaceAddresses := [2130706433], physical := false, managementNetwork := false,
    mtu := some 65536 }

def grayIface (owner : String) : Interface :=
  { id := owner ++ ":gray", device := owner, zone := .gray, address := some 174326018,
    namespaceAddresses := [174326018], physical := true, managementNetwork := false,
    mtu := some 1400 }

theorem same_loopback_address_in_two_namespaces :
    namespaceLocalAddress [localIface "A", localIface "B"] "A" 2130706433 ∧
    namespaceLocalAddress [localIface "A", localIface "B"] "B" 2130706433 := by
  decide

theorem another_namespace_does_not_authorize_local_source :
    ¬ namespaceLocalAddress [localIface "A"] "B" 2130706433 := by
  decide

def grayDevice : Device :=
  { id := "G", site := "A", kind := .ordinaryGrayRouter, layer := none,
    level := ⟨"secret", ∅, ∅, ∅⟩, infrastructure := false }

def grayRouter (base : Deployment) : Deployment :=
  { base with devices := [grayDevice], interfaces := [localIface "G", grayIface "G"] }

theorem gray_router_with_loopback_is_recognized (base : Deployment) :
    (grayRouter base).OrdinaryGray "G" := by
  simp [Deployment.OrdinaryGray, grayRouter, grayDevice, localIface, grayIface]

def mixedRouter (base : Deployment) (zone : Zone) : Deployment :=
  { grayRouter base with interfaces :=
    [localIface "G", grayIface "G", { grayIface "G" with id := "G:other", zone := zone }] }

theorem red_interface_excludes_ordinary_gray (base : Deployment) :
    ¬ (mixedRouter base .red).OrdinaryGray "G" := by
  simp [Deployment.OrdinaryGray, mixedRouter, grayRouter, grayDevice, localIface, grayIface]

theorem black_interface_excludes_ordinary_gray (base : Deployment) :
    ¬ (mixedRouter base .black).OrdinaryGray "G" := by
  simp [Deployment.OrdinaryGray, mixedRouter, grayRouter, grayDevice, localIface, grayIface]


def priorProjectedLocalAddress (interfaces : List Interface) (owner : String) (address : Nat) : Prop :=
  ∃ interface ∈ interfaces, interface.device = owner ∧ interface.address = some address

lemma prior_projection_omits_recorded_loopback :
    ¬ priorProjectedLocalAddress [localIface "A"] "A" 2130706433 := by
  unfold priorProjectedLocalAddress
  decide

lemma corrected_projection_recognizes_recorded_loopback :
    namespaceLocalAddress [localIface "A"] "A" 2130706433 := by
  decide


def priorLocalZoneProjection : Interface := { localIface "A" with zone := .red }

lemma prior_local_zone_creates_false_Red_source_obligation :
    ¬ ((none : Option String) = some "A/red-network" ↔
      ∃ interface ∈ [priorLocalZoneProjection], interface.id = "A:lo" ∧ interface.zone = .red ∧
        interface.managementNetwork = false ∧ interface.device ∈ (["A"] : List String)) := by
  decide

lemma corrected_local_zone_is_not_a_Red_attachment : (localIface "A").zone ≠ .red := by
  decide

end TDN.Deployments.NamespaceLocalIpChecks

