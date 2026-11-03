import TDN.Targets.CompleteSpecifications

namespace TDN.Targets.Complete
open Compliance

structure KeyGenerationRecords where
  generators : List String
  administrators : List String
  eapDerivations : List (String × String)

def KeyOriginChecks (d : Deployment) (key : MACsecKey) (provisioning : List KeyProvisioning)
    (records : KeyGenerationRecords) : Prop :=
  match key.cakOrigin with
  | .generated generator => generator ∈ records.generators ∧
      ∃ provision ∈ provisioning, provision.key = key.cak ∧ provision.generator = generator ∧
        provision.administrator ∈ records.administrators ∧
        ∀ tunnel ∈ d.tunnels, tunnel.mechanism = .macsec → tunnel.keyContext = key.cak →
          (∃ applied ∈ provision.applications,
            applied.1 = tunnel.sender ∧ provision.obtainedOrder < applied.2) ∧
          ∃ applied ∈ provision.applications,
            applied.1 = tunnel.receiver ∧ provision.obtainedOrder < applied.2
  | .eapDerived msk => msk ≠ "" ∧ ∃ generator ∈ records.generators,
      (key.cak, generator) ∈ records.eapDerivations

instance (d : Deployment) (key : MACsecKey) (provisioning : List KeyProvisioning)
    (records : KeyGenerationRecords) : Decidable (KeyOriginChecks d key provisioning records) := by
  unfold KeyOriginChecks
  cases key.cakOrigin <;> infer_instance

def ServerCentralCheck (d : Deployment) (pair : MACsecServerPair) : Prop :=
  match pair.centralSite with
  | none => True
  | some site =>
    (∃ first ∈ d.devices, first.id = pair.first ∧ first.site = site ∧ pair.firstValue = 0) ∨
    (∃ second ∈ d.devices, second.id = pair.second ∧ second.site = site ∧ pair.secondValue = 0)

instance (d : Deployment) (pair : MACsecServerPair) : Decidable (ServerCentralCheck d pair) := by
  unfold ServerCentralCheck
  cases pair.centralSite <;> infer_instance

def KeyGenerationChecks (d : Deployment) (keys : List MACsecKey)
    (pairs : List MACsecServerPair) (provisioning : List KeyProvisioning)
    (records : KeyGenerationRecords) : Prop :=
  (∀ key ∈ keys, 16 ≤ key.ckn.length ∧ key.cknGenerator ∈ records.generators ∧
    KeyOriginChecks d key provisioning records ∧ key.fallbackEnabled = false) ∧
  (∀ tunnel ∈ d.tunnels, tunnel.mechanism = .macsec →
    (∃ key ∈ keys, key.cak = tunnel.keyContext) ∧
    ∃ pair ∈ pairs, pair.first = tunnel.sender ∧ pair.second = tunnel.receiver) ∧
  ∀ pair ∈ pairs, pair.centralSite = d.centralManagementSite ∧ pair.first ≠ pair.second ∧
    ((pair.firstValue = 0 ∧ pair.secondValue = 1) ∨
      (pair.firstValue = 1 ∧ pair.secondValue = 0)) ∧ ServerCentralCheck d pair

instance (d : Deployment) (keys : List MACsecKey) (pairs : List MACsecServerPair)
    (provisioning : List KeyProvisioning) (records : KeyGenerationRecords) :
    Decidable (KeyGenerationChecks d keys pairs provisioning records) := by
  unfold KeyGenerationChecks
  infer_instance

def keyGenerationChecked (d : Deployment) (keys : List MACsecKey)
    (pairs : List MACsecServerPair) (provisioning : List KeyProvisioning)
    (records : KeyGenerationRecords) : Bool :=
  decide (KeyGenerationChecks d keys pairs provisioning records)

theorem macsec_key_generation_from_checked_records
    (d : Deployment) (keys : List MACsecKey) (pairs : List MACsecServerPair)
    (provisioning : List KeyProvisioning) (records : KeyGenerationRecords)
    (eapCAKGeneratedByApprovedKGS : String → String → Prop)
    (checked : keyGenerationChecked d keys pairs provisioning records = true)
    (approvedGenerators : ∀ generator ∈ records.generators,
      d.authority.nsaApprovedGenerator generator)
    (authorizedAdministrators : ∀ administrator ∈ records.administrators,
      d.authority.securityAdministrator administrator)
    (derivationsBound : ∀ derivation ∈ records.eapDerivations,
      eapCAKGeneratedByApprovedKGS derivation.1 derivation.2) :
    msc_macsec_key_generation_and_server d keys pairs provisioning
      eapCAKGeneratedByApprovedKGS := by
  have checks : KeyGenerationChecks d keys pairs provisioning records :=
    of_decide_eq_true checked
  refine ⟨?_, ?_, ?_⟩
  · intro key member _
    obtain ⟨length, generator, origin, noFallback⟩ := checks.1 key member
    refine ⟨length, approvedGenerators key.cknGenerator generator, ?_, noFallback⟩
    cases chosen : key.cakOrigin with
    | generated source =>
      simp only [KeyOriginChecks, chosen] at origin ⊢
      obtain ⟨approved, provision, present, sameKey, sameGenerator, administrator, applications⟩ := origin
      refine ⟨approvedGenerators source approved, provision, present,
        sameKey, sameGenerator, authorizedAdministrators provision.administrator administrator, ?_⟩
      intro tunnel member _ mechanism keyContext
      exact applications tunnel member mechanism keyContext
    | eapDerived msk =>
      simp only [KeyOriginChecks, chosen] at origin ⊢
      obtain ⟨nonempty, source, approved, binding⟩ := origin
      exact ⟨nonempty, source, approvedGenerators source approved,
        derivationsBound (key.cak, source) binding⟩
  · intro tunnel member _ mechanism
    exact checks.2.1 tunnel member mechanism
  · intro pair member _
    obtain ⟨central, distinct, values, atSite⟩ := checks.2.2 pair member
    refine ⟨central, distinct, values, ?_⟩
    intro site same
    simpa [ServerCentralCheck, same] using atSite

end TDN.Targets.Complete
