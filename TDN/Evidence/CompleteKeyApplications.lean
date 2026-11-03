import TDN.Evidence.KeyInterfaceChecks

namespace TDN.Imported.CompleteKeyApplications
open Compliance Targets Targets.Complete

abbrev Store := List KeyObject
abbrev Native := NativeExecutionBinding Store KeyAction

def keys : List PrivateKey := [⟨"private.key", "gateway"⟩]

def readers (identity : GatewayKey) : Finset String := {identity.1}

def token : KeyObject := ⟨1, ("gateway", "private.key"), true, false⟩

def copied : KeyObject := ⟨2, ("gateway", "private.key"), true, false⟩

def store (copyFirst : Bool) : Store :=
  if copyFirst then [copied, token] else [token]

def setup (copyFirst : Bool) : List KeyAction :=
  if copyFirst then [.provision token, .duplicate token copied] else [.provision token]

def events : KeyAction → List ProcessingEvent
  | .sign object principal | .digest object principal =>
      [.privateKeyRead object.key.1 object.key.2 principal]
  | .value object interface | .wrap object interface =>
      [.privateKeyExport object.key.1 object.key.2 interface]
  | _ => []

def model (native : Native) (copyFirst : Bool) : ExecutionModel Store KeyAction :=
  { system := KeyInterface.system (protectedGatewayKey keys)
      (fun identity principal => principal ∈ readers identity)
    initial := fun state => state = store copyFirst
    events := events
    native := native }

def deployment (base : Deployment) : Deployment :=
  { base with storedVPNKey := fun gateway key => gateway = "gateway" ∧ key = "private.key" }

def policies : List MandatoryKeyPolicy :=
  [⟨"gateway", true, fun principal _ => principal = "gateway"⟩]

lemma setup_run (copyFirst : Bool) :
    (KeyInterface.system (protectedGatewayKey keys)
      (fun identity principal => principal ∈ readers identity)).MTr
      [] (setup copyFirst) (store copyFirst) := by
  cases copyFirst with
  | false =>
      exact .single _ (.provision [] token (by simp [KeyInterface.Object.Restricted, token]))
  | true =>
      refine .stepL (.provision [] token (by simp [KeyInterface.Object.Restricted, token])) ?_
      exact .single _ (.duplicate [token] token copied (by simp) rfl
        (by simp [token, copied]) (by simp [token, copied]))

lemma event_projection (action : KeyAction) :
    (events action).flatMap privateEvent = action.events := by
  cases action <;> rfl

theorem complete_interface_model_RG021 (base : Deployment) (native : Native)
    (copyFirst : Bool) :
    msc_vpn_private_key_confinement (deployment base) (model native copyFirst)
      keys (fun _ => true) policies := by
  apply vpn_private_key_confinement_from_interface_steps
    (deployment base) (model native copyFirst) keys (fun _ => true) policies
    readers id id [] (store copyFirst) (setup copyFirst)
  · simp [deployment, keys, eq_comm]
  · simp [KeyInterface.StoreSafe]
  · exact setup_run copyFirst
  · intro state initial
    exact initial
  · intro before action after step
    exact step
  · cases copyFirst <;> rfl
  · exact event_projection
  · intro key member _
    simp only [keys, List.mem_singleton] at member
    subst key
    exact Finset.Subset.refl _
  · intro key member _
    simp only [keys, List.mem_singleton] at member
    subst key
    refine ⟨⟨"gateway", true, fun principal _ => principal = "gateway"⟩,
      by simp [policies], rfl, rfl, ?_⟩
    intro principal
    simp [readers]

theorem signing_model_RG021 (base : Deployment) (native : Native) :
    msc_vpn_private_key_confinement (deployment base) (model native false)
      keys (fun _ => true) policies :=
  complete_interface_model_RG021 base native false

theorem copied_digest_model_RG021 (base : Deployment) (native : Native) :
    msc_vpn_private_key_confinement (deployment base) (model native true)
      keys (fun _ => true) policies :=
  complete_interface_model_RG021 base native true

lemma signing_is_reachable (native : Native) :
    (model native false).initial [token] ∧
    (model native false).system.MTr [token] [.sign token "gateway"] [token] ∧
    ProcessingEvent.privateKeyRead "gateway" "private.key" "gateway" ∈
      (model native false).TraceEvents [.sign token "gateway"] := by
  refine ⟨rfl, .single _ (.sign [token] token "gateway" (by simp) (by simp [readers, token])), ?_⟩
  simp [ExecutionModel.TraceEvents, model, events, ObservedHistory.Events, token]

lemma copied_digest_is_reachable (native : Native) :
    (model native true).initial [copied, token] ∧
    (model native true).system.MTr [copied, token] [.digest copied "gateway"] [copied, token] ∧
    ProcessingEvent.privateKeyRead "gateway" "private.key" "gateway" ∈
      (model native true).TraceEvents [.digest copied "gateway"] := by
  refine ⟨rfl, .single _ (.digest [copied, token] copied "gateway"
    (by simp) (by simp [readers, copied])), ?_⟩
  simp [ExecutionModel.TraceEvents, model, events, ObservedHistory.Events, copied]

end TDN.Imported.CompleteKeyApplications
