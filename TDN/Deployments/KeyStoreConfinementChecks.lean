import TDN.Requirements.VerifiedPrivateKeyConfinement

namespace TDN.Deployments.KeyStoreConfinementChecks
open KeyInterface

def key : String × String := ("gateway", "private.key")
def tokenObject : Object (String × String) := ⟨1, key, true, false⟩
def copiedObject : Object (String × String) := ⟨2, key, true, false⟩
def confidential (identity : String × String) : Prop := identity = key
def permitted (identity : String × String) (principal : String) : Prop :=
  identity = key ∧ principal = "gateway"

def usefulActions : List (KeyInterface.Action (String × String) String String) :=
  [.provision tokenObject, .duplicate tokenObject copiedObject,
    .sign copiedObject "gateway", .reject "C_GetAttributeValue(CKA_VALUE)"]

lemma useful_run :
    (system confidential permitted).MTr [] usefulActions [copiedObject, tokenObject] := by
  refine .stepL (KeyInterface.Step.provision [] tokenObject (fun _ => ⟨rfl, rfl⟩)) ?_
  refine .stepL (KeyInterface.Step.duplicate [tokenObject] tokenObject copiedObject
    (by native_decide) rfl (by native_decide) (by native_decide)) ?_
  refine .stepL (KeyInterface.Step.sign [copiedObject, tokenObject] copiedObject "gateway"
    (by native_decide) ⟨rfl, rfl⟩) ?_
  exact .single _ (KeyInterface.Step.reject [copiedObject, tokenObject] "C_GetAttributeValue(CKA_VALUE)")

lemma signing_is_possible :
    KeyInterface.Event.read key "gateway" ∈ usefulActions.flatMap KeyInterface.Action.events := by native_decide

lemma useful_run_cannot_export (interface : String) :
    KeyInterface.Event.export key interface ∉ usefulActions.flatMap KeyInterface.Action.events := by
  exact protected_exports_impossible useful_run (by simp [StoreSafe]) rfl interface

lemma unsafe_copy_rejected :
    ¬ KeyInterface.Step (Interface := String) confidential permitted [tokenObject]
      (.duplicate tokenObject { copiedObject with sensitive := false })
      [{ copiedObject with sensitive := false }, tokenObject] := by
  intro step
  have invalid := step_preserves_store step
    (by simp [StoreSafe, tokenObject, Object.Restricted])
    { copiedObject with sensitive := false } (List.mem_cons_self ..) rfl
  exact Bool.noConfusion invalid.1

lemma wrapping_protected_key_rejected :
    ¬ KeyInterface.Step (Interface := String) confidential permitted [tokenObject]
      (.wrap tokenObject "rpc") [tokenObject] := by
  intro step
  have impossible := step_export_impossible step
    (by simp [StoreSafe, tokenObject, Object.Restricted])
    (key := key) rfl "rpc"
  exact impossible (by native_decide)

def fileObject : Object (String × String) := ⟨3, key, false, true⟩

lemma readable_object_has_export_path :
    ∃ action, KeyInterface.Step (Interface := String) confidential permitted [fileObject] action [fileObject] ∧
      KeyInterface.Event.export key "console" ∈ action.events := by
  exact ⟨.value fileObject "console", KeyInterface.Step.value [fileObject] fileObject "console"
    (by native_decide) rfl, by native_decide⟩

lemma unsafe_provisioning_rejected :
    ¬ KeyInterface.Step (Interface := String) confidential permitted [] (.provision fileObject) [fileObject] := by
  intro step
  have invalid := step_preserves_store step (by simp [StoreSafe])
    fileObject (List.mem_singleton_self _) rfl
  exact Bool.noConfusion invalid.1

end TDN.Deployments.KeyStoreConfinementChecks
