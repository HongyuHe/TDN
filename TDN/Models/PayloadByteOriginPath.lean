import TDN.Models.MultiPacketByteFlows

namespace TDN.ByteLineage

inductive Step {S A : Type} (network : Cslib.LTS S A) (assembly : S → S → Prop) :
    S → Option A → S → Prop where
  | network {before after action} (step : network.Tr before action after) :
      Step network assembly before (some action) after
  | assemble {before after} (compatible : assembly before after) :
      Step network assembly before none after

def lts {S A : Type} (network : Cslib.LTS S A) (assembly : S → S → Prop) :
    Cslib.LTS S (Option A) := ⟨Step network assembly⟩

def HasOrigin {S B A : Type} (network : Cslib.LTS S A) (origin : S → B → Prop)
    (assembly : S → S → Prop) (byte : B) (state : S) : Prop :=
  ∃ start actions, origin start byte ∧ (lts network assembly).MTr start actions state

theorem every_byte_has_source_path {S B A : Type}
    (network : Cslib.LTS S A) (origin : S → B → Prop) (assembly : S → S → Prop)
    {after : List (ByteFlows.Carrier S B)} {actions : List (ByteFlows.Action A)}
    (run : (ByteFlows.lts network origin assembly).MTr [] actions after) :
    ByteFlows.Safe (HasOrigin network origin assembly) after := by
  refine ByteFlows.all_traces_preserve_byte_properties network origin assembly
    (HasOrigin network origin assembly) ?_ ?_ ?_ run ?_
  · intro state byte source
    exact ⟨state, [], source, Cslib.LTS.MTr.refl⟩
  · intro byte before action after step path
    obtain ⟨start, labels, source, prior⟩ := path
    exact ⟨start, labels ++ [some action], source,
      prior.stepR (lts network assembly) (Step.network step)⟩
  · intro before after byte compatible path
    obtain ⟨start, labels, source, prior⟩ := path
    exact ⟨start, labels ++ [none], source,
      prior.stepR (lts network assembly) (Step.assemble compatible)⟩
  · simp [ByteFlows.Safe]

lemma local_checks_preserve_lineage {S A : Type}
    (network : Cslib.LTS S A) (assembly : S → S → Prop) (property : S → Prop)
    (networkChecks : network.TrInv property)
    (assemblyChecks : ∀ before after, assembly before after → property before → property after) :
    (lts network assembly).TrInv property := by
  intro before action after step safe
  cases step with
  | network step => exact networkChecks _ _ _ step safe
  | assemble compatible => exact assemblyChecks _ _ compatible safe

end TDN.ByteLineage
