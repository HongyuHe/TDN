import TDN.Import.Command
import TDN.Targets.Administration

namespace TDN.Imported.FreshAdministratorSessions
open Targets
set_option maxRecDepth 100000
set_option maxHeartbeats 0

/-- Credential identities are modeled here. Human appointments and AW accounts remain external. -/
tdn_data accounts : List AdministrativeAccount from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.accounts"]

tdn_data authentication0 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.authentication0"]

tdn_data operation0 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.operation0"]

tdn_data authentication1 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.authentication1"]

tdn_data operation1 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.operation1"]

tdn_data authentication2 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.authentication2"]

tdn_data operation2 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.operation2"]

tdn_data authentication3 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.authentication3"]

tdn_data operation3 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.operation3"]

tdn_data authentication4 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.authentication4"]

tdn_data operation4 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.operation4"]

tdn_data authentication5 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.authentication5"]

tdn_data operation5 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.operation5"]

tdn_data authentication6 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.authentication6"]

tdn_data operation6 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.operation6"]

tdn_data authentication7 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.authentication7"]

tdn_data operation7 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.operation7"]

tdn_data authentication8 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.authentication8"]

tdn_data operation8 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.operation8"]

tdn_data authentication9 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.authentication9"]

tdn_data operation9 : AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.operation9"]

/-- Session names and causal orders are witnesses derived from the reviewed handler sequence. -/
tdn_data sessions : List AdministrativeSession from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.sessions"]

tdn_data events : List AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.events"]

tdn_data actions : List AdminEvent from "../../evidence/lean/FreshAdministratorSessions.json" ["TDN.Imported.FreshAdministratorSessions.actions"]

def needsAuthentication (event : AdminEvent) : Prop := event.kind = .operation
def prerequisite := MatchingAdministratorAuthentication false false events accounts sessions

lemma step0 : (Admission.lts needsAuthentication prerequisite).Tr [] authentication0 [authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step1 : (Admission.lts needsAuthentication prerequisite).Tr [authentication0] operation0 [operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step2 : (Admission.lts needsAuthentication prerequisite).Tr [operation0, authentication0] authentication1 [authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step3 : (Admission.lts needsAuthentication prerequisite).Tr [authentication1, operation0, authentication0] operation1 [operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step4 : (Admission.lts needsAuthentication prerequisite).Tr [operation1, authentication1, operation0, authentication0] authentication2 [authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step5 : (Admission.lts needsAuthentication prerequisite).Tr [authentication2, operation1, authentication1, operation0, authentication0] operation2 [operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step6 : (Admission.lts needsAuthentication prerequisite).Tr [operation2, authentication2, operation1, authentication1, operation0, authentication0] authentication3 [authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step7 : (Admission.lts needsAuthentication prerequisite).Tr [authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] operation3 [operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step8 : (Admission.lts needsAuthentication prerequisite).Tr [operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] authentication4 [authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step9 : (Admission.lts needsAuthentication prerequisite).Tr [authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] operation4 [operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step10 : (Admission.lts needsAuthentication prerequisite).Tr [operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] authentication5 [authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step11 : (Admission.lts needsAuthentication prerequisite).Tr [authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] operation5 [operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step12 : (Admission.lts needsAuthentication prerequisite).Tr [operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] authentication6 [authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step13 : (Admission.lts needsAuthentication prerequisite).Tr [authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] operation6 [operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step14 : (Admission.lts needsAuthentication prerequisite).Tr [operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] authentication7 [authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step15 : (Admission.lts needsAuthentication prerequisite).Tr [authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] operation7 [operation7, authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step16 : (Admission.lts needsAuthentication prerequisite).Tr [operation7, authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] authentication8 [authentication8, operation7, authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step17 : (Admission.lts needsAuthentication prerequisite).Tr [authentication8, operation7, authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] operation8 [operation8, authentication8, operation7, authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step18 : (Admission.lts needsAuthentication prerequisite).Tr [operation8, authentication8, operation7, authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] authentication9 [authentication9, operation8, authentication8, operation7, authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma step19 : (Admission.lts needsAuthentication prerequisite).Tr [authentication9, operation8, authentication8, operation7, authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] operation9 [operation9, authentication9, operation8, authentication8, operation7, authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0] := by
  apply Admission.Step.record
  simp [needsAuthentication, prerequisite, MatchingAdministratorAuthentication, AdministrativeSessionActive, accounts, sessions, events, authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]

lemma admitted_history : (Admission.lts needsAuthentication prerequisite).MTr [] actions events := by
  exact Cslib.LTS.MTr.stepL step0 (Cslib.LTS.MTr.stepL step1 (Cslib.LTS.MTr.stepL step2 (Cslib.LTS.MTr.stepL step3 (Cslib.LTS.MTr.stepL step4 (Cslib.LTS.MTr.stepL step5 (Cslib.LTS.MTr.stepL step6 (Cslib.LTS.MTr.stepL step7 (Cslib.LTS.MTr.stepL step8 (Cslib.LTS.MTr.stepL step9 (Cslib.LTS.MTr.stepL step10 (Cslib.LTS.MTr.stepL step11 (Cslib.LTS.MTr.stepL step12 (Cslib.LTS.MTr.stepL step13 (Cslib.LTS.MTr.stepL step14 (Cslib.LTS.MTr.stepL step15 (Cslib.LTS.MTr.stepL step16 (Cslib.LTS.MTr.stepL step17 (Cslib.LTS.MTr.stepL step18 (Cslib.LTS.MTr.stepL step19 (Cslib.LTS.MTr.refl))))))))))))))))))))

/-- The result is limited to the retained service requests. The import report records the source contract. -/
theorem recorded_service_authentication :
    msc_administrator_authentication false false events accounts sessions [] := by
  apply administrator_authentication_from_admitted_operations false false events actions accounts sessions [] (fun _ => 0)
  · exact admitted_history
  · decide
  · simp

theorem successful_operations_are_present :
    (events.filter (fun event => event.kind == .operation)).length = 10 := by decide

end TDN.Imported.FreshAdministratorSessions
