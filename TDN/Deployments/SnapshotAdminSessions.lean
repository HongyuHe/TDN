import TDN.Import.SnapshotLoader
import TDN.Requirements.ManagementPlaneRequirements

namespace TDN.Deployments.SnapshotAdminSessions
open Requirements
set_option maxRecDepth 100000
set_option maxHeartbeats 0

load_network_records accounts : List AdministrativeAccount from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.accounts"]

load_network_records authentication0 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.authentication0"]

load_network_records operation0 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.operation0"]

load_network_records authentication1 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.authentication1"]

load_network_records operation1 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.operation1"]

load_network_records authentication2 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.authentication2"]

load_network_records operation2 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.operation2"]

load_network_records authentication3 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.authentication3"]

load_network_records operation3 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.operation3"]

load_network_records authentication4 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.authentication4"]

load_network_records operation4 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.operation4"]

load_network_records authentication5 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.authentication5"]

load_network_records operation5 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.operation5"]

load_network_records authentication6 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.authentication6"]

load_network_records operation6 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.operation6"]

load_network_records authentication7 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.authentication7"]

load_network_records operation7 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.operation7"]

load_network_records authentication8 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.authentication8"]

load_network_records operation8 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.operation8"]

load_network_records authentication9 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.authentication9"]

load_network_records operation9 : AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.operation9"]

load_network_records sessions : List AdministrativeSession from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.sessions"]

load_network_records events : List AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.events"]

load_network_records actions : List AdminEvent from "../../data/evidence/SnapshotAdminSessions.json" ["TDN.Deployments.SnapshotAdminSessions.actions"]

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

theorem recorded_service_authentication :
    msc_administrator_authentication false false events accounts sessions [] := by
  apply administrator_authentication_from_admitted_operations false false events actions accounts sessions [] (fun _ => 0)
  · exact admitted_history
  · native_decide
  · simp

theorem successful_operations_are_present :
    (events.filter (fun event => event.kind == .operation)).length = 10 := by native_decide

end TDN.Deployments.SnapshotAdminSessions
