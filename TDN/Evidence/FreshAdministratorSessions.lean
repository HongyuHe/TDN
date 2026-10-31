import TDN.Targets.Administration

namespace TDN.Imported.FreshAdministratorSessions
open Targets
set_option maxRecDepth 100000
set_option maxHeartbeats 0

/-- Credential identities are modeled here. Human appointments and AW accounts remain external. -/
def accounts : List AdministrativeAccount := [⟨0, 0, "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", false, false, 0⟩, ⟨1, 0, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, 0⟩]

def authentication0 : AdminEvent := ⟨.authentication, 1, 0, 1, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-0"⟩
def operation0 : AdminEvent := ⟨.operation, 1, 0, 2, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-0"⟩
def authentication1 : AdminEvent := ⟨.authentication, 1, 0, 3, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-1"⟩
def operation1 : AdminEvent := ⟨.operation, 1, 0, 4, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-1"⟩
def authentication2 : AdminEvent := ⟨.authentication, 1, 0, 5, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-2"⟩
def operation2 : AdminEvent := ⟨.operation, 1, 0, 6, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-2"⟩
def authentication3 : AdminEvent := ⟨.authentication, 1, 0, 7, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-3"⟩
def operation3 : AdminEvent := ⟨.operation, 1, 0, 8, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-3"⟩
def authentication4 : AdminEvent := ⟨.authentication, 0, 0, 9, "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", false, false, "audit-request-4"⟩
def operation4 : AdminEvent := ⟨.operation, 0, 0, 10, "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", false, false, "audit-request-4"⟩
def authentication5 : AdminEvent := ⟨.authentication, 0, 0, 11, "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", false, false, "audit-request-5"⟩
def operation5 : AdminEvent := ⟨.operation, 0, 0, 12, "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", false, false, "audit-request-5"⟩
def authentication6 : AdminEvent := ⟨.authentication, 0, 0, 13, "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", false, false, "audit-request-6"⟩
def operation6 : AdminEvent := ⟨.operation, 0, 0, 14, "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", false, false, "audit-request-6"⟩
def authentication7 : AdminEvent := ⟨.authentication, 1, 0, 15, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-7"⟩
def operation7 : AdminEvent := ⟨.operation, 1, 0, 16, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-7"⟩
def authentication8 : AdminEvent := ⟨.authentication, 1, 0, 17, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-8"⟩
def operation8 : AdminEvent := ⟨.operation, 1, 0, 18, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-8"⟩
def authentication9 : AdminEvent := ⟨.authentication, 1, 0, 19, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-9"⟩
def operation9 : AdminEvent := ⟨.operation, 1, 0, 20, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", false, false, "audit-request-9"⟩

/-- Session names and causal orders are witnesses derived from the reviewed handler sequence. -/
def sessions : List AdministrativeSession := [⟨"audit-request-0", 1, 0, 1, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02"⟩, ⟨"audit-request-1", 1, 0, 3, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02"⟩, ⟨"audit-request-2", 1, 0, 5, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02"⟩, ⟨"audit-request-3", 1, 0, 7, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02"⟩, ⟨"audit-request-4", 0, 0, 9, "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138"⟩, ⟨"audit-request-5", 0, 0, 11, "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138"⟩, ⟨"audit-request-6", 0, 0, 13, "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138"⟩, ⟨"audit-request-7", 1, 0, 15, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02"⟩, ⟨"audit-request-8", 1, 0, 17, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02"⟩, ⟨"audit-request-9", 1, 0, 19, "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02"⟩]
def events : List AdminEvent := [operation9, authentication9, operation8, authentication8, operation7, authentication7, operation6, authentication6, operation5, authentication5, operation4, authentication4, operation3, authentication3, operation2, authentication2, operation1, authentication1, operation0, authentication0]
def actions : List AdminEvent := [authentication0, operation0, authentication1, operation1, authentication2, operation2, authentication3, operation3, authentication4, operation4, authentication5, operation5, authentication6, operation6, authentication7, operation7, authentication8, operation8, authentication9, operation9]
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
