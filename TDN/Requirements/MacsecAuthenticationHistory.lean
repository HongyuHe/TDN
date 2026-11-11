import TDN.Requirements.CoreMscRequirements
import TDN.Requirements.NetworkEventTraceOrder

namespace TDN.Requirements.Msc
open Compliance LayeredFrame

deriving instance DecidableEq for Trust.Identity
deriving instance DecidableEq for TLSHandshakeInput
deriving instance DecidableEq for TLSVerifiedSession
deriving instance DecidableEq for EAPBackendInput
deriving instance DecidableEq for EAPBackendVerified

def HistoryEventAt (history : ObservedHistory) (position : Nat)
    (session : Option String) (event : NetworkEvent) : Prop :=
  match history.entries[position]? with
  | none => False
  | some record => record.position = position ∧ record.session = session ∧ record.event = event

instance (history : ObservedHistory) (position : Nat)
    (session : Option String) (event : NetworkEvent) :
    Decidable (HistoryEventAt history position session event) := by
  unfold HistoryEventAt
  cases history.entries[position]? <;> infer_instance

lemma history_event_at_is_setup {history : ObservedHistory} {position : Nat}
    {session : Option String} {event : NetworkEvent}
    (checked : HistoryEventAt history position session event) :
    HistoricalSetup history session event position := by
  cases selected : history.entries[position]? with
  | none => simp [HistoryEventAt, selected] at checked
  | some record =>
    have fields : record.position = position ∧ record.session = session ∧ record.event = event := by
      simpa [HistoryEventAt, selected] using checked
    exact ⟨record, List.mem_of_getElem? selected, fields⟩

lemma history_event_at_index {history : ObservedHistory} {position : Nat}
    {session : Option String} {event : NetworkEvent}
    (checked : HistoryEventAt history position session event) :
    history.Events[position]? = some event := by
  cases selected : history.entries[position]? with
  | none => simp [HistoryEventAt, selected] at checked
  | some record =>
    have fields : record.position = position ∧ record.session = session ∧ record.event = event := by
      simpa [HistoryEventAt, selected] using checked
    simp [ObservedHistory.Events, List.getElem?_map, selected, fields.2.2]

def HistoryPath (history : ObservedHistory) (first : Nat) : List Nat → Nat → Prop
  | [], last => first = last
  | next :: rest, last => first < next ∧ (first, next) ∈ history.dependencies ∧
      HistoryPath history next rest last

instance (history : ObservedHistory) (first last : Nat) (path : List Nat) :
    Decidable (HistoryPath history first path last) := by
  induction path generalizing first with
  | nil => exact inferInstanceAs (Decidable (first = last))
  | cons next rest ih =>
    change Decidable (first < next ∧ (first, next) ∈ history.dependencies ∧ HistoryPath history next rest last)
    have := ih next
    infer_instance

def CausalPathChecked (history : ObservedHistory) (first last : Nat) (path : List Nat) : Prop :=
  first < last ∧ HistoryPath history first path last

instance (history : ObservedHistory) (first last : Nat) (path : List Nat) :
    Decidable (CausalPathChecked history first last path) := by
  unfold CausalPathChecked
  infer_instance

lemma history_path_reaches {history : ObservedHistory} {first last : Nat} {path : List Nat}
    (checked : HistoryPath history first path last) :
    Relation.ReflTransGen (fun before after => (before, after) ∈ history.dependencies) first last := by
  induction path generalizing first with
  | nil => exact checked ▸ .refl
  | cons next rest ih =>
    exact (Relation.ReflTransGen.single checked.2.1).trans (ih checked.2.2)

lemma causal_path_is_before {history : ObservedHistory} {first last : Nat} {path : List Nat}
    (checked : CausalPathChecked history first last path) : history.CausallyBefore first last :=
  ⟨checked.1, history_path_reaches checked.2⟩

structure MACsecSetupRecord where
  installation : MACsecHistoryInstallation
  authenticationIndex : Nat
  tunnelIndex : Nat
  exchangeIndex : Nat
  material : List UInt8
  authenticated : Nat
  verified : Nat
  delivered : Nat
  supplicantDerived : Nat
  authenticatorDerived : Nat
  issuancePath : List Nat
  installationPath : List Nat
  verifiedToDelivered : List Nat
  verifiedToSupplicant : List Nat
  deliveredToAuthenticator : List Nat
  supplicantToAuthenticated : List Nat
  authenticatorToAuthenticated : List Nat

def MACsecSetupRecord.InstallationChecked {S A : Type} (record : MACsecSetupRecord)
    (model : ForwardingModel S A) : Prop :=
  model.native.macsecEpoch = some record.installation.epoch ∧
  record.installation.epoch = model.history.epoch ∧
  record.installation.installation ≠ "" ∧ record.installation.source ≠ "" ∧
  record.installation.keyReference ≠ "" ∧
  model.native.keyName record.installation.association.keyGeneration = record.installation.keyReference ∧
  CausalPathChecked model.history record.installation.issuedAt record.installation.installedAt record.installationPath ∧
  record.installation.installedAt < model.history.cut ∧
  HistoryEventAt model.history record.installation.installedAt record.installation.session
    (.installSAK (model.native.componentName record.installation.device) record.installation.keyReference
      record.installation.installation record.installation.epoch) ∧
  HistoryEventAt model.history record.installation.issuedAt record.installation.session
    (.issueSAK record.installation.issuer record.installation.peer record.installation.keyReference) ∧
  (record.material.length = 16 ∨ record.material.length = 32) ∧
  model.historicalKeyMaterial record.installation.keyReference = some record.material ∧
  model.native.macsecKeyMaterial record.installation.association = some record.material

def MACsecSetupRecord.EAPChecked {S A : Type} (record : MACsecSetupRecord)
    (model : ForwardingModel S A) (primitive : TLSPrimitive) (selected : MACsecAuthentication) : Prop :=
  match selected.exchanges[record.exchangeIndex]? with
  | none => False
  | some exchange =>
    EAPSessionBinding primitive selected exchange ∧
    record.installation.session = some exchange.input.session ∧
    HistoryEventAt model.history record.verified record.installation.session
      (.eapTLSVerified exchange.input.session selected.eapSupplicant selected.server
        exchange.input.deviceCertificate selected.serverCertificate exchange.verified.masterSessionKey) ∧
    HistoryEventAt model.history record.delivered record.installation.session
      (.eapKeyDelivered exchange.input.session selected.server selected.eapAuthenticator
        selected.eapSupplicant exchange.verified.masterSessionKey) ∧
    HistoryEventAt model.history record.supplicantDerived record.installation.session
      (.deriveCAK exchange.input.session selected.eapSupplicant exchange.verified.masterSessionKey selected.cak) ∧
    HistoryEventAt model.history record.authenticatorDerived record.installation.session
      (.deriveCAK exchange.input.session selected.eapAuthenticator exchange.verified.masterSessionKey selected.peerCAK) ∧
    CausalPathChecked model.history record.verified record.delivered record.verifiedToDelivered ∧
    CausalPathChecked model.history record.verified record.supplicantDerived record.verifiedToSupplicant ∧
    CausalPathChecked model.history record.delivered record.authenticatorDerived record.deliveredToAuthenticator ∧
    CausalPathChecked model.history record.supplicantDerived record.authenticated record.supplicantToAuthenticated ∧
    CausalPathChecked model.history record.authenticatorDerived record.authenticated record.authenticatorToAuthenticated

def MACsecSetupRecord.AuthenticationChecked {S A : Type} (record : MACsecSetupRecord)
    (d : Deployment) (model : ForwardingModel S A) (primitive : TLSPrimitive)
    (authentication : List MACsecAuthentication) : Prop :=
  match authentication[record.authenticationIndex]?, d.tunnels[record.tunnelIndex]? with
  | some selected, some tunnel =>
    selected.device = model.native.componentName record.installation.device ∧ selected.peer = tunnel.receiver ∧
    tunnel.id = model.native.macsecTunnel record.installation.association ∧
    tunnel.sender = selected.device ∧ tunnel.mechanism = .macsec ∧
    record.installation.issuer = selected.keyServer ∧
    record.installation.peer = (if selected.keyServer = selected.device then selected.peer else selected.device) ∧
    record.installation.keyReference = selected.secureAssociationKey ∧
    HistoryEventAt model.history record.authenticated record.installation.session
      (.authenticate record.installation.issuer record.installation.peer selected.cak) ∧
    CausalPathChecked model.history record.authenticated record.installation.issuedAt record.issuancePath ∧
    match selected.method with
    | .preSharedCAK => record.installation.session = none
    | .eapTLS => record.EAPChecked model primitive selected
  | _, _ => False

lemma checked_macsec_installation_is_bound {S A : Type} {record : MACsecSetupRecord}
    {model : ForwardingModel S A} (checked : record.InstallationChecked model) (valid : model.history.Valid) :
    record.installation.Bound model := by
  obtain ⟨epoch, historyEpoch, name, source, key, generation, path, cut, installed, issued,
    length, historical, device⟩ := checked
  obtain ⟨installRecord, installMember, installPosition, installSession, installEvent⟩ := history_event_at_is_setup installed
  obtain ⟨issueRecord, issueMember, issuePosition, issueSession, issueEvent⟩ := history_event_at_is_setup issued
  have installEpoch := (valid.2.1 installRecord installMember).2.2.1
  have issueEpoch := (valid.2.1 issueRecord issueMember).2.2.1
  exact ⟨epoch, historyEpoch, name, source, key, generation, causal_path_is_before path, cut,
    ⟨installRecord, installMember, installPosition, installEpoch.trans historyEpoch.symm, installSession, installEvent⟩,
    ⟨issueRecord, issueMember, issuePosition, issueEpoch.trans historyEpoch.symm, issueSession, issueEvent⟩,
    record.material, length, historical, device⟩

lemma checked_macsec_eap_has_history {S A : Type} {record : MACsecSetupRecord}
    {model : ForwardingModel S A} {primitive : TLSPrimitive} {selected : MACsecAuthentication}
    (checked : record.EAPChecked model primitive selected)
    (authenticated : HistoryEventAt model.history record.authenticated record.installation.session
      (.authenticate record.installation.issuer record.installation.peer selected.cak))
    (issued : CausalPathChecked model.history record.authenticated record.installation.issuedAt record.issuancePath) :
    HistoricalEAPSetup model.history primitive selected record.installation := by
  cases chosen : selected.exchanges[record.exchangeIndex]? with
  | none => simp [MACsecSetupRecord.EAPChecked, chosen] at checked
  | some exchange =>
    have checks := checked
    simp only [MACsecSetupRecord.EAPChecked, chosen] at checks
    obtain ⟨binding, session, verified, delivered, supplicant, authenticator,
      toDelivered, toSupplicant, toAuthenticator, fromSupplicant, fromAuthenticator⟩ := checks
    exact ⟨exchange, List.mem_of_getElem? chosen, binding, session,
      record.verified, record.delivered, record.supplicantDerived, record.authenticatorDerived,
      record.authenticated, history_event_at_is_setup verified, history_event_at_is_setup delivered,
      history_event_at_is_setup supplicant, history_event_at_is_setup authenticator,
      history_event_at_is_setup authenticated,
      causal_path_is_before toDelivered, causal_path_is_before toSupplicant,
      causal_path_is_before toAuthenticator, causal_path_is_before fromSupplicant,
      causal_path_is_before fromAuthenticator, causal_path_is_before issued⟩

def MACsecSetupChecks {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (primitive : TLSPrimitive) (authentication : List MACsecAuthentication)
    (records : List MACsecSetupRecord) : Prop :=
  model.history.Valid ∧
  (∀ record ∈ records, record.installation ∈ model.macsecInstallationHistory ∧
    record.InstallationChecked model ∧ record.AuthenticationChecked d model primitive authentication) ∧
  ∀ iface ∈ model.native.configuration.macIfaces,
    match iface.transmitAssociation with
    | none => True
    | some association => ∃ record ∈ records,
        record.installation.device = model.native.configuration.ip.owner iface.physicalIface ∧
        record.installation.association = association

lemma checked_macsec_authentication_has_history {S A : Type} {record : MACsecSetupRecord}
    {d : Deployment} {model : ForwardingModel S A} {primitive : TLSPrimitive}
    {authentication : List MACsecAuthentication}
    (checked : record.AuthenticationChecked d model primitive authentication) :
    ∃ tunnel ∈ d.tunnels, tunnel.id = model.native.macsecTunnel record.installation.association ∧
      tunnel.sender = model.native.componentName record.installation.device ∧ tunnel.mechanism = .macsec ∧
      ∃ selected ∈ authentication, selected.device = model.native.componentName record.installation.device ∧
        selected.peer = tunnel.receiver ∧ HistoricalSAKSetup model.history selected record.installation ∧
        match selected.method with
        | .preSharedCAK => record.installation.session = none
        | .eapTLS => HistoricalEAPSetup model.history primitive selected record.installation := by
  cases chosen : authentication[record.authenticationIndex]? with
  | none => simp [MACsecSetupRecord.AuthenticationChecked, chosen] at checked
  | some selected =>
    cases target : d.tunnels[record.tunnelIndex]? with
    | none => simp [MACsecSetupRecord.AuthenticationChecked, chosen, target] at checked
    | some tunnel =>
      simp only [MACsecSetupRecord.AuthenticationChecked, chosen, target] at checked
      obtain ⟨device, peer, name, sender, mechanism, issuer, receiver, key, authenticated, issued, method⟩ := checked
      refine ⟨tunnel, List.mem_of_getElem? target, name, sender.trans device, mechanism,
        selected, List.mem_of_getElem? chosen, device, peer, ?_, ?_⟩
      · exact ⟨issuer, receiver, key, record.authenticated,
          history_event_at_is_setup authenticated, causal_path_is_before issued⟩
      · cases methodName : selected.method with
        | preSharedCAK => simpa only [methodName] using method
        | eapTLS =>
          rw [methodName] at method
          exact checked_macsec_eap_has_history method authenticated issued

theorem macsec_installed_history_from_local_checks {S A : Type} {d : Deployment}
    {model : ForwardingModel S A} {primitive : TLSPrimitive}
    {authentication : List MACsecAuthentication} {records : List MACsecSetupRecord}
    (checks : MACsecSetupChecks d model primitive authentication records) :
    MACsecInstalledHistory d model primitive authentication := by
  refine ⟨checks.1, ?_⟩
  intro iface member association transmitted
  dsimp only
  intro relevant
  have covered := checks.2.2 iface member
  rw [transmitted] at covered
  obtain ⟨record, present, owner, associated⟩ := covered
  have checked := checks.2.1 record present
  refine ⟨record.installation, checked.1, checked_macsec_installation_is_bound checked.2.1 checks.1,
    owner, associated, ?_⟩
  obtain ⟨tunnel, tunnelMember, name, sender, mechanism, selected, selectedMember, device, peer, sak, method⟩ :=
    checked_macsec_authentication_has_history (d := d) (model := model) (primitive := primitive)
      (authentication := authentication) checked.2.2
  exact ⟨tunnel, tunnelMember, associated ▸ name, owner ▸ sender, mechanism,
    selected, selectedMember, owner ▸ device, peer, sak, method⟩

lemma checked_sak_prefix {S A : Type} {record : MACsecSetupRecord}
    {model : ForwardingModel S A} {selected : MACsecAuthentication}
    (installation : record.InstallationChecked model)
    (issuer : record.installation.issuer = selected.keyServer)
    (peer : record.installation.peer = (if selected.keyServer = selected.device then selected.peer else selected.device))
    (key : record.installation.keyReference = selected.secureAssociationKey)
    (authenticated : HistoryEventAt model.history record.authenticated record.installation.session
      (.authenticate record.installation.issuer record.installation.peer selected.cak))
    (issued : CausalPathChecked model.history record.authenticated record.installation.issuedAt record.issuancePath)
    {payload : PayloadId} {tunnel : String} {current : List NetworkEvent}
    (used : .useSAK payload tunnel selected.secureAssociationKey ∈ current) :
    ∃ usedAt, SAKKeyUseAt selected payload tunnel (model.history.Events ++ current)
      record.authenticated record.installation.issuedAt usedAt := by
  obtain ⟨position, found⟩ := List.mem_iff_getElem?.mp used
  have authenticatedAt := history_event_at_index authenticated
  have issuedAt := history_event_at_index installation.2.2.2.2.2.2.2.2.2.1
  have bound := event_index_is_bounded issuedAt
  refine ⟨model.history.Events.length + position, ?_⟩
  refine ⟨?_, ?_, event_index_in_right_append found, issued.1, by omega⟩
  · exact event_index_in_left_append (by simpa only [issuer, peer] using authenticatedAt)
  · exact event_index_in_left_append (by simpa only [issuer, peer, key] using issuedAt)

lemma checked_eap_prefix {S A : Type} {record : MACsecSetupRecord}
    {model : ForwardingModel S A} {primitive : TLSPrimitive} {selected : MACsecAuthentication}
    (checked : record.EAPChecked model primitive selected)
    {payload : PayloadId} {tunnel : String} {current : List NetworkEvent} {usedAt : Nat}
    (sak : SAKKeyUseAt selected payload tunnel (model.history.Events ++ current)
      record.authenticated record.installation.issuedAt usedAt) :
    EAPKeyUsePrefix primitive selected payload tunnel (model.history.Events ++ current) := by
  cases chosen : selected.exchanges[record.exchangeIndex]? with
  | none => simp [MACsecSetupRecord.EAPChecked, chosen] at checked
  | some exchange =>
    simp only [MACsecSetupRecord.EAPChecked, chosen] at checked
    obtain ⟨binding, session, verified, delivered, supplicant, authenticator,
      toDelivered, toSupplicant, toAuthenticator, fromSupplicant, fromAuthenticator⟩ := checked
    have cak : selected.peerCAK = selected.cak := binding.2.2.2.2.2.2.2.2.2.2.2.symm
    refine ⟨exchange, List.mem_of_getElem? chosen, binding, record.verified, record.delivered,
      record.supplicantDerived, record.authenticatorDerived, record.authenticated,
      record.installation.issuedAt, usedAt, ?_, ?_, ?_, ?_, sak,
      toDelivered.1, toSupplicant.1, toAuthenticator.1, fromSupplicant.1, fromAuthenticator.1⟩
    · exact event_index_in_left_append (history_event_at_index verified)
    · exact event_index_in_left_append (history_event_at_index delivered)
    · exact event_index_in_left_append (history_event_at_index supplicant)
    · exact event_index_in_left_append (by simpa only [cak] using history_event_at_index authenticator)

end TDN.Requirements.Msc
