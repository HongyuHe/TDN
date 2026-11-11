import TDN.Requirements.MacsecAuthenticationHistory
import TDN.Requirements.MacsecEncryptionKeyUse

namespace TDN.Requirements.Msc
open Compliance

def MACsecAuthenticationConfigChecked (d : Deployment) (primitive : TLSPrimitive)
    (selected : MACsecAuthentication) : Prop :=
  d.IsDevice selected.device .macsec ∧ d.IsDevice selected.peer .macsec ∧
  (selected.method = .preSharedCAK ↔ d.preSharedCAKAuthenticated selected.device = true) ∧
  (selected.method = .eapTLS ↔ d.certificateAuthenticated selected.device = true) ∧
  (selected.keyServer = selected.device ∨ selected.keyServer = selected.peer) ∧
  selected.secureAssociationKey ≠ "" ∧
  match selected.method with
  | .preSharedCAK => selected.cak ≠ "" ∧ selected.cak = selected.peerCAK
  | .eapTLS => d.IsDevice selected.server .authenticationServer ∧
      selected.supportedRoles = [.supplicant, .authenticator] ∧
      selected.deviceCertificate ≠ "" ∧ selected.peerCertificate ≠ "" ∧ selected.serverCertificate ≠ "" ∧
      EAPEndpointRoleEvidence primitive selected ∧
      (∃ exchange ∈ selected.exchanges, EAPSessionBinding primitive selected exchange) ∧
      (∀ site zone, (site, zone) ∈ selected.serverAttachments ↔ d.networkAttachment selected.server site zone) ∧
      (∃ site zone, selected.serverAttachments ≠ [] ∧
        ∀ attachment ∈ selected.serverAttachments, attachment = (site, zone)) ∧
      ∀ attachment ∈ selected.serverAttachments, attachment.2 = .red ∨ attachment.2 = .gray

def TunnelNamesUnique (d : Deployment) : Prop :=
  ∀ first ∈ d.tunnels, ∀ second ∈ d.tunnels, first.id = second.id → first = second

lemma checked_record_gives_key_prefix {S A : Type} {d : Deployment} {model : ForwardingModel S A}
    {primitive : TLSPrimitive} {authentication : List MACsecAuthentication} {record : MACsecSetupRecord}
    (installation : record.InstallationChecked model)
    (checked : record.AuthenticationChecked d model primitive authentication)
    (unique : TunnelNamesUnique d) (configured : Tunnel) (member : configured ∈ d.tunnels)
    (mapped : model.native.macsecTunnel record.installation.association = configured.id)
    {payload : PayloadId} {current : List NetworkEvent}
    (used : .useSAK payload configured.id
      (model.native.keyName record.installation.association.keyGeneration) ∈ current) :
    ∃ selected ∈ authentication, selected.device = configured.sender ∧ selected.peer = configured.receiver ∧
      MACsecKeyUsePrefix primitive selected payload configured.id (model.history.Events ++ current) := by
  cases chosen : authentication[record.authenticationIndex]? with
  | none => simp [MACsecSetupRecord.AuthenticationChecked, chosen] at checked
  | some selected =>
    cases target : d.tunnels[record.tunnelIndex]? with
    | none => simp [MACsecSetupRecord.AuthenticationChecked, chosen, target] at checked
    | some tunnel =>
      simp only [MACsecSetupRecord.AuthenticationChecked, chosen, target] at checked
      obtain ⟨device, peer, name, sender, mechanism, issuer, receiver, key, authenticated, issued, method⟩ := checked
      have same : tunnel = configured := unique tunnel (List.mem_of_getElem? target)
        configured member (name.trans mapped)
      subst tunnel
      refine ⟨selected, List.mem_of_getElem? chosen, sender.symm, peer, ?_⟩
      have generation := installation.2.2.2.2.2.1
      have selectedUse : .useSAK payload configured.id selected.secureAssociationKey ∈ current := by
        simpa only [generation, key] using used
      obtain ⟨usedAt, sak⟩ := checked_sak_prefix installation issuer receiver key authenticated issued selectedUse
      cases methodName : selected.method with
      | preSharedCAK =>
        simp only [MACsecKeyUsePrefix, methodName]
        exact ⟨record.authenticated, record.installation.issuedAt, usedAt, sak⟩
      | eapTLS =>
        simp only [MACsecKeyUsePrefix, methodName]
        rw [methodName] at method
        exact checked_eap_prefix method sak

theorem macsec_authentication_from_local_checks {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (primitive : TLSPrimitive) (authentication : List MACsecAuthentication)
    (records : List MACsecSetupRecord) (faithful : model.Faithful)
    (separate : MACsecTunnelNamesSeparate {d with focus := none} model.native)
    (unique : TunnelNamesUnique {d with focus := none})
    (setup : MACsecSetupChecks {d with focus := none} model primitive authentication records)
    (inventory : ∀ device ∈ d.devices, device.kind = .macsec →
      ∃ selected ∈ authentication, selected.device = device.id)
    (settings : ∀ selected ∈ authentication,
      MACsecAuthenticationConfigChecked {d with focus := none} primitive selected) :
    msc_macsec_authentication_choice_and_as d model primitive authentication := by
  refine ⟨macsec_installed_history_from_local_checks setup, ?_, ?_, ?_⟩
  · intro device member relevant kind
    exact inventory device member kind
  · intro selected member relevant
    exact settings selected member
  · intro start actions finish initial run earlier later payload tunnel split configured member name mechanism
    rw [← name] at split ⊢
    obtain ⟨leading, trailing, currentSplit, earlierIs⟩ := history_precedes_encrypt setup.1 split
    obtain ⟨iface, configuredIface, association, installed, mapped, used⟩ :=
      forwarding_encrypt_has_prior_sak_use model faithful separate run configured member mechanism currentSplit
    have covered := setup.2.2 iface configuredIface
    rw [installed] at covered
    obtain ⟨record, present, owner, associated⟩ := covered
    have checked := setup.2.1 record present
    rw [earlierIs]
    exact checked_record_gives_key_prefix checked.2.1 checked.2.2 unique configured member
      (associated ▸ mapped) (by simpa only [associated] using used)

end TDN.Requirements.Msc
