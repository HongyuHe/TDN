import TDN.Deployments.MacsecProtection_TrafficExamples

namespace TDN.Deployments.MacsecProtection
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

load_network_records integrityFrame : LinkAdmission.Frame from
  "../../data/evidence/macsecProtection/MacsecFramingFrames.json" ["integrityOnly"]
load_network_records encryptedFrame : LinkAdmission.Frame from
  "../../data/evidence/macsecProtection/MacsecFramingFrames.json" ["fullProtection"]
load_network_records capturedAssociation : MACsecAssociation from
  "../../data/evidence/macsecProtection/MacsecFramingFrames.json" ["association"]

def sampleEthernet : EthernetHeader := ⟨1, 2, 34997, []⟩

theorem captured_integrity_pdu_is_not_full_confidentiality (body : Body) :
    integrityFrame.DescribesBody (.macsecPdu capturedAssociation false 0 body) ∧
      ¬ integrityFrame.DescribesBody (.macsec capturedAssociation body) := by
  dsimp only [LinkAdmission.Frame.DescribesBody]
  decide

theorem captured_encrypted_pdu_has_full_confidentiality_framing (body : Body) :
    encryptedFrame.DescribesBody (.macsec capturedAssociation body) := by
  dsimp only [LinkAdmission.Frame.DescribesBody]
  decide

def integrityIface : MACIface :=
  ⟨0, 1, ⟨true, true, false, 0⟩, some capturedAssociation, [], true⟩

def integrityConfiguration : Config :=
  { direct.configuration with macIfaces := [integrityIface] }

def sampleReady : MultiProtocolForwarding.State :=
  { iface := 0, datapathStage := .egressReady, enteredIface := 0
    authenticated := [], tracking := "new"
    frame := ⟨LinkAdmission.payloadCode [7, 8], 0, .ethernet sampleEthernet, none, []⟩ }

def integrityOutput : MultiProtocolForwarding.State :=
  { sampleReady with
    iface := 1, frame := integrityConfiguration.macsecPduFrame sampleReady.frame capturedAssociation false 0 }

theorem integrity_only_transmit_keeps_macsec_framing :
    MultiProtocolForwarding.Step integrityConfiguration sampleReady .protectMACsec integrityOutput ∧
      integrityOutput.frame.body.isMACsecPdu = true ∧
      integrityOutput.frame.body.protectionLayers = [] ∧
      integrityOutput.frame.body.originalEthernet = some sampleEthernet := by
  refine ⟨.protectMACsec integrityIface capturedAssociation (by decide) rfl rfl rfl rfl rfl
    (Or.inl rfl), rfl, rfl, rfl⟩

def offsetIface : MACIface :=
  { integrityIface with settings := ⟨true, true, true, 30⟩ }

def offsetConfiguration : Config :=
  { direct.configuration with macIfaces := [offsetIface] }

def offsetOutput : MultiProtocolForwarding.State :=
  { sampleReady with
    iface := 1, frame := offsetConfiguration.macsecPduFrame sampleReady.frame capturedAssociation true 30 }

theorem nonzero_offset_transmit_is_reduced_confidentiality :
    MultiProtocolForwarding.Step offsetConfiguration sampleReady .protectMACsec offsetOutput ∧
      offsetOutput.frame.body.isMACsecPdu = true ∧
      offsetOutput.frame.body.protectionLayers = [] ∧
      LinkProtection.transmit offsetIface.settings (some 1) sampleEthernet =
        some (.encrypted 1 30 sampleEthernet) ∧
      ¬ LinkProtection.FullyEncrypted (.encrypted 1 30 sampleEthernet) := by
  exact ⟨.protectMACsec offsetIface capturedAssociation (by decide) rfl rfl rfl rfl rfl
    (Or.inr (by decide)), rfl, rfl, rfl, by change ¬30 = 0; decide⟩

theorem protection_disabled_and_sa_absent_have_distinct_results :
    LinkProtection.transmit ⟨true, false, true, 0⟩ none sampleEthernet = some (.plain sampleEthernet) ∧
      LinkProtection.transmit ⟨true, true, false, 0⟩ none sampleEthernet = none ∧
      LinkProtection.transmit ⟨false, false, true, 0⟩ (some 1) sampleEthernet = none := by
  exact ⟨rfl, rfl, rfl⟩

def disabledIface : MACIface :=
  { integrityIface with settings := ⟨true, false, false, 0⟩ }

def disabledConfiguration : Config :=
  { direct.configuration with macIfaces := [disabledIface] }

theorem disabled_protection_does_not_add_a_macsec_pdu :
    MultiProtocolForwarding.Step disabledConfiguration sampleReady .forwardWithoutEncap
      { sampleReady with initialEntry := false, iface := 1 } ∧
      sampleReady.frame.body.isMACsecPdu = false := by
  exact ⟨.unprotectedMACsec disabledIface (by decide) rfl rfl rfl rfl, rfl⟩

def integrityAdvertisedSecure : ProfileRecords :=
  { direct with
    macIfaces := direct.macIfaces.map (fun iface =>
      { iface with settings := { iface.settings with encryptFrames := false } }) }

def offsetAdvertisedZero : ProfileRecords :=
  { direct with
    macIfaces := direct.macIfaces.map (fun iface =>
      { iface with settings := { iface.settings with confidentialityOffset := 30 } }) }

theorem advertised_must_secure_is_bound_to_device_encryption :
    ¬ MACsecParametersBound integrityAdvertisedSecure.deployment integrityAdvertisedSecure.model parameters := by
  intro bound
  have mismatch := bound parameters[0] (by simp [parameters, observedParameters]) (Or.inl rfl)
    integrityAdvertisedSecure.sender (by decide) rfl
  have impossible : true = false := mismatch.1
  cases impossible

theorem advertised_zero_offset_is_bound_to_device_offset :
    ¬ MACsecParametersBound offsetAdvertisedZero.deployment offsetAdvertisedZero.model parameters := by
  intro bound
  have mismatch := bound parameters[0] (by simp [parameters, observedParameters]) (Or.inl rfl)
    offsetAdvertisedZero.sender (by decide) rfl
  have impossible : 0 = 30 := mismatch.2
  cases impossible

theorem disconnected_parameter_records_fail_whole_requirement :
    ¬ msc_macsec_protection_parameters integrityAdvertisedSecure.deployment integrityAdvertisedSecure.model parameters ∧
      ¬ msc_macsec_protection_parameters offsetAdvertisedZero.deployment offsetAdvertisedZero.model parameters := by
  exact ⟨fun accepted => advertised_must_secure_is_bound_to_device_encryption accepted.2.1,
    fun accepted => advertised_zero_offset_is_bound_to_device_offset accepted.2.1⟩

theorem snapshot_RG028_direct_nonempty_delivery :
    ∃ start actions finish, direct.model.initial start ∧
      direct.model.system.MTr start actions finish ∧
      (direct.model.native.state finish).datapathStage = .delivered ∧
      (direct.model.native.state finish).frame.payload = LinkAdmission.payloadCode [7, 8] ∧
      (direct.model.native.state finish).frame.body = direct.trafficDatagram.body :=
  profile_nonempty_payload_is_delivered direct (Or.inl rfl)

theorem snapshot_RG028_routed_nonempty_delivery :
    ∃ start actions finish, routed.model.initial start ∧
      routed.model.system.MTr start actions finish ∧
      (routed.model.native.state finish).datapathStage = .delivered ∧
      (routed.model.native.state finish).frame.payload = LinkAdmission.payloadCode [7, 8] ∧
      (routed.model.native.state finish).frame.body = routed.trafficDatagram.body :=
  profile_nonempty_payload_is_delivered routed (Or.inr rfl)

def noSaIface : MACIface := { integrityIface with transmitAssociation := none }
def noSaConfiguration : Config := { direct.configuration with macIfaces := [noSaIface] }

theorem absent_tx_sa_blocks_macsec_pdu_creation :
    (¬ ∃ after, MultiProtocolForwarding.Step noSaConfiguration sampleReady .protectMACsec after) ∧
      (¬ ∃ after, MultiProtocolForwarding.Step noSaConfiguration sampleReady .encryptMACsec after) := by
  constructor
  · rintro ⟨after, step⟩
    cases step with
    | protectMACsec iface association configured stage logical enabled protect installed limited =>
      have same : iface = noSaIface := by simpa [noSaConfiguration] using configured
      subst iface
      cases installed
  · rintro ⟨after, step⟩
    cases step with
    | encryptMACsec iface association configured stage logical emits =>
      have same : iface = noSaIface := by simpa [noSaConfiguration] using configured
      subst iface
      cases emits.1

def reducedReceiveIface (installed : MACsecAssociation) : MACIface :=
  { integrityIface with receiveAssociations := [installed] }

def reducedReceiveConfiguration (installed : MACsecAssociation) : Config :=
  { integrityConfiguration with
    macIfaces := [reducedReceiveIface installed]
    linkEncoding := fun _ _ => some integrityFrame }

def reducedReceiveBinding (installed : MACsecAssociation) :
    DeviceExecutionBinding MultiProtocolForwarding.State MultiProtocolForwarding.Action :=
  { direct.prototype with configuration := reducedReceiveConfiguration installed }

def reducedReceived : MultiProtocolForwarding.State :=
  { integrityOutput with datapathStage := .received }

def reducedRestored : MultiProtocolForwarding.State :=
  { reducedReceived with
    iface := 0, frame := integrityConfiguration.restoredFrame reducedReceived.frame (.ethernet sampleEthernet) }

def wrongKeyAssociation : MACsecAssociation :=
  { capturedAssociation with keyGeneration := 2 }

lemma reduced_receive_step (installed : MACsecAssociation)
    (sameWire : SameMACWireIdentity capturedAssociation installed) :
    MultiProtocolForwarding.Step (reducedReceiveConfiguration installed)
      reducedReceived .validateMACsec reducedRestored := by
  exact .validateMACsec (reducedReceiveIface installed) installed capturedAssociation false 0
    (.ethernet sampleEthernet) (by simp [reducedReceiveConfiguration]) rfl rfl rfl
    (by simp [reducedReceiveIface]) sameWire

lemma reduced_receive_frame_is_admitted (installed : MACsecAssociation) :
    (reducedReceiveConfiguration installed).LinkAdmitted reducedReceived.iface false reducedReceived.frame := by
  refine ⟨integrityFrame, rfl, ?_, ⟨⟨⟨[], .allow⟩, ⟨[], .allow⟩⟩, rfl, rfl⟩⟩
  exact ⟨(captured_integrity_pdu_is_not_full_confidentiality _).1, by intro header impossible; cases impossible⟩

theorem reduced_receive_with_matching_keys_is_accepted :
    (reducedReceiveBinding capturedAssociation).AcceptedStep
      reducedReceived .validateMACsec reducedRestored := by
  refine ⟨reduced_receive_step capturedAssociation ⟨rfl, rfl⟩, by simp, by simp, ?_,
    by simp [Config.HeaderStepAdmitted], ?_⟩
  · exact ⟨by simp, fun _ => reduced_receive_frame_is_admitted _, by simp, by simp⟩
  · intro _
    exact ⟨reducedReceiveIface capturedAssociation, by simp [reducedReceiveBinding, reducedReceiveConfiguration],
      capturedAssociation, by simp [reducedReceiveIface], capturedAssociation, false, 0,
      .ethernet sampleEthernet, rfl, rfl, rfl, rfl, ⟨rfl, rfl⟩,
      ⟨List.replicate 16 (UInt8.ofNat capturedAssociation.keyGeneration), Or.inl (by simp), rfl, rfl⟩⟩

theorem reduced_receive_with_wrong_key_is_rejected :
    SameMACWireIdentity capturedAssociation wrongKeyAssociation ∧
      MultiProtocolForwarding.Step (reducedReceiveConfiguration wrongKeyAssociation)
        reducedReceived .validateMACsec reducedRestored ∧
      ¬ (reducedReceiveBinding wrongKeyAssociation).AcceptedStep
        reducedReceived .validateMACsec reducedRestored := by
  refine ⟨⟨rfl, rfl⟩, reduced_receive_step wrongKeyAssociation ⟨rfl, rfl⟩, ?_⟩
  intro accepted
  obtain ⟨iface, configured, installed, member, transmitted, encryptFrames, offset, body,
    physical, logical, framed, restored, sameWire, material⟩ := accepted.2.2.2.2.2 rfl
  have ifaceEq : iface = reducedReceiveIface wrongKeyAssociation := by
    simpa [reducedReceiveBinding, reducedReceiveConfiguration] using configured
  subst iface
  have installedEq : installed = wrongKeyAssociation := by simpa [reducedReceiveIface] using member
  subst installed
  have frameEq : Body.macsecPdu capturedAssociation false 0 (.ethernet sampleEthernet) =
      .macsecPdu transmitted encryptFrames offset body := framed
  cases frameEq
  obtain ⟨key, length, transmittedKey, installedKey⟩ := material
  have mismatch : some (List.replicate 16 (UInt8.ofNat 1)) =
      some (List.replicate 16 (UInt8.ofNat 2)) := transmittedKey.trans installedKey.symm
  have impossible : (List.replicate 16 (UInt8.ofNat 1)) =
      List.replicate 16 (UInt8.ofNat 2) := Option.some.inj mismatch
  have unequal : (List.replicate 16 (UInt8.ofNat 1)) ≠ List.replicate 16 (UInt8.ofNat 2) := by decide
  exact unequal impossible

def reducedEventOutput (encryptFrames : Bool) (offset : Nat) : MultiProtocolForwarding.State :=
  { sampleReady with
    iface := 1, frame := integrityConfiguration.macsecPduFrame sampleReady.frame capturedAssociation encryptFrames offset }

theorem reduced_transmit_records_sa_use_without_full_encryption (encryptFrames : Bool) (offset : Nat) :
    direct.prototype.OperationEvents sampleReady .protectMACsec (reducedEventOutput encryptFrames offset) =
      [.useSAK ⟨0, LinkAdmission.payloadCode [7, 8]⟩ (direct.macsecTunnel capturedAssociation)
        (direct.prototype.keyName capturedAssociation.keyGeneration),
       .protect ⟨0, LinkAdmission.payloadCode [7, 8]⟩ (direct.macsecTunnel capturedAssociation)
        (.macsec capturedAssociation)] ∧
      BodySessions (reducedEventOutput encryptFrames offset).frame.body = [.macsec capturedAssociation] ∧
      direct.prototype.LayerIds (reducedEventOutput encryptFrames offset).frame.body = [] := by
  exact ⟨rfl, rfl, rfl⟩

theorem reduced_receive_records_validation_without_full_decryption :
    direct.prototype.OperationEvents reducedReceived .validateMACsec reducedRestored =
      [.unprotect ⟨0, LinkAdmission.payloadCode [7, 8]⟩ (direct.macsecTunnel capturedAssociation)
        (.macsec capturedAssociation)] := by
  rfl

theorem reduced_wire_transmit_records_sa_session (encryptFrames : Bool) (offset : Nat) :
    direct.prototype.OperationEvents (reducedEventOutput encryptFrames offset) .linkTransmit
      (reducedEventOutput encryptFrames offset) =
      [.sessionTransmit ⟨0, LinkAdmission.payloadCode [7, 8]⟩ (direct.ifaceName 1) [.macsec capturedAssociation],
       .transmit ⟨0, LinkAdmission.payloadCode [7, 8]⟩ (direct.ifaceName 1) [] .protectedData,
       .receive ⟨0, LinkAdmission.payloadCode [7, 8]⟩ (direct.ifaceName 1) [] .protectedData,
       .sessionReceive ⟨0, LinkAdmission.payloadCode [7, 8]⟩ (direct.ifaceName 1) [.macsec capturedAssociation]] := by
  rfl

end TDN.Deployments.MacsecProtection
