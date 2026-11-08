import TDN.Import.Command
import TDN.Targets.MultiProtocolPackets
import TDN.Semantics.FiniteMultiProtocol

namespace TDN.Imported.PairingIpsecIpsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.devices"]

tdn_data ifaces : List Execution.IfaceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.ifaces"]

tdn_data routes : List Execution.Route from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.routes"]

tdn_data links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.links"]

tdn_data bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.bridges"]

tdn_data macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.macIfaces"]

tdn_data carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.carriers"]

def config : Config := MultiProtocolExecution.dataPlaneConfigFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := Execution.expectedEncapStackFromRecords ifaces
tdn_data redSources : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.redSources"]

tdn_data grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.grayIfaces"]

tdn_data blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.blackIfaces"]

lemma mac_configuration_checked : ∀ iface ∈ macIfaces,
    iface.settings.controlledPortEnabled = true ∧ iface.settings.protectFrames = true ∧
    iface.settings.encryptFrames = true ∧ iface.settings.confidentialityOffset = 0 ∧
    ∃ association, iface.transmitAssociation = some association := by
  simp [macIfaces]

lemma receive_peer_bindings : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    ∃ peer ∈ macIfaces, peer.transmitAssociation = some association := by
  unfold macIfaces; decide

theorem every_configured_mac_iface_emits_full_encryption (iface : MACIface)
    (member : iface ∈ macIfaces) :
    ∃ association, ∀ body, fullMACsecTransmit iface association body := by
  obtain ⟨enabled, protect, encrypt, zero, association, installed⟩ := mac_configuration_checked iface member
  refine ⟨association, fun body => ⟨installed, ?_⟩⟩
  simpa [zero] using LinkProtection.enabled_sa_emits_encryption iface.settings enabled protect encrypt
    association.keyGeneration body

theorem payload_preserved_by_every_mixed_execution {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_executions_preserve_payload config run
end TDN.Imported.PairingIpsecIpsecIntegrated

namespace TDN.Imported.PairingIpsecMacsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.devices"]

tdn_data ifaces : List Execution.IfaceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.ifaces"]

tdn_data routes : List Execution.Route from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.routes"]

tdn_data links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.links"]

tdn_data bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.bridges"]

tdn_data macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.macIfaces"]

tdn_data carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.carriers"]

def config : Config := MultiProtocolExecution.dataPlaneConfigFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := Execution.expectedEncapStackFromRecords ifaces
tdn_data redSources : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.redSources"]

tdn_data grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.grayIfaces"]

tdn_data blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.blackIfaces"]

lemma mac_configuration_checked : ∀ iface ∈ macIfaces,
    iface.settings.controlledPortEnabled = true ∧ iface.settings.protectFrames = true ∧
    iface.settings.encryptFrames = true ∧ iface.settings.confidentialityOffset = 0 ∧
    ∃ association, iface.transmitAssociation = some association := by
  simp [macIfaces]

lemma receive_peer_bindings : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    ∃ peer ∈ macIfaces, peer.transmitAssociation = some association := by
  unfold macIfaces; decide

theorem every_configured_mac_iface_emits_full_encryption (iface : MACIface)
    (member : iface ∈ macIfaces) :
    ∃ association, ∀ body, fullMACsecTransmit iface association body := by
  obtain ⟨enabled, protect, encrypt, zero, association, installed⟩ := mac_configuration_checked iface member
  refine ⟨association, fun body => ⟨installed, ?_⟩⟩
  simpa [zero] using LinkProtection.enabled_sa_emits_encryption iface.settings enabled protect encrypt
    association.keyGeneration body

theorem payload_preserved_by_every_mixed_execution {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_executions_preserve_payload config run
end TDN.Imported.PairingIpsecMacsecIntegrated

namespace TDN.Imported.PairingMacsecIpsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.devices"]

tdn_data ifaces : List Execution.IfaceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.ifaces"]

tdn_data routes : List Execution.Route from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.routes"]

tdn_data links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.links"]

tdn_data bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.bridges"]

tdn_data macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.macIfaces"]

tdn_data carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.carriers"]

def config : Config := MultiProtocolExecution.dataPlaneConfigFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := Execution.expectedEncapStackFromRecords ifaces
tdn_data redSources : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.redSources"]

tdn_data grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.grayIfaces"]

tdn_data blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.blackIfaces"]

lemma mac_configuration_checked : ∀ iface ∈ macIfaces,
    iface.settings.controlledPortEnabled = true ∧ iface.settings.protectFrames = true ∧
    iface.settings.encryptFrames = true ∧ iface.settings.confidentialityOffset = 0 ∧
    ∃ association, iface.transmitAssociation = some association := by
  simp [macIfaces]

lemma receive_peer_bindings : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    ∃ peer ∈ macIfaces, peer.transmitAssociation = some association := by
  unfold macIfaces; decide

theorem every_configured_mac_iface_emits_full_encryption (iface : MACIface)
    (member : iface ∈ macIfaces) :
    ∃ association, ∀ body, fullMACsecTransmit iface association body := by
  obtain ⟨enabled, protect, encrypt, zero, association, installed⟩ := mac_configuration_checked iface member
  refine ⟨association, fun body => ⟨installed, ?_⟩⟩
  simpa [zero] using LinkProtection.enabled_sa_emits_encryption iface.settings enabled protect encrypt
    association.keyGeneration body

theorem payload_preserved_by_every_mixed_execution {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_executions_preserve_payload config run
end TDN.Imported.PairingMacsecIpsecIntegrated

namespace TDN.Imported.PairingMacsecIpsecStandalone
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.devices"]

tdn_data ifaces : List Execution.IfaceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.ifaces"]

tdn_data routes : List Execution.Route from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.routes"]

tdn_data links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.links"]

tdn_data bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.bridges"]

tdn_data macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.macIfaces"]

tdn_data carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.carriers"]

def config : Config := MultiProtocolExecution.dataPlaneConfigFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := Execution.expectedEncapStackFromRecords ifaces
tdn_data redSources : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.redSources"]

tdn_data grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.grayIfaces"]

tdn_data blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.blackIfaces"]

lemma mac_configuration_checked : ∀ iface ∈ macIfaces,
    iface.settings.controlledPortEnabled = true ∧ iface.settings.protectFrames = true ∧
    iface.settings.encryptFrames = true ∧ iface.settings.confidentialityOffset = 0 ∧
    ∃ association, iface.transmitAssociation = some association := by
  simp [macIfaces]

lemma receive_peer_bindings : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    ∃ peer ∈ macIfaces, peer.transmitAssociation = some association := by
  unfold macIfaces; decide

theorem every_configured_mac_iface_emits_full_encryption (iface : MACIface)
    (member : iface ∈ macIfaces) :
    ∃ association, ∀ body, fullMACsecTransmit iface association body := by
  obtain ⟨enabled, protect, encrypt, zero, association, installed⟩ := mac_configuration_checked iface member
  refine ⟨association, fun body => ⟨installed, ?_⟩⟩
  simpa [zero] using LinkProtection.enabled_sa_emits_encryption iface.settings enabled protect encrypt
    association.keyGeneration body

theorem payload_preserved_by_every_mixed_execution {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_executions_preserve_payload config run
end TDN.Imported.PairingMacsecIpsecStandalone

namespace TDN.Imported.PairingMacsecMacsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.devices"]

tdn_data ifaces : List Execution.IfaceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.ifaces"]

tdn_data routes : List Execution.Route from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.routes"]

tdn_data links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.links"]

tdn_data bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.bridges"]

tdn_data macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.macIfaces"]

tdn_data carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.carriers"]

def config : Config := MultiProtocolExecution.dataPlaneConfigFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := Execution.expectedEncapStackFromRecords ifaces
tdn_data redSources : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.redSources"]

tdn_data grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.grayIfaces"]

tdn_data blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.blackIfaces"]

lemma mac_configuration_checked : ∀ iface ∈ macIfaces,
    iface.settings.controlledPortEnabled = true ∧ iface.settings.protectFrames = true ∧
    iface.settings.encryptFrames = true ∧ iface.settings.confidentialityOffset = 0 ∧
    ∃ association, iface.transmitAssociation = some association := by
  simp [macIfaces]

lemma receive_peer_bindings : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    ∃ peer ∈ macIfaces, peer.transmitAssociation = some association := by
  unfold macIfaces; decide

theorem every_configured_mac_iface_emits_full_encryption (iface : MACIface)
    (member : iface ∈ macIfaces) :
    ∃ association, ∀ body, fullMACsecTransmit iface association body := by
  obtain ⟨enabled, protect, encrypt, zero, association, installed⟩ := mac_configuration_checked iface member
  refine ⟨association, fun body => ⟨installed, ?_⟩⟩
  simpa [zero] using LinkProtection.enabled_sa_emits_encryption iface.settings enabled protect encrypt
    association.keyGeneration body

theorem payload_preserved_by_every_mixed_execution {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_executions_preserve_payload config run
end TDN.Imported.PairingMacsecMacsecIntegrated

namespace TDN.Imported.PairingMacsecMacsecStandalone
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.devices"]

tdn_data ifaces : List Execution.IfaceData from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.ifaces"]

tdn_data routes : List Execution.Route from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.routes"]

tdn_data links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.links"]

tdn_data bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.bridges"]

tdn_data macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.macIfaces"]

tdn_data carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.carriers"]

def config : Config := MultiProtocolExecution.dataPlaneConfigFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := Execution.expectedEncapStackFromRecords ifaces
tdn_data redSources : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.redSources"]

tdn_data grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.grayIfaces"]

tdn_data blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.blackIfaces"]

lemma mac_configuration_checked : ∀ iface ∈ macIfaces,
    iface.settings.controlledPortEnabled = true ∧ iface.settings.protectFrames = true ∧
    iface.settings.encryptFrames = true ∧ iface.settings.confidentialityOffset = 0 ∧
    ∃ association, iface.transmitAssociation = some association := by
  simp [macIfaces]

lemma receive_peer_bindings : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    ∃ peer ∈ macIfaces, peer.transmitAssociation = some association := by
  unfold macIfaces; decide

theorem every_configured_mac_iface_emits_full_encryption (iface : MACIface)
    (member : iface ∈ macIfaces) :
    ∃ association, ∀ body, fullMACsecTransmit iface association body := by
  obtain ⟨enabled, protect, encrypt, zero, association, installed⟩ := mac_configuration_checked iface member
  refine ⟨association, fun body => ⟨installed, ?_⟩⟩
  simpa [zero] using LinkProtection.enabled_sa_emits_encryption iface.settings enabled protect encrypt
    association.keyGeneration body

theorem payload_preserved_by_every_mixed_execution {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_executions_preserve_payload config run
end TDN.Imported.PairingMacsecMacsecStandalone
