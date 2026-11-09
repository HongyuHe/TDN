import TDN.Import.SnapshotLoader
import TDN.Requirements.MultiProtocolPacketDefinitions
import TDN.Models.TableDrivenMultiProtocolDataPlane

namespace TDN.Deployments.PairingIpsecIpsecIntegrated
open MultiProtocolForwarding LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
load_network_records devices : List DataPlaneForwarding.DeviceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecIpsecIntegrated.devices"]

load_network_records ifaces : List DataPlaneForwarding.IfaceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecIpsecIntegrated.ifaces"]

load_network_records routes : List DataPlaneForwarding.FibRoute from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecIpsecIntegrated.routes"]

load_network_records links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecIpsecIntegrated.links"]

load_network_records bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecIpsecIntegrated.bridges"]

load_network_records macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecIpsecIntegrated.macIfaces"]

load_network_records carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecIpsecIntegrated.carriers"]

def config : Config := MultiProtocolForwarding.dataPlaneModelFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := DataPlaneForwarding.expectedEncapStackFromRecords ifaces
load_network_records redSources : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecIpsecIntegrated.redSources"]

load_network_records grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecIpsecIntegrated.grayIfaces"]

load_network_records blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecIpsecIntegrated.blackIfaces"]

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

theorem payload_preserved_by_every_mixed_forwarding {start finish : MultiProtocolForwarding.State} {actions : List MultiProtocolForwarding.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_traces_preserve_payload config run
end TDN.Deployments.PairingIpsecIpsecIntegrated

namespace TDN.Deployments.PairingIpsecMacsecIntegrated
open MultiProtocolForwarding LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
load_network_records devices : List DataPlaneForwarding.DeviceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecMacsecIntegrated.devices"]

load_network_records ifaces : List DataPlaneForwarding.IfaceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecMacsecIntegrated.ifaces"]

load_network_records routes : List DataPlaneForwarding.FibRoute from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecMacsecIntegrated.routes"]

load_network_records links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecMacsecIntegrated.links"]

load_network_records bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecMacsecIntegrated.bridges"]

load_network_records macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecMacsecIntegrated.macIfaces"]

load_network_records carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecMacsecIntegrated.carriers"]

def config : Config := MultiProtocolForwarding.dataPlaneModelFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := DataPlaneForwarding.expectedEncapStackFromRecords ifaces
load_network_records redSources : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecMacsecIntegrated.redSources"]

load_network_records grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecMacsecIntegrated.grayIfaces"]

load_network_records blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingIpsecMacsecIntegrated.blackIfaces"]

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

theorem payload_preserved_by_every_mixed_forwarding {start finish : MultiProtocolForwarding.State} {actions : List MultiProtocolForwarding.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_traces_preserve_payload config run
end TDN.Deployments.PairingIpsecMacsecIntegrated

namespace TDN.Deployments.PairingMacsecIpsecIntegrated
open MultiProtocolForwarding LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
load_network_records devices : List DataPlaneForwarding.DeviceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecIntegrated.devices"]

load_network_records ifaces : List DataPlaneForwarding.IfaceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecIntegrated.ifaces"]

load_network_records routes : List DataPlaneForwarding.FibRoute from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecIntegrated.routes"]

load_network_records links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecIntegrated.links"]

load_network_records bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecIntegrated.bridges"]

load_network_records macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecIntegrated.macIfaces"]

load_network_records carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecIntegrated.carriers"]

def config : Config := MultiProtocolForwarding.dataPlaneModelFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := DataPlaneForwarding.expectedEncapStackFromRecords ifaces
load_network_records redSources : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecIntegrated.redSources"]

load_network_records grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecIntegrated.grayIfaces"]

load_network_records blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecIntegrated.blackIfaces"]

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

theorem payload_preserved_by_every_mixed_forwarding {start finish : MultiProtocolForwarding.State} {actions : List MultiProtocolForwarding.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_traces_preserve_payload config run
end TDN.Deployments.PairingMacsecIpsecIntegrated

namespace TDN.Deployments.PairingMacsecIpsecStandalone
open MultiProtocolForwarding LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
load_network_records devices : List DataPlaneForwarding.DeviceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.devices"]

load_network_records ifaces : List DataPlaneForwarding.IfaceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.ifaces"]

load_network_records routes : List DataPlaneForwarding.FibRoute from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.routes"]

load_network_records links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.links"]

load_network_records bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.bridges"]

load_network_records macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.macIfaces"]

load_network_records carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.carriers"]

def config : Config := MultiProtocolForwarding.dataPlaneModelFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := DataPlaneForwarding.expectedEncapStackFromRecords ifaces
load_network_records redSources : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.redSources"]

load_network_records grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.grayIfaces"]

load_network_records blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.blackIfaces"]

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

theorem payload_preserved_by_every_mixed_forwarding {start finish : MultiProtocolForwarding.State} {actions : List MultiProtocolForwarding.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_traces_preserve_payload config run
end TDN.Deployments.PairingMacsecIpsecStandalone

namespace TDN.Deployments.PairingMacsecMacsecIntegrated
open MultiProtocolForwarding LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
load_network_records devices : List DataPlaneForwarding.DeviceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecIntegrated.devices"]

load_network_records ifaces : List DataPlaneForwarding.IfaceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecIntegrated.ifaces"]

load_network_records routes : List DataPlaneForwarding.FibRoute from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecIntegrated.routes"]

load_network_records links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecIntegrated.links"]

load_network_records bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecIntegrated.bridges"]

load_network_records macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecIntegrated.macIfaces"]

load_network_records carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecIntegrated.carriers"]

def config : Config := MultiProtocolForwarding.dataPlaneModelFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := DataPlaneForwarding.expectedEncapStackFromRecords ifaces
load_network_records redSources : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecIntegrated.redSources"]

load_network_records grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecIntegrated.grayIfaces"]

load_network_records blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecIntegrated.blackIfaces"]

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

theorem payload_preserved_by_every_mixed_forwarding {start finish : MultiProtocolForwarding.State} {actions : List MultiProtocolForwarding.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_traces_preserve_payload config run
end TDN.Deployments.PairingMacsecMacsecIntegrated

namespace TDN.Deployments.PairingMacsecMacsecStandalone
open MultiProtocolForwarding LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
load_network_records devices : List DataPlaneForwarding.DeviceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecStandalone.devices"]

load_network_records ifaces : List DataPlaneForwarding.IfaceData from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecStandalone.ifaces"]

load_network_records routes : List DataPlaneForwarding.FibRoute from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecStandalone.routes"]

load_network_records links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecStandalone.links"]

load_network_records bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecStandalone.bridges"]

load_network_records macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecStandalone.macIfaces"]

load_network_records carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecStandalone.carriers"]

def config : Config := MultiProtocolForwarding.dataPlaneModelFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := DataPlaneForwarding.expectedEncapStackFromRecords ifaces
load_network_records redSources : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecStandalone.redSources"]

load_network_records grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecStandalone.grayIfaces"]

load_network_records blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/TunnelMatrix_Configs.json" ["TDN.Deployments.PairingMacsecMacsecStandalone.blackIfaces"]

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

theorem payload_preserved_by_every_mixed_forwarding {start finish : MultiProtocolForwarding.State} {actions : List MultiProtocolForwarding.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_traces_preserve_payload config run
end TDN.Deployments.PairingMacsecMacsecStandalone
