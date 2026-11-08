import TDN.Import.Command
import TDN.Targets.MultiProtocolPackets
import TDN.Semantics.FiniteMultiProtocol

namespace TDN.Imported.PairingInnerMacsecOuterIpsec
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../data/evidence/spec002-carrier-fields/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.devices"]

tdn_data ifaces : List Execution.IfaceData from "../../data/evidence/spec002-carrier-fields/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.ifaces"]

tdn_data routes : List Execution.Route from "../../data/evidence/spec002-carrier-fields/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.routes"]

tdn_data links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.links"]

tdn_data bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.bridges"]

tdn_data macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.macIfaces"]

tdn_data carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.carriers"]

def config : Config := MultiProtocolExecution.dataPlaneConfigFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := Execution.expectedEncapStackFromRecords ifaces
tdn_data redSources : List Nat from "../../data/evidence/spec002-carrier-fields/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.redSources"]

tdn_data grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.grayIfaces"]

tdn_data blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.blackIfaces"]

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
end TDN.Imported.PairingInnerMacsecOuterIpsec
