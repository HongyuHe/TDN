import TDN.Import.SnapshotLoader
import TDN.Requirements.MultiProtocolPacketDefinitions
import TDN.Models.TableDrivenMultiProtocolDataPlane

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec
open MultiProtocolForwarding LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
load_network_records devices : List DataPlaneForwarding.DeviceData from "../../data/evidence/spec002-carrier-fields/SnapshotBridgedMacsecConfig.json" ["TDN.Deployments.PairingInnerMacsecOuterIpsec.devices"]

load_network_records ifaces : List DataPlaneForwarding.IfaceData from "../../data/evidence/spec002-carrier-fields/SnapshotBridgedMacsecConfig.json" ["TDN.Deployments.PairingInnerMacsecOuterIpsec.ifaces"]

load_network_records routes : List DataPlaneForwarding.FibRoute from "../../data/evidence/spec002-carrier-fields/SnapshotBridgedMacsecConfig.json" ["TDN.Deployments.PairingInnerMacsecOuterIpsec.routes"]

load_network_records links : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/SnapshotBridgedMacsecConfig.json" ["TDN.Deployments.PairingInnerMacsecOuterIpsec.links"]

load_network_records bridges : List (Nat × Nat) from "../../data/evidence/spec002-carrier-fields/SnapshotBridgedMacsecConfig.json" ["TDN.Deployments.PairingInnerMacsecOuterIpsec.bridges"]

load_network_records macIfaces : List MACIface from "../../data/evidence/spec002-carrier-fields/SnapshotBridgedMacsecConfig.json" ["TDN.Deployments.PairingInnerMacsecOuterIpsec.macIfaces"]

load_network_records carriers : List CarrierIface from "../../data/evidence/spec002-carrier-fields/SnapshotBridgedMacsecConfig.json" ["TDN.Deployments.PairingInnerMacsecOuterIpsec.carriers"]

def config : Config := MultiProtocolForwarding.dataPlaneModelFromRecords devices ifaces routes links bridges macIfaces carriers
def expectedEncapStack := DataPlaneForwarding.expectedEncapStackFromRecords ifaces
load_network_records redSources : List Nat from "../../data/evidence/spec002-carrier-fields/SnapshotBridgedMacsecConfig.json" ["TDN.Deployments.PairingInnerMacsecOuterIpsec.redSources"]

load_network_records grayIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/SnapshotBridgedMacsecConfig.json" ["TDN.Deployments.PairingInnerMacsecOuterIpsec.grayIfaces"]

load_network_records blackIfaces : List Nat from "../../data/evidence/spec002-carrier-fields/SnapshotBridgedMacsecConfig.json" ["TDN.Deployments.PairingInnerMacsecOuterIpsec.blackIfaces"]

lemma mac_configuration_checked : ∀ iface ∈ macIfaces,
    iface.settings.controlledPortEnabled = true ∧ iface.settings.protectFrames = true ∧
    iface.settings.encryptFrames = true ∧ iface.settings.confidentialityOffset = 0 ∧
    ∃ association, iface.transmitAssociation = some association := by
  simp [macIfaces]

lemma receive_peer_bindings : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    ∃ peer ∈ macIfaces, peer.transmitAssociation = some association := by
  unfold macIfaces; native_decide

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
end TDN.Deployments.PairingInnerMacsecOuterIpsec
