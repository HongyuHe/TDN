import TDN.Import.Command
import TDN.Targets.MultiProtocolPackets
import TDN.Semantics.FiniteMultiProtocol

namespace TDN.Imported.PairingInnerMacsecOuterIpsec
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../data/evidence/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.devices"]

tdn_data ports : List Execution.PortData from "../../data/evidence/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.ports"]

tdn_data routes : List Execution.Route from "../../data/evidence/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.routes"]

tdn_data links : List (Nat × Nat) from "../../data/evidence/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.links"]

tdn_data bridges : List (Nat × Nat) from "../../data/evidence/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.bridges"]

tdn_data macPorts : List MACPort from "../../data/evidence/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.macPorts"]

tdn_data carriers : List CarrierPort from "../../data/evidence/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.carriers"]

def config : Config := MultiProtocolExecution.finiteConfig devices ports routes links bridges macPorts carriers
def layout := Execution.finiteLayout ports
tdn_data redSources : List Nat from "../../data/evidence/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.redSources"]

tdn_data grayPorts : List Nat from "../../data/evidence/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.grayPorts"]

tdn_data blackPorts : List Nat from "../../data/evidence/FreshBridgedMACsecConfig.json" ["TDN.Imported.PairingInnerMacsecOuterIpsec.blackPorts"]

lemma mac_configuration_checked : ∀ port ∈ macPorts,
    port.settings.controlledPortEnabled = true ∧ port.settings.protectFrames = true ∧
    port.settings.encryptFrames = true ∧ port.settings.confidentialityOffset = 0 ∧
    ∃ association, port.transmitAssociation = some association := by
  simp [macPorts]

lemma receive_peer_bindings : ∀ port ∈ macPorts, ∀ association ∈ port.receiveAssociations,
    ∃ peer ∈ macPorts, peer.transmitAssociation = some association := by
  unfold macPorts; decide

theorem every_configured_mac_port_emits_full_encryption (port : MACPort)
    (member : port ∈ macPorts) :
    ∃ association, ∀ body, fullMACsecTransmit port association body := by
  obtain ⟨enabled, protect, encrypt, zero, association, installed⟩ := mac_configuration_checked port member
  refine ⟨association, fun body => ⟨installed, ?_⟩⟩
  simpa [zero] using LinkProtection.enabled_sa_emits_encryption port.settings enabled protect encrypt
    association.keyGeneration body

theorem payload_preserved_by_every_mixed_execution {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish) :
    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=
  all_executions_preserve_payload config run
end TDN.Imported.PairingInnerMacsecOuterIpsec
