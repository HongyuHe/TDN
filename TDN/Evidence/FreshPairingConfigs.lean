import TDN.Import.Command
import TDN.Targets.MultiProtocolPackets
import TDN.Semantics.FiniteMultiProtocol

namespace TDN.Imported.PairingIpsecIpsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.devices"]

tdn_data ports : List Execution.PortData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.ports"]

tdn_data routes : List Execution.Route from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.routes"]

tdn_data links : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.links"]

tdn_data bridges : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.bridges"]

tdn_data macPorts : List MACPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.macPorts"]

tdn_data carriers : List CarrierPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.carriers"]

def config : Config := MultiProtocolExecution.finiteConfig devices ports routes links bridges macPorts carriers
def layout := Execution.finiteLayout ports
tdn_data redSources : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.redSources"]

tdn_data grayPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.grayPorts"]

tdn_data blackPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecIpsecIntegrated.blackPorts"]

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
end TDN.Imported.PairingIpsecIpsecIntegrated

namespace TDN.Imported.PairingIpsecMacsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.devices"]

tdn_data ports : List Execution.PortData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.ports"]

tdn_data routes : List Execution.Route from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.routes"]

tdn_data links : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.links"]

tdn_data bridges : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.bridges"]

tdn_data macPorts : List MACPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.macPorts"]

tdn_data carriers : List CarrierPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.carriers"]

def config : Config := MultiProtocolExecution.finiteConfig devices ports routes links bridges macPorts carriers
def layout := Execution.finiteLayout ports
tdn_data redSources : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.redSources"]

tdn_data grayPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.grayPorts"]

tdn_data blackPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingIpsecMacsecIntegrated.blackPorts"]

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
end TDN.Imported.PairingIpsecMacsecIntegrated

namespace TDN.Imported.PairingMacsecIpsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.devices"]

tdn_data ports : List Execution.PortData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.ports"]

tdn_data routes : List Execution.Route from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.routes"]

tdn_data links : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.links"]

tdn_data bridges : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.bridges"]

tdn_data macPorts : List MACPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.macPorts"]

tdn_data carriers : List CarrierPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.carriers"]

def config : Config := MultiProtocolExecution.finiteConfig devices ports routes links bridges macPorts carriers
def layout := Execution.finiteLayout ports
tdn_data redSources : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.redSources"]

tdn_data grayPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.grayPorts"]

tdn_data blackPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecIntegrated.blackPorts"]

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
end TDN.Imported.PairingMacsecIpsecIntegrated

namespace TDN.Imported.PairingMacsecIpsecStandalone
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.devices"]

tdn_data ports : List Execution.PortData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.ports"]

tdn_data routes : List Execution.Route from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.routes"]

tdn_data links : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.links"]

tdn_data bridges : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.bridges"]

tdn_data macPorts : List MACPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.macPorts"]

tdn_data carriers : List CarrierPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.carriers"]

def config : Config := MultiProtocolExecution.finiteConfig devices ports routes links bridges macPorts carriers
def layout := Execution.finiteLayout ports
tdn_data redSources : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.redSources"]

tdn_data grayPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.grayPorts"]

tdn_data blackPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecIpsecStandalone.blackPorts"]

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
end TDN.Imported.PairingMacsecIpsecStandalone

namespace TDN.Imported.PairingMacsecMacsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.devices"]

tdn_data ports : List Execution.PortData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.ports"]

tdn_data routes : List Execution.Route from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.routes"]

tdn_data links : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.links"]

tdn_data bridges : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.bridges"]

tdn_data macPorts : List MACPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.macPorts"]

tdn_data carriers : List CarrierPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.carriers"]

def config : Config := MultiProtocolExecution.finiteConfig devices ports routes links bridges macPorts carriers
def layout := Execution.finiteLayout ports
tdn_data redSources : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.redSources"]

tdn_data grayPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.grayPorts"]

tdn_data blackPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecIntegrated.blackPorts"]

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
end TDN.Imported.PairingMacsecMacsecIntegrated

namespace TDN.Imported.PairingMacsecMacsecStandalone
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
tdn_data devices : List Execution.DeviceData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.devices"]

tdn_data ports : List Execution.PortData from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.ports"]

tdn_data routes : List Execution.Route from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.routes"]

tdn_data links : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.links"]

tdn_data bridges : List (Nat × Nat) from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.bridges"]

tdn_data macPorts : List MACPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.macPorts"]

tdn_data carriers : List CarrierPort from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.carriers"]

def config : Config := MultiProtocolExecution.finiteConfig devices ports routes links bridges macPorts carriers
def layout := Execution.finiteLayout ports
tdn_data redSources : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.redSources"]

tdn_data grayPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.grayPorts"]

tdn_data blackPorts : List Nat from "../../evidence/lean/FreshPairingConfigs.json" ["TDN.Imported.PairingMacsecMacsecStandalone.blackPorts"]

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
end TDN.Imported.PairingMacsecMacsecStandalone
