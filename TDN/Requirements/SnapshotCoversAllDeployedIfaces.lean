import TDN.Requirements.StandardMtuSizingBridge
import TDN.Requirements.VerifiedHostTransmitSources

namespace TDN.Requirements.StandardDataPlaneBridge
open Compliance LayeredFrame PacketSource MultiProtocolForwarding IPsecFrameEncoding

structure DeviceDeploymentBindings {S A : Type} (prototype : DeviceExecutionBinding S A)
    (ifaces : List Nat) (d : Deployment) : Prop where
  processing : prototype.ProcessingBound d
  interfaceLinks : d.InterfaceLinksWellFormed
  linkPolicies : d.LinkPoliciesComplete
  headerGeneration : ∃ inventory, d.processing = some inventory ∧
    prototype.configuration.HeaderGenerationKnown inventory.ifaces
  macsecKeys : prototype.MACsecKeyInventory
  ipsecKeys : prototype.IPsecKeyInventory
  redNetworks : d.networks ≠ []
  peers : ∀ tunnel ∈ d.tunnels, d.intendedPeer tunnel.sender tunnel.receiver
  deviceIDs : ∀ first ∈ d.devices, ∀ second ∈ d.devices, first.id = second.id → first = second
  interfaceIDs : ∀ first ∈ d.interfaces, ∀ second ∈ d.interfaces, first.id = second.id → first = second
  tunnelIDs : ∀ first ∈ d.tunnels, ∀ second ∈ d.tunnels, first.id = second.id → first = second
  interfaceIndices : ∀ interface ∈ d.interfaces, ∃ iface,
    prototype.ifaceName iface = interface.id ∧
      prototype.componentName (prototype.configuration.ip.owner iface) = interface.device
  ifaceRecords : ∀ iface ∈ ifaces, ∃ interface ∈ d.interfaces,
    interface.id = prototype.ifaceName iface ∧
      interface.device = prototype.componentName (prototype.configuration.ip.owner iface)
  physicalLinks : ∀ first last, prototype.configuration.physicalLink first last →
    d.physicalLink (prototype.ifaceName first) (prototype.ifaceName last)
  sourceEntries : ∀ iface network, prototype.sourceEntry iface = some network ↔
    ∃ interface ∈ d.interfaces, interface.id = prototype.ifaceName iface ∧
      interface.zone = .red ∧ interface.managementNetwork = false ∧ ∃ red ∈ d.networks,
        red.id = network ∧ interface.device ∈ red.innerComponents
  macsecTunnels : ∀ iface ∈ prototype.configuration.macIfaces, ∀ association,
    iface.transmitAssociation = some association → ∃ tunnel ∈ d.tunnels,
      tunnel.id = prototype.macsecTunnel association ∧ tunnel.mechanism = .macsec ∧
      tunnel.keyContext = prototype.keyName association.keyGeneration ∧
      tunnel.sender = prototype.componentName (prototype.configuration.ip.owner iface.physicalIface) ∧
      ∀ peer ∈ prototype.configuration.macIfaces,
        (∃ installed ∈ peer.receiveAssociations, SameMACWireIdentity association installed) →
        tunnel.receiver = prototype.componentName (prototype.configuration.ip.owner peer.physicalIface)
  ipsecTunnels : ∀ iface association policy,
    (association ∈ prototype.configuration.ip.egressSAs iface ∧ policy ∈ prototype.configuration.ip.egressPolicies iface ∨
      association ∈ prototype.configuration.ip.ingressSAs iface ∧ policy ∈ prototype.configuration.ip.ingressPolicies iface) →
    DataPlaneForwarding.saMatchesPolicy association policy → ∃ tunnel ∈ d.tunnels,
      tunnel.id = prototype.ipsecTunnel (policy.seal association) ∧ tunnel.mechanism = .ipsec ∧
      d.AddressOwner association.sender = some tunnel.sender ∧ d.AddressOwner association.receiver = some tunnel.receiver


theorem standard_deployment_covered {S A Key : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (static : DeviceDeploymentBindings prototype ifaces d) (historyValid : history.Valid)
    (ifaceChecks : IfaceConditions prototype.configuration ifaces)
    (codec : Codec Key) (required : Nat → Bool) (mtu plaintextLimit authenticationLimit : Nat → Nat)
    (sizeChecks : SizeChecks prototype.configuration required mtu plaintextLimit authenticationLimit)
    (processing : HeaderProcessing) (mode : prototype.configuration.headerProcessing = some processing)
    (headerBounds : HeaderBounds processing)
    (encoding : ∀ iface frame, prototype.configuration.linkEncoding iface frame = some (linkEncoding codec frame))
    (sources : prototype.sourceProcessing = sourceProcessing mtu) (minimum : ∀ iface, 1280 ≤ mtu iface)
    (noUDPBindings : d.udpBindings = [])
    (sourceIfaces : ∀ request, (binding prototype ifaces).SourceRequestAllowed d request → request.iface ∈ ifaces)
    (networkSources : ∀ network ∈ d.networks, ∃ request datagrams,
      (binding prototype ifaces).SourceRequestAllowed d request ∧ request.application ≠ [] ∧
      prototype.origin request.originDomain = .red network.id ∧
      prototype.sourceProcessing.process request = .emitted datagrams) :
    (model prototype ifaces d history).CoversDeployment d := by
  have emissions : EmissionConditions prototype.sourceProcessing := by
    rw [sources]
    exact source_processing_emission_conditions mtu minimum
  refine ⟨static.processing, standard_model_faithful prototype ifaces d history,
    standard_model_covers_every_native_step prototype ifaces d history ifaceChecks,
    standard_generated_source_coverage prototype ifaces d history mtu sources minimum noUDPBindings
      sourceIfaces networkSources,
    historyValid, static.interfaceLinks, static.linkPolicies, static.headerGeneration, ?_,
    static.macsecKeys, static.ipsecKeys, static.redNetworks, static.peers,
    static.deviceIDs, static.interfaceIDs, static.tunnelIDs, static.interfaceIndices, ?_,
    static.physicalLinks, static.sourceEntries, static.macsecTunnels, static.ipsecTunnels⟩
  · intro start actions state initialized run
    exact ⟨standard_reachable_headers prototype ifaces d history processing mode headerBounds
      start state actions initialized run,
      standard_reachable_link_encoding prototype ifaces d history codec required mtu plaintextLimit
        authenticationLimit sizeChecks emissions processing mode headerBounds encoding initialized run⟩
  · intro state
    exact static.ifaceRecords state.native.iface state.ifacePresent

end TDN.Requirements.StandardDataPlaneBridge
