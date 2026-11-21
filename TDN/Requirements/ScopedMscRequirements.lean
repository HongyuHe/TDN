import TDN.Requirements.MscComplianceSchema
import TDN.Requirements.PermittedGrayForwardingFlows
import TDN.Requirements.PerimeterInterfaceSlice
import TDN.Requirements.InnerOuterTunnelCompositionSpec
import TDN.Requirements.MscFirewallWaypointingTheorems

namespace TDN.Requirements.Msc
open Compliance

structure Flow where
  sourceNetwork : String
  destinationNetwork : String
  innerTunnel : String
  outerTunnel : String

def Flow.Valid (d : Deployment) (flow : Flow) (independentKeys : String → String → Prop) : Prop :=
  ∃ inner ∈ d.tunnels, ∃ outer ∈ d.tunnels,
    inner.id = flow.innerTunnel ∧ outer.id = flow.outerTunnel ∧
    inner.layer = .inner ∧ outer.layer = .outer ∧
    independentKeys inner.keyContext outer.keyContext ∧
    (∀ tunnel ∈ [inner, outer], ∃ sender ∈ d.devices, ∃ receiver ∈ d.devices,
      sender.id = tunnel.sender ∧ receiver.id = tunnel.receiver ∧
      sender.infrastructure = true ∧ receiver.infrastructure = true ∧
      sender.layer = some tunnel.layer ∧ receiver.layer = some tunnel.layer ∧
      sender.site ≠ receiver.site ∧
      (tunnel.protocol = .ipsec → sender.kind = .vpn ∧ receiver.kind = .vpn) ∧
      (tunnel.protocol = .macsec → sender.kind = .macsec ∧ receiver.kind = .macsec)) ∧
    (∃ source ∈ d.networks, ∃ destination ∈ d.networks,
      source.id = flow.sourceNetwork ∧ destination.id = flow.destinationNetwork ∧
      inner.sender ∈ source.innerComponents ∧ inner.receiver ∈ destination.innerComponents ∧
      (∃ sender ∈ d.devices, sender.id = outer.sender ∧ sender.site = source.site) ∧
      ∃ receiver ∈ d.devices, receiver.id = outer.receiver ∧ receiver.site = destination.site) ∧
    (outer.protocol = .macsec → ∃ first second,
      first ≠ second ∧ ∀ device ∈ d.devices, d.InScope device.id →
        device.layer = some .outer → device.site = first ∨ device.site = second)

def AuthenticationServices (d : Deployment) : Prop :=
  (∀ component ∈ d.devices, d.InScope component.id →
    d.certificateAuthenticated component.id = true →
    ∃ authority ∈ d.devices, authority.kind = .certificationAuthority ∧
      d.keyManagementCA component.id authority.id) ∧
  (∀ component ∈ d.devices, d.InScope component.id →
    d.preSharedCAKAuthenticated component.id = true →
    ∃ generator ∈ d.devices, generator.kind = .keyGenerationSolution ∧
      d.keyManagementGenerator component.id generator.id)

def ArchitectureServices (d : Deployment) : Prop :=
  AuthenticationServices d ∧
  ∀ a ∈ d.devices, ∀ b ∈ d.devices, a.layer = some .inner → b.layer = some .inner →
    a.level ≠ b.level → (∃ outer, d.innerUsesOuter a.id outer ∧ d.innerUsesOuter b.id outer) →
      ∃ firewall ∈ d.devices, firewall.kind = .grayFirewall

def CrossedBlack (d : Deployment) (events : List NetworkEvent) (payload : PayloadId) : Prop :=
  ∃ interface ∈ d.interfaces, interface.zone = .black ∧ ∃ layers,
    ∃ trafficClass, .transmit payload interface.id layers trafficClass ∈ events ∨
      .receive payload interface.id layers trafficClass ∈ events

def scoped_nested_layer_protection {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (flows : List Flow) (flowOf : S → List A → S → PayloadId → Flow) (independentKeys : String → String → Prop) : Prop :=
  model.CoversDeployment d ∧ ArchitectureServices d ∧
  (∀ flow ∈ flows, flow.Valid d independentKeys) ∧
  (∀ start actions finish, model.initial start → model.ForwardsAlongTrace start actions finish →
    let events := model.TraceEvents actions
    let selectedFlow := flowOf start actions finish
    (∀ payload network, .inject payload network ∈ events →
      selectedFlow payload ∈ flows ∧ (selectedFlow payload).sourceNetwork = network) ∧
    (∀ earlier later payload iface layers trafficClass,
      events = earlier ++ [.transmit payload iface layers trafficClass] ++ later →
      model.ProtectedPayload d payload →
      ∀ interface ∈ d.interfaces, d.InScope interface.device → interface.id = iface →
      (interface.zone = .gray → selectedFlow payload ∈ flows ∧ layers = [(selectedFlow payload).innerTunnel] ∧
        .encrypt payload (selectedFlow payload).innerTunnel ∈ earlier) ∧
      (interface.zone = .black → selectedFlow payload ∈ flows ∧
        layers = [(selectedFlow payload).outerTunnel, (selectedFlow payload).innerTunnel] ∧
        Before earlier (.encrypt payload (selectedFlow payload).innerTunnel)
          (.encrypt payload (selectedFlow payload).outerTunnel))) ∧
    (∀ payload iface layers trafficClass, .receive payload iface layers trafficClass ∈ events →
      model.ProtectedPayload d payload →
      ∀ interface ∈ d.interfaces, d.InScope interface.device → interface.id = iface → interface.zone = .black →
      selectedFlow payload ∈ flows ∧
      layers = [(selectedFlow payload).outerTunnel, (selectedFlow payload).innerTunnel]) ∧
    ∀ earlier later payload network layers,
      events = earlier ++ [.deliver payload network layers] ++ later →
      .inject payload (selectedFlow payload).sourceNetwork ∈ earlier → CrossedBlack d earlier payload →
      selectedFlow payload ∈ flows ∧ network = (selectedFlow payload).destinationNetwork ∧ layers = [] ∧
      Before earlier (.decrypt payload (selectedFlow payload).outerTunnel)
        (.decrypt payload (selectedFlow payload).innerTunnel))

def scoped_security_level_connectivity {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (authenticatedInnerPairs establishedInnerTunnels : List (String × String))
    (requiredConnectivity : List (String × String)) (includedUnclassified : List String) : Prop :=
  model.CoversDeployment d ∧
  DedicatedInnerAssignments d.networks ∧
  (∀ network ∈ d.networks, ∀ inner ∈ network.innerComponents,
    ∃ device ∈ d.devices, device.id = inner ∧ device.layer = some .inner ∧
      device.level = network.level) ∧
  (∀ pair ∈ authenticatedInnerPairs ++ establishedInnerTunnels,
    ∃ first ∈ d.devices, ∃ second ∈ d.devices,
      first.id = pair.1 ∧ second.id = pair.2 ∧ first.layer = some .inner ∧
      second.layer = some .inner ∧ first.level = second.level) ∧
  (model.AllTraces (fun events => ∀ payload source destination layers,
    Before events (.inject payload source) (.deliver payload destination layers) →
    ∃ first ∈ d.networks, ∃ second ∈ d.networks,
      first.id = source ∧ second.id = destination ∧ first.level = second.level)) ∧
  (∀ pair ∈ requiredConnectivity, ∃ start actions finish payload,
    model.initial start ∧ model.ForwardsAlongTrace start actions finish ∧
    Before (model.TraceEvents actions) (.inject payload pair.1) (.deliver payload pair.2 [])) ∧
  ∀ network ∈ includedUnclassified,
    (∃ red ∈ d.networks, red.id = network ∧ red.level.classification = "unclassified")

structure GrayTopology where
  edge : String → String → Prop
  inner : String → Prop
  grayFirewall : String → Prop
  outer : String → Prop
  workstation : String → Prop
  localCA : String → Prop
  certificationAuthority : String → Prop
  revocationService : String → Prop
  level : String → SecurityLevel
  highest : SecurityLevel
  dominates : SecurityLevel → SecurityLevel → Prop

def GrayManagement (topology : GrayTopology) (node : String) : Prop :=
  topology.workstation node ∨ topology.localCA node

def InnerEndpoints (d : Deployment) (traffic : Traffic) : Prop :=
  ∃ source destination, traffic.sourceDevice = some source ∧
    traffic.destinationDevice = some destination ∧
    d.IsLayer source .inner ∧ d.IsLayer destination .inner

def FiltersIntendedPeers (d : Deployment) (device : String) : Prop :=
  ∀ interface ∈ d.interfaces, d.InScope interface.device → interface.device = device → interface.zone = .gray →
    d.PolicyCoverage interface ∧ ∀ direction traffic,
      d.PermitsOnInterface interface.id direction traffic → InnerEndpoints d traffic →
      d.SameLevelInner traffic

def scoped_gray_firewall_path_coverage (d : Deployment) (topology : GrayTopology) : Prop :=
  d.AddressInventoryCoherent ∧
  (∀ node, topology.inner node ↔ d.IsLayer node .inner) ∧
  (∀ node, topology.grayFirewall node ↔ d.IsDevice node .grayFirewall) ∧
  (∀ node, topology.outer node ↔ d.IsLayer node .outer) ∧
  (∀ node, topology.workstation node ↔ d.grayWorkstation node) ∧
  (∀ node, topology.localCA node → topology.certificationAuthority node) ∧
  (∀ node, topology.certificationAuthority node ↔
    d.IsDevice node .certificationAuthority ∧
      ∃ interface ∈ d.interfaces, interface.device = node ∧ interface.zone = .gray) ∧
  (∀ node, topology.revocationService node ↔
    d.IsDevice node .revocationService ∧
      ∃ interface ∈ d.interfaces, interface.device = node ∧ interface.zone = .gray) ∧
  (∀ device ∈ d.devices, d.InScope device.id → topology.level device.id = device.level) ∧
  TDN.Requirements.graph_gray_firewall_waypointing topology.edge topology.grayFirewall topology.inner
    (GrayManagement topology) topology.level topology.highest topology.dominates
    (FiltersIntendedPeers d) d.authority.protectsAsClassified ∧
  (∀ service component,
    (topology.workstation service ∨ topology.certificationAuthority service ∨
      topology.revocationService service) → topology.inner component →
    topology.level service ≠ topology.level component →
    ¬ Waypointing.ReachableWithoutWaypoint topology.edge topology.grayFirewall service component) ∧
  (∀ outer, topology.outer outer → FiltersIntendedPeers d outer) ∧
  (∀ firewall, topology.grayFirewall firewall → ∀ interface ∈ d.interfaces, d.InScope interface.device →
    interface.device = firewall → ∀ direction traffic,
      d.PermitsOnInterface interface.id direction traffic →
      ∀ manager component, GrayManagement topology manager → topology.inner component →
        topology.level component ≠ topology.highest →
        ¬ ((traffic.sourceDevice = some manager ∧ traffic.destinationDevice = some component) ∨
          (traffic.sourceDevice = some component ∧ traffic.destinationDevice = some manager))) ∧
  ∀ firewall, topology.grayFirewall firewall → ∃ outer inner,
    topology.outer outer ∧ topology.inner inner ∧
    Waypointing.ReachableByLinks topology.edge inner firewall ∧
    Waypointing.ReachableByLinks topology.edge firewall outer

def InternalZone : EncryptionLayer → Zone
  | .inner => .red
  | .outer => .gray

def ExternalZone : EncryptionLayer → Zone
  | .inner => .gray
  | .outer => .black

def TraceNoBypass (d : Deployment) (genuineControl : PayloadId → Prop)
    (layer : EncryptionLayer) (events : List NetworkEvent) : Prop :=
  (∀ earlier middle later payload ingress receivedLayers receiveClass egress sentLayers sendClass,
    events = earlier ++ [.receive payload ingress receivedLayers receiveClass] ++ middle ++
      [.transmit payload egress sentLayers sendClass] ++ later →
    ¬ genuineControl payload →
    ∀ input ∈ d.interfaces, ∀ output ∈ d.interfaces,
      input.id = ingress → output.id = egress → input.device = output.device →
      d.IsLayer input.device layer →
      (input.zone = InternalZone layer → output.zone ≠ InternalZone layer →
        ∃ tunnel ∈ d.tunnels, tunnel.layer = layer ∧ tunnel.sender = input.device ∧
          tunnel.id ∈ sentLayers ∧ .encrypt payload tunnel.id ∈ middle) ∧
      (input.zone = ExternalZone layer → output.zone = InternalZone layer →
        ∃ tunnel ∈ d.tunnels, tunnel.layer = layer ∧ tunnel.receiver = input.device ∧
          tunnel.id ∈ receivedLayers ∧ .decrypt payload tunnel.id ∈ middle)) ∧
  ∀ earlier later payload iface layers trafficClass,
    events = earlier ++ [.transmit payload iface layers trafficClass] ++ later →
    ¬ genuineControl payload →
    ∀ interface ∈ d.interfaces, interface.id = iface →
      d.IsLayer interface.device layer → interface.zone = ExternalZone layer →
      ∃ tunnel ∈ d.tunnels, tunnel.layer = layer ∧ tunnel.sender = interface.device ∧
        tunnel.id ∈ layers ∧ .encrypt payload tunnel.id ∈ earlier

def LayerNoBypass {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (layer : EncryptionLayer) : Prop :=
  model.CoversDeployment d ∧ model.AllTraces (TraceNoBypass d model.GenuineControl layer)

def ComponentConfigurationCoverage (d : Deployment) (layer : EncryptionLayer)
    (components : List EncryptionComponentConfiguration) : Prop :=
  ∀ device ∈ d.devices, d.InScope device.id → device.layer = some layer →
    ∃ component ∈ components, component.id = device.id ∧
      ((device.kind = .vpn ∧ component.protocol = .ipsec) ∨
        (device.kind = .macsec ∧ component.protocol = .macsec))

def scoped_inner_tunnel_no_bypass {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool) : Prop :=
  ComponentConfigurationCoverage d .inner components ∧ LayerNoBypass d model .inner ∧
  ∀ component ∈ components, d.InScope component.id →
    (component.protocol = .ipsec → component.espTunnelMode = true ∧ component.associatedIPTunnel = true) ∧
    (outboundMACObjective = true → component.outboundMACPolicy = true) ∧
    (inboundMACObjective = true → component.inboundMACPolicy = true)

def scoped_outer_tunnel_no_bypass {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool) : Prop :=
  ComponentConfigurationCoverage d .outer components ∧ LayerNoBypass d model .outer ∧
  (∀ component ∈ components, d.InScope component.id →
    (component.protocol = .ipsec → component.espTunnelMode = true) ∧
    (outboundMACObjective = true → component.outboundMACPolicy = true) ∧
    (inboundMACObjective = true → component.inboundMACPolicy = true)) ∧
  model.AllTraces (fun events => ∀ payload ingress layers trafficClass,
    .receive payload ingress layers trafficClass ∈ events → ¬ model.GenuineControl payload →
    ∀ interface ∈ d.interfaces, d.InScope interface.device → interface.id = ingress → interface.zone = .gray →
      d.IsLayer interface.device .outer →
      ∃ tunnel ∈ d.tunnels, tunnel.layer = .inner ∧ layers = [tunnel.id])

def ApprovedControl (d : Deployment) (device : String) (traffic : Traffic) : Prop :=
  traffic.trafficClass = .control ∧ d.policyApproved device traffic

def AOApprovedControl (d : Deployment) (device : String) (traffic : Traffic) : Prop :=
  ApprovedControl d device traffic ∧ d.aoApproved device traffic

def LocalOuterAddress (d : Deployment) (firewall outer : String) (address : Nat) : Prop :=
  d.IsDevice firewall .outerFirewall ∧ d.IsLayer outer .outer ∧
  ∃ interface ∈ d.interfaces, interface.device = outer ∧ interface.zone = .black ∧
    interface.address = some address

def scoped_boundary_interface_filtering (d : Deployment) (outerFirewallRequired : Bool)
    (firewallInternal : String → Bool) (localOuter : String → String) : Prop :=
  d.AddressInventoryCoherent ∧ d.ProcessingCoherent ∧ d.UDPBindingsCoherent ∧
  ∀ interface ∈ d.interfaces, d.InScope interface.device → ∀ device ∈ d.devices, d.InScope device.id → interface.device = device.id →
    ((device.layer = some .outer ∧ interface.zone = .black) ∨
      (device.layer = some .inner ∧ interface.zone = .gray) ∨
      (device.layer = some .inner ∧ interface.zone = .red) ∨
      (device.kind = .outerFirewall ∧ outerFirewallRequired = true)) →
    d.BoundaryPolicyCoverage interface ∧ ∀ direction traffic, d.BoundaryAdmission device interface direction traffic →
      (device.layer = some .outer → interface.zone = .black →
        ((device.kind = .vpn → d.IPsecTraffic traffic ∨
          ApprovedControl d device.id traffic) ∧
        (device.kind = .macsec → PacketMACsec traffic.packet ∨
          ApprovedControl d device.id traffic) ∧
        (direction = .outbound → d.IntendedPacketPeerAt interface.id device.id traffic))) ∧
      (device.layer = some .inner → interface.zone = .gray →
        d.PermittedTunnelTraffic traffic ∨ AOApprovedControl d device.id traffic) ∧
      (device.layer = some .inner → interface.zone = .red →
        d.redService device.id traffic.packet.source (TransportServicePort traffic.packet true) ∨
        d.redService device.id traffic.packet.destination (TransportServicePort traffic.packet false)) ∧
      (device.kind = .outerFirewall → outerFirewallRequired = true →
        (d.PermittedTunnelTraffic traffic ∨ ApprovedControl d device.id traffic) ∧
        (direction = .inbound → ¬ ApprovedControl d device.id traffic →
          if firewallInternal interface.id then
            LocalOuterAddress d device.id (localOuter device.id) traffic.packet.source
          else LocalOuterAddress d device.id (localOuter device.id) traffic.packet.destination))

def HeaderFilterApplies (device : Device) (interface : Interface) : Prop :=
  (device.layer = some .outer ∧ interface.zone = .black) ∨ device.kind = .vpn

def NecessaryApprovedL2Control (d : Deployment) (interface : Interface) (traffic : Traffic) : Prop :=
  traffic.trafficClass = .control ∧ d.policyApproved interface.device traffic ∧
  traffic.packet.destination = 1652522221571 ∧
  ∃ inventory, d.processing = some inventory ∧
    ∃ endpoint ∈ inventory.mkaPeers,
      inventory.ifaceName endpoint.destinationIface = interface.id ∧
      PacketPolicy.Packet.MKAFraming traffic.packet endpoint.actorSCI ∧
      (traffic.packet.payloadBytes.bind (fun bytes => bytes[0]?)) = some 3 ∧
      ∃ tunnel ∈ d.tunnels, tunnel.id = endpoint.tunnel ∧ tunnel.layer = .outer ∧
        tunnel.protocol = .macsec ∧
        inventory.componentName (inventory.configuration.ip.owner endpoint.sourceIface) = tunnel.sender ∧
        inventory.componentName (inventory.configuration.ip.owner endpoint.destinationIface) = tunnel.receiver ∧
        tunnel.receiver = interface.device ∧ d.intendedPeer tunnel.sender tunnel.receiver

def scoped_ip_header_and_multicast_filtering (d : Deployment)
    (dropIPv4OptionsObjective : String → Bool) : Prop :=
  (∀ device, dropIPv4OptionsObjective device = d.dropIPv4Options device) ∧
  d.AddressInventoryCoherent ∧ d.ProcessingCoherent ∧ d.LinkPoliciesComplete ∧
  ∀ interface ∈ d.interfaces, d.InScope interface.device → ∀ device ∈ d.devices, d.InScope device.id → interface.device = device.id →
    HeaderFilterApplies device interface →
    d.PolicyCoverage interface ∧
    ∀ traffic, d.PermitsOnInterface interface.id .inbound traffic →
      (device.layer = some .outer → interface.zone = .black →
        traffic.multicast = false ∨ NecessaryApprovedL2Control d interface traffic) ∧
      (device.kind = .vpn → traffic.ipVersion = some 4 → traffic.ipProtocol ∈ [6, 17, 50, 1]) ∧
      (device.kind = .vpn → traffic.ipVersion = some 6 →
        traffic.packet.ipv6NextHeader ∈ [50, 6, 17, 58]) ∧
      (device.kind = .vpn → device.layer = some .outer → traffic.ipVersion = some 4 →
        dropIPv4OptionsObjective device.id = true → traffic.packet.ipv4HeaderWords = 5)

def OuterManagementInitiation (d : Deployment) (traffic : Traffic) : Prop :=
  traffic.trafficClass = .management ∧
    (d.grayWorkstation traffic.originator ∨
      (d.IsLayer traffic.originator .outer ∧ traffic.service ∈ ["logging", "authentication"]))

def OuterTunnelAllowance (d : Deployment) (device : String) (traffic : Traffic) : Prop :=
  (d.TunnelTraffic traffic ∨ (∃ source destination, d.CarrierInnerPair traffic source destination)) ∧
    ((d.SameLevelInner traffic ∧ d.AppropriateInnerTunnel traffic) ∨
      (d.grayManagementService device traffic ∧ d.GrayManagementTunnel traffic))

def RevocationHTTP (traffic : Traffic) : Prop :=
  traffic.service = "http" ∧ traffic.innerRevocation = true

def OuterPolicyAllowance (d : Deployment) (device : String) (cdpOnGray : Bool)
    (traffic : Traffic) : Prop :=
  OuterTunnelAllowance d device traffic ∨
    (cdpOnGray = true ∧ d.IsDevice device .vpn ∧ RevocationHTTP traffic) ∨
    ((traffic.trafficClass = .management ∨ traffic.trafficClass = .control) ∧
      d.policyApproved device traffic)

def OuterGrayRestrictions (d : Deployment) (interface : Interface) (direction : Direction)
    (cdpOnGray : Bool) (traffic : Traffic) : Prop :=
  d.HeaderEligible interface traffic ∧
  (traffic.trafficClass = .management → OuterManagementInitiation d traffic) ∧
  (direction = .inbound → d.reachableSource interface.id traffic.packet.source) ∧
  (traffic.trafficClass = .protectedData → ¬ RevocationHTTP traffic →
    d.SameLevelInner traffic ∨
      (d.grayManagementService interface.device traffic ∧ d.GrayManagementTunnel traffic)) ∧
  (traffic.service = "http" → cdpOnGray = true → d.IsDevice interface.device .vpn →
    traffic.innerRevocation = true)

def scoped_outer_gray_interface_policy (d : Deployment) (cdpOnGray : Bool) : Prop :=
  d.AddressInventoryCoherent ∧ d.ProcessingCoherent ∧ d.UDPBindingsCoherent ∧
  ∀ interface ∈ d.interfaces, d.InScope interface.device → d.IsLayer interface.device .outer → interface.zone = .gray →
    d.PolicyCoverage interface ∧
    (∀ direction traffic, d.PermitsOnInterface interface.id direction traffic →
      OuterGrayRestrictions d interface direction cdpOnGray traffic ∧
      OuterPolicyAllowance d interface.device cdpOnGray traffic) ∧
    ∀ direction hook traffic, d.PacketEligibleAt interface direction hook traffic →
      OuterGrayRestrictions d interface direction cdpOnGray traffic →
      OuterPolicyAllowance d interface.device cdpOnGray traffic →
      d.PermitsAtHook interface.id direction hook traffic

def GrayManagementAllowance (d : Deployment) (interface : Interface) (traffic : Traffic) : Prop :=
  interface.physical = true ∧ interface.managementNetwork = true ∧
    traffic.trafficClass = .management ∧ d.grayManagementService interface.device traffic ∧
    d.policyApproved interface.device traffic

def GrayPolicyAllowance (d : Deployment) (interface : Interface) (traffic : Traffic) : Prop :=
  ((d.TunnelTraffic traffic ∨ (∃ source destination, d.CarrierInnerPair traffic source destination)) ∧
    d.SameLevelInner traffic ∧ d.AppropriateInnerTunnel traffic) ∨ RevocationHTTP traffic ∨
    GrayManagementAllowance d interface traffic ∨
    (traffic.trafficClass = .control ∧ d.policyApproved interface.device traffic)

def DifferentClassificationVPNs (d : Deployment) (traffic : Traffic) : Prop :=
  ∃ source ∈ d.devices, ∃ destination ∈ d.devices,
    source.kind = .vpn ∧ destination.kind = .vpn ∧
    source.layer = some .inner ∧ destination.layer = some .inner ∧
    source.level.classification ≠ destination.level.classification ∧
    d.InnerPair traffic source.id destination.id

def GrayFirewallRestrictions (d : Deployment) (interface : Interface) (direction : Direction)
    (traffic : Traffic) : Prop :=
  d.HeaderEligible interface traffic ∧
  (traffic.trafficClass = .management → GrayManagementAllowance d interface traffic) ∧
  (traffic.trafficClass = .protectedData → ¬ RevocationHTTP traffic → d.SameLevelInner traffic) ∧
  (direction = .inbound → d.reachableSource interface.id traffic.packet.source) ∧
  (traffic.service = "http" → traffic.innerRevocation = true) ∧
  ¬ DifferentClassificationVPNs d traffic

def scoped_gray_firewall_allowlist (d : Deployment) (grayFirewallRequired : Bool) : Prop :=
  d.AddressInventoryCoherent ∧
  (grayFirewallRequired = true → d.ProcessingCoherent ∧ d.UDPBindingsCoherent ∧
    ∀ interface ∈ d.interfaces, d.InScope interface.device →
      d.IsDevice interface.device .grayFirewall → d.PolicyCoverage interface ∧
        (∀ direction traffic, d.PermitsOnInterface interface.id direction traffic →
          GrayFirewallRestrictions d interface direction traffic ∧
          GrayPolicyAllowance d interface traffic) ∧
        ∀ direction hook traffic, d.PacketEligibleAt interface direction hook traffic →
          d.GrayForwardPermission interface hook traffic →
          GrayFirewallRestrictions d interface direction traffic →
          GrayPolicyAllowance d interface traffic →
          d.PermitsAtHook interface.id direction hook traffic) ∧
  ∀ interface ∈ d.interfaces, d.InScope interface.device → d.IsDevice interface.device .grayFirewall →
    ∀ direction traffic, DifferentClassificationVPNs d traffic →
      ¬ d.PermitsOnInterface interface.id direction traffic

end TDN.Requirements.Msc
