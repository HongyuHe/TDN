import TDN.Targets.PhysicalBoundaryView
import TDN.Semantics.BoundaryObservation

namespace TDN.Compliance

def BoundaryFilterStep (configuration : MultiProtocolExecution.Config)
    (context : PacketProcessing.Context) (filtered : MultiProtocolExecution.State) : Prop :=
  (context.hook = .forward ∧
    MultiProtocolExecution.Step configuration context.state .forwardFilter filtered) ∨
  (context.hook = .output ∧
    MultiProtocolExecution.Step configuration context.state .outputFilter filtered)

inductive NativeBoundaryView (configuration : MultiProtocolExecution.Config)
    (context : PacketProcessing.Context) :
    Direction → Nat → PacketPolicy.Packet → Prop
  | inbound (header : PacketPolicy.Packet)
      (visible : configuration.visibleHeader context.entry.frame = some header) :
      NativeBoundaryView configuration context .inbound context.entry.iface
        (MultiProtocolExecution.BoundaryPacket configuration context.entry.iface false header)
  | outbound (filtered ready afterWire : MultiProtocolExecution.State)
      (filter : BoundaryFilterStep configuration context filtered)
      (processing : MultiProtocolExecution.FirstReadyRun configuration filtered ready)
      (wire : MultiProtocolExecution.Step configuration ready .linkTransmit afterWire)
      (header : PacketPolicy.Packet)
      (visible : configuration.visibleHeader ready.frame = some header) :
      NativeBoundaryView configuration context .outbound ready.iface
        (MultiProtocolExecution.BoundaryPacket configuration ready.iface true header)

def Deployment.NativeBoundaryAccepts (d : Deployment) (interface : String)
    (direction : Direction) (traffic : Traffic) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    ∃ filteringInterface ∈ d.interfaces,
    ∃ context : PacketProcessing.Context,
      d.SupportedAt filteringInterface direction context
        (d.Observe (context.Packet inventory.configuration)) ∧
      d.AcceptsAt filteringInterface.id direction context.hook
        (d.Observe (context.Packet inventory.configuration)) ∧
      context.entry.frame.HeadersCoherent ∧
      ∃ iface ∈ inventory.ifaces,
        inventory.ifaceName iface = interface ∧
        NativeBoundaryView inventory.configuration context direction iface traffic.packet ∧
        d.Supported traffic

def Deployment.BoundaryAccepts (d : Deployment) (interface : String)
    (direction : Direction) (traffic : Traffic) : Prop :=
  d.NativeBoundaryAccepts interface direction traffic ∨
    d.AcceptsAt interface direction .link traffic ∨
    d.PhysicalBoundaryAccepts interface direction traffic

end TDN.Compliance

namespace TDN.Compliance

def CryptographicBoundary (device : Device) (interface : Interface) : Prop :=
  (device.layer = some .outer ∧ interface.zone = .black) ∨
    (device.layer = some .inner ∧ interface.zone = .gray)

instance (device : Device) (interface : Interface) :
    Decidable (CryptographicBoundary device interface) := by
  unfold CryptographicBoundary
  infer_instance

def Deployment.BoundaryAdmission (d : Deployment) (device : Device) (interface : Interface)
    (direction : Direction) (traffic : Traffic) : Prop :=
  if CryptographicBoundary device interface then d.BoundaryAccepts interface.id direction traffic
  else d.Accepts interface.id direction traffic

def TransportServicePort (packet : PacketPolicy.Packet) (source : Bool) : Nat :=
  if packet.protocol ∈ ["icmp", "icmpv6"] then 0
  else if source then packet.sourcePort else packet.destinationPort

lemma decoded_ICMP_service_ports (packet : PacketPolicy.Packet) (header payload : List UInt8)
    (icmp : packet.protocol ∈ ["icmp", "icmpv6"])
    (decoded : PacketSource.TransportHeaderMatches packet header payload) :
    TransportServicePort packet true = packet.sourcePort ∧
      TransportServicePort packet false = packet.destinationPort := by
  rcases decoded with udp | tcp | control
  · simp_all
  · simp_all
  · simp [TransportServicePort, icmp, control.2.2.1, control.2.2.2.1]

end TDN.Compliance

namespace TDN.Compliance

def Deployment.BoundaryPolicyCoverage (d : Deployment) (interface : Interface) : Prop :=
  d.PolicyCoverage interface ∧
    ∀ inventory, d.processing = some inventory →
      ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
        d.LinkPath inventory iface →
        ∃ policy, LinkAdmission.lookup inventory.configuration.linkPolicies iface = some policy

end TDN.Compliance
