import TDN.Targets.ComplianceModel

namespace TDN.Compliance

inductive PhysicalBoundaryView (configuration : MultiProtocolExecution.Config) :
    Direction → Nat → LinkAdmission.Frame → Prop
  | outbound (before after : MultiProtocolExecution.State) (encoded : LinkAdmission.Frame)
      (wire : MultiProtocolExecution.Step configuration before .linkTransmit after)
      (describes : encoded.Describes before.frame) :
      PhysicalBoundaryView configuration .outbound before.iface encoded
  | inbound (before after : MultiProtocolExecution.State) (encoded : LinkAdmission.Frame)
      (wire : MultiProtocolExecution.Step configuration before .linkTransmit after)
      (describes : encoded.Describes after.frame) :
      PhysicalBoundaryView configuration .inbound after.iface encoded

def PhysicalBoundaryPacket (configuration : MultiProtocolExecution.Config)
    (iface : Nat) (direction : Direction) (encoded : LinkAdmission.Frame) : PacketPolicy.Packet :=
  encoded.Packet
    (if direction = .inbound then configuration.ip.interfaceName iface else "")
    (if direction = .outbound then configuration.ip.interfaceName iface else "")

def Deployment.PhysicalBoundaryAccepts (d : Deployment) (interface : String)
    (direction : Direction) (traffic : Traffic) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    ∃ iface ∈ inventory.ifaces,
      d.LinkPath inventory iface ∧ inventory.ifaceName iface = interface ∧
      inventory.configuration.ip.interfaceName iface = interface ∧
      ∃ record ∈ d.interfaces, record.id = interface ∧
        record.device = inventory.componentName (inventory.configuration.ip.owner iface) ∧
        ∃ encoded,
          PhysicalBoundaryView inventory.configuration direction iface encoded ∧
          traffic.packet = PhysicalBoundaryPacket inventory.configuration iface direction encoded ∧
          d.Supported traffic ∧
          LinkAdmission.Admitted inventory.configuration.linkPolicies iface
            (direction = .outbound) traffic.packet

end TDN.Compliance
