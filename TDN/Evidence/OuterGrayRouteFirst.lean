import TDN.Evidence.OuterGrayNativeModel

namespace TDN.Imported.OuterGrayNativeModel
open Compliance Targets Targets.Complete MultiProtocolExecution

def Records.RouteFirstMaskLookup (records : Records) (base : Deployment)
    (interface : Interface) (direction : Direction) : Prop :=
  ∀ route ∈ records.routes,
    (if direction = .inbound then records.ifaceName route.ingress = interface.id
      else records.ifaceName route.egress = interface.id) →
    ∀ record ∈ records.pairs,
    route.matches (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress) →
    route.ingress ∈ records.inventory.ifaces → route.egress ∈ records.inventory.ifaces →
    Execution.SelectedRoute records.routes route
      (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress) →
    (direction = .inbound → records.reachableSource interface.id record.endpoints.sourceAddress) →
    ∀ choice ∈ authenticationChoices records.configuration route.ingress,
      AuthenticationChoiceValid (records.deployment base) records.inventory route.ingress
        record.endpoints.sourceAddress record.endpoints.destinationAddress choice →
      ∀ form ∈ PacketPolicy.IPsecForm.all, ∃ entry ∈ records.masks,
        entry.owner = (Execution.ifaceAt records.nativeIfaces (records.ifaceIndex interface)).owner ∧
        entry.packet = form.mask record.endpoints.sourceAddress record.endpoints.destinationAddress
          (records.configuration.ip.interfaceName route.ingress)
          (records.configuration.ip.interfaceName route.egress) (choiceAuthentication choice)
          ((Execution.selectedAssociations (records.configuration.ip.outbound route.egress)
            (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress)).map
              Execution.Association.id) (interface.mtu.getD 0)

set_option synthInstance.maxSize 2048 in
instance (records : Records) (base : Deployment) (interface : Interface) (direction : Direction) :
    Decidable (records.RouteFirstMaskLookup base interface direction) := by
  unfold Records.RouteFirstMaskLookup Execution.Route.matches
  infer_instance

theorem Records.route_first_lookup_iff (records : Records) (base : Deployment)
    (interface : Interface) (direction : Direction) :
    records.RouteFirstMaskLookup base interface direction ↔ records.ForwardMaskLookup base interface direction := by
  constructor
  · intro checked record recordMember route routeMember name ingressMember egressMember selected
    exact checked route routeMember name record recordMember selected.2.1 ingressMember egressMember selected
  · intro checked route routeMember name record recordMember _
    exact checked record recordMember route routeMember name

end TDN.Imported.OuterGrayNativeModel
