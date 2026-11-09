import TDN.Requirements.PermittedGrayForwardingFlows
import TDN.Requirements.GrayFirewallAllowlistSpec
import TDN.Requirements.OuterToGrayIptablesPatterns
import TDN.Models.Ipv4OptionsIpsecMasks

namespace TDN.Requirements.Msc
open Compliance DeriveEndpointInputOutputRules MultiProtocolForwarding

def GrayRevocationServiceAbsent (d : Deployment) : Prop :=
  ∀ device ∈ d.devices, device.kind ≠ .revocationService

instance (d : Deployment) : Decidable (GrayRevocationServiceAbsent d) := by
  unfold GrayRevocationServiceAbsent
  infer_instance

lemma Gray_revocation_HTTP_is_absent (d : Deployment) (checks : GrayRevocationServiceAbsent d)
    (traffic : Traffic) (supported : d.Supported traffic) : ¬ RevocationHTTP traffic := by
  have noEndpoint : d.RevocationEndpoint traffic.packet = false := by
    unfold Deployment.RevocationEndpoint
    apply Bool.eq_false_iff.mpr
    intro hit
    obtain ⟨device, member, matched⟩ := List.any_eq_true.mp hit
    simp only [Bool.and_eq_true, beq_iff_eq] at matched
    exact checks device member matched.1.2
  intro http
  rw [supported.1] at http
  exact Bool.false_ne_true (noEndpoint.symm.trans http.2)

lemma Gray_IPsec_allowance_has_record (d : Deployment) (pairs : List InnerIPsecPair)
    (udp : d.udpBindings = []) (carrier : d.carrierBindings = [])
    (mechanisms : ∀ tunnel ∈ d.tunnels, tunnel.layer = .inner → tunnel.mechanism = .ipsec)
    (coverage : InnerIPsecAddressCoverage d pairs) (revocation : GrayRevocationServiceAbsent d)
    (interface : Interface)
    (noApproved : ∀ traffic, ¬ d.policyApproved interface.device traffic)
    (noManagement : ∀ traffic, ¬ d.grayManagementService interface.device traffic)
    (traffic : Traffic) (supported : d.Supported traffic)
    (allowance : GrayPolicyAllowance d interface traffic) :
    IPsecPacket traffic.packet ∧ ∃ record ∈ pairs,
      traffic.packet.source = record.endpoints.sourceAddress ∧
      traffic.packet.destination = record.endpoints.destinationAddress := by
  rcases allowance with ⟨_, _, appropriate⟩ | http | management | ⟨_, approved⟩
  · exact appropriate_inner_IPsec_has_record d pairs udp carrier mechanisms coverage traffic appropriate
  · exact False.elim (Gray_revocation_HTTP_is_absent d revocation traffic supported http)
  · exact False.elim (noManagement traffic management.2.2.2.1)
  · exact False.elim (noApproved traffic approved)

def DeviceNamesUniqueByComponent (inventory : PacketProcessing.Inventory) : Prop :=
  ∀ first ∈ inventory.ifaces, ∀ second ∈ inventory.ifaces,
    inventory.componentName (inventory.configuration.ip.owner first) =
      inventory.componentName (inventory.configuration.ip.owner second) →
    inventory.configuration.ip.interfaceName first = inventory.configuration.ip.interfaceName second →
    first = second

instance (inventory : PacketProcessing.Inventory) : Decidable (DeviceNamesUniqueByComponent inventory) := by
  unfold DeviceNamesUniqueByComponent
  infer_instance

def GrayIncomingSource (d : Deployment) (inventory : PacketProcessing.Inventory)
    (device : String) (iface source : Nat) : Prop :=
  ∃ incoming ∈ d.interfaces, inventory.ifaceName iface = incoming.id ∧
    incoming.device = device ∧ d.reachableSource incoming.id source

instance (d : Deployment) (inventory : PacketProcessing.Inventory) (device : String)
    (iface source : Nat) [∀ interface, DecidablePred (d.reachableSource interface)] :
    Decidable (GrayIncomingSource d inventory device iface source) := by
  unfold GrayIncomingSource
  infer_instance

lemma forward_permission_has_known_source_at_actual_iface (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (unique : DeviceNamesUniqueByComponent inventory)
    (interface : Interface) (traffic : Traffic)
    (iface : Nat) (member : iface ∈ inventory.ifaces)
    (owner : inventory.componentName (inventory.configuration.ip.owner iface) = interface.device)
    (ingress : inventory.configuration.ip.interfaceName iface = traffic.packet.ingress)
    (permission : d.GrayForwardPermission interface .forward traffic) :
    GrayIncomingSource d inventory interface.device iface traffic.packet.source := by
  obtain ⟨actual, actualMember, incoming, incomingMember, name, incomingOwner,
    actualOwner, actualIngress, source⟩ :=
    forward_permission_records_the_actual_incoming_source_check d inventory present interface traffic permission
  have same := unique actual actualMember iface member (actualOwner.trans owner.symm)
    (actualIngress.trans ingress.symm)
  subst actual
  exact ⟨incoming, incomingMember, name, incomingOwner, source⟩

lemma forward_context_without_inbound_policies_has_empty_authentication
    (configuration : Config) (processing : HeaderProcessing)
    (mode : configuration.headerProcessing = some processing) (bounds : HeaderBounds processing)
    (context : PacketProcessing.Context) (hook : context.hook = .forward)
    (coherent : context.entry.frame.HeadersCoherent)
    (atHook : context.AtHook configuration)
    (noInbound : configuration.ip.ingressPolicies context.entry.iface = []) :
    context.state.authenticated = [] := by
  obtain ⟨visible, actual⟩ := atHook
  rw [hook] at actual
  obtain ⟨entered, route, ingress, _, routed, _⟩ := actual
  obtain ⟨_, empty | ⟨policy, configured, _⟩⟩ :=
    ingress_route_detailed_authentication processing mode bounds coherent ingress routed visible
  · exact empty.1
  · simp [noInbound] at configured

end TDN.Requirements.Msc
