import TDN.Targets.CPDuties

namespace TDN.Targets.Complete
open Compliance

def msc_nested_layer_protection {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (flows : List Flow) (flowOf : S → List A → S → PayloadId → Flow) (independentKeys : String → String → Prop) : Prop :=
  Primitive_msc_nested_layer_protection { d with focus := none } model flows flowOf independentKeys

def msc_security_level_connectivity {S A : Type} (context : CPContext S A) : Prop :=
  SecurityLevelConnectivityCore { context.deployment with focus := none } context.model
    context.authenticatedInnerPairs context.establishedInnerTunnels context.requiredConnectivity
    context.includedUnclassified ∧
  (∃ contexts, context ∈ contexts ∧ MSCReferencesClosed contexts) ∧
  ∀ network ∈ context.includedUnclassified, context.AllApplicableDuties (.network network)

def msc_security_level_key_and_management_separation :=
  Primitive_msc_security_level_key_and_management_separation

def msc_gray_firewall_path_coverage (d : Deployment) (topology : GrayTopology) : Prop :=
  Primitive_msc_gray_firewall_path_coverage { d with focus := none } topology

def msc_gray_addressing_for_level_filtering (d : Deployment)
    (ranges : List (Addressing.Range SecurityLevel)) (pairs : List IntendedAddressPair) : Prop :=
  Primitive_msc_gray_addressing_for_level_filtering { d with focus := none } ranges pairs

def msc_macsec_encapsulation {S A : Type} (context : CPContext S A) : Prop :=
  MACsecEncapsulationCore { context.deployment with focus := none } context.model
    context.encapsulations context.crossesIP ∧
  ∀ use ∈ context.encapsulations, use.builtInSupported = false →
    context.AllApplicableDuties (.component use.encapsulator)

def msc_vpn_private_key_confinement {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (keys : List PrivateKey) (objectiveSelected : String → Bool)
    (policies : List MandatoryKeyPolicy) : Prop :=
  Primitive_msc_vpn_private_key_confinement { d with focus := none } model keys objectiveSelected policies

def msc_macsec_authentication_choice_and_as {S A : Type} (d : Deployment)
    (model : ExecutionModel S A) (primitive : TLSPrimitive)
    (authentication : List MACsecAuthentication) : Prop :=
  Primitive_msc_macsec_authentication_choice_and_as { d with focus := none } model primitive authentication

def msc_macsec_key_generation_and_server (d : Deployment) (keys : List MACsecKey)
    (pairs : List MACsecServerPair) (provisioning : List KeyProvisioning)
    (eapCAKGeneratedByApprovedKGS : String → String → Prop) : Prop :=
  Primitive_msc_macsec_key_generation_and_server { d with focus := none } keys pairs provisioning
    eapCAKGeneratedByApprovedKGS

def msc_macsec_protection_parameters {S A : Type} (d : Deployment)
    (model : ExecutionModel S A) (parameters : List MACsecParameters) : Prop :=
  Primitive_msc_macsec_protection_parameters { d with focus := none } model parameters

def msc_inner_tunnel_no_bypass {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool) : Prop :=
  Primitive_msc_inner_tunnel_no_bypass { d with focus := none } model components
    outboundMACObjective inboundMACObjective

def msc_outer_tunnel_no_bypass {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool) : Prop :=
  Primitive_msc_outer_tunnel_no_bypass { d with focus := none } model components
    outboundMACObjective inboundMACObjective

def msc_transec_conditions := Primitive_msc_transec_conditions

def msc_packet_size_configuration {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (sizes : WireSizeModel S) (sizing : List PacketSizing) (profiles : List FragmentationProfile) : Prop :=
  model.CoversDeployment { d with focus := none } ∧ sizes.Correspondence model sizing ∧ sizes.NoFurtherFragmentation model sizing ∧
  PacketSizingInventory { d with focus := none } model sizing ∧
  Primitive_msc_packet_size_configuration sizing profiles

def msc_outer_firewall_placement := @Primitive_msc_outer_firewall_placement

def msc_boundary_interface_filtering (d : Deployment) (outerFirewallRequired : Bool)
    (firewallInternal : String → Bool) (localOuter : String → String) : Prop :=
  Primitive_msc_boundary_interface_filtering { d with focus := none } outerFirewallRequired
    firewallInternal localOuter

def msc_outer_third_party_services (d : Deployment) (objectiveSelected : String → Bool)
    (features : List ThirdPartyFeature) : Prop :=
  Primitive_msc_outer_third_party_services { d with focus := none } objectiveSelected features

def msc_ip_header_and_multicast_filtering (d : Deployment)
    (dropIPv4OptionsObjective : String → Bool) : Prop :=
  Primitive_msc_ip_header_and_multicast_filtering { d with focus := none } dropIPv4OptionsObjective

def msc_outer_gray_interface_policy (d : Deployment) (cdpOnGray : Bool) : Prop :=
  Primitive_msc_outer_gray_interface_policy { d with focus := none } cdpOnGray

def msc_gray_firewall_allowlist (d : Deployment) (grayFirewallRequired : Bool) : Prop :=
  Primitive_msc_gray_firewall_allowlist { d with focus := none } grayFirewallRequired

def msc_administrator_authentication (d : Deployment)
    (certificateObjective nistObjective : Bool) (events : List AdminEvent)
    (accounts : List AdministrativeAccount) (sessions : List AdministrativeSession)
    (awAdministrators : List Nat) : Prop :=
  Primitive_msc_administrator_authentication { d with focus := none } certificateObjective
    nistObjective events accounts sessions awAdministrators

def msc_site_interoperability {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (requiredSitePairs : List (String × String)) (selected : List Interoperation)
    (domain : PayloadDomain) : Prop :=
  Primitive_msc_site_interoperability { d with focus := none } model requiredSitePairs selected domain

def msc_approved_red_egress_paths {S A : Type} (d : Deployment)
    (red outside : String → Prop) (conformingMSC aoApprovedProtection : String → Prop)
    (solutions : List (CPContext S A)) : Prop :=
  MSCReferencesClosed solutions ∧
  (∀ solution, conformingMSC solution → ∃ context ∈ solutions,
    context.solution = solution ∧ context.AllApplicableDuties (.solution solution)) ∧
  RedEgressCore { d with focus := none } red outside conformingMSC aoApprovedProtection

def msc_redundant_component_permission {S A : Type} (context : CPContext S A)
    (redundant : String → Prop) : Prop :=
  ∀ device ∈ context.deployment.devices, redundant device.id →
    (¬ context.deployment.OrdinaryGray device.id ∨
      context.deployment.standaloneEncapsulator device.id) →
    context.AllApplicableDuties (.component device.id)

end TDN.Targets.Complete
