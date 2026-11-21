import TDN.Requirements.AllZoneCrossingLinksCovered

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding LayeredFrame

structure RoutedMacsecCase where
  entryIface : Nat
  route : DataPlaneForwarding.FibRoute
  header : PacketPolicy.Packet
  application : List UInt8
  originDomain : Nat
  mac : MACIface
  peerIface : Nat

def RoutedMacsecCase.entry (sample : RoutedMacsecCase) : MultiProtocolForwarding.TunnelForwardingState :=
  { iface := sample.entryIface
    datapathStage := .received
    enteredIface := sample.entryIface
    frame := { payload := LinkAdmission.payloadCode sample.application
               originDomain := sample.originDomain
               body := .datagram sample.header }
    authenticated := []
    tracking := "new" }

def RoutedMacsecCase.entered (sample : RoutedMacsecCase) : MultiProtocolForwarding.TunnelForwardingState :=
  { sample.entry with initialEntry := false, datapathStage := .ingress }

def RoutedMacsecCase.routed (sample : RoutedMacsecCase) (configuration : TunnelForwardingModel) :
    MultiProtocolForwarding.TunnelForwardingState :=
  { sample.entered with
    initialEntry := false
    iface := sample.route.egress
    datapathStage := .routed
    frame := configuration.forwardedFrame sample.entry.frame }

def RoutedMacsecCase.forwardedHeader (sample : RoutedMacsecCase) : PacketPolicy.Packet :=
  { sample.header with hopLimit := sample.header.hopLimit - 1 }

def RoutedMacsecCase.filtered (sample : RoutedMacsecCase) (configuration : TunnelForwardingModel) :
    MultiProtocolForwarding.TunnelForwardingState :=
  { sample.routed configuration with initialEntry := false, datapathStage := .filtered }

def RoutedMacsecCase.egressReady (sample : RoutedMacsecCase) (configuration : TunnelForwardingModel) :
    MultiProtocolForwarding.TunnelForwardingState :=
  { sample.filtered configuration with initialEntry := false, datapathStage := .egressReady }

def RoutedMacsecCase.RoutingChecks (sample : RoutedMacsecCase) (configuration : TunnelForwardingModel) : Prop :=
  sample.route.ingress = sample.entryIface ∧ sample.route.egress = sample.mac.logicalIface ∧
    DataPlaneForwarding.SelectedFibRoute configuration.ip.routes sample.route sample.header ∧
    1 < sample.header.hopLimit ∧ sample.header.hopLimit ≤ 255 ∧
    PacketPolicy.AclAllows (configuration.ip.forwardRules sample.route.egress)
      (configuration.ip.forwardFallback sample.route.egress)
      (policyHeader configuration (sample.routed configuration) sample.forwardedHeader) ∧
    DataPlaneForwarding.lookupSpdPolicies (configuration.ip.egressPolicies sample.route.egress)
      sample.forwardedHeader = []

instance (sample : RoutedMacsecCase) (configuration : TunnelForwardingModel) :
    Decidable (sample.RoutingChecks configuration) := by
  unfold RoutedMacsecCase.RoutingChecks PacketPolicy.AclAllows DataPlaneForwarding.SelectedFibRoute DataPlaneForwarding.FibRoute.matches
  infer_instance

lemma routed_macsec_case_reaches_logical_output (sample : RoutedMacsecCase)
    (configuration : TunnelForwardingModel) (processing : HeaderProcessing)
    (mode : configuration.headerProcessing = some processing)
    (checks : sample.RoutingChecks configuration) :
    (lts configuration).MTr sample.entry [.receive, .route, .forwardFilter, .forwardWithoutEncap]
      (sample.egressReady configuration) ∧
    (sample.egressReady configuration).iface = sample.mac.logicalIface ∧
    (sample.egressReady configuration).datapathStage = .egressReady ∧
    (sample.egressReady configuration).frame.payload = LinkAdmission.payloadCode sample.application := by
  obtain ⟨ingress, egress, selected, _, _, accepted, noIPsec⟩ := checks
  have initialVisible : configuration.visibleHeader sample.entry.frame = some sample.header := by
    simp [RoutedMacsecCase.entry, TunnelForwardingModel.visibleHeader, mode, TunnelFrame.visibleHeader, Body.visibleHeader]
  have outputVisible : configuration.visibleHeader (sample.routed configuration).frame =
      some sample.forwardedHeader := by
    simp [RoutedMacsecCase.routed, RoutedMacsecCase.entry, RoutedMacsecCase.forwardedHeader,
      TunnelForwardingModel.visibleHeader, TunnelForwardingModel.forwardedFrame, mode, TunnelFrame.forwarded, TunnelFrame.visibleHeader,
      Body.visibleHeader]
  have received : MultiProtocolForwarding.TunnelForwardingStep configuration sample.entry .receive sample.entered :=
    .receive rfl initialVisible "new"
  have routed : MultiProtocolForwarding.TunnelForwardingStep configuration sample.entered .route (sample.routed configuration) :=
    .route sample.route rfl initialVisible selected ingress
  have filtered : MultiProtocolForwarding.TunnelForwardingStep configuration (sample.routed configuration) .forwardFilter
      (sample.filtered configuration) := .forwardFilter rfl outputVisible accepted
  have plain : MultiProtocolForwarding.TunnelForwardingStep configuration (sample.filtered configuration) .forwardWithoutEncap
      (sample.egressReady configuration) := .forwardWithoutEncap rfl outputVisible noIPsec
  refine ⟨.stepL received (.stepL routed (.stepL filtered (.stepL plain .refl))), egress, rfl, ?_⟩
  simp [RoutedMacsecCase.egressReady, RoutedMacsecCase.filtered, RoutedMacsecCase.routed,
    RoutedMacsecCase.entry, TunnelForwardingModel.forwardedFrame, mode]

end TDN.Requirements.Msc
