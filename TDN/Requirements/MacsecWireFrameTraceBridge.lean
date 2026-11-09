import TDN.Requirements.AllZoneCrossingLinksCovered

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding LayeredFrame

structure RoutedMACsecCase where
  entryIface : Nat
  route : DataPlaneForwarding.FibRoute
  header : PacketPolicy.Packet
  application : List UInt8
  originDomain : Nat
  mac : MACIface
  peerIface : Nat

def RoutedMACsecCase.entry (sample : RoutedMACsecCase) : MultiProtocolForwarding.State :=
  { iface := sample.entryIface
    datapathStage := .received
    enteredIface := sample.entryIface
    frame := { payload := LinkAdmission.payloadCode sample.application
               originDomain := sample.originDomain
               body := .datagram sample.header }
    authenticated := []
    tracking := "new" }

def RoutedMACsecCase.entered (sample : RoutedMACsecCase) : MultiProtocolForwarding.State :=
  { sample.entry with initialEntry := false, datapathStage := .ingress }

def RoutedMACsecCase.routed (sample : RoutedMACsecCase) (configuration : Config) :
    MultiProtocolForwarding.State :=
  { sample.entered with
    initialEntry := false
    iface := sample.route.egress
    datapathStage := .routed
    frame := configuration.forwardedFrame sample.entry.frame }

def RoutedMACsecCase.forwardedHeader (sample : RoutedMACsecCase) : PacketPolicy.Packet :=
  { sample.header with hopLimit := sample.header.hopLimit - 1 }

def RoutedMACsecCase.filtered (sample : RoutedMACsecCase) (configuration : Config) :
    MultiProtocolForwarding.State :=
  { sample.routed configuration with initialEntry := false, datapathStage := .filtered }

def RoutedMACsecCase.egressReady (sample : RoutedMACsecCase) (configuration : Config) :
    MultiProtocolForwarding.State :=
  { sample.filtered configuration with initialEntry := false, datapathStage := .egressReady }

def RoutedMACsecCase.RoutingChecks (sample : RoutedMACsecCase) (configuration : Config) : Prop :=
  sample.route.ingress = sample.entryIface ∧ sample.route.egress = sample.mac.logicalIface ∧
    DataPlaneForwarding.SelectedFibRoute configuration.ip.routes sample.route sample.header ∧
    1 < sample.header.hopLimit ∧ sample.header.hopLimit ≤ 255 ∧
    DataPlaneForwarding.accepts (configuration.ip.forwardRules sample.route.egress)
      (configuration.ip.forwardFallback sample.route.egress)
      (policyHeader configuration (sample.routed configuration) sample.forwardedHeader) ∧
    DataPlaneForwarding.lookupSpdPolicies (configuration.ip.egressPolicies sample.route.egress)
      sample.forwardedHeader = []

instance (sample : RoutedMACsecCase) (configuration : Config) :
    Decidable (sample.RoutingChecks configuration) := by
  unfold RoutedMACsecCase.RoutingChecks DataPlaneForwarding.accepts DataPlaneForwarding.SelectedFibRoute DataPlaneForwarding.FibRoute.matches
  infer_instance

lemma routed_MACsec_case_reaches_logical_output (sample : RoutedMACsecCase)
    (configuration : Config) (processing : HeaderProcessing)
    (mode : configuration.headerProcessing = some processing)
    (checks : sample.RoutingChecks configuration) :
    (lts configuration).MTr sample.entry [.receive, .route, .forwardFilter, .forwardWithoutEncap]
      (sample.egressReady configuration) ∧
    (sample.egressReady configuration).iface = sample.mac.logicalIface ∧
    (sample.egressReady configuration).datapathStage = .egressReady ∧
    (sample.egressReady configuration).frame.payload = LinkAdmission.payloadCode sample.application := by
  obtain ⟨ingress, egress, selected, _, _, accepted, noIPsec⟩ := checks
  have initialVisible : configuration.visibleHeader sample.entry.frame = some sample.header := by
    simp [RoutedMACsecCase.entry, Config.visibleHeader, mode, Frame.visibleHeader, Body.visibleHeader]
  have outputVisible : configuration.visibleHeader (sample.routed configuration).frame =
      some sample.forwardedHeader := by
    simp [RoutedMACsecCase.routed, RoutedMACsecCase.entry, RoutedMACsecCase.forwardedHeader,
      Config.visibleHeader, Config.forwardedFrame, mode, Frame.forwarded, Frame.visibleHeader,
      Body.visibleHeader]
  have received : MultiProtocolForwarding.Step configuration sample.entry .receive sample.entered :=
    .receive rfl initialVisible "new"
  have routed : MultiProtocolForwarding.Step configuration sample.entered .route (sample.routed configuration) :=
    .route sample.route rfl initialVisible selected ingress
  have filtered : MultiProtocolForwarding.Step configuration (sample.routed configuration) .forwardFilter
      (sample.filtered configuration) := .forwardFilter rfl outputVisible accepted
  have plain : MultiProtocolForwarding.Step configuration (sample.filtered configuration) .forwardWithoutEncap
      (sample.egressReady configuration) := .forwardWithoutEncap rfl outputVisible noIPsec
  refine ⟨.stepL received (.stepL routed (.stepL filtered (.stepL plain .refl))), egress, rfl, ?_⟩
  simp [RoutedMACsecCase.egressReady, RoutedMACsecCase.filtered, RoutedMACsecCase.routed,
    RoutedMACsecCase.entry, Config.forwardedFrame, mode]

end TDN.Requirements.Msc
