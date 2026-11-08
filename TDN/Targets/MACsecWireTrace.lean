import TDN.Targets.PhysicalBoundaryCoverage

namespace TDN.Targets.Complete
open Compliance MultiProtocolExecution LayeredFrame

structure RoutedMACsecCase where
  entryIface : Nat
  route : Execution.Route
  header : PacketPolicy.Packet
  application : List UInt8
  originDomain : Nat
  mac : MACIface
  peerIface : Nat

def RoutedMACsecCase.entry (sample : RoutedMACsecCase) : MultiProtocolExecution.State :=
  { iface := sample.entryIface
    datapathStage := .received
    enteredIface := sample.entryIface
    frame := { payload := LinkAdmission.payloadCode sample.application
               originDomain := sample.originDomain
               body := .datagram sample.header }
    authenticated := []
    tracking := "new" }

def RoutedMACsecCase.entered (sample : RoutedMACsecCase) : MultiProtocolExecution.State :=
  { sample.entry with initialEntry := false, datapathStage := .ingress }

def RoutedMACsecCase.routed (sample : RoutedMACsecCase) (configuration : Config) :
    MultiProtocolExecution.State :=
  { sample.entered with
    initialEntry := false
    iface := sample.route.egress
    datapathStage := .routed
    frame := configuration.forwardedFrame sample.entry.frame }

def RoutedMACsecCase.forwardedHeader (sample : RoutedMACsecCase) : PacketPolicy.Packet :=
  { sample.header with hopLimit := sample.header.hopLimit - 1 }

def RoutedMACsecCase.filtered (sample : RoutedMACsecCase) (configuration : Config) :
    MultiProtocolExecution.State :=
  { sample.routed configuration with initialEntry := false, datapathStage := .filtered }

def RoutedMACsecCase.ready (sample : RoutedMACsecCase) (configuration : Config) :
    MultiProtocolExecution.State :=
  { sample.filtered configuration with initialEntry := false, datapathStage := .ready }

def RoutedMACsecCase.RoutingChecks (sample : RoutedMACsecCase) (configuration : Config) : Prop :=
  sample.route.ingress = sample.entryIface ∧ sample.route.egress = sample.mac.logicalIface ∧
    Execution.SelectedRoute configuration.ip.routes sample.route sample.header ∧
    1 < sample.header.hopLimit ∧ sample.header.hopLimit ≤ 255 ∧
    Execution.accepts (configuration.ip.forwardRules sample.route.egress)
      (configuration.ip.forwardFallback sample.route.egress)
      (policyHeader configuration (sample.routed configuration) sample.forwardedHeader) ∧
    Execution.selectedAssociations (configuration.ip.outbound sample.route.egress)
      sample.forwardedHeader = []

instance (sample : RoutedMACsecCase) (configuration : Config) :
    Decidable (sample.RoutingChecks configuration) := by
  unfold RoutedMACsecCase.RoutingChecks Execution.accepts Execution.SelectedRoute Execution.Route.matches
  infer_instance

lemma routed_MACsec_case_reaches_logical_output (sample : RoutedMACsecCase)
    (configuration : Config) (processing : HeaderProcessing)
    (mode : configuration.headerProcessing = some processing)
    (checks : sample.RoutingChecks configuration) :
    (lts configuration).MTr sample.entry [.receive, .route, .forwardFilter, .passWithoutTransform]
      (sample.ready configuration) ∧
    (sample.ready configuration).iface = sample.mac.logicalIface ∧
    (sample.ready configuration).datapathStage = .ready ∧
    (sample.ready configuration).frame.payload = LinkAdmission.payloadCode sample.application := by
  obtain ⟨ingress, egress, selected, _, _, accepted, noIPsec⟩ := checks
  have initialVisible : configuration.visibleHeader sample.entry.frame = some sample.header := by
    simp [RoutedMACsecCase.entry, Config.visibleHeader, mode, Frame.visibleHeader, Body.visibleHeader]
  have outputVisible : configuration.visibleHeader (sample.routed configuration).frame =
      some sample.forwardedHeader := by
    simp [RoutedMACsecCase.routed, RoutedMACsecCase.entry, RoutedMACsecCase.forwardedHeader,
      Config.visibleHeader, Config.forwardedFrame, mode, Frame.forwarded, Frame.visibleHeader,
      Body.visibleHeader]
  have received : MultiProtocolExecution.Step configuration sample.entry .receive sample.entered :=
    .receive rfl initialVisible "new"
  have routed : MultiProtocolExecution.Step configuration sample.entered .route (sample.routed configuration) :=
    .route sample.route rfl initialVisible selected ingress
  have filtered : MultiProtocolExecution.Step configuration (sample.routed configuration) .forwardFilter
      (sample.filtered configuration) := .forwardFilter rfl outputVisible accepted
  have plain : MultiProtocolExecution.Step configuration (sample.filtered configuration) .passWithoutTransform
      (sample.ready configuration) := .passWithoutTransform rfl outputVisible noIPsec
  refine ⟨.stepL received (.stepL routed (.stepL filtered (.stepL plain .refl))), egress, rfl, ?_⟩
  simp [RoutedMACsecCase.ready, RoutedMACsecCase.filtered, RoutedMACsecCase.routed,
    RoutedMACsecCase.entry, Config.forwardedFrame, mode]

end TDN.Targets.Complete
