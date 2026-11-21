import TDN.Deployments.MtuSizing_SourceToFirstLink
import TDN.Deployments.NestedProtection_AuthenticationRecords
import TDN.Requirements.RedDeliveryTrace
import TDN.Requirements.RedNetworkLabelAssignment
import TDN.Requirements.SecurityLevelConnectivity

namespace TDN.Deployments.SecurityLevelConnectivity
open Compliance Requirements.Msc Requirements.StandardDataPlaneBridge MtuSizing_Records NestedProtection

structure DeliveryPlan (Move : Type) where
  path : SizingPath
  moves : List Move
  recipient : Nat

def deploymentWithPeerRecords (d : Deployment) (assigned : List RedLabelAssignment)
    (authentication : List PublicAuthenticationBinding) (innerOuterUses : List (String × String)) : Deployment :=
  { deploymentWithRedLabels d assigned with
    certificateAuthenticated := fun component => authentication.any fun row =>
      row.device == component && row.certificateAuthenticated
    preSharedCAKAuthenticated := fun component => authentication.any fun row =>
      row.device == component && row.preSharedCAKAuthenticated
    keyManagementCA := fun component authority => ∃ row ∈ authentication,
      row.device = component ∧ row.authorityId = authority
    innerUsesOuter := fun inner outer => (inner, outer) ∈ innerOuterUses }

structure InstalledChild where
  device : String
  peer : String
  ike : String
  child : String
  observation : String
  capture : String
  deriving DecidableEq

def observedInnerPairs (devices : List Device) (pairs : List (String × String)) :=
  (pairs.filter fun pair => devices.any fun d =>
    d.layer == some .inner && (d.id == pair.1 || d.id == pair.2)).eraseDups

def connectedContext {S A : Type} (base : ComplianceContext S A) (d : Deployment)
    (forwarding : ForwardingModel S A) (solution : String) (externalSolutions : List String)
    (authenticated installed demands : List (String × String)) : ComplianceContext S A :=
  { base with
    solution := solution
    deployment := d
    model := forwarding
    conformingMSC := fun name => name ∈ externalSolutions
    authenticatedInnerPairs := authenticated
    establishedInnerTunnels := installed
    establishedTunnel := fun first last => (first, last) ∈ installed
    requiredConnectivity := demands
    includedUnclassified := unclassifiedNetworkIds d.networks }

theorem residual_context_exists {S A : Type} (d : Deployment) (forwarding : ForwardingModel S A)
    (datagram : PacketSource.EncodedDatagram) (flow : Flow) : Nonempty (ComplianceContext S A) := by
  let externalFacts : ExternalFacts := ⟨fun _ _ => False⟩
  let runtime : TimeRuntimeCorrespondence := ⟨fun _ => False, fun _ => False, fun _ => False,
    fun _ => False, fun _ => False, fun _ => False, fun _ => False⟩
  let emptyTime : TimeObservationInventory := ⟨[], [], [], [], [], [], runtime⟩
  let technical : TechnicalDutyRecords := by
    constructor <;> first | exact externalFacts | exact emptyTime | exact default |
      exact AuthenticationPrimitive.mk (fun _ => false) (fun _ => false)
  let level : SecurityLevel := ⟨"", ∅, ∅, ∅⟩
  let topology : GrayTopology := by
    constructor <;> first | exact level | exact fun _ => level | exact fun _ => False |
      exact fun _ _ => False
  let tls : EapTlsAuthProvider := ⟨fun _ => none, fun _ => none, fun _ _ => false, fun _ => ""⟩
  let sizes : WireSizeModel S :=
    ⟨fun _ => [], fun _ _ _ => [], fun _ _ => none, fun _ => datagram, fun _ => 0, fun _ => 0⟩
  constructor
  constructor <;> first
    | exact d
    | exact forwarding
    | exact technical
    | exact tls
    | exact sizes
    | exact topology
    | exact PayloadDomain.mk [] 0
    | exact fun _ _ _ _ => flow
    | exact fun _ _ => False
    | exact fun _ => False
    | exact default

theorem recorded_red_delivery_has_trace {S A : Type} (prototype : DeviceExecutionBinding S A)
    (ifaces : List Nat) (d : Deployment) (path : SizingPath) (name : Nat → String) (recipient : Nat)
    (covered : (model prototype ifaces d {}).CoversDeployment d)
    (origin : ∀ domain, prototype.origin domain = .red (name domain))
    (destination : prototype.domainName recipient = name recipient)
    (source : prototype.sourceEntry path.flow.iface = some (name path.flow.domain))
    (network : ∃ n ∈ d.networks, n.id = name path.flow.domain)
    (emission : prototype.sourceProcessing.process path.flow.request = .emitted [path.datagram])
    (replay : ∀ start : State ifaces, (model prototype ifaces d {}).initial start →
      start.deviceState = path.start → ∃ actions last,
        (model prototype ifaces d {}).system.MTr start actions last ∧
        last.deviceState.datapathStage = .delivered ∧
        prototype.configuration.ip.ifaceSecurityDomain last.deviceState.iface = some recipient) :
    ∃ start actions finish payload, (model prototype ifaces d {}).initial start ∧
      (model prototype ifaces d {}).ForwardsAlongTrace start actions finish ∧
      Before ((model prototype ifaces d {}).TraceEvents actions)
        (.inject payload (name path.flow.domain)) (.deliver payload (name recipient) []) := by
  have allowed : (binding prototype ifaces).SourceRequestAllowed d path.flow.request := by
    refine ⟨Or.inl ⟨path.template, rfl⟩, rfl, ?_⟩
    simpa only [binding, DeviceExecutionBinding.withProjection, SourceFlow.request, origin]
      using And.intro source network
  obtain ⟨_, start, initialized, state, _⟩ := covered.2.2.2.1.2.1 path.flow.request
    [path.datagram] path.datagram allowed emission (by simp)
  have same : start.deviceState = path.start := by
    change start.deviceState = (binding prototype ifaces).SourceState path.flow.request path.datagram at state
    rw [state]
    simp only [DeviceExecutionBinding.SourceState, binding, DeviceExecutionBinding.withProjection,
      SourceFlow.request, origin, SizingPath.start]
    rfl
  obtain ⟨actions, last, run, done, target⟩ := replay start initialized same
  refine ⟨start, actions, last, ⟨start.deviceState.frame.originDomain, start.deviceState.frame.payload⟩,
    initialized, run, ?_⟩
  rw [← destination]
  refine injection_precedes_delivered_endpoint prototype ifaces d {} run ?_ ?_ done target
  · rw [packet_binding_source_events]
    change (packetBinding (binding prototype ifaces)).SourceEvents start.deviceState = _
    rw [same]
    simp [DeviceExecutionBinding.SourceEvents, packetBinding, binding, DeviceExecutionBinding.withProjection,
      SizingPath.start, origin, source, SizingPath.datagram, PacketSource.encodeSourceDatagram,
      PacketSource.EncodedDatagram.asWhole, DeviceExecutionBinding.LayerIds]
  · rw [same]
    rfl

end TDN.Deployments.SecurityLevelConnectivity
