import TDN.Deployments.MtuSizing_Application
import TDN.Requirements.NonVacuousReachabilityCheck

namespace TDN.Deployments.MtuSizing_Records
open Compliance Requirements OuterToGray_DeviceModel MultiProtocolForwarding PacketSource LayeredFrame

deriving instance DecidableEq for LayeredFrame.Body
deriving instance DecidableEq for PacketSource.Fragment
deriving instance DecidableEq for PacketSource.Datagram
deriving instance DecidableEq for PacketSource.Outcome

structure SizingPath where
  flow : SourceFlow
  route : DataPlaneForwarding.FibRoute
  policy : DataPlaneForwarding.IpsecPolicy
  association : DataPlaneForwarding.InstalledSA
  routeOuterPacket : DataPlaneForwarding.FibRoute
  nextIface : Nat


def SizingPath.template (sample : SizingPath) : PacketPolicy.Packet :=
  { source := sample.flow.source, destination := sample.flow.destination, protocol := "tcp",
    ingress := "", egress := "", sourcePort := 53000, destinationPort := 8080,
    ipv4HeaderWords := 5, matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "new",
    payloadBytes := some sample.flow.request.application, hopLimit := 64 }


def SizingPath.datagram (sample : SizingPath) : Datagram :=
  (encodeSourceDatagram sample.flow.request sample.template sample.flow.request.application).asWhole


def SizingPath.header (sample : SizingPath) : PacketPolicy.Packet :=
  sourceHeader sample.flow.request sample.template sample.flow.request.application


def SizingPath.start (sample : SizingPath) : MultiProtocolForwarding.State :=
  { initialEntry := true
    iface := sample.flow.iface, datapathStage := .received, enteredIface := sample.flow.iface
    frame := {
      payload := PayloadCode sample.datagram.application, originDomain := sample.flow.domain
      body := sample.datagram.body }
    authenticated := [], tracking := "new" }


def SizingPath.entered (sample : SizingPath) : MultiProtocolForwarding.State :=
  { sample.start with
    initialEntry := false, datapathStage := .ingress, enteredIface := sample.flow.iface,
    authenticated := [], tracking := "new" }


def SizingPath.routed (sample : SizingPath) (records : Records) : MultiProtocolForwarding.State :=
  { sample.entered with
    initialEntry := false, iface := sample.route.egress, datapathStage := .routed,
    frame := records.configuration.forwardedFrame sample.entered.frame }


def SizingPath.filtered (sample : SizingPath) (records : Records) : MultiProtocolForwarding.State :=
  { sample.routed records with
    initialEntry := false, datapathStage := .filtered }


def SizingPath.encrypted (sample : SizingPath) (records : Records) : MultiProtocolForwarding.State :=
  { sample.filtered records with
    initialEntry := false, datapathStage := .encapsulated,
    frame := records.configuration.ipsecFrame sample.route.egress (sample.filtered records).frame
      (sample.policy.seal sample.association) }


def SizingPath.egressReady (sample : SizingPath) (records : Records) : MultiProtocolForwarding.State :=
  { sample.encrypted records with
    initialEntry := false, iface := sample.routeOuterPacket.egress, datapathStage := .egressReady }


def SizingPath.wired (sample : SizingPath) (records : Records) : MultiProtocolForwarding.State :=
  { sample.egressReady records with
    initialEntry := false, iface := sample.nextIface, datapathStage := .received,
    authenticated := [] }


def SizingPath.outerHeader (sample : SizingPath) : PacketPolicy.Packet :=
  { LayeredFrame.outerHeader sample.policy.sender sample.policy.receiver "esp" 0 0 with hopLimit := 64 }


def SizingPath.Checks (sample : SizingPath) (records : Records)
    (installations : List PublicSARecord) : Prop :=
  sample.route.ingress = sample.flow.iface ∧
  DataPlaneForwarding.SelectedFibRoute records.routes sample.route sample.header ∧
  DataPlaneForwarding.accepts (records.configuration.ip.forwardRules sample.route.egress)
    (records.configuration.ip.forwardFallback sample.route.egress)
    (policyHeader records.configuration (sample.routed records) { sample.header with hopLimit := 63 }) ∧
  sample.policy ∈ DataPlaneForwarding.lookupSpdPolicies (records.configuration.ip.egressPolicies sample.route.egress)
    { sample.header with hopLimit := 63 } ∧
  sample.association ∈ directionalStates installations (records.configuration.ip.owner sample.route.egress) .outbound ∧
  DataPlaneForwarding.saMatchesPolicy sample.association sample.policy ∧
  sample.routeOuterPacket.ingress = sample.route.egress ∧
  DataPlaneForwarding.SelectedFibRoute records.routes sample.routeOuterPacket sample.outerHeader ∧
  (sample.routeOuterPacket.egress, sample.nextIface) ∈ records.links

instance (sample : SizingPath) (records : Records) (installations : List PublicSARecord) :
    Decidable (sample.Checks records installations) := by
  unfold SizingPath.Checks DataPlaneForwarding.accepts
  infer_instance


theorem SizingPath.encrypted_header (sample : SizingPath) (records : Records)
    (bound : DataPlaneForwarding.saMatchesPolicy sample.association sample.policy) :
    records.configuration.visibleHeader (sample.encrypted records).frame = some sample.outerHeader := by
  simp [SizingPath.encrypted, SizingPath.outerHeader, Records.configuration,
    Config.visibleHeader, Config.ipsecFrame, Frame.visibleHeader, Frame.pushHeader,
    Body.visibleHeader, DataPlaneForwarding.IpsecPolicy.seal, bound.2.1, bound.2.2.1]


theorem non_link_native_step_is_accepted {S A : Type} (binding : DeviceExecutionBinding S A)
    (before after : MultiProtocolForwarding.State) (action : MultiProtocolForwarding.Action)
    (step : MultiProtocolForwarding.Step binding.configuration before action after)
    (ordinary : action = .receive ∨ action = .route ∨ action = .forwardFilter ∨ action = .encryptIPsec)
    (header : binding.configuration.HeaderStepAdmitted before action) :
    binding.AcceptedStep before action after := by
  refine ⟨step, ?_, ?_, ?_, header, ?_⟩
  all_goals rcases ordinary with rfl | rfl | rfl | rfl <;> simp [Config.LinkStepAdmitted]


theorem SizingPath.accepted_prefix {Key : Type} (sample : SizingPath) (records : Records)
    (installations : List PublicSARecord) (entries : List SourceEntry) (roles : List SizingRole)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (epoch : String)
    (codec : IPsecFrameEncoding.Codec Key) (material : String → IPsecKeyMaterial)
    (checked : sample.Checks records installations) :
    (Cslib.LTS.mk (prototype records installations entries roles policies epoch codec material).AcceptedStep).MTr
      sample.start [.receive, .route, .forwardFilter, .encryptIPsec, .route] (sample.egressReady records) := by
  obtain ⟨entry, selected, allowed, policy, installed, bound, outerEntry, outerSelected, linked⟩ := checked
  let binding := prototype records installations entries roles policies epoch codec material
  have receive : binding.AcceptedStep sample.start .receive sample.entered := by
    apply non_link_native_step_is_accepted binding _ _ _ (.receive rfl rfl "new") (Or.inl rfl)
    simp [Config.HeaderStepAdmitted]
  have route : binding.AcceptedStep sample.entered .route (sample.routed records) := by
    apply non_link_native_step_is_accepted binding _ _ _ (.route sample.route rfl rfl selected entry)
      (Or.inr (Or.inl rfl))
    intro _ _ header visible _
    have same : header = sample.header := by
      change some sample.header = some header at visible
      exact Option.some.inj visible.symm
    subst header
    change 1 < 64
    native_decide
  have filter : binding.AcceptedStep (sample.routed records) .forwardFilter (sample.filtered records) := by
    apply non_link_native_step_is_accepted binding _ _ _ (.forwardFilter (s := sample.routed records) (header := { sample.header with hopLimit := 63 }) rfl rfl allowed)
      (Or.inr (Or.inr (Or.inl rfl)))
    simp [Config.HeaderStepAdmitted]
  have encrypt : binding.AcceptedStep (sample.filtered records) .encryptIPsec (sample.encrypted records) := by
    apply non_link_native_step_is_accepted binding _ _ _
      (.encryptIPsec (s := sample.filtered records) (header := { sample.header with hopLimit := 63 })
        sample.policy sample.association rfl rfl policy installed bound)
      (Or.inr (Or.inr (Or.inr rfl)))
    simp [Config.HeaderStepAdmitted]
  have outer : binding.AcceptedStep (sample.encrypted records) .route (sample.egressReady records) := by
    apply non_link_native_step_is_accepted binding _ _ _
      (.routeOuterPacket sample.routeOuterPacket rfl (sample.encrypted_header records bound) outerSelected outerEntry)
      (Or.inr (Or.inl rfl))
    intro _ impossible
    cases impossible
  exact .stepL receive (.stepL route (.stepL filter (.stepL encrypt (.stepL outer .refl))))


def SizingPath.SourceChecks (sample : SizingPath) (records : Records) (entries : List SourceEntry)
    (roles : List SizingRole) (networks : List RedNetworkIdentity) : Prop :=
  (∃ network ∈ networks, sourceEntry entries sample.flow.iface = some network.id ∧
    sourceOrigin entries records.componentName sample.flow.domain = .red network.id) ∧
  processSource (sourceMtu roles sample.flow.iface) sample.flow.request = .emitted [sample.datagram]

instance (sample : SizingPath) (records : Records) (entries : List SourceEntry)
    (roles : List SizingRole) (networks : List RedNetworkIdentity) :
    Decidable (sample.SourceChecks records entries roles networks) := by
  unfold SizingPath.SourceChecks
  infer_instance


def openLinkPolicy : LinkAdmission.IfacePolicy :=
  ⟨⟨[], .allow⟩, ⟨[], .allow⟩⟩


theorem SizingPath.source_to_required_wire {Key : Type} (sample : SizingPath) (records : Records)
    (installations : List PublicSARecord) (entries : List SourceEntry) (roles : List SizingRole)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (epoch : String)
    (codec : IPsecFrameEncoding.Codec Key) (material : String → IPsecKeyMaterial)
    (networks : List RedNetworkIdentity) (attachments : List RedNetworkAttachment)
    (services : List ServiceRegistration) (base : Deployment)
    (covered : (StandardDataPlaneBridge.model
      (prototype records installations entries roles policies epoch codec material) records.inventory.ifaces
      (completeDeployment records installations policies codec networks attachments services base) {}).CoversDeployment
      (completeDeployment records installations policies codec networks attachments services base))
    (sizeChecked : SizeRecordChecks records installations roles) (mtuChecked : RoleMtuChecks roles)
    (checked : sample.Checks records installations)
    (sourceChecked : sample.SourceChecks records entries roles networks)
    (required : requiredSizing roles sample.routeOuterPacket.egress = true)
    (notBridge : ∀ edge ∈ records.bridges, edge.1 ≠ sample.routeOuterPacket.egress ∧ edge.2 ≠ sample.routeOuterPacket.egress)
    (nextPolicy : (∀ edge ∈ records.bridges, edge.1 ≠ sample.nextIface ∧ edge.2 ≠ sample.nextIface) ∨
      LinkAdmission.lookup policies sample.nextIface = some openLinkPolicy) :
    ∃ start actions before action after,
      (StandardDataPlaneBridge.model (prototype records installations entries roles policies epoch codec material)
        records.inventory.ifaces (completeDeployment records installations policies codec networks attachments services base) {}).initial start ∧
      (StandardDataPlaneBridge.model (prototype records installations entries roles policies epoch codec material)
        records.inventory.ifaces (completeDeployment records installations policies codec networks attachments services base) {}).system.MTr start actions before ∧
      (StandardDataPlaneBridge.model (prototype records installations entries roles policies epoch codec material)
        records.inventory.ifaces (completeDeployment records installations policies codec networks attachments services base) {}).system.Tr before action after ∧
      action.operation = .linkTransmit ∧ before.native = sample.egressReady records ∧
      requiredSizing roles before.native.iface = true ∧ before.native.frame.payload ≠ 0 := by
  let binding := prototype records installations entries roles policies epoch codec material
  let d := completeDeployment records installations policies codec networks attachments services base
  let model := StandardDataPlaneBridge.model binding records.inventory.ifaces d {}
  obtain ⟨network, networkMember, sourceEntry, origin⟩ := sourceChecked.1
  have allowed : binding.SourceRequestAllowed d sample.flow.request := by
    refine ⟨Or.inl ⟨sample.template, rfl⟩, rfl, ?_⟩
    change match sourceOrigin entries records.componentName sample.flow.domain with
      | .red network => _
      | .management component => _
      | .control component protocol => _
    rw [origin]
    exact ⟨sourceEntry, network, networkMember, rfl⟩
  have sourceState : binding.SourceState sample.flow.request sample.datagram = sample.start := by
    change (DeviceExecutionBinding.SourceState binding sample.flow.request sample.datagram) = _
    unfold DeviceExecutionBinding.SourceState
    have redOrigin : binding.origin sample.flow.request.originDomain = .red network.id := origin
    rw [redOrigin]
    rfl

  obtain ⟨_, start, initialized, sameStart, _⟩ := covered.2.2.2.1.2.1
    sample.flow.request [sample.datagram] sample.datagram allowed sourceChecked.2 (by simp)
  have nativeRun := sample.accepted_prefix records installations entries roles policies epoch codec material checked
  obtain ⟨actions, before, run, sameBefore⟩ := model.lift_accepted_native_run covered.2.2.1 nativeRun start
    (sameStart.trans sourceState)
  have budgets := size_checks_from_captured_records records installations roles policies codec sizeChecked
  have emissions : EmissionConditions binding.sourceProcessing :=
    source_processing_emission_conditions (sourceMtu roles) (source_mtu_minimum roles mtuChecked)
  have description := StandardDataPlaneBridge.standard_reachable_link_frame_describes binding records.inventory.ifaces d {}
    codec (requiredSizing roles) (sourceMtu roles) plaintextLimit authenticationLimit budgets.1 emissions
    ⟨fun _ => 64, fun _ => 64⟩ rfl
    (by intro iface; exact ⟨by change 64 ≤ 255; native_decide, by change 64 ≤ 255; native_decide⟩) initialized run
  change (IPsecFrameEncoding.linkEncoding codec before.native.frame).Describes before.native.frame at description
  change before.native = sample.egressReady records at sameBefore
  rw [sameBefore] at description
  have noBefore : ¬ binding.configuration.LinkPath (sample.egressReady records).iface := by
    rintro (⟨mac, impossible, _⟩ | ⟨next, linked | linked⟩ | ⟨carrier, impossible, _⟩)
    · cases impossible
    · exact (notBridge (_,next) linked).1 rfl
    · exact (notBridge (next,_) linked).2 rfl
    · cases impossible
  have wire : binding.AcceptedStep (sample.egressReady records) .linkTransmit (sample.wired records) := by
    refine ⟨.linkTransmit sample.nextIface rfl checked.2.2.2.2.2.2.2.2, ?_, ?_, ?_, ?_, ?_⟩
    · intro impossible; cases impossible
    · intro impossible; cases impossible
    · refine ⟨?_, (by rintro (impossible | impossible) <;> cases impossible), (by intro impossible; cases impossible),
        (by intro impossible; cases impossible)⟩
      intro _
      refine ⟨fun path => False.elim (noBefore path), ?_, fun _ => rfl⟩
      intro path
      rcases nextPolicy with unlinked | openPolicy
      · rcases path with ⟨mac, impossible, _⟩ | ⟨next, forward | backward⟩ | ⟨carrier, impossible, _⟩
        · cases impossible
        · exact False.elim ((unlinked (sample.nextIface,next) forward).1 rfl)
        · exact False.elim ((unlinked (next,sample.nextIface) backward).2 rfl)
        · cases impossible
      · refine ⟨IPsecFrameEncoding.linkEncoding codec (sample.egressReady records).frame, rfl, description,
          openLinkPolicy, openPolicy, rfl⟩
    · intro impossible; cases impossible
    · intro impossible; cases impossible
  obtain ⟨action, after, tr, operation, _⟩ := covered.2.2.1 before .linkTransmit (sample.wired records)
    (by
      change binding.AcceptedStep before.native .linkTransmit (sample.wired records)
      rw [sameBefore]
      exact wire)
  refine ⟨start, actions, before, action, after, initialized, run, tr, ?_, sameBefore, ?_, ?_⟩
  · exact Option.some.inj operation
  · rw [sameBefore]
    exact required
  · rw [sameBefore]
    change PayloadCode sample.flow.request.application ≠ 0
    change PayloadCode ([71, 69, 84, 32, 47, 32, 72, 84, 84, 80] : List UInt8) ≠ 0
    native_decide
end TDN.Deployments.MtuSizing_Records

