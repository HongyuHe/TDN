import TDN.Deployments.MtuSizing_Path

namespace TDN.Deployments.MtuSizing_Records
open Compliance Requirements OuterToGray_DeviceModel MultiProtocolForwarding LayeredFrame

structure SizingMove where
  operation : MultiProtocolForwarding.Action
  header : PacketPolicy.Packet
  next : Nat
  route : DataPlaneForwarding.FibRoute
  policy : DataPlaneForwarding.IpsecPolicy
  association : DataPlaneForwarding.InstalledSA


def SizingMove.after (move : SizingMove) (records : Records) (before : MultiProtocolForwarding.State) :
    MultiProtocolForwarding.State :=
  match move.operation with
  | .receive => { before with
      initialEntry := false, datapathStage := .ingress,
      enteredIface := before.iface, authenticated := [], tracking := "new" }
  | .route => if before.datapathStage = .encapsulated then
      { before with
      initialEntry := false, iface := move.route.egress, datapathStage := .egressReady }
    else { before with
      initialEntry := false, iface := move.route.egress, datapathStage := .routed,
      frame := records.configuration.forwardedFrame before.frame }
  | .forwardFilter => { before with
      initialEntry := false, datapathStage := .filtered }
  | .encryptIPsec => { before with
      initialEntry := false, datapathStage := .encapsulated,
      frame := records.configuration.ipsecFrame before.iface before.frame (move.policy.seal move.association) }
  | .forwardWithoutEncap => { before with
      initialEntry := false, datapathStage := .egressReady }
  | .linkTransmit => { before with
      initialEntry := false, iface := move.next, datapathStage := .received, authenticated := [] }
  | .bridge => { before with
      initialEntry := false, iface := move.next, datapathStage := .egressReady }
  | _ => before


def SizingMove.Check (move : SizingMove) (records : Records) (installations : List PublicSARecord)
    (before : MultiProtocolForwarding.State) : Prop :=
  match move.operation with
  | .receive => before.datapathStage = .received ∧ records.configuration.visibleHeader before.frame = some move.header
  | .route => records.configuration.visibleHeader before.frame = some move.header ∧
      DataPlaneForwarding.SelectedFibRoute records.routes move.route move.header ∧ move.route.ingress = before.iface ∧
      (before.datapathStage = .encapsulated ∨ before.datapathStage = .ingress ∧ 1 < move.header.hopLimit)
  | .forwardFilter => before.datapathStage = .routed ∧ records.configuration.visibleHeader before.frame = some move.header ∧
      DataPlaneForwarding.accepts (records.configuration.ip.forwardRules before.iface)
        (records.configuration.ip.forwardFallback before.iface)
        (policyHeader { records.configuration with networkBytes := fun body _ => IPsecFrameEncoding.networkLength body }
          before move.header)
  | .encryptIPsec => before.datapathStage = .filtered ∧ records.configuration.visibleHeader before.frame = some move.header ∧
      move.policy ∈ DataPlaneForwarding.lookupSpdPolicies (records.configuration.ip.egressPolicies before.iface) move.header ∧
      move.association ∈ directionalStates installations (records.configuration.ip.owner before.iface) .outbound ∧
      DataPlaneForwarding.saMatchesPolicy move.association move.policy
  | .forwardWithoutEncap => before.datapathStage = .filtered ∧ records.configuration.visibleHeader before.frame = some move.header ∧
      DataPlaneForwarding.lookupSpdPolicies (records.configuration.ip.egressPolicies before.iface) move.header = []
  | .linkTransmit => before.datapathStage = .egressReady ∧ (before.iface, move.next) ∈ records.links
  | .bridge => before.datapathStage = .received ∧ (before.iface, move.next) ∈ records.bridges
  | _ => False

instance (move : SizingMove) (records : Records) (installations : List PublicSARecord)
    (before : MultiProtocolForwarding.State) : Decidable (move.Check records installations before) := by
  unfold SizingMove.Check DataPlaneForwarding.accepts
  cases move.operation <;> infer_instance


def SizingOpenIface (records : Records) (policies : List (Nat × LinkAdmission.IfacePolicy)) (iface : Nat) : Prop :=
  (∀ edge ∈ records.bridges, edge.1 ≠ iface ∧ edge.2 ≠ iface) ∨
    LinkAdmission.lookup policies iface = some openLinkPolicy

instance (records : Records) (policies : List (Nat × LinkAdmission.IfacePolicy)) (iface : Nat) :
    Decidable (SizingOpenIface records policies iface) := by
  unfold SizingOpenIface
  infer_instance


def SizingMove.LinkCheck (move : SizingMove) (records : Records)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (before : MultiProtocolForwarding.State) : Prop :=
  move.operation = .linkTransmit ∨ move.operation = .bridge →
    SizingOpenIface records policies before.iface ∧ SizingOpenIface records policies (move.after records before).iface

instance (move : SizingMove) (records : Records) (policies : List (Nat × LinkAdmission.IfacePolicy))
    (before : MultiProtocolForwarding.State) : Decidable (move.LinkCheck records policies before) := by
  unfold SizingMove.LinkCheck
  infer_instance


theorem SizingMove.step {Key : Type} (move : SizingMove) (records : Records)
    (installations : List PublicSARecord) (policies : List (Nat × LinkAdmission.IfacePolicy))
    (codec : IPsecFrameEncoding.Codec Key) (before : MultiProtocolForwarding.State)
    (checked : move.Check records installations before) :
    MultiProtocolForwarding.Step (completeConfiguration records installations policies codec)
      before move.operation (move.after records before) := by
  cases operation : move.operation <;> simp only [SizingMove.Check, operation] at checked
  all_goals simp only [SizingMove.after, operation]
  case receive => exact .receive (c := completeConfiguration records installations policies codec) checked.1 checked.2 "new"
  case route =>
    rcases checked with ⟨visible, selected, entry, datapathStage | ⟨datapathStage, hops⟩⟩
    · simpa only [datapathStage, ite_true] using
        (MultiProtocolForwarding.Step.routeOuterPacket (c := completeConfiguration records installations policies codec)
          move.route datapathStage visible selected entry)
    · simpa [datapathStage, Config.forwardedFrame, completeConfiguration, directionalConfiguration] using
        (MultiProtocolForwarding.Step.route (c := completeConfiguration records installations policies codec)
          move.route datapathStage visible selected entry)
  case forwardFilter => exact .forwardFilter checked.1 checked.2.1 checked.2.2
  case encryptIPsec =>
    exact .encryptIPsec move.policy move.association checked.1 checked.2.1
      checked.2.2.1 checked.2.2.2.1 checked.2.2.2.2
  case forwardWithoutEncap => exact .forwardWithoutEncap checked.1 checked.2.1 checked.2.2
  case linkTransmit => exact .linkTransmit move.next checked.1 checked.2
  case bridge => exact .bridge move.next checked.1 checked.2


theorem SizingMove.header_admitted {Key : Type} (move : SizingMove) (records : Records)
    (installations : List PublicSARecord) (policies : List (Nat × LinkAdmission.IfacePolicy))
    (codec : IPsecFrameEncoding.Codec Key) (before : MultiProtocolForwarding.State)
    (checked : move.Check records installations before) :
    (completeConfiguration records installations policies codec).HeaderStepAdmitted before move.operation := by
  intro operation datapathStage header visible mode
  have check := checked
  simp only [SizingMove.Check, operation] at check
  have same : header = move.header := Option.some.inj (visible.symm.trans check.1)
  rcases check.2.2.2 with encapsulated | ingress
  · rw [datapathStage] at encapsulated
    cases encapsulated
  · simpa only [same] using ingress.2


theorem sizing_open_iface_admits {Key : Type} (records : Records)
    (installations : List PublicSARecord) (policies : List (Nat × LinkAdmission.IfacePolicy))
    (codec : IPsecFrameEncoding.Codec Key) (iface : Nat) (frame : Frame) (outbound : Bool)
    (checked : SizingOpenIface records policies iface)
    (description : (IPsecFrameEncoding.linkEncoding codec frame).Describes frame)
    (path : (completeConfiguration records installations policies codec).LinkPath iface) :
    (completeConfiguration records installations policies codec).LinkAdmitted iface outbound frame := by
  rcases checked with unlinked | openPolicy
  · rcases path with ⟨mac, impossible, _⟩ | ⟨next, forward | backward⟩ | ⟨carrier, impossible, _⟩
    · cases impossible
    · exact False.elim ((unlinked (iface,next) forward).1 rfl)
    · exact False.elim ((unlinked (next,iface) backward).2 rfl)
    · cases impossible
  · refine ⟨IPsecFrameEncoding.linkEncoding codec frame, rfl, description, openLinkPolicy, openPolicy, ?_⟩
    cases outbound <;> rfl


theorem SizingMove.accepted {Key : Type} (move : SizingMove) (records : Records)
    (installations : List PublicSARecord) (entries : List SourceEntry) (roles : List SizingRole)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (epoch : String)
    (codec : IPsecFrameEncoding.Codec Key) (material : String → IPsecKeyMaterial)
    (before : MultiProtocolForwarding.State) (checked : move.Check records installations before)
    (linkChecked : move.LinkCheck records policies before)
    (description : (IPsecFrameEncoding.linkEncoding codec before.frame).Describes before.frame) :
    (prototype records installations entries roles policies epoch codec material).AcceptedStep
      before move.operation (move.after records before) := by
  refine ⟨move.step records installations policies codec before checked, ?_, ?_, ?_,
    move.header_admitted records installations policies codec before checked, ?_⟩
  · intro impossible
    simp only [SizingMove.Check, impossible] at checked
  · intro impossible
    simp only [SizingMove.Check, impossible] at checked
  · refine ⟨?_, ?_, ?_, ?_⟩
    · intro wire
      obtain ⟨first, last⟩ := linkChecked (Or.inl wire)
      have sameFrame : (move.after records before).frame = before.frame := by simp [SizingMove.after, wire]
      refine ⟨sizing_open_iface_admits records installations policies codec before.iface before.frame true first description,
        ?_, ?_⟩
      · rw [sameFrame]
        exact sizing_open_iface_admits records installations policies codec _ before.frame false last description
      · intro _
        change some (IPsecFrameEncoding.linkEncoding codec before.frame) =
          some (IPsecFrameEncoding.linkEncoding codec (move.after records before).frame)
        rw [sameFrame]
    · rintro (impossible | impossible) <;>
        simp only [SizingMove.Check, impossible] at checked
    · intro bridge
      obtain ⟨first, last⟩ := linkChecked (Or.inr bridge)
      have linked := checked
      simp only [SizingMove.Check, bridge] at linked
      have sameFrame : (move.after records before).frame = before.frame := by simp [SizingMove.after, bridge]
      refine ⟨?_, ?_⟩
      · exact sizing_open_iface_admits records installations policies codec before.iface before.frame false first description
          (Or.inr (Or.inl ⟨move.next, Or.inl (by exact linked.2)⟩))
      · rw [sameFrame]
        exact sizing_open_iface_admits records installations policies codec _ before.frame true last description
          (Or.inr (Or.inl ⟨before.iface, Or.inr (by change (before.iface, (move.after records before).iface) ∈ records.bridges; simpa only [SizingMove.after, bridge] using linked.2)⟩))
    · intro impossible
      simp only [SizingMove.Check, impossible] at checked
  · intro impossible
    simp only [SizingMove.Check, impossible] at checked


def sizingFinish (records : Records) (before : MultiProtocolForwarding.State) : List SizingMove → MultiProtocolForwarding.State
  | [] => before
  | move :: rest => sizingFinish records (move.after records before) rest


def sizingContinuationChecked (records : Records) (installations : List PublicSARecord)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (before : MultiProtocolForwarding.State) :
    List SizingMove → Prop
  | [] => True
  | move :: rest => move.Check records installations before ∧ move.LinkCheck records policies before ∧
      sizingContinuationChecked records installations policies (move.after records before) rest

instance (records : Records) (installations : List PublicSARecord)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (before : MultiProtocolForwarding.State)
    (moves : List SizingMove) : Decidable (sizingContinuationChecked records installations policies before moves) := by
  induction moves generalizing before with
  | nil => exact isTrue trivial
  | cons move rest ih =>
    change Decidable (move.Check records installations before ∧ move.LinkCheck records policies before ∧ _)
    have := ih (move.after records before)
    infer_instance


theorem sizing_continuation_reaches {Key : Type} (records : Records)
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
    (moves : List SizingMove) (start first : StandardDataPlaneBridge.State records.inventory.ifaces)
    (actions : List (StandardDataPlaneBridge.Action records.inventory.ifaces))
    (initialized : (StandardDataPlaneBridge.model
      (prototype records installations entries roles policies epoch codec material) records.inventory.ifaces
      (completeDeployment records installations policies codec networks attachments services base) {}).initial start)
    (run : (StandardDataPlaneBridge.model
      (prototype records installations entries roles policies epoch codec material) records.inventory.ifaces
      (completeDeployment records installations policies codec networks attachments services base) {}).system.MTr start actions first)
    (checked : sizingContinuationChecked records installations policies first.native moves) :
    ∃ steps last, (StandardDataPlaneBridge.model
      (prototype records installations entries roles policies epoch codec material) records.inventory.ifaces
      (completeDeployment records installations policies codec networks attachments services base) {}).system.MTr start steps last ∧
      last.native = sizingFinish records first.native moves ∧ last.native.frame.payload = first.native.frame.payload := by
  let binding := prototype records installations entries roles policies epoch codec material
  let d := completeDeployment records installations policies codec networks attachments services base
  let model := StandardDataPlaneBridge.model binding records.inventory.ifaces d {}
  have budgets := size_checks_from_captured_records records installations roles policies codec sizeChecked
  have emissions : PacketSource.EmissionConditions binding.sourceProcessing :=
    PacketSource.source_processing_emission_conditions (sourceMtu roles) (source_mtu_minimum roles mtuChecked)
  induction moves generalizing first actions with
  | nil => exact ⟨actions, first, run, rfl, rfl⟩
  | cons move rest ih =>
    obtain ⟨stepChecked, linkChecked, tailChecked⟩ := checked
    have description := StandardDataPlaneBridge.standard_reachable_link_frame_describes binding records.inventory.ifaces d {}
      codec (requiredSizing roles) (sourceMtu roles) plaintextLimit authenticationLimit budgets.1 emissions
      ⟨fun _ => 64, fun _ => 64⟩ rfl
      (by intro iface; exact ⟨by change 64 ≤ 255; decide, by change 64 ≤ 255; decide⟩) initialized run
    have accepted := move.accepted records installations entries roles policies epoch codec material
      first.native stepChecked linkChecked description
    obtain ⟨action, after, tr, operation, same⟩ := covered.2.2.1 first move.operation (move.after records first.native) accepted
    change after.native = move.after records first.native at same
    obtain ⟨steps, last, reached, final, payload⟩ := ih after (actions ++ [action])
      ((Cslib.LTS.MTr.append_iff model.system).mpr ⟨first, run, Cslib.LTS.MTr.stepL tr Cslib.LTS.MTr.refl⟩)
      (by simpa only [same] using tailChecked)
    refine ⟨steps, last, reached, ?_, ?_⟩
    · simpa only [sizingFinish, same] using final
    · rw [same] at payload
      exact payload.trans (MultiProtocolForwarding.step_preserves_payload
        (move.step records installations policies codec first.native stepChecked)).1


theorem sizing_continuation_transmits {Key : Type} (records : Records)
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
    (moves : List SizingMove) (transmission : SizingMove)
    (start first : StandardDataPlaneBridge.State records.inventory.ifaces)
    (actions : List (StandardDataPlaneBridge.Action records.inventory.ifaces))
    (initialized : (StandardDataPlaneBridge.model
      (prototype records installations entries roles policies epoch codec material) records.inventory.ifaces
      (completeDeployment records installations policies codec networks attachments services base) {}).initial start)
    (run : (StandardDataPlaneBridge.model
      (prototype records installations entries roles policies epoch codec material) records.inventory.ifaces
      (completeDeployment records installations policies codec networks attachments services base) {}).system.MTr start actions first)
    (checked : sizingContinuationChecked records installations policies first.native moves)
    (transmissionChecked : transmission.Check records installations (sizingFinish records first.native moves))
    (linkChecked : transmission.LinkCheck records policies (sizingFinish records first.native moves))
    (wire : transmission.operation = .linkTransmit)
    (endpoint : String)
    (required : ∃ setting ∈ settings roles,
      setting.interface = (sizingFinish records first.native moves).iface ∧
      setting.role = .grayFirewallOrEncryptionExternal ∧ records.ifaceName setting.interface = endpoint)
    (nonempty : first.native.frame.payload ≠ 0) :
    ∃ steps before action after,
      (StandardDataPlaneBridge.model (prototype records installations entries roles policies epoch codec material)
        records.inventory.ifaces (completeDeployment records installations policies codec networks attachments services base) {}).system.MTr start steps before ∧
      (StandardDataPlaneBridge.model (prototype records installations entries roles policies epoch codec material)
        records.inventory.ifaces (completeDeployment records installations policies codec networks attachments services base) {}).system.Tr before action after ∧
      action.operation = .linkTransmit ∧ before.native.frame.payload ≠ 0 ∧
      ∃ setting ∈ settings roles, setting.interface = before.native.iface ∧
        setting.role = .grayFirewallOrEncryptionExternal ∧ records.ifaceName setting.interface = endpoint := by
  let binding := prototype records installations entries roles policies epoch codec material
  let d := completeDeployment records installations policies codec networks attachments services base
  let model := StandardDataPlaneBridge.model binding records.inventory.ifaces d {}
  obtain ⟨steps, before, reached, same, payload⟩ := sizing_continuation_reaches records installations entries roles
    policies epoch codec material networks attachments services base covered sizeChecked mtuChecked moves
    start first actions initialized run checked
  have budgets := size_checks_from_captured_records records installations roles policies codec sizeChecked
  have emissions : PacketSource.EmissionConditions binding.sourceProcessing :=
    PacketSource.source_processing_emission_conditions (sourceMtu roles) (source_mtu_minimum roles mtuChecked)
  have description := StandardDataPlaneBridge.standard_reachable_link_frame_describes binding records.inventory.ifaces d {}
    codec (requiredSizing roles) (sourceMtu roles) plaintextLimit authenticationLimit budgets.1 emissions
    ⟨fun _ => 64, fun _ => 64⟩ rfl
    (by intro iface; exact ⟨by change 64 ≤ 255; decide, by change 64 ≤ 255; decide⟩) initialized reached
  have accepted := transmission.accepted records installations entries roles policies epoch codec material before.native
    (by rw [same]; exact transmissionChecked) (by rw [same]; exact linkChecked) description
  obtain ⟨action, after, tr, operation, _⟩ := covered.2.2.1 before transmission.operation
    (transmission.after records before.native) accepted
  refine ⟨steps, before, action, after, reached, tr, ?_, ?_, ?_⟩
  · exact (Option.some.inj operation).trans wire
  · rw [payload]
    exact nonempty
  · simpa only [same] using required

end TDN.Deployments.MtuSizing_Records
