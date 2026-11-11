import TDN.Requirements.MasterMscRequirementSpecs
import TDN.Models.MacsecExternalOutputProtection

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding LayeredFrame

structure MACsecExternalIfaceChecks {S A : Type} (d : Deployment)
    (binding : DeviceExecutionBinding S A) : Prop where
  output : MACsecOutputChecks binding.configuration
  externalIfaces : ∀ iface next, binding.configuration.physicalLink iface next →
    ∀ interface ∈ d.interfaces, interface.id = binding.ifaceName iface →
    ∀ device ∈ d.devices, device.id = interface.device → device.kind = .macsec →
    (device.layer = some .inner ∧ interface.zone = .gray ∨
      device.layer = some .outer ∧ interface.zone = .black) →
    ∃ mac ∈ binding.configuration.macIfaces, mac.physicalIface = iface ∧
      binding.componentName (binding.configuration.ip.owner mac.physicalIface) = device.id

lemma source_events_have_no_transmit {S A : Type} (binding : DeviceExecutionBinding S A)
    (before : S) (payload : PayloadId) (iface : String) (layers : List String)
    (trafficClass : TrafficClass) :
    NetworkEvent.transmit payload iface layers trafficClass ∉ binding.SourceEvents before := by
  dsimp only [DeviceExecutionBinding.SourceEvents]
  split
  · split
    · split <;> simp
    · simp
  · simp

lemma operation_transmit_is_wire {S A : Type} (binding : DeviceExecutionBinding S A)
    (before after : S) (action : MultiProtocolForwarding.Action)
    (payload : PayloadId) (iface : String) (layers : List String) (trafficClass : TrafficClass)
    (member : NetworkEvent.transmit payload iface layers trafficClass ∈
      binding.OperationEvents before action after) :
    action = .linkTransmit ∧ iface = binding.ifaceName (binding.state before).iface ∧
      layers = binding.LayerIds (binding.state before).frame.body := by
  cases action <;> simp only [DeviceExecutionBinding.OperationEvents] at member
  all_goals try contradiction
  all_goals try { split at member <;> simp_all }
  all_goals simp_all

lemma model_step_preserves_macsec_output {S A : Type} (model : ForwardingModel S A)
    (faithful : model.Faithful) (checks : MACsecOutputChecks model.native.configuration)
    {before after : S} {action : A} (step : model.system.Tr before action after)
    (safe : MACsecOutputProtected model.native.configuration (model.native.state before)) :
    MACsecOutputProtected model.native.configuration (model.native.state after) := by
  have record := faithful before action after step
  cases nativeAction : model.native.action action with
  | none =>
    rw [nativeAction] at record
    simpa only [record.1] using safe
  | some native =>
    rw [nativeAction] at record
    exact step_preserves_macsec_output_protection checks record.1.1 safe

lemma wire_transmit_has_own_macsec_layer {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (checks : MACsecExternalIfaceChecks d model.native)
    (faithful : model.Faithful)
    (tunnels : ∀ mac ∈ model.native.configuration.macIfaces, ∀ association,
      mac.transmitAssociation = some association →
      ∃ tunnel ∈ d.tunnels, tunnel.id = model.native.macsecTunnel association ∧
        tunnel.mechanism = .macsec ∧
        tunnel.sender = model.native.componentName
          (model.native.configuration.ip.owner mac.physicalIface))
    {before after : S} {action : A} (step : model.system.Tr before action after)
    (safe : MACsecOutputProtected model.native.configuration (model.native.state before))
    (payload : PayloadId) (iface : String) (layers : List String) (trafficClass : TrafficClass)
    (sent : .transmit payload iface layers trafficClass ∈ model.events action)
    (interface : Interface) (interfaceMember : interface ∈ d.interfaces) (interfaceName : interface.id = iface)
    (device : Device) (deviceMember : device ∈ d.devices) (deviceName : device.id = interface.device)
    (kind : device.kind = .macsec)
    (external : device.layer = some .inner ∧ interface.zone = .gray ∨
      device.layer = some .outer ∧ interface.zone = .black) :
    ∃ tunnel ∈ d.tunnels, tunnel.mechanism = .macsec ∧ tunnel.sender = device.id ∧ tunnel.id ∈ layers := by
  have recorded : .transmit payload iface layers trafficClass ∈
      (model.events action).filter NetworkEvent.NetworkOperation :=
    List.mem_filter.mpr ⟨sent, rfl⟩
  have native := faithful before action after step
  cases actionName : model.native.action action with
  | none =>
    rw [actionName] at native
    rw [native.2] at recorded
    simp at recorded
  | some operation =>
    rw [actionName] at native
    rw [native.2, DeviceExecutionBinding.RequiredEvents] at recorded
    rcases List.mem_append.mp recorded with source | operationEvent
    · exact False.elim (source_events_have_no_transmit model.native before payload iface layers trafficClass source)
    · obtain ⟨rfl, sameIface, sameLayers⟩ :=
        operation_transmit_is_wire model.native before after operation payload iface layers trafficClass operationEvent
      obtain ⟨ready, linked⟩ := link_transmit_uses_ready_output native.1.1
      obtain ⟨mac, configured, physical, owner⟩ := checks.externalIfaces _ _ linked
        interface interfaceMember (interfaceName.trans sameIface)
        device deviceMember deviceName kind external
      obtain ⟨association, body, installed, framed⟩ := safe.2 ready mac configured physical.symm
      obtain ⟨tunnel, member, tunnelName, mechanism, sender⟩ := tunnels mac configured association installed
      refine ⟨tunnel, member, mechanism, sender.trans owner, ?_⟩
      rw [sameLayers, framed, DeviceExecutionBinding.LayerIds, ← tunnelName]
      exact List.mem_cons_self

theorem macsec_protection_from_local_checks {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (parameters : List MACsecParameters)
    (coverage : model.CoversDeployment { d with focus := none })
    (bound : MACsecParametersBound { d with focus := none } model parameters)
    (inventory : ∀ device ∈ d.devices, device.kind = .macsec →
      ∃ parameter ∈ parameters, parameter.device = device.id)
    (settings : ∀ parameter ∈ parameters, parameter.dataDelayProtection = true ∧
      parameter.lifetimeMilliseconds = 6000 ∧ parameter.normalHelloMilliseconds = 2000 ∧
      0 < parameter.activeHelloMilliseconds ∧ parameter.activeHelloMilliseconds ≤ 2000 ∧
      (parameter.replayWindow = 2 ∨ (parameter.feasibleReplayWindow parameter.replayWindow ∧
        ∀ feasible, parameter.feasibleReplayWindow feasible → parameter.replayWindow ≤ feasible)) ∧
      parameter.confidentialityOffset = 0 ∧ parameter.mustSecure = true)
    (checks : MACsecExternalIfaceChecks { d with focus := none } model.native)
    (initial : ∀ state, model.initial state →
      MACsecOutputProtected model.native.configuration (model.native.state state)) :
    msc_macsec_protection_parameters d model parameters := by
  have faithful := coverage.2.1
  have tunnelBindings := coverage
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, tunnelRecords, _⟩ := tunnelBindings
  have tunnels : ∀ mac ∈ model.native.configuration.macIfaces, ∀ association,
      mac.transmitAssociation = some association →
      ∃ tunnel ∈ d.tunnels, tunnel.id = model.native.macsecTunnel association ∧
        tunnel.mechanism = .macsec ∧
        tunnel.sender = model.native.componentName
          (model.native.configuration.ip.owner mac.physicalIface) := by
    intro mac member association installed
    obtain ⟨tunnel, present, name, mechanism, key, sender, receiver⟩ :=
      tunnelRecords mac member association installed
    exact ⟨tunnel, present, name, mechanism, sender⟩
  refine ⟨coverage, bound, ?_, ?_, ?_⟩
  · intro device member relevant kind
    exact inventory device member kind
  · intro parameter member relevant
    exact settings parameter member
  · intro start actions finish started run payload iface layers trafficClass sent notControl
      interface interfaceMember interfaceRelevant interfaceName device deviceMember deviceRelevant deviceName kind external
    have reachable : ∀ before actions after, model.system.MTr before actions after →
        MACsecOutputProtected model.native.configuration (model.native.state before) →
        .transmit payload iface layers trafficClass ∈ actions.flatMap model.events →
          ∃ tunnel ∈ d.tunnels, tunnel.mechanism = .macsec ∧ tunnel.sender = device.id ∧ tunnel.id ∈ layers := by
      intro before actions after forwarding
      induction forwarding with
      | refl => simp
      | @stepL first action next rest last step tail ih =>
        intro safe member
        simp only [List.flatMap_cons, List.mem_append] at member
        rcases member with now | later
        · exact wire_transmit_has_own_macsec_layer d model
            ⟨checks.output, checks.externalIfaces⟩ faithful tunnels step safe
            payload iface layers trafficClass now interface interfaceMember interfaceName
            device deviceMember deviceName kind external
        · exact ih (model_step_preserves_macsec_output model faithful checks.output step safe) later
    change .transmit payload iface layers trafficClass ∈
      model.history.Events ++ actions.flatMap model.events at sent
    rcases List.mem_append.mp sent with historical | current
    · obtain ⟨record, member, same⟩ := List.mem_map.mp historical
      obtain ⟨_, _, _, _, setup⟩ := coverage.2.2.2.2.1.2.1 record member
      simp [HistoricalEvent.SetupOnly, same] at setup
    · exact reachable start actions finish run (initial start started) current

end TDN.Requirements.Msc
