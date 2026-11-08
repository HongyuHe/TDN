import TDN.Semantics.NativeHookFacts

namespace TDN.MultiProtocolExecution
open LayeredFrame

def BoundaryPacket (configuration : Config) (iface : Nat) (outbound : Bool)
    (header : PacketPolicy.Packet) : PacketPolicy.Packet :=
  { header with
    ingress := if outbound then "" else configuration.ip.interfaceName iface
    egress := if outbound then configuration.ip.interfaceName iface else ""
    inboundPolicies := [], outboundPolicies := [] }

lemma boundary_packet_keeps_endpoints (configuration : Config) (iface : Nat)
    (outbound : Bool) (header : PacketPolicy.Packet) :
    (BoundaryPacket configuration iface outbound header).source = header.source ∧
      (BoundaryPacket configuration iface outbound header).destination = header.destination ∧
      (BoundaryPacket configuration iface outbound header).protocol = header.protocol := by
  exact ⟨rfl, rfl, rfl⟩

lemma IPsec_output_has_configured_outer_header (configuration : Config)
    {before after : State} (encrypted : Step configuration before .encryptIPsec after) :
    ∃ policy ∈ configuration.ip.outbound before.iface,
      ∃ association ∈ configuration.ip.outboundStates before.iface,
        Execution.StateBindsPolicy association policy ∧
        ∃ header, configuration.visibleHeader after.frame = some header ∧
          header.source = policy.sender ∧ header.destination = policy.receiver ∧
          header.protocol = "esp" := by
  cases encrypted with
  | encryptIPsec policy association datapathStage visible selected installed bound =>
    refine ⟨policy, List.mem_filter.mp selected |>.1, association, installed, bound, ?_⟩
    cases mode : configuration.headerProcessing with
    | none =>
      refine ⟨outerHeader policy.sender policy.receiver "esp" 0 0, ?_, rfl, rfl, rfl⟩
      simp [Config.visibleHeader, Config.ipsecFrame, mode, Body.visibleHeader, Execution.Association.seal, bound.2.1, bound.2.2.1]
    | some processing =>
      refine ⟨{ outerHeader policy.sender policy.receiver "esp" 0 0 with
        hopLimit := processing.ipsecHopLimit before.iface }, ?_, rfl, rfl, rfl⟩
      simp [Config.visibleHeader, Config.ipsecFrame, mode, Frame.visibleHeader,
        Frame.pushHeader, Body.visibleHeader, Execution.Association.seal, bound.2.1, bound.2.2.1]

lemma IPsec_input_has_configured_outer_header (configuration : Config)
    (processing : HeaderProcessing) (mode : configuration.headerProcessing = some processing)
    {before after : State} (coherent : before.frame.HeadersCoherent)
    (decrypted : Step configuration before .decryptIPsec after) :
    ∃ policy ∈ configuration.ip.inbound before.iface,
      ∃ association ∈ configuration.ip.inboundStates before.iface,
        Execution.StateBindsPolicy association policy ∧
        ∃ header, configuration.visibleHeader before.frame = some header ∧
          header.source = policy.sender ∧ header.destination = policy.receiver ∧
          header.protocol = "esp" := by
  cases decrypted with
  | decryptIPsec policy association body inner datapathStage encrypted configured installed bound visible selected tracking =>
    have bodyVisible : before.frame.body.visibleHeader =
        some (outerHeader policy.sender policy.receiver "esp" 0 0) := by
      simp [encrypted, Body.visibleHeader, Execution.Association.seal, bound.2.1, bound.2.2.1]
    have frameVisible : before.frame.visibleHeader =
        some (before.frame.activeHeader.getD (outerHeader policy.sender policy.receiver "esp" 0 0)) := by
      simp [Frame.visibleHeader, bodyVisible]
    obtain ⟨nominal, nominalVisible, identity⟩ :=
      Frame.coherent_visible coherent _ frameVisible
    have nominalEq : nominal = outerHeader policy.sender policy.receiver "esp" 0 0 :=
      Option.some.inj (nominalVisible.symm.trans bodyVisible)
    subst nominal
    refine ⟨policy, configured, association, installed, bound,
      before.frame.activeHeader.getD (outerHeader policy.sender policy.receiver "esp" 0 0),
      ?_, ?_, ?_, ?_⟩
    · simpa [Config.visibleHeader, mode] using frameVisible
    · simpa [outerHeader] using congrArg PacketPolicy.Packet.source identity.1
    · simpa [outerHeader] using congrArg PacketPolicy.Packet.destination identity.1
    · simpa [outerHeader] using congrArg PacketPolicy.Packet.protocol identity.1

lemma outer_route_keeps_boundary_header (configuration : Config)
    {before after : State} (datapathStage : before.datapathStage = .encapsulated)
    (routed : Step configuration before .route after) :
    configuration.visibleHeader after.frame = configuration.visibleHeader before.frame ∧
      after.datapathStage = .ready := by
  cases routed with
  | route route impossible => simp [impossible] at datapathStage
  | routeLocalOutput route impossible => simp [impossible] at datapathStage
  | routeOuterPacket => exact ⟨rfl, rfl⟩

lemma wire_keeps_boundary_header (configuration : Config)
    {before after : State} (wire : Step configuration before .linkTransmit after) :
    configuration.visibleHeader after.frame = configuration.visibleHeader before.frame ∧
      after.frame.body = before.frame.body := by
  cases wire
  exact ⟨rfl, rfl⟩

inductive OutboundSuffix (configuration : Config) : State → State → Prop
  | passWithoutTransform {filtered ready : State}
      (step : Step configuration filtered .passWithoutTransform ready)
      (datapathStage : filtered.datapathStage = .filtered) : OutboundSuffix configuration filtered ready
  | IPsec {filtered encrypted ready : State}
      (protect : Step configuration filtered .encryptIPsec encrypted)
      (route : Step configuration encrypted .route ready) :
      OutboundSuffix configuration filtered ready

lemma outbound_suffix_has_ready_state (configuration : Config)
    {filtered ready : State} (suffix : OutboundSuffix configuration filtered ready) :
    ready.datapathStage = .ready := by
  cases suffix with
  | passWithoutTransform step datapathStage =>
    cases step <;> simp_all
  | IPsec protect route =>
    cases protect
    exact (outer_route_keeps_boundary_header configuration rfl route).2

lemma outbound_suffix_is_native_execution (configuration : Config)
    {filtered ready : State} (suffix : OutboundSuffix configuration filtered ready) :
    ∃ actions, (lts configuration).MTr filtered actions ready := by
  cases suffix with
  | passWithoutTransform step datapathStage =>
    exact ⟨[.passWithoutTransform], Cslib.LTS.MTr.single (lts configuration) step⟩
  | IPsec protect route =>
    exact ⟨[.encryptIPsec, .route], .stepL protect (.stepL route .refl)⟩

lemma IPsec_suffix_boundary_packet_uses_installed_policy (configuration : Config)
    {filtered encrypted ready : State}
    (protect : Step configuration filtered .encryptIPsec encrypted)
    (route : Step configuration encrypted .route ready) :
    ∃ policy ∈ configuration.ip.outbound filtered.iface,
      ∃ association ∈ configuration.ip.outboundStates filtered.iface,
        Execution.StateBindsPolicy association policy ∧
        ∃ header, configuration.visibleHeader ready.frame = some header ∧
          (BoundaryPacket configuration ready.iface true header).source = policy.sender ∧
          (BoundaryPacket configuration ready.iface true header).destination = policy.receiver ∧
          (BoundaryPacket configuration ready.iface true header).protocol = "esp" := by
  obtain ⟨policy, member, association, installed, bound, header, visible, source, destination, protocol⟩ :=
    IPsec_output_has_configured_outer_header configuration protect
  have datapathStage : encrypted.datapathStage = .encapsulated := by cases protect; rfl
  have same := (outer_route_keeps_boundary_header configuration datapathStage route).1
  exact ⟨policy, member, association, installed, bound, header, same.trans visible,
    source, destination, protocol⟩

inductive FirstReadyRun (configuration : Config) : State → State → Prop
  | ready {state : State} (datapathStage : state.datapathStage = .ready) :
      FirstReadyRun configuration state state
  | next {before middle ready : State} {action : Action}
      (notReady : before.datapathStage ≠ .ready)
      (step : Step configuration before action middle)
      (tail : FirstReadyRun configuration middle ready) :
      FirstReadyRun configuration before ready

lemma first_ready_run_is_native_execution (configuration : Config)
    {before ready : State} (run : FirstReadyRun configuration before ready) :
    ∃ actions, (lts configuration).MTr before actions ready := by
  induction run with
  | ready => exact ⟨[], .refl⟩
  | next notReady step tail ih =>
    obtain ⟨actions, execution⟩ := ih
    exact ⟨_ :: actions, .stepL step execution⟩

lemma first_ready_run_finishes_ready (configuration : Config)
    {before ready : State} (run : FirstReadyRun configuration before ready) :
    ready.datapathStage = .ready := by
  induction run with
  | ready datapathStage => exact datapathStage
  | next _ _ _ ih => exact ih

lemma first_ready_run_from_ready_is_identity (configuration : Config)
    {before ready : State} (datapathStage : before.datapathStage = .ready)
    (run : FirstReadyRun configuration before ready) : before = ready := by
  cases run with
  | ready => rfl
  | next notReady => exact False.elim (notReady datapathStage)

lemma dropped_state_has_no_first_ready_run (configuration : Config)
    {before ready : State} (datapathStage : before.datapathStage = .dropped) :
    ¬ FirstReadyRun configuration before ready := by
  intro run
  induction run with
  | ready readyPhase => simp [datapathStage] at readyPhase
  | next notReady step tail ih =>
    apply ih
    cases step <;> simp_all

lemma first_ready_run_from_encapsulated_is_one_route (configuration : Config)
    {before ready : State} (datapathStage : before.datapathStage = .encapsulated)
    (run : FirstReadyRun configuration before ready) :
    Step configuration before .route ready := by
  cases run with
  | ready readyPhase => simp [datapathStage] at readyPhase
  | @next before middle ready action notReady step tail =>
    cases step <;> try simp_all
    case routeOuterPacket route actualPhase visible chosen entry =>
      have same := first_ready_run_from_ready_is_identity configuration rfl tail
      subst ready
      exact .routeOuterPacket route actualPhase visible chosen entry
    case drop =>
      exact False.elim (dropped_state_has_no_first_ready_run configuration rfl tail)

theorem first_ready_run_from_filtered_is_native_suffix (configuration : Config)
    {filtered ready : State} (datapathStage : filtered.datapathStage = .filtered)
    (run : FirstReadyRun configuration filtered ready) :
    OutboundSuffix configuration filtered ready := by
  cases run with
  | ready readyPhase => simp [datapathStage] at readyPhase
  | @next before middle ready action notReady step tail =>
    cases step <;> try simp_all
    case encryptIPsec policy association actualPhase visible selected installed bound =>
      exact .IPsec (.encryptIPsec policy association actualPhase visible selected installed bound)
        (first_ready_run_from_encapsulated_is_one_route configuration rfl tail)
    case passWithoutTransform actualPhase visible noPolicy =>
      have same := first_ready_run_from_ready_is_identity configuration rfl tail
      subst ready
      exact .passWithoutTransform (.passWithoutTransform actualPhase visible noPolicy) actualPhase
    case drop =>
      exact False.elim (dropped_state_has_no_first_ready_run configuration rfl tail)

theorem outbound_policy_annotation_forces_actual_IPsec (configuration : Config)
    {filtered ready : State} {header : PacketPolicy.Packet}
    (datapathStage : filtered.datapathStage = .filtered)
    (visible : configuration.visibleHeader filtered.frame = some header)
    (requestId : Nat)
    (required : requestId ∈ (policyHeader configuration filtered header).outboundPolicies)
    (run : FirstReadyRun configuration filtered ready) :
    ∃ encrypted, Step configuration filtered .encryptIPsec encrypted ∧
      Step configuration encrypted .route ready := by
  have suffix := first_ready_run_from_filtered_is_native_suffix configuration datapathStage run
  cases suffix with
  | passWithoutTransform step actualPhase =>
    cases step <;> simp_all [policyHeader]
  | IPsec protect route => exact ⟨_, protect, route⟩

theorem inbound_policy_annotation_requires_actual_decryption (configuration : Config)
    {entry entered routed : State}
    (ingress : PacketProcessing.Ingress configuration entry entered)
    (route : Step configuration entered .route routed)
    (authenticated : routed.authenticated ≠ []) :
    Step configuration entry .decryptIPsec entered := by
  rcases ingress with receive | decrypt
  · cases receive
    have preserved := route_from_ingress_preserves_local_state rfl route
    exact False.elim (authenticated preserved.2.2.1)
  · exact decrypt

end TDN.MultiProtocolExecution
