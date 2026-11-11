import TDN.Requirements.IPsecFlowTunnelNames

namespace TDN.Requirements.Msc
open Compliance LayeredFrame MultiProtocolForwarding

def FlowMixedIPsecStamp {S A : Type} (binding : DeviceExecutionBinding S A) (flow : Flow)
    (remoteHeader : Option PacketPolicy.Packet → Prop)
    (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop)
    (association : DataPlaneForwarding.TunnelSAStamp) (body : Body) : Prop :=
  allowedStamp association ∧ association.tag = 1 ∧
    binding.ipsecTunnel association = flow.innerTunnel ∧ remoteHeader body.originalHeader

def FlowMixedMACsecStamp {S A : Type} (binding : DeviceExecutionBinding S A) (flow : Flow)
    (allowedAssociation : MACsecAssociation → Prop) (association : MACsecAssociation) : Prop :=
  allowedAssociation association ∧ association.tag = 2 ∧
    binding.macsecTunnel association = flow.outerTunnel

def FlowMixedBody {S A : Type} (binding : DeviceExecutionBinding S A) (flow : Flow)
    (remoteHeader : Option PacketPolicy.Packet → Prop)
    (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop)
    (allowedAssociation : MACsecAssociation → Prop) : Body → Prop
  | .datagram _ | .ethernet _ => True
  | .ipsec association body =>
      FlowMixedIPsecStamp binding flow remoteHeader allowedStamp association body ∧
        FlowMixedBody binding flow remoteHeader allowedStamp allowedAssociation body
  | .macsec association body =>
      FlowMixedMACsecStamp binding flow allowedAssociation association ∧
        FlowMixedBody binding flow remoteHeader allowedStamp allowedAssociation body
  | .macsecPdu _ _ _ _ | .carrier _ _ => False

lemma flow_mixed_body_has_selected_tunnel_names {S A : Type} (binding : DeviceExecutionBinding S A)
    (flow : Flow) (remoteHeader : Option PacketPolicy.Packet → Prop)
    (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop)
    (allowedAssociation : MACsecAssociation → Prop) (body : Body)
    (valid : FlowMixedBody binding flow remoteHeader allowedStamp allowedAssociation body) :
    binding.LayerIds body = body.protectionLayers.map (flowTunnelName flow) := by
  induction body with
  | datagram | ethernet => rfl
  | ipsec association body ih =>
    have name : binding.ipsecTunnel association = flowTunnelName flow association.tag := by
      simp [flowTunnelName, valid.1.2.1, valid.1.2.2.1]
    exact congrArg₂ List.cons name (ih valid.2)
  | macsec association body ih =>
    have name : binding.macsecTunnel association = flowTunnelName flow association.tag := by
      simp [flowTunnelName, valid.1.2.1, valid.1.2.2]
    exact congrArg₂ List.cons name (ih valid.2)
  | macsecPdu | carrier => exact False.elim valid

lemma flow_mixed_inner_layer_has_remote_destination {S A : Type} (binding : DeviceExecutionBinding S A)
    (flow : Flow) (remoteHeader : Option PacketPolicy.Packet → Prop)
    (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop)
    (allowedAssociation : MACsecAssociation → Prop) (body : Body)
    (valid : FlowMixedBody binding flow remoteHeader allowedStamp allowedAssociation body)
    (inner : 1 ∈ body.protectionLayers) : remoteHeader body.originalHeader := by
  induction body with
  | datagram | ethernet => simp [Body.protectionLayers] at inner
  | ipsec association body ih => exact valid.1.2.2.2
  | macsec association body ih =>
    have member : 1 ∈ body.protectionLayers := by
      rcases List.mem_cons.mp inner with head | member
      · simp [valid.1.2.1] at head
      · exact member
    exact ih valid.2 member
  | macsecPdu | carrier => exact False.elim valid

def InnerMACsecEgressGuard (destinationLogicalIface : Nat) (state : MultiProtocolForwarding.State) : Prop :=
  state.frame.body.protectionLayers = [1] → state.iface = destinationLogicalIface →
    state.datapathStage ≠ .routed ∧ state.datapathStage ≠ .outputRouted ∧
      state.datapathStage ≠ .filtered ∧ state.datapathStage ≠ .egressReady

structure MixedFlowTunnelChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (flow : Flow) (remoteHeader : Option PacketPolicy.Packet → Prop)
    (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop)
    (allowedAssociation : MACsecAssociation → Prop)
    (plainAllowed : Nat → Body → Prop) (expectedEncapStack : Nat → List Nat)
    (destinationLogicalIface : Nat) : Prop where
  noCarriers : binding.configuration.carriers = []
  routeOwners : ∀ route ∈ binding.configuration.ip.routes,
    binding.configuration.ip.owner route.egress = binding.configuration.ip.owner route.ingress
  ownerPlain : ∀ first last body, binding.configuration.ip.owner first = binding.configuration.ip.owner last →
    plainAllowed first body → plainAllowed last body
  physicalPlain : ∀ first last body, binding.configuration.physicalLink first last →
    expectedEncapStack first = [] → plainAllowed first body → plainAllowed last body
  bridgePlain : ∀ first last body, binding.configuration.bridge first last →
    expectedEncapStack first = [] → plainAllowed first body → plainAllowed last body
  routeDestination : ∀ frame header route,
    frame.HeadersCoherent → binding.configuration.visibleHeader frame = some header →
    FlowMixedBody binding flow remoteHeader allowedStamp allowedAssociation frame.body →
    frame.body.protectionLayers = [1] →
    DataPlaneForwarding.SelectedFibRoute binding.configuration.ip.routes route header →
    route.egress ≠ destinationLogicalIface
  bridgeDestination : ∀ first last, binding.configuration.bridge first last → last ≠ destinationLogicalIface
  macLogicalNonempty : ∀ iface ∈ binding.configuration.macIfaces, expectedEncapStack iface.logicalIface ≠ []
  outboundIPsec : ∀ iface frame header policy association,
    frame.HeadersCoherent → binding.configuration.visibleHeader frame = some header →
    policy ∈ DataPlaneForwarding.lookupSpdPolicies (binding.configuration.ip.egressPolicies iface) header →
    association ∈ binding.configuration.ip.egressSAs iface → DataPlaneForwarding.saMatchesPolicy association policy →
    FlowMixedBody binding flow remoteHeader allowedStamp allowedAssociation frame.body →
    (frame.body.protectionLayers = [] → plainAllowed iface frame.body) →
    policy.tag :: frame.body.protectionLayers = expectedEncapStack iface →
    FlowMixedIPsecStamp binding flow remoteHeader allowedStamp (policy.seal association) frame.body
  inboundPlain : ∀ iface policy association body,
    policy ∈ binding.configuration.ip.ingressPolicies iface →
    association ∈ binding.configuration.ip.ingressSAs iface → DataPlaneForwarding.saMatchesPolicy association policy →
    FlowMixedBody binding flow remoteHeader allowedStamp allowedAssociation (.ipsec (policy.seal association) body) →
    policy.tag :: body.protectionLayers = expectedEncapStack iface → body.protectionLayers = [] →
    plainAllowed iface body
  outboundMACsec : ∀ iface association state,
    iface ∈ binding.configuration.macIfaces → state.datapathStage = .egressReady →
    state.iface = iface.logicalIface → fullMACsecTransmit iface association state.frame.body →
    state.frame.body.protectionLayers = expectedEncapStack state.iface →
    InnerMACsecEgressGuard destinationLogicalIface state →
    FlowMixedMACsecStamp binding flow allowedAssociation association

def MixedFlowInvariant {S A : Type} (binding : DeviceExecutionBinding S A)
    (flow : Flow) (remoteHeader : Option PacketPolicy.Packet → Prop)
    (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop)
    (allowedAssociation : MACsecAssociation → Prop)
    (plainAllowed : Nat → Body → Prop) (expectedEncapStack : Nat → List Nat)
    (destinationLogicalIface : Nat) (state : MultiProtocolForwarding.State) : Prop :=
  HeaderedStackInvariant binding.configuration expectedEncapStack state ∧
  FlowMixedBody binding flow remoteHeader allowedStamp allowedAssociation state.frame.body ∧
  (state.frame.body.protectionLayers = [] → plainAllowed state.iface state.frame.body) ∧
  InnerMACsecEgressGuard destinationLogicalIface state

lemma mixed_step_preserves_flow_tunnel_names {S A : Type} (binding : DeviceExecutionBinding S A)
    (flow : Flow) (remoteHeader : Option PacketPolicy.Packet → Prop)
    (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop)
    (allowedAssociation : MACsecAssociation → Prop)
    (plainAllowed : Nat → Body → Prop) (expectedEncapStack : Nat → List Nat)
    (destinationLogicalIface : Nat)
    (checks : MixedFlowTunnelChecks binding flow remoteHeader allowedStamp allowedAssociation plainAllowed expectedEncapStack destinationLogicalIface)
    (stackChecks : HeaderedLocalConditions binding.configuration expectedEncapStack)
    (processing : HeaderProcessing) (mode : binding.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing) {before after : MultiProtocolForwarding.State}
    {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before operation after)
    (safe : MixedFlowInvariant binding flow remoteHeader allowedStamp allowedAssociation plainAllowed expectedEncapStack destinationLogicalIface before) :
    MixedFlowInvariant binding flow remoteHeader allowedStamp allowedAssociation plainAllowed expectedEncapStack destinationLogicalIface after := by
  have nextStack := headered_step_preserves_stack stackChecks processing mode bounds step safe.1
  refine ⟨nextStack, ?_, ?_, ?_⟩
  · cases step
    all_goals simp only [Config.forwardedFrame_body, Config.restoredFrame_body]
    all_goals try { exact safe.2.1 }
    case encryptIPsec policy association stage visible selected installed bound =>
      have postStack : policy.tag :: before.frame.body.protectionLayers = expectedEncapStack before.iface := by
        simpa only [HeaderedStackInvariant, Config.ipsecFrame_body, Body.protectionLayers,
          DataPlaneForwarding.IpsecPolicy.seal] using nextStack.2.2.1
      have named := checks.outboundIPsec before.iface before.frame _ policy association safe.1.1
        visible selected installed bound safe.2.1 safe.2.2.1 postStack
      simpa only [Config.ipsecFrame_body, FlowMixedBody] using And.intro named safe.2.1
    case decryptIPsec policy association body header stage encrypted configured installed bound visible selected tracking =>
      have valid := safe.2.1
      rw [encrypted] at valid
      exact valid.2
    case encryptMACsec iface association configured stage logical emits =>
      have layout : before.frame.body.protectionLayers = expectedEncapStack before.iface := by
        simpa only [stage] using safe.1.2.2
      have named := checks.outboundMACsec iface association before configured stage logical emits layout safe.2.2.2
      simpa only [Config.macsecFrame_body, FlowMixedBody] using And.intro named safe.2.1
    case decryptMACsec iface association transmitted body configured stage physical encrypted installed spi =>
      have valid := safe.2.1
      rw [encrypted] at valid
      exact valid.2
    case validateMACsec iface association transmitted encryptFrames offset body configured stage physical framed installed spi =>
      simpa only [framed, FlowMixedBody] using safe.2.1
    case protectMACsec iface association configured stage logical enabled protection installed limited =>
      obtain ⟨_, encrypt, zero, _⟩ := stackChecks.macSecure iface configured
      rcases limited with impossible | impossible
      · simp [encrypt] at impossible
      · exact False.elim (impossible zero)
    all_goals simp_all only [checks.noCarriers, List.not_mem_nil]
  · cases step
    all_goals simp only [Config.forwardedFrame_body, Config.restoredFrame_body]
    all_goals try { exact safe.2.2.1 }
    case route route stage visible selected entry =>
      intro empty
      apply checks.ownerPlain before.iface route.egress before.frame.body
      · exact ((checks.routeOwners route selected.1).trans (congrArg binding.configuration.ip.owner entry)).symm
      · exact safe.2.2.1 empty
    case routeLocalOutput route stage visible selected entry =>
      intro empty
      apply checks.ownerPlain before.iface route.egress before.frame.body
      · exact ((checks.routeOwners route selected.1).trans (congrArg binding.configuration.ip.owner entry)).symm
      · exact safe.2.2.1 empty
    case routeOuterPacket route stage visible selected entry =>
      intro empty
      apply checks.ownerPlain before.iface route.egress before.frame.body
      · exact ((checks.routeOwners route selected.1).trans (congrArg binding.configuration.ip.owner entry)).symm
      · exact safe.2.2.1 empty
    case encryptIPsec => simp only [Config.ipsecFrame_body, Body.protectionLayers, List.cons_ne_nil, false_implies]
    case decryptIPsec policy association body header stage encrypted configured installed bound visible selected tracking =>
      intro empty
      have valid := safe.2.1
      rw [encrypted] at valid
      apply checks.inboundPlain before.iface policy association body configured installed bound valid
      · simpa only [HeaderedStackInvariant, stage, encrypted, Body.protectionLayers,
          DataPlaneForwarding.IpsecPolicy.seal] using safe.1.2.2
      · exact empty
    case encryptMACsec => simp only [Config.macsecFrame_body, Body.protectionLayers, List.cons_ne_nil, false_implies]
    case decryptMACsec iface association transmitted body configured stage physical encrypted installed spi =>
      intro empty
      have named := safe.2.1
      rw [encrypted] at named
      have layout : transmitted.tag :: body.protectionLayers = expectedEncapStack before.iface := by
        simpa only [HeaderedStackInvariant, stage, encrypted, Body.protectionLayers] using safe.1.2.2
      have transmit := stackChecks.macReceive iface configured association installed
      have role := stackChecks.macRoleAgreement
      have impossible : body.protectionLayers = expectedEncapStack iface.logicalIface := by
        have bodyRecorded := safe.1.2.1
        rw [encrypted] at bodyRecorded
        obtain ⟨recursive, sender, senderMember, senderProduced⟩ := bodyRecorded
        have same := role sender senderMember transmitted senderProduced iface configured association installed spi
        rw [physical, ← transmit, same] at layout
        exact (List.cons.inj layout).2
      exact False.elim (checks.macLogicalNonempty iface configured (impossible.symm.trans empty))
    case bridge last stage linked =>
      intro empty
      have emptyStack : expectedEncapStack before.iface = [] := by
        have shape : before.frame.body.protectionLayers = expectedEncapStack before.iface := by simpa only [stage] using safe.1.2.2
        exact shape.symm.trans empty
      exact checks.bridgePlain before.iface last before.frame.body linked emptyStack (safe.2.2.1 empty)
    case bridgeOutput last stage linked =>
      intro empty
      have emptyStack : expectedEncapStack before.iface = [] := by
        have shape : before.frame.body.protectionLayers = expectedEncapStack before.iface := by simpa only [stage] using safe.1.2.2
        exact shape.symm.trans empty
      exact checks.bridgePlain before.iface last before.frame.body linked emptyStack (safe.2.2.1 empty)
    case linkTransmit last stage linked =>
      intro empty
      have emptyStack : expectedEncapStack before.iface = [] := by
        have shape : before.frame.body.protectionLayers = expectedEncapStack before.iface := by simpa only [stage] using safe.1.2.2
        exact shape.symm.trans empty
      exact checks.physicalPlain before.iface last before.frame.body linked emptyStack (safe.2.2.1 empty)
    case unprotectedMACsec iface configured stage logical enabled unprotected =>
      have protect := (stackChecks.macSecure iface configured).1
      simp [protect] at unprotected
    case protectMACsec iface association configured stage logical enabled protection installed limited =>
      obtain ⟨_, encrypt, zero, _⟩ := stackChecks.macSecure iface configured
      rcases limited with impossible | impossible
      · simp [encrypt] at impossible
      · exact False.elim (impossible zero)
    case validateMACsec iface association transmitted encryptFrames offset body configured stage physical framed installed spi =>
      have valid := safe.2.1
      simp only [framed, FlowMixedBody] at valid
    case uncheckedMACsec iface configured stage physical unchecked =>
      have strict := (stackChecks.macSecure iface configured).2.2.2
      simp [strict] at unchecked
    all_goals simp_all only [checks.noCarriers, List.not_mem_nil]
  · cases step
    all_goals dsimp only [InnerMACsecEgressGuard]
    all_goals try { simp only [Config.forwardedFrame_body, Config.restoredFrame_body] }
    all_goals try { simp only [ne_eq, reduceCtorEq, not_false_eq_true, implies_true, and_self] }
    case route route stage visible selected entry =>
      intro layers iface
      exact False.elim ((checks.routeDestination before.frame _ route safe.1.1 visible safe.2.1 (by simpa only [Config.forwardedFrame_body] using layers) selected) iface)
    case routeLocalOutput route stage visible selected entry =>
      intro layers iface
      exact False.elim ((checks.routeDestination before.frame _ route safe.1.1 visible safe.2.1 (by simpa only [Config.forwardedFrame_body] using layers) selected) iface)
    case routeOuterPacket route stage visible selected entry =>
      intro layers iface
      exact False.elim ((checks.routeDestination before.frame _ route safe.1.1 visible safe.2.1 (by simpa only [Config.forwardedFrame_body] using layers) selected) iface)
    case forwardFilter header stage visible accepted =>
      intro layers iface
      exact False.elim ((safe.2.2.2 layers iface).1 stage)
    case outputFilter header stage visible accepted =>
      intro layers iface
      exact False.elim ((safe.2.2.2 layers iface).2.1 stage)
    case forwardWithoutEncap header stage visible noPolicy =>
      intro layers iface
      exact False.elim ((safe.2.2.2 layers iface).2.2.1 stage)
    case bridge last stage linked =>
      intro layers iface
      exact False.elim ((checks.bridgeDestination _ _ linked) iface)
    case bridgeOutput last stage linked =>
      intro layers iface
      exact False.elim ((checks.bridgeDestination _ _ linked) iface)
    case encryptMACsec iface association configured stage logical emits =>
      have layout : before.frame.body.protectionLayers = expectedEncapStack before.iface := by simpa only [stage] using safe.1.2.2
      have named := checks.outboundMACsec iface association before configured stage logical emits layout safe.2.2.2
      simp [Config.macsecFrame_body, Body.protectionLayers, named.2.1]
    case unprotectedMACsec iface configured stage logical enabled unprotected =>
      have protect := (stackChecks.macSecure iface configured).1
      simp [protect] at unprotected
    case protectMACsec iface association configured stage logical enabled protection installed limited =>
      obtain ⟨_, encrypt, zero, _⟩ := stackChecks.macSecure iface configured
      rcases limited with impossible | impossible
      · simp [encrypt] at impossible
      · exact False.elim (impossible zero)
    case decryptMACsec iface association transmitted body configured stage physical encrypted installed spi =>
      simp only [stage, ne_eq, reduceCtorEq, not_false_eq_true, and_self, implies_true]
    case validateMACsec iface association transmitted encryptFrames offset body configured stage physical framed installed spi =>
      simp only [stage, ne_eq, reduceCtorEq, not_false_eq_true, and_self, implies_true]
    case uncheckedMACsec iface configured stage physical unchecked =>
      simp only [stage, ne_eq, reduceCtorEq, not_false_eq_true, and_self, implies_true]
    all_goals simp_all only [checks.noCarriers, List.not_mem_nil]

end TDN.Requirements.Msc
