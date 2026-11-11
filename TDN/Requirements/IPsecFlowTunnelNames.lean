import TDN.Requirements.NestedFlowChecks
import TDN.Models.HeaderAwareEncapPreservation

namespace TDN.Requirements.Msc
open Compliance LayeredFrame MultiProtocolForwarding

def FlowIPsecStamp {S A : Type} (binding : DeviceExecutionBinding S A) (flow : Flow)
    (remoteHeader : Option PacketPolicy.Packet → Prop) (association : DataPlaneForwarding.TunnelSAStamp)
    (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop) (body : Body) : Prop :=
  allowedStamp association ∧ ((association.tag = 1 ∧ binding.ipsecTunnel association = flow.innerTunnel ∧ remoteHeader body.originalHeader) ∨
  (association.tag = 2 ∧ binding.ipsecTunnel association = flow.outerTunnel))

def FlowIPsecBody {S A : Type} (binding : DeviceExecutionBinding S A) (flow : Flow)
    (remoteHeader : Option PacketPolicy.Packet → Prop) (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop) : Body → Prop
  | .datagram _ | .ethernet _ => True
  | .ipsec association body =>
      FlowIPsecStamp binding flow remoteHeader association allowedStamp body ∧ FlowIPsecBody binding flow remoteHeader allowedStamp body
  | .macsec _ _ | .macsecPdu _ _ _ _ | .carrier _ _ => False

def flowTunnelName (flow : Flow) (layer : Nat) : String :=
  if layer = 1 then flow.innerTunnel else flow.outerTunnel

lemma flow_ipsec_body_has_selected_tunnel_names {S A : Type} (binding : DeviceExecutionBinding S A)
    (flow : Flow) (remoteHeader : Option PacketPolicy.Packet → Prop) (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop) (body : Body)
    (valid : FlowIPsecBody binding flow remoteHeader allowedStamp body) :
    binding.LayerIds body = body.protectionLayers.map (flowTunnelName flow) := by
  induction body with
  | datagram | ethernet => rfl
  | ipsec association body ih =>
    have name : binding.ipsecTunnel association = flowTunnelName flow association.tag := by
      rcases valid.1.2 with inner | outer
      · simp [flowTunnelName, inner.1, inner.2.1]
      · simp [flowTunnelName, outer.1, outer.2]
    exact congrArg₂ List.cons name (ih valid.2)
  | macsec | macsecPdu | carrier => exact False.elim valid

lemma flow_ipsec_inner_layer_has_remote_destination {S A : Type} (binding : DeviceExecutionBinding S A)
    (flow : Flow) (remoteHeader : Option PacketPolicy.Packet → Prop) (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop) (body : Body)
    (valid : FlowIPsecBody binding flow remoteHeader allowedStamp body) (inner : 1 ∈ body.protectionLayers) :
    remoteHeader body.originalHeader := by
  induction body with
  | datagram | ethernet => simp [Body.protectionLayers] at inner
  | ipsec association body ih =>
    rcases valid.1.2 with selected | outer
    · exact selected.2.2
    · have member : 1 ∈ body.protectionLayers := by
        rcases List.mem_cons.mp inner with head | member
        · simp [outer.1] at head
        · exact member
      exact ih valid.2 member
  | macsec | macsecPdu | carrier => exact False.elim valid

structure IPsecFlowTunnelChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (flow : Flow) (remoteHeader : Option PacketPolicy.Packet → Prop)
    (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop)
    (plainAllowed : Nat → Body → Prop) (expectedEncapStack : Nat → List Nat) : Prop where
  noMACsec : binding.configuration.macIfaces = []
  noCarriers : binding.configuration.carriers = []
  routeOwners : ∀ route ∈ binding.configuration.ip.routes,
    binding.configuration.ip.owner route.egress = binding.configuration.ip.owner route.ingress
  ownerPlain : ∀ first last body, binding.configuration.ip.owner first = binding.configuration.ip.owner last →
    plainAllowed first body → plainAllowed last body
  physicalPlain : ∀ first last body, binding.configuration.physicalLink first last →
    expectedEncapStack first = [] → plainAllowed first body → plainAllowed last body
  bridgePlain : ∀ first last body, binding.configuration.bridge first last →
    expectedEncapStack first = [] → plainAllowed first body → plainAllowed last body
  outboundStamp : ∀ iface frame header policy association,
    frame.HeadersCoherent → binding.configuration.visibleHeader frame = some header →
    policy ∈ DataPlaneForwarding.lookupSpdPolicies (binding.configuration.ip.egressPolicies iface) header →
    association ∈ binding.configuration.ip.egressSAs iface → DataPlaneForwarding.saMatchesPolicy association policy →
    FlowIPsecBody binding flow remoteHeader allowedStamp frame.body →
    (frame.body.protectionLayers = [] → plainAllowed iface frame.body) →
    policy.tag :: frame.body.protectionLayers = expectedEncapStack iface →
    FlowIPsecStamp binding flow remoteHeader (policy.seal association) allowedStamp frame.body
  inboundPlain : ∀ iface policy association body,
    policy ∈ binding.configuration.ip.ingressPolicies iface →
    association ∈ binding.configuration.ip.ingressSAs iface → DataPlaneForwarding.saMatchesPolicy association policy →
    FlowIPsecBody binding flow remoteHeader allowedStamp (.ipsec (policy.seal association) body) →
    policy.tag :: body.protectionLayers = expectedEncapStack iface → body.protectionLayers = [] →
    plainAllowed iface body

def IPsecFlowInvariant {S A : Type} (binding : DeviceExecutionBinding S A)
    (flow : Flow) (remoteHeader : Option PacketPolicy.Packet → Prop)
    (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop)
    (plainAllowed : Nat → Body → Prop) (expectedEncapStack : Nat → List Nat) (state : MultiProtocolForwarding.State) : Prop :=
  HeaderedStackInvariant binding.configuration expectedEncapStack state ∧
  FlowIPsecBody binding flow remoteHeader allowedStamp state.frame.body ∧
  (state.frame.body.protectionLayers = [] → plainAllowed state.iface state.frame.body)

lemma ipsec_step_preserves_flow_tunnel_names {S A : Type} (binding : DeviceExecutionBinding S A)
    (flow : Flow) (remoteHeader : Option PacketPolicy.Packet → Prop)
    (allowedStamp : DataPlaneForwarding.TunnelSAStamp → Prop)
    (plainAllowed : Nat → Body → Prop) (expectedEncapStack : Nat → List Nat)
    (checks : IPsecFlowTunnelChecks binding flow remoteHeader allowedStamp plainAllowed expectedEncapStack)
    (stackChecks : HeaderedLocalConditions binding.configuration expectedEncapStack)
    (processing : HeaderProcessing) (mode : binding.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing) {before after : MultiProtocolForwarding.State}
    {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before operation after)
    (safe : IPsecFlowInvariant binding flow remoteHeader allowedStamp plainAllowed expectedEncapStack before) :
    IPsecFlowInvariant binding flow remoteHeader allowedStamp plainAllowed expectedEncapStack after := by
  have nextStack := headered_step_preserves_stack stackChecks processing mode bounds step safe.1
  refine ⟨nextStack, ?_⟩
  cases step
  all_goals simp only [Config.forwardedFrame_body, Config.restoredFrame_body]
  all_goals try { simpa only [Config.forwardedFrame_body] using safe.2 }
  case route route stage visible selected entry =>
    refine ⟨safe.2.1, ?_⟩
    intro empty
    apply checks.ownerPlain before.iface route.egress before.frame.body
    · exact ((checks.routeOwners route selected.1).trans (congrArg binding.configuration.ip.owner entry)).symm
    · exact safe.2.2 empty
  case routeLocalOutput route stage visible selected entry =>
    refine ⟨safe.2.1, ?_⟩
    intro empty
    apply checks.ownerPlain before.iface route.egress before.frame.body
    · exact ((checks.routeOwners route selected.1).trans (congrArg binding.configuration.ip.owner entry)).symm
    · exact safe.2.2 empty
  case routeOuterPacket route stage visible selected entry =>
    refine ⟨safe.2.1, ?_⟩
    intro empty
    apply checks.ownerPlain before.iface route.egress before.frame.body
    · exact ((checks.routeOwners route selected.1).trans (congrArg binding.configuration.ip.owner entry)).symm
    · exact safe.2.2 empty
  case encryptIPsec policy association stage visible selected installed bound =>
    have postStack : policy.tag :: before.frame.body.protectionLayers = expectedEncapStack before.iface := by
      simpa only [HeaderedStackInvariant, Config.ipsecFrame_body, Body.protectionLayers,
        DataPlaneForwarding.IpsecPolicy.seal] using nextStack.2.2.1
    have named := checks.outboundStamp before.iface before.frame _ policy association safe.1.1
      visible selected installed bound safe.2.1 safe.2.2 postStack
    constructor
    · simpa only [Config.ipsecFrame_body, FlowIPsecBody] using And.intro named safe.2.1
    · simp only [Config.ipsecFrame_body, Body.protectionLayers, List.cons_ne_nil, false_implies]
  case decryptIPsec policy association body header stage encrypted configured installed bound visible selected tracking =>
    have bodyValid := safe.2.1
    rw [encrypted] at bodyValid
    refine ⟨?_, ?_⟩
    · simpa only [Config.restoredFrame_body] using bodyValid.2
    · intro empty
      have emptyBody : body.protectionLayers = [] := by simpa only [Config.restoredFrame_body] using empty
      apply checks.inboundPlain before.iface policy association body configured installed bound bodyValid
      · simpa only [HeaderedStackInvariant, stage, encrypted, Body.protectionLayers,
          DataPlaneForwarding.IpsecPolicy.seal] using safe.1.2.2
      · exact emptyBody
  case bridge last stage linked =>
    refine ⟨safe.2.1, ?_⟩
    intro empty
    have emptyStack : expectedEncapStack before.iface = [] := by
      have stack : before.frame.body.protectionLayers = expectedEncapStack before.iface := by
        simpa only [stage] using safe.1.2.2
      exact stack.symm.trans empty
    exact checks.bridgePlain before.iface last before.frame.body linked emptyStack (safe.2.2 empty)
  case bridgeOutput last stage linked =>
    refine ⟨safe.2.1, ?_⟩
    intro empty
    have emptyStack : expectedEncapStack before.iface = [] := by
      have stack : before.frame.body.protectionLayers = expectedEncapStack before.iface := by
        simpa only [stage] using safe.1.2.2
      exact stack.symm.trans empty
    exact checks.bridgePlain before.iface last before.frame.body linked emptyStack (safe.2.2 empty)
  case linkTransmit last stage linked =>
    refine ⟨safe.2.1, ?_⟩
    intro empty
    have emptyStack : expectedEncapStack before.iface = [] := by
      have stack : before.frame.body.protectionLayers = expectedEncapStack before.iface := by
        simpa only [stage] using safe.1.2.2
      exact stack.symm.trans empty
    exact checks.physicalPlain before.iface last before.frame.body linked emptyStack (safe.2.2 empty)
  all_goals simp_all only [checks.noMACsec, checks.noCarriers, List.not_mem_nil]

end TDN.Requirements.Msc
