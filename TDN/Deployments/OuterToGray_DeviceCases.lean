import TDN.Deployments.OuterToGray_DeviceModel
import TDN.Requirements.DeviceIngressArrivalLemmas

namespace TDN.Deployments.OuterToGray_DeviceModel
open Compliance Requirements Requirements.Msc MultiProtocolForwarding

structure ForwardCase where
  interface : Interface
  entryIface : Nat
  route : DataPlaneForwarding.FibRoute
  header : PacketPolicy.Packet
  network : List UInt8
  transport : List UInt8
  payload : List UInt8
  entryMtu : Nat
  exitMtu : Nat
  bytes : Nat

def ForwardCase.entry (sample : ForwardCase) : MultiProtocolForwarding.State :=
  { iface := sample.entryIface, datapathStage := .received, enteredIface := sample.entryIface
    frame := { payload := 1, originDomain := 1, body := .datagram sample.header }, authenticated := [], tracking := "new" }

def ForwardCase.entered (sample : ForwardCase) : MultiProtocolForwarding.State :=
  { sample.entry with
    initialEntry := false
    datapathStage := .ingress
    enteredIface := sample.entryIface
    authenticated := []
    tracking := "new" }

def ForwardCase.routed (sample : ForwardCase) (records : Records) : MultiProtocolForwarding.State :=
  { sample.entered with
    initialEntry := false
    iface := sample.route.egress
    datapathStage := .routed
    frame := records.configuration.forwardedFrame sample.entered.frame }

def ForwardCase.context (sample : ForwardCase) (records : Records) : PacketProcessing.Context :=
  { entry := sample.entry, state := sample.routed records
    header := { sample.header with hopLimit := sample.header.hopLimit - 1 }
    raw := .ip sample.network sample.transport sample.payload, hook := .forward }

def ForwardCase.packet (sample : ForwardCase) (records : Records) : PacketPolicy.Packet :=
  (sample.context records).Packet records.configuration

def ForwardCase.Checks (sample : ForwardCase) (records : Records) (base : Deployment) : Prop :=
  sample.interface ∈ records.interfaces ∧ sample.interface.HookApplies .forward .inbound ∧
  sample.route.ingress = sample.entryIface ∧
  DataPlaneForwarding.SelectedFibRoute records.routes sample.route sample.header ∧
  1 < sample.header.hopLimit ∧ sample.header.hopLimit ≤ 255 ∧
  (records.deployment base).ContextLocation records.inventory sample.interface .inbound (sample.context records) ∧
  (sample.context records).raw.PreHookValid (sample.packet records) .forward ∧
  DeviceIngressAttachment records.inventory sample.entryIface ∧
  ¬ (records.deployment base).InboundIPsecRequired records.inventory sample.entryIface (sample.context records).header ∧
  (sample.packet records).networkBytes = some sample.bytes ∧
  (∃ interface ∈ records.interfaces, interface.id = records.ifaceName sample.entryIface ∧ interface.mtu = some sample.entryMtu) ∧
  sample.bytes ≤ sample.entryMtu ∧
  (∃ interface ∈ records.interfaces, interface.id = records.ifaceName sample.route.egress ∧ interface.mtu = some sample.exitMtu) ∧
  sample.bytes ≤ sample.exitMtu ∧
  (∀ policy ∈ DataPlaneForwarding.lookupSpdPolicies (records.configuration.ip.egressPolicies sample.route.egress)
      (sample.context records).header,
    ∃ size ∈ records.ipsecSizes, size.Valid ∧ size.iface = sample.route.egress ∧ size.policy = policy ∧
      size.EncodedSize sample.bytes ≤ sample.exitMtu) ∧
  (∀ policy ∈ records.projectedPolicies, policy.interface = sample.interface.id →
    policy.direction = .inbound → policy.hook = .forward →
      policy.Accepts ((records.deployment base).Observe (sample.packet records)))

set_option synthInstance.maxSize 2048 in
instance (sample : ForwardCase) (records : Records) (base : Deployment) :
    Decidable (sample.Checks records base) := by
  unfold ForwardCase.Checks Deployment.ContextLocation Interface.HookApplies HookDirection InterfacePolicy.Accepts
  dsimp only [ForwardCase.context]
  infer_instance

lemma observed_packet_is_supported (records : Records) (base : Deployment) (packet : PacketPolicy.Packet)
    (fresh : packet.connectionState = "new") :
    (records.deployment base).Supported ((records.deployment base).Observe packet) := by
  refine ⟨rfl, ?_⟩
  intro _ established
  change packet.connectionState = "established" at established
  rw [fresh] at established
  exact False.elim ((by decide : ("new" : String) ≠ "established") established)

lemma checked_forward_case_is_eligible_and_accepted (sample : ForwardCase) (records : Records)
    (base : Deployment) (unique : InterfaceIDsUnique records.interfaces)
    (checks : sample.Checks records base) :
    (records.deployment base).PacketEligibleAt sample.interface .inbound .forward
        ((records.deployment base).Observe (sample.packet records)) ∧
      (records.deployment base).AcceptsAt sample.interface.id .inbound .forward
        ((records.deployment base).Observe (sample.packet records)) := by
  obtain ⟨member, applies, entry, selected, ttl, bounded, location, raw, attachment, noRequired,
    bytes, receiveMtu, receiveBound, sendMtu, sendBound, sizes, permits⟩ := checks
  have received : MultiProtocolForwarding.Step records.configuration sample.entry .receive sample.entered :=
    .receive rfl rfl "new"
  have routed : MultiProtocolForwarding.Step records.configuration sample.entered .route (sample.routed records) :=
    .route sample.route rfl rfl selected entry
  have supported : (records.deployment base).SupportedAt sample.interface .inbound (sample.context records)
      ((records.deployment base).Observe (sample.packet records)) := by
    refine ⟨records.inventory, rfl, member, applies, ?_, location, raw, rfl,
      observed_packet_is_supported records base _ rfl⟩
    refine ⟨rfl, sample.entered, sample.route, Or.inl received, ?_, routed, rfl, rfl, ?_, entry, rfl⟩
    · intro incoming visible
      have same : incoming = sample.header := Option.some.inj visible.symm
      subst incoming
      intro _
      exact ttl
    · exact (selected_route_depends_on_destination records.routes sample.route sample.header
        (sample.context records).header rfl).mp selected
  have sizeEligible : (records.deployment base).ContextSizeEligible (sample.context records) := by
    refine ⟨records.inventory, rfl, sample.bytes, bytes, ?_, ?_⟩
    · intro _
      exact ⟨sample.entryMtu, receiveMtu, receiveBound⟩
    · intro _
      exact ⟨sample.exitMtu, sendMtu, sendBound, sizes⟩
  have ingressEligible : (records.deployment base).ContextIngressEligible (sample.context records)
      ((records.deployment base).Observe (sample.packet records)) := by
    refine ⟨records.inventory, rfl, ?_, fun _ => Or.inl attachment, ?_⟩
    · exact ⟨⟨rfl, bounded⟩, rfl⟩
    · intro _ required
      exact False.elim (noRequired required)
  refine ⟨Or.inl ⟨sample.context records, rfl, supported, sizeEligible, ingressEligible⟩, ?_⟩
  refine ⟨observed_packet_is_supported records base _ rfl,
    eligible_routed_packet_has_hook_context _ _ _ _ _ supported, ?_⟩
  obtain ⟨policy, policyMember, name, direction, hook, only⟩ :=
    device_policies_cover_hooks records.inventory records.interfaces records.ifaceIndex unique
      sample.interface member .inbound .forward applies
  exact ⟨policy, policyMember, name, direction, hook, only, permits policy policyMember name direction hook⟩

end TDN.Deployments.OuterToGray_DeviceModel
