import TDN.Models.SourceGuardedAutoReplyNetwork

namespace TDN.EncryptedResponseGuards
open DataPlaneForwarding

def LocallyEncrypted (c : DataPlaneForwarding.DataPlaneModel) (state : DataPlaneForwarding.State) : Prop :=
  ∃ iface, c.owner state.iface = c.owner iface ∧
    ∃ association ∈ c.egressPolicies iface, ∃ sa previous,
      state.frame = encrypt association sa previous

def ExcludesWireSource (rule : PacketPolicy.Rule) (source : Nat) : Prop :=
  ∃ atom ∈ rule.atoms, match atom with
    | .destinationRange low high => source < low ∨ high < source
    | _ => False

instance (rule : PacketPolicy.Rule) (source : Nat) :
    Decidable (ExcludesWireSource rule source) := by
  unfold ExcludesWireSource
  letI (atom : PacketPolicy.MatchCondition) : Decidable (match atom with
    | .destinationRange low high => source < low ∨ high < source
    | _ => False) := by cases atom <;> infer_instance
  infer_instance

lemma matching_destination_not_excluded {rule : PacketPolicy.Rule}
    {packet : PacketPolicy.Packet} {source : Nat}
    (matched : rule.toFilter.accepts packet = true)
    (destination : packet.destination = source)
    (excludes : ExcludesWireSource rule source) : False := by
  obtain ⟨atom, member, disjoint⟩ := excludes
  have holds := PacketPolicy.matching_atom matched member
  cases atom <;> simp only at disjoint <;> try contradiction
  simp only [PacketPolicy.MatchCondition.matchesPacket] at holds
  omega

def LocalDeny (c : DataPlaneForwarding.DataPlaneModel) : Prop :=
  ∀ input output, c.owner input = c.owner output →
    ∀ association ∈ c.egressPolicies input,
      c.outputFallback output = .deny ∧
      ∀ rule ∈ c.outputRules output, rule.verdict = .allow →
        KernelResponses.SafeResponseRule rule ∨ ExcludesWireSource rule association.sender

theorem encrypted_error_cannot_leave_component
    (c : DataPlaneForwarding.DataPlaneModel) (checked : LocalDeny c)
    (state : DataPlaneForwarding.State) (reply : PacketPolicy.Packet) (output : Nat)
    (encrypted : LocallyEncrypted c state)
    (sameOwner : c.owner output = c.owner state.iface)
    (returns : reply.destination = state.frame.packet.source)
    (protocol : KernelResponses.ResponseProtocol reply.protocol)
    (external : reply.egress ≠ "lo")
    (accepted : Filter.evaluate ((c.outputRules output).map PacketPolicy.Rule.toFilter)
      (c.outputFallback output) reply = .allow) : False := by
  obtain ⟨input, owner, association, member, sa, previous, frame⟩ := encrypted
  obtain ⟨fallback, checks⟩ := checked input output (owner.symm.trans sameOwner.symm) association member
  rw [fallback] at accepted
  obtain ⟨rule, inRules, matched, allows⟩ := Filter.allowed_has_matching_allow _ _ accepted
  obtain ⟨original, inOriginal, rfl⟩ := List.mem_map.mp inRules
  rcases checks original inOriginal allows with safe | destination
  · rcases safe with loopback | ⟨atom, inAtoms, excludes⟩
    · exact external (PacketPolicy.matching_atom matched loopback)
    · have holds := PacketPolicy.matching_atom matched inAtoms
      cases atom <;> simp only at excludes <;> try contradiction
      case protocol name =>
        exact excludes (holds ▸ protocol)
  · apply matching_destination_not_excluded matched _ destination
    simpa [frame, DataPlaneForwarding.encrypt] using returns

def TableDrivenDeny (devices : List DeviceData) : Prop :=
  ∀ device ∈ ({} : DeviceData) :: devices, ∀ association ∈ device.egressPolicies,
    device.outputFallback = .deny ∧ ∀ rule ∈ device.outputRules, rule.verdict = .allow →
      KernelResponses.SafeResponseRule rule ∨ ExcludesWireSource rule association.sender

instance (devices : List DeviceData) : Decidable (TableDrivenDeny devices) := by
  unfold TableDrivenDeny
  infer_instance

theorem table_driven_deny_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (links switches : List (Nat × Nat))
    (checked : TableDrivenDeny devices) :
    LocalDeny (dataPlaneModelFromRecords devices ifaces routes links switches) := by
  intro input output owner association member
  change (ifaceAt ifaces input).owner = (ifaceAt ifaces output).owner at owner
  have result := checked (deviceAt devices (ifaceAt ifaces input).owner)
    (device_at_member_or_default devices _) association member
  change (deviceAt devices (ifaceAt ifaces output).owner).outputFallback = .deny ∧
    ∀ rule ∈ (deviceAt devices (ifaceAt ifaces output).owner).outputRules,
      rule.verdict = .allow → KernelResponses.SafeResponseRule rule ∨
        ExcludesWireSource rule association.sender
  rw [← owner]
  exact result

def combinedConfig (data : GuardedResponseNetwork.Data) : KernelResponses.Config DataPlaneForwarding.State :=
  { GuardedResponseNetwork.responseConfig data with
    generates := fun state =>
      (GuardedResponseNetwork.responseConfig data).generates state ∨
        LocallyEncrypted data.config state }

lemma combined_reply_preserves_safe (data : GuardedResponseNetwork.Data)
    (conditions : PerHopEncapConditions data.config data.expectedEncapStack)
    (pairs : SourceResponseGuards.TableDrivenReplyChecks data.devices data.ifaces data.sourceGuards)
    (coverage : SourceResponseGuards.TableDrivenGuardCoverage data.ifaces data.sourceGuards)
    (defaults : ∀ guard ∈ data.sourceGuards,
      (deviceAt data.devices guard.1).outputFallback = .deny)
    (encryptedChecks : LocalDeny data.config)
    (source : DataPlaneForwarding.State) (header : PacketPolicy.Packet) (output : Nat)
    (valid : GuardedResponseNetwork.Safe data source)
    (enabled : (combinedConfig data).generates source)
    (protocol : KernelResponses.ResponseProtocol header.protocol)
    (selected : (combinedConfig data).selectedRoute source header output)
    (accepted : Filter.evaluate
      (((combinedConfig data).outputRules source output).map PacketPolicy.Rule.toFilter)
      ((combinedConfig data).outputFallback source output)
      (KernelResponses.outputPacket (combinedConfig data) header output) = .allow)
    (external : (combinedConfig data).interfaceName output ≠ "lo") :
    GuardedResponseNetwork.Safe data ((combinedConfig data).emit source header output) := by
  rcases enabled with original | encrypted
  · exact GuardedResponseNetwork.reply_emission_preserves_safe data conditions pairs coverage
      defaults source header output valid original protocol selected accepted external
  · obtain ⟨⟨route, chosen, atSource, atOutput⟩, outputMember, returns⟩ := selected
    have owner := conditions.routeOwner route chosen.1
    rw [atSource, atOutput] at owner
    exact False.elim (encrypted_error_cannot_leave_component data.config encryptedChecks source
      (KernelResponses.outputPacket (combinedConfig data) header output) output encrypted owner
      returns protocol external accepted)

theorem combined_traces_preserve_stack (data : GuardedResponseNetwork.Data)
    (conditions : PerHopEncapConditions data.config data.expectedEncapStack)
    (pairs : SourceResponseGuards.TableDrivenReplyChecks data.devices data.ifaces data.sourceGuards)
    (coverage : SourceResponseGuards.TableDrivenGuardCoverage data.ifaces data.sourceGuards)
    (defaults : ∀ guard ∈ data.sourceGuards,
      (deviceAt data.devices guard.1).outputFallback = .deny)
    (encryptedChecks : LocalDeny data.config)
    {before after : DataPlaneForwarding.State} {actions : List (KernelResponses.Action DataPlaneForwarding.Action)}
    (run : (KernelResponses.lts (GuardedResponseNetwork.network data) (combinedConfig data)).MTr
      (.network before) actions (.network after))
    (initial : GuardedResponseNetwork.Safe data before) :
    EncapStackConsistent data.config data.expectedEncapStack after :=
  (KernelResponses.copied_response_traces_remain_safe
    (GuardedResponseNetwork.network data) (combinedConfig data)
    (GuardedResponseNetwork.Safe data)
    (GuardedResponseNetwork.network_preserves_safe data conditions)
    (combined_reply_preserves_safe data conditions pairs coverage defaults encryptedChecks)
    run initial).1

lemma encryption_step_is_local {c : DataPlaneForwarding.DataPlaneModel} {before after : DataPlaneForwarding.State}
    (step : DataPlaneForwarding.Step c before .encrypt after) : LocallyEncrypted c after := by
  cases step with
  | encrypt association sa selected installed bound =>
    exact ⟨_, rfl, association, (matched_policy_is_configured selected).1, sa, _, rfl⟩

lemma network_trace_in_response_system {S A : Type} (network : Cslib.LTS S A)
    (config : KernelResponses.Config S) {before after : S} {actions : List A}
    (run : network.MTr before actions after) :
    (KernelResponses.lts network config).MTr (.network before)
      (actions.map KernelResponses.Action.network) (.network after) := by
  induction run with
  | refl => exact .refl
  | stepL first tail ih => exact .stepL (.network first) ih

end TDN.EncryptedResponseGuards
