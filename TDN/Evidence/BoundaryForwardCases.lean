import TDN.Evidence.BoundaryTransformCases

namespace TDN.Imported.BoundaryForwardCases
open Compliance Targets Targets.Complete MultiProtocolExecution OuterGrayNativeModel BoundaryTransformCases

def ForwardHookChecks (sample : ForwardCase) (records : Records)
    (d : Deployment) (direction : Direction) : Prop :=
  sample.interface ∈ records.interfaces ∧ sample.interface.HookApplies .forward direction ∧
    sample.route.ingress = sample.entryIface ∧
    Execution.SelectedRoute records.routes sample.route sample.header ∧
    1 < sample.header.hopLimit ∧ sample.header.hopLimit ≤ 255 ∧
    d.ContextLocation records.inventory sample.interface direction (sample.context records) ∧
    (sample.context records).raw.PreHookValid (sample.packet records) .forward

instance (sample : ForwardCase) (records : Records) (d : Deployment) (direction : Direction) :
    Decidable (ForwardHookChecks sample records d direction) := by
  cases direction <;>
    unfold ForwardHookChecks Interface.HookApplies HookDirection Deployment.ContextLocation <;>
    dsimp only [ForwardCase.context] <;> infer_instance

theorem checked_forward_context_is_supported (sample : ForwardCase) (records : Records)
    (d : Deployment) (present : d.processing = some records.inventory)
    (interfaces : d.interfaces = records.interfaces) (direction : Direction)
    (checks : ForwardHookChecks sample records d direction) :
    d.SupportedAt sample.interface direction (sample.context records)
      (d.Observe (sample.packet records)) := by
  obtain ⟨member, applies, entry, selected, ttl, bounded, location, raw⟩ := checks
  have received : MultiProtocolExecution.Step records.configuration sample.entry .receive sample.entered :=
    .receive rfl rfl "new"
  have routed : MultiProtocolExecution.Step records.configuration sample.entered .route (sample.routed records) :=
    .route sample.route rfl rfl selected entry
  refine ⟨records.inventory, present, interfaces.symm ▸ member, applies, ?_, location, raw, rfl,
    fresh_observed_packet_is_supported d _ rfl⟩
  refine ⟨rfl, sample.entered, sample.route, Or.inl received, ?_, routed, rfl, rfl, ?_, entry, rfl⟩
  · intro incoming visible
    have same : incoming = sample.header := Option.some.inj visible.symm
    subst incoming
    intro _
    exact ttl
  · exact (selected_route_depends_on_destination records.routes sample.route sample.header
      (sample.context records).header rfl).mp selected

theorem checked_forward_context_is_accepted (sample : ForwardCase) (records : Records)
    (d : Deployment) (present : d.processing = some records.inventory)
    (interfaces : d.interfaces = records.interfaces) (policies : d.policies = records.projectedPolicies)
    (unique : InterfaceIDsUnique records.interfaces) (direction : Direction)
    (checks : ForwardHookChecks sample records d direction)
    (permits : ∀ policy ∈ d.policies, policy.interface = sample.interface.id →
      policy.direction = direction → policy.hook = .forward →
        policy.Accepts (d.Observe (sample.packet records))) :
    d.AcceptsAt sample.interface.id direction .forward (d.Observe (sample.packet records)) := by
  have supported := checked_forward_context_is_supported sample records d present interfaces direction checks
  refine ⟨fresh_observed_packet_is_supported d _ rfl,
    eligible_routed_packet_has_hook_context d sample.interface direction _ _ supported, ?_⟩
  have coverage := native_policies_have_checked_indices d records.inventory records.ifaceIndex
    (by simpa only [interfaces, Records.projectedPolicies] using policies)
    (interfaces.symm ▸ unique)
  obtain ⟨policy, member, name, policyDirection, hook, only⟩ :=
    policy_coverage_from_checked_indices d coverage sample.interface
      (interfaces.symm ▸ checks.1) direction .forward checks.2.1
  exact ⟨policy, member, name, policyDirection, hook, only,
    permits policy member name policyDirection hook⟩

theorem checked_forward_hook_is_denied (d : Deployment) (interface : String)
    (direction : Direction) (traffic : Traffic)
    (denied : ∀ policy ∈ d.policies, policy.interface = interface →
      policy.direction = direction → policy.hook = .forward →
        Filter.evaluate (policy.rules.map PacketPolicy.Rule.toFilter)
          policy.defaultVerdict traffic.packet = .deny) :
    ¬ d.AcceptsAt interface direction .forward traffic := by
  rintro ⟨_, _, policy, member, name, policyDirection, hook, _, accepted⟩
  change Filter.evaluate (policy.rules.map PacketPolicy.Rule.toFilter)
    policy.defaultVerdict traffic.packet = .allow at accepted
  rw [denied policy member name policyDirection hook] at accepted
  cases accepted

end TDN.Imported.BoundaryForwardCases
