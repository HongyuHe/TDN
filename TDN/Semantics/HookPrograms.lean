import TDN.Semantics.PacketProcessing

namespace TDN.PacketPolicy

def Rule.withContext (context : List Atom) (rule : Rule) : Rule :=
  { rule with atoms := context ++ rule.atoms }

def contextProgram (context : List Atom) (rules : List Rule) : List Rule :=
  rules.map (Rule.withContext context)

lemma context_rule_matches (context : List Atom) (rule : Rule) (packet : Packet)
    (holds : ∀ atom ∈ context, atom.holds packet) :
    (rule.withContext context).toFilter.accepts packet = rule.toFilter.accepts packet := by
  simp only [Rule.toFilter, Rule.withContext, List.all_append]
  have checked : context.all (fun atom => decide (atom.holds packet)) = true := by
    exact List.all_eq_true.mpr (fun atom member => decide_eq_true (holds atom member))
  rw [checked]
  rfl

theorem context_program_evaluation (context : List Atom) (rules : List Rule)
    (fallback : Filter.Verdict) (packet : Packet)
    (holds : ∀ atom ∈ context, atom.holds packet) :
    Filter.evaluate ((contextProgram context rules).map Rule.toFilter) fallback packet =
      Filter.evaluate (rules.map Rule.toFilter) fallback packet := by
  induction rules with
  | nil => rfl
  | cons rule remaining ih =>
    simp only [contextProgram, List.map_cons, Filter.evaluate]
    rw [context_rule_matches context rule packet holds]
    split
    · rfl
    · exact ih

lemma context_rule_requires_context (context : List Atom) (rule : Rule) (packet : Packet)
    (matched : (rule.withContext context).toFilter.accepts packet = true) :
    ∀ atom ∈ context, atom.holds packet := by
  intro atom member
  exact matching_atom matched (List.mem_append_left rule.atoms member)

theorem context_program_rejects_wrong_context (context : List Atom) (rules : List Rule)
    (packet : Packet) (wrong : ∃ atom ∈ context, ¬ atom.holds packet) :
    Filter.evaluate ((contextProgram context rules).map Rule.toFilter) .deny packet = .deny := by
  cases outcome : Filter.evaluate ((contextProgram context rules).map Rule.toFilter) .deny packet with
  | deny => rfl
  | allow =>
    obtain ⟨selected, member, matched, _⟩ := Filter.allowed_has_matching_allow
      ((contextProgram context rules).map Rule.toFilter) packet outcome
    obtain ⟨guarded, guardedMember, same⟩ := List.mem_map.mp member
    obtain ⟨raw, rawMember, guardedEq⟩ := List.mem_map.mp guardedMember
    subst selected
    subst guarded
    obtain ⟨atom, atomMember, fails⟩ := wrong
    exact False.elim (fails (context_rule_requires_context context raw packet matched atom atomMember))

end TDN.PacketPolicy

namespace TDN.LinkAdmission

def Program.withContext (context : List PacketPolicy.Atom) (program : Program) : Program :=
  { program with rules := PacketPolicy.contextProgram context program.rules }

lemma Program.context_evaluation (context : List PacketPolicy.Atom) (program : Program)
    (packet : PacketPolicy.Packet) (holds : ∀ atom ∈ context, atom.holds packet) :
    (program.withContext context).Accepts packet ↔ program.Accepts packet := by
  unfold Program.Accepts Program.withContext
  rw [PacketPolicy.context_program_evaluation context program.rules program.fallback packet holds]

def IfacePolicy.withContext (name : String) (policy : IfacePolicy) : IfacePolicy :=
  { inbound := policy.inbound.withContext [.ingress name]
    outbound := policy.outbound.withContext [.egress name] }

def contextPolicies (name : Nat → String) (policies : List (Nat × IfacePolicy)) :
    List (Nat × IfacePolicy) :=
  policies.map fun entry => (entry.1, entry.2.withContext (name entry.1))

lemma lookup_context_policies (name : Nat → String) (policies : List (Nat × IfacePolicy))
    (iface : Nat) :
    lookup (contextPolicies name policies) iface =
      (lookup policies iface).map (fun policy => policy.withContext (name iface)) := by
  induction policies with
  | nil => rfl
  | cons entry rest ih =>
    unfold lookup contextPolicies at *
    simp only [List.map_cons, List.find?_cons]
    by_cases same : entry.1 = iface
    · simp [same]
    · have missed : (entry.1 == iface) = false := by simp [same]
      simpa only [missed] using ih

theorem contextual_link_admission_preserves_actual_hook (name : Nat → String)
    (policies : List (Nat × IfacePolicy)) (iface : Nat) (outbound : Bool) (frame : Frame) :
    Admitted (contextPolicies name policies) iface outbound
        (frame.Packet (if outbound then "" else name iface) (if outbound then name iface else "")) ↔
      Admitted policies iface outbound
        (frame.Packet (if outbound then "" else name iface) (if outbound then name iface else "")) := by
  unfold Admitted
  rw [lookup_context_policies]
  constructor
  · rintro ⟨policy, selected, admitted⟩
    obtain ⟨raw, rawSelected, same⟩ := Option.map_eq_some_iff.mp selected
    subst policy
    refine ⟨raw, rawSelected, ?_⟩
    cases outbound <;>
      exact (Program.context_evaluation _ _ _ (by intro atom member; simp only [List.mem_singleton] at member; subst atom; rfl)).mp admitted
  · rintro ⟨policy, selected, admitted⟩
    refine ⟨policy.withContext (name iface), by simp [selected], ?_⟩
    cases outbound <;>
      exact (Program.context_evaluation _ _ _ (by intro atom member; simp only [List.mem_singleton] at member; subst atom; rfl)).mpr admitted

end TDN.LinkAdmission

namespace TDN.MultiProtocolExecution

def Config.withLinkContext (configuration : Config) : Config :=
  { configuration with
    linkPolicies := LinkAdmission.contextPolicies configuration.ip.interfaceName configuration.linkPolicies }

theorem link_context_preserves_native_admission (configuration : Config) (iface : Nat)
    (outbound : Bool) (frame : LayeredFrame.Frame) :
    configuration.withLinkContext.LinkAdmitted iface outbound frame ↔
      configuration.LinkAdmitted iface outbound frame := by
  unfold Config.LinkAdmitted Config.withLinkContext
  simp only
  constructor
  · rintro ⟨encoded, selected, describes, admitted⟩
    exact ⟨encoded, selected, describes,
      (LinkAdmission.contextual_link_admission_preserves_actual_hook ..).mp admitted⟩
  · rintro ⟨encoded, selected, describes, admitted⟩
    exact ⟨encoded, selected, describes,
      (LinkAdmission.contextual_link_admission_preserves_actual_hook ..).mpr admitted⟩

theorem link_context_preserves_native_step_admission (configuration : Config)
    (before : State) (operation : Action) (after : State) :
    configuration.withLinkContext.LinkStepAdmitted before operation after ↔
      configuration.LinkStepAdmitted before operation after := by
  simp only [Config.LinkStepAdmitted, link_context_preserves_native_admission]
  rfl

end TDN.MultiProtocolExecution
