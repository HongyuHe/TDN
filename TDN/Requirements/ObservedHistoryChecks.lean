import TDN.Requirements.MacsecAuthenticationHistory

namespace TDN.Requirements.Msc
open Compliance

instance (record : HistoricalEvent) : Decidable record.SetupOnly := by
  unfold HistoricalEvent.SetupOnly
  cases record.event <;> infer_instance

def HistoryOrderChecked (first second : HistoricalEvent) : Prop :=
  (first.observer = second.observer ∧ first.component = second.component ∧
    first.localPosition < second.localPosition) ∨
  match first.event, second.event with
  | .historySend session sender receiver message, .historyReceive otherSession otherSender otherReceiver otherMessage =>
    message ≠ [] ∧ first.component = sender ∧ second.component = receiver ∧ first.epoch = second.epoch ∧
    session = otherSession ∧ sender = otherSender ∧ receiver = otherReceiver ∧ message = otherMessage
  | _, _ => False

instance (first second : HistoricalEvent) : Decidable (HistoryOrderChecked first second) := by
  unfold HistoryOrderChecked
  cases first.event <;> cases second.event <;> infer_instance

lemma checked_history_order_is_direct {first second : HistoricalEvent}
    (checked : HistoryOrderChecked first second) : first.DirectPrecedes second := by
  rcases checked with localOrder | messageOrder
  · exact Or.inl localOrder
  · cases sent : first.event <;> cases received : second.event <;>
      simp only [sent, received] at messageOrder <;> try contradiction
    obtain ⟨nonempty, sender, receiver, epoch, session, senderMatch, receiverMatch, message⟩ := messageOrder
    exact Or.inr ⟨_, _, _, _, nonempty, sender, receiver, epoch, sent,
      by simpa only [session, senderMatch, receiverMatch, message] using received⟩

def HistoryDependencyChecked (history : ObservedHistory) (edge : Nat × Nat) : Prop :=
  edge.1 < edge.2 ∧
  match history.entries[edge.1]?, history.entries[edge.2]? with
  | some first, some second => first.position = edge.1 ∧ second.position = edge.2 ∧ HistoryOrderChecked first second
  | _, _ => False

instance (history : ObservedHistory) (edge : Nat × Nat) : Decidable (HistoryDependencyChecked history edge) := by
  unfold HistoryDependencyChecked
  cases history.entries[edge.1]? <;> cases history.entries[edge.2]? <;> infer_instance

def ObservedHistoryChecked (history : ObservedHistory) : Prop :=
  (history.entries ≠ [] → history.stream ≠ "" ∧ history.epoch ≠ "") ∧
  (∀ record ∈ history.entries, record.source ≠ "" ∧ record.observer ≠ "" ∧ record.epoch = history.epoch ∧
    record.position < history.cut ∧ record.SetupOnly) ∧
  history.entries.Pairwise (fun first second => first.position < second.position) ∧
  ∀ edge ∈ history.dependencies, HistoryDependencyChecked history edge

instance (history : ObservedHistory) : Decidable (ObservedHistoryChecked history) := by
  unfold ObservedHistoryChecked
  infer_instance

theorem observed_history_checks_sound {history : ObservedHistory} (checked : ObservedHistoryChecked history) :
    history.Valid := by
  refine ⟨checked.1, checked.2.1, checked.2.2.1, ?_⟩
  intro edge member
  have checkedEdge := checked.2.2.2 edge member
  refine ⟨checkedEdge.1, ?_⟩
  cases firstAt : history.entries[edge.1]? with
  | none => simp [HistoryDependencyChecked, firstAt] at checkedEdge
  | some first =>
    cases secondAt : history.entries[edge.2]? with
    | none => simp [HistoryDependencyChecked, secondAt] at checkedEdge
    | some second =>
      simp only [HistoryDependencyChecked, firstAt, secondAt] at checkedEdge
      exact ⟨first, List.mem_of_getElem? firstAt, second, List.mem_of_getElem? secondAt,
        checkedEdge.2.1, checkedEdge.2.2.1, checked_history_order_is_direct checkedEdge.2.2.2⟩

lemma deployment_coverage_with_history {S A : Type} {d : Deployment} {model : ForwardingModel S A}
    (covered : model.CoversDeployment d) (history : ObservedHistory) (valid : history.Valid)
    (installations : List MACsecHistoryInstallation) (material : String → Option (List UInt8)) :
    {model with
      history := history, macsecInstallationHistory := installations,
      historicalKeyMaterial := material}.CoversDeployment d := by
  obtain ⟨processing, faithful, steps, sources, oldHistory, links, policies, headers, coherent,
    macKeys, ipKeys, networks, peers, devices, ifaces, tunnels, interfaces, states, physical, entries, mac, ip⟩ := covered
  exact ⟨processing, faithful, steps, sources, valid, links, policies, headers, coherent,
    macKeys, ipKeys, networks, peers, devices, ifaces, tunnels, interfaces, states, physical, entries, mac, ip⟩

end TDN.Requirements.Msc
