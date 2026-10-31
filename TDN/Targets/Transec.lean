import TDN.Targets.Components
import TDN.Semantics.CoverTraffic

namespace TDN.Targets

/-- RG-032's selected size-masking interpretation has a concrete sender model.
The sender emits fixed records and keeps a bounded FIFO. Shared send times and
link outcomes imply equal size observations. The timing premise remains explicit. -/
def ScheduledCoverGuarantee (config : CoverTraffic.Config) : Prop :=
  config.Valid ∧
  ∀ firstDeadline actions finish,
    (CoverTraffic.system config).MTr (CoverTraffic.initial firstDeadline) actions finish →
      CoverTraffic.Safe config finish

theorem scheduled_cover_guarantee_from_parameters (config : CoverTraffic.Config)
    (checked : config.Valid) : ScheduledCoverGuarantee config :=
  ⟨checked, fun _ _ _ run =>
    CoverTraffic.all_executions_have_bounded_queues_and_fixed_records checked run⟩

/-- An installed mechanism is bound to its RG-032 applicability record. Active is
observed for the captured process interval. Continued execution assumes that the
reviewed sender and MACsec path stay installed and follow their recorded semantics. -/
structure CoverInstallation where
  device : String
  use : TransecUse
  sender : CoverTraffic.Config
  active : Bool
  deriving DecidableEq, Repr

/-- Public-Internet applicability and the selected OR-9 objective retain their
separate triggers. Enabling the bounded mechanism supplies the size-masking reading
of TRANSEC. Product approval and other transmission-security services are not supplied
by this record. INT032-COVER records the chosen interpretation and its limits. -/
theorem transec_conditions_from_cover_installations (installations : List CoverInstallation)
    (binding : ∀ i ∈ installations, i.use.enabled = i.active)
    (checked : ∀ i ∈ installations,
      (i.use.publicInternet = true ∨
        (i.use.objectiveSelected = true ∧ i.use.externalMACsec = true ∧
          i.use.outerFirewallAttached = true)) → i.active = true ∧ i.sender.Valid) :
    msc_transec_conditions (installations.map CoverInstallation.use) ∧
    ∀ i ∈ installations,
      (i.use.publicInternet = true ∨
        (i.use.objectiveSelected = true ∧ i.use.externalMACsec = true ∧
          i.use.outerFirewallAttached = true)) → ScheduledCoverGuarantee i.sender := by
  constructor
  · intro use member
    obtain ⟨i, present, same⟩ := List.mem_map.mp member
    subst use
    constructor
    · intro internet
      exact (binding i present).trans (checked i present (Or.inl internet)).1
    · intro objective macsec firewall
      exact (binding i present).trans
        (checked i present (Or.inr ⟨objective, macsec, firewall⟩)).1
  · intro i present applicable
    exact scheduled_cover_guarantee_from_parameters i.sender (checked i present applicable).2

end TDN.Targets
