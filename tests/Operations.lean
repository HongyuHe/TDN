import TDN.Targets.Operations
open TDN.Targets

-- A useful NTP reply cannot establish synchronization when no clock was synchronized.
def unsynchronizedTime : TimeSynchronizationModel Unit Unit where
  components := {()}
  inner := fun _ => True
  outer := fun _ => False
  redManagementService := fun _ => False
  grayManagementService := fun _ => False
  grayFirewall := fun _ => False
  locatedIn := fun _ n => n = .red
  trusted := fun _ => True
  synchronizedTo := fun _ _ => False

example : ¬ msc_trusted_time_synchronization unsynchronizedTime := by
  intro h
  obtain ⟨s, _, _, hs⟩ := h.1 () (by simp [unsynchronizedTime]) (Or.inl trivial)
  exact hs

-- DNS's threshold server-specified alternative does not require the optional lookup objective.
def explicitDNS : DefaultsModel Unit where
  components := {()}
  networkDevice := fun _ => True
  originalDefaults := fun _ => {⟨"initial-admin", .account⟩}
  changed := fun _ _ => True
  removed := fun _ _ => False
  dnsServers := fun _ => [Sum.inl ⟨1, by decide⟩]
  dnsServicesDisabled := fun _ => False
  dnsLookupDisabled := fun _ => False
  automaticRemoteBootDisabled := fun _ => True
  dnsLookupObjectiveSelected := false

example : msc_defaults_dns_and_boot_configuration explicitDNS := by
  simp [msc_defaults_dns_and_boot_configuration, explicitDNS]

example : ¬ msc_defaults_dns_and_boot_configuration
    { explicitDNS with dnsLookupObjectiveSelected := true } := by
  simp [msc_defaults_dns_and_boot_configuration, explicitDNS]
