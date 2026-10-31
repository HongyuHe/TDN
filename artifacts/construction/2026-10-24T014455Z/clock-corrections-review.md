# RG-042 clock-correction contribution

The two source rows require Inner/Red-management clocks to synchronize to a trusted Red source and Outer/Gray-management/Gray-firewall clocks to synchronize to a trusted Gray Management source. The existing encompassing definition preserves both clauses. The new general assignment theorem exposes source location, trust and actual synchronization as explicit local obligations. It remains conditional until each obligation is supported.

The retained Red experiment records two FreeBSD guest corrections. The Gray experiment records two Debian Linux guest corrections in a different deployment. The importer binds each guest connection, source address, actual ntpdate -b command, query before adjustment and query afterward. It reads decimal offsets exactly as integer microseconds. The four final estimates are26,18,-16 and3 microseconds. Each is smaller in magnitude than the original displacement and below the selected1000-microsecond measurement threshold. That threshold is an analysis choice, not a bound imposed by the CP.

A query can print 'step time' without changing the clock. The importer therefore requires an actual successful -b invocation and source-specific correction diagnostic. The Gray collector records completion time after subprocess.run returns. Those timestamps belong to the collecting host, so a guest clock step does not reorder observations. Red records provide both command start and end. Two failed --version commands are retained but are not used as successful correction evidence.

The general improvement proof uses integer magnitude comparison and the checked finite correction records. No new temporal framework is needed for those finite measured inequalities. The source trust and NTP implementation remain external to the arithmetic. No proof turns a time query into trusted synchronization.

Whole RG-042 remains unproved. Neither experiment supplies organizational trust in the time authority. The Gray server attaches to the Gray data interface; the required Gray Management Network placement has not been established. The temporary servers were removed afterward. No persistent synchronization, future drift bound, complete set of management-service clocks, or complete Gray-firewall clock inventory is claimed. Red and Gray records must not be presented as one atomic snapshot.

The meaningful contribution is a checked technical correction and its exact remaining connection to SR-3/SR-4. These gaps are recorded for the Construction Agent to assess alongside other retained time evidence. Optional management does not gate the separate data-path proofs.

Files: TDN/Semantics/ClockSamples.lean, TDN/Targets/TimeSynchronization.lean, TDN/Evidence/FreshClockCorrections.lean, scripts/construction/import_clock_corrections.py, tests/test_clock_corrections.py. Eleven mutation tests and the Lean evidence build pass. Independent Construction review is required before mapping the contribution.
