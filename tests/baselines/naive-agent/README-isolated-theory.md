# One-fault TDN experiment

The run `runs/20261112-isolated-theory-01` tests the same one hundred intended cases separately. Every network starts from its restored clean configuration. The runner applies one mutation, verifies its behavior on the actual device, collects a fresh snapshot, imports the observations, and invokes Lean. It restores the clean configuration before introducing the next mutation. Five independent deployments can run concurrently. Each deployment has at most one injected case active.

`isolated_worker.py` performs the worker operations. Before each mutation and after its restoration, it compares public configuration files, filters, routes, routing-policy tables, interface states, and source-check settings against the clean control. A mismatch stops the network's sequence. Each mutation journal must contain exactly one case. A single change can violate more than one document requirement; the experiment isolates the injected change rather than asserting that no other clause is affected.

`run_isolated_theory.py` collects and imports every network afresh. The general theory, parser code, and two existing proof templates are hashed before the run. The driver uses the same `SnapshotCompliance.lean` and `HeaderCompliance.lean` applications as the previous experiment. It adds no checks based on the injected requirement. The raw snapshot and imported Lean inputs are retained for every case. A Lean error caused by a false finite condition counts as rejection. A parser error or compiler infrastructure failure has a separate status and does not count as detection.

The passive collector option omits unrelated all-host ping and management TLS tests. It retains the full configuration/state inventory and its before/after stability checks. Omitted active tests are marked incomplete in the manifest. The designated fault still receives its own actual packet or loaded-configuration check. Tunnel establishment is checked after every restoration and mutation.

The preparation audit found old IKE sessions still closing in several early captures. The reset procedure now loads the intended connection settings, force-removes earlier sessions, and waits for established IKE sessions and installed CHILD SAs. Captures containing closing, connecting, or rekeying sessions are repeated. Parallel fully established sessions are allowed. An intermediate single-session check was too restrictive and is recorded among the runner revisions; the affected attempts are retained separately and repeated.

`score_isolated_theory.py` requires all one hundred cases to finish. It verifies the clean controls, single-mutation journals, successful live checks, stable snapshots, actual Lean outcomes, source/input hashes, and restoration records before computing the result. The source-address interpretation for net-04 PF-18 remains qualified; the scores also exclude that case. The five deployments are left in their checked clean configurations.

The resulting score applies to the instantiated data-plane stack, protocol, and multicast proofs. It is not a claim that every existing RG theorem was instantiated or that passing the selected proofs establishes complete CSfC compliance. The Astra and Sol results remain the earlier blind document audits with twenty mutations per network. Their trials are not rerun in this experiment.

Run locally with the experiment virtual environment:

```sh
tests/baselines/naive-agent/.runtime/venv/bin/python tests/baselines/naive-agent/run_isolated_theory.py
tests/baselines/naive-agent/.runtime/venv/bin/python tests/baselines/naive-agent/score_isolated_theory.py
```

The runner refuses to overwrite a new run. Resume only after reviewing the last recorded state. The source directory and remote run must remain available. Private credentials stay on the worker and are excluded from downloaded archives. No commit or push is performed.
