# MSC in Answer Set Programming

The ASP implementation uses clingo 5.8.0 and the same pinned node-1 evidence as the Lean MSC model.
The generated [facts.lp](../../artifacts/msc-node1-asp/facts.lp) contains ordinary ASP facts with named predicates, readable addresses, and comments separating declarations, observations, and derived inputs.
No TSV fact files are required to run the ASP model.

The implementation maps the original 46 Lean theorem names to explicitly scoped ASP checks. The October 2026 Lean review added forwarding contracts, Outer Firewall cuts, and intended IPsec configuration checks. Those extensions are outside the ASP comparison; new reports list their names in `unmapped_lean_theorems`.
A completed counterexample query returns UNSAT when no violation exists in that scope, or SAT with violating tuples.
The solver result is not an independently checked Lean proof certificate.
The [three-way comparison](../../docs/MSC_Lean_Datalog_ASP_comparison.md) explains the practical results and the differences in proof scope.

## Setup and run

Run the commands from `/Users/hongyu/Projects/Formal/TDN`.
The `.venv-asp` environment has already been created on the configured Mac.

```sh
python3 -m venv .venv-asp
.venv-asp/bin/python -m pip install -r asp/requirements.txt
.venv-asp/bin/python scripts/run_msc_asp.py
```

The runner verifies the original snapshot, renders native ASP inputs, grounds the program, checks the base model, and asks all 46 counterexample questions.
It exits with status 1 if a property fails and fails with an error if validation, grounding, solving, or model completeness fails.
The default per-solve timeout is 60 seconds; it excludes parsing and grounding.
Use `--timeout SECONDS` to change that limit.
An interrupted or unknown solve is an error, never a successful proof.

The baseline outputs are in `artifacts/msc-node1-asp/`:

| File | Meaning |
|---|---|
| `facts.lp` | Human-readable deployment facts, observations, evidence hashes, and check catalog |
| `packet_cases.lp` | Generated firewall regression cases, explicitly separate from observations |
| `answers.lp` | Native ASP `result(...)` and `violation(...)` atoms |
| `answer_set.lp` | All shown atoms from the unique base stable model |
| `relations.json` | Structured paths, decisions, transmissions, deliveries, and other derived relations |
| `report.json` | Per-property SAT/UNSAT results, witnesses, scope labels, timings, hashes, and solver statistics |
| `comparison.json` | Lean/ASP/Datalog behavioral comparison and timing measurements |
| `experiments/` | Saved synthetic mutations produced by the comparison runner |

The generation process does not contact node-1 or change the deployment.
Generated files should be regenerated from source evidence rather than edited to make a check pass.

## Read a fact

The following facts describe the real imported I_A1 declarations and first forwarding rule:

```prolog
device("I_A1", inner, "A", "S1").
interface("I_A1", "gray", gray, "10.100.1.2/24").
forward_table("I_A1", drop).
forward_rule("I_A1", 0).
input_interface("I_A1", 0, "red").
output_interface("I_A1", 0, "gray").
source_range("I_A1", 0, ipv4(10,1,1,0), ipv4(10,1,1,255)).
destination_range("I_A1", 0, ipv4(10,2,1,0), ipv4(10,2,1,255)).
requires_policy("I_A1", 0, out, 101).
```

The ACCEPT rule requires the outbound IPsec policy with request ID 101.
The chain defaults to DROP.
Omitted rule fields are wildcards within the supported parser's semantics; an absent entire table remains unknown.
IPv4 terms preserve octet order without overflowing clingo's signed integer representation.
Packet policy tags use `none` or `some(Reqid)`, so missing policy and policy ID zero remain distinct.

The original evidence bundle remains the source of truth.
The ASP facts are a partial projection of its information, just as `Deployment.lean` and the Datalog input relations are projections.
`authorized` pairs come from declared inner peer relationships; they do not establish separate organizational approval.
`packet_case` tuples are generated tests, not observed network traffic.
`property` facts name checks to perform; they do not assert that the named properties hold.

## Ask for a counterexample directly

The ordinary runner always checks base consistency before interpreting a counterexample result.
A direct clingo query is useful after that validation and after generating the baseline facts.

```sh
.venv-asp/bin/python -m clingo \
  asp/MSC/msc.lp \
  artifacts/msc-node1-asp/facts.lp \
  artifacts/msc-node1-asp/packet_cases.lp \
  -c target=site_a_gray_cut
```

The baseline returns UNSATISFIABLE because the selected Gray graph contains no bypass from I_A1 to I_A2.
The query adds an integrity constraint requiring a violation of `site_a_gray_cut`.
An invalid target name produces an `invalid_query(...)` atom rather than a successful absence claim.
Use one of the 46 names in [coverage.json](coverage.json).

The base program with the default `target=all` is SATISFIABLE even when all properties hold.
A stable model means the facts and rules are consistent; it is not a counterexample unless the query explicitly requires a property violation.
The runner rejects an inconsistent base and also rejects multiple base stable models, preventing either condition from being mistaken for the intended deterministic model.

## Explore failures

Each command creates a copied-input experiment and exits with status 1 because at least one property fails.
The runner prints SAT counterexample witnesses and records all checks in the experiment report.

```sh
.venv-asp/bin/python scripts/run_msc_asp.py --mutation gray-bypass
.venv-asp/bin/python scripts/run_msc_asp.py --mutation unguarded-encryptor
.venv-asp/bin/python scripts/run_msc_asp.py --mutation gray-default-accept
.venv-asp/bin/python scripts/run_msc_asp.py --mutation cross-level-authorization
.venv-asp/bin/python scripts/run_msc_asp.py --mutation missing-sa
```

Standalone experiments go to `artifacts/msc-asp-experiments/<mutation>/`.
The Gray bypass creates a direct cable between I_A1 and I_A2 in the copied model.
Its `site_a_gray_cut` counterexample is the endpoint pair `("I_A1", "I_A2")`.
Its conditional `walk_preserves` check still passes because the edge-invariant premise is false; the separate local invariant and isolation checks fail.

The missing-SA experiment changes a historical observation to unknown.
It fails the sampled-tunnel check while leaving hypothetical readiness-state flow results unchanged.
That separation prevents an absent observation from being silently treated as a healthy gateway.

## Compare all three implementations

Lean and Soufflé must also be available for the comparison command.
The existing Lean toolchain is pinned by the project, and Soufflé is already installed on the configured Mac.

```sh
.venv-asp/bin/python scripts/compare_msc_asp.py --runs 3
.venv-asp/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

The comparison checks the Lean sources and evaluates the actual Lean definitions on all modeled sender/receiver readiness combinations.
It compares graph reachability, generated firewall cases, and complete finite transmission/delivery behavior across all three implementations.
It also reruns the five fact mutations and requires ASP and Datalog to identify the same failed checks.
Temporary Datalog/Lean query files are comparison interfaces only; they are not inputs to the ASP implementation and are removed after comparison.

## Model files and boundaries

| File | Role |
|---|---|
| `msc.lp` | Entry point |
| `topology.lp` | Cable graphs, recursive reachability, labels, peers, and the four Red hosts |
| `policy.lp` | Supported FORWARD-rule matching and structural guard conditions |
| `flow.lp` | All 512 readiness states and symbolic encryption/decryption transitions |
| `properties.lp` | The 46 named violation checks, results, and domain counts |
| `queries.lp` | Counterexample constraints and incremental query externals |
| `show.lp` | Relations exposed in answer sets |
| `coverage.json` | Mapping to Lean theorem names, scopes, and limitations |

The graph rules cover paths of arbitrary finite length by deriving reachable endpoint pairs.
The flow rules cover all 16 host pairs and all 512 states at each endpoint.
Payload values are abstracted because no transition guard examines their contents.
The model does not implement cryptography, Linux refinement, OSPF convergence, timing, or complete management/control-plane behavior.
The general Lean induction and rule/table theorems receive instance-only ASP checks rather than new proofs over arbitrary graphs, rules, or types.

The shared importer and packet-case generator reduce accidental differences between experiments.
Agreement cannot detect bugs common to that shared translation and sampling code.
The ASP structural conditions for all-packet firewall claims have a documented soundness argument, not an independently kernel-checked proof.
The grounder and solver are trusted to establish the reported ASP results.

## References

- [Potassco clingo overview and installation](https://potassco.org/clingo/)
- [Potassco language and system guide](https://github.com/potassco/guide)
