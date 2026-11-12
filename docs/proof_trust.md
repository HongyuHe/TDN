# Trust in TDN proofs

TDN uses `native_decide` for concrete, computable deployment checks. Lean runs each decision procedure through its compiled evaluator. A successful result supports the ordinary proof that applies the general network theorem to the captured records.

The reusable network arguments remain ordinary Lean proofs. The kernel checks their proof terms and the applications that combine them with deployment facts. Native evaluation adds an explicit trust assumption for the concrete checks. The kernel accepts the recorded evaluation result rather than repeating that computation itself.

## Trusted software

The trusted computing base is the software whose correctness the result depends on. TDN explicitly includes the following components:

- Lean's kernel and its standard logical foundations: `propext`, `Classical.choice`, and `Quot.sound`.
- Lean's native decision tactic, compiler, evaluator, and runtime. The executed implementations selected by `@[implemented_by]` and `@[extern]` are included.
- The C compiler, LLVM when used by that compiler, linker, and native libraries used to build and execute the checked code. The validation worker's Lean 4.34.1 distribution uses Clang/LLVM 22.1.4 through `leanc`. A build that selects another C compiler also trusts that compiler.

Lean 4.34.1 records a native decision as a generated axiom with a name containing `._native.native_decide.ax_`. Its statement says that a closed Boolean decision evaluates to `true`. The tactic rejects a decision that evaluates to `false`. The current tactic does not use the older `Lean.ofReduceBool` mechanism.

The official [native_decide reference](https://lean-lang.org/doc/reference/latest/Tactic-Proofs/Tactic-Reference/) describes the compiler trust requirement. The project's pinned implementation is in [Lean.Meta.Native](https://github.com/leanprover/lean4/blob/5045d0056413266e57c625dcd7c365b10e377c52/src/Lean/Meta/Native.lean).

## Audit policy

[`audit_axioms.lean`](../scripts/construction/audit_axioms.lean) examines every imported TDN theorem. It accepts the three foundational axioms above. For each additional axiom, it requires the generated native-decision name, a safe closed declaration, and exactly the Boolean equality shape emitted by `native_decide`. It then evaluates the decision again and requires `true`. Each distinct decision is evaluated once per audit.

[`export_proof_audit.lean`](../scripts/construction/export_proof_audit.lean) applies the same policy to submitted proof roots and records the number of native decisions. Both tools share the policy in [`NativeDecide.lean`](../TDN/Import/NativeDecide.lean). An arbitrary axiom, `sorryAx`, a forged native name with the wrong statement, or a false decision fails the audit. Re-evaluation checks the recorded assertion under the same compiler trust assumption; it does not provide an independent verification of the compiler.

Some checks mention a deployment parameter even though their result depends only on fields replaced by captured records. `unfold_check_parameters` unfolds those parameter-dependent expressions while keeping closed evidence folded. Lean verifies that the new goal is definitionally equal to the original goal. Any parameter that still affects the check causes failure. The following `native_decide` therefore checks a closed version of the same proposition.

Some checks have custom decision procedures that need the original predicate to remain intact. `close_check_with emptyDeploymentForChecks` substitutes a closed representative for an unused deployment parameter and requires definitional equality with the original goal. The representative supplies empty values only for fields that do not affect the obligation. If the replacement changes the obligation, Lean rejects the step. The original universally parameterized theorem is preserved.

Use native evaluation for substantial closed checks. Keep direct symbolic proofs for general arguments. Small arithmetic facts in reusable proofs can retain `decide`, and checks involving noncomputable definitions need a symbolic proof or kernel reduction. A Boolean expression such as `decide (route.metric ≤ other.metric)` inside a checker is ordinary executable code. It remains part of the decision procedure that native evaluation runs.

## Evidence and model boundaries

Compiler trust does not establish that a snapshot matches the deployed network. Collection, parsing, source interpretation, and the correspondence between the Lean packet model and real implementations still need their own validation. The indexed route and ACL certificates retain their coverage and soundness proofs. Native evaluation changes how their concrete conditions are checked; it does not change the requirement statements or remove certificate obligations.

Run the full theory build, regression tests, and axiom audit together:

```sh
lake build TDN
python3 scripts/construction/run_lean_tests.py
lake env lean scripts/construction/audit_axioms.lean
```
