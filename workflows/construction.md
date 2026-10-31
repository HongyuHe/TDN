# Evidence-driven construction of CSfC theories

This workflow coordinates an Evidence Agent and a Construction Agent to refine the current Lean theory from the CSfC preprocessing results. It targets all 76 requirement groups. Each group should have an encompassing specification and a general theorem supported by reusable proofs. Concrete networks supply the facts, witnesses, and checks needed to apply those theorems. Continue until all actionable obligations are proved and every remaining clause has a justified limitation under the completion criteria in Section 7.

The initial construction run was authorized on October 17, 2026. These continuation objectives were updated on October 22, 2026. Preserve the initial run and record subsequent work under `artifacts/construction/`, with timestamps in UTC.

The Construction Agent must be an independent subagent of type **GPT-6 Astra with High reasoning**, using model `gpt-6-astra` and reasoning effort `high`. The Evidence Agent must be an independent subagent of type **GPT-6.1 Sol with High reasoning**, using model `gpt-6.1-sol` and reasoning effort `high`. Launch each with fresh context. Neither agent may inherit the coordinator's conversation or the other agent's private working context. They exchange explicit requests, responses, and artifacts through the coordinator and the recorded workflow.

The active workflow tools live under [`scripts/construction`](../scripts/construction/README.md). Theory importers, validation and coordination tools are at that directory's top level. Emulation, collection and protocol tools live under [`scripts/construction/evidence`](../scripts/construction/evidence/README.md), with specifications in its `profiles/` directory. Use those locations for new commands and agent handoffs. Historical snapshots and checkpoints retain their original paths and hashes.

## 1. Inputs and scope

The preprocessing artifacts define the obligations and representative cases. Current implementation limits must not silently narrow that scope.

| Input | Purpose |
| --- | --- |
| [Requirement groups](../artifacts/extraction/requirements/requirement_groups.md) | All 76 proposed statements, their applicability, exceptions, and source passages |
| [Example networks](../artifacts/extraction/networks/networks.md) | Nine concrete network topologies |
| [Partial configurations and alternatives](../artifacts/extraction/networks/configurations.md) | Seventeen records containing arrangements and configuration choices |
| [Protocol exchanges](../artifacts/extraction/networks/protocol_exchanges.md) | The illustrated IKEv2 exchange and its selected protocol behavior |
| [Requirement mappings](../artifacts/extraction/networks/network_requirement_links.md) | Clause-specific relationships between examples and requirements |
| [Source index](../artifacts/extraction/source/source_index.jsonl) and [original document](../artifacts/extraction/source/CSfC_documentation_v1.3.0.pdf) | Authoritative passages for resolving interpretation questions |
| [Device roles and ontology](../artifacts/extraction/roles/roles.md) | Source-linked vocabulary for components and relationships |

Explicit textual descriptions and applicable requirements supply details omitted from figures. The agents must preserve conditions, exceptions, and alternative choices when formalizing a group. Resolve ambiguity and conflicting wording through the original-document review and documented interpretation procedure in Section 1.2.

All 76 statements enter the construction register from the beginning. The agents may work incrementally, but must not replace the full target set with a smaller pilot or exclude difficult statements because the current emulation lacks their evidence.

### 1.1. Retrieve missing official documents and resources

Both agents are authorized to search the web and retrieve official documents and resources needed to interpret requirements or supply supporting evidence. No separate approval is needed for each retrieval. Sources may include CSfC annexes, referenced standards, official implementation documentation, and the [NSA CSfC Components List](https://www.nsa.gov/Resources/Commercial-Solutions-for-Classified-Program/Components-List/). Use the issuing organization's official publication or repository as the authoritative source. Search results and third-party summaries may help locate it, but do not replace the source itself.

Treat “Missing referenced documents” as a retrieval task before accepting it as a limitation. Review existing entries in that category, locate the referenced materials, and reopen affected obligations when the missing information becomes available. If retrieval fails, record the official locations searched, access failures or unavailable versions, and the exact clauses that remain blocked. Continue work on independent clauses.

Preserve retrieved materials under the active run's `artifacts/construction/<run>/references/` directory. Record the title, issuing organization, requested and final source URLs, document version or publication date, UTC retrieval timestamp, content hash, and affected requirement groups. Retain the downloaded document or a captured copy of the relevant webpage, with section or page references for the passages used. Share the recorded artifacts through the coordinator so both agents use the same source versions.

Match referenced versions to the CSfC document being formalized. When only a newer version is available, record the difference and its effect on the obligation; do not silently replace the original requirement. For changing resources such as component lists, record the captured date and the product and version identifiers used in any comparison. An official listing supplies evidence about the listed product; establishing that the deployed component matches that listing requires separate deployment evidence.

Web retrieval must preserve the archive restrictions in Section 2. Neither agent may use online repository history, reports, or other copies to recover the forbidden archived theory.

### 1.2. Resolve ambiguity using the original document

Whenever ambiguity, inconsistency, or conflicting wording affects an obligation, both agents must double-check the relevant original document. Sentence extractions and requirement groups may omit context. Read the surrounding paragraphs, definitions, exceptions, cross-references, and applicable table headers, notes, and figure captions. Inspect the rendered pages when layout affects meaning. Use the official references retrieved under Section 1.1 when the document delegates a requirement to another source.

If ambiguity remains after that review, the agents should select one of the most plausible and reasonable interpretations and continue construction. They are authorized to make that choice without waiting for separate user approval. Base the choice on the source context, the architecture described, and consistency with applicable requirements. Ease of proof alone is not a justification. Preserve the competing passages and explain how the chosen reading handles them. A documented choice states the interpretation used by the theory; it does not claim that the issuing organization has resolved the ambiguity.

Maintain a separate `artifacts/construction/<run>/interpretations.md` file as part of the final deliverables. Give each decision a stable identifier and record:

- Affected requirement groups and clauses, with original quotations and document version, page, and section references.
- The original context inspected and any information lost or distorted during extraction.
- The plausible interpretations considered, the selected interpretation, and the reasons for choosing it.
- The resulting formal meaning, assumptions, affected declarations, and consequences for evidence collection or emulation.
- The decision date, participating agents, and any later revision with its reason.

The coordinator shares each decision with both agents so that evidence provision and proof construction use the same reading. Link the decision from the construction register and relevant Lean comments. Revisit existing interpretation blockers under this procedure. Reserve unresolved-interpretation status for cases where the source review cannot support any reasonable choice, and document why. An ambiguity with a defensible documented interpretation must not stop otherwise tractable proof work.

## 2. Continue the current theory and preserve archive isolation

Continue from the active `TDN/` tree, its importers, and the current construction register. Preserve a versioned checkpoint before changes. The original archive operation has already been completed. Preserve `archive/v1/` unchanged, keep it excluded from the active build, and do not move the current theory into that archive.

Both agents are forbidden to read, search, import, copy, or receive the archived proofs and libraries. The prohibition also covers archive-derived code, proof descriptions, and comparisons recovered through Git history, reports, conversation transcripts, or other locations. The coordinator must not pass archived implementation details or proof summaries to either agent. Start both agents independently with fresh context containing the specification inputs, these continuation instructions, and permitted current-development artifacts. The current theory may be inspected and refined.

Enforce archive isolation before launching the agents. Use restricted workspace access or an isolated workspace containing only explicitly permitted files. Exclude the archive, repository history, and unreviewed reports or transcripts that could expose archived material. Inspect handoff artifacts for forbidden content. Merely omitting an archive path from a prompt is insufficient. Record the permitted paths and the access restrictions before work begins.

Improve the active importer, models, specifications, and proofs as needed. Existing declaration names, device counts, and module boundaries may be changed when the revision improves source fidelity or reuse. The Evidence Agent may reuse and extend Twinet's emulation infrastructure without consulting the archived Lean development.

## 3. Evidence Agent: choose representative emulations

The Evidence Agent constructs one or several Twinet emulations that collectively represent all extracted networks, configuration choices, and protocol cases that it can implement. The agent should exploit containment between examples to reduce redundant deployments.

An example may be merged into or represented within another emulation only when none of its representative cases is lost. Record the correspondence between the source example and the relevant devices, settings, paths, or protocol scenario in the encompassing emulation. A Lean equivalence proof between examples is not required for deployment selection.

Genuinely different setups must receive separate realizations. They may use separate networks or separately recorded configurations of a reusable deployment. Distinct authentication choices, encryption technologies, encapsulation placements, or management arrangements must remain visible when those differences are part of the extracted cases. A record containing several alternatives may therefore require several runs.

Maintain a coverage register with the following fields:

- Example ID and the particular cases or alternatives being represented.
- Emulation and configuration IDs that provide the evidence.
- The containment or merging justification, when applicable.
- Case-specific observations to collect.
- Any unrepresented case and the reason evidence cannot be provided.

The Evidence Agent improves the MSC profile as needed to support the preprocessing results. Extensions may include additional security levels, MACsec, IPv6, authentication choices, protocol exchanges, or management arrangements. The existing profile is a starting implementation, not the scope definition.

Reusable MSC deployments must retain Twinet's FRR routing and OVS switching stack with native device CLI access, as required for the existing emulation infrastructure. Supplemental namespace or protocol experiments may supply additional evidence when their scope is explicit. Record the runtime backend in every profile and snapshot so that a result from a legacy Linux/static-routing profile cannot be attributed to a native FRR/OVS deployment.

Management cases receive separate evidence and applicability records. Their availability must not gate proofs about the optional-management-free MSC data path.

## 4. Evidence Agent: collect and respond

The Evidence Agent collects versioned snapshots after the relevant emulation state has converged. Record the configuration, software versions, collection interval, collection failures, and source-example coverage for each snapshot. Preserve raw observations alongside normalized exports, with hashes and timestamps sufficient to reproduce the import.

Convergence and collection checks must match the observations used by the proof. Check relevant route, filtering, and tunnel state for consistency across collection when necessary. The plan does not assume that a converged snapshot establishes arbitrary behavior over time. If a proposed statement needs additional event records or other evidence, the Construction Agent must request them explicitly.

The Evidence Agent may accept or reject evidence requests. Every response must identify the affected theorem or clause and provide either the requested artifact or a concrete rejection reason. Valid reasons include external organizational evidence, unavailable physical capabilities, unresolved source meaning, an unsupported mechanism that cannot practically be implemented, or a request that a snapshot cannot answer.

A rejection must distinguish an unavailable observation from a deployment that violates the requirement. Rejections do not remove theorem targets from the construction register. Record what change, if any, could make the request actionable later.

Before rejecting a request because a referenced document or official resource is missing, perform and record the retrieval steps in Section 1.1. A document's absence from the local repository alone is not grounds for rejection.

The Construction Agent specifies the evidence and supporting witnesses required by each general theorem. The Evidence Agent supplies observations and implements justified collection or deployment changes. Record who generates derived information such as region labels or explicit paths. Lean must check the conditions those witnesses are intended to establish; a Python calculation alone does not discharge a proof obligation. Keep each derived value traceable to its source observations and generation procedure.

## 5. Construction Agent: formalize and prove all targets

The Construction Agent works on all 76 proposed statements using the specification and permitted evidence. Translate each requirement group into one encompassing top-level specification, normally using `def … : Prop`. Define the network conditions required by the source, including applicability, alternatives, and exceptions. Introduce a general top-level theorem proving that explicit supporting conditions imply that specification.

Use `lemma` for supporting results: individual-step preservation, record and rule checks, witness steps, initial-state facts, and proofs assembling local assumptions. Use `theorem` for a module's principal reusable guarantees, requirement or clause results, final snapshot applications, and complete delivery or counterexample witnesses. A principal library theorem remains a theorem when another proof reuses it. Choose the keyword by the declaration's role in its module; both general proofs and concrete checks can serve either role, and `by decide` does not determine the keyword. Apply the same convention in Python generators. The keyword convention communicates the organization; reuse comes from the declarations' parameters, assumptions, and dependencies.

For each target, record its source clauses, intended meaning, quantifiers, applicability, assumptions, required evidence, and current proof status. Record separate names and statuses for the specification, general theorem, supporting lemmas, and snapshot applications. Keep partial clause results distinct from establishment of the whole group. Resolve source ambiguities under Section 1.2 and link the selected interpretation to each affected target. Do not hide missing clauses behind placeholder propositions, replace the full specification with its proved subset, or silently choose the easiest interpretation.

### 5.1. Separate general networking, CSfC requirements, and snapshot checks

Organize the theory into three parts with dependencies in one direction:

1. **General network library:** Define relevant behavior such as packet processing, routing, filtering, encryption operations, switching, delivery, and paths. Prove general results about those operations and their composition. These modules must import neither CSfC requirements nor concrete snapshots.
2. **CSfC specifications and general proofs:** Define document-specific roles, architectural constraints, requirement specifications, and reusable proofs that supporting conditions imply those specifications. These modules may import the general library, but must not import concrete snapshots. Inner/Outer and Red/Gray/Black definitions that embody the MSC architecture belong here unless a justified general formulation is introduced.
3. **Network-specific evidence and checks:** Import concrete devices, configurations, topologies, and observations. Generate witnesses, check the premises required by the general proofs, and apply the CSfC theorems. Concrete device names, snapshot paths, and topology lists belong here.

The existing `TDN/Semantics`, `TDN/Targets`, and `TDN/Evidence` directories provide starting locations for these three parts. Refactor their contents and introduce submodules where needed to enforce the stated responsibilities. Verify import dependencies. Generality must be reflected in the declarations and their assumptions, not only in directory names.

Build reusable components as the requirements demand them. Reuse suitable definitions and proved results from Mathlib and CSLib, with compatible versions pinned. Avoid building an expansive networking library before addressing the obligations. Keep general network results independent of CSfC clauses, and keep reusable CSfC results independent of deployment names and snapshots.

#### Assess library reuse before implementing overlapping infrastructure

The Construction Agent must inspect relevant Mathlib and CSLib definitions and theorems before introducing or substantially revising general proof infrastructure. Use CSLib as the first candidate foundation for the new packet-execution model. Evaluate its representation of states and named actions, finite executions, preservation of invariants, and relationships between detailed and simpler models. An invariant is a condition preserved by each permitted step. A simulation relates two models by showing how steps in one are matched by steps in the other.

Inspect the actual declarations and assumptions in a specific library revision. Starting candidates include CSLib's `LTS`, `LTS.MTr`, `LTS.mtrInv_of_trInv`, and `LTS.IsSimulation`, together with its execution-matching results. Verify their names and behavior in the chosen revision. Compare their treatment of action labels, internal steps, and one-step versus multistep matching with the obligations of the network model. Consult the [official CSLib repository](https://github.com/leanprover/cslib) and [API documentation](https://api.cslib.io/docs/) under the retrieval rules in Section 1.1.

Record the assessment in `artifacts/construction/<run>/library_reuse.md`. For each relevant candidate, include:

- The library revision, module, declaration, and affected requirement or general proof obligation.
- The declaration's assumptions and how the network model would satisfy them.
- The definitions or proofs it would replace or support, and any necessary connecting definitions or lemmas.
- The adoption decision, with links to actual uses in the theory or a specific reason for rejection.
- Compatibility checks, small Lean integration examples where fit is uncertain, and their commands and results.

Prefer direct reuse when the library result fits the obligation. Keep network-specific reasoning explicit in the supporting lemmas. Existing short Mathlib-based arguments may remain when CSLib migration offers no meaningful benefit; document that decision for overlapping infrastructure. A blanket statement that Mathlib sufficed for previously completed proofs does not justify skipping the assessment. Adding a dependency without using its results does not demonstrate reuse.

Check Lean, Mathlib, and CSLib compatibility before adopting a dependency. Select a compatible pinned revision or test a coordinated toolchain update in an isolated copy of the permitted current development. Preserve the working baseline, record exact revisions and manifest changes, and rerun affected builds and validation after integration. A mismatch with CSLib's latest branch alone is insufficient grounds to reject the library; assess compatible revisions or a practical upgrade. Do not assume that current online documentation describes an older pinned revision.

Library adoption does not discharge the network-specific obligations. The agents must still define the relevant packet operations, establish their local preservation conditions, and connect imported evidence to the general model. Revisit the assessment when a new obligation requires additional execution, protocol, or temporal reasoning. The coordinator checks the recorded decisions before accepting newly implemented overlapping infrastructure or a claim that no suitable library result exists. Archive isolation remains in force throughout library evaluation and compatibility experiments.

### 5.2. Construct general proofs and check their applications

Construct the proof from explicit connections between observations and properties:

1. Formalize the requirement and identify the supporting conditions sufficient to establish it. Do not assume that a candidate network already complies.
2. Specify which observations can establish those conditions and how to represent them in Lean. Revise the obligations or representation when practical evidence exposes a mismatch, while preserving the source requirement.
3. Implement and validate the importer and the relevant network behavior. Make the modeled operations and their implementation assumptions explicit.
4. Prove reusable lemmas connecting the supporting conditions to the required global properties. Assemble those lemmas into the general top-level theorem.
5. For each supported snapshot, import facts and generate any supporting witnesses, such as region labels or paths. Check the required conditions using `by decide` where applicable, or other checked proof constructions. Local checks may concern individual devices, multiple devices, paths, or relationships across the whole network.
6. Apply the same general theorem to each relevant emulation or configuration. Record which checked facts discharge each premise and which assumptions remain external to the proof.

Proof construction and evidence provision inform one another throughout these steps. A theorem's local conditions must be justified as sufficient for its conclusion and supported by obtainable evidence. Do not make the target property itself an assumed premise or treat a restatement of the desired global behavior as a completed evidence check.

Network-specific changes should primarily affect imported facts, generated witnesses, and their checks. Avoid reconstructing general reasoning for each snapshot. Apply unchanged general proofs to materially different supported configurations where the requirements apply, and record the validation results. A different number of devices, different addresses, or another topology within the model's scope should require new evidence and checks. Extend the model or general proof when previously unsupported behavior or a discovered modeling error requires a change, and document the reason.

The importer must preserve the information required by the selected obligations and make unsupported inputs explicit. Check coverage of relevant records so that missing devices, rules, or observations cannot silently make a universal statement pass. Keep the truth of collected observations and the interpretation of implementation behavior separate from Lean's checking of the resulting mathematical statements.

Unproved targets must remain visibly unproved. Do not use `sorry`, a new axiom asserting the desired result, or an unjustified assumption to count a target as completed. Record useful conditional theorems together with their unfulfilled assumptions. A failed attempt alone does not establish mathematical unprovability.

### 5.3. Connect packet-processing evidence to global claims

Complete the connection between imported packet-processing facts and the general proofs wherever the requirement needs an end-to-end argument. Account for the relevant route selection, firewall evaluation, encryption and decryption operations, switching, and delivery behavior. Include input, output, forwarding, and local processing paths where they affect the claim. Explain the treatment of unsupported operations and control-traffic exceptions.

For protected Red payloads reaching Black, establish that the allowed executions apply the required Inner and Outer protection in order. Connect accepted policy conditions to the selected encryption operations and subsequent transmission. For delivery between Red networks, establish the required security-level restriction throughout the modeled execution. Make any source-address, initial-state, or authentication assumptions explicit and justify them against the requirement's scope.

Prove that the relevant executions derived from the snapshot satisfy the conditions of the general model. A general theorem assuming that connection remains conditional until its premise is established. Firewall-traversal results, policy metadata checks, and selected traffic probes may support the construction, but do not individually establish every allowed packet execution. Renaming declarations or wrapping existing conditional results does not complete the missing argument. These packet claims are required work within the full set of 76 groups, not a replacement for that set.

## 6. Diagnose failures before requesting changes

The Construction Agent first investigates its own statement, definitions, importer, model, and proof strategy. A proof failure does not by itself justify changing the emulation or requesting additional exports.

After that investigation, an evidence request must include:

- The requirement group, clause, and precise unresolved obligation.
- The failed check or concrete example that exposes the gap.
- The construction errors considered and the findings of that investigation.
- The additional observation or justified deployment correction requested.
- How the proposed response would address the obligation.

The Evidence Agent evaluates the request against the source requirements and its implementation capabilities. It corrects genuine deployment flaws and extends collection when appropriate. It rejects requests it cannot support or returns a clarification when the requested evidence is underspecified.

Preserve failed checks and before/after evidence when repairing a deployment. The Construction Agent must re-import the new evidence and rerun affected proofs. Include positive behavior checks where needed to ensure a safety result is not achieved merely by disabling all useful traffic.

## 7. Continue until all actionable obligations are proved

The agents alternate evidence provision and proof construction, with independent work proceeding in parallel when dependencies allow. The Construction Agent can begin formalization while the Evidence Agent prepares representative emulations. Each feedback round concerns specific unresolved obligations rather than rebuilding every deployment and proof.

The harness records each request, response, rejection, implementation change, snapshot, proof attempt, and validation result under `artifacts/construction/`. Store new evidence bundles under `artifacts/snapshots/` with timestamped names. Use paths relative to a documented base in manifests and cross-references.

Each evolution record includes the UTC timestamp, actor, requirement and example IDs, previous state, new state, reason, supporting evidence, changed files, and validation result. Preserve intermediate proof sources and deployment configurations with content hashes, including failed attempts and rejected requests. A summary alone is insufficient: retain commands and their results with secrets redacted so that the sequence can be reconstructed afterward.

The authorized emulation servers are `hy@clnode176.clemson.cloudlab.us`, `hy@clnode159.clemson.cloudlab.us`, `hy@clnode163.clemson.cloudlab.us`, `hy@pc08.cloudlab.umass.edu`, `hy@pc22.cloudlab.umass.edu`, and `hy@pc16.cloudlab.umass.edu`. The Clemson reservation expires October 24 at 1:02 p.m.; the Massachusetts reservation expires October 24 at 4:23 p.m. Treat the supplied reservation times as America/New_York. Begin with one suitable server and expand when representative cases or resources require additional servers. Preserve unrelated workloads and copy durable evidence into the repository before either reservation expires.

Continue working on all 76 groups until every applicable, well-defined obligation that can be established within the authorized implementation and evidence scope has a checked proof. Completion requires reusable general theorems and checked applications to the relevant network configurations. A conditional theorem does not establish deployment compliance while required premises remain unchecked. There is no fixed round limit.

Missing importer functionality, incomplete packet-processing models, repairable deployment flaws, and failed proof attempts remain actionable work. An unanswered request is not the only reason to continue: an accepted response must be incorporated into the affected proofs, and outstanding construction work must be completed. An evidence rejection or a status assignment alone does not justify convergence.

For each obligation that cannot be established within scope, record the exact blocked clauses, the supporting reason, the attempted remedies, and the evidence, capability, or source clarification needed to proceed. Distinguish unavailable evidence, actual requirement violations, unresolved source meaning, and mathematical impossibility. A deployment limitation does not by itself make a specification or a general conditional theorem mathematically unprovable. Continue proving independent, well-defined clauses in the same group. A temporarily blocked run remains incomplete unless the completion criteria are met.

Use distinct outcomes for fully established targets, partial results, conditional results with outstanding assumptions, demonstrated violations, unavailable evidence, unresolved interpretation, and unresolved proof construction. Applicability exclusions require a source-based explanation. A justified scope or capability rejection may close an evidence request while leaving its affected clause unproved. The coordinator must check each claimed limitation against the authorized extensions and available alternatives before accepting it as a reason that no actionable work remains. Do not repeatedly request the same rejected evidence unless new information changes the request.

Before declaring convergence, validate source fidelity, coverage of all 76 targets and their clauses, representative-case coverage, importer behavior, proof compilation, assumption accounting, and archive isolation. Check that missing-reference limitations have documented official-source retrieval attempts and that retrieved information has been incorporated into affected obligations. Check the separation of general network, CSfC, and snapshot modules. Demonstrate reuse across materially different applicable configurations. Confirm that required packet-execution connections have been established or have a clause-specific justified limitation. Report remaining limitations explicitly. A whole RG remains unproved when any applicable clause is still blocked, even if its other clauses have passed.

### 7.1. Demonstrate completion of all practically tractable proofs

The agents must demonstrate that all practically tractable proofs have been completed before stopping. A proof remains practically tractable when its obligation can be established through available evidence, reasonable implementation or collection extensions, a defensible documented interpretation, and supported proof methods within the authorized scope. Missing code, a difficult proof attempt, elapsed rounds, or the approaching end of a server reservation do not by themselves establish that further work is intractable.

Prepare `artifacts/construction/<run>/completion_assessment.md` with a clause-level accounting of all 76 groups. For each completed obligation, identify the specification, general theorem, checked snapshot applications, interpretation decisions, and successful validation commands and results against the final source and evidence versions. For each unfinished obligation, state the precise remaining task, the attempts and alternatives considered, the concrete external or practical limitation, and the records supporting that assessment. Explain why available evidence, authorized extensions, alternative proof decompositions, or reusable library results cannot presently resolve the remaining task. Check that independent clauses in the same group have been completed.

Both agents must contribute to the assessment. The Construction Agent accounts for remaining formalization and proof work, including relevant library candidates and the decisions recorded in `library_reuse.md`. The Evidence Agent accounts for remaining collection, implementation, and deployment work. The coordinator checks their conclusions against the artifacts and reopens any obligation whose claimed limitation is unsupported or has an actionable remedy. Record disagreements and their resolution. The final report must link the assessment and summarize completed and unfinished obligations with their reasons.

The workflow may declare completion only after that assessment supports the conclusion that no practically tractable proof work remains. An interruption or resource loss must be reported as an incomplete run with pending work. The assessment documents the basis for stopping; it must not present failed attempts as a mathematical proof of impossibility.

## 8. Final deliverables

The final report must explain what the new development establishes and what remains open. Deliver:

- Reproducible Twinet configurations and a coverage register for all extracted examples and alternatives.
- Versioned snapshots, collection procedures, and accepted or rejected evidence requests.
- Retrieved official references with source URLs, versions, retrieval timestamps, content hashes, and requirement mappings.
- A separate `interpretations.md` documenting original-document checks, selected readings, alternatives, justifications, and affected proofs.
- A `completion_assessment.md` demonstrating completion of all practically tractable proof work and supporting every remaining limitation with clause-specific records.
- A `library_reuse.md` documenting evaluated Mathlib and CSLib declarations, actual uses, justified rejections, and tested dependency compatibility.
- The refined importer and Lean development, with a general network library, reusable CSfC specifications and proofs, and separate snapshot applications.
- A register covering all 76 groups, with specification names, general theorem names, supporting lemmas, checked snapshot applications, clause-level progress, and supporting evidence.
- A map showing how each top-level specification is established by general theorems and lemmas, which concrete checks discharge their premises, and which assumptions remain unfulfilled.
- Reuse validation showing unchanged general proofs applied to materially different supported configurations, plus reasons for any model or proof extensions.
- An interaction history showing how proof construction changed evidence collection or repaired emulations.
- Validation results and a clear account of assumptions, unresolved obligations, and rejected requests.
