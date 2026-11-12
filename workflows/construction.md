# Evidence-driven construction of CSfC theories

The current theory is v3.3. Nineteen of the 24 selected requirement groups have passed complete-candidate review under their recorded model assumptions. The current results are recorded in [the publication verdict](../data/publication/v3.3/verdict.json).

The user narrowed the November 10 continuation to RG-007 and requested stopping once it passed review, followed by a v3.3 release. RG-007 passed its second complete-candidate review. The same continuation also completed RG-024, RG-028, RG-029 and RG-030 before the scope was narrowed. Proof construction is stopped. RG-008, RG-015, RG-054, RG-056 and RG-074 remain deferred until a new instruction. Their supporting results remain available.

The continuation used an independent GPT-6.1 Sol Constructor with Extra High reasoning in an isolated workspace. Its records are preserved under `data/construction/v3.2-20261111T040601Z-remaining/`, reflecting the version at the start of the run. Complete one RG’s general proof and meaningful model applications before supervisor validation. Focused compiler feedback is allowed during construction; broad validation and complete-candidate review wait until that RG is ready. Follow `docs/naming.md` for every new or changed declaration. Preserve accepted specification meanings; run a fresh blind interpretation when a meaning changes. The per-RG review limit and completion criteria below remain in force for any later authorized continuation.

The following paragraphs preserve earlier stopping decisions and review history.

The user narrowed the stopping point on November 4, 2026: finish and validate RG-033, update the affected documentation, role ontology, and theorem hierarchy, then stop. RG-035, RG-039, and RG-040 have passed the continuation's complete-candidate reviews. Preserve those results and the earlier ten accepted groups. Defer RG-007, RG-008, RG-015, RG-024, RG-028, RG-029, RG-030, RG-054, RG-056, and RG-074 until a later instruction. Their unfinished status must remain visible. That stopping point required a complete RG-033 PASS and documentation updates; it does not claim completion of all 24 selected groups.

The narrowed continuation completed RG-033 in its third complete-candidate review. Fourteen selected groups now have accepted complete model applications, and ten remain deferred. The [completion record](../data/construction/v3.1-20261104-continuation/completion_assessment.md) preserves the reviews, assumptions, final validation and documentation updates. Construction stopped at that earlier milestone.

The user resumed v3.1 construction on November 4, 2026 for the fourteen unfinished groups: RG-007, RG-008, RG-015, RG-024, RG-028, RG-029, RG-030, RG-033, RG-035, RG-039, RG-040, RG-054, RG-056 and RG-074. Preserve the ten groups that passed the earlier review: RG-012, RG-013, RG-014, RG-021, RG-027, RG-032, RG-034, RG-037, RG-038 and RG-047. The [earlier review record](../data/construction/v3.1-20261031T231942Z/proof/round-002/supervisor-review.md) remains unchanged. Record the continuation separately under a new UTC-stamped run directory.

Finish one RG's complete general proof and its model applications before submitting that RG for supervisor validation. Do not repeatedly review unfinished lemmas, rerun broad regression suites, or rebuild unrelated modules during construction. The Constructor may use focused Lean compiler feedback when needed to develop a proof. A complete submission triggers kernel checking, clause and assumption review, and reuse checks for that RG. Recheck earlier completed results only when changed dependencies could affect them. Run the final build and affected development checks at the user's selected stopping point. Preserve the accepted specification meanings; a meaning change still requires a fresh blind interpretation before its proof can pass.

For this continuation, count candidate-review rounds separately for each RG. A PASS advances to the next RG only while that group remains within the user's authorized scope. The repeated-failure limit in Section 7 applies to that RG's complete submissions; successful reviews of different RGs do not consume another RG's revision allowance. Record the final integration review separately.

Version 3.1 refines the active CSfC theory through interpretation round-tripping followed by supervised proof construction. The Constructor Agent obtains network observations through the evidence MCP server. The [proof scope](../specs/proof_scope.json) selects 24 requirement groups for formal reasoning: RG-007, RG-008, RG-012, RG-013, RG-014, RG-015, RG-021, RG-024, RG-027, RG-028, RG-029, RG-030, RG-032, RG-033, RG-034, RG-035, RG-037, RG-038, RG-039, RG-040, RG-047, RG-054, RG-056, and RG-074. All 76 groups remain in the register. The other groups retain their direct-check, external-evidence, or permission dispositions.

Version 3.1 must establish every clause of each accepted top-level specification for those 24 groups. The existing scope file describes partial contributions from the previous development. Those contributions provide starting points and do not establish completion of v3.1. Preserve source conditions, exceptions, alternatives, and independently applicable clauses when constructing the complete specifications. Record any unavoidable external assumption explicitly; an assumption of the desired conclusion cannot count as a proof.

The supervisor runs two independent agent roles. The **Constructor Agent uses GPT-6.1 Sol with Extra High reasoning**, model `gpt-6.1-sol`, effort `xhigh`. Each temporary **Interpreter Agent uses GPT-6.1 Sol with High reasoning**, model `gpt-6.1-sol`, effort `high`. Start every agent with fresh context, without inheriting the supervisor's conversation. The Constructor may inspect the permitted active development and source requirements. Each Interpreter receives only the frozen Lean specifications and the definitions needed to understand them. It must never inspect the RGs or their chosen interpretations.

The supervisor compares each blind interpretation with the original requirements and documented interpretation choices. The Constructor corrects discrepancies before another fresh Interpreter reads the revised specifications. Proof construction starts only after every selected specification passes that comparison. The supervisor then reviews successive proof candidates, supplies constructive feedback, and repairs or improves the MCP server when necessary. Section 7 defines validation and stopping rules.

The initial run began on October 17, 2026. Record v3.1 in a new UTC-stamped directory named `data/construction/v3.1-<timestamp>/`. Preserve all previous runs, pointers, snapshots, reports, and histories. Record exact prompts, replies, source versions, decisions, and validation results so that the development can be reconstructed.

The [evidence MCP server](../mcp/README.md) lives under `mcp/`. Its adapters, parsers, and export views provide the interface for new evidence collection and queries. Proof validation and coordination tools live under [`scripts/construction`](../scripts/construction/README.md). Twinet deployment and protocol experiment tools live under [`scripts/construction/evidence`](../scripts/construction/evidence/README.md), with network profiles in [`data/extraction/networks/profiles`](../data/extraction/networks/profiles/README.md). Historical snapshots and checkpoints retain their original paths and hashes.

## 1. Inputs and scope

The preprocessing artifacts define the obligations and representative cases. Current implementation limits must not silently narrow that scope.

| Input | Purpose |
| --- | --- |
| [Requirement groups](../specs/requirement_groups.md) | All 76 proposed statements, their applicability, exceptions, and source passages |
| [Example networks](../data/extraction/networks/networks.md) | Nine concrete network topologies |
| [Partial configurations and alternatives](../data/extraction/networks/configurations.md) | Seventeen records containing arrangements and configuration choices |
| [Protocol exchanges](../data/extraction/networks/protocol_exchanges.md) | The illustrated IKEv2 exchange and its selected protocol behavior |
| [Requirement mappings](../data/extraction/networks/network_requirement_links.md) | Clause-specific relationships between examples and requirements |
| [Source index](../data/extraction/source/source_index.jsonl) and [original document](../data/extraction/source/CSfC_documentation_v1.3.0.pdf) | Authoritative passages for resolving interpretation questions |
| [Device roles and ontology](../data/extraction/roles/roles.md) | Source-linked vocabulary for components and relationships |

Explicit textual descriptions and applicable requirements supply details omitted from figures. The Constructor Agent must preserve conditions, exceptions, and alternative choices when formalizing a group. Resolve ambiguity and conflicting wording through the original-document review and documented interpretation procedure in Section 1.2.

All 76 statements remain in the requirements register. Each clause records whether it needs a general proof, a direct check, external assurance, or no mandatory claim. The current decisions apply to the assessed contributions. Revisit a decision when a new behavioral obligation warrants a proof. Difficulty alone does not justify excluding a clause.

### 1.1. Retrieve missing official documents and resources

The Constructor Agent and coordinator are authorized to search the web and retrieve official documents and resources needed to interpret requirements or supply supporting evidence. No separate approval is needed for each retrieval. Sources may include CSfC annexes, referenced standards, official implementation documentation, and the [NSA CSfC Components List](https://www.nsa.gov/Resources/Commercial-Solutions-for-Classified-Program/Components-List/). Use the issuing organization's official publication or repository as the authoritative source. Search results and third-party summaries may help locate it, but do not replace the source itself.

Treat “Missing referenced documents” as a retrieval task before accepting it as a limitation. Review existing entries in that category, locate the referenced materials, and reopen affected obligations when the missing information becomes available. If retrieval fails, record the official locations searched, access failures or unavailable versions, and the exact clauses that remain blocked. Continue work on independent clauses.

Preserve retrieved materials under the active run's `data/construction/<run>/references/` directory. Record the title, issuing organization, requested and final source URLs, document version or publication date, UTC retrieval timestamp, content hash, and affected requirement groups. Retain the downloaded document or a captured copy of the relevant webpage, with section or page references for the passages used. Use the recorded source versions consistently in proof construction, parser changes, and deployment work.

Match referenced versions to the CSfC document being formalized. When only a newer version is available, record the difference and its effect on the obligation; do not silently replace the original requirement. For changing resources such as component lists, record the captured date and the product and version identifiers used in any comparison. An official listing supplies evidence about the listed product; establishing that the deployed component matches that listing requires separate deployment evidence.

Web retrieval must preserve the archive restrictions in Section 2. The Constructor Agent must not use online repository history, reports, or other copies to recover the forbidden archived theory.

### 1.2. Resolve ambiguity using the original document

Whenever ambiguity, inconsistency, or conflicting wording affects an obligation, the Constructor Agent must double-check the relevant original document. Sentence extractions and requirement groups may omit context. Read the surrounding paragraphs, definitions, exceptions, cross-references, and applicable table headers, notes, and figure captions. Inspect the rendered pages when layout affects meaning. Use the official references retrieved under Section 1.1 when the document delegates a requirement to another source.

If ambiguity remains after that review, the Constructor Agent should select one of the most plausible and reasonable interpretations and continue construction. It is authorized to make that choice without waiting for separate user approval. Base the choice on the source context, the architecture described, and consistency with applicable requirements. Ease of proof alone is not a justification. Preserve the competing passages and explain how the chosen reading handles them. A documented choice states the interpretation used by the theory; it does not claim that the issuing organization has resolved the ambiguity.

Maintain a separate `data/construction/<run>/interpretations.md` file as part of the final deliverables. Give each decision a stable identifier and record:

- Affected requirement groups and clauses, with original quotations and document version, page, and section references.
- The original context inspected and any information lost or distorted during extraction.
- The plausible interpretations considered, the selected interpretation, and the reasons for choosing it.
- The resulting formal meaning, assumptions, affected declarations, and consequences for evidence collection or emulation.
- The decision date, author, coordinator review, and any later revision with its reason.

The coordinator checks that each interpretation is applied consistently to the proofs, evidence requests, parser changes, and network configurations. Link the decision from the construction register and separate explanation files. Do not add comments to proofs. Revisit existing interpretation blockers under this procedure. Reserve unresolved-interpretation status for cases where the source review cannot support any reasonable choice, and document why. An ambiguity with a defensible documented interpretation must not stop otherwise tractable proof work.

## 2. Continue the current theory and preserve archive isolation

Continue from the active `TDN/` tree, its importers, and the current construction register. Preserve a versioned checkpoint before changes. The original archive operation has already been completed. Preserve `archive/v1/` unchanged, keep it excluded from the active build, and do not move the current theory into that archive.

The Constructor Agent is forbidden to read, search, import, copy, or receive the archived proofs and libraries. The prohibition also covers archive-derived code, proof descriptions, and comparisons recovered through Git history, reports, conversation transcripts, or other locations. The coordinator must not pass archived implementation details or proof summaries to the agent. Start the agent with fresh context containing the specification inputs, these continuation instructions, and permitted current-development artifacts. The current theory may be inspected and refined.

Enforce archive isolation before launching the Constructor Agent. Use restricted workspace access or an isolated workspace containing only explicitly permitted files. Exclude the archive, repository history, and unreviewed reports or transcripts that could expose archived material. Inspect handoff artifacts for forbidden content. Merely omitting an archive path from a prompt is insufficient. Record the permitted paths and the access restrictions before work begins. Configure the MCP server to expose only permitted networks and evidence collections. Review saved-snapshot paths, adapters, and export views so that tool results cannot expose archived theory or excluded reports.

Improve the active importer, models, specifications, and proofs as needed. Existing declaration names, device counts, and module boundaries may be changed when the revision improves source fidelity or reuse. The coordinator may reuse and extend Twinet's emulation infrastructure without consulting the archived Lean development.

### 2.1. Freeze the selected specifications and account for their clauses

Before the first interpretation round, the Constructor records one top-level `def … : Prop` for each selected RG. Create missing specifications and complete partial ones using the original requirements and documented interpretations. Maintain a clause register linking every source obligation to its formal expression, applicability condition, interpretation decision, and supporting definitions. Include direct-check clauses within an otherwise behavioral group when they are part of its accepted specification. Do not omit a clause merely because its current proof is absent.

The supervisor verifies the 24-to-24 mapping and compares it against `specs/requirement_groups.md`. Check the original PDF when extraction or wording obscures the meaning. Keep genuine applicability exclusions explicit. Record external facts and implementation assumptions separately from properties that the theory must derive. If a group includes a clause that cannot be established, retain that clause and report the gap in validation.

### 2.2. Interpretation Round-tripping

Each interpretation round uses an immutable candidate and a new independent Interpreter Agent. The supervisor prepares a separate workspace containing the 24 specifications, their transitively needed definitions and types, and any required standard-library definitions. Preserve binder types, quantifiers, alternatives, assumptions, and default values. Exclude requirement documents, RG summaries, source-document quotations, interpretation decisions, previous interpreter outputs, proof explanations, archive material, and repository history. Record the supplied files and hashes. Test the access restrictions before starting the Interpreter. The supervisor must document the actual isolation mechanism and any limits to its enforcement.

The Interpreter translates each specification into plain English from the Lean code alone. It explains every required clause, who or what it quantifies over, when it applies, its exceptions, and the consequences of its assumptions. It follows supporting definitions far enough to expose their meaning. Unavailable or unclear definitions must be reported as translation gaps. A declaration name is not evidence of what its body requires. The Interpreter does not repair code or consult the source requirements.

The supervisor compares the translations with the original RG clauses under the chosen, documented interpretations. Check for missing obligations, extra restrictions, weakened quantifiers, misplaced conditions, lost alternatives, mismatched device roles, and conclusions supplied as assumptions. Record a verdict and concrete discrepancy for every affected clause. A defensible interpretation choice must preserve source context and be recorded under Section 1.2. The Constructor must not choose a new interpretation solely to make an existing definition pass.

The Constructor revises the specifications and their dependencies in response to that feedback. Freeze the new candidate, preserve its diff and hashes, and repeat with a fresh Interpreter. Continue until every selected specification has no unresolved discrepancy or translation gap. There is no fixed limit on interpretation rounds. Record the accepted source hashes and clause mapping. If later proof work changes the meaning of a specification, return the affected specifications to fresh blind interpretation and supervisor comparison before accepting their proofs.

## 3. Choose and prepare representative emulations

The Constructor Agent identifies one or several Twinet emulations that collectively represent all extracted networks, configuration choices, and protocol cases that can be implemented. It first uses `list_networks` to inspect the configured networks and saved collections. It should exploit containment between examples to reduce redundant deployments. The coordinator creates or updates the required deployments through the existing Twinet tools, then registers their workers, device identities, and adapters in the server configuration.

An example may be merged into or represented within another emulation only when none of its representative cases is lost. Record the correspondence between the source example and the relevant devices, settings, paths, or protocol scenario in the encompassing emulation. A Lean equivalence proof between examples is not required for deployment selection.

Genuinely different setups must receive separate realizations. They may use separate networks or separately recorded configurations of a reusable deployment. Distinct authentication choices, encryption technologies, encapsulation placements, or management arrangements must remain visible when those differences are part of the extracted cases. A record containing several alternatives may therefore require several runs.

Maintain a coverage register with the following fields:

- Example ID and the particular cases or alternatives being represented.
- Emulation and configuration IDs that provide the evidence.
- The containment or merging justification, when applicable.
- Case-specific observations to collect.
- Any unrepresented case and the reason evidence cannot be provided.

The coordinator improves the MSC profile when the Constructor Agent identifies a justified missing case or deployment flaw. Extensions may include additional security levels, MACsec, IPv6, authentication choices, protocol exchanges, or management arrangements. The existing profile is a starting implementation, not the scope definition.

Reusable MSC deployments must retain Twinet's FRR routing and OVS switching stack with native device CLI access, as required for the existing emulation infrastructure. Supplemental namespace or protocol experiments may supply additional evidence when their scope is explicit. Record the runtime backend in every profile and snapshot so that a result from a legacy Linux/static-routing profile cannot be attributed to a native FRR/OVS deployment.

Management cases receive separate evidence and applicability records. Their availability must not gate proofs about the optional-management-free MSC data path.

## 4. Collect, query, and import evidence through MCP

The evidence MCP server provides read-only collection, saved-observation queries, and structured JSON exports. The Constructor Agent uses those tools directly. Network creation, configuration changes, protocol experiments, and source interpretation remain explicit workflow tasks assigned in Sections 1, 3, and 6.

### 4.1. Configure access and discover available observations

The coordinator starts the server through `mcp/run.sh` with a trusted configuration file and connects it to the Constructor Agent's MCP client. Paths inside the configuration file are relative to that file. Each live device identifies its worker, container, declared role, and adapters. The server can collect across workers using those per-device addresses. Record the configuration version used by the run. See the [server guide](../docs/evidence_service.md) for setup and supported views.

The Constructor Agent begins with `list_networks` and `describe_capabilities(network)`. For each unresolved clause, identify the required devices, observation categories, supported interpretation, and expected coverage. A capability may return structured records or preserve command text. Raw text still requires a supported parser before it can supply typed facts to the proof.

### 4.2. Collect and inspect one identified snapshot

The Constructor Agent follows the same collection sequence for each evidence request:

1. For live state, call `collect_evidence(network, capabilities)` and retain the returned collection ID. Poll `collection_status(collection)` until collection finishes. Use `cancel_collection(collection)` when an unfinished capture is no longer useful. For saved evidence, select an existing collection or configured snapshot ID from `list_networks`.
2. Call `query_evidence(collection, capability, device, offset, limit)` as needed. Follow `next_offset` until all relevant records have been retrieved. Check coverage and `devices_without_observation`; a returned page alone does not establish a complete inventory.
3. Inspect `evidence://COLLECTION/manifest` and the relevant `raw/OBSERVATION` and `stderr/OBSERVATION` resources. Retain source references, collection intervals, exit codes, parser versions, and hashes. Preserve failed and unsupported observations in the request record.
4. Check the state needed by the obligation. For steady-state claims, inspect the relevant routes, filters, tunnel state, and available consistency rechecks. Repeated equal observations support the recorded stability check. Collection completion alone establishes neither protocol convergence nor an atomic snapshot across workers.
5. Call `prepare_lean_bundle(collection, view)` for a supported view. Record its output path, hash, and supported type or record keys. Import JSON with `load_network_records` or `load_network_snapshot`, then run the local Lean checks required by the general theorem.

Every query and export must identify its collection. A query reads the saved capture and does not silently refresh the network. After a deployment change, start a new collection and retain the previous one so that failed and repaired cases remain distinguishable.

The saved-snapshot interface supports inventory, validated packet-filter, and topology views. Live collection currently prepares typed forwarding inventories. Other observations, including protocol and encryption state, have the interpretation described by their capabilities. A new packet-execution model may require additional parsing and export support. Do not treat the inventory view as a complete packet-execution configuration.

Store JSON used by proofs under `data/evidence/`, which Lake tracks as a build dependency. The JSON path in a Lean import is relative to the Lean source file. Keep general proofs and snapshot checks as ordinary Lean declarations. Python supplies records and candidate witnesses, such as region labels or explicit paths; Lean checks the conditions those witnesses are intended to establish. Do not generate Lean data literals or proof bodies with Python strings. Historical generation scripts remain available for replay in their corresponding revisions.

### 4.3. Resolve missing observations and interpretations

The Constructor Agent diagnoses failed, incomplete, or unsupported MCP results before recording a limitation. Check the requested network, device inventory, capabilities, collection errors, and parser coverage. An unsupported response identifies a current server capability gap. It does not establish that the requirement cannot be proved.

When a required device observation or interpretation is missing, the Constructor Agent implements a versioned adapter, parser, or export view under `mcp/tdn_evidence/`. Adapters use fixed read commands and explain what their parsed records mean. Saved-evidence views can use `register_projection`. Keep the original output, preserve fields needed by the proof, and explicitly report unsupported input. Test ordinary cases, missing records, and unsupported features before the coordinator enables the extension in the trusted server configuration. Recollect or re-export as required and record the changed versions. The server guide describes the current extension interfaces.

Deployment repairs and new protocol experiments follow Section 6. The coordinator performs those changes through Twinet or the existing experiment tools. The Constructor Agent then obtains the resulting observations through MCP. If an experiment produces a saved format that the server cannot yet read, add and validate the necessary adapter or saved-evidence view before relying on its results.

Official documents and organizational records use the retrieval procedure in Section 1.1. The Constructor Agent resolves source ambiguity through Section 1.2. The MCP server reports observations and supported interpretations; the agent decides how those records bear on a requirement.

A justified limitation record names the exact clause, requested observation, MCP results, attempted remedies, and reason evidence still cannot be supplied. Distinguish unavailable observations from actual requirement violations. Keep the affected requirement in the register and state what evidence, capability, or implementation change could make progress possible. A finite snapshot cannot establish arbitrary behavior over time; request the relevant event records or state-transition evidence when a claim needs them.

## 5. Constructor Agent: prove the selected behavioral requirements

The Constructor Agent reviews every group and follows its clause-level decision in `specs/proof_scope.json`. For selected behavioral clauses, define a specification using `def … : Prop` and prove it from explicit supporting conditions. Preserve applicability, alternatives, and exceptions. Keep the complete source requirement in the catalog when the formal specification covers only a clause.

Routine settings, inventory comparisons, recorded-operation comparisons, and saved-result checks belong in the evidence layer. Use `scripts/construction/check_configuration_records.py` for the currently migrated clauses. Keep a small Lean certificate when a retained general theorem consumes the fact. Avoid constructing a separate state model or top-level proof merely to restate a finite comparison. External approvals and missing capabilities stay explicit in the register without placeholder Lean specifications.

Use `lemma` for supporting results: individual-step preservation, record and rule checks, witness steps, initial-state facts, and proofs assembling local assumptions. Use `theorem` for a module's principal reusable guarantees, requirement or clause results, final snapshot applications, and complete delivery or counterexample witnesses. A principal library theorem remains a theorem when another proof reuses it. Choose the keyword by the declaration's role in its module; both general proofs and concrete checks can serve either role, and `by native_decide` does not determine the keyword. Use Lean commands to import JSON data; keep proofs in Lean source. The keyword convention communicates the organization; reuse comes from the declarations' parameters, assumptions, and dependencies.

For each target, record its source clauses, intended meaning, quantifiers, applicability, assumptions, required evidence, and current proof status. Record separate names and statuses for the specification, general theorem, supporting lemmas, and snapshot applications. Keep partial clause results distinct from establishment of the whole group. Resolve source ambiguities under Section 1.2 and link the selected interpretation to each affected target. Do not hide missing clauses behind placeholder propositions, replace the full specification with its proved subset, or silently choose the easiest interpretation.

### 5.1. Separate general networking, CSfC requirements, and snapshot checks

Organize the theory into three parts with dependencies in one direction:

1. **General network library:** Define relevant behavior such as packet processing, routing, filtering, encryption operations, switching, delivery, and paths. Prove general results about those operations and their composition. These modules must import neither CSfC requirements nor concrete snapshots.
2. **CSfC specifications and general proofs:** Define document-specific roles, architectural constraints, requirement specifications, and reusable proofs that supporting conditions imply those specifications. These modules may import the general library, but must not import concrete snapshots. Inner/Outer and Red/Gray/Black definitions that embody the MSC architecture belong here unless a justified general formulation is introduced.
3. **Network-specific evidence and checks:** Import concrete devices, configurations, topologies, and observations. Generate witnesses, check the premises required by the general proofs, and apply the CSfC theorems. Concrete device names, snapshot paths, and topology lists belong here.

The existing `TDN/Models`, `TDN/Requirements`, and `TDN/Deployments` directories provide starting locations for these three parts. Refactor their contents and introduce submodules where needed to enforce the stated responsibilities. Verify import dependencies. Generality must be reflected in the declarations and their assumptions, not only in directory names.

Build reusable components as the requirements demand them. Reuse suitable definitions and proved results from Mathlib and CSLib, with compatible versions pinned. Avoid building an expansive networking library before addressing the obligations. Keep general network results independent of CSfC clauses, and keep reusable CSfC results independent of deployment names and snapshots.

#### Assess library reuse before implementing overlapping infrastructure

The Constructor Agent must inspect relevant Mathlib and CSLib definitions and theorems before introducing or substantially revising general proof infrastructure. Use CSLib as the first candidate foundation for the new packet-execution model. Evaluate its representation of states and named actions, finite executions, preservation of invariants, and relationships between detailed and simpler models. An invariant is a condition preserved by each permitted step. A simulation relates two models by showing how steps in one are matched by steps in the other.

Inspect the actual declarations and assumptions in a specific library revision. Starting candidates include CSLib's `LTS`, `LTS.MTr`, `LTS.mtrInv_of_trInv`, and `LTS.IsSimulation`, together with its execution-matching results. Verify their names and behavior in the chosen revision. Compare their treatment of action labels, internal steps, and one-step versus multistep matching with the obligations of the network model. Consult the [official CSLib repository](https://github.com/leanprover/cslib) and [API documentation](https://api.cslib.io/docs/) under the retrieval rules in Section 1.1.

Record the assessment in `data/construction/<run>/library_reuse.md`. For each relevant candidate, include:

- The library revision, module, declaration, and affected requirement or general proof obligation.
- The declaration's assumptions and how the network model would satisfy them.
- The definitions or proofs it would replace or support, and any necessary connecting definitions or lemmas.
- The adoption decision, with links to actual uses in the theory or a specific reason for rejection.
- Compatibility checks, small Lean integration examples where fit is uncertain, and their commands and results.

Prefer direct reuse when the library result fits the obligation. Keep network-specific reasoning explicit in the supporting lemmas. Existing short Mathlib-based arguments may remain when CSLib migration offers no meaningful benefit; document that decision for overlapping infrastructure. A blanket statement that Mathlib sufficed for previously completed proofs does not justify skipping the assessment. Adding a dependency without using its results does not demonstrate reuse.

Check Lean, Mathlib, and CSLib compatibility before adopting a dependency. Select a compatible pinned revision or test a coordinated toolchain update in an isolated copy of the permitted current development. Preserve the working baseline, record exact revisions and manifest changes, and rerun affected builds and validation after integration. A mismatch with CSLib's latest branch alone is insufficient grounds to reject the library; assess compatible revisions or a practical upgrade. Do not assume that current online documentation describes an older pinned revision.

Library adoption does not discharge the network-specific obligations. The Constructor Agent must still define the relevant packet operations, establish their local preservation conditions, and connect imported evidence to the general model. Revisit the assessment when a new obligation requires additional execution, protocol, or temporal reasoning. The coordinator checks the recorded decisions before accepting newly implemented overlapping infrastructure or a claim that no suitable library result exists. Archive isolation remains in force throughout library evaluation and compatibility experiments.

### 5.2. Construct general proofs and check their applications

Begin proof construction after the interpretation round-trip has passed. Constructor proof sources must contain no comments. Put explanations, source mappings, decisions, and review responses in separate records. Follow Mathlib and CSLib conventions for explicit assumptions, small reusable results, appropriate namespaces, and direct reuse of library infrastructure. Use `theorem` for public requirement results and `lemma` for intermediate arguments and concrete checks.

Construct the proof from explicit connections between observations and properties:

1. Formalize the requirement and identify the supporting conditions sufficient to establish it. Do not assume that a candidate network already complies.
2. Specify which observations can establish those conditions and how to represent them in Lean. Revise the obligations or representation when practical evidence exposes a mismatch, while preserving the source requirement.
3. Implement and validate the importer and the relevant network behavior. Make the modeled operations and their implementation assumptions explicit.
4. Prove reusable lemmas connecting the supporting conditions to the required global properties. Assemble those lemmas into the general top-level theorem.
5. For each supported snapshot, import facts and generate any supporting witnesses, such as region labels or paths. Check the required conditions using `by native_decide` for closed, computable checks, or other checked proof constructions. Local checks may concern individual devices, multiple devices, paths, or relationships across the whole network.
6. Apply the same general theorem to each relevant emulation or configuration. Record which checked facts discharge each premise and which assumptions remain external to the proof.

Proof construction and evidence provision inform one another throughout these steps. A theorem's local conditions must be justified as sufficient for its conclusion and supported by obtainable evidence. Do not make the target property itself an assumed premise or treat a restatement of the desired global behavior as a completed evidence check.

Network-specific changes should primarily affect imported facts, generated witnesses, and their checks. Avoid reconstructing general reasoning for each snapshot. Apply unchanged general proofs to materially different supported configurations where the requirements apply, and record the validation results. A different number of devices, different addresses, or another topology within the model's scope should require new evidence and checks. Extend the model or general proof when previously unsupported behavior or a discovered modeling error requires a change, and document the reason.

The importer must preserve the information required by the selected obligations and make unsupported inputs explicit. Check coverage of relevant records so that missing devices, rules, or observations cannot silently make a universal statement pass. Keep the truth of collected observations and the interpretation of implementation behavior separate from Lean's checking of the resulting mathematical statements.

Unproved targets must remain visibly unproved. Do not use `sorry`, a new axiom asserting the desired result, or an unjustified assumption to count a target as completed. Record useful conditional theorems together with their unfulfilled assumptions. A failed attempt alone does not establish mathematical unprovability.

### 5.3. Connect packet-processing evidence to global claims

Complete the connection between imported packet-processing facts and the general proofs wherever the requirement needs an end-to-end argument. Account for the relevant route selection, firewall evaluation, encryption and decryption operations, switching, and delivery behavior. Include input, output, forwarding, and local processing paths where they affect the claim. Explain the treatment of unsupported operations and control-traffic exceptions.

For protected Red payloads reaching Black, establish that the allowed executions apply the required Inner and Outer protection in order. Connect accepted policy conditions to the selected encryption operations and subsequent transmission. For delivery between Red networks, establish the required security-level restriction throughout the modeled execution. Make any source-address, initial-state, or authentication assumptions explicit and justify them against the requirement's scope.

Prove that the relevant executions derived from the snapshot satisfy the conditions of the general model. A general theorem assuming that connection remains conditional until its premise is established. Firewall-traversal results, policy metadata checks, and selected traffic probes may support the construction, but do not individually establish every allowed packet execution. Renaming declarations or wrapping existing conditional results does not complete the missing argument. These packet claims are required work within the 24 selected proof targets. Preserve the dispositions of all 76 groups in the register.

## 6. Diagnose failures before requesting changes

The Constructor Agent first investigates its own statement, definitions, importer, model, and proof strategy. A proof failure does not by itself justify changing the emulation or requesting additional exports.

After that investigation, an evidence request must include:

- The requirement group, clause, and precise unresolved obligation.
- The failed check or concrete example that exposes the gap.
- The construction errors considered and the findings of that investigation.
- The additional observation or justified deployment correction requested.
- How the proposed response would address the obligation.

The Constructor Agent maps the request to a supported MCP capability and calls the server when the needed observation is available. For missing parsing or export support, it follows Section 4.3. For a justified deployment change or experiment, it sends the coordinator the diagnosed issue, proposed change, and expected evidence. The coordinator performs the authorized work and records its outcome. Unsupported MCP responses remain actionable until those remedies have been considered.

Preserve failed checks and before/after evidence when repairing a deployment. The Constructor Agent must re-import the new evidence and rerun affected proofs. Include positive behavior checks where needed to ensure a safety result is not achieved merely by disabling all useful traffic.

## 7. Validate complete requirement groups and record every round

For the resumed v3.2 construction, apply the complete-candidate criteria separately to each of the ten groups listed at the start of this workflow. Review a group after its general proof and meaningful model applications are finished. Recheck accepted results when changed dependencies could affect them. Preserve the result of every review, then advance to the next unfinished group within the authorized scope. The earlier instruction to stop after RG-033 is historical and has been superseded by this continuation.

At final integration, build the complete active development and refresh the affected documentation, ontology, hierarchy, and public exports. Apply the 24-group criteria below to the fourteen preserved groups and the ten resumed groups together. A group that reaches its review limit remains explicitly incomplete.

The Constructor Agent alternates proof construction with MCP queries, collection requests, and checked imports. It can work on independent obligations while a capture runs or the coordinator prepares a deployment. Each round names the unresolved clause, the requested evidence or change, the result, and the proof or direct check that uses it.

The harness records each MCP call and response, capability gap, implementation change, snapshot, proof attempt, and validation result under `data/construction/<run>/`. Record the tool name, arguments, network or collection ID, relevant device IDs, and affected RG clauses. Keep collection manifests and raw observations with their hashes. Store proof-relevant captures under `data/snapshots/` using timestamped paths, and keep Lean imports under `data/evidence/`. Configure the server store accordingly or preserve the complete capture before its routine working directory is cleaned. Use paths relative to a documented base in manifests and cross-references.

Each evolution record includes the UTC timestamp, actor, requirement and example IDs, previous state, new state, reason, supporting evidence, changed files, and validation result. Preserve intermediate proof sources and deployment configurations with content hashes, including failed attempts and rejected requests. A summary alone is insufficient: retain commands and their results with secrets redacted so that the sequence can be reconstructed afterward.

The previously authorized emulation servers are `hy@clnode176.clemson.cloudlab.us`, `hy@clnode159.clemson.cloudlab.us`, `hy@clnode163.clemson.cloudlab.us`, `hy@pc08.cloudlab.umass.edu`, `hy@pc22.cloudlab.umass.edu`, and `hy@pc16.cloudlab.umass.edu`. Those addresses came from reservations originally ending on October 24. Before a new deployment, the coordinator verifies current availability and records the workers selected in the MCP configuration. Begin with one suitable server and expand when representative cases or resources require additional servers. Preserve unrelated workloads and save durable evidence before a reservation ends.

The supervisor validates each submitted proof candidate and sends constructive, clause-specific feedback to the Constructor. Count a proof-validation round only when a candidate receives a recorded supervisor verdict. Keep that count separate from interpretation rounds, individual Lean builds, and ordinary implementation attempts. After FAIL, revise and validate again. Stop proof iterations on PASS or after the number of completed proof-validation rounds exceeds 10. The latter condition means round 11 is the last permitted failing review. A round-limit stop must report FAIL or INCOMPLETE and all outstanding work; it must never be called convergence.

A PASS requires all of the following:

- Each of the 24 accepted top-level specifications has a complete general theorem establishing every applicable clause. Each theorem has substantive supporting reasoning and explicit justified assumptions. Assuming the specification, supplying each global conclusion as an opaque premise, or hiding a clause in an unverified Boolean cannot establish completion.
- Lean kernel checking succeeds for the entire active development and the claimed results. No `sorry`, `admit`, target-specific axiom, or unchecked replacement of a proof is permitted. Audit the axioms of claimed results using `scripts/construction/audit_axioms.lean` and `scripts/construction/export_proof_audit.lean`. Permit the three standard foundational axioms and closed native-decision results that the audit re-evaluates successfully. The trusted computing base explicitly includes Lean’s compiler, evaluator, runtime, executed replacement implementations, the C compiler, LLVM when used, and the native linking toolchain. Follow `docs/proof_trust.md`. Prefer `native_decide` for concrete computable checks; retain symbolic proofs or kernel reduction when native evaluation is inapplicable. Computational uses of `decide` inside Boolean checker definitions remain executable code.
- Reusable semantics and general requirement proofs are independent of concrete configurations and snapshots. Their imports and declarations must reflect that separation. Concrete imported facts, generated witnesses, and local checks live in the evidence modules. Check general theorem reuse on materially different applicable configurations.
- Each modeled deployment claim identifies the concrete checks that establish its premises. Record truth-of-observation and implementation-correspondence assumptions explicitly. Required deployment premises that remain unchecked keep that deployment claim conditional. Empty inventories, impossible starts, or disabled traffic must not silently make a safety claim vacuous.
- The source-to-specification comparison remains valid for the final source hashes. Review all 24 groups clause by clause. Validate changed parsers and imports, representative positive and negative cases, and the absence of proof comments. Confirm library reuse and archive isolation.

The other 52 groups retain explicit status in the register without being counted as one of the 24 completed proof targets. Their prior direct-check or external-evidence disposition must not be used to silently discard a clause from a selected group.

Missing importer functionality, incomplete packet-processing models, repairable deployment flaws, and failed proof attempts remain actionable work. New MCP observations must be incorporated into the affected proofs or direct checks, and outstanding construction work must be completed. An unsupported MCP result or a status assignment alone does not justify convergence.

For each obligation that cannot be established within scope, record the exact blocked clauses, the supporting reason, the attempted remedies, and the evidence, capability, or source clarification needed to proceed. Distinguish unavailable evidence, actual requirement violations, unresolved source meaning, and mathematical impossibility. A deployment limitation does not by itself make a specification or a general conditional theorem mathematically unprovable. Continue proving independent, well-defined clauses in the same group. A temporarily blocked run remains incomplete unless the completion criteria are met.

Use distinct outcomes for fully established targets, partial results, conditional results with outstanding assumptions, demonstrated violations, unavailable evidence, unresolved interpretation, and unresolved proof construction. Applicability exclusions require a source-based explanation. A documented scope limit or unavailable external capability may close an evidence request while leaving its affected clause unproved. The coordinator must check each claimed limitation against the authorized extensions and available alternatives before accepting it as a reason that no actionable work remains. Do not repeat an unchanged request after a justified limitation has been recorded unless new information changes the available remedies.

Before declaring convergence, validate source fidelity, coverage of all 76 targets and their clauses, representative-case coverage, importer behavior, proof compilation, assumption accounting, and archive isolation. Check that missing-reference limitations have documented official-source retrieval attempts and that retrieved information has been incorporated into affected obligations. Check the separation of general network, CSfC, and snapshot modules. Demonstrate reuse across materially different applicable configurations. Confirm that required packet-execution connections have been established or have a clause-specific justified limitation. Report remaining limitations explicitly. A whole RG remains unproved when any applicable clause is still blocked, even if its other clauses have passed.

### 7.1. Demonstrate clause-level completion

The Constructor Agent must demonstrate that every clause of all 24 accepted specifications is proved before a PASS. The round-limit rule permits stopping with an explicit incomplete result. A direct-check decision closes the need for a standalone Lean proof of that finite comparison. A proof remains practically tractable when its obligation can be established through available evidence, reasonable implementation or collection extensions, a defensible documented interpretation, and supported proof methods within the authorized scope. Missing code, a difficult proof attempt, elapsed rounds, or the approaching end of a server reservation do not by themselves establish that further work is intractable.

Prepare `data/construction/<run>/completion_assessment.md` with a clause-level accounting of all 76 groups. For each completed behavioral obligation, identify the specification, general theorem, checked snapshot applications, interpretation decisions, and successful validation commands. For a direct check, identify the comparison, input files and hashes, validator, result, and trust assumptions. Both records must describe the final source and evidence versions. For each unfinished obligation, state the precise remaining task, the attempts and alternatives considered, the concrete external or practical limitation, and the records supporting that assessment. Explain why available evidence, authorized extensions, alternative proof decompositions, or reusable library results cannot presently resolve the remaining task. Check that independent clauses in the same group have been completed.

The Constructor Agent accounts for remaining formalization, proof, collection, and parser work. It cites MCP responses, source observations, capability-extension attempts, and relevant library decisions from `library_reuse.md`. The coordinator accounts for deployment changes and unavailable infrastructure, checks the conclusions against the artifacts, and reopens any obligation whose claimed limitation is unsupported or has an actionable remedy. Record disagreements and their resolution. The final report must link the assessment and summarize completed and unfinished obligations with their reasons.

The workflow may declare completion only after the assessment satisfies every v3.1 PASS criterion. An interruption or resource loss must be reported as an incomplete run with pending work. The assessment documents the basis for stopping; it must not present failed attempts as a mathematical proof of impossibility.

### 7.2. Preserve a reconstructable evolution record

Each run records the baseline commit, toolchain and package revisions, model and reasoning settings, workspace restrictions, permitted inputs, and initial source hashes. Keep separate `interpretation/round-NNN/` and `proof/round-NNN/` directories. Never reuse a previous run directory or replace a completed round's records. Preserve each submitted source candidate, a manifest of hashes, its diff from the preceding candidate, and the complete agent instruction and response text. Also record supervisor comparisons, verdicts, feedback, and the Constructor's response to every requested change.

Maintain an append-only UTC event log with actor, affected RG clauses, before and after states, reason, changed files, and links to the supporting records. Save build and test commands, exit codes, full output, axiom-audit results, and MCP requests and responses with secrets redacted. Capture deployment changes and their before/after configurations and observations. Record failed attempts and rejected evidence requests as well as successful ones. Keep the final accepted clause-to-proof mapping and a concise account of why every specification, model, parser, or network change was necessary.

## 8. Final deliverables

The final report must explain what the new development establishes and what remains open. Deliver:

- Reproducible Twinet configurations and a coverage register for all extracted examples and alternatives.
- Versioned snapshots, server configuration, adapter and parser versions, MCP call records, and resolved or outstanding evidence requests.
- Retrieved official references with source URLs, versions, retrieval timestamps, content hashes, and requirement mappings.
- A separate `interpretations.md` documenting original-document checks, selected readings, alternatives, justifications, and affected proofs.
- A `completion_assessment.md` demonstrating completion of all practically tractable proof work and supporting every remaining limitation with clause-specific records.
- A `library_reuse.md` documenting evaluated Mathlib and CSLib declarations, actual uses, justified rejections, and tested dependency compatibility.
- The refined MCP adapters, parsers, export views, and Lean development, with a general network library, reusable CSfC specifications and proofs, and separate snapshot applications.
- A register covering all 76 groups, with clause-level assurance decisions and supporting evidence. Behavioral entries include specification names, general theorem names, supporting lemmas, and checked applications. Direct-check entries include validator commands and results.
- A map showing how each top-level specification is established by general theorems and lemmas, which concrete checks discharge their premises, and which assumptions remain unfulfilled.
- Reuse validation showing unchanged general proofs applied to materially different supported configurations, plus reasons for any model or proof extensions.
- A recorded sequence of proof attempts, MCP queries and exports, parser extensions, and deployment changes showing why each revision was needed.
- Blind interpreter translations, supervisor source comparisons, accepted specification hashes, proof-round verdicts, and a final PASS, FAIL, or INCOMPLETE result.
- Validation results and a clear account of assumptions, unresolved obligations, and rejected requests.
