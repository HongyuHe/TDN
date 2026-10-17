# Specification preprocessing prototype

Build a prototype that uses an AI harness and subagents to preprocess specification documents, starting with `docs/CSfC_documentation_v1.3.0.pdf`. Produce separate artifacts for exhaustive source extraction, requirement groups, example networks, and device roles. These artifacts will support later obligation discovery, curation, and Lean formalization.

Use two fixed conventions: each period ends a sentence, and each requirement group targets one encompassing top-level Lean theorem. Supporting definitions and lemmas may be developed during later formalization. The preprocessing stage identifies theorem targets without constructing their proofs.

1. **Create a shared source index.**

   Use ordinary PDF extraction software to obtain baseline text and page coordinates. Use OCR for content that lacks extractable text. Preserve the original PDF and rendered pages so that extraction errors can be checked against the document.

   Give every source unit a stable ID within the document version. Record the document hash, page number, location on the page, unit type, and extracted text. Preserve section headings, requirement labels, captions, footnotes, table headers, and figure references. Record any corrections to extracted text with their source locations.

   All four artifacts must reference these source IDs. Keep quoted source text separate from AI explanations and interpretations. Preserve wording and punctuation verbatim; normalize layout whitespace only through a documented rule, while retaining the original extracted text.

2. **Extract every sentence and contextualized table row.**

   Instruct an extraction subagent to produce the exhaustive source artifact using the baseline text and rendered pages.

   - Split prose at each period and retain the period. Apply the same rule to prose in captions and footnotes. Do not introduce linguistic exceptions or AI-selected sentence boundaries.
   - Preserve headings, labels, and trailing text without a period as separately typed source units.
   - Extract each table row as one structured unit with the relevant column headers, row headers, table title, and applicable notes. Preserve relationships between merged cells and their rows. Table rows remain separate from the prose sentence count.
   - Preserve document order and source locations. Shared table headers may be referenced by multiple rows without becoming duplicate source records.

   **Validation:** Count prose sentences with external software using the same period rule and extraction scope, then compare that total with the subagent's sentence count. Check table-row counts separately. Match records to baseline source spans to detect omissions, duplicates, and text changes that equal counts would miss. Inspect discrepancies against rendered pages and record their resolution. Verify that remaining text is represented by another source-unit type.

3. **Group requirement-bearing sentences verbatim.**

   Instruct a requirement subagent to organize the extracted sentences and table rows into coherent requirement groups. Every requirement group must target exactly one top-level Lean theorem. A theorem may encompass several clauses, cases, or conditions that together express the group's requirement.

   Each group must contain:

   - A stable group ID, descriptive title, and original requirement identifiers where available.
   - Verbatim requirement passages with source IDs.
   - The applicable devices, traffic, configurations, or operating conditions.
   - Exceptions, definitions, qualifications, and cross-references needed to interpret the requirement.
   - The document's stated requirement strength, such as mandatory, recommended, or permitted.
   - One proposed top-level theorem name and a plain-English statement of its intended meaning. Label the statement as an interpretation for later formalization.

   Put uncategorized sentences and general descriptions into one background group. Preserve individual source IDs and reasons for placement. Mark uncertain classifications explicitly within that group so that they remain visible for review. The background group has no theorem target. Background or contextual passages may support multiple requirement groups through shared references.

   Group requirements according to their meaning in the specification. Retain requirements whose evidence needs or provability remain unknown; the current emulation must not determine which document obligations are discovered.

   **Validation:** Assign every source unit to at least one requirement group or the background group. Check every quotation against its indexed source. Require exactly one proposed top-level theorem per requirement group. Have an independent review subagent inspect the original document and the groups for missing obligations, incorrect grouping, altered meaning, omitted exceptions, and unsupported interpretations. Review the background group for requirements placed there by mistake. Resolve findings or retain them as explicit open issues; coverage counts alone do not establish semantic correctness.

4. **Extract example networks.**

   Instruct a network subagent to extract examples described in figures, prose, or tables. Associate related subfigures with the same example network when they describe that example.

   For each network, record:

   - A stable example ID and all supporting source references.
   - Crops of associated figures, including readable legends and captions. Preserve page locations and crop coordinates.
   - Devices, their names, and their roles, such as inner encryptor or outer firewall.
   - Specified links, interfaces, security zones, site boundaries, and shared components.
   - Detailed setup descriptions verbatim, including relevant qualifications and exceptions.
   - The requirements the example illustrates, with links to requirement groups.
   - Whether the document presents the example as satisfying or violating particular requirements. Record unspecified compliance status explicitly.

   Distinguish explicitly stated facts, interpretations of visual symbols, and unknown details. Leave missing configuration values unknown. An example's appearance in the document does not establish complete compliance.

   **Validation:** Maintain a figure-and-example register that maps every relevant figure, subfigure, and textual example to an extracted network record or a justified exclusion. Retain the proposed figure-count comparison as a sanity check, counting related subfigures as one example figure. Review the mappings directly because several figures may describe one network. Check device names, roles, links, and quoted setup descriptions against the source, and verify that each crop is readable and complete.

5. **Extract device roles across the entire document.**

   Instruct a role subagent to identify roles in prose, requirements, tables, and example networks. Record each role's preferred name, source wording, aliases, description, and supporting source IDs. Preserve distinctions that the document makes between roles.

   Distinguish device roles from named device instances. Allow a device to have multiple roles when the document supports that assignment. Mark uncertain alias matches or role assignments for review.

   **Validation:** The role set must include every role used in the extracted example networks. Every role must have supporting source evidence, and every identified role mention must map to a role record or an unresolved item. Independently review the full document for roles omitted from the examples or overlooked during extraction.

6. **Coordinate the harness and deliver the artifacts.**

   Complete and validate the source index before grouping requirements. Example-network and role extraction may proceed alongside requirement grouping once the source index is available. Reconcile references among all three artifacts before final review.

   Store structured records in JSON or JSONL and generate readable Markdown views from those records. Keep the following outputs separate:

   - Document metadata and the shared source index.
   - Exhaustive sentences, contextualized table rows, and other source units.
   - Requirement groups and the background group.
   - Example-network records and figure crops.
   - Device-role records.
   - Validation results, reviewer findings, revisions, and unresolved issues.

   The harness must check source references, text matches, counts, and cross-artifact consistency before requesting semantic review. Reviewer findings should identify affected source and artifact IDs so that the producing subagent can make targeted corrections.

   Report mechanical validation and semantic review separately. Mark an artifact ready for downstream formalization only after its required checks pass and material extraction or interpretation issues are resolved. Retain incomplete artifacts with an explicit incomplete status and their open issues. Completion of preprocessing establishes a reviewed document representation; later work must justify the network models and prove the theorem targets.
