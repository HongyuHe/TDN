# Cross-artifact mechanical validation

Status: **pass**. Semantic review remains a separate assessment.

- PASS: all_source_references_resolve. []
- PASS: all_indexed_quotations_match. []
- PASS: requirements_use_current_source_index. "39b9770a52900512a58e468a83839238d4583e030ac76870fd8f11e4aff2d5dc"
- PASS: every_source_assigned. {"source_units": 1596, "assigned_units": 1596, "unassigned": []}
- PASS: one_unique_theorem_per_requirement_group. {"groups": 76, "invalid_groups": []}
- PASS: background_has_no_theorem. "BG-001"
- PASS: requirement_group_ids_unique. []
- PASS: original_requirement_map_export_matches_groups. "The separate map must equal the map in groups.json."
- PASS: example_assessments_are_complete_scoped_and_source_grounded. []
- PASS: all_original_requirement_ids_mapped. {"original_requirement_ids": 214}
- PASS: network_roles_endpoints_and_requirement_groups. []
- PASS: role_instance_export_matches_examples. {"expected_instances": 125}
- PASS: role_mentions_have_exact_source_spans. {"mentions": 1328, "invalid": []}
- PASS: all_roles_have_evidence. {"roles": 76}
- PASS: role_ontology_matches_roles_evidence_and_curated_hierarchy. {"stale_outputs": [], "counts": {"extracted_roles": 76, "owl_classes": 77, "source_backed_subclass_edges": 40, "organizational_root_edges": 44, "annotation_associations": 31, "multiple_parent_roles": 8}}
- PASS: all_ten_figures_registered_once. {"figures": 10, "topology_figures": 9, "protocol_figures": 1}
- PASS: all_crops_present_and_reviewed. []
- PASS: example_categories_are_separate_and_complete. []
- PASS: example_reports_have_all_relative_figure_links. ["crops/figure-01.png", "crops/figure-02.png", "crops/figure-03.png", "crops/figure-04.png", "crops/figure-05.png", "crops/figure-06.png", "crops/figure-07.png", "crops/figure-08.png", "crops/figure-09.png", "crops/figure-10.png"]
- PASS: all_full_captions_match_indexed_pdf_spans. {"captions": 10}
- PASS: readable_network_assessments_match_structured_records. []
- PASS: source_validation_passed. "pass"
- PASS: independent_review_and_recorded_updates_have_valid_provenance. {"status": "current", "review_directory": "validation/ontology_review", "changed_artifacts": [], "missing_bindings": [], "missing_review_reports": [], "review_status": "reviewed_with_unresolved_source_interpretations", "semantic_verdict_is_separate": true, "relocation_receipt": "validation/network_source_precedence_update.json", "relocation_scope": "Apply the user-directed policy that explicit text supplies details omitted from schematic figures. Resolve NET-001-MAP-05 and NET-009-MAP-02 as presented_as_satisfying at the described-design level, add the controlling source passages, and label text-only configurations. Preserve earlier layout, presentation, and path changes. Independent reviews remain historical; the two amended judgments received coordinator verification only. Omit routine missing implementation details and repeated partial-topology disclaimers from example unknowns; retain example-specific uncertainties. Assessment judgments are unchanged by that cleanup. Separate network topologies, partial configurations and alternatives, and protocol exchanges into category-specific overviews. Preserve IDs, canonical records, assessments, figures, and quotations. The added reports are generated views with coordinator validation. No new independent semantic review is claimed.", "post_review_semantic_amendments": [{"mapping_id": "NET-001-MAP-05", "before": "ambiguous", "after": "presented_as_satisfying", "authority": "User instruction: explicit textual descriptions supply details missing from figures.", "review_scope": "Coordinator source verification; no new independent semantic review."}, {"mapping_id": "NET-009-MAP-02", "before": "ambiguous", "after": "presented_as_satisfying", "authority": "User instruction: explicit textual descriptions supply details missing from figures.", "review_scope": "Coordinator source verification; no new independent semantic review."}], "independent_review_covers_current_semantics": false}
