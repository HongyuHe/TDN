# Independent review of the CSfC role ontology

The ontology extension passes the stated independent review after three verified corrections. The final hierarchy covers all 76 extracted roles. It contains 40 source-backed subclass decisions, 44 explicitly organizational root links, and 31 association annotations. Eight roles retain multiple direct parents. The OWL export contains 77 classes and 4,292 RDF triples.

## Review scope and independence

The reviewer read all 40 subtype decisions, all 31 associations, all 14 excluded inferences, and their cited source-index passages. The review also checked every role projection, all eight navigation families, the exporter, the HTML template, the new tests, and the changed pipeline integration. The review compared the retained source PDF and unchanged artifacts with the prior audit hashes. The unchanged requirement and network interpretations retain the scope of the prior plan audit; the ontology review does not claim a new full-document audit.

The reviewer wrote findings, reports, and binding evidence only. The coordinator authored the exporter and visualization, and a separate curator authored the relationship decisions. The coordinator ran browser interactions and the isolated portability replay. The reviewer independently ran the tests and RDF comparisons, inspected the implementation, and viewed the three final browser screenshots. Curation notes and coordinator evidence identify their separate provenance.

## Semantic assessment

Every asserted subtype passes the source-context inclusion test within the stated curation scope. Inner and outer VPN/MACsec roles preserve both technology and encryption-layer parents. The Key Server subtype follows the glossary definition of a designated MACsec Device. AW-to-Management component and Key/certificate management-to-Management component remain explicitly labeled source interpretations. Selective Solution Component membership preserves the source boundary around external routers, generic CAs, and Black AW mentions.

The ontology keeps conditional relationships and realization choices as annotations. AW realization, VM hosting, authentication functions, certificate provisioning, log collection, and aggregate composition carry source evidence and qualifications. Root CA and Trust Anchor CA remain separate classes. The encapsulator boundary remains unresolved under REQ-I01. No omitted relationship is interpreted as negation or disjointness.

The class interpretation preserves the heterogeneous source inventory. Role categories and uncertainty metadata survive in JSON and OWL. The Registration Authority qualification retains the original hardware/software inventory boundary. The export introduces no named deployment individuals, class-equivalence axioms, disjointness axioms, or object-property restrictions. The topic families organize the interface only. The organizational root and its 44 links are clearly distinguished from source-backed subtype decisions.

The OWL serialization uses blank-node axiom annotations under the [W3C mapping for annotated axioms](https://www.w3.org/TR/owl2-mapping-to-rdf/#Axioms_that_Generate_a_Main_Triple). Class inclusion and class-level annotations follow the distinctions described in the [W3C OWL 2 Primer](https://www.w3.org/TR/owl2-primer/). The review checks the constructs actually emitted; it does not claim execution of a general OWL DL reasoner.

## Verification and corrections

The independent checks pass for exact class coverage, hierarchy closure, source quotations, page references, all relationship metadata, role categories, and the Registration Authority qualification. RDFLib parsed both serializations and found isomorphic graphs. Every subclass and association has its expected annotated record. All 115 annotation records use blank nodes. The five delivered outputs exactly match an in-memory deterministic replay. The independent test invocation passed all 30 tests.

The three review findings are resolved and verified. ONT-001 corrected named-IRI axiom reification. ONT-002 corrected stale wording about the already-resolved AW-host issue. ONT-003 restored role kinds and the Registration Authority qualification. The findings file distinguishes the two reviewer-origin findings from the coordinator-origin metadata finding.

The frozen browser evidence covers all 76 roles at widths of 1600, 900, and 390 pixels. It records working source views, search, topic filtering, association toggles, hierarchy navigation, theme changes, and downloads that match the exports. The report records no JavaScript errors, external requests, or layout issues. The independent reviewer inspected the template and the final light, dark, and mobile screenshots. The screenshots and report are pinned to the delivered HTML hash. The coordinator's isolated derived replay also passed without the separate docs directory.

## Binding and remaining limits

The new manifest retains all 57 keys from the prior plan audit and adds the ontology artifacts, inputs, implementation dependencies, and review evidence. Five prior entries receive reviewed current hashes. Three entries contain pipeline integration changes. The other two add only the ontology-navigation paragraph to roles.md and its producer; removing exactly that paragraph reproduces both prior hashes. The original roles.json, source PDF, source index, requirement data, network data, and prior review files remain unchanged.

The review remains complete only for its stated scope. Eleven source-interpretation or external-scope issues remain, and downstream formalization readiness stays false. The ontology does not settle those issues, prove a Lean theorem, or establish CSfC deployment compliance. A final all-stage replay after binding is a separate coordinator check. Generated status summaries, validation reports, README, and replay logs remain outside the binding because those files are refreshed by that check.
