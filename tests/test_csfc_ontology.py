"""Regressions for hierarchy meaning, source coverage, and OWL serialization."""
import copy
import importlib.util
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('csfc_ontology', ROOT / 'scripts/preprocess/preprocess_csfc_ontology.py')
ONTOLOGY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ONTOLOGY)
OUT = ROOT / 'artifacts/extraction'


class RoleOntologyContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.roles = json.loads((OUT / 'roles/roles.json').read_text())
        cls.source = {r['source_id']: r for r in map(json.loads, (OUT / 'source/source_index.jsonl').read_text().splitlines())}
        cls.decisions = json.loads((OUT / 'roles/ontology_decisions.json').read_text())
        cls.graph = ONTOLOGY.build_graph()
        cls.statements = ONTOLOGY.triples(cls.graph)

    def errors(self, decisions):
        return ONTOLOGY.decision_errors(self.roles, self.source, decisions)

    def test_every_extracted_role_has_a_class(self):
        self.assertEqual({n['role_id'] for n in self.graph['nodes']}, {r['role_id'] for r in self.roles} | {'ExtractedRole'})
        self.assertEqual(self.errors(self.decisions), [])

    def test_role_categories_and_source_qualifications_survive(self):
        nodes = {n['role_id']: n for n in self.graph['nodes']}
        for role in self.roles:
            node = nodes[role['role_id']]
            self.assertEqual(node['kind'], role['role_kind'])
            self.assertEqual(node['uncertainty'], role.get('uncertainty', ''))
            self.assertIn((node['iri'], ONTOLOGY.BASE + 'roleKind', role['role_kind'], True), self.statements)
            if role.get('uncertainty'):
                self.assertIn((node['iri'], ONTOLOGY.BASE + 'qualification', role['uncertainty'], True), self.statements)

    def test_inner_vpn_inherits_both_technology_and_layer(self):
        node = next(n for n in self.graph['nodes'] if n['role_id'] == 'ROLE-inner-vpn')
        self.assertIn('ROLE-vpn-gateway', node['parents'])
        self.assertIn('ROLE-inner-encryption', node['parents'])
        self.assertIn('ROLE-encryption-component', node['ancestors'])

    def test_cycle_is_rejected_as_invalid_hierarchy(self):
        decision = copy.deepcopy(self.decisions)
        edge = copy.deepcopy(decision['subclass_edges'][0])
        edge['child'], edge['parent'] = edge['parent'], edge['child']
        decision['subclass_edges'].append(edge)
        self.assertTrue(any('cycle' in error.lower() for error in self.errors(decision)))

    def test_unknown_parent_is_rejected(self):
        decision = copy.deepcopy(self.decisions)
        decision['subclass_edges'][0]['parent'] = 'ROLE-unrecorded'
        self.assertTrue(any('Unknown subtype endpoint' in error for error in self.errors(decision)))

    def test_unknown_evidence_is_rejected(self):
        decision = copy.deepcopy(self.decisions)
        decision['subclass_edges'][0]['source_ids'] = ['invented-source']
        self.assertTrue(any('source references' in error for error in self.errors(decision)))

    def test_missing_family_member_is_rejected(self):
        decision = copy.deepcopy(self.decisions)
        decision['families'][0]['role_ids'].pop()
        self.assertTrue(any('partition' in error for error in self.errors(decision)))

    def test_associations_are_annotations_not_subtypes(self):
        rdf_type = ONTOLOGY.NS['rdf'] + 'type'
        annotation = ONTOLOGY.NS['owl'] + 'AnnotationProperty'
        for edge in self.graph['associations']:
            prop = ONTOLOGY.BASE + edge['relation']
            self.assertIn((prop, rdf_type, annotation, False), self.statements)
            self.assertIn((ONTOLOGY.BASE + edge['source'], prop, ONTOLOGY.BASE + edge['target'], False), self.statements)
        self.assertFalse(any(p == rdf_type and o == ONTOLOGY.NS['owl'] + 'ObjectProperty' for _, p, o, _ in self.statements))

    def test_axiom_annotations_use_blank_nodes(self):
        axiom = ONTOLOGY.NS['owl'] + 'Axiom'
        nodes = {s for s, p, o, literal in self.statements if p == ONTOLOGY.NS['rdf'] + 'type' and o == axiom and not literal}
        self.assertEqual(len(nodes), len(self.graph['subclass_edges']) + len(self.graph['associations']))
        self.assertTrue(all(n.startswith('_:') for n in nodes))
        tree = ET.fromstring(ONTOLOGY.rdf_xml(self.statements))
        blank_descriptions = [d for d in tree if '{' + ONTOLOGY.NS['rdf'] + '}nodeID' in d.attrib]
        self.assertEqual(len(blank_descriptions), len(nodes))
        self.assertTrue(all('{' + ONTOLOGY.NS['rdf'] + '}about' not in d.attrib for d in blank_descriptions))

    def test_source_qualifiers_survive_xml_round_trip(self):
        text = ONTOLOGY.rdf_xml(self.statements)
        self.assertEqual(ONTOLOGY.read_generated_xml(text), set(self.statements))
        self.assertTrue(any(p == ONTOLOGY.BASE + 'qualification' for _, p, _, _ in self.statements))

    def test_input_drift_requires_recuration(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            for name in ['roles/roles.json', 'roles/ontology_decisions.json', 'source/source_index.jsonl']:
                target = out / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((OUT / name).read_bytes())
            roles = copy.deepcopy(self.roles)
            roles[0]['preferred_name'] = 'Changed source role'
            (out / 'roles/roles.json').write_text(json.dumps(roles))
            with self.assertRaisesRegex(ValueError, 'input hash differs'):
                ONTOLOGY.build_graph(out)

    def test_open_world_scope_does_not_invent_equivalence_or_disjointness(self):
        prohibited = {ONTOLOGY.NS['owl'] + p for p in ['equivalentClass', 'disjointWith', 'sameAs']}
        self.assertFalse(any(predicate in prohibited for _, predicate, _, _ in self.statements))
        self.assertFalse(any(obj == ONTOLOGY.NS['owl'] + 'NamedIndividual' for _, _, obj, _ in self.statements))

    def test_html_embeds_the_current_graph_safely(self):
        graph, _, outputs = ONTOLOGY.expected_outputs()
        self.assertIn('data-theme="light"', outputs['ontology.html'])
        self.assertNotIn('__ONTOLOGY_DATA__', outputs['ontology.html'])
        self.assertEqual(json.loads(outputs['ontology.json'])['counts'], graph['counts'])
        self.assertNotIn('<script src=', outputs['ontology.html'])


if __name__ == '__main__':
    unittest.main()
