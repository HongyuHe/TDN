#!/usr/bin/env python3
"""Build a source-backed role hierarchy, OWL exports, and an offline explorer."""
import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'artifacts/extraction'
BASE = 'urn:tdn:csfc:msc:roles:'
ONTOLOGY_IRI = 'urn:tdn:csfc:msc:roles'
NS = {'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#', 'rdfs': 'http://www.w3.org/2000/01/rdf-schema#', 'owl': 'http://www.w3.org/2002/07/owl#', 'skos': 'http://www.w3.org/2004/02/skos/core#', 'tdn': BASE}
for prefix, uri in NS.items():
    ET.register_namespace(prefix, uri)
OUTPUT_NAMES = ['ontology.json', 'ontology.owl', 'ontology.ttl', 'ontology.md', 'ontology.html']
TEMPLATE = ROOT / 'scripts/preprocess/templates/csfc_role_ontology.html'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def source_iri(source_id):
    return 'urn:tdn:csfc:source:' + source_id


def decision_errors(roles, source, decisions):
    ids = {r['role_id'] for r in roles}
    errors = []
    if len(ids) != len(roles):
        errors.append('Duplicate extracted role identifiers.')
    if decisions.get('root', {}).get('id') != 'ExtractedRole':
        errors.append('The organizational root must be ExtractedRole.')
    assigned = [rid for family in decisions['families'] for rid in family['role_ids']]
    if set(assigned) != ids or len(assigned) != len(ids):
        errors.append('Navigation families must partition the extracted roles exactly.')
    if len({f['id'] for f in decisions['families']}) != len(decisions['families']):
        errors.append('Duplicate navigation family identifiers.')
    parents = defaultdict(list)
    pairs = []
    for edge in decisions['subclass_edges']:
        child, parent = edge['child'], edge['parent']
        pairs.append((child, parent))
        if child not in ids or parent not in ids:
            errors.append('Unknown subtype endpoint: ' + child + ' / ' + parent)
        if child == parent:
            errors.append('A role cannot be its own immediate parent: ' + child)
        parents[child].append(parent)
    if len(set(pairs)) != len(pairs):
        errors.append('Duplicate subtype edges.')
    for role_id in ids:
        pending, visited = list(parents[role_id]), set()
        while pending:
            parent = pending.pop()
            if parent == role_id:
                errors.append('Subtype cycle reaches ' + role_id)
                break
            if parent not in visited:
                visited.add(parent)
                pending.extend(parents[parent])
    association_keys = []
    for relation in decisions['associations']:
        if relation['source'] not in ids or relation['target'] not in ids:
            errors.append('Unknown association endpoint.')
        if not re.fullmatch(r'[a-z][a-z0-9_]*', relation['relation']):
            errors.append('Invalid association identifier: ' + relation['relation'])
        association_keys.append((relation['source'], relation['relation'], relation['target']))
    if len(set(association_keys)) != len(association_keys):
        errors.append('Duplicate associations.')
    for edge in decisions['subclass_edges'] + decisions['associations']:
        if edge.get('basis') not in {'source_stated', 'source_interpretation'}:
            errors.append('Missing or unsupported relationship evidence basis.')
        if not edge.get('rationale', '').strip() or not isinstance(edge.get('qualifications'), list):
            errors.append('Missing relationship rationale or qualifications.')
        if not edge.get('source_ids') or not set(edge['source_ids']) <= set(source):
            errors.append('Missing or unknown relationship source references.')
    for excluded in decisions.get('excluded_inferences', []):
        if not excluded.get('source_ids') or not set(excluded['source_ids']) <= set(source):
            errors.append('Excluded inference has missing or unknown evidence.')
    return errors


def ancestors(role_id, parents):
    found, pending = set(), list(parents.get(role_id, []))
    while pending:
        parent = pending.pop()
        if parent not in found:
            found.add(parent)
            pending.extend(parents.get(parent, []))
    return sorted(found)


def build_graph(out=OUT):
    roles = read(out / 'roles/roles.json')
    source = {r['source_id']: r for r in map(json.loads, (out / 'source/source_index.jsonl').read_text().splitlines())}
    decisions = read(out / 'roles/ontology_decisions.json')
    errors = decision_errors(roles, source, decisions)
    for key, filename in [('source_roles_sha256', 'roles/roles.json'), ('source_index_sha256', 'source/source_index.jsonl')]:
        if decisions.get(key) != digest(out / filename):
            errors.append('Curated ontology input hash differs: ' + filename)
    if errors:
        raise ValueError('\n'.join(errors))
    families = {rid: f['id'] for f in decisions['families'] for rid in f['role_ids']}
    root = {**decisions['root'], 'role_id': 'ExtractedRole', 'iri': BASE + 'ExtractedRole', 'source_ids': [], 'family': 'organization', 'aliases': [], 'kind': 'analyst_organization'}
    nodes = [root]
    for role in roles:
        nodes.append({'role_id': role['role_id'], 'iri': BASE + role['role_id'], 'label': role['preferred_name'], 'description': role['description']['text'], 'aliases': role['aliases'], 'source_ids': role['source_ids'], 'family': families[role['role_id']], 'kind': role.get('role_kind', 'extracted_role'), 'uncertainty': role.get('uncertainty', '')})
    edges = []
    for edge in decisions['subclass_edges']:
        edges.append({**edge, 'type': 'subclass'})
    children_with_parents = {e['child'] for e in edges}
    for role in roles:
        if role['role_id'] not in children_with_parents:
            edges.append({'child': role['role_id'], 'parent': 'ExtractedRole', 'type': 'subclass', 'basis': 'analyst_organization', 'source_ids': [], 'rationale': 'Attach an otherwise unparented extracted role to the organizing root. The root is an analyst-defined category.', 'qualifications': ['The document does not define the organizing root.']})
    for index, edge in enumerate(edges, 1):
        edge['edge_id'] = f'subclass-{index:03}'
    associations = [{**a, 'edge_id': f'association-{i:03}', 'type': 'annotation_association'} for i, a in enumerate(decisions['associations'], 1)]
    parents = defaultdict(list)
    for edge in edges:
        parents[edge['child']].append(edge['parent'])
    for node in nodes:
        node['parents'] = parents[node['role_id']]
        node['ancestors'] = ancestors(node['role_id'], parents)
    used_sources = {sid for node in nodes for sid in node['source_ids']}
    used_sources.update(sid for edge in edges + associations + decisions.get('excluded_inferences', []) for sid in edge['source_ids'])
    source_views = {sid: {'text': source[sid]['text'], 'pages': sorted({p['page'] for p in source[sid]['locations']})} for sid in sorted(used_sources)}
    return {'schema_version': '1.0', 'ontology_iri': ONTOLOGY_IRI, 'class_semantics': 'A class describes entities matching an extracted role or realization concept. Classes may overlap and may have multiple parents. No device existence, class disjointness, or class equivalence is asserted.', 'association_semantics': 'Non-subtype links are OWL annotation assertions between class IRIs. They preserve source context without imposing object-property restrictions or asserting a relationship for every class member.', 'root_id': 'ExtractedRole', 'families': decisions['families'], 'nodes': nodes, 'subclass_edges': edges, 'associations': associations, 'excluded_inferences': decisions.get('excluded_inferences', []), 'sources': source_views, 'input_hashes': {'roles/roles.json': digest(out / 'roles/roles.json'), 'source/source_index.jsonl': digest(out / 'source/source_index.jsonl'), 'roles/ontology_decisions.json': digest(out / 'roles/ontology_decisions.json')}, 'counts': {'extracted_roles': len(roles), 'owl_classes': len(nodes), 'source_backed_subclass_edges': len(decisions['subclass_edges']), 'organizational_root_edges': len(edges) - len(decisions['subclass_edges']), 'annotation_associations': len(associations), 'multiple_parent_roles': sum(len(n['parents']) > 1 for n in nodes)}}


def triples(graph):
    result = set()
    def add(subject, predicate, value, literal=False):
        result.add((subject, predicate, value, literal))
    rdf_type, label = NS['rdf'] + 'type', NS['rdfs'] + 'label'
    add(ONTOLOGY_IRI, rdf_type, NS['owl'] + 'Ontology')
    add(ONTOLOGY_IRI, NS['rdfs'] + 'comment', graph['class_semantics'] + ' ' + graph['association_semantics'], True)
    add(ONTOLOGY_IRI, NS['owl'] + 'versionInfo', 'CSfC MSC 1.3.0; TDN role hierarchy 1.0', True)
    props = ['roleId', 'roleKind', 'sourceUnit', 'sourceText', 'pdfPages', 'basis', 'rationale', 'qualification', 'inputHash']
    props += sorted({a['relation'] for a in graph['associations']})
    for prop in props:
        add(BASE + prop, rdf_type, NS['owl'] + 'AnnotationProperty')
    add(NS['skos'] + 'altLabel', rdf_type, NS['owl'] + 'AnnotationProperty')
    for filename, sha in graph['input_hashes'].items():
        add(ONTOLOGY_IRI, BASE + 'inputHash', filename + ' sha256:' + sha, True)
    for node in graph['nodes']:
        iri = node['iri']
        add(iri, rdf_type, NS['owl'] + 'Class')
        add(iri, label, node['label'], True)
        add(iri, NS['rdfs'] + 'comment', node['description'], True)
        add(iri, BASE + 'roleId', node['role_id'], True)
        add(iri, BASE + 'roleKind', node['kind'], True)
        if node.get('uncertainty'):
            add(iri, BASE + 'qualification', node['uncertainty'], True)
        for alias in node['aliases']:
            if alias != node['label']:
                add(iri, NS['skos'] + 'altLabel', alias, True)
        for sid in node['source_ids']:
            add(iri, BASE + 'sourceUnit', source_iri(sid))
    for edge in graph['subclass_edges'] + graph['associations']:
        if edge['type'] == 'subclass':
            subject, predicate, target = BASE + edge['child'], NS['rdfs'] + 'subClassOf', BASE + edge['parent']
        else:
            subject, predicate, target = BASE + edge['source'], BASE + edge['relation'], BASE + edge['target']
        add(subject, predicate, target)
        axiom = '_:' + edge['edge_id']
        add(axiom, rdf_type, NS['owl'] + 'Axiom')
        add(axiom, NS['owl'] + 'annotatedSource', subject)
        add(axiom, NS['owl'] + 'annotatedProperty', predicate)
        add(axiom, NS['owl'] + 'annotatedTarget', target)
        for key in ['basis', 'rationale']:
            add(axiom, BASE + key, edge[key], True)
        for qualification in edge['qualifications']:
            add(axiom, BASE + 'qualification', qualification, True)
        for sid in edge['source_ids']:
            add(axiom, BASE + 'sourceUnit', source_iri(sid))
    for sid, source in graph['sources'].items():
        add(source_iri(sid), label, sid, True)
        add(source_iri(sid), BASE + 'sourceText', source['text'], True)
        add(source_iri(sid), BASE + 'pdfPages', ', '.join(map(str, source['pages'])), True)
    return sorted(result)


def xml_name(uri):
    for prefix, namespace in NS.items():
        if uri.startswith(namespace):
            return '{' + namespace + '}' + uri[len(namespace):]
    raise ValueError('Unknown predicate namespace: ' + uri)


def rdf_xml(statements):
    root = ET.Element('{' + NS['rdf'] + '}RDF')
    subjects = {}
    for subject, predicate, value, literal in statements:
        if subject not in subjects:
            attribute = 'nodeID' if subject.startswith('_:') else 'about'
            identifier = subject[2:] if subject.startswith('_:') else subject
            subjects[subject] = ET.SubElement(root, '{' + NS['rdf'] + '}Description', {'{' + NS['rdf'] + '}' + attribute: identifier})
        element = ET.SubElement(subjects[subject], xml_name(predicate))
        if literal:
            element.text = value
        else:
            element.set('{' + NS['rdf'] + '}resource', value)
    ET.indent(root, space='  ')
    return ET.tostring(root, encoding='unicode', xml_declaration=True) + '\n'


def turtle(statements):
    def term(value):
        if value.startswith('_:'):
            return value
        for prefix, namespace in NS.items():
            local = value[len(namespace):] if value.startswith(namespace) else ''
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*', local):
                return prefix + ':' + local
        return '<' + value + '>'
    lines = ['@prefix ' + prefix + ': <' + uri + '> .' for prefix, uri in NS.items()] + ['']
    for subject, predicate, value, literal in statements:
        obj = json.dumps(value, ensure_ascii=False) if literal else term(value)
        lines.append(term(subject) + ' ' + term(predicate) + ' ' + obj + ' .')
    return '\n'.join(lines) + '\n'


def markdown(graph):
    nodes = {n['role_id']: n for n in graph['nodes']}
    lines = ['# CSfC role ontology', '', 'The hierarchy organizes all extracted roles and preserves source evidence for each subtype relationship. A role can have multiple parents. The navigation families group related topics for browsing and add no OWL subclass claims.', '', '[Interactive explorer](ontology.html) | [OWL in RDF/XML](ontology.owl) | [Turtle](ontology.ttl) | [Structured graph](ontology.json) | [Curation decisions](ontology_decisions.json)', '', graph['class_semantics'], '', graph['association_semantics'], '', 'OWL uses an open-world interpretation: an absent relationship remains unasserted. The extraction validators separately check that every extracted role and every declared evidence reference is present.', '', 'The transitive parent lists are computed for the exported subclass graph. The pipeline validates its supported serialization and hierarchy; it does not run a general OWL DL reasoner or prove CSfC compliance.', '', '## Counts', '']
    lines += ['- ' + key.replace('_', ' ') + ': ' + str(value) for key, value in graph['counts'].items()]
    for family in graph['families']:
        lines += ['', '## ' + family['label'], '', '| Role | Direct broader roles |', '| --- | --- |']
        for rid in family['role_ids']:
            node = nodes[rid]
            lines.append('| ' + node['label'] + ' | ' + ', '.join(nodes[p]['label'] for p in node['parents']) + ' |')
    lines += ['', '## Role scope notes', '']
    lines += ['- **' + n['label'] + '**: ' + n['uncertainty'] for n in graph['nodes'] if n.get('uncertainty')]
    lines += ['', '## Subtype evidence', '']
    for edge in graph['subclass_edges']:
        if edge['basis'] == 'analyst_organization':
            continue
        lines += ['### ' + nodes[edge['child']]['label'] + ' → ' + nodes[edge['parent']]['label'], '', edge['rationale'], '', 'Basis: ' + edge['basis'] + '.', '']
        lines += ['- ' + q for q in edge['qualifications']]
        for sid in edge['source_ids']:
            lines += ['', '`' + sid + '`', '', '> ' + graph['sources'][sid]['text']]
    lines += ['', '## Documented associations', '']
    for edge in graph['associations']:
        lines += ['### ' + nodes[edge['source']]['label'] + ' — ' + edge['label'] + ' — ' + nodes[edge['target']]['label'], '', edge['rationale'], '', 'Basis: ' + edge['basis'] + '. The relationship is an annotation assertion.', '']
        lines += ['- ' + q for q in edge['qualifications']]
        for sid in edge['source_ids']:
            lines += ['', '`' + sid + '`', '', '> ' + graph['sources'][sid]['text']]
    lines += ['', '## Inferences deliberately left unasserted', '']
    for exclusion in graph['excluded_inferences']:
        lines += ['- **' + exclusion['claim'] + '**: ' + exclusion['reason']]
    lines += ['', '## Regenerate and check', '', 'Run from the repository root:', '', '```bash', 'python3 scripts/preprocess/run_csfc_preprocessing.py --stage ontology', 'python3 scripts/preprocess/preprocess_csfc_ontology.py --check', '```', '', 'The pipeline uses explicit curated decisions for the pinned source. Changes to the role inventory or source index invalidate the decision hashes and require updating the hierarchy evidence.', '', 'An optional independent RDF parser check is available after installing the package in `scripts/preprocess/requirements-csfc-ontology.txt`:', '', '```bash', 'python3 scripts/preprocess/preprocess_csfc_ontology.py --check --rdf-check', '```', '', 'OWL semantics and RDF/XML mapping follow the [W3C OWL 2 Primer](https://www.w3.org/TR/owl2-primer/) and [OWL 2 Mapping to RDF Graphs](https://www.w3.org/TR/owl2-mapping-to-rdf/).', '']
    return '\n'.join(lines)


def expected_outputs(out=OUT):
    graph = build_graph(out)
    statements = triples(graph)
    xml, ttl = rdf_xml(statements), turtle(statements)
    payload = {**graph, 'downloads': {'owl': xml, 'turtle': ttl}}
    embedded = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    template = TEMPLATE.read_text()
    if template.count('__ONTOLOGY_DATA__') != 1:
        raise ValueError('The HTML template must contain one data placeholder.')
    outputs = {'ontology.json': json.dumps(graph, ensure_ascii=False, indent=2) + '\n', 'ontology.owl': xml, 'ontology.ttl': ttl, 'ontology.md': markdown(graph), 'ontology.html': template.replace('__ONTOLOGY_DATA__', embedded)}
    return graph, statements, outputs


def read_generated_xml(text):
    parsed = ET.fromstring(text)
    found = set()
    if parsed.tag != '{' + NS['rdf'] + '}RDF':
        raise ValueError('Expected RDF/XML root.')
    for description in parsed:
        subject = description.attrib.get('{' + NS['rdf'] + '}about')
        if subject is None:
            subject = '_:' + description.attrib['{' + NS['rdf'] + '}nodeID']
        for prop in description:
            namespace, local = prop.tag[1:].split('}', 1)
            resource = prop.attrib.get('{' + NS['rdf'] + '}resource')
            found.add((subject, namespace + local, prop.text or '' if resource is None else resource, resource is None))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check existing ontology outputs without changing them.')
    parser.add_argument('--rdf-check', action='store_true', help='Also parse both serializations with RDFLib and compare their graphs.')
    args = parser.parse_args()
    graph, statements, outputs = expected_outputs()
    folder = OUT / 'roles'
    if args.check:
        changed = [name for name, expected in outputs.items() if not (folder / name).is_file() or (folder / name).read_text() != expected]
        if changed:
            raise ValueError('Missing or stale ontology output: ' + ', '.join(changed))
    else:
        for name, content in outputs.items():
            (folder / name).write_text(content)
    if read_generated_xml(outputs['ontology.owl']) != set(statements):
        raise ValueError('RDF/XML round-trip differs from expected statements.')
    parser_check = 'not_requested'
    if args.rdf_check:
        from rdflib import Graph
        from rdflib.compare import isomorphic
        xml_graph = Graph().parse(data=outputs['ontology.owl'], format='xml')
        turtle_graph = Graph().parse(data=outputs['ontology.ttl'], format='turtle')
        if not isomorphic(xml_graph, turtle_graph) or len(xml_graph) != len(statements):
            raise ValueError('Independent RDF parsers disagree with the expected ontology.')
        parser_check = 'pass'
    report = {'status': 'pass', 'counts': graph['counts'], 'rdf_triples': len(statements), 'independent_rdf_parser': parser_check, 'scope': 'Source references, exact role coverage, acyclic subclass structure, supported RDF/XML round-trip, and deterministic JSON/OWL/Turtle/Markdown/HTML consistency. General OWL DL reasoning and CSfC compliance are outside this check.', 'input_hashes': graph['input_hashes'], 'artifact_hashes': {name: hashlib.sha256(content.encode()).hexdigest() for name, content in outputs.items()}}
    (OUT / 'validation/ontology_validation.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': 'pass', 'counts': graph['counts'], 'rdf_triples': len(statements), 'independent_rdf_parser': parser_check}))


if __name__ == '__main__':
    main()
