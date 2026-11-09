#!/usr/bin/env python3
"""Build a source-backed role hierarchy, OWL exports, and an offline explorer."""
import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
import copy
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'data/extraction'
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


def lean_excerpt(path, name, branch=None):
    lines = (ROOT / path).read_text().splitlines()
    starts = [i for i, line in enumerate(lines)
              if re.match(r'^(?:def|structure|inductive|theorem|lemma|abbrev) ' + re.escape(name) + r'(?=\s|\{|\(|:|$)', line)]
    if len(starts) != 1:
        raise ValueError('Missing or ambiguous obligation declaration: ' + name)
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines))
                if re.match(r'^(?:def|structure|inductive|theorem|lemma|abbrev|namespace|end)\b', lines[i])), len(lines))
    if branch is not None:
        start = next(i for i in range(start, end) if lines[i].startswith(f'  | {branch} =>'))
        end = next((i for i in range(start + 1, end) if lines[i].startswith('  | ')), end)
    code = '\n'.join(lines[start:end]).strip()
    return {'path': path, 'line': start + 1, 'label': name if branch is None else f'{name}, branch {branch}',
            'code': code, 'kind': 'declaration' if branch is None else 'match_branch'}


def obligation_catalog(out, role_ids):
    curated = read(out / 'roles/ontology_obligations.json')
    if set(curated['direct_role_groups']) != role_ids:
        raise ValueError('Obligation mappings must cover every role exactly.')
    for path, expected in curated['source_hashes'].items():
        if digest(ROOT / path) != expected:
            raise ValueError('Lean obligations changed; review translations: ' + path)
    register_path = 'data/publication/v3.2/register.json'
    register = read(ROOT / register_path)['groups']
    groups = {g['rg_id']: g for g in register}
    if set(curated['translations']) != set(groups):
        raise ValueError('Obligation translations must cover the requirement register exactly.')
    for role, ids in curated['direct_role_groups'].items():
        if len(ids) != len(set(ids)) or not set(ids) <= set(groups):
            raise ValueError('Duplicate or unknown obligation for ' + role)
    if not set(curated['role_notes']) <= role_ids:
        raise ValueError('Unknown role in obligation scope notes.')
    catalog = {}
    for rg, group in groups.items():
        translation = curated['translations'][rg]
        if not translation.strip():
            raise ValueError('Missing obligation translation: ' + rg)
        if group.get('specification'):
            name = group['specification'].removeprefix('TDN.Requirements.Msc.')
            reference = lean_excerpt('TDN/Requirements/MasterMscRequirementSpecs.lean', name)
            references = [reference]
            for primitive in dict.fromkeys(re.findall(r'\b(?:CoreReq_msc_\w+|SecurityLevelConnectivityCore|MACsecEncapsulationCore|RedEgressCore)\b', reference['code'])):
                references.append(lean_excerpt('TDN/Requirements/CoreMscRequirements.lean', primitive))
            if rg == 'RG-012':
                references.append(lean_excerpt('TDN/Requirements/CrossEnclavePkiIsolationSpec.lean', name))
            if rg in {'RG-013', 'RG-034'}:
                references.append(lean_excerpt('TDN/Requirements/MscFirewallWaypointingTheorems.lean', name))
            status = 'Complete model proof reviewed' if group['proof_status'] == 'PASS' else 'Complete proof unfinished'
            formalization = 'Dedicated requirement specification'
        else:
            references = [lean_excerpt('TDN/Requirements/CsfcRoleObligations.lean', 'MscComplianceContext.RequirementGroupSpec', int(rg[3:]))]
            status = {'check': 'Assigned to direct checks', 'external': 'Requires external evidence',
                      'scope': 'Permission or applicability condition'}.get(group['proof_status'], group['proof_status'])
            formalization = 'Shared requirement condition'
        for declaration in curated.get('supporting_declarations', {}).get(rg, []):
            if declaration['path'] not in curated['source_hashes']:
                raise ValueError('Unpinned obligation source: ' + declaration['path'])
            references.append(lean_excerpt(declaration['path'], declaration['name']))
        catalog[rg] = {'rg_id': rg, 'title': group['title'], 'translation': translation,
                       'status': status, 'formalization': formalization, 'references': references,
                       'proof_note': group['new_validation_claim']}
    hashes = {**curated['source_hashes'], register_path: digest(ROOT / register_path)}
    return {**curated, 'source_hashes': hashes, 'catalog': catalog}


def inherited_obligations(role_id, parents, direct):
    origins = defaultdict(set)
    for origin in [role_id, *ancestors(role_id, parents)]:
        for rg in direct.get(origin, []):
            origins[rg].add(origin)
    return [{'rg_id': rg, 'direct': role_id in owners,
             'inherited_from': sorted(owners - {role_id})}
            for rg, owners in sorted(origins.items())]


def theory_mapping(out, role_ids):
    mapping = read(out / 'roles/ontology_theory.json')
    if set(mapping['roles']) != role_ids:
        raise ValueError('Theory mappings must cover every extracted role exactly.')
    for filename, expected in mapping['source_hashes'].items():
        path = ROOT / filename
        if not path.is_file() or digest(path) != expected:
            raise ValueError('Lean source changed; review role mappings: ' + filename)
    result = copy.deepcopy(mapping)
    for reference in result['references'].values():
        if reference['path'] not in result['source_hashes']:
            raise ValueError('Unpinned Lean reference: ' + reference['path'])
        lines = (ROOT / reference['path']).read_text().splitlines()
        matches = [i + 1 for i, line in enumerate(lines) if line.startswith(reference['anchor'])]
        if len(matches) != 1:
            raise ValueError('Ambiguous or missing Lean reference: ' + reference['label'])
        reference['line'] = matches[0]
    for role_id, record in result['roles'].items():
        if record['status'] not in result['status_labels'] or not record['meaning']:
            raise ValueError('Invalid role representation: ' + role_id)
        if not set(record['references']) <= set(result['references']):
            raise ValueError('Unknown Lean reference for ' + role_id)
        if not set(record['interpretations']) <= set(result['interpretations']):
            raise ValueError('Unknown v3.2 interpretation for ' + role_id)
        if record['status'] in {'direct', 'composed'} and not record['references']:
            raise ValueError('Represented role lacks a code reference: ' + role_id)
    return result


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
    theory = theory_mapping(out, {r['role_id'] for r in roles})
    obligations = obligation_catalog(out, {r['role_id'] for r in roles})
    theory['source_hashes'].update(obligations['source_hashes'])
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
        node['theory'] = theory['roles'].get(node['role_id'])
        node['obligations'] = inherited_obligations(node['role_id'], parents, obligations['direct_role_groups'])
        node['obligation_note'] = obligations['role_notes'].get(node['role_id'], '')
    used_sources = {sid for node in nodes for sid in node['source_ids']}
    used_sources.update(sid for edge in edges + associations + decisions.get('excluded_inferences', []) for sid in edge['source_ids'])
    source_views = {sid: {'text': source[sid]['text'], 'pages': sorted({p['page'] for p in source[sid]['locations']})} for sid in sorted(used_sources)}
    return {'schema_version': '1.2', 'theory': theory, 'obligations': {'scope': obligations['scope'], 'catalog': obligations['catalog']}, 'ontology_iri': ONTOLOGY_IRI, 'class_semantics': 'A class describes entities matching an extracted role or realization concept. Classes may overlap and may have multiple parents. No device existence, class disjointness, or class equivalence is asserted.', 'association_semantics': 'Non-subtype links are OWL annotation assertions between class IRIs. They preserve source context without imposing object-property restrictions or asserting a relationship for every class member.', 'root_id': 'ExtractedRole', 'families': decisions['families'], 'nodes': nodes, 'subclass_edges': edges, 'associations': associations, 'excluded_inferences': decisions.get('excluded_inferences', []), 'sources': source_views, 'input_hashes': {'roles/roles.json': digest(out / 'roles/roles.json'), 'source/source_index.jsonl': digest(out / 'source/source_index.jsonl'), 'roles/ontology_decisions.json': digest(out / 'roles/ontology_decisions.json'), 'roles/ontology_theory.json': digest(out / 'roles/ontology_theory.json'), 'roles/ontology_obligations.json': digest(out / 'roles/ontology_obligations.json')}, 'counts': {'extracted_roles': len(roles), 'owl_classes': len(nodes), 'source_backed_subclass_edges': len(decisions['subclass_edges']), 'organizational_root_edges': len(edges) - len(decisions['subclass_edges']), 'annotation_associations': len(associations), 'multiple_parent_roles': sum(len(n['parents']) > 1 for n in nodes), 'explicit_lean_roles': sum(r['status'] == 'direct' for r in theory['roles'].values()), 'combined_lean_roles': sum(r['status'] == 'composed' for r in theory['roles'].values()), 'contextual_roles': sum(r['status'] == 'context' for r in theory['roles'].values()), 'unrepresented_roles': sum(r['status'] == 'unrepresented' for r in theory['roles'].values())}}


def triples(graph):
    result = set()
    def add(subject, predicate, value, literal=False):
        result.add((subject, predicate, value, literal))
    rdf_type, label = NS['rdf'] + 'type', NS['rdfs'] + 'label'
    add(ONTOLOGY_IRI, rdf_type, NS['owl'] + 'Ontology')
    add(ONTOLOGY_IRI, NS['rdfs'] + 'comment', graph['class_semantics'] + ' ' + graph['association_semantics'], True)
    add(ONTOLOGY_IRI, NS['owl'] + 'versionInfo', 'CSfC MSC 1.3.0; TDN role hierarchy 1.1; TDN theory v3.2', True)
    props = ['roleId', 'roleKind', 'sourceUnit', 'sourceText', 'pdfPages', 'basis', 'rationale', 'qualification', 'inputHash', 'theoryVersion', 'leanRepresentation', 'leanMapping', 'leanExpression', 'leanReference', 'theoryInterpretation']
    props += ['associatedRequirement', 'directRequirement', 'inheritedRequirement', 'requirementTranslation', 'requirementCode', 'requirementStatus']
    props += sorted({a['relation'] for a in graph['associations']})
    for prop in props:
        add(BASE + prop, rdf_type, NS['owl'] + 'AnnotationProperty')
    add(NS['skos'] + 'altLabel', rdf_type, NS['owl'] + 'AnnotationProperty')
    add(ONTOLOGY_IRI, BASE + 'theoryVersion', graph['theory']['theory_version'], True)
    for filename, sha in graph['theory']['source_hashes'].items():
        add(ONTOLOGY_IRI, BASE + 'inputHash', filename + ' sha256:' + sha, True)
    for filename, sha in graph['input_hashes'].items():
        add(ONTOLOGY_IRI, BASE + 'inputHash', filename + ' sha256:' + sha, True)
    for node in graph['nodes']:
        iri = node['iri']
        add(iri, rdf_type, NS['owl'] + 'Class')
        add(iri, label, node['label'], True)
        add(iri, NS['rdfs'] + 'comment', node['description'], True)
        add(iri, BASE + 'roleId', node['role_id'], True)
        add(iri, BASE + 'roleKind', node['kind'], True)
        for obligation in node['obligations']:
            requirement = BASE + obligation['rg_id']
            add(iri, BASE + 'associatedRequirement', requirement)
            if obligation['direct']:
                add(iri, BASE + 'directRequirement', requirement)
            if obligation['inherited_from']:
                add(iri, BASE + 'inheritedRequirement', requirement)
        if node.get('uncertainty'):
            add(iri, BASE + 'qualification', node['uncertainty'], True)
        if node.get('theory'):
            record = node['theory']
            add(iri, BASE + 'leanRepresentation', record['status'], True)
            add(iri, BASE + 'leanMapping', record['meaning'], True)
            for expression in record['expressions']:
                add(iri, BASE + 'leanExpression', expression, True)
            for key in record['references']:
                reference = graph['theory']['references'][key]
                add(iri, BASE + 'leanReference', reference['label'] + ' at ' + reference['path'] + ':' + str(reference['line']), True)
            for key in record['interpretations']:
                add(iri, BASE + 'theoryInterpretation', key + ': ' + graph['theory']['interpretations'][key]['summary'], True)
        for alias in node['aliases']:
            if alias != node['label']:
                add(iri, NS['skos'] + 'altLabel', alias, True)
        for sid in node['source_ids']:
            add(iri, BASE + 'sourceUnit', source_iri(sid))
    for rg, obligation in graph['obligations']['catalog'].items():
        iri = BASE + rg
        add(iri, label, obligation['title'], True)
        add(iri, BASE + 'requirementTranslation', obligation['translation'], True)
        add(iri, BASE + 'requirementStatus', obligation['status'], True)
        for reference in obligation['references']:
            add(iri, BASE + 'requirementCode', reference['path'] + ':' + str(reference['line']) + '\n' + reference['code'], True)
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
    lines += ['', '## Representation in TDN v3.2', '', graph['theory']['mapping_scope'], '',
              '[Curated Lean mappings](ontology_theory.json) records all 76 source roles, code references, chosen interpretations and pinned Lean source hashes.', '',
              '| Role | Representation | Meaning | Code |', '| --- | --- | --- | --- |']
    for node in graph['nodes']:
        record = node.get('theory')
        if not record:
            continue
        references = [graph['theory']['references'][key] for key in record['references']]
        links = ', '.join('[' + r['label'] + '](../../../' + r['path'] + ')' for r in references)
        lines.append('| ' + node['label'] + ' | ' + graph['theory']['status_labels'][record['status']] + ' | ' + record['meaning'] + ' | ' + links + ' |')
    lines += ['', '## Associated proof obligations', '', graph['obligations']['scope'], '',
              'The explorer shows each selected role’s obligations below its name. Every entry includes a plain-English summary, its current Lean code, source links, and the recorded proof status. Parent-role obligations are included once and identify the roles from which they were inherited.', '',
              '[Curated obligation mappings and translations](ontology_obligations.json) connect roles to requirement groups. The generator reads the code and proof status from the current sources. Source changes require reviewing the translations before regeneration.', '',
              '| Role | Directly associated RGs | Inherited RGs |', '| --- | --- | --- |']
    for node in graph['nodes']:
        if node['role_id'] == graph['root_id']:
            continue
        direct = ', '.join(o['rg_id'] for o in node['obligations'] if o['direct']) or 'None recorded'
        inherited = ', '.join(o['rg_id'] for o in node['obligations'] if o['inherited_from']) or 'None'
        lines.append('| ' + node['label'] + ' | ' + direct + ' | ' + inherited + ' |')
    lines += ['', '## Chosen v3.2 interpretations', '']
    for key, interpretation in graph['theory']['interpretations'].items():
        lines += ['### ' + interpretation['title'], '', interpretation['summary'], '',
                  'Recorded decision: `' + interpretation['source_path'] + ':' + str(interpretation['source_line']) + '`.', '']
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
    payload = {**graph, 'project_root': str(ROOT), 'downloads': {'owl': xml, 'turtle': ttl}}
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
        subprocess.run([sys.executable, str(ROOT / 'scripts/publication/export_pages.py'), '--page', 'ontology'], check=True)
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
