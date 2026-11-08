"""Map the current construction records to freshly exported Lean dependencies."""
from collections import Counter
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[3]
ASSETS = Path(__file__).resolve().parent
HERE = ROOT / ".lavish/theorem-hierarchy"
HERE.mkdir(parents=True, exist_ok=True)
inputs = {}


def load(path):
    raw = (ROOT / path).read_bytes()
    inputs[str(path)] = hashlib.sha256(raw).hexdigest()
    return json.loads(raw)


SUBMISSION = Path('data/publication/v3.1')
REGISTER = SUBMISSION / 'register.json'
compiled = {row['name']: row for row in load(HERE.relative_to(ROOT) / 'lean-dependencies.json')}
register = load(REGISTER)['groups']
proof_map = {row['rg_id']: row for row in load(SUBMISSION / 'proof_map.json')}
applications_register = {row['rg_id']: row for row in load(SUBMISSION / 'applications.json')}
verdict = load(SUBMISSION / 'verdict.json')
RUN = Path(verdict.get('source_run', 'data/construction/v3.1-20261031T231942Z'))
extracted = {row['group_id']: row for row in load('data/extraction/requirements/groups.json')['groups']}
assert verdict['verdict'] == 'PASS' and set(proof_map) == set(verdict['selected_RGs'])
nodes = {}
source_hashes = {}
active_modules, pending_modules = set(), ['TDN']
while pending_modules:
    module = pending_modules.pop()
    if module in active_modules:
        continue
    active_modules.add(module)
    source = ROOT / (module.replace('.', '/') + '.lean')
    for imported in re.findall(r'^import\s+(TDN(?:\.[\w]+)*)\s*$', source.read_text(), re.M):
        pending_modules.append(imported)
inactive_source_files = []


def without_comments(text):
    #* Preserve newlines and offsets while ignoring nested Lean comments and strings.
    pattern = re.compile(r'/\-|\-/|--[^\n]*|"(?:\\.|[^"\\])*"')
    result = list(text)
    depth = 0
    start = None
    for match in pattern.finditer(text):
        token = match[0]
        if token == '/-':
            if not depth:
                start = match.start()
            depth += 1
        elif token == '-/' and depth:
            depth -= 1
            if not depth:
                for pos in range(start, match.end()):
                    if result[pos] != '\n':
                        result[pos] = ' '
        elif not depth:
            for pos in range(match.start(), match.end()):
                if result[pos] != '\n':
                    result[pos] = ' '
    return ''.join(result)


#* Source spelling distinguishes lemma from theorem; Lean checks both as theorems.
declaration = re.compile(r'^(?:@\[[^\]]+\]\s*)?(?:(?:noncomputable|private|protected)\s+)*(theorem|lemma|def|abbrev|structure|inductive|tdn_data)\s+([\w.\u0080-\uffff]+)')
for path in sorted((ROOT / 'TDN').rglob('*.lean')):
    if 'Import' in path.relative_to(ROOT / 'TDN').parts[:-1]:
        continue
    module = '.'.join(path.relative_to(ROOT).with_suffix('').parts)
    if module not in active_modules:
        inactive_source_files.append(str(path.relative_to(ROOT)))
        continue
    original = path.read_text()
    lines = original.splitlines()
    clean = without_comments(original).splitlines()
    relative = str(path.relative_to(ROOT))
    source_hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    #* Imported JSON contributes to the compiled declarations shown by the page.
    for imported in re.findall(r'^tdn_(?:data|snapshot)\b[^\n]*(?:\n[ \t]+[^\n]*)*?\bfrom\s+"([^"\n]+)"', original, re.M):
        evidence = (path.parent / imported).resolve()
        if not evidence.is_relative_to(ROOT) or not evidence.is_file():
            raise ValueError('Missing or external hierarchy evidence input: ' + imported)
        source_hashes[str(evidence.relative_to(ROOT))] = hashlib.sha256(evidence.read_bytes()).hexdigest()
    scopes = []
    starts = []
    for i, line in enumerate(clean):
        scope = re.match(r'^(namespace|section)(?:\s+(\S+))?', line)
        if scope:
            scopes.append((scope[1], scope[2] or ''))
        if re.match(r'^end(?:\s|$)', line) and scopes:
            scopes.pop()
        match = declaration.match(line)
        if match:
            name = '.'.join([s[1] for s in scopes if s[0] == 'namespace'] + [match[2]])
            starts.append((i, name, match[1]))
    for pos, (i, name, keyword) in enumerate(starts):
        if name not in compiled:
            raise ValueError('Source declaration absent from compiled environment: ' + name)
        stop = starts[pos + 1][0] if pos + 1 < len(starts) else len(lines)
        source = '\n'.join(lines[i:stop])
        source = re.split(r'\n(?:/--|end\s|namespace\s)', source)[0].rstrip()
        prefix = '\n'.join(lines[:i]).rstrip()
        doc = re.search(r'/--((?:(?!/--).)*?)\-/\s*$', prefix, re.S)
        nodes[name] = {
            'name': name, 'short': name.split('.')[-1], 'path': relative, 'line': i + 1,
            'source': source, 'kind': 'def' if keyword == 'tdn_data' else keyword, 'compiledKind': compiled[name]['kind'],
            'decide': bool(re.search(r'\b(?:(?:native_)?decide|of_decide_eq_true|decide_eq_true)\b', without_comments(source))),
            'doc': ' '.join(doc[1].split()) if doc else '',
            'conclusionHead': compiled[name]['conclusionHead'],
            'aliasOf': compiled[name].get('aliasOf', ''),
        }


@lru_cache(None)
def visible_dependencies(name):
    #* Expand compiler-generated helpers until a named source declaration is reached.
    found, seen = set(), {name}
    todo = list(compiled[name]['valueDependencies'])
    while todo:
        dependency = todo.pop()
        if dependency in seen:
            continue
        seen.add(dependency)
        if dependency in nodes:
            found.add(dependency)
        elif dependency.startswith('TDN.') and dependency in compiled:
            todo.extend(compiled[dependency]['valueDependencies'])
    return found


for name, node in nodes.items():
    dependencies = visible_dependencies(name)
    node['proofs'] = sorted(n for n in dependencies if nodes[n]['compiledKind'] == 'theorem')
    node['definitions'] = sorted(n for n in dependencies if nodes[n]['compiledKind'] != 'theorem')
    node['statementDefinitions'] = sorted(n for n in compiled[name]['typeDependencies'] if n in nodes)
    node['libraries'] = sorted(n for n in compiled[name]['valueDependencies'] if n.startswith(('Relation.', 'List.', 'Finset.', 'Cslib.')))


def proof_reaches(start, goal):
    seen, todo = set(), [start]
    while todo:
        name = todo.pop()
        if name == goal:
            return True
        if name in seen:
            continue
        seen.add(name)
        todo.extend(nodes[name]['proofs'])
    return False


def canonical(name):
    seen = set()
    while name in compiled and compiled[name].get('aliasOf') and name not in seen:
        seen.add(name)
        name = compiled[name]['aliasOf']
    return name


def reaches(start, goal):
    seen, todo = set(), [start]
    while todo:
        name = todo.pop()
        if name == goal:
            return True
        if name in seen or name not in compiled:
            continue
        seen.add(name)
        todo.extend(compiled[name]['valueDependencies'])
    return False


for name, node in nodes.items():
    node['canonicalName'] = canonical(name)
    node['canonicalHead'] = canonical(node['conclusionHead'])

descriptions = load(ASSETS.relative_to(ROOT) / 'v31-descriptions.json')
for name, meaning in descriptions.items():
    assert name in nodes, name
    nodes[name]['description'] = meaning

groups, audits = [], []
for row in register:
    gid = row['rg_id']
    original = extracted[gid]
    formal = row.get('specification')
    reviewed = proof_map.get(gid)
    assert formal is None or formal in nodes, (gid, formal)
    generals, applications, scopes = [], {}, {}
    complete_applications = []
    partial_specs = []
    if formal:
        #* Keep the accepted specification as the root; older narrower definitions remain named clauses.
        old_name = 'TDN.Targets.' + original['theorem_name']
        if old_name in nodes and canonical(old_name) != canonical(formal):
            partial_specs.append(old_name)
        for name, node in nodes.items():
            if node['compiledKind'] != 'theorem':
                continue
            head = canonical(node['conclusionHead'])
            full = head == canonical(formal)
            partial = head in {canonical(n) for n in partial_specs}
            if not full and not partial:
                continue
            if node['path'].startswith('TDN/Evidence/'):
                applications[name] = ('Applies the accepted specification to its stated model under the displayed assumptions.' if full else
                                      'Establishes the older, narrower specification for its stated model. The complete v3.1 specification remains separate.')
                if full:
                    scopes[name] = applications[name]
            else:
                generals.append(name)
    if formal:
        #* Retain explicitly RG-named partial applications without promoting their scope.
        tagged = [name for name, node in nodes.items() if node['compiledKind'] == 'theorem'
                  and re.search(r'RG' + gid[3:] + r'(?:_|$)', node['short'])]
        for name in tagged:
            node = nodes[name]
            head = node['conclusionHead']
            if head in nodes and head.startswith('TDN.Targets.') and nodes[head]['short'].startswith('msc_'):
                if canonical(head) != canonical(formal) and head not in partial_specs:
                    partial_specs.append(head)
                if node['path'].startswith('TDN/Evidence/'):
                    applications.setdefault(name, 'Retained RG-specific application. Its conclusion establishes the named clause; the complete v3.1 specification has the status shown above.')
                elif name not in generals:
                    generals.append(name)
        for name, node in nodes.items():
            if node['compiledKind'] == 'theorem' and node['canonicalHead'] in {canonical(n) for n in partial_specs} and not node['path'].startswith('TDN/Evidence/'):
                if name not in generals:
                    generals.append(name)
    if reviewed:
        general = reviewed['general_theorem']
        assert general in nodes and canonical(nodes[general]['conclusionHead']) == canonical(formal), (gid, general)
        generals = list(dict.fromkeys([general] + generals))
        for item in reviewed['concrete_applications'] + reviewed.get('new_supporting_applications', []):
            name = item['name'] if isinstance(item, dict) else item
            assert name in nodes, (gid, name)
            applications[name] = item.get('status', 'Supporting model check recorded in the reviewed submission.') if isinstance(item, dict) else 'Supporting model check.'
        for item in applications_register[gid]['applications_and_exact_binders']:
            name = item['name']
            assert name in nodes and nodes[name]['compiledKind'] == 'theorem', (gid, name)
            applications.setdefault(name, 'Checked model application or supporting check recorded in the v3.1 review.')
            if canonical(item['conclusion_head'] or '') == canonical(formal):
                assert reaches(name, general), (gid, 'application does not use general proof', name)
                complete_applications.append(name)
                scopes[name] = applications_register[gid]['scope']
        assert complete_applications, gid
    status = 'review_pass' if reviewed else 'deferred' if formal else 'outside_selected_scope'
    reason = ('All clauses of the accepted specification have a general proof and checked applications within the recorded model scope. Complete-candidate review passed. Applying the result to a running deployment still requires its explicit premises.' if reviewed else
              verdict.get('deferred_reason', 'The specification passed interpretation review. A complete proof remains deferred under the user-selected stopping point.') if formal else
              row['prior_reason'])
    conditions = reviewed.get('open_application_conditions', []) if reviewed else []
    roots = list(dict.fromkeys(generals + list(applications)))
    record = {
        'id': gid, 'title': original['title'], 'status': status, 'positive': bool(reviewed),
        'formal': formal, 'targetName': original['theorem_name'], 'target': original['theorem_statement'],
        'roots': roots, 'generals': generals, 'applications': applications, 'scopes': scopes,
        'countedGeneral': reviewed['general_theorem'] if reviewed else None,
        'countedApplication': complete_applications[0] if complete_applications else None,
        'clause': 'Every clause of the accepted v3.1 specification.' if reviewed else 'Complete v3.1 proof deferred.' if formal else 'Outside the 24 selected formal-proof targets.',
        'reason': reason, 'remaining': conditions if reviewed else ([reason] if formal else []),
        'evidence': [], 'certificates': [], 'partialSpecifications': partial_specs,
        'completeApplications': complete_applications, 'disposition': row['prior_disposition'],
        'registerPath': str(REGISTER),
        'reviewPath': str(SUBMISSION / 'verdict.json') if reviewed else None,
    }
    for name in applications:
        nodes[name]['applicationScope'] = applications[name]
    for name in roots:
        assert name in nodes and nodes[name]['compiledKind'] == 'theorem', (gid, name)
    groups.append(record)
    audits.append({'group': gid, 'status': status, 'formal_definition': formal,
                   'general': record['countedGeneral'], 'complete_applications': complete_applications,
                   'registered_results': roots, 'application_uses_unchanged_general': bool(reviewed),
                   'formal_alias': canonical(formal) if formal else None})

assert len(groups) == 76
assert sum(g['formal'] is not None for g in groups) == 24
passed_count = sum(g['positive'] for g in groups)
formal_count = sum(g['formal'] is not None for g in groups)
assert passed_count == len(verdict['selected_RGs'])
summary = {'groups': len(groups), 'formal_definitions': formal_count, 'review_pass_groups': passed_count,
           'deferred_groups': formal_count - passed_count, 'outside_selected_groups': len(groups) - formal_count,
           'complete_model_applications': sum(len(g['completeApplications']) for g in groups),
           'registered_proof_associations': sum(len(g['roots']) for g in groups),
           'source_declarations': len(nodes), 'source_kinds': dict(Counter(n['kind'] for n in nodes.values()))}
metadata = {'version': 'v3.1', 'run': str(RUN), 'register_path': str(REGISTER),
            'generated_at': datetime.now(ZoneInfo('America/New_York')).isoformat(),
            'inputs': inputs, 'source_hashes': source_hashes, 'summary': summary,
            'inactive_source_files': inactive_source_files,
            'review_scope': verdict['scope'], 'review_verdict': verdict['verdict']}
(HERE / 'proof-map.json').write_text(json.dumps({'groups': groups, 'nodes': nodes, 'metadata': metadata}, ensure_ascii=False, indent=2) + '\n')
(HERE / 'target-mapping-audit.json').write_text(json.dumps({**metadata, 'groups': audits,
    'method': f'Fresh compiled proof dependencies and current source locations. All {formal_count} accepted definitions and {passed_count} reviewed general roots resolve. Complete registered applications conclude the accepted definition or an exact constant alias and use the recorded general proof. The other {len(groups) - formal_count} RGs remain catalog entries.'}, indent=2) + '\n')
print(json.dumps(summary))
