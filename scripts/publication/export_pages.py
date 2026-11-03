#!/usr/bin/env python3
"""Export self-contained TDN pages and install a verified revision on the website."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / 'public'
REVISION = '__TDN_REVISION__'
CODE_BASE = 'https://github.com/HongyuHe/TDN/blob/' + REVISION
PAGES = {
    'hierarchy': ('.lavish/theorem-hierarchy.html', 'hierarchy-data'),
    'ontology': ('data/extraction/roles/ontology.html', 'ontology-data'),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def embedded(html, identifier):
    pattern = re.compile(r'(<script[^>]*id="' + re.escape(identifier) + r'"[^>]*>)(.*?)(</script>)', re.S)
    match = pattern.search(html)
    if not match:
        raise ValueError('Missing embedded data: ' + identifier)
    return pattern, json.loads(match[2])


def source_files(paths):
    return {str(p.relative_to(ROOT)): digest(p) for p in paths if p.is_file()}


def render(page):
    source, identifier = PAGES[page]
    html = (ROOT / source).read_text()
    pattern, data = embedded(html, identifier)
    data['codeBase'] = CODE_BASE
    if page == 'hierarchy':
        data['root'] = ''
        hashes = dict(data['metadata']['source_hashes'])
        hashes.update({p: h for p, h in data['metadata']['inputs'].items() if not p.startswith('.lavish/')})
        html = html.replace('<a href="construction-v3.1-walkthrough.html">Read the v3.1 report</a>', '<a href="/tdn/ontology/">Role ontology</a>')
        html = html.replace('<p>In Lavish, turn Annotate off to use the diagram.</p>', '')
        assets = list((ROOT / 'scripts/publication/hierarchy').glob('*')) + [ROOT / 'scripts/publication/build_hierarchy.py']
    else:
        data['project_root'] = ''
        hashes = dict(data['theory']['source_hashes'])
        hashes.update({'data/extraction/' + path: value for path, value in data['input_hashes'].items()})
        interpretation_path = 'data/publication/v3.1/interpretations.md'
        lines = (ROOT / interpretation_path).read_text().splitlines()
        for key, record in data['theory']['interpretations'].items():
            record['source_path'] = interpretation_path
            record['source_line'] = next(i for i, line in enumerate(lines, 1) if line.startswith('## ' + key + ' '))
        hashes.update(source_files([ROOT / interpretation_path]))
        assets = [ROOT / 'scripts/preprocess/preprocess_csfc_ontology.py', ROOT / 'scripts/preprocess/templates/csfc_role_ontology.html']
        assets += [ROOT / 'data/extraction/roles' / n for n in ['roles.json', 'ontology_decisions.json', 'ontology_theory.json']]
        html = html.replace('</header>', '<a href="/tdn/hierarchy/" style="display:inline-block;margin-top:8px">Theory hierarchy</a></header>', 1)
    hashes.update(source_files(assets + [Path(__file__)]))
    payload = json.dumps(data, ensure_ascii=False, separators=(',', ':')).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    html = pattern.sub(lambda m: m[1] + payload + m[3], html, count=1)
    #* Public pages only contain GitHub source links; the local UI keeps its editor links.
    html = re.sub(r'`vscode://file\$\{data\.(?:root|project_root)\}/\$\{(?:n|reference)\.path\}:\$\{(?:n|reference)\.line\}`', '""', html)
    html = html.replace('Open in VS Code', 'View on GitHub')
    if re.search(r'vscode://|file:///|/Users/|127\.0\.0\.1|localhost:', html):
        raise ValueError('Local-only reference remains in public ' + page)
    return html, hashes


def export(page):
    html, hashes = render(page)
    output = PUBLIC / page / 'index.html'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html)
    manifest_path = PUBLIC / 'manifest.json'
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {'schema': 1, 'repository': 'HongyuHe/TDN', 'pages': {}}
    manifest['pages'][page] = {'path': str(output.relative_to(ROOT)), 'sha256': digest(output), 'source_hashes': hashes}
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    print('Updated public/' + page + '/index.html')


def validate():
    manifest = json.loads((PUBLIC / 'manifest.json').read_text())
    if set(manifest['pages']) != set(PAGES):
        raise ValueError('Publication must contain both pages.')
    for name, record in manifest['pages'].items():
        if record['path'] != f'public/{name}/index.html':
            raise ValueError('Unexpected publication path.')
        for path, expected in {record['path']: record['sha256'], **record['source_hashes']}.items():
            actual = ROOT / path
            if not actual.is_file() or digest(actual) != expected:
                raise ValueError('Stale publication input: ' + path + '. Regenerate ' + name + '.')
        html = (ROOT / record['path']).read_text()
        if CODE_BASE not in html:
            raise ValueError('Missing revision-pinned GitHub links.')
        _, data = embedded(html, PAGES[name][1])
        if name == 'hierarchy':
            refs = list(data['nodes'].values())
            refs += [{'path': data['registerPath'], 'line': g['registerLine']} for g in data['groups']]
        else:
            refs = list(data['theory']['references'].values())
            refs += [{'path': v['source_path'], 'line': v['source_line']} for v in data['theory']['interpretations'].values()]
        for ref in refs:
            p = ROOT / ref['path']
            if not p.is_file() or not 1 <= ref['line'] <= len(p.read_text().splitlines()):
                raise ValueError('Invalid source location: ' + str(ref))
    return manifest


def install(destination, revision):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('A full Git commit ID is required.')
    current = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if revision != current:
        raise ValueError('The link revision must match the checked-out TDN commit.')
    manifest = validate()
    paths = {'public/manifest.json'}
    for record in manifest['pages'].values():
        paths.update(record['source_hashes'])
        paths.add(record['path'])
    paths = sorted(paths)
    tree = subprocess.check_output(['git', 'ls-tree', '-rz', revision, '--', *paths], cwd=ROOT).decode()
    committed = {row.split('\t', 1)[1]: row.split('\t', 1)[0].split()[2] for row in tree.split('\0') if row}
    local = subprocess.check_output(['git', 'hash-object', '--stdin-paths'], input='\n'.join(paths) + '\n', cwd=ROOT, text=True).splitlines()
    changed = [path for path, blob in zip(paths, local) if committed.get(path) != blob]
    if changed:
        raise ValueError('Commit publication inputs before installing revision-pinned links: ' + ', '.join(changed))
    for name, record in manifest['pages'].items():
        output = destination / name / 'index.html'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text((ROOT / record['path']).read_text().replace(REVISION, revision))
    provenance = {'repository': manifest['repository'], 'revision': revision,
                  'publication_sha256': digest(PUBLIC / 'manifest.json'),
                  'pages': {name: digest(destination / name / 'index.html') for name in PAGES}}
    (destination / 'source.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print('Installed verified pages at ' + str(destination))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--page', choices=list(PAGES) + ['all'])
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--install', type=Path)
    parser.add_argument('--revision')
    args = parser.parse_args()
    if args.page:
        for name in PAGES if args.page == 'all' else [args.page]:
            export(name)
    if args.check:
        validate()
        print('Both public pages and their source locations are current.')
    if args.install:
        revision = args.revision or subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        install(args.install, revision)


if __name__ == '__main__':
    main()
