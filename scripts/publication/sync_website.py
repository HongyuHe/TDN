#!/usr/bin/env python3
"""Commit changed explorers to the website while preserving all other files."""
import argparse
import json
from pathlib import Path
import re
import subprocess
from export_pages import PUBLIC, ROOT, PAGES, REVISION, digest, install, validate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('website', type=Path)
    args = parser.parse_args()
    website = args.website.resolve()
    target = website / 'tdn'
    manifest = validate()
    source = target / 'source.json'
    previous = json.loads(source.read_text()) if source.is_file() else {}
    previous_revision = previous.get('revision', '')
    if previous.get('publication_sha256') == digest(PUBLIC / 'manifest.json') and re.fullmatch(r'[0-9a-f]{40}', previous_revision):
        same = all((target / name / 'index.html').is_file() and
                   (target / name / 'index.html').read_text() ==
                   (ROOT / record['path']).read_text().replace(REVISION, previous_revision)
                   for name, record in manifest['pages'].items())
        if same:
            print('The website already contains the current publication.')
            return
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    install(target, revision)
    subprocess.run(['git', 'config', 'user.name', 'Hongyu Hè'], cwd=website, check=True)
    subprocess.run(['git', 'config', 'user.email', 'hongyuhe.cs@googlemail.com'], cwd=website, check=True)
    paths = ['tdn/' + name + '/index.html' for name in PAGES] + ['tdn/source.json']
    subprocess.run(['git', 'add', '--', *paths], cwd=website, check=True)
    subprocess.run(['git', 'commit', '-m', 'Update TDN explorers from ' + revision[:12], '--', *paths], cwd=website, check=True)
    subprocess.run(['git', 'push', 'origin', 'HEAD:master'], cwd=website, check=True)


if __name__ == '__main__':
    main()
