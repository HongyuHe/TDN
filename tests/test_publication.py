"""Validate standalone publication, source links, and stale-input rejection."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('publication', ROOT / 'scripts/publication/export_pages.py')
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


class PublicationTests(unittest.TestCase):
    def test_project_version_is_named_tdn_in_both_explorers(self):
        for page in publication.PAGES:
            html = (publication.PUBLIC / page / 'index.html').read_text()
            title = re.search(r'<title>(.*?)</title>', html)[1]
            self.assertTrue(title.startswith('TDN v3.1 | '), title)
            self.assertNotIn('Lean v3.1', html)
            header = re.search(r'<header[^>]*>(.*?)</header>', html, re.S)[1]
            self.assertIn('TDN v3.1', header)

    def test_current_sources_and_line_numbers(self):
        self.assertEqual(set(publication.validate()['pages']), {'hierarchy', 'ontology'})

    def test_installed_pages_pin_source_revision_and_stay_standalone(self):
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp)
            publication.install(destination, revision)
            self.assertEqual(json.loads((destination / 'source.json').read_text())['revision'], revision)
            for page in publication.PAGES:
                html = (destination / page / 'index.html').read_text()
                self.assertIn('https://github.com/HongyuHe/TDN/blob/' + revision, html)
                self.assertNotIn(publication.REVISION, html)
                self.assertIsNone(re.search(r'vscode://|file:///|/Users/|127\.0\.0\.1|<script[^>]+src=|<link[^>]+rel="stylesheet"', html))

    def test_stale_inputs_fail_before_installation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            public = root / 'public'
            (public / 'hierarchy').mkdir(parents=True)
            (public / 'hierarchy/index.html').write_text('changed')
            record = {'path': 'public/hierarchy/index.html', 'sha256': '0' * 64, 'source_hashes': {}}
            (public / 'manifest.json').write_text(json.dumps({'pages': {'hierarchy': record, 'ontology': {}}}))
            with patch.object(publication, 'ROOT', root), patch.object(publication, 'PUBLIC', public):
                with self.assertRaisesRegex(ValueError, 'Stale publication input'):
                    publication.validate()

    def test_revision_must_be_a_full_commit_and_match_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, 'full Git commit'):
                publication.install(Path(temp), 'main')
            with self.assertRaisesRegex(ValueError, 'checked-out TDN'):
                publication.install(Path(temp), '0' * 40)


if __name__ == '__main__':
    unittest.main()
