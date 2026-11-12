"""Validate standalone publication, source links, and stale-input rejection."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('publication', ROOT / 'scripts/publication/export_pages.py')
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)
sync_spec = importlib.util.spec_from_file_location('website_sync', ROOT / 'scripts/publication/sync_website.py')
website_sync = importlib.util.module_from_spec(sync_spec)
with patch.dict(sys.modules, {'export_pages': publication}):
    sync_spec.loader.exec_module(website_sync)


class PublicationTests(unittest.TestCase):
    def test_project_version_is_named_tdn_in_both_explorers(self):
        version = (ROOT / 'THEORY_VERSION').read_text().strip()
        for page in publication.PAGES:
            html = (publication.PUBLIC / page / 'index.html').read_text()
            title = re.search(r'<title>(.*?)</title>', html)[1]
            self.assertTrue(title.startswith('TDN v' + version + ' | '), title)
            self.assertNotIn('Lean v' + version, html)
            header = re.search(r'<header[^>]*>(.*?)</header>', html, re.S)[1]
            self.assertIn('TDN v' + version, header)

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

    def test_unchanged_pages_refresh_links_after_revision_changes(self):
        self.check_website_sync(previous_revision='1' * 40, expect_install=True)

    def test_unchanged_pages_at_current_revision_need_no_commit(self):
        self.check_website_sync(previous_revision='2' * 40, expect_install=False)

    def check_website_sync(self, previous_revision, expect_install):
        revision = '2' * 40
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            public = root / 'public'
            website = root / 'website'
            target = website / 'tdn'
            manifest = {'pages': {}}
            for name in publication.PAGES:
                relative = f'public/{name}/index.html'
                source = root / relative
                source.parent.mkdir(parents=True)
                source.write_text('Source revision: ' + publication.REVISION)
                output = target / name / 'index.html'
                output.parent.mkdir(parents=True)
                output.write_text(source.read_text().replace(publication.REVISION, previous_revision))
                manifest['pages'][name] = {'path': relative}
            (public / 'manifest.json').write_text(json.dumps(manifest))
            (target / 'source.json').write_text(json.dumps({
                'revision': previous_revision,
                'publication_sha256': publication.digest(public / 'manifest.json'),
            }))
            with (
                patch.object(website_sync, 'ROOT', root),
                patch.object(website_sync, 'PUBLIC', public),
                patch.object(website_sync, 'validate', return_value=manifest),
                patch.object(website_sync, 'install') as install,
                patch.object(website_sync.subprocess, 'check_output', return_value=revision),
                patch.object(website_sync.subprocess, 'run') as run,
                patch.object(sys, 'argv', ['sync_website.py', str(website)]),
            ):
                website_sync.main()
            if expect_install:
                install.assert_called_once_with(target, revision)
                self.assertEqual(run.call_args.args[0], ['git', 'push', 'origin', 'HEAD:master'])
            else:
                install.assert_not_called()
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
