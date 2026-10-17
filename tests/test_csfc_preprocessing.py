"""Regression checks for the extraction's user-mandated segmentation contract."""
import importlib.util
import json
import unittest
import tempfile
from unittest.mock import patch
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / 'scripts/preprocess/preprocess_csfc_source.py'
SPEC = importlib.util.spec_from_file_location('preprocess_csfc_source', MODULE)
SOURCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE)


class LiteralPeriodContract(unittest.TestCase):
    def segments(self, value):
        return [(value[a:z], terminal) for a, z, terminal in SOURCE.literal_segments(value)]

    def test_abbreviations_have_no_linguistic_exception(self):
        self.assertEqual(self.segments('U.S. e.g. End.'), [('U.', True), ('S.', True), (' e.', True), ('g.', True), (' End.', True)])

    def test_decimals_versions_and_urls_end_at_every_period(self):
        self.assertEqual(self.segments('TLS 1.3 https://nsa.gov/a.pdf'), [('TLS 1.', True), ('3 https://nsa.', True), ('gov/a.', True), ('pdf', False)])

    def test_line_wrap_does_not_end_a_sentence(self):
        self.assertEqual(self.segments('The component\nmust authenticate.'), [('The component\nmust authenticate.', True)])

    def test_repeated_periods_remain_distinct(self):
        self.assertEqual(self.segments('A...'), [('A.', True), ('.', True), ('.', True)])

    def test_unterminated_text_and_whitespace_are_explicit(self):
        self.assertEqual(self.segments('Caption without period'), [('Caption without period', False)])
        self.assertEqual(self.segments('Done.\n '), [('Done.', True)])

    def test_normalization_preserves_punctuation_and_hyphens(self):
        self.assertEqual(SOURCE.norm('  Non-\nPerson\tX.509 “CA”  '), 'Non- Person X.509 “CA”')


class HarnessFailureContract(unittest.TestCase):
    def module(self, filename):
        path = MODULE.parent / filename
        spec = importlib.util.spec_from_file_location(filename.removesuffix('.py'), path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def temporary(self):
        directory = MODULE.parents[2] / 'artifacts/extraction/validation'
        directory.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(prefix='harness-test-', dir=directory)

    def test_missing_final_artifacts_fail(self):
        validator = self.module('validate_csfc_artifacts.py')
        with self.temporary() as directory:
            validator.OUT = Path(directory)
            with self.assertRaisesRegex(FileNotFoundError, 'Required final artifacts'):
                validator.validate(require_semantic_review=True)

    def test_missing_required_tools_fail(self):
        harness = self.module('run_csfc_preprocessing.py')
        with self.temporary() as directory:
            harness.ROOT = Path(directory)
            with patch('sys.argv', ['run_csfc_preprocessing.py', '--stage', 'check']):
                with self.assertRaisesRegex(FileNotFoundError, 'Required preprocessing tools'):
                    harness.main()

    def test_changed_source_pdf_is_rejected(self):
        harness = self.module('run_csfc_preprocessing.py')
        with self.temporary() as directory:
            wrong_pdf = Path(directory) / 'changed.pdf'
            wrong_pdf.write_bytes(b'changed source document')
            harness.PDF = wrong_pdf
            with patch('sys.argv', ['run_csfc_preprocessing.py', '--stage', 'check']):
                with self.assertRaisesRegex(ValueError, 'Pinned source PDF identity'):
                    harness.main()


class ExportConsistencyContract(unittest.TestCase):
    module = HarnessFailureContract.module
    temporary = HarnessFailureContract.temporary

    def example_export(self, directory):
        root = Path(directory)
        (root / 'source').mkdir()
        (root / 'exhaustive').mkdir()
        records = [{'source_id': 'example:sentence', 'unit_type': 'sentence', 'text': 'Keep the qualification.', 'locations': [{'page': 1}]}]
        (root / 'source/source_index.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records))
        SOURCE.render_views(root)
        return root, records

    def test_modified_exported_sentence_is_rejected(self):
        validator = self.module('validate_csfc_extraction.py')
        with self.temporary() as directory:
            root, records = self.example_export(directory)
            self.assertEqual(validator.exhaustive_view_errors(root, records), [])
            p = root / 'exhaustive/sentences.jsonl'
            p.write_text(p.read_text().replace('Keep the qualification.', 'Drop the qualification.'))
            self.assertTrue(validator.exhaustive_view_errors(root, records))

    def test_modified_readable_sentence_is_rejected(self):
        validator = self.module('validate_csfc_extraction.py')
        with self.temporary() as directory:
            root, records = self.example_export(directory)
            p = root / 'exhaustive/sentences.md'
            p.write_text(p.read_text().replace('Keep the qualification.', 'Drop the qualification.'))
            self.assertTrue(validator.exhaustive_view_errors(root, records))

    def test_reference_date_stays_in_its_table_row(self):
        path = MODULE.parents[2] / 'artifacts/extraction/source/source_index.jsonl'
        records = {r['source_id']: r for r in map(json.loads, path.read_text().splitlines())}
        prefix = 'CSFC-MSC-1.3.0-4e40e3d83708:p064:'
        row = records[prefix + 'u021']
        self.assertEqual(row['logical_cells'][2]['text'], 'December 2005')
        self.assertNotIn(prefix + 'u022.s001', records)
        self.assertEqual(records[prefix + 'u023']['text'], '57')

    def test_omitted_table_qualification_is_rejected(self):
        validator = self.module('validate_csfc_extraction.py')
        path = MODULE.parents[2] / 'artifacts/extraction/source/source_index.jsonl'
        source = list(map(json.loads, path.read_text().splitlines()))
        index = {r['source_id']: r for r in source}
        row = next(r for r in source if r.get('requirement_id') == 'MSC-SR-14')
        selected = {row['source_id'], *row['header_source_ids'], *row['applicable_note_source_ids']}
        records = [r for r in source if r['source_id'] in selected]
        note = next(index[sid]['text'] for sid in row['applicable_note_source_ids'] if len(index[sid]['text']) > 20)
        with self.temporary() as directory:
            root = Path(directory)
            (root / 'source').mkdir()
            (root / 'exhaustive').mkdir()
            (root / 'source/source_index.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records))
            SOURCE.render_views(root)
            self.assertEqual(validator.exhaustive_view_errors(root, records), [])
            p = root / 'exhaustive/table_rows.md'
            p.write_text(p.read_text().replace(note, '[Qualification omitted]'))
            self.assertTrue(validator.exhaustive_view_errors(root, records))


class NetworkMappingContract(unittest.TestCase):
    module = HarnessFailureContract.module

    def fixture(self):
        root = MODULE.parents[2] / 'artifacts/extraction'
        examples = json.loads((root / 'networks/examples.json').read_text())[1:2]
        groups = {g['group_id']: g for g in json.loads((root / 'requirements/groups.json').read_text())['groups']}
        index = {r['source_id']: r for r in map(json.loads, (root / 'source/source_index.jsonl').read_text().splitlines())}
        decisions = json.loads((root / 'networks/mapping_decisions.json').read_text())
        decisions['examples'] = [e for e in decisions['examples'] if e['example_id'] == examples[0]['example_id']]
        return examples, groups, index, decisions

    def test_blanket_unspecified_cannot_replace_assessments(self):
        validator = self.module('validate_csfc_artifacts.py')
        examples, groups, index, decisions = self.fixture()
        self.assertEqual(validator.scoped_mapping_errors(examples, groups, index, decisions), [])
        examples[0]['requirement_group_mappings'] = []
        examples[0]['compliance']['status'] = 'unspecified'
        self.assertTrue(validator.scoped_mapping_errors(examples, groups, index, decisions))

    def test_clause_from_unrelated_group_is_rejected(self):
        validator = self.module('validate_csfc_artifacts.py')
        examples, groups, index, decisions = self.fixture()
        mapping = examples[0]['requirement_group_mappings'][0]
        mapping['clause_source_ids'] = groups['RG-076']['source_ids'][:1]
        self.assertTrue(validator.scoped_mapping_errors(examples, groups, index, decisions))

    def test_altered_quoted_requirement_is_rejected(self):
        validator = self.module('validate_csfc_artifacts.py')
        examples, groups, index, decisions = self.fixture()
        examples[0]['requirement_group_mappings'][0]['clause_passages'][0]['text'] = 'A replacement claim.'
        self.assertTrue(validator.scoped_mapping_errors(examples, groups, index, decisions))

    def test_changed_requirement_strength_is_rejected(self):
        validator = self.module('validate_csfc_artifacts.py')
        examples, groups, index, decisions = self.fixture()
        examples[0]['requirement_group_mappings'][0]['requirement_strength']['interpretation'] = 'Always optional.'
        self.assertTrue(validator.scoped_mapping_errors(examples, groups, index, decisions))


class NetworkPresentationContract(unittest.TestCase):
    module = HarnessFailureContract.module

    def caption_fixture(self):
        root = MODULE.parents[2] / 'artifacts/extraction'
        units = [json.loads(line) for line in (root / 'source/source_index.jsonl').read_text().splitlines()]
        spans = [json.loads(line) for line in (root / 'baseline/spans.jsonl').read_text().splitlines()]
        figures = json.loads((root / 'networks/crop_manifest.json').read_text())
        return units, spans, figures

    def test_complete_caption_keeps_decimal_despite_sentence_segmentation(self):
        renderer = self.module('reconcile_csfc_extraction.py')
        captions = renderer.extract_figure_captions(*self.caption_fixture())
        self.assertEqual(len(captions), 10)
        self.assertEqual(captions[-1]['text'], 'Figure 10. CNSA 2.0 IKEv2 Exchanges')
        self.assertGreater(len(captions[-1]['source_ids']), 2)

    def test_missing_caption_fragment_fails(self):
        renderer = self.module('reconcile_csfc_extraction.py')
        units, spans, figures = self.caption_fixture()
        caption = renderer.extract_figure_captions(units, spans, figures)[-1]
        units = [u for u in units if u['source_id'] != caption['source_ids'][-1]]
        with self.assertRaisesRegex(ValueError, 'fragments do not cover'):
            renderer.extract_figure_captions(units, spans, figures)

    def test_details_cannot_leak_back_into_overview(self):
        validator = self.module('validate_csfc_artifacts.py')
        root = MODULE.parents[2] / 'artifacts/extraction/networks'
        examples = json.loads((root / 'examples.json').read_text())
        captions = json.loads((root / 'figure_captions.json').read_text())
        overview = '\n'.join((root / name).read_text() for name in ['networks.md', 'protocol_exchanges.md', 'configurations.md'])
        details = (root / 'network_requirement_links.md').read_text()
        self.assertEqual(validator.network_view_errors(examples, overview, details, captions), [])
        self.assertTrue(validator.network_view_errors(examples, overview + '\n### Requirement-group assessment\n', details, captions))

    def test_configuration_in_network_topologies_is_rejected(self):
        validator = self.module('validate_csfc_artifacts.py')
        root = MODULE.parents[2] / 'artifacts/extraction/networks'
        examples = json.loads((root / 'examples.json').read_text())
        overviews = {kind: (root / name).read_text() for kind, name in [('topology', 'networks.md'), ('protocol_exchange', 'protocol_exchanges.md'), ('textual_configuration', 'configurations.md')]}
        self.assertEqual(validator.example_partition_errors(examples, overviews), [])
        marker = '## NET-011: Four layering configurations'
        overviews['textual_configuration'] = overviews['textual_configuration'].replace(marker, '')
        overviews['topology'] += '\n' + marker + '\n'
        self.assertTrue(validator.example_partition_errors(examples, overviews))


if __name__ == '__main__':
    unittest.main()
