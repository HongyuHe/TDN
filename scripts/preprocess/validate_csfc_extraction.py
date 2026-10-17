#!/usr/bin/env python3
"""Validate provenance partitions and cross-artifact references independently."""
import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path


def load_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def normalized(text):
    return ' '.join(text.split())


def exhaustive_view_errors(out, units):
    errors = []
    index = {u['source_id']: u for u in units}
    selections = {
        'sentences': [u for u in units if u['unit_type'] == 'sentence'],
        'table_rows': [u for u in units if u['unit_type'] == 'table_row'],
        'other_units': [u for u in units if u['unit_type'] not in {'sentence', 'table_row'}],
    }
    for name, expected in selections.items():
        actual = load_jsonl(out / 'exhaustive' / (name + '.jsonl'))
        if actual != expected:
            errors.append(name + ': structured export differs from the indexed records or their order')
        markdown = (out / 'exhaustive' / (name + '.md')).read_text()
        sections = re.split(r'^## (.+)\n', markdown, flags=re.MULTILINE)
        headings = sections[1::2]
        bodies = sections[2::2]
        if headings != [u['source_id'] for u in expected]:
            errors.append(name + ': Markdown record headings differ from the source index')
            continue
        for unit, body in zip(expected, bodies):
            if unit['unit_type'] == 'table_row':
                snippets = [unit['table_title']]
                snippets += [c['text'] for c in unit['logical_cells']]
                snippets += [index[sid]['text'] for sid in unit['header_source_ids'] + unit['applicable_note_source_ids']]
            else:
                snippets = ['> ' + unit['text']]
            if any(snippet not in body for snippet in snippets):
                errors.append(unit['source_id'] + ': Markdown omits or changes source text or table context')
    return errors


def validate(out):
    units = load_jsonl(out / 'source/source_index.jsonl')
    spans = load_jsonl(out / 'baseline/spans.jsonl')
    chars = load_jsonl(out / 'baseline/characters.jsonl')
    doc = json.loads((out / 'source/document.json').read_text())
    uid = {u['source_id']: u for u in units}
    sid = {s['span_id']: s for s in spans}
    char_map = {c['char_id']: c for c in chars}
    errors = []
    checks = {}
    def check(name, condition, detail):
        checks[name] = {'passed': bool(condition), 'detail': detail}
        if not condition:
            errors.append(name)
    check('unique_source_ids', len(uid) == len(units), len(units))
    check('document_hash', hashlib.sha256((out / doc['retained_pdf']).read_bytes()).hexdigest() == doc['document_sha256'], doc['document_sha256'])
    counts = Counter(cid for s in spans for cid in s['char_ids'])
    missing = [c['char_id'] for c in chars if c['text'].strip() and c['char_id'] not in counts]
    duplicates = [cid for cid, n in counts.items() if n != 1]
    check('all_nonwhitespace_pdf_characters_owned_once', not missing and not duplicates, {'nonwhitespace_char_objects': sum(bool(c['text'].strip()) for c in chars), 'unowned': missing, 'duplicated': duplicates, 'whitespace_objects_omitted_by_pdfplumber': sum(not c['text'].strip() and c['char_id'] not in counts for c in chars)})
    altered = []
    for s in spans:
        actual = Counter(c for c in s['raw_text'] if not c.isspace())
        expected = Counter(c for cid in s['char_ids'] for c in char_map[cid]['text'] if not c.isspace())
        if s.get('method') == 'manual_visual_transcription':
            continue
        if actual != expected:
            altered.append(s['span_id'])
    check('baseline_span_character_content', not altered, {'altered_spans': altered})
    ownership = defaultdict(list)
    text_errors = []
    corrections = json.loads((out / 'source/corrections.json').read_text()) if (out / 'source/corrections.json').exists() else []
    correction_map = {c['source_id']: c for c in corrections}
    for u in units:
        strings = []
        for ref in u['baseline_spans']:
            if ref['span_id'] not in sid:
                text_errors.append(u['source_id'] + ':missing-span')
                continue
            s = sid[ref['span_id']]
            start, end = ref['start'], ref['end']
            strings.append(s['raw_text'][start:end])
            ownership[ref['span_id']].append((start, end, u['source_id']))
        expected = '\n'.join(strings)
        if u['raw_text'] != expected:
            text_errors.append(u['source_id'] + ':raw-mismatch')
        if u['text'] != normalized(expected):
            c = correction_map.get(u['source_id'])
            if not c or c['original_normalized_text'] != normalized(expected) or c['corrected_text'] != u['text']:
                text_errors.append(u['source_id'] + ':normalized-mismatch')
    check('unit_text_matches_baseline_or_reviewed_correction', not text_errors, text_errors)
    gaps, overlaps = [], []
    for s in spans:
        coverage = [0] * len(s['raw_text'])
        for start, end, source in ownership[s['span_id']]:
            for i in range(start, end):
                coverage[i] += 1
        if any(n == 0 and not s['raw_text'][i].isspace() for i, n in enumerate(coverage)):
            gaps.append(s['span_id'])
        if any(n > 1 for n in coverage):
            overlaps.append(s['span_id'])
        if not s['raw_text'] and not ownership[s['span_id']]:
            gaps.append(s['span_id'])
    check('source_span_partition_no_omissions_or_duplicates', not gaps and not overlaps, {'omitted_spans': gaps, 'overlapping_spans': overlaps})
    prose = [s for s in spans if s['kind'] in ['prose', 'figure_caption', 'table_caption', 'footnote']]
    scope = '\n'.join(s['raw_text'] for s in prose)
    (out / 'baseline/prose_scope.txt').write_text(scope)
    external_count = int(subprocess.check_output(['perl', '-ne', '$n += tr/.//; END {print $n}', str(out / 'baseline/prose_scope.txt')]).decode())
    sentences = [u for u in units if u['unit_type'] == 'sentence']
    malformed = [u['source_id'] for u in sentences if u['raw_text'].count('.') != 1 or not u['raw_text'].endswith('.')]
    tails = [u['source_id'] for u in units if u['unit_type'] == 'trailing_text' and '.' in u['raw_text']]
    check('external_literal_period_sentence_count', external_count == len(sentences), {'external_perl_count': external_count, 'indexed_sentences': len(sentences), 'scope': 'baseline/prose_scope.txt'})
    check('literal_period_boundaries', not malformed and not tails, {'invalid_sentences': malformed, 'tails_with_periods': tails})
    physical = sum(s['kind'] == 'table_row' for s in spans)
    rows = [u for u in units if u['unit_type'] == 'table_row']
    fragment_count = sum(len(u['row_fragments']) for u in rows)
    check('table_row_count_separate_from_prose', physical == fragment_count, {'physical_data_row_fragments': physical, 'logical_table_rows': len(rows), 'cross_page_extra_fragments': fragment_count - len(rows), 'by_table': dict(Counter(u['table_key'] for u in rows))})
    bad_context = []
    for u in rows:
        for field in ['header_source_ids', 'table_title_source_ids', 'applicable_note_source_ids']:
            for ref in u[field]:
                if ref not in uid:
                    bad_context.append([u['source_id'], field, ref])
    check('table_context_references', not bad_context, bad_context)
    view_errors = exhaustive_view_errors(out, units)
    check('exhaustive_exports_match_source_and_context', not view_errors, view_errors)
    context_errors = []
    for row in rows:
        expected_headers = list(dict.fromkeys(f['header_source_id'] for f in row['row_fragments'] if f['header_source_id']))
        if row['header_source_ids'] != expected_headers:
            context_errors.append([row['source_id'], 'continued fragment headers'])
        if not expected_headers and not row.get('contextual_column_labels_interpretation'):
            context_errors.append([row['source_id'], 'missing printed or interpreted column labels'])
        for cell in row['logical_cells']:
            texts = [c['text'] for fragment in row['row_fragments'] for c in fragment['cells'] if c['column'] == cell['column']]
            if cell['text'] != normalized('\n'.join(texts)):
                context_errors.append([row['source_id'], 'logical column ' + str(cell['column'])])
    check('table_columns_and_fragment_context_agree', not context_errors, context_errors)
    check('all_rendered_pages_present', all((out / 'pages' / f'page-{p:02d}.png').exists() for p in range(1, doc['page_count'] + 1)), {'expected_pages': doc['page_count'], 'render_dpi': 120})
    result = {'status': 'pass' if not errors else 'fail', 'validation_kind': 'mechanical_source_validation', 'semantic_correctness_claimed': False, 'checks': checks, 'source_counts': dict(Counter(u['unit_type'] for u in units)), 'errors': errors}
    (out / 'validation/source_validation.json').write_text(json.dumps(result, indent=2) + '\n')
    doc['status'] = 'mechanically_validated_semantic_review_separate' if not errors else 'mechanical_validation_failed'
    doc['source_index_units'] = len(units)
    doc['image_label_method'] = '131 manual visual transcriptions; raw OCR retained separately; figure-level boxes and relative label positions.'
    (out / 'source/document.json').write_text(json.dumps(doc, ensure_ascii=False, indent=2) + '\n')
    lines = ['# Mechanical source validation', '', f'Status: **{result["status"]}**. Mechanical coverage does not establish semantic correctness.', '']
    for name, data in checks.items():
        lines.append(f'- {"PASS" if data["passed"] else "FAIL"}: {name}. {json.dumps(data["detail"], ensure_ascii=False)}')
    (out / 'validation/source_validation.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps({'status': result['status'], 'counts': result['source_counts'], 'errors': errors}, indent=2))
    return not errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=Path('artifacts/extraction'))
    args = parser.parse_args()
    raise SystemExit(0 if validate(args.out) else 1)
