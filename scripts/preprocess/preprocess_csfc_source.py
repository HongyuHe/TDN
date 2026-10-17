#!/usr/bin/env python3
"""Create a reproducible, coordinate-backed source index for the CSfC MSC PDF."""
import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path



def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records))


def norm(text):
    return re.sub(r'\s+', ' ', text).strip()


def box(chars):
    return [round(min(c['x0'] for c in chars), 4), round(min(c['top'] for c in chars), 4), round(max(c['x1'] for c in chars), 4), round(max(c['bottom'] for c in chars), 4)]


def inside(c, b):
    x, y = (c['x0'] + c['x1']) / 2, (c['top'] + c['bottom']) / 2
    return b[0] <= x < b[2] and b[1] <= y < b[3]


def extract(chars):
    import pdfplumber
    return pdfplumber.utils.extract_text(chars, x_tolerance=3, y_tolerance=3) or ''


def literal_segments(text):
    start = 0
    for pos, ch in enumerate(text):
        if ch == '.':
            yield start, pos + 1, True
            start = pos + 1
    if text[start:].strip():
        yield start, len(text), False


def physical_table(t, p, no, ti):
    #* Borders of the leftmost cells distinguish actual rows from text-box fragments.
    left = t.bbox[0]
    first_cells = sorted([c for c in t.cells if abs(c[0] - left) < 1], key=lambda c: c[1])
    intervals = []
    for c in first_cells:
        pair = (c[1], c[3])
        if pair not in intervals:
            intervals.append(pair)
    header = t.extract()[0]
    requirement = 'Req.' in ' '.join(s or '' for s in header)
    if requirement:
        large = [c for c in t.rows[0].cells if c and c[2] - c[0] > 20]
        xs = [left, large[0][2], large[1][2], large[-1][0], t.bbox[2]]
    else:
        #* Body cells reveal true column edges without the narrow shaded-header margins.
        row = next((r for r in t.rows[1:] if r.cells[0] and r.cells[0][2] - r.cells[0][0] > 20), t.rows[-1])
        cells = [c for c in row.cells if c and c[2] - c[0] > 20]
        xs = [left] + [c[2] for c in cells]
        if t.bbox[2] - xs[-1] < 10:
            xs[-1] = t.bbox[2]
        elif xs[-1] < t.bbox[2]:
            xs.append(t.bbox[2])
    rows = []
    for ri, (top, bottom) in enumerate(intervals):
        cells = []
        for ci, (x0, x1) in enumerate(zip(xs, xs[1:])):
            b = [x0, top, x1, bottom]
            cc = [c for c in p.chars if inside(c, b)]
            cells.append({'column': ci + 1, 'bbox': b, 'raw_text': extract(cc), 'char_ids': [c['_cid'] for c in cc]})
        merges = []
        for original in t.cells:
            covered = [i for i, (a, z) in enumerate(zip(xs, xs[1:])) if abs(original[0] - a) < 1 and original[2] > z + 20]
            if covered and abs(original[1] - top) < 1 and abs(original[3] - bottom) < 1:
                first = covered[0]
                last = next((i for i, z in enumerate(xs[1:]) if abs(original[2] - z) < 1), first)
                if last > first:
                    cc = [c for c in p.chars if inside(c, original)]
                    cells[first].update({'raw_text': extract(cc), 'char_ids': [c['_cid'] for c in cc], 'bbox': list(original), 'column_span': list(range(first + 1, last + 2))})
                    for i in range(first + 1, last + 1):
                        cells[i].update({'raw_text': '', 'char_ids': [], 'merged_into_column': first + 1})
                    merges.append({'columns': list(range(first + 1, last + 2)), 'bbox': list(original)})
        rows.append({'row': ri, 'bbox': [left, top, t.bbox[2], bottom], 'cells': cells, 'merged_cell_relationships': merges})
    return {'physical_table_id': f'PT-p{no:03d}-{ti:02d}', 'page': no, 'bbox': list(t.bbox), 'requirement_table': requirement, 'rows': rows, 'detected_cells': [list(c) for c in t.cells]}


def build(pdf_path, out):
    import pdfplumber
    for folder in ['source', 'baseline', 'pages', 'exhaustive', 'validation', 'coordination']:
        (out / folder).mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(pdf_path.read_bytes()).hexdigest()
    if digest != '4e40e3d83708f33a033808d8362f78127973f53239dc03b72163fa6cfa5925c4':
        raise ValueError('The curated extraction decisions apply only to the pinned CSfC MSC v1.3.0 PDF. A different document requires fresh extraction and semantic review.')
    docid = 'CSFC-MSC-1.3.0-' + digest[:12]
    source_copy = out / 'source' / pdf_path.name
    if pdf_path.resolve() != source_copy.resolve():
        shutil.copyfile(pdf_path, source_copy)
    spans, units, physical_tables, page_inventory, figures = [], [], [], [], []
    all_chars = []
    current_table = None
    last_req_row = None
    last_table_row = None
    table_counter = 0

    def span(no, kind, raw, bbox_, cids, extra=None):
        number = max((int(s['span_id'].rsplit(':b', 1)[1]) for s in spans if s['page'] == no), default=0) + 1
        #* PA-001 retired the split reference year; keep its ID reserved for provenance.
        if no == 64 and number == 22:
            number = 23
        rec = {'span_id': f'{docid}:p{no:03d}:b{number:03d}', 'page': no, 'kind': kind, 'raw_text': raw, 'bbox': bbox_, 'char_ids': cids}
        if extra:
            rec.update(extra)
        spans.append(rec)
        return rec

    def add_unit(s, kind=None, extra=None):
        uid = s['span_id'].replace(':b', ':u')
        rec = {'source_id': uid, 'document_id': docid, 'document_sha256': digest, 'unit_type': kind or s['kind'], 'text': norm(s['raw_text']), 'raw_text': s['raw_text'], 'locations': [{'page': s['page'], 'bbox': s['bbox']}], 'baseline_spans': [{'span_id': s['span_id'], 'start': 0, 'end': len(s['raw_text'])}]}
        if extra:
            rec.update(extra)
        units.append(rec)
        return rec

    def prose(s):
        for j, (start, end, terminal) in enumerate(literal_segments(s['raw_text']), 1):
            rec = {'source_id': s['span_id'].replace(':b', ':u') + f'.s{j:03d}', 'document_id': docid, 'document_sha256': digest, 'unit_type': 'sentence' if terminal else 'trailing_text', 'prose_kind': s['kind'], 'text': norm(s['raw_text'][start:end]), 'raw_text': s['raw_text'][start:end], 'locations': [{'page': s['page'], 'bbox': s['bbox']}], 'baseline_spans': [{'span_id': s['span_id'], 'start': start, 'end': end}]}
            units.append(rec)

    with pdfplumber.open(pdf_path) as pdf:
        for no, p in enumerate(pdf.pages, 1):
            for ci, c in enumerate(p.chars):
                c['_cid'] = f'p{no:03d}:c{ci:05d}'
                all_chars.append({'char_id': c['_cid'], 'page': no, 'text': c['text'], 'bbox': [c['x0'], c['top'], c['x1'], c['bottom']], 'font': c['fontname'], 'size': c['size']})
            tables = [t for t in p.find_tables() if len(t.columns) > 1]
            pts = [physical_table(t, p, no, i) for i, t in enumerate(tables, 1)]
            if no >= 64:
                left_lines = p.filter(lambda o: o.get('object_type') != 'char' or (o['x0'] < 148 and 70 < o['top'] < 710)).extract_text_lines()
                starts = [l['top'] - 1 for l in left_lines if re.match(r'^(CNSS|FIPS|IEEE|RFC|SP |DoDI|CSfC)', l['text'])]
                rows = []
                for ri, (top, bottom) in enumerate(zip(starts, starts[1:] + [720])):
                    cells = []
                    for ci, (x0, x1) in enumerate(zip([70, 148, 487, 555], [148, 487, 555])):
                        bb = [x0, top, x1, bottom]
                        cc = [c for c in p.chars if inside(c, bb)]
                        cells.append({'column': ci + 1, 'bbox': bb, 'raw_text': extract(cc), 'char_ids': [c['_cid'] for c in cc]})
                    rows.append({'row': ri + 1, 'bbox': [70, top, 555, bottom], 'cells': cells, 'merged_cell_relationships': []})
                pts.append({'physical_table_id': f'PT-p{no:03d}-01', 'page': no, 'bbox': [70, starts[0], 555, 720], 'requirement_table': False, 'rows': rows, 'detected_cells': [], 'header_absent': True, 'contextual_column_labels_interpretation': ['Reference identifier', 'Reference title and attribution', 'Publication date']})
            physical_tables.extend(pts)
            occupied = {cid for t in pts for r in t['rows'] for c in r['cells'] for cid in c['char_ids']}
            remaining = p.filter(lambda o: o.get('object_type') != 'char' or o['_cid'] not in occupied)
            lines = remaining.extract_text_lines(x_tolerance=3, y_tolerance=3, return_chars=True)
            events = [{'top': l['top'], 'line': l} for l in lines] + [{'top': t['bbox'][1], 'table': t} for t in pts]
            events.sort(key=lambda e: e['top'])
            pending = []
            def flush():
                if pending:
                    chars = [c for l in pending for c in l['chars']]
                    raw = '\n'.join(l['text'] for l in pending)
                    s = span(no, 'prose', raw, box(chars), [c['_cid'] for c in chars])
                    prose(s)
                    pending.clear()
            for event in events:
                if 'table' in event:
                    flush()
                    t = event['table']
                    table_counter += 1
                    if current_table is None:
                        current_table = {'title': 'Document revision history', 'source_ids': [], 'table_key': 'revision-history'}
                    if no in [62, 63]:
                        current_table = {'title': 'APPENDIX B. ACRONYMS', 'source_ids': [u['source_id'] for u in units if u['text'] == 'APPENDIX B. ACRONYMS'], 'table_key': 'appendix-b-acronyms'}
                    if no >= 64:
                        current_table = {'title': 'APPENDIX C. REFERENCES', 'source_ids': [u['source_id'] for u in units if u['text'] == 'APPENDIX C. REFERENCES'], 'table_key': 'appendix-c-references'}
                    t['table_key'] = current_table['table_key']
                    t['title'] = current_table['title']
                    header_ref = None
                    for row in t['rows']:
                        raw = '\n'.join(c['raw_text'] for c in row['cells'])
                        cids = [cid for c in row['cells'] for cid in c['char_ids']]
                        extra = {'physical_table_id': t['physical_table_id'], 'table_key': t['table_key'], 'row_index': row['row'], 'cells': row['cells']}
                        s = span(no, 'table_header' if row['row'] == 0 else 'table_row', raw, row['bbox'], cids, extra)
                        cells = [{'column': c['column'], 'raw_text': c['raw_text'], 'text': norm(c['raw_text']), 'bbox': c['bbox']} for c in row['cells']]
                        if row['row'] == 0:
                            u = add_unit(s, extra={'table_key': t['table_key'], 'cells': cells, 'physical_table_id': t['physical_table_id']})
                            header_ref = u['source_id']
                        else:
                            first = norm(cells[0]['text'])
                            req = re.fullmatch(r'MSC-[A-Z]+-\d+', first)
                            continuation = t['requirement_table'] and not first and last_req_row and last_req_row['table_key'] == t['table_key']
                            if continuation:
                                u = last_req_row
                                u['raw_text'] += '\n' + raw
                                u['text'] = norm(u['raw_text'])
                                u['baseline_spans'].append({'span_id': s['span_id'], 'start': 0, 'end': len(raw)})
                                u['locations'].append({'page': no, 'bbox': row['bbox']})
                                u['row_fragments'].append({'span_id': s['span_id'], 'page': no, 'cells': cells, 'header_source_id': header_ref})
                                u['continuation'] = 'Physical page fragments form one logical source table row.'
                            else:
                                u = add_unit(s, extra={'table_key': t['table_key'], 'table_title': current_table['title'], 'table_title_source_ids': list(current_table['source_ids']), 'header_source_ids': [header_ref] if header_ref else [], 'contextual_column_labels_interpretation': t.get('contextual_column_labels_interpretation'), 'cells': cells, 'row_fragments': [{'span_id': s['span_id'], 'page': no, 'cells': cells, 'header_source_id': header_ref}], 'requirement_id': first if req else None, 'applicable_note_source_ids': [], 'merged_cell_relationships': row.get('merged_cell_relationships', [])})
                                last_table_row = u
                                if req:
                                    last_req_row = u
                    continue
                l = event['line']
                text = l['text']
                fonts = {c['fontname'] for c in l['chars']}
                if l['top'] > 720 or l['bottom'] < 70:
                    kind = 'page_furniture'
                elif no <= 7:
                    kind = 'front_matter'
                elif any('Cambria' in f for f in fonts):
                    kind = 'heading'
                elif re.match(r'(Figure|Table)\s+\d+\.', text):
                    kind = 'figure_caption' if text.startswith('Figure') else 'table_caption'
                elif l['chars'] and max(c['size'] for c in l['chars']) < 9:
                    kind = 'footnote'
                else:
                    kind = 'prose'
                if kind == 'prose':
                    #* Keep line wrapping but distinguish layout paragraphs and list items.
                    if pending and (l['top'] - pending[-1]['bottom'] > 7 or text.startswith(('•', ''))):
                        flush()
                    pending.append(l)
                    continue
                flush()
                s = span(no, kind, text, [l['x0'], l['top'], l['x1'], l['bottom']], [c['_cid'] for c in l['chars']])
                if kind in ['figure_caption', 'table_caption', 'footnote']:
                    before = len(units)
                    prose(s)
                    refs = [u['source_id'] for u in units[before:]]
                    if kind == 'table_caption':
                        match = re.match(r'Table\s+(\d+)\.', text)
                        current_table = {'title': text, 'source_ids': refs, 'table_key': 'table-' + match[1]}
                else:
                    add_unit(s)
            flush()
            body_images = [i for i in p.images if i['top'] > 65 and i['bottom'] < 720 and i['width'] > 80 and i['height'] > 60]
            for fi, im in enumerate(body_images, 1):
                fid = f'{docid}:p{no:03d}:fig{fi:02d}'
                bbox_ = [im['x0'], im['top'], im['x1'], im['bottom']]
                figures.append({'figure_image_id': fid, 'page': no, 'bbox': bbox_, 'source_method': 'embedded_raster', 'image_name': im['name'], 'pixel_size': im['srcsize']})
                s = span(no, 'figure', '', bbox_, [], {'figure_image_id': fid})
                add_unit(s, extra={'figure_image_id': fid, 'image_only': True})
            page_inventory.append({'page': no, 'width': p.width, 'height': p.height, 'character_count': len(p.chars), 'physical_tables': len(pts), 'raster_figures': len(body_images), 'extractable_text': bool(p.chars)})
    #* The lone superscript footnote is visually identified on physical page 36.
    marker_id = f'{docid}:p036:u014.s001'
    note_ids = [u['source_id'] for u in units if u['source_id'].startswith(f'{docid}:p036:u015.')]
    for s in spans:
        if s['span_id'] == f'{docid}:p036:b015':
            s['kind'] = 'footnote'
    for u in units:
        if u['source_id'] == marker_id:
            u['unit_type'] = 'footnote_label'
        if u['source_id'] in note_ids:
            u['prose_kind'] = 'footnote'
            u['footnote_label_source_id'] = marker_id
        if u.get('requirement_id') == 'MSC-SR-14':
            u['applicable_note_source_ids'] = [marker_id] + note_ids

    labels_path = out / 'networks' / 'reviewed_labels.json'
    if labels_path.exists():
        label_doc = json.loads(labels_path.read_text())
        crop_manifest = json.loads((out / 'networks' / 'crop_manifest.json').read_text())
        crops = {c['figure_number']: c for c in crop_manifest}
        for figure in label_doc['figures']:
            fn = figure['figure_number']
            crop = crops[fn]
            no = crop['page']
            parent = next(u for u in units if u['unit_type'] == 'figure' and u['locations'][0]['page'] == no)
            for li, label in enumerate(figure['labels'], 1):
                raw = label['text']
                sid = f'{docid}:p{no:03d}:f{fn:02d}:label{li:03d}'
                s = {'span_id': sid + ':baseline', 'page': no, 'kind': 'figure_label', 'raw_text': raw, 'bbox': crop['image_bbox'], 'char_ids': [], 'method': 'manual_visual_transcription', 'relative_position': label['relative_position'], 'raw_ocr_file': f'baseline/ocr/figure-{fn:02d}.txt'}
                spans.append(s)
                u = {'source_id': sid, 'document_id': docid, 'document_sha256': digest, 'unit_type': 'figure_label', 'text': norm(raw), 'raw_text': raw, 'locations': [{'page': no, 'bbox': crop['image_bbox'], 'bbox_precision': 'entire_figure', 'relative_position': label['relative_position']}], 'baseline_spans': [{'span_id': s['span_id'], 'start': 0, 'end': len(raw)}], 'method': 'manual_visual_transcription', 'figure_number': fn, 'parent_figure_source_id': parent['source_id'], 'reviewed_label_file': 'networks/reviewed_labels.json'}
                units.append(u)

    #* Rejoin interrupted prose across a physical page break without creating a sentence boundary.
    for page in range(1, len(page_inventory)):
        prior = [u for u in units if u['locations'][-1]['page'] == page and u.get('prose_kind') == 'prose']
        following = [u for u in units if u['locations'][0]['page'] == page + 1 and u.get('prose_kind') == 'prose']
        if prior and following:
            a, z = prior[-1], following[0]
            if a['unit_type'] == 'trailing_text' and a['locations'][-1]['bbox'][3] > 650 and z['locations'][0]['bbox'][1] < 100:
                a['unit_type'] = z['unit_type']
                a['raw_text'] += '\n' + z['raw_text']
                a['text'] = norm(a['raw_text'])
                a['locations'].extend(z['locations'])
                a['baseline_spans'].extend(z['baseline_spans'])
                a['continuation'] = 'Prose continues across a physical page break.'
                units.remove(z)
    units.sort(key=lambda u: (u['locations'][0]['page'], u['locations'][0]['bbox'][1], u['locations'][0]['bbox'][0], u['source_id']))
    for order, u in enumerate(units, 1):
        u['document_order'] = order
    write_jsonl(out / 'baseline' / 'characters.jsonl', all_chars)
    write_jsonl(out / 'baseline' / 'spans.jsonl', spans)
    write_json(out / 'baseline' / 'tables.json', physical_tables)
    write_json(out / 'baseline' / 'figures.json', figures)
    write_json(out / 'baseline' / 'pages.json', page_inventory)
    corrections_path = out / 'source' / 'corrections.json'
    corrections = json.loads(corrections_path.read_text()) if corrections_path.exists() else []
    for correction in corrections:
        u = next(u for u in units if u['source_id'] == correction['source_id'])
        if u['text'] != correction['original_normalized_text']:
            raise ValueError('Correction precondition failed: ' + u['source_id'])
        u['text'] = correction['corrected_text']
        u['correction_id'] = correction['correction_id']
        for change in correction.get('cell_corrections', []):
            col = change['column'] - 1
            u['cells'][col]['text'] = change['corrected_text']
            u['row_fragments'][0]['cells'][col]['text'] = change['corrected_text']
    for u in units:
        if u['unit_type'] == 'table_row':
            u['header_source_ids'] = list(dict.fromkeys(f['header_source_id'] for f in u['row_fragments'] if f['header_source_id']))
            u['logical_cells'] = [{'column': ci, 'text': norm('\n'.join(f['cells'][ci - 1]['text'] for f in u['row_fragments'] if len(f['cells']) >= ci)), 'source_fragments': [{'span_id': f['span_id'], 'column': ci} for f in u['row_fragments'] if len(f['cells']) >= ci]} for ci in range(1, max(len(f['cells']) for f in u['row_fragments']) + 1)]
    write_jsonl(out / 'source' / 'source_index.jsonl', units)
    metadata = {'document_id': docid, 'title': 'Commercial Solutions for Classified Multi-Site Connectivity Capability Package', 'version': '1.3.0', 'document_sha256': digest, 'source_pdf': 'source/' + pdf_path.name, 'source_pdf_path_base': 'extraction_directory', 'original_source_pdf': 'docs/CSfC_documentation_v1.3.0.pdf', 'original_source_pdf_path_base': 'repository_root_historical_location', 'retained_pdf': 'source/' + pdf_path.name, 'page_count': len(page_inventory), 'printed_page_offset': -7, 'coordinate_system': 'PDF points, origin top-left; page numbers are one-based physical PDF pages.', 'normalization': 'Replace each run of Unicode whitespace with one ASCII space and trim only leading/trailing whitespace. Preserve case, punctuation, hyphens and all other characters. Raw extracted strings and char coordinates are retained.', 'sentence_rule': 'Every literal U+002E period ends a prose sentence and is retained. No abbreviation, decimal, URL, or linguistic exceptions. Typed headings, labels, table cells and front matter are outside prose scope. Prose in captions and footnotes is in scope. Trailing text without a period is separately typed.', 'table_rule': 'One record per logical data row. Repeated physical headers are separate source occurrences. Continuation rows across pages are joined with original fragments and locations retained. Header/title/note references contextualize rows.', 'status': 'source_extracted_pending_validation', 'extractor': 'pdfplumber ' + pdfplumber.__version__}
    write_json(out / 'source' / 'document.json', metadata)
    return units


def render_views(out):
    units = [json.loads(l) for l in (out / 'source' / 'source_index.jsonl').read_text().splitlines()]
    index = {u['source_id']: u for u in units}
    categories = {'sentences': [u for u in units if u['unit_type'] == 'sentence'], 'table_rows': [u for u in units if u['unit_type'] == 'table_row'], 'other_units': [u for u in units if u['unit_type'] not in ['sentence', 'table_row']]}
    for name, records in categories.items():
        write_jsonl(out / 'exhaustive' / (name + '.jsonl'), records)
        lines = ['# ' + name.replace('_', ' ').title(), '', 'Quoted text follows the documented whitespace rule. Source IDs preserve locations and raw extraction in the shared index.', '']
        for u in records:
            pages = ', '.join(str(l['page']) for l in u['locations'])
            lines.extend([f'## {u["source_id"]}', '', f'Type: {u["unit_type"]}. PDF page(s): {pages}.', ''])
            if u['unit_type'] == 'table_row':
                lines.extend([u['table_title'], ''])
                for ref in u['header_source_ids']:
                    lines.extend([f'Header `{ref}`:', '', '> ' + index[ref]['text'], ''])
                if u.get('contextual_column_labels_interpretation'):
                    lines.extend(['Column labels supplied as interpretation: ' + '; '.join(u['contextual_column_labels_interpretation']), ''])
                lines.extend(['Logical row cells:', ''])
                for cell in u['logical_cells']:
                    lines.append(f'- Column {cell["column"]}: {cell["text"]}')
                lines.append('')
                if u.get('merged_cell_relationships'):
                    lines.extend(['Merged columns: ' + '; '.join(', '.join(map(str, m['columns'])) for m in u['merged_cell_relationships']), ''])
                for ref in u['applicable_note_source_ids']:
                    lines.extend([f'Applicable note `{ref}`:', '', '> ' + index[ref]['text'], ''])
                for frag in u['row_fragments']:
                    lines.extend([f'Page {frag["page"]} cells:', ''])
                    for c in frag['cells']:
                        lines.append(f'- Column {c["column"]}: {c["text"]}')
                lines.append('')
            else:
                lines.extend(['> ' + u['text'], ''])
        (out / 'exhaustive' / (name + '.md')).write_text('\n'.join(lines))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--pdf', type=Path, default=Path('artifacts/extraction/source/CSfC_documentation_v1.3.0.pdf'))
    parser.add_argument('--out', type=Path, default=Path('artifacts/extraction'))
    args = parser.parse_args()
    result = build(args.pdf, args.out)
    render_views(args.out)
    print(json.dumps(Counter(u['unit_type'] for u in result), indent=2))
