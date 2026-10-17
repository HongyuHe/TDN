#!/usr/bin/env python3
"""Replay the reviewed CSfC extraction decisions and run mechanical checks."""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'artifacts/extraction'
PDF = OUT / 'source/CSfC_documentation_v1.3.0.pdf'


def run(command):
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'Command failed: {command}\n{result.stdout}\n{result.stderr}')
    return {'command': command, 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}


def baseline(render):
    import pdfplumber
    from PIL import Image
    directory = OUT / 'baseline'
    directory.mkdir(parents=True, exist_ok=True)
    with pdfplumber.open(PDF) as pdf:
        for no, page in enumerate(pdf.pages, 1):
            (directory / f'page-{no:03d}.txt').write_text(page.extract_text(layout=False) or '')
    poppler = shutil.which('pdftotext')
    if poppler is None:
        candidates = list((Path.home() / '.cache/codex-runtimes/codex-primary-runtime/dependencies').glob('native/poppler/**/pdftotext'))
        poppler = str(candidates[0]) if candidates else None
    if poppler:
        run([poppler, '-layout', str(PDF), str(directory / 'poppler-layout.txt')])
    if render:
        run(['pdftoppm', '-r', '120', '-png', str(PDF), str(OUT / 'pages/page')])
        manifest = json.loads((OUT / 'networks/crop_manifest.json').read_text())
        rendered = directory / 'figure-pages'
        rendered.mkdir(exist_ok=True)
        for crop in manifest:
            no = crop['page']
            base = rendered / f'page-{no:03d}'
            run(['pdftoppm', '-f', str(no), '-l', str(no), '-singlefile', '-r', '200', '-png', str(PDF), str(base)])
            im = Image.open(base.with_suffix('.png'))
            im.crop(crop['pixel_bbox_at_200dpi']).save(ROOT / crop['crop_path'])
            ocr = directory / 'ocr' / f'figure-{crop["figure_number"]:02d}'
            ocr.parent.mkdir(exist_ok=True)
            run(['tesseract', str(ROOT / crop['crop_path']), str(ocr), '--psm', '11', 'tsv', 'txt'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', choices=['all', 'source', 'derived', 'ontology', 'check'], default='all')
    parser.add_argument('--render', action='store_true', help='Regenerate all page renders, final crops, and raw OCR from the retained crop manifest.')
    args = parser.parse_args()
    expected = '4e40e3d83708f33a033808d8362f78127973f53239dc03b72163fa6cfa5925c4'
    if hashlib.sha256(PDF.read_bytes()).hexdigest() != expected:
        raise ValueError('Pinned source PDF identity does not match the reviewed extraction decisions.')
    required_tools = ['preprocess_csfc_source.py','validate_csfc_extraction.py','preprocess_csfc_requirements.py','preprocess_csfc_networks_roles.py','reconcile_csfc_extraction.py','preprocess_csfc_ontology.py','validate_csfc_artifacts.py','summarize_csfc_extraction.py']
    absent = [name for name in required_tools if not (ROOT / 'scripts/preprocess' / name).is_file()]
    if absent:
        raise FileNotFoundError('Required preprocessing tools are missing: ' + ', '.join(absent))
    log = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'python': sys.executable, 'stage': args.stage, 'render': args.render, 'mode': 'deterministic_replay_of_agent_authored_extraction_and_review_inputs', 'steps': []}
    if args.stage in ['all', 'source']:
        baseline(args.render)
        log['steps'].append(run([sys.executable, str(ROOT / 'scripts/preprocess/preprocess_csfc_source.py'), '--pdf', str(PDF)]))
        log['steps'].append(run([sys.executable, str(ROOT / 'scripts/preprocess/validate_csfc_extraction.py')]))
    if args.stage in ['all', 'derived']:
        #* Requirement production is gated by source provenance validation.
        log['steps'].append(run([sys.executable, str(ROOT / 'scripts/preprocess/validate_csfc_extraction.py')]))
        for name in ['preprocess_csfc_requirements.py', 'preprocess_csfc_networks_roles.py']:
            log['steps'].append(run([sys.executable, str(ROOT / 'scripts/preprocess' / name)]))
        reconciler = ROOT / 'scripts/preprocess/reconcile_csfc_extraction.py'
        log['steps'].append(run([sys.executable, str(reconciler)]))
    if args.stage == 'ontology':
        log['steps'].append(run([sys.executable, str(ROOT / 'scripts/preprocess/validate_csfc_extraction.py')]))
    if args.stage in ['all', 'derived', 'ontology']:
        log['steps'].append(run([sys.executable, str(ROOT / 'scripts/preprocess/preprocess_csfc_ontology.py')]))
    if args.stage == 'check':
        log['steps'].append(run([sys.executable, str(ROOT / 'scripts/preprocess/preprocess_csfc_ontology.py'), '--check']))
    if args.stage in ['all', 'derived', 'check']:
        log['steps'].append(run([sys.executable, str(ROOT / 'scripts/preprocess/validate_csfc_extraction.py')]))
        checker = ROOT / 'scripts/preprocess/validate_csfc_artifacts.py'
        command = [sys.executable, str(checker)]
        if args.stage in ['all', 'check']:
            command.append('--require-semantic-review')
        log['steps'].append(run(command))
    if args.stage in ['all', 'check']:
        log['steps'].append(run([sys.executable, str(ROOT / 'scripts/preprocess/summarize_csfc_extraction.py')]))
    log['steps'].append(run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_csfc*.py', '-v']))
    (OUT / 'coordination/replay_run.json').write_text(json.dumps(log, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': 'pass', 'stage': args.stage, 'steps': len(log['steps'])}))


if __name__ == '__main__':
    main()
