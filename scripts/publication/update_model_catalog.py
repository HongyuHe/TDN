#!/usr/bin/env python3
"""Refresh the declaration indexes without replacing the model explanations."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / 'docs/library.md'
DECLARATION = re.compile(
    r'^(?:@\[[^\]]*\]\s*)?(?:(?:private|protected|noncomputable)\s+)*'
    r'(def|abbrev|structure|inductive|theorem|lemma)\s+([\w.]+)')
INSTANCE = re.compile(r'^(?:@\[[^\]]*\]\s*)?(?:noncomputable\s+)?instance\b')


def refresh():
    text = CATALOG.read_text()
    blocks = re.split(r'(?=^### )', text, flags=re.M)
    covered = set()
    declaration_count = instance_count = 0
    for index, block in enumerate(blocks):
        source = re.search(r'^Source:.*?\(\.\./(TDN/Models/\w+\.lean)\)', block, re.M)
        if not source:
            continue
        relative = source[1]
        path = ROOT / relative
        declarations, instances = [], []
        for line, content in enumerate(path.read_text().splitlines(), 1):
            match = DECLARATION.match(content)
            if match:
                declarations.append((match[1], match[2], line))
            if INSTANCE.match(content):
                instances.append(line)
        covered.add(path)
        declaration_count += len(declarations)
        instance_count += len(instances)
        rows = ['<details>', f'<summary>All {len(declarations)} named declarations in {path.stem}</summary>',
                '', '| Kind | Declaration |', '| --- | --- |']
        rows += [f'| `{kind}` | [`{name}`](../{relative}#L{line}) |' for kind, name, line in declarations]
        if instances:
            rows += ['', 'Explicit instances:', '']
            rows += [f'- [Instance at line {line}](../{relative}#L{line})' for line in instances]
        rows += ['', '</details>']
        blocks[index], count = re.subn(r'<details>.*?</details>', '\n'.join(rows), block, count=1, flags=re.S)
        if count != 1:
            raise ValueError(f'Missing declaration index for {relative}')
    expected = set((ROOT / 'TDN/Models').glob('*.lean'))
    if covered != expected:
        raise ValueError(f'Unindexed modules: {expected - covered}')
    text = ''.join(blocks)
    text = re.sub(r'The catalog covers all \d+ active Lean files',
                  f'The catalog covers all {len(covered)} active Lean files', text)
    text = re.sub(r'It indexes \d+ explicitly named declarations and \d+ explicit instances\.',
                  f'It indexes {declaration_count} explicitly named declarations and {instance_count} explicit instances.', text)
    CATALOG.write_text(text)
    print(f'Updated {len(covered)} modules, {declaration_count} declarations, {instance_count} instances.')


if __name__ == '__main__':
    refresh()
