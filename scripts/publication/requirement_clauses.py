"""Build a two-way reading guide from the reviewed passages, Lean declarations and proof inputs."""
from collections import defaultdict
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
PDF = "data/extraction/source/CSfC_documentation_v1.3.0.pdf"
DECL = re.compile(r'^(?:(?:private|protected|noncomputable) )?(?:def|abbrev|structure|inductive|theorem|lemma) ([\w.]+)')

@lru_cache
def declarations():
    entries = defaultdict(list)
    for path in sorted((ROOT / "TDN").rglob("*.lean")):
        lines = path.read_text().splitlines()
        namespaces = []
        for at, line in enumerate(lines):
            if line.startswith("namespace "):
                namespaces.append(line.split()[1])
            if re.match(r'^end(?:\s|$)', line) and namespaces:
                namespaces.pop()
            match = DECL.match(line)
            if match:
                name = match[1]
                entries[name].append((path.relative_to(ROOT), ".".join([*namespaces, name]), at, lines))
    return entries

def locate(ref, anchor="", clauses=False):
    if ref.startswith("tests/"):
        if not (ROOT / ref).is_file():
            raise ValueError(ref)
        return ref, 1, ref
    hits = []
    for name, records in declarations().items():
        if ref != name and not ref.endswith("." + name):
            continue
        for path, qualified, start, lines in records:
            if clauses and path.parent.name != "Requirements":
                continue
            if ref not in (name, path.stem + "." + name) and not qualified.endswith("." + ref):
                continue
            end = next((i for i in range(start + 1, len(lines)) if lines[i] and not lines[i][0].isspace()), len(lines))
            body = '\n'.join(lines[start:end]).strip()
            if anchor:
                matches = [i for i in range(start, end) if anchor in lines[i]]
                if len(matches) != 1:
                    continue
                line = matches[0]
            else:
                line = start
            hits.append((str(path), line + 1, body))
    if len(hits) != 1:
        raise ValueError(f"Expected one declaration for {ref} / {anchor}, found {[(p,n) for p,n,_ in hits]}")
    return hits[0]

def code_link(name, anchor="", clauses=False):
    path, line, _ = locate(name, anchor, clauses)
    return f'[`{name}`](../{path}#L{line})'

def data_link(row):
    path, field = row['path'], row['field']
    with (ROOT / path).open() as stream:
        data = json.load(stream)
    keys = [k for k in data if k.endswith(field[1:])] if field.startswith("*.") else [field] if field in data else []
    if len(keys) != 1:
        raise ValueError(f"Missing or ambiguous evidence key {path}#{field}")
    return f"[{Path(path).name}](../{path}) `{keys[0]}`"

def review_signature(review, group, top_specification, indexed):
    names = {top_specification, *review["helpers"], *(c["declaration"] for c in review["clauses"])}
    bodies = {name: locate(name, clauses=True)[2] for name in sorted(names)}
    passages = {p["source_id"]: p["text"] for p in group["requirement_passages"]}
    for ref in review.get("related_sources", []):
        passages[ref] = indexed[ref]["text"]
    material = {"map": {k: v for k, v in review.items() if k != "reviewed_sha256"},
                "declarations": bodies, "passages": passages}
    return hashlib.sha256(json.dumps(material, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def render():
    data = json.loads((ROOT / "specs/requirement_clause_map.json").read_text())
    extraction = json.loads((ROOT / "data/extraction/requirements/groups.json").read_text())
    if extraction["document_sha256"] != hashlib.sha256((ROOT / PDF).read_bytes()).hexdigest():
        raise ValueError("The clause map requires review against the changed PDF")
    catalog = json.loads((ROOT / "specs/proof_scope.json").read_text())['groups']
    selected = {g['id']:g for g in catalog if g['decision']=='formal'}
    if set(data) != set(selected):
        raise ValueError("Clause map and selected requirements differ")
    indexed = {p['source_id'].split(':', 1)[1]:p for p in
               map(json.loads,(ROOT/"data/extraction/source/source_index.jsonl").read_text().splitlines())}
    text = ["# Reading the ten CSfC requirements in Lean", "",
        "Each row links a CSfC passage to the Lean condition that implements the chosen reading. Page numbers count from the first page of the PDF. The last column gives a hypothetical failure. The evidence below each table links to actual checked examples.", "",
        "A recorded input is a field from a saved capture or derived export. A declared input states what the network is meant to do. An assumption supplies a fact the caller must justify. A Lean proof checks what follows from those inputs. An accepted or rejected example shows which conditions a particular deployment actually exercises.", "",
        "The packet proofs for RG-007, RG-008, RG-029 and RG-030 require a forwarding model that covers the deployment. Coverage binds device steps, eligible sources, valid setup history, links and identities to the model. It also requires a nonempty Red inventory and an emission for each Red network. The processing model adds fixed installed associations and a specific ESP cipher profile. Those are conditions of the proof model. The CSfC passages below supply the network requirements. " + code_link('ForwardingModel.CoversDeployment') + " " + code_link('DeviceExecutionBinding.ProcessingBound'), "",
        "A proof under a false condition holds without exercising any traffic. Read each positive example together with its profile and its exclusion example. The IPv4 firewall profiles and the captured link-layer program exercise different portions of the specifications.", ""]
    for group in extraction['groups']:
        key = group['group_id']
        if key not in data:
            continue
        review = data[key]
        primary = {r['source_id']:r for r in group['requirement_passages']}
        used = {s for c in review['clauses'] for s in c['sources']}
        if used != set(primary):
            raise ValueError(f"{key}: missing or foreign source IDs {used.symmetric_difference(primary)}")
        name = selected[key]["specification"].split(".")[-1]
        current = review_signature(review, group, name, indexed)
        status = ("An independent agent reviewed these passages, interpretations and evidence examples against the Lean definitions."
                  if review.get("reviewed_sha256") == current else
                  "The passages, mapped definitions or interpretation have changed since the independent source review.")
        text += [f"## {key} {group['title']}", "", "Whole-deployment specification " + code_link(name, clauses=True) + ".", "",
                 review['scope'], "", status, "",
                 "| Source | Lean condition | What the condition means | Example failure |", "| --- | --- | --- | --- |"]
        ordinal = {s:i for i,s in enumerate(primary,1)}
        for c in review['clauses']:
            refs = ", ".join(f"[{ordinal[s]}](#{key.lower()}-source-{ordinal[s]})" for s in c['sources'])
            text.append(f"| {refs} | {code_link(c['declaration'],c['anchor'],True)} | {c['interpretation']} | {c['counterexample']} |")
        text += ["", "Additional conditions and definitions. " +
                 " ".join(code_link(name, clauses=True) for name in review["helpers"]), "", "### Evidence and assumptions", ""]
        for e in review['evidence']:
            captured = ", ".join(map(data_link,e['records'])) or "The fixture is defined directly in Lean."
            text += [f"**{e['profile']}**", "", f"- Recorded inputs. {captured}",
                     f"- Declared inputs. {e['declared']}", f"- Conditions on the result. {e['assumed']}",
                     f"- {e.get('positive_label','Checked example')}. {code_link(e['positive'])}.",
                     f"- {e.get('negative_label','Rejection or counterexample')}. {code_link(e['negative'])}."]
            if e.get("also_checked"):
                text.append("- Related proofs. " + " ".join(code_link(name) for name in e["also_checked"]))
            text.append("")
        text += ["<details>", "<summary>Original passages and page links</summary>", ""]
        for source_id, row in primary.items():
            n = ordinal[source_id]
            page = row['locations'][0]['page']
            text.append(f'<a id="{key.lower()}-source-{n}"></a>{n}. [PDF p. {page}](../{PDF}#page={page}) `{source_id.split(":",1)[1]}` {row["text"]}')
            text.append("")
        extra = review.get("related_sources", [])
        if extra:
            text.append("Additional context")
            text.append("")
            for ref in extra:
                row=indexed[ref]
                page=row['locations'][0]['page']
                text.append(f'- [PDF p. {page}](../{PDF}#page={page}) `{ref}` {row["text"]}')
            text.append("")
        text += ["</details>", ""]
    return "\n".join(text)
