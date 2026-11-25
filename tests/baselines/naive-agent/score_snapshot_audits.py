"""Validate paired snapshot audits and aggregate verdicts grounded in the two final responses."""
from collections import Counter
from datetime import datetime
import json
import statistics

from blind_audit import MODELS, PROMPT
from snapshot_inputs import digest, HERE, LIVE, NETS, PDF, RUN
from snapshot_exposure import visible


def load(path):
    return json.loads(path.read_text())


def events(path):
    with path.open() as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def score():
    live = load(LIVE/"score.json")
    matrix = load(RUN/"matrix.json")
    protocol = load(RUN/"protocol.json")
    assert protocol["source_run"] == LIVE.name
    assert protocol["pdf_sha256"] == digest(PDF.read_bytes())
    assert protocol["reader_sha256"] == digest((HERE/"snapshot_reader.py").read_bytes())
    assert protocol["matrix_sha256"] == digest((RUN/"matrix.json").read_bytes())
    assert protocol["preparation_sha256"] == digest((HERE/"snapshot_inputs.py").read_bytes())
    assert len(matrix) == 43
    controls = {n:load(RUN/"inputs/control"/(n+".json"))["bundle"] for n in NETS}
    rows, stats, sessions = [], {}, set()
    tool_counts = Counter()
    longest_read = 0.0
    types = sorted(live["types"])
    for item in live["rows"]:
        family,n = item["type"],item["network"]
        case = family+"/"+n
        bundles = matrix[case]
        assert set(bundles) == set(NETS)
        assert bundles[n] == load(RUN/"inputs"/family/(n+".json"))["bundle"]
        assert all(bundles[other] == controls[other] for other in NETS if other != n)
        assert bundles[n] != controls[n]
        row = {"type":family,"network":n,"target":item["target"],"oracle":item["oracle"],
               "old":{m:item["methods"][m]["verdict"] for m in ("astra","sol","tdn")}, "new":{}}
        for method,model in MODELS.items():
            folder = RUN/"trials"/case/method
            run = load(folder/"execution.json")
            judgement = load(folder/"assessment.json")
            answer = folder/"answer.md"
            assert run["status"]=="completed" and run["returncode"]==0 and run["read_pdf"] and run["read_observations"]
            assert run["unexpected_tools"]==[] and run["bundles"]==bundles
            assert run["model"]==model and run["reasoning"]=="high" and run["prompt"]==PROMPT
            assert run["document_sha256"]==protocol["pdf_sha256"] and 0<run["duration_seconds"]<=3610
            answer_text = answer.read_text()
            assert judgement["answer_sha256"]==digest(answer.read_bytes())
            assert judgement["verdict"] in {"hit","miss"} and judgement["reason"].strip()
            assert judgement["lines"] and all(0<i<=len(answer_text.splitlines()) and answer_text.splitlines()[i-1].strip()
                                              for i in judgement["lines"])
            access = list(events(folder/"access.jsonl"))
            assert all(v["tool"] in {"networks","document","observe"} for v in access)
            assert any(v["tool"]=="observe" and v["ok"] and v["records"] for v in access)
            assert any(v["tool"]=="document" and v["ok"] for v in access)
            trace = events(folder/"events.jsonl")
            session = next(trace)["thread_id"]
            last_message = ""
            for event in trace:
                if event.get("type") != "item.completed":
                    continue
                action = event["item"]
                if action["type"] == "mcp_tool_call":
                    assert action["server"] == "reader" and action["tool"] in {"document","networks","observe"}
                    tool_counts[action["tool"]] += 1
                else:
                    assert action["type"] in {"reasoning","agent_message","todo_list","plan_update"}
                    if action["type"] == "agent_message":
                        last_message = action["text"]
            assert last_message.strip() == answer_text.strip()
            longest_read = max(longest_read, max(v["seconds"] for v in access))
            assert session not in sessions
            sessions.add(session)
            row["new"][method]={**judgement,"seconds":run["duration_seconds"],"calls":len(access),
                               "networks_read":sorted({v["arguments"]["network"] for v in access if v["tool"]=="observe" and v["ok"] and v["records"]})}
        if row["old"]["astra"] == "miss" or row["new"]["astra"]["verdict"] == "miss":
            row["snapshot_astra_reads"] = visible(case, item["target"])
        rows.append(row)
    assert len(rows)==43 and len(sessions)==86 and len(types)==11
    for method in MODELS:
        elapsed = [r["new"][method]["seconds"] for r in rows]
        pairs = Counter((r["old"][method],r["new"][method]["verdict"]) for r in rows)
        hits = sum(r["new"][method]["verdict"]=="hit" for r in rows)
        complete = sum(all(r["new"][method]["verdict"]=="hit" for r in rows if r["type"]==f) for f in types)
        for f in types:
            assert sum(r["type"]==f for r in rows)==(3 if f=="gray-eligible-deny" else 4)
        stats[method]={"trials":43,"hit":hits,"miss":43-hits,"credited_slots":hits+1,"complete_types":complete,
                       "paired":{a+"_"+b:pairs[a,b] for a in ("hit","miss") for b in ("hit","miss")},
                       "median_seconds":statistics.median(elapsed),"min_seconds":min(elapsed),"max_seconds":max(elapsed),
                       "all_four_read":sum(set(r["new"][method]["networks_read"])==set(NETS) for r in rows)}
    def capture_time(folder):
        return datetime.fromisoformat(load(folder/"snapshot/native/manifest.json")["started_at"])
    control_times = {n:capture_time(LIVE/"raw/controls"/n) for n in NETS}
    latest = sum(capture_time(LIVE/"raw/trials"/r["type"]/r["network"]) >
                 max(t for n,t in control_times.items() if n!=r["network"]) for r in rows)
    return {"completed_reader_calls":dict(tool_counts), "longest_reader_seconds":longest_read,
            "affected_capture_latest":latest,"source_run":LIVE.name,"live_score_sha256":digest((LIVE/"score.json").read_bytes()),
            "pdf_sha256":protocol["pdf_sha256"],"sessions":len(sessions),"rows":rows,"stats":stats}


if __name__=="__main__":
    result=score()
    (RUN/"score.json").write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps(result["stats"],indent=2))
