"""Repeat the blinded audits against frozen, four-network inputs without contacting devices."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import random
import shutil
import signal
import subprocess
import tempfile
import time

from blind_audit import DISABLED, MODELS, PROMPT
from snapshot_inputs import digest, HERE, LIVE, PDF, put, RUN


TOOLS = {"document", "networks", "observe"}
TIMEOUT = 3600
FEATURES = DISABLED
PYTHON = HERE / ".runtime/venv/bin/python"


def utc():
    return datetime.now(timezone.utc).isoformat()


def load(path):
    return json.loads(path.read_text())


def lines(path):
    return [json.loads(s) for s in path.read_text().splitlines() if s.strip().startswith("{")]


def audit(case, model, bundles):
    dest = RUN / "trials" / case / model
    if (dest/"execution.json").exists() and load(dest/"execution.json")["status"] == "completed":
        return "completed"
    if dest.exists():
        archive = RUN/"attempts"/case/model/str(time.time_ns())
        archive.parent.mkdir(parents=True,exist_ok=True)
        dest.rename(archive)
    dest.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="network-review-") as tmp:
        stage = Path(tmp)
        workspace, server = stage/"workspace", stage/"reader"
        workspace.mkdir()
        server.mkdir()
        shutil.copyfile(HERE/"snapshot_reader.py", server/"reader.py")
        os.link(PDF, server/"document.pdf") if PDF.stat().st_dev == stage.stat().st_dev else shutil.copyfile(PDF, server/"document.pdf")
        for n,file in bundles.items():
            src = RUN/"raw"/file
            if digest(src.read_bytes()) != file.removesuffix(".json.gz"):
                raise ValueError("Changed detector input")
            if src.stat().st_dev == stage.stat().st_dev:
                os.link(src,server/(n+".json.gz"))
            else:
                shutil.copyfile(src,server/(n+".json.gz"))
        argv = ["codex","exec","--ignore-user-config","--ignore-rules","--skip-git-repo-check","--ephemeral",
                "--json","-s","read-only","-C",str(workspace),"-m",MODELS[model],
                "-c",'model_reasoning_effort="high"',"-c",'web_search="disabled"',"-c","project_doc_max_bytes=0",
                "-c",'history.persistence="none"',"-c","mcp_servers.reader.command="+json.dumps(str(PYTHON)),
                "-c","mcp_servers.reader.args="+json.dumps([str(server/"reader.py")])]
        for name in sorted(TOOLS):
            argv.extend(["-c",f'mcp_servers.reader.tools.{name}.approval_mode="approve"'])
        for feature in FEATURES:
            argv.extend(["--disable",feature])
        argv.extend(["-o",str(stage/"answer.md"),PROMPT])
        began = utc()
        start = time.monotonic()
        with (dest/"events.jsonl").open("w") as events, (dest/"stderr.txt").open("w") as err:
            proc = subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=events,stderr=err,cwd=workspace,start_new_session=True)
            try:
                code = proc.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL)
                proc.wait()
                code = 124
        duration = time.monotonic()-start
        if (stage/"answer.md").is_file():
            shutil.copyfile(stage/"answer.md",dest/"answer.md")
        if (server/"access.jsonl").exists():
            shutil.copyfile(server/"access.jsonl",dest/"access.jsonl")
        else:
            (dest/"access.jsonl").touch()
    events = lines(dest/"events.jsonl")
    calls = [r["item"] for r in events if r.get("type")=="item.completed" and "item" in r]
    foreign = [v.get("type") for v in calls if v.get("type") not in {"reasoning","agent_message","mcp_tool_call","todo_list","plan_update"}
               or (v.get("type")=="mcp_tool_call" and (v.get("server")!="reader" or v.get("tool") not in TOOLS))]
    access = lines(dest/"access.jsonl")
    pdf_read = any(r["tool"]=="document" and r["ok"] and r["response_bytes"]>2 for r in access)
    rows_read = any(r["tool"]=="observe" and r["ok"] and r["records"] for r in access)
    success = code==0 and pdf_read and rows_read and not foreign and (dest/"answer.md").is_file() and (dest/"answer.md").stat().st_size>0
    status = "completed" if success else ("timeout" if code==124 else "invalid_run")
    record = {"model":MODELS[model],"reasoning":"high","status":status,"returncode":code,"started_at":began,
              "duration_seconds":duration,"reader_calls":len(access),"unexpected_tools":foreign,
              "read_pdf":pdf_read,"read_observations":rows_read,"document_sha256":digest(PDF.read_bytes()),
              "bundles":bundles,"prompt":PROMPT}
    put(dest/"execution.json",record)
    print(f"{case} {model} {status} {duration:.1f}s {len(access)} queries",flush=True)
    return status


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers",type=int,default=4)
    parser.add_argument("--case",action="append")
    parser.add_argument("--model",choices=MODELS,action="append")
    args=parser.parse_args()
    matrix=load(RUN/"matrix.json")
    put(RUN/"protocol.json", {"source_run":LIVE.name,"pdf_sha256":digest(PDF.read_bytes()),
        "reader_sha256":digest((HERE/"snapshot_reader.py").read_bytes()),"matrix_sha256":digest((RUN/"matrix.json").read_bytes()),
        "preparation_sha256":digest((HERE/"snapshot_inputs.py").read_bytes()),"models":MODELS,"reasoning":"high","prompt":PROMPT,
        "audit_limit_seconds":TIMEOUT,"tools":sorted(TOOLS),"disabled_features":list(FEATURES),
        "scoring":"Same target network and observed fault or effect as the live study; a different CP citation is accepted. "
                  "Count an observed type only when every applicable instance is identified. Keep the assigned net-02 point separate."})
    cases=args.case or sorted(matrix)
    random.Random(317).shuffle(cases)
    jobs=[(case,model) for case in cases for model in (args.model or MODELS)]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures=[pool.submit(audit,case,model,matrix[case]) for case,model in jobs]
        for future in as_completed(futures):
            if future.result()!="completed":
                for f in futures:
                    f.cancel()
                raise SystemExit("A detector session failed; inspect its execution and transcript before retrying.")


if __name__=="__main__":
    main()
