"""Start a fresh, tool-limited document and live-network audit and preserve its output."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from observe_controls import HERE, NETWORKS


ROOT = HERE.parents[2]
PROMPT = ("Use the reader to inspect the supplied document and networks. Identify any departures from the document "
          "that you can substantiate. For each finding, identify the network and devices, what you observed and why it matters. "
          "Use only the reader for evidence.")
MODELS = {"astra":"gpt-6-astra","sol":"gpt-6-sol"}
DISABLED = ("shell_tool","unified_exec","computer_use","plugins","apps","multi_agent","memories","tool_suggest")
FIELDS = ("id","role","site","level","network","interfaces")


def run(model, destination):
    destination.mkdir(parents=True,exist_ok=False)
    pdf=ROOT/"data/extraction/source/CSfC_documentation_v1.3.0.pdf"
    py=HERE/".runtime/venv/bin/python"
    if not py.is_file():raise FileNotFoundError("The reader requires a Python environment with PyMuPDF.")
    with tempfile.TemporaryDirectory(prefix="network-review-") as base:
        stage=Path(base);workspace=stage/"workspace";workspace.mkdir()
        server=stage/"reader";server.mkdir()
        shutil.copyfile(HERE/"reader.py",server/"reader.py");shutil.copyfile(pdf,server/"document.pdf")
        inventory={}
        for name in NETWORKS:
            t=json.loads((HERE/"profiles"/(name+".json")).read_text())["topology"]
            inventory[name]={"devices":[{k:d[k] for k in FIELDS if k in d} for d in t["devices"]],"links":t["links"]}
        (server/"devices.json").write_text(json.dumps(inventory))
        argv=["codex","exec","--ignore-user-config","--ignore-rules","--skip-git-repo-check","--ephemeral","--json",
              "-s","read-only","-C",str(workspace),"-m",MODELS[model],"-c",'model_reasoning_effort="high"',
              "-c",'web_search="disabled"',"-c","project_doc_max_bytes=0","-c",'history.persistence="none"',
              "-c","mcp_servers.reader.command="+json.dumps(str(py)),"-c","mcp_servers.reader.args="+json.dumps([str(server/"reader.py")])]
        for operation in ("document","networks","observe"):
            argv.extend(["-c",f'mcp_servers.reader.tools.{operation}.approval_mode="approve"'])
        for f in DISABLED:argv.extend(["--disable",f])
        argv.extend(["-o",str(destination.resolve()/"answer.md"),PROMPT])
        started=datetime.now(timezone.utc).isoformat(); clock=time.monotonic_ns()
        timeout=False
        with (destination/"events.jsonl").open("w") as events,(destination/"stderr.txt").open("w") as err:
            try:code=subprocess.run(argv,cwd=workspace,stdout=events,stderr=err,timeout=3600).returncode
            except subprocess.TimeoutExpired:code=124;timeout=True
        elapsed=(time.monotonic_ns()-clock)/1e9
        access=server/"access.jsonl"
        if access.exists():
            shutil.copyfile(access,destination/access.name)
        else:
            (destination/"access.jsonl").write_text("")
        log=[json.loads(l) for l in (destination/"events.jsonl").read_text().splitlines() if l.strip().startswith("{")]
        calls=[r.get("item",{}) for r in log if r.get("type")=="item.completed"]
        foreign=[v.get("type") for v in calls if (v.get("type")=="mcp_tool_call" and v.get("server")!="reader")
                 or v.get("type") in {"command_execution","file_change","web_search","collab_tool_call"}]
        access_log=[json.loads(l) for l in (destination/"access.jsonl").read_text().splitlines()]
        checked=any(v["tool"]=="document" for v in access_log) and any(v["tool"]=="observe" for v in access_log)
        status="completed" if code==0 and checked and not foreign and (destination/"answer.md").is_file() else ("timeout" if timeout else "invalid_run")
        record={"model":MODELS[model],"reasoning":"high","started_at":started,"duration_seconds":elapsed,"returncode":code,"status":status,
                "unexpected_tools":foreign,"reader_calls":len(access_log),"prompt":PROMPT,"document_sha256":hashlib.sha256(pdf.read_bytes()).hexdigest()}
        (destination/"execution.json").write_text(json.dumps(record,indent=2)+"\n")
        print(model,status,f"{elapsed:.3f} seconds",len(access_log),"reader calls",flush=True)
        return record


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("model",choices=MODELS);p.add_argument("destination",type=Path)
    args=p.parse_args();res=run(args.model,args.destination);raise SystemExit(0 if res["status"]=="completed" else 1)
