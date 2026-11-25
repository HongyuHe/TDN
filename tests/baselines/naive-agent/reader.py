"""A read-only MCP endpoint for the original PDF and the four emulated networks."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time


DIR = Path(__file__).resolve().parent
DOC = DIR / "document.pdf"
COMMANDS = {
    "interfaces": ["ip", "-j", "-d", "addr", "show"],
    "routes4": ["ip", "-j", "-4", "route", "show", "table", "all"],
    "routes6": ["ip", "-j", "-6", "route", "show", "table", "all"],
    "rules4": ["ip", "-j", "-4", "rule", "show"], "rules6": ["ip", "-j", "-6", "rule", "show"],
    "firewall4": ["iptables-save"], "firewall6": ["ip6tables-save"],
    "sockets": ["ss", "-lnptu"], "policies": ["ip", "xfrm", "policy"],
    "states": ["ip", "xfrm", "state", "list", "nokeys"],
    "connections": ["swanctl", "--list-conns", "--raw"], "sessions": ["swanctl", "--list-sas", "--raw"],
    "certificates": ["swanctl", "--list-certs", "--utc"], "algorithms": ["swanctl", "--list-algs"],
    "configuration": ["cat", "/etc/swanctl/swanctl.conf"],
    "addresses": ["ip", "-br", "address"], "neighbours": ["ip", "-j", "neigh"],
    "link_macsec": ["ip", "macsec", "show"], "switch": ["ovs-vsctl", "show"],
    "switch_flows": ["ovs-ofctl", "dump-flows", "br0"], "routing": ["vtysh", "-c", "show running-config"],
    "routing_neighbors": ["vtysh", "-c", "show ip ospf neighbor json"], "processes": ["ps", "-eo", "pid,comm"],
    "forwarding": ["sysctl", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"],
}
SCHEMAS = {
    "document": ("Read the supplied PDF by page, search its text, or request a page image.",
                 {"page":{"type":"integer","minimum":1},"pages":{"type":"integer","minimum":1,"maximum":8},
                  "search":{"type":"string"},"image":{"type":"boolean"}}),
    "networks": ("List the available networks or read the device inventory and declared links of one network.",
                 {"network":{"type":"string"}}),
    "observe": ("Read public live device state. Supply one network, device names, and an observation. An optional literal filter retains matching lines; offset and limit page through the result.",
                {"network":{"type":"string"},"devices":{"type":"array","items":{"type":"string"}},
                 "observation":{"type":"string","enum":list(COMMANDS)},"filter":{"type":"string"},
                 "offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":100,"maximum":32000}}),
}


def content(value):
    return [{"type":"text","text":value if isinstance(value,str) else json.dumps(value,ensure_ascii=False)}]


def call(name, args):
    if name == "document":
        import pymupdf
        with pymupdf.open(DOC) as doc:
            if args.get("search"):
                term=args["search"].casefold()
                return content([{"page":p.number+1,"line":l} for p in doc for l in p.get_text().splitlines()
                                if term in l.casefold()][:150])
            p=args.get("page",1)
            if not 1<=p<=len(doc): raise ValueError("Page out of range")
            if args.get("image"):
                import base64
                return [{"type":"image","mimeType":"image/png","data":base64.b64encode(doc[p-1].get_pixmap().tobytes("png")).decode()}]
            return content([{"page":i+1,"pages_in_document":len(doc),"text":doc[i].get_text()}
                            for i in range(p-1,min(len(doc),p-1+max(1,min(8,args.get("pages",1)))))])
    inventory=json.loads((DIR/"devices.json").read_text())
    if name == "networks":
        if not args.get("network"): return content(list(inventory))
        return content(inventory[args["network"]])
    if name != "observe": raise ValueError("Unknown tool")
    network=inventory[args["network"]]
    devices={d["id"]:d for d in network["devices"]}
    names=args.get("devices") or list(devices)
    if any(n not in devices for n in names):raise ValueError("Unknown network device")
    op=args["observation"]; command=COMMANDS[op]
    def fetch(n):
        target=n
        if op in ("routing","routing_neighbors") and devices[n]["role"] in ("firewall","gray-firewall","transport"):
            target=n+"-frr"
        argv=["sudo","-n","docker","exec",target,*command]
        result=subprocess.run(["ssh","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes",
            "-o","ControlMaster=auto","-o","ControlPersist=60","-o","ControlPath=/tmp/tdn-rg-read-%C",
            "-o","ConnectTimeout=8","hy@clnode176.clemson.cloudlab.us",shlex.join(argv)],capture_output=True,text=True,timeout=30)
        data=result.stdout
        if op=="configuration" and re.search(r'(?im)^\s*(?:secrets|include)\b',data):data="Configuration contains a restricted section. Use the public connections view."
        if re.search(r"-----BEGIN (?:.* )?PRIVATE KEY-----",data):raise ValueError("Restricted response")
        if args.get('filter'):data='\n'.join(l for l in data.splitlines() if args["filter"].casefold() in l.casefold())
        return {"device":n,"exit":result.returncode,"output":data}
    with ThreadPoolExecutor(max_workers=5) as pool: rows=list(pool.map(fetch,names))
    combined=json.dumps(rows,ensure_ascii=False)
    start=max(0,args.get("offset",0));limit=max(100,min(32000,args.get("limit",20000)))
    return content({"characters":len(combined),"offset":start,"data":combined[start:start+limit]})


def main():
    for line in sys.stdin:
        try:
            req=json.loads(line); method=req.get("method"); rid=req.get("id")
            if rid is None:continue
            if method=="initialize":
                result={"protocolVersion":req["params"]["protocolVersion"],"capabilities":{"tools":{}},"serverInfo":{"name":"reader","version":"1.0"}}
            elif method=="tools/list":
                result={"tools":[{"name":k,"description":desc,"annotations":{"readOnlyHint":True,"destructiveHint":False,
                    "idempotentHint":True,"openWorldHint":k=="observe"},"inputSchema":{"type":"object","properties":props,"additionalProperties":False,
                    "required":["network","observation"] if k=="observe" else []}} for k,(desc,props) in SCHEMAS.items()]}
            elif method=="tools/call":
                key=req["params"]["name"];args=req["params"].get("arguments",{})
                with (DIR/"access.jsonl").open("a") as log:log.write(json.dumps({"time":time.time(),"tool":key,"arguments":args})+"\n")
                try:result={"content":call(key,args)}
                except Exception as err:result={"content":content(str(err)),"isError":True}
            elif method=="resources/list":result={"resources":[]}
            elif method=="resources/templates/list":result={"resourceTemplates":[]}
            elif method=="prompts/list":result={"prompts":[]}
            elif method=="ping":result={}
            else:
                print(json.dumps({"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":"Unknown method"}}),flush=True); continue
            print(json.dumps({"jsonrpc":"2.0","id":rid,"result":result}),flush=True)
        except (ValueError,KeyError) as err:
            print(str(err),file=sys.stderr,flush=True)


if __name__ == "__main__":
    main()
