import hashlib
import json
import re
from validate_evidence import EvidenceError, require


def parse_configuration(text):
    root={}
    stack=[root]
    for line in text.splitlines():
        line=line.strip()
        if not line:
            continue
        if line=="}":
            if len(stack)==1:
                raise EvidenceError("unbalanced configuration braces")
            stack.pop()
        elif re.fullmatch(r"[A-Za-z0-9_-]+\s*\{",line):
            name=line[:-1].strip()
            if name in stack[-1]:
                raise EvidenceError("duplicate configuration section")
            child={};stack[-1][name]=child;stack.append(child)
        elif "=" in line and not any(char in line for char in "{}#"):
            key,value=[part.strip() for part in line.split("=",1)]
            if not re.fullmatch(r"[A-Za-z0-9_-]+",key) or not value or key in stack[-1]:
                raise EvidenceError("invalid/duplicate configuration assignment")
            stack[-1][key]=value
        else:
            raise EvidenceError("unsupported include/inheritance/comment or configuration syntax")
    if len(stack)!=1 or set(root)!={"connections"}:
        raise EvidenceError("incomplete or unsupported configuration root")
    return root["connections"]


def proposal_modes(text,esp):
    if not text or "default" in text:
        raise EvidenceError("implicit/default proposal expansion is unsupported")
    result=[]
    for proposal in text.split(","):
        tokens=proposal.strip().split("-")
        ciphers=[]
        hmac=False
        for token in tokens:
            if re.fullmatch(r"aes(?:128|192|256)gcm(?:8|12|16)",token):
                ciphers.append("gcm")
            elif re.fullmatch(r"aes(?:128|192|256)",token):
                ciphers.append("cbc")
            elif token in {"sha1","sha256","sha384","sha512"}:
                hmac=True
            elif re.fullmatch(r"(?:prfsha(?:1|256|384|512)|ecp(?:256|384|521)|modp(?:2048|3072|4096|6144|8192)|(?:ke[1-7]_)?mlkem(?:512|768|1024))",token):
                pass
            else:
                raise EvidenceError("unsupported proposal algorithm: "+token)
        if not ciphers:
            raise EvidenceError("proposal lacks an explicit encryption mode")
        result.extend({"mode":mode,"hmac":hmac} for mode in ciphers)
    if esp and any(p["mode"]=="cbc" and not p["hmac"] for p in result):
        raise EvidenceError("ESP CBC proposal lacks HMAC integrity")
    return result


def brace_content(text,position):
    if text[position]!="{":
        raise EvidenceError("expected runtime section")
    depth=0
    for i in range(position,len(text)):
        if text[i]=="{":depth+=1
        if text[i]=="}":
            depth-=1
            if depth==0:return text[position+1:i]
    raise EvidenceError("unbalanced runtime connection section")


def immediate_sections(text):
    result=[]
    depth=0
    for match in re.finditer(r"[{}]|[A-Za-z0-9_-]+(?=\s*\{)",text):
        token=match.group()
        if token=="{":depth+=1
        elif token=="}":depth-=1
        elif depth==0:result.append(token)
    return result


def loaded_policies(bundle,snapshot):
    manifest=json.loads((bundle/"manifest.json").read_text())
    require(all(manifest["inventory_complete"][kind]["complete"] is True
                for kind in ["devices","tunnels"]), "complete device/tunnel inventory required")
    devices={d["id"]:d for d in snapshot["devices"]}
    require(set(devices)==set(snapshot["scope"]["expected_device_ids"]),
            "complete expected device inventory required")
    observations={o["id"]:o for o in snapshot["observations"]}
    records=[]
    evidence=[]
    seen_devices=set()
    for tunnel in snapshot["tunnels"]:
        if tunnel["mechanism"]!="IPsec":continue
        device=tunnel["device_id"]
        require(tunnel["status"]=="observed" and devices[device]["status"]=="observed",
                "observed gateway and tunnel required")
        namespace=devices[device]["namespace"]
        prefixes=[["docker","exec",namespace],["ip","netns","exec",namespace]]
        def successful_local(observation):
            return (observation is not None and observation["device_id"]==device and
                    observation["returncode"]==0 and observation["parse_status"]=="parsed")
        if device in seen_devices:raise EvidenceError("multiple endpoint records need explicit connection binding")
        seen_devices.add(device)
        config=tunnel.get("loaded_public_configuration")
        if not isinstance(config,str):raise EvidenceError("loaded configuration missing")
        digest=hashlib.sha256(config.encode()).hexdigest()
        confirmation=tunnel["load_confirmation"]
        if digest!=tunnel["loaded_configuration_sha256"] or digest!=confirmation["loaded_file_sha256"]:
            raise EvidenceError("loaded configuration hash mismatch")
        load=observations.get(confirmation["observation_id"])
        if not successful_local(load) or confirmation["returncode"]!=0:
            raise EvidenceError("successful per-device load confirmation missing")
        load_raw=json.loads((bundle/load["raw_path"]).read_text())
        if load_raw["stdout"]!=confirmation["output"] or "--file" not in load["command"] or "--load-conns" not in load["command"]:
            raise EvidenceError("load confirmation not bound to exact-file command")
        path=load["command"][load["command"].index("--file")+1]
        matching_prefixes=[prefix for prefix in prefixes if load["command"]==
                           prefix+["swanctl","--load-conns","--file",path]]
        require(len(matching_prefixes)==1, "load command target or operation mismatch")
        prefix=matching_prefixes[0]
        supplied=[observations[oid] for oid in tunnel["observation_ids"]]
        reads=[o for o in supplied if successful_local(o) and o["command"]==prefix+["cat",path] and json.loads((bundle/o["raw_path"]).read_text())["stdout"]==config and o["ended_at"]<=load["started_at"]]
        runtime=tunnel["all_runtime_connections"]
        queries=[o for o in supplied if successful_local(o) and o["command"]==prefix+["swanctl","--list-conns","--raw"] and json.loads((bundle/o["raw_path"]).read_text())["stdout"]==runtime and load["ended_at"]<=o["started_at"]]
        if len(reads)!=1 or len(queries)!=1:
            raise EvidenceError("configuration-read/load/runtime ordering or content association missing")
        connections=parse_configuration(config)
        runtime_matches=list(re.finditer(r"list-conn event \{([A-Za-z0-9_-]+) \{",runtime))
        runtime_names=[m[1] for m in runtime_matches]
        loaded_names=re.findall(r"loaded connection '([^']+)'",load_raw["stdout"])
        if not connections or len(set(runtime_names))!=len(runtime_names) or set(runtime_names)!=set(connections) or set(loaded_names)!=set(connections):
            raise EvidenceError("loaded/runtime connection inventory mismatch")
        for name,connection in connections.items():
            if connection.get("version")!="2":raise EvidenceError("IKEv2-only configuration required")
            match=next(m for m in runtime_matches if m[1]==name)
            body=brace_content(runtime,match.end()-1)
            if "version=IKEv2" not in body:raise EvidenceError("runtime IKE version mismatch")
            for key in ["local_addrs","remote_addrs"]:
                if key+"=["+connection.get(key,"")+"]" not in body:raise EvidenceError("runtime endpoint mismatch")
            children=connection.get("children")
            marker=re.search(r"children \{",body)
            if not isinstance(children,dict) or not children or marker is None:
                raise EvidenceError("complete nonempty CHILD inventory missing")
            runtime_children=immediate_sections(brace_content(body,marker.end()-1))
            if set(runtime_children)!=set(children):raise EvidenceError("runtime CHILD inventory mismatch")
            ike=proposal_modes(connection.get("proposals"),False)
            esp=[]
            for child,child_config in children.items():
                esp.extend(proposal_modes(child_config.get("esp_proposals"),True))
            records.append({"device":device,"connection":name,"ike_versions":[2],"ike_modes":[p["mode"] for p in ike],"esp_proposals":esp,"children":list(children)})
        evidence.append({"device":device,"configuration_sha256":digest,"read_observation":reads[0]["id"],"load_observation":load["id"],"runtime_observation":queries[0]["id"],"load_stderr":load_raw["stderr"]})
    expected={d["id"] for d in snapshot["devices"] if d["role"] in {"inner","outer"}}
    if seen_devices!=expected or not expected:
        raise EvidenceError("not all inventoried VPN encryption devices have a loaded policy")
    return records,evidence
