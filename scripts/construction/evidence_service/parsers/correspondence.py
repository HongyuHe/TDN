"""Check exact normalized filter records and address bindings against referenced raw observations."""
import ipaddress
import json
from pathlib import Path
import re
import shlex
from .snapshot import EvidenceError, require


def raw_observation(bundle, snapshot, identifier):
    matches = [o for o in snapshot["observations"] if o["id"] == identifier]
    require(len(matches) == 1, "Missing or duplicate raw observation " + identifier)
    observation = matches[0]
    require(observation["returncode"] == 0, "Failed raw observation " + identifier)
    raw = json.loads((Path(bundle) / observation["raw_path"]).read_text())
    return observation, raw["stdout"]


def parse_iptables_save(text, wanted_table="filter"):
    table = None
    chains = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            continue
        if line == "COMMIT":
            table = None
            continue
        if table != wanted_table:
            continue
        tokens = shlex.split(line)
        if line.startswith(":"):
            require(len(tokens) == 3, "Unsupported raw chain declaration")
            name = tokens[0][1:]
            require(name not in chains, "Duplicate raw chain declaration")
            chains[name] = {"policy": tokens[1].lower(), "rules": []}
        else:
            require(len(tokens) >= 4 and tokens[0] == "-A", "Unsupported raw filter operation")
            name = tokens[1]
            require(name in chains, "Rule references undeclared raw chain")
            require(tokens.count("-j") == 1, "Unsupported raw verdict syntax")
            target_index = tokens.index("-j")
            require(target_index == len(tokens) - 2, "Unsupported raw target arguments")
            chains[name]["rules"].append({"tokens": tokens[2:target_index], "action": tokens[-1].lower(), "raw": line})
    require(chains, "Missing raw filter table")
    return chains


def check_filter_correspondence(bundle, snapshot, device_ids=None, families=(4, 6)):
    selected = [c for c in snapshot["filters"] if c["family"] in families and c["table"] == "filter" and (device_ids is None or c["device_id"] in device_ids)]
    observed = {}
    for chain in selected:
        candidates = []
        for identifier in chain["observation_ids"]:
            observation, text = raw_observation(bundle, snapshot, identifier)
            if observation["device_id"] == chain["device_id"] and observation["kind"] == "filters" + str(chain["family"]):
                candidates.append((identifier, text))
        require(len(candidates) == 1, "Ambiguous raw filter binding " + chain["id"])
        identifier, text = candidates[0]
        key = (chain["device_id"], chain["family"], identifier)
        parsed = parse_iptables_save(text)
        require(chain["chain"] in parsed, "Normalized chain absent from raw filter table")
        raw = parsed[chain["chain"]]
        require(chain["policy"] == raw["policy"], "Raw/default policy mismatch " + chain["id"])
        require(len(chain["ordered_rules"]) == len(raw["rules"]), "Raw/normalized rule count mismatch " + chain["id"])
        for ordinal, (normalized, actual) in enumerate(zip(chain["ordered_rules"], raw["rules"])):
            require(normalized["ordinal"] == ordinal, "Raw rule order mismatch")
            require(normalized["matches"] == {"iptables_tokens": actual["tokens"]}, "Raw match-token mismatch " + chain["id"])
            require(normalized["action"] == actual["action"], "Raw verdict mismatch " + chain["id"])
            require(shlex.split(normalized["raw_text"]) == shlex.split(actual["raw"]), "Raw quotation mismatch")
        observed.setdefault(key, {"raw": set(parsed), "normalized": set()})["normalized"].add(chain["chain"])
    expected_tables = {(o["device_id"], int(o["kind"][-1]), o["id"])
        for o in snapshot["observations"]
        if o["kind"] in {"filters" + str(f) for f in families}
        and (device_ids is None or o["device_id"] in device_ids)}
    require(set(observed) == expected_tables, "Raw filter-table observation omitted by normalized export")
    for key, inventory in observed.items():
        require(inventory["raw"] == inventory["normalized"], "Raw chain omitted by normalized export " + str(key))
    return {"chains": len(selected), "raw_tables": len(observed), "method": "Exact ordered shlex token/default/chain equality against referenced iptables-save output"}


def raw_interface_addresses(bundle, snapshot, device_id, interface_name):
    interfaces = [i for i in snapshot["interfaces"] if i["device_id"] == device_id and i["name"] == interface_name]
    require(len(interfaces) == 1, "Missing or duplicate interface identity")
    interface = interfaces[0]
    candidates = []
    for identifier in interface["observation_ids"]:
        observation, text = raw_observation(bundle, snapshot, identifier)
        if observation["device_id"] != device_id:
            continue
        try:
            rows = json.loads(text)
        except (ValueError, TypeError):
            continue
        if isinstance(rows, list):
            candidates.extend(row for row in rows if isinstance(row, dict) and row.get("ifname") == interface_name and "addr_info" in row)
    require(len(candidates) == 1, "Missing or ambiguous raw interface address binding")
    raw_addresses = candidates[0]["addr_info"]
    require(interface["addresses"] == raw_addresses, "Normalized interface addresses differ from raw")
    return {a["local"] for a in raw_addresses if a["family"] == "inet"}


def check_inner_tunnel_address_bindings(bundle, snapshot):
    checked = []
    for tunnel in snapshot["tunnels"]:
        if tunnel["layer"] != "inner":
            continue
        for end, device in [("local", tunnel["device_id"]), ("remote", tunnel["peer_device_id"])]:
            address = tunnel["endpoints"][end]
            require(address in raw_interface_addresses(bundle, snapshot, device, "gray"), "Inner endpoint is not assigned to observed Gray interface")
        sas = []
        policies = []
        for identifier in tunnel["observation_ids"]:
            observation, text = raw_observation(bundle, snapshot, identifier)
            if observation["device_id"] != tunnel["device_id"]:
                continue
            if observation["kind"] == "sas":
                sas.append(text)
            if observation["kind"] == "policies":
                policies.append(text)
        require(tunnel["observed_state"] in sas, "Normalized SA text lacks exact raw binding")
        require(tunnel["policies"] in policies, "Normalized policy text lacks exact raw binding")
        local_rows = re.findall(r"(?m)^  local  .* @ ([^\[\n]+)\[", tunnel["observed_state"])
        remote_rows = re.findall(r"(?m)^  remote .* @ ([^\[\n]+)\[", tunnel["observed_state"])
        require(local_rows == [tunnel["endpoints"]["local"]] and remote_rows == [tunnel["endpoints"]["remote"]], "Tunnel endpoints differ from observed SA endpoints")
        checked.append(tunnel["id"])
    return checked
