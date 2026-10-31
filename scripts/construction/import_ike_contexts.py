"""Bind recorded IKE/CHILD peer sessions without inventing secret-key identities."""
import argparse
import ipaddress
import json
from pathlib import Path
import re

from import_execution import policy_blocks, state_blocks
from loaded_policy import loaded_policies, parse_configuration
from validate_evidence import require, validate_bundle


def match(pattern, line, what):
    result = re.fullmatch(pattern, line)
    require(result is not None, "Unsupported IKE context " + what)
    return result.groups()


def parse_listing(text):
    lines = [line for line in text.splitlines() if line.strip()]
    require(len(lines) == 11, "Complete single IKE/CHILD listing required")
    connection, ike_id, initiator, init_star, responder, resp_star = match(
        r"(\S+): #(\d+), ESTABLISHED, IKEv2, ([0-9a-f]{16})_i(\*?) ([0-9a-f]{16})_r(\*?)",
        lines[0], "header")
    require(bool(init_star) != bool(resp_star), "Ambiguous IKE initiator role")
    local_id, local_address = match(r"  local  '([^']+)' @ ([0-9.]+)\[500\]", lines[1], "local endpoint")
    remote_id, remote_address = match(r"  remote '([^']+)' @ ([0-9.]+)\[500\]", lines[2], "remote endpoint")
    require(lines[3] == "  AES_GCM_16-256/PRF_HMAC_SHA2_384/ECP_384", "Unreviewed IKE algorithms")
    match(r"  established \d+s ago, reauth in \d+s", lines[4], "established age")
    child, child_id, reqid = match(
        r"  (\S+): #(\d+), reqid (\d+), INSTALLED, TUNNEL, ESP:AES_GCM_16-256(?:/ECP_384)?",
        lines[5], "CHILD")
    match(r"    installed \d+s ago, rekeying in \d+s, expires in \d+s", lines[6], "CHILD age")
    inbound, = match(r"    in  ([0-9a-f]{8}),\s+\d+ bytes,\s+\d+ packets(?:,\s+\d+s ago)?", lines[7], "inbound SPI")
    outbound, = match(r"    out ([0-9a-f]{8}),\s+\d+ bytes,\s+\d+ packets(?:,\s+\d+s ago)?", lines[8], "outbound SPI")
    local_ts, = match(r"    local  (\S+)", lines[9], "local selectors")
    remote_ts, = match(r"    remote (\S+)", lines[10], "remote selectors")
    return dict(connection=connection, child=child, daemon_ike_id=int(ike_id), daemon_child_id=int(child_id),
                reqid=int(reqid), local_is_initiator=bool(init_star), child_pfs="ECP_384" if lines[5].endswith("/ECP_384") else None,
                local_id=local_id, remote_id=remote_id,
                local_address=int(ipaddress.IPv4Address(local_address)),
                remote_address=int(ipaddress.IPv4Address(remote_address)),
                ike_initiator_spi=int(initiator, 16), ike_responder_spi=int(responder, 16),
                inbound_spi=int(inbound, 16), outbound_spi=int(outbound, 16),
                local_ts=local_ts, remote_ts=remote_ts)


def parse(bundle):
    bundle = Path(bundle)
    validation = validate_bundle(bundle)
    snapshot = json.loads((bundle / "snapshot.json").read_text())
    _, loaded = loaded_policies(bundle, snapshot)
    devices = {d["id"]: d for d in snapshot["devices"]}
    gateways = {d["id"] for d in snapshot["devices"] if d["role"] in {"inner", "outer"}}
    tunnels = {t["device_id"]: t for t in snapshot["tunnels"] if t["mechanism"] == "IPsec"}
    require(gateways and set(tunnels) == gateways, "Complete gateway session inventory required")
    observations = snapshot["observations"]
    records = []
    for device in sorted(gateways):
        namespace = devices[device]["namespace"]
        prefix = ["docker", "exec", namespace]
        used = []
        def raw(suffix, multiple=False):
            selected = [o for o in observations if o["device_id"] == device and o["command"] == prefix + suffix]
            require(selected and (multiple or len(selected) == 1), "Missing or ambiguous context observation")
            values = []
            for observation in selected:
                record = json.loads((bundle / observation["raw_path"]).read_text())
                require(observation["returncode"] == 0 and observation["parse_status"] == "parsed" and
                        observation.get("error") is None and set(record) == {"stdout", "stderr"},
                        "Failed or mismatched context observation")
                used.append({"id": observation["id"], "started_at": observation["started_at"],
                             "ended_at": observation["ended_at"], "raw_sha256": observation["raw_sha256"]})
                values.append(record["stdout"])
            return values if multiple else values[0]
        endpoint = parse_listing(raw(["swanctl", "--list-sas"]))
        configurations = parse_configuration(tunnels[device]["loaded_public_configuration"])
        require(set(configurations) == {endpoint["connection"]}, "Context connection inventory differs")
        config = configurations[endpoint["connection"]]
        require(config["local"]["id"] == endpoint["local_id"] and config["remote"]["id"] == endpoint["remote_id"] and
                int(ipaddress.IPv4Address(config["local_addrs"])) == endpoint["local_address"] and
                int(ipaddress.IPv4Address(config["remote_addrs"])) == endpoint["remote_address"],
                "Context identity/address differs from loaded configuration")
        require(set(config["children"]) == {endpoint["child"]}, "Context CHILD inventory differs")
        child = config["children"][endpoint["child"]]
        require(child["local_ts"] == endpoint["local_ts"] and child["remote_ts"] == endpoint["remote_ts"] and
                int(child["reqid"]) == endpoint["reqid"], "Context selectors/reqid differ")
        states = state_blocks(raw(["ip", "-s", "xfrm", "state", "list", "nokeys"]))
        expected = [[endpoint["reqid"], endpoint["outbound_spi"], endpoint["local_address"], endpoint["remote_address"]],
                    [endpoint["reqid"], endpoint["inbound_spi"], endpoint["remote_address"], endpoint["local_address"]]]
        require(sorted(states) == sorted(expected), "Context SPIs differ from complete installed SAD")
        local = ipaddress.IPv4Network(endpoint["local_ts"])
        remote = ipaddress.IPv4Network(endpoint["remote_ts"])
        endpoint.update(local_low=int(local.network_address), local_high=int(local.broadcast_address),
                        remote_low=int(remote.network_address), remote_high=int(remote.broadcast_address))
        for value in raw(["ip", "xfrm", "policy", "list"], multiple=True):
            policies = policy_blocks(value, 0)
            for direction in ["out", "in", "fwd"]:
                require(len(policies[direction]) == 1, "Context SPD inventory differs")
                p = policies[direction][0]
                forward = direction == "out"
                wanted = [endpoint["reqid"], 0,
                          endpoint["local_address"] if forward else endpoint["remote_address"],
                          endpoint["remote_address"] if forward else endpoint["local_address"],
                          endpoint["local_low"] if forward else endpoint["remote_low"],
                          endpoint["local_high"] if forward else endpoint["remote_high"],
                          endpoint["remote_low"] if forward else endpoint["local_low"],
                          endpoint["remote_high"] if forward else endpoint["local_high"]]
                require(p[:8] == wanted and p[9] in {None, endpoint["outbound_spi"] if forward else endpoint["inbound_spi"]},
                        "Context SPD endpoints/selectors differ")
        endpoint.update(device=device, peer=tunnels[device]["peer_device_id"], observations=used)
        records.append(endpoint)
    by_device = {r["device"]: r for r in records}
    for record in records:
        require(record["peer"] in by_device, "Context peer missing")
        peer = by_device[record["peer"]]
        require(peer["peer"] == record["device"], "Context peer inventory not reciprocal")
        require(record["local_is_initiator"] != peer["local_is_initiator"], "Reciprocal initiator roles disagree")
        require(record["child_pfs"] == peer["child_pfs"], "Reciprocal CHILD PFS differs")
        for left, right in [("local_id","remote_id"),("remote_id","local_id"),
                            ("local_address","remote_address"),("remote_address","local_address"),
                            ("ike_initiator_spi","ike_initiator_spi"),("ike_responder_spi","ike_responder_spi"),
                            ("inbound_spi","outbound_spi"),("outbound_spi","inbound_spi"),
                            ("local_ts","remote_ts"),("remote_ts","local_ts")]:
            require(record[left] == peer[right], "Reciprocal context mismatch: " + left)
    return {"bundle": str(bundle), "source_manifest_sha256": validation["source_manifest_sha256"],
            "endpoints": records, "gateway_count": len(records), "loaded_connection_count": len(loaded),
            "scope": [
                "Public IKE/CHILD identities, directions and installed SAD/SPD bindings only; no secret-key equality is inferred from public identifiers.",
                "Key derivation, fresh nonce/key separation, complete actual key-holder coverage and fixed-program producer behavior remain implementation contracts.",
                "Matching records were collected at the retained observation times. A fixed-session interpretation assumes the recorded negotiated associations remained in use across those observations; matching public records do not prove uninterrupted stability.",
                "Recorded daemon IDs may differ at the two endpoints and are not receive-side guards. Observation times identify retained epochs, not authenticated wire fields.",
                "The selected records cover a mid-run snapshot. Prior replayable publications need explicit history coverage; freshness and replay rejection remain separate.",
                "No security domain is assigned to a key context. Shared Outer contexts may carry several protected source domains.",
            ]}


def generate(data):
    devices = {r["device"]: i for i, r in enumerate(data["endpoints"])}
    entries = []
    fields = ["local_address", "remote_address", "ike_initiator_spi", "ike_responder_spi",
              "inbound_spi", "outbound_spi", "local_low", "local_high", "remote_low", "remote_high"]
    for row in data["endpoints"]:
        values = [str(devices[row["device"]]), json.dumps(row["local_id"]), json.dumps(row["remote_id"])]
        values += [str(row[field]) for field in fields]
        values += [str(row["local_is_initiator"]).lower(), str(row["child_pfs"] is not None).lower()]
        entries.append("⟨" + ", ".join(values) + "⟩")
    pairs = ["(" + str(devices[r["device"]]) + ", " + str(devices[r["peer"]]) + ")" for r in data["endpoints"]]
    return '''import TDN.Semantics.IKEContexts

namespace TDN.Imported.FreshSharedIKEContexts
open IKEContexts

def endpoints : List Endpoint := [\n  ''' + ",\n  ".join(entries) + ''']
def pairs : List (Nat × Nat) := [''' + ", ".join(pairs) + ''']

def endpoint (index : Nat) : Endpoint :=
  endpoints[index]?.getD ⟨0, "", "", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, false⟩

lemma all_context_pairs_checked : ∀ pair ∈ pairs, Peer (endpoint pair.1) (endpoint pair.2) := by decide
lemma complete_gateway_count : endpoints.length = ''' + str(len(entries)) + ''' := by decide

theorem recorded_directional_contexts_agree : ∀ pair ∈ pairs,
    sendName (endpoint pair.1) = receiveName (endpoint pair.2) := by
  intro pair member
  exact reciprocal_peers_agree_on_directional_record _ _ (all_context_pairs_checked pair member)

end TDN.Imported.FreshSharedIKEContexts
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.bundle)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"gateways": data["gateway_count"], "secret_key_equality_claimed": False}))

if __name__ == "__main__":
    main()
