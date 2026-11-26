"""Hold one replacement fault, observe it independently and restore its private Twinet replica."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets

from architecture_cases import (
    ANY,
    FAMILIES,
    OBLIGATION,
    SPI,
    captured,
    complete_proof_input,
    project,
    proof_input,
)
from blind_audit import MODELS, run as audit
from cohort import HERE, NETWORKS, registered_profile, require_current_run, runtime_profile
from measure import typecheck
from observed_profile import capture_topology
from run_mode_trial import event, write
from supervisor_transport import call

WORKER = HERE / "architecture_worker.py"
PROOF = HERE / "MscArchitectureChecks.lean"
EXECUTE = """
import json, pathlib, subprocess, sys, tempfile
req = json.load(sys.stdin)
with tempfile.TemporaryDirectory(prefix="tdn-architecture-") as work:
    program = pathlib.Path(work)/"worker.py"
    program.write_text(req["source"])
    proc = subprocess.run([sys.executable,str(program)],input=json.dumps(req["request"]),text=True)
    sys.exit(proc.returncode)
"""


def worker(p, family, nonce, action, source=None):
    if not registered_profile(p) or family not in FAMILIES:
        raise ValueError("Unregistered trial")
    req = {"network": p["network"], "family": family, "nonce": nonce, "action": action}
    if family == "gray-cross-level-forward":
        req["permit"] = "peer-addresses"
    result = call(
        p["worker"],
        ["sudo", "-n", "python3", "-c", EXECUTE],
        data=json.dumps(
            {
                "source": source if source is not None else WORKER.read_text(),
                "request": req,
            }
        ).encode(),
        timeout=135,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.decode()[-1700:])
    return json.loads(result.stdout)


def project_readings(p, rows, projection=project):
    interfaces = {n: json.loads(values["interfaces"]) for n, values in rows.items()}
    original = p["topology"]
    if set(interfaces) != {d["id"] for d in original["devices"]}:
        raise ValueError("Missing device observations")
    topo = capture_topology(original, interfaces)
    return projection(
        topo, {(n, k): v for n, row in rows.items() for k, v in row.items()}
    )


def validate_reading(p, reading):
    data, witness = project_readings(p, reading["devices"])
    if json.loads(json.dumps([data, witness])) != json.loads(
        json.dumps([reading["evidence"], reading["witness"]])
    ):
        raise ValueError(
            "The recorded proof input differs from the raw device readings"
        )


def observed(p, family, nonce, source):
    rows = worker(p, family, nonce, "read", source)
    data, witness = project_readings(p, rows)
    packets = (
        worker(p, family, nonce, "packet", source)
        if family == "gray-cross-level-forward"
        else {}
    )
    shared = any(len(members) > 1 for members in witness["assignments"].values())
    usage = (
        worker(p, family, nonce, "usage", source)
        if shared and family == "shared-inner-gateway"
        else []
    )
    return {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "devices": rows,
        "evidence": data,
        "shared_traffic": usage,
        "witness": witness,
        "packet_observations": packets,
    }


def check_packets(record, forwarded):
    evidence, packets = record["evidence"], record["packet_observations"]
    incoming, outgoing = packets["ingress"], packets["egress"]
    if len(incoming) != 1 or len(outgoing) != int(forwarded):
        raise ValueError(
            "Missing the expected single-packet observation at the firewall"
        )
    from ipaddress import IPv4Address

    packet = evidence["packet"]
    for row in incoming + outgoing:
        if (
            (
                int(IPv4Address(row["source"])),
                int(IPv4Address(row["destination"])),
                row["spi"],
            )
            != (packet["source"], packet["destination"], SPI)
            or row["protocol"] != 50
            or row["seq"] <= 0
            or len(bytes.fromhex(row["esp_sha256"])) != 32
        ):
            raise ValueError(
                "Packet does not match the two gateway addresses and the protected test flow"
            )
    if incoming[0]["iface"] != packet["ingress"]:
        raise ValueError("Wrong firewall ingress")
    if forwarded and (
        outgoing[0]["iface"] != packet["egress"]
        or any(
            incoming[0][k] != outgoing[0][k]
            for k in ("source", "destination", "spi", "seq", "esp_sha256")
        )
    ):
        raise ValueError(
            "The two firewall interfaces did not observe the same ESP bytes"
        )


def verify_change(family, before, held):
    b, h = before["evidence"], held["evidence"]
    a, other = held["witness"]["gateways"]
    if (
        before["witness"]["gateways"] != [a, other]
        or before["witness"]["firewall"] != held["witness"]["firewall"]
    ):
        raise ValueError("Endpoint or firewall identity changed")
    if b["levels"][b["endpoints"][0]] == b["levels"][b["endpoints"][1]]:
        raise ValueError("The two Inner endpoints have the same level")
    altered = {k for k in b if b[k] != h[k]}
    if family == "shared-inner-gateway":
        previous, current = (
            before["witness"]["assignments"],
            held["witness"]["assignments"],
        )
        changes = [n for n in current if current[n] != previous.get(n)]
        if altered != {"reds"} or len(changes) != 1 or set(current) != set(previous):
            raise ValueError(
                "Expected exactly one new Inner assignment and a fixed Gray network"
            )
        red = changes[0]
        if (
            previous[red] != [other]
            or set(current[red]) != {a, other}
            or not any(members == [a] for n, members in previous.items() if n != red)
        ):
            raise ValueError(
                "Two distinct Red networks do not share the same installed Inner"
            )
        samples = held["shared_traffic"]
        if [r["child"] for r in samples] != ["protected", "red2"]:
            raise ValueError("Missing traffic measurements for both Red networks")
        for row, suffix, source in zip(
            samples, ("_R_A1", "_R_A2"), ("10.1.1.10", "10.1.2.252")
        ):
            key = row["child"]
            old, new = row["before"], row["after"]
            if (
                row["gateway"] != a
                or row["host"] != a.rsplit("_I_A1", 1)[0] + suffix
                or row["source"] != source
                or row["destination"] != "10.2.1.248"
                or old[key]["spi"] != new[key]["spi"]
                or old[key]["reqid"] != {"protected": 101, "red2": 31001}[key]
                or new[key]["packets"] != old[key]["packets"] + 1
            ):
                raise ValueError(
                    "The named Red host did not send through its installed SA on the shared gateway"
                )
        return (
            a,
            f"{a} protects the newly attached Red network {red} and its original Red network.",
        )
    if family == "gray-cross-level-path":
        ends = b["endpoints"]
        old_edges, new_edges = (set(map(tuple, v["edges"])) for v in (b, h))
        if (
            altered - {"regions", "edges"}
            or not old_edges <= new_edges
            or new_edges - old_edges != {tuple(ends), tuple(reversed(ends))}
            or before["witness"]["gray_path"] is not None
            or held["witness"]["gray_path"] != [a, other]
        ):
            raise ValueError(
                "Expected a new, reciprocally observed firewall-free path between the unlike-level Inners"
            )
        return (
            a,
            f"The observed Gray link directly joins {a} to {other}. Their Red security levels differ.",
        )
    if family != "gray-cross-level-forward":
        raise ValueError("Unknown architecture case")
    r = h["espRules"][0] if h["espRules"] else {}
    pkt = h["packet"]
    if (
        altered != {"espRules"}
        or h["espRules"][1:] != b["espRules"]
        or not r.get("permit")
        or list(r["spi"]) != list(ANY)
        or list(r["source"]) != [pkt["source"]] * 2
        or list(r["destination"]) != [pkt["destination"]] * 2
        or (r["ingress"], r["egress"]) != (pkt["ingress"], pkt["egress"])
    ):
        raise ValueError(
            "Expected exactly one protected-flow permit and unchanged topology"
        )
    check_packets(before, False)
    check_packets(held, True)
    return held["witness"][
        "firewall"
    ], f"The same ESP bytes from {a} to {other} arrived on s1 and left on s2."


def verify_restored(family, before, restored):
    if (
        before["evidence"] != restored["evidence"]
        or before["witness"] != restored["witness"]
    ):
        raise ValueError(
            "Restored links, assignments or firewall decisions differ from the clean control"
        )
    if family == "gray-cross-level-forward":
        check_packets(restored, False)


@contextmanager
def active_change(p, family, folder):
    nonce = secrets.token_hex(8)
    source = WORKER.read_text()
    (folder / WORKER.name).write_text(source)
    before = observed(p, family, nonce, source)
    write(folder / "before.json", before)
    event(folder, "change_requested")
    change = worker(p, family, nonce, "edit", source)
    try:
        write(folder / "change.json", change)
        held = observed(p, family, nonce, source)
        write(folder / "independent-evidence.json", held)
        device, detail = verify_change(family, before, held)
        event(folder, "single_fault_observed", device=device, detail=detail)
        yield before, held
        final = observed(p, family, nonce, source)
        verify_change(family, before, final)
        if final["evidence"] != held["evidence"]:
            raise ValueError("The held configuration changed during observation")
    finally:
        restored = worker(p, family, nonce, "restore", source)
        after = observed(p, family, nonce, source)
        write(folder / "restored-observations.json", after)
        verify_restored(family, before, after)
        write(folder / "restoration.json", restored)
        event(folder, "restoration_verified")


def proof(data, dest, source=PROOF):
    return typecheck(source, dest, data, {"  native_decide"})


def qualify(root, name, family):
    if family not in FAMILIES:
        raise ValueError("Unknown replacement")
    p = runtime_profile(name)
    folder = root / family / name
    folder.mkdir(parents=True, exist_ok=False)
    fixed = folder / PROOF.name
    fixed.write_bytes(PROOF.read_bytes())
    with active_change(p, family, folder) as (before, held):
        control = proof(
            project_readings(p, before["devices"], proof_input),
            folder / "clean-lean",
            fixed,
        )
        from capture_stable import capture_stable

        cap = capture_stable(p, folder / "raw")
        if not cap["converged"]:
            raise ValueError("The full snapshot did not converge")
        imported, witness = captured(folder / "raw" / "snapshot" / "native")
        if imported != held["evidence"] or witness != held["witness"]:
            raise ValueError(
                "The full snapshot and the independent live readings disagree"
            )
        generic = complete_proof_input(folder / "raw" / "snapshot" / "native")
        if generic != project_readings(p, held["devices"], proof_input):
            raise ValueError(
                "The full snapshot disagrees with the independent Gray Firewall observations"
            )
        fault = proof(generic, folder / "fault-lean", fixed)
    after = json.loads((folder / "restored-observations.json").read_text())
    clean_again = proof(
        project_readings(p, after["devices"], proof_input),
        folder / "restored-lean",
        fixed,
    )
    names = [line.split()[1] for line in fault["failed_obligations"]]
    if [control["status"], fault["status"], clean_again["status"]] != [
        "pass",
        "rejected",
        "pass",
    ] or names != [OBLIGATION[family]]:
        raise ValueError(
            f"Unexpected Lean verdicts: {control['status']}, {fault['status']} {names}, {clean_again['status']}"
        )
    result = {
        "network": name,
        "family": family,
        "source_sha256": hashlib.sha256(fixed.read_bytes()).hexdigest(),
        "scope": "live qualification without blind detectors",
        "snapshot": "raw/snapshot/native",
        "lean": ["pass", "rejected", "pass"],
        "failed_obligation": names[0],
    }
    write(folder / "qualification.json", result)
    return result


def execute(root, name, family):
    from attachment_view import check as check_attachments, from_native
    from capture_stable import capture_stable
    from delivery_paths import check_trial as check_paths
    from full_suite import suite
    from gray_connectivity import trial as check_gray
    from mode_lab import evidence as modes_evidence, snapshot
    from restore_health import verify as health

    root = require_current_run(root)
    p = runtime_profile(name)
    protocol = json.loads((root / "protocol.json").read_text())
    source_hash = hashlib.sha256(PROOF.read_bytes()).hexdigest()
    if protocol["clean_proofs"][name]["architecture"]["source_sha256"] != source_hash:
        raise ValueError(
            "The architecture checks must pass on the clean snapshot before a scored trial"
        )
    folder = root / "trials" / family / name
    folder.mkdir(parents=True, exist_ok=False)
    with active_change(p, family, folder):
        with ThreadPoolExecutor(max_workers=3) as pool:
            audits = {m: pool.submit(audit, m, folder / m) for m in MODELS}
            raw = root / "raw" / "trials" / family / name
            capture = pool.submit(capture_stable, p, raw)
            modes = snapshot(p)
            write(folder / "mode-observations.json", modes)
            mode_source = HERE / "ModeChecks.lean"
            typecheck(
                mode_source,
                folder / "lean",
                modes_evidence(modes),
                set(mode_source.read_text().splitlines()),
            )
            result = capture.result()
            if result["converged"]:
                native = raw / "snapshot" / "native"
                suite(native, raw / "snapshot" / "processing", folder / "tdn-full")
                active = {
                    **p,
                    "topology": json.loads((native / "spec.json").read_text()),
                }
                check_attachments(
                    active, from_native(active, native), folder / "attachment-check"
                )
                if (root / "delivery-protocol.json").is_file():
                    check_paths(root, name, folder)
                if (root / "gray-connectivity-protocol.json").is_file():
                    check_gray(root, folder)
            event(folder, "full_snapshot_collected", converged=result["converged"])
            for model, future in audits.items():
                event(
                    folder,
                    "detector_finished",
                    model=model,
                    status=future.result()["status"],
                )
    restored = health(p)
    write(folder / "restored-health.json", restored)
    if not restored["ready"]:
        raise RuntimeError(
            "Restored network failed the tunnel and Red delivery controls"
        )


if __name__ == "__main__":
    cli = argparse.ArgumentParser(
        description="Qualify the three new cases without starting detector sessions"
    )
    cli.add_argument("output", type=Path)
    cli.add_argument("network", choices=NETWORKS)
    cli.add_argument("families", nargs="*")
    args = cli.parse_args()
    for f in args.families or FAMILIES:
        print(qualify(args.output, args.network, f), flush=True)
