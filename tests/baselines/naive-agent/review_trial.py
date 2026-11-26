"""Attach the supervisor's reading of both blind answers to one restored, measured fault."""

import argparse
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from run_mode_trial import captured_modes
from peer_lab import loaded_peers
from score_trials import KNOWN_TYPES


def read(file):
    return json.loads(file.read_text())


def observed_fault(family, network, folder):
    change = read(folder / "change.json")
    from architecture_cases import FAMILIES
    if family in FAMILIES:
        from run_architecture_trial import verify_change, verify_restored
        before = read(folder / "before.json")
        verify_restored(family,before,read(folder/"restored-observations.json"))
        return verify_change(family,before,read(folder/"independent-evidence.json"))
    if family in ("inner-empty-ipv4-header", "firewall-local-empty-udp"):
        before = read(folder / "before.json")
        trial = read(folder / "independent-evidence.json")
        restored = read(folder / "delivery-restored.json")
        observations = [before[0], trial["probe"][0], restored[0]]
        network_bytes = 20 if family == "inner-empty-ipv4-header" else 28
        if (
            [o["accepted_by_local_ip"] for o in observations] != [False, True, False]
            or any(
                o["total_ipv4_bytes"] != network_bytes or o["payload_bytes"] != 0
                for o in observations
            )
            or trial["counter_after"]["packets"]
            != trial["counter_before"]["packets"] + 1
        ):
            raise ValueError(
                "Local admission and restoration of the header were not established"
            )
        if family == "inner-empty-ipv4-header":
            return (
                change["device"],
                "The same Red host sent an empty IPv4 header directly to its own Inner gateway. The receiving interface saw it before, during and after the change. Only during the trial did the INPUT rule count it and Linux record the unlisted protocol after filtering.",
            )
        return (
            change["device"],
            "The adjacent Black router sent an empty UDP datagram to the Outer Firewall itself. The chosen port has no listener and the declared Black control policy allows OSPF. During the change the rule counted the packet and the local UDP stack recorded the closed port. The original filter dropped the same packet before and after the trial.",
        )
    if family == "inner-peer-loopback":
        before = read(folder / "before.json")
        after = read(folder / "snapshot.json")
        clean_session = read(folder / "fresh-peer-control.json")
        faulty_session = read(folder / "fresh-peer-fault.json")
        if (
            not clean_session["cross_site_child_installed"]
            or faulty_session["cross_site_child_installed"]
        ):
            raise ValueError(
                "The clean and faulty renegotiations must demonstrate loss of the required cross-site tunnel"
            )
        diff = [
            (n, d, old, loaded_peers(after[n])[d])
            for n, items in before.items()
            for d, old in items.items()
            if loaded_peers(after[n])[d] != old
        ]
        if diff != [
            (network, change["device"], change["original_address"], "127.0.0.2")
        ]:
            raise ValueError("Expected exactly one changed running peer address")
        return (
            change["device"],
            "The running protected connection points to its own loopback. The designated remote gateway is at the other site. Fresh negotiation installed a cross-site tunnel in the clean control. The same operation under the changed setting left both gateways without that tunnel. The saved configuration and all other loaded connection settings retained their clean values.",
        )
    if family in ("inner-mode", "outer-mode"):
        before = read(folder / "before.json")
        after = read(folder / "snapshot.json")
        differences = [
            (n, d, old, captured_modes(after[n])[d])
            for n, devices in before.items()
            for d, old in devices.items()
            if captured_modes(after[n])[d] != old
        ]
        if differences != [(network, change["device"], "TUNNEL", "TRANSPORT")]:
            raise ValueError(
                "Expected exactly one change in the loaded modes of the active networks"
            )
        return (
            change["device"],
            "The sole protected child connection on "
            + change["device"]
            + " changed from tunnel to transport mode. The inventories of the active networks located exactly one changed mode.",
        )
    if family in ("firewall-inside-disconnected", "firewall-outside-disconnected"):
        side = family.split("-")[1]
        original = change["original"]
        if (
            not change["isolated"]
            or read(folder / "restoration.json")["restored"] != original
        ):
            raise ValueError(
                "Missing before and after check of the disconnected interface"
            )
        return (
            change["device"],
            "The "
            + side
            + " interface of "
            + change["device"]
            + f" was disconnected. The independently matched live interface peers lost exactly one {side} attachment. Restoring the original interface reinstated the link.",
        )
    evidence = read(folder / "independent-evidence.json")
    before = read(folder / "before.json")
    after = evidence["probe"]
    lost = [p for p in after if not p["delivered"]]
    added = evidence["counter_after"]["packets"] - evidence["counter_before"]["packets"]
    if not lost or not all(p["delivered"] for p in before) or added <= 0:
        raise ValueError(
            "A new rule did not cause a previously working exchange to fail"
        )
    phrase = (
        "approved management TCP connections"
        if evidence["rule"].get("chain") == "INPUT"
        else "intended Red delivery directions"
    )
    return (
        change["device"],
        f"{len(lost)} of {len(after)} {phrase} failed after the single deny on {change['device']}. The new rule counted {added} packets over the observation interval. Restoring the rule restored the original exchange.",
    )


def assessment(folder, method, verdict, lines, reason):
    if verdict in ("timeout", "unevaluable"):
        log = read(folder / method / "execution.json")
        expected = "timeout" if verdict == "timeout" else "invalid_run"
        if log["status"] != expected or lines != "-" or not reason.strip():
            raise ValueError("Supply the recorded run status and a reason")
        return {
            "verdict": verdict,
            "source": method + "/execution.json",
            "reason": reason,
        }
    path = folder / method / "answer.md"
    bound = len(path.read_text().splitlines())
    refs = [int(number) for number in lines.split(",")]
    if (
        verdict not in ("hit", "miss")
        or not refs
        or any(number < 1 or number > bound for number in refs)
    ):
        raise ValueError(
            "Supply a hit or miss and actual line numbers from the complete answer"
        )
    return {
        "verdict": verdict,
        "source": method + "/answer.md",
        "lines": refs,
        "reason": reason,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    for name in ("astra", "sol"):
        parser.add_argument(
            "--" + name, required=True, nargs=3, metavar=("VERDICT", "LINES", "REASON")
        )
    parser.add_argument(
        "--tdn", required=True, nargs=3, metavar=("VERDICT", "RESULT_FILE", "REASON")
    )
    args = parser.parse_args()
    folder = args.folder.resolve()
    network, family = folder.name, folder.parent.name
    from cohort import NETWORKS, require_current_run
    require_current_run(folder.parents[2])
    if network not in NETWORKS or family not in KNOWN_TYPES:
        raise ValueError("Unregistered case")
    events = [
        json.loads(l)["event"]
        for l in (folder / "events.jsonl").read_text().splitlines()
    ]
    if "single_fault_observed" not in events or "restoration_verified" not in events:
        raise ValueError("Single fault and completed restoration must both be verified")
    target, oracle = observed_fault(family, network, folder)
    root = folder.parents[2]
    if family == "inner-empty-ipv4-header":
        from protocol_diagnostic import inspect
        inspect(root, folder)
    if (root / "gray-connectivity-protocol.json").is_file():
        from gray_connectivity import trial as gray_paths

        gray_paths(root, folder)
    methods = {
        name: assessment(folder, name, *getattr(args, name))
        for name in ("astra", "sol")
    }
    verdict, file, reason = args.tdn
    if (
        verdict not in ("hit", "miss", "unevaluable")
        or not (folder / file).resolve().is_relative_to(folder)
        or not (folder / file).is_file()
    ):
        raise ValueError("Supply the source of the TDN judgment inside the trial")
    methods["tdn"] = {"verdict": verdict, "source": file, "reason": reason}
    record = {
        "network": network,
        "type": family,
        "clauses": KNOWN_TYPES[family]["clause_ids"],
        "target": target,
        "oracle": oracle,
        "methods": methods,
    }
    with NamedTemporaryFile(dir=folder, mode="w", encoding="utf-8") as staged:
        json.dump(record, staged, indent=2, ensure_ascii=False)
        staged.write("\n")
        staged.flush()
        os.link(staged.name, folder / "adjudication.json")


if __name__ == "__main__":
    main()
