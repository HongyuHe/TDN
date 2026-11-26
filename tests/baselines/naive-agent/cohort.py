"""Network names and runs used by the current single-fault experiment."""

import json
import os
from pathlib import Path

NETWORKS = ("net-03", "net-04", "net-05")
SCALE_PREFIXES = {"Base": "XB", "10xLevels": "XL", "10xDevices": "XD"}


def registered_profile(value):
    if value["network"] in SCALE_PREFIXES:
        from scale.profiles import profile
        return profile(value["network"]) == value
    return value["network"] in NETWORKS
REVISION = "three-multilevel-profiles-v1"
HERE = Path(__file__).resolve().parent
LIVE_RUN = Path(
    os.environ.get("TDN_BASELINE_LIVE_RUN", HERE / "runs" / "multilevel-live-01")
).resolve()
SNAPSHOT_RUN = Path(
    os.environ.get(
        "TDN_BASELINE_SNAPSHOT_RUN", HERE / "runs" / "multilevel-snapshots-01"
    )
).resolve()


def require_current_run(folder):
    folder = Path(folder).resolve()
    protocol = folder / "protocol.json"
    if protocol.is_file():
        saved = json.loads(protocol.read_text())
        if saved.get("revision") != REVISION or saved.get("original_profiles") != list(
            NETWORKS
        ):
            raise ValueError(
                f"{folder} belongs to a different benchmark. Choose a new run directory."
            )
    return folder


def runtime_profile(network):
    if network in SCALE_PREFIXES:
        from scale.profiles import profile
        return profile(network)
    if network not in NETWORKS:
        raise ValueError(f"Network outside the benchmark: {network}")
    original = json.loads((HERE / "profiles" / (network + ".json")).read_text())
    source = original["topology"]
    prefix = {"net-03": "NF", "net-04": "NR", "net-05": "NM"}[network]
    copy_prefix = "Q" + prefix[1]
    mapping = {d["id"]: copy_prefix + d["id"][2:] for d in source["devices"]}
    if not all(n.startswith(prefix + "_") for n in mapping):
        raise ValueError("Unexpected device inventory")

    def rename(value):
        if isinstance(value, dict):
            return {k: rename(v) for k, v in value.items()}
        if isinstance(value, list):
            return [rename(v) for v in value]
        return mapping.get(value, value) if isinstance(value, str) else value

    topology = rename(source)
    topology["name"] = "baseline-" + copy_prefix.lower()
    return {
        **original,
        "topology": topology,
        "deployment_directory": "/var/tmp/tdn-multilevel-replicas/"
        + network
        + "/state",
    }
