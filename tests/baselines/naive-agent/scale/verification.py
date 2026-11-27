"""Replay the registered TDN obligations using only immutable snapshot inputs."""

from pathlib import Path
import hashlib
from functools import cache
from ipaddress import ip_interface
import json
import re
import sys

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from attachment_view import check as check_attachments, from_native
from delivery_paths import check as check_deliveries, clean_paths
from full_suite import suite
from gray_connectivity import evidence as gray_evidence, verify as check_gray
from measure import typecheck
from mode_lab import evidence as mode_evidence
from scale.profiles import profile
from scale.design import control_profile, key_attestations
from scale.service_policy import check as check_service_policy
from snapshot_inputs import put

REGISTERED_PROOF_SUITES = {"architecture", "topology", "forwarding", "headers", "firewall",
                           "modes", "attachments", "gray-connectivity", "service-policy", "key-contexts", "deliveries"}


def read(path):
    return json.loads(path.read_bytes())


def management_inputs(topology):
    admins = {str(ip_interface(p["address"]).ip): d["id"] for d in topology["devices"]
              if d["role"] == "admin" for p in d["interfaces"] if p.get("address")}
    result = []
    for d in topology["devices"]:
        if d["role"] != "gray-firewall" or not d.get("admin"):
            continue
        for p in d["interfaces"]:
            if p["zone"] == "management":
                result.append({"iface": d["id"] + ":" + p["name"], "sourceDevice": admins[d["admin"]],
                               "sourceAddress": d["admin"], "destinationAddress": str(ip_interface(p["address"]).ip),
                               "sourcePort": 49152, "destinationPort": 8443})
    return result


def connections(native):
    rows = []
    spec = read(native / "spec.json")
    obs = read(native / "snapshot.json")["observations"]
    commands = {r["device_id"]: r for r in obs if r["kind"] == "connections-raw"}
    for d in spec["devices"]:
        if d["role"] not in ("inner", "outer"):
            continue
        command = commands[d["id"]]
        data = (native / command["raw_path"]).read_bytes()
        if (
            command["returncode"]
            or hashlib.sha256(data).hexdigest() != command["raw_sha256"]
        ):
            raise ValueError("Missing effective gateway configuration on " + d["id"])
        output = json.loads(data)["stdout"]
        modes = re.findall(r"children\s*\{protected\s*\{mode=([A-Z_]+)\b", output)
        if len(modes) != 1:
            raise ValueError("Ambiguous protected child on " + d["id"])
        rows.append(
            {"device": d["id"], "role": d["role"], "mode": modes[0], "output": output}
        )
    return rows


def check_key_contexts(native, intended, dest):
    snapshot = read(native / "snapshot.json")
    roles = {d["id"]: d["role"] for d in intended["devices"] if d["role"] in {"inner", "outer"}}
    observed = {d["id"]: d["role"] for d in snapshot["devices"] if d["role"] in {"inner", "outer"}}
    if observed != roles or set(roles.values()) != {"inner", "outer"}:
        raise ValueError("The captured gateways differ from the registered Inner and Outer inventory")
    contexts = key_attestations(native, snapshot, require_complete=True)
    evidence = {role: sorted((r["origin"], r["key_context"]) for d, r in contexts.items()
                              if roles[d] == role and r["active"])
                for role in ("inner", "outer")}
    if not all(evidence.values()):
        raise ValueError("The recorded gateways have no active key context to compare at one layer")
    source = HERE / "KeyContextChecks.lean"
    return typecheck(source, dest, evidence, set(source.read_text().splitlines()))


def verify(root, name, snapshot, out, *, control=False, registered_policy=None, control_variant=None):
    p = control_profile(name, control_variant) if control_variant is not None else profile(name)
    native = snapshot / "native"
    results = suite(native, snapshot / "processing", out)

    def run(key, fn):
        try:
            result = fn()
            results[key] = {
                k: result[k]
                for k in (
                    "status",
                    "typecheck_ns",
                    "failed_obligations",
                    "source_sha256",
                    "evidence_sha256",
                )
            }
        except Exception as exc:
            results[key] = {
                "status": "import_error",
                "typecheck_ns": None,
                "message": str(exc),
            }

    def mode():
        source = HERE / "ModeChecks.lean"
        return typecheck(
            source,
            out / "modes",
            mode_evidence(connections(native)),
            set(source.read_text().splitlines()),
        )

    run("modes", mode)
    @cache
    def census():
        return from_native(p, native)

    run("attachments", lambda: check_attachments(p, census(), out / "attachments"))

    def gray():
        observed_profile = {**p, "topology": read(native / "spec.json")}
        actual = {
            (d["device"], i["ifname"])
            for d in census()["devices"]
            for i in d["interfaces"]
        }
        expected = {
            (d["id"], i["name"])
            for d in observed_profile["topology"]["devices"]
            for i in d["interfaces"]
        }
        missing = sorted(expected - actual)
        return check_gray(
            out / "gray-connectivity", gray_evidence(observed_profile, census(), missing)
        )

    run("gray-connectivity", gray)
    run("service-policy", lambda: check_service_policy(
        native, p["topology"], read(out / "forwarding/evidence.json"), out / "service-policy",
        registered_policy=registered_policy))
    if registered_policy is not None:
        run("key-contexts", lambda: check_key_contexts(native, p["topology"], out / "key-contexts"))
    if control:
        put(root / "controls" / (name + "-management-inputs.json"), management_inputs(p["topology"]))
    if control and not (root / "controls" / (name + "-approved-paths.json")).exists():
        try:
            clean_paths(root, name)
        except Exception as exc:
            results["delivery-witness"] = {
                "status": "import_error",
                "message": str(exc),
                "typecheck_ns": None,
            }
    run(
        "deliveries",
        lambda: check_deliveries(
            root, name, out / "forwarding/evidence.json", out / "deliveries"
        ),
    )
    put(out / "verification.json", results)
    return results
