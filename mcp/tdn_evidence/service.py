"""Immutable captures and read-only collection over allowlisted worker connections."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock
import hashlib
import importlib
import json
import re
import shlex
import subprocess
import uuid

from .adapters import ADAPTERS, Unsupported
from .models import Settings, Manifest, Observation


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def safe_id(value):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", value) or value in {".", ".."}:
        raise ValueError("Invalid identifier")
    return value


class Transport:
    def run(self, device, argv):
        command = ["sudo", "-n", "docker", "exec", device.container, *argv]
        if device.worker != "local":
            command = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ControlMaster=auto", "-o", "ControlPersist=60", "-o", "ControlPath=/tmp/tdn-evidence-%C", "--", device.worker, shlex.join(command)]
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return None, b"", b"Collection command timed out after 30 seconds"


class EvidenceService:
    def __init__(self, config, transport=None):
        self.config_path = Path(config).resolve()
        self.settings = Settings.model_validate_json(self.config_path.read_text())
        if set(self.settings.saved_experiments) & set(self.settings.saved_snapshots):
            raise ValueError("Saved experiment and snapshot identifiers must be distinct")
        if set(self.settings.saved_execution_supplements) - set(self.settings.saved_snapshots):
            raise ValueError("Execution supplement refers to an unknown saved snapshot")
        if set(self.settings.execution_epoch_union) - set(self.settings.saved_execution_supplements):
            raise ValueError("An execution epoch union requires a configured supplement")
        for module in self.settings.adapter_modules:
            importlib.import_module(module)
        self.root = self.resolve(self.settings.store)
        self.root.mkdir(parents=True, exist_ok=True)
        self.transport = transport or Transport()
        self.networks = {n.id: n for n in self.settings.networks}
        if len(self.networks) != len(self.settings.networks):
            raise ValueError("Duplicate network identifier")
        for network in self.settings.networks:
            safe_id(network.id)
            if len({d.id for d in network.devices}) != len(network.devices):
                raise ValueError("Duplicate device identifier")
            for device in network.devices:
                safe_id(device.id)
                safe_id(device.container)
                if not re.fullmatch(r"[a-zA-Z0-9_.@-]+", device.worker) or device.worker.startswith("-"):
                    raise ValueError("Invalid worker address")
                for adapter in device.adapters:
                    if adapter not in ADAPTERS:
                        raise ValueError("Unknown adapter: " + adapter)
        self.jobs = {}
        self.lock = Lock()
        self.pool = ThreadPoolExecutor(max_workers=2)

    def resolve(self, value):
        path = Path(value)
        return path.resolve() if path.is_absolute() else (self.config_path.parent / path).resolve()

    def experiment(self, collection):
        from .experiments import adapter
        configured = self.settings.saved_experiments[collection]
        return adapter(configured.parser), self.resolve(configured.path)

    def list_networks(self):
        return {"live": [n.model_dump() for n in self.settings.networks],
                "saved": sorted([*self.settings.saved_snapshots, *self.settings.saved_experiments]),
                "saved_experiments": {name: item.parser for name, item in self.settings.saved_experiments.items()},
                "collections": sorted(p.name for p in self.root.iterdir() if (p / "manifest.json").is_file())}

    def describe_capabilities(self, network=None):
        if network in self.settings.saved_experiments:
            adapter, _ = self.experiment(network)
            return {"saved_experiment": {"parser": self.settings.saved_experiments[network].parser,
                "capabilities": adapter.CAPABILITIES, "lean_views": [adapter.LEAN_VIEW],
                "scope": adapter.SCOPE}}
        if network in self.settings.saved_snapshots:
            from .projections import PROJECTIONS
            return {"saved": {"capabilities": ["devices", "interfaces", "links", "routes", "filters", "tunnels", "credentials", "probes"],
                "lean_views": ["inventory", "packet_filters", "topology", "multi_protocol_execution", *sorted(PROJECTIONS)],
                "execution_supplement_configured": network in self.settings.saved_execution_supplements,
                "execution_scope": "Retained native IPv4 IPsec/OVS observations; other mechanisms require a matching parser",
                "execution_epoch_union": network in self.settings.execution_epoch_union}}
        names = ADAPTERS if network is None else {a for d in self.networks[network].devices for a in d.adapters}
        return {name: {"parser_version": ADAPTERS[name].version, "capabilities": {
            k: {"meaning": c.meaning, "rechecked": c.recheck} for k, c in ADAPTERS[name].capabilities.items()}}
            for name in names}

    def collect_evidence(self, network, capabilities=None):
        if network not in self.networks:
            if network in self.settings.saved_snapshots or network in self.settings.saved_experiments:
                raise ValueError("This ID names a saved snapshot. Use query_evidence or prepare_lean_bundle with that collection ID. collect_evidence requires a configured live network.")
            raise ValueError("Unknown configured live network; use list_networks to discover available IDs")
        capabilities = capabilities or []
        known = {a + "." + c for a, adapter in ADAPTERS.items() for c in adapter.capabilities}
        if set(capabilities) - known:
            raise ValueError("Unknown capabilities: " + str(sorted(set(capabilities) - known)))
        ident = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
        job = {"id": ident, "status": "running", "network": network, "cancel": Event()}
        with self.lock:
            self.jobs[ident] = job
        self.pool.submit(self._collect, job, capabilities)
        return {"id": ident, "status": "running"}

    def collection_status(self, collection):
        safe_id(collection)
        if collection in self.settings.saved_experiments:
            manifest = self.read_manifest(collection)
            return {"id": collection, "status": "complete", "source_kind": "saved_experiment",
                    "runtime_backend": manifest["runtime_backend"]}
        if collection in self.settings.saved_snapshots:
            manifest = self.read_manifest(collection)
            return {"id": collection, "status": "complete", "source_kind": "saved", "convergence": manifest["convergence"]}
        with self.lock:
            if collection in self.jobs:
                return {k: v for k, v in self.jobs[collection].items() if k != "cancel"}
        manifest = self.read_manifest(collection)
        return {"id": collection, "status": "complete", "consistency": manifest["consistency"]}

    def cancel_collection(self, collection):
        with self.lock:
            job = self.jobs[collection]
            if job["status"] == "running":
                job["cancel"].set()
            return {"id": collection, "status": job["status"], "cancellation_requested": job["cancel"].is_set()}

    def _collect(self, job, requested):
        ident = job["id"]
        directory = self.root / (".pending-" + ident)
        directory.mkdir()
        (directory / "raw").mkdir()
        started = now()
        observations = []
        rechecks = []
        stable = True
        try:
            network = self.networks[job["network"]]
            for device in network.devices:
                for adapter_name in device.adapters:
                    adapter = ADAPTERS[adapter_name]
                    for capability_name, capability in adapter.capabilities.items():
                        if requested and adapter_name + "." + capability_name not in requested:
                            continue
                        if job["cancel"].is_set():
                            raise InterruptedError("Collection cancelled")
                        oid = f"{device.id}.{adapter_name}.{capability_name}"
                        began = now()
                        code, stdout, stderr = self.transport.run(device, capability.argv)
                        ended = now()
                        path = f"raw/{oid}.stdout"
                        error_path = f"raw/{oid}.stderr"
                        (directory / path).write_bytes(stdout)
                        (directory / error_path).write_bytes(stderr)
                        status = "observed" if code == 0 else "failed"
                        records = []
                        diagnostics = [] if code == 0 else ["Command failed; inspect the stderr resource"]
                        if status == "observed":
                            try:
                                records = capability.parse((stdout or (stderr if capability_name == "version" else b"" )).decode("utf-8"))
                            except (ValueError, KeyError, TypeError) as error:
                                status = "unsupported"
                                diagnostics = [str(error)]
                        observations.append(Observation(id=oid, device=device.id, worker=device.worker,
                            adapter=adapter_name, capability=capability_name, argv=list(capability.argv),
                            started=began, finished=ended, exit_code=code, status=status, path=path,
                            sha256=digest(stdout), stderr_path=error_path, stderr_sha256=digest(stderr),
                            parser_version=adapter.version, records=records, diagnostics=diagnostics))
                        if capability.recheck:
                            rechecks.append((device, capability, oid, stdout, code))
            for device, capability, oid, original, original_code in rechecks:
                if job["cancel"].is_set():
                    raise InterruptedError("Collection cancelled")
                code, stdout, stderr = self.transport.run(device, capability.argv)
                path = f"raw/{oid}.recheck.stdout"
                error_path = f"raw/{oid}.recheck.stderr"
                (directory / path).write_bytes(stdout)
                (directory / error_path).write_bytes(stderr)
                same = original_code == 0 and code == 0 and original == stdout
                stable = stable and same
                observations.append(Observation(id=oid + ".recheck", device=device.id, worker=device.worker,
                    adapter="recheck", capability=oid, argv=list(capability.argv), started=now(), finished=now(),
                    exit_code=code, status="observed" if code == 0 else "failed", path=path, sha256=digest(stdout),
                    stderr_path=error_path, stderr_sha256=digest(stderr), parser_version="byte-comparison-v1",
                    records=[{"unchanged": same}]))
            manifest = Manifest(id=ident, network=network.id, started=started, finished=now(), devices=network.devices,
                                consistency=("stable-during-recheck" if stable else "changed") if rechecks else "not-checked",
                                observations=observations)
            raw = encode(manifest.model_dump())
            (directory / "manifest.json").write_bytes(raw)
            (directory / "manifest.sha256").write_text(digest(raw) + "\n")
            directory.rename(self.root / ident)
            with self.lock:
                job.update(status="complete", consistency=manifest.consistency, manifest_uri=f"evidence://{ident}/manifest")
        except Exception as error:
            (directory / "failure.json").write_bytes(encode({"error": str(error), "observations": [o.model_dump() for o in observations]}))
            with self.lock:
                job.update(status="cancelled" if isinstance(error, InterruptedError) else "failed", error=str(error))

    def read_manifest(self, collection):
        if collection in self.settings.saved_experiments:
            adapter, directory = self.experiment(collection)
            manifest, _ = adapter.validated_experiment(directory)
            return manifest
        if collection in self.settings.saved_snapshots:
            from .saved import validated_snapshot
            manifest, _, _ = validated_snapshot(self.resolve(self.settings.saved_snapshots[collection]))
            return manifest
        directory = self.root / safe_id(collection)
        if not directory.resolve().is_relative_to(self.root):
            raise ValueError("Collection path escapes evidence store")
        raw = (directory / "manifest.json").read_bytes()
        if digest(raw) != (directory / "manifest.sha256").read_text().strip():
            raise ValueError("Manifest hash mismatch")
        manifest = Manifest.model_validate_json(raw).model_dump()
        for observation in manifest["observations"]:
            for pathkey, hashkey in [("path", "sha256"), ("stderr_path", "stderr_sha256")]:
                path = (directory / observation[pathkey]).resolve()
                if not path.is_relative_to(directory.resolve()) or digest(path.read_bytes()) != observation[hashkey]:
                    raise ValueError("Raw observation path/hash mismatch")
        return manifest

    def query_evidence(self, collection, capability=None, device=None, offset=0, limit=100):
        if offset < 0 or not 1 <= limit <= 500:
            raise ValueError("Require offset >= 0 and limit between 1 and 500")
        if collection in self.settings.saved_experiments:
            adapter, directory = self.experiment(collection)
            return adapter.query_experiment(directory, collection, capability, device, offset, limit)
        if collection in self.settings.saved_snapshots:
            from .saved import query_snapshot
            return query_snapshot(self.resolve(self.settings.saved_snapshots[collection]), capability, device, offset, limit)
        manifest = self.read_manifest(collection)
        observations = [o for o in manifest["observations"] if (device is None or o["device"] == device)
                        and (capability is None or o["adapter"] + "." + o["capability"] == capability)]
        if device is not None and device not in {d["id"] for d in manifest["devices"]}:
            raise ValueError("Unknown device")
        rows = [{"observation": o["id"], "device": o["device"], "status": o["status"], "source_sha256": o["sha256"],
                 "source_uri": f"evidence://{collection}/raw/{o['id']}", "started": o["started"], "finished": o["finished"], "record": r}
                for o in observations for r in o["records"]]
        end = min(offset + limit, len(rows))
        return {"collection": collection, "consistency": manifest["consistency"], "records": rows[offset:end],
                "total": len(rows), "next_offset": end if end < len(rows) else None,
                "coverage": [{"observation": o["id"], "status": o["status"], "diagnostics": o["diagnostics"], "exit_code": o["exit_code"], "stderr_uri": f"evidence://{collection}/stderr/{o['id']}"} for o in observations],
                "requested_capability_collected": bool(observations),
                "devices_without_observation": sorted(({device} if device else {d["id"] for d in manifest["devices"]}) - {o["device"] for o in observations})}

    def read_raw(self, collection, observation):
        if collection in self.settings.saved_experiments:
            adapter, directory = self.experiment(collection)
            return adapter.read_experiment_raw(directory, observation)
        if collection in self.settings.saved_snapshots:
            from .saved import validated_snapshot
            directory = self.resolve(self.settings.saved_snapshots[collection])
            _, snapshot, _ = validated_snapshot(directory)
            selected = next(o for o in snapshot["observations"] if o["id"] == observation)
            return (directory / selected["raw_path"]).read_text()
        manifest = self.read_manifest(collection)
        selected = next(o for o in manifest["observations"] if o["id"] == observation)
        return (self.root / collection / selected["path"]).read_text()

    def read_stderr(self, collection, observation):
        if collection in self.settings.saved_experiments:
            adapter, directory = self.experiment(collection)
            return adapter.read_experiment_raw(directory, observation, stderr=True)
        if collection in self.settings.saved_snapshots:
            return json.loads(self.read_raw(collection, observation)).get("stderr", "")
        manifest = self.read_manifest(collection)
        selected = next(o for o in manifest["observations"] if o["id"] == observation)
        return (self.root / collection / selected["stderr_path"]).read_text()

    def prepare_lean_bundle(self, collection, view="inventory"):
        from .bundle import prepare_bundle
        if collection in self.settings.saved_experiments:
            adapter, directory = self.experiment(collection)
            if view != adapter.LEAN_VIEW:
                raise ValueError("Selected experiment exports view=" + adapter.LEAN_VIEW)
            result = adapter.export_experiment(directory,
                self.root / (safe_id(collection) + "-export") / (adapter.LEAN_VIEW + ".json"))
        elif collection in self.settings.saved_snapshots:
            from .export_saved import export_saved, export_projection
            if view != "inventory":
                supplement = self.settings.saved_execution_supplements.get(collection)
                result = export_projection(self.resolve(self.settings.saved_snapshots[collection]),
                    self.root / (safe_id(collection) + "-export") / (safe_id(view) + ".json"), view,
                    execution_supplement=self.resolve(supplement) if supplement else None,
                    include_recorded_sa_epochs=collection in self.settings.execution_epoch_union)
            else:
                result = export_saved(self.resolve(self.settings.saved_snapshots[collection]), self.root / (safe_id(collection) + "-export") / "lean.json")
        else:
            if view != "inventory":
                raise ValueError("Live captures currently export the observed-route inventory")
            manifest = self.read_manifest(collection)
            result = prepare_bundle(self.root / collection, manifest)
        if self.settings.lean_output is not None:
            destination = self.resolve(self.settings.lean_output) / (safe_id(collection) + ("" if view == "inventory" else "-" + safe_id(view)) + ".json")
            destination.parent.mkdir(parents=True, exist_ok=True)
            raw = Path(result["path"]).read_bytes()
            if destination.exists() and destination.read_bytes() != raw:
                raise ValueError("Published evidence is immutable; choose a new collection")
            destination.write_bytes(raw)
            result["path"] = str(destination)
        return result
