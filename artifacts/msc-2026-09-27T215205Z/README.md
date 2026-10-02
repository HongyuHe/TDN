# Evidence used by the node-1 Lean model

The `snapshot/` directory is a read-only export collected on node-1 at `/users/hy/msc-tdn-model.YdghYs/snapshot`.
Its manifest records the collection interval, runtime source revision, specification hash, and SHA-256 of all 140 exported files.
The export contains no private keys.

The separate `check.json` records the following live check, which passed all 273 checks.
It references the same specification hash but was collected after the snapshot.
The snapshot and probes do not form an atomic observation.

`scripts/import_msc_snapshot.py` verifies the bundle before generating `TDN/MSC/Deployment.lean`.
The generated file also records the manifest and probe-file hashes.
Hashes identify evidence; they do not authenticate its source or prove the correctness of the observed implementation.

The original deployment remains running.
Collection did not change topology, firewall rules, or tunnel configuration.
Earlier exports remain in the sibling artifact directories.
