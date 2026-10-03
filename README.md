# Theory-defined Networking (TDN)

Theory-defined Networking (TDN) explores **networks that carry and maintain their own correctness arguments**. Network intent is spread across documentation, configurations, and changing runtime state. TDN aims to turn those artifacts into a coherent formal theory, making network changes easier to explain, debug, and trust.

TDN combines **top-down concept discovery with bottom-up theory construction**. Desired properties guide the abstractions and lemmas to develop; configurations and observations supply the concrete facts. The theory follows the network's hierarchy and modular structure, connecting facts to reusable theorems through an explicit dependency graph. As the network changes, that graph should identify which assumptions and proofs need revisiting.

**AI agents construct the theory and proofs; Lean checks the proofs.** The aim is to shift expensive reasoning toward construction and reuse, with independently checkable results. Proofs establish claims about the formal model, so accurate semantics, justified assumptions, and reliable evidence remain essential.

The current prototype models the deployed node-1 MSC network in Lean. Automated theory construction and continuous proof maintenance remain research goals. Research proposal [here](https://www.notion.so/hongyuhe/Theory-defined-Networking-TDN-3d98ffe4d93e80eba19acafd29acb301) for the broader motivation and design questions.

## Run Lean

The project pins **Lean 4.34.1** in `lean-toolchain`.
Lake ships with Lean.
The model uses only Lean's bundled libraries and has no Mathlib dependency.

On the configured Mac, run:

```sh
source "$HOME/.elan/env"
cd ~/Projects/Formal/TDN
lake build
lake exe msc_demo
lake env lean Playground.lean
```

`lake build` checks the library proofs and builds the executable.
`lake exe msc_demo` prints the pinned deployment identity and evaluates same-level delivery, cross-level rejection, missing SAs/policies, failed authentication, transport failure, and imported firewall rules.
The examples assume fixed readiness; they do not run live probes.
`lake env lean Playground.lean` checks the scratch file and prints its `#eval` results.

Run the complete focused validation with:

```sh
bash scripts/check_msc_model.sh
```

You can also check or execute a single file directly:

```sh
lake env lean TDN/MSC.lean
lake env lean --run Main.lean
```

Run the commands from the project root.
`lake env` supplies the import paths for the compiled project.
Run `lake build` again after editing imported modules.

## Understand the model

The model is pinned to the node-1 default topology: two sites, two security levels, 35 devices, 44 cables, and four bidirectional IPsec tunnel relationships.
Detailed Lean comments explain each abstraction, proof technique, and trust boundary.
Read the files in the following order:

| File | Purpose |
|---|---|
| [Types.lean](TDN/MSC/Types.lean) | Device, interface, tunnel, IPv4 filtering, and observation vocabulary |
| [Deployment.lean](TDN/MSC/Deployment.lean) | Generated declarations from the pinned, hashed export |
| [Topology.lean](TDN/MSC/Topology.lean) | Inventory checks, unbounded Gray-path cuts, management cable separation, and peer/trust facts |
| [Policy.lean](TDN/MSC/Policy.lean) | Supported observed FORWARD-rule semantics and universal missing-policy rejection |
| [Flow.lean](TDN/MSC/Flow.lean) | Authorized host pairs, symbolic nested encryption/decryption, failure handling, and conditional delivery |
| [MSC.lean](TDN/MSC.lean) | Public entry point importing the model |

The model proves theorems about its declarations and semantics.
Linux refinement, cryptographic security, timing, physical separation, and institutional approval remain outside those theorems.
Encryption wrappers are readable symbolic data.
`healthy` is an explicit example assumption, and observed success is kept separate.

## Refresh the pinned deployment data

The current input is [artifacts/msc-2026-10-03T070453Z/snapshot](artifacts/msc-2026-10-03T070453Z/snapshot/manifest.json), with its separately collected [273-check report](artifacts/msc-2026-10-03T070453Z/check.json).
Snapshot directory names use the export-start timestamp in UTC; `Z` denotes UTC.
Git tracks only the latest snapshot. Older snapshots remain local and ignored.
Historical diagnostics and the original solver experiments require a separately retained September 27 snapshot.
The offline importer verifies all export hashes, checks declared/deployed identities, and requires supported intended and observed forwarding rules to agree.
Unsupported rules and mismatched evidence produce errors.

```sh
python3 scripts/import_msc_snapshot.py --check
```

To use a new export, retain it in a new artifact directory and regenerate:

```sh
python3 scripts/import_msc_snapshot.py \
  --snapshot artifacts/new-run/snapshot \
  --checks artifacts/new-run/check.json
lake build
```

The importer emits data, not axioms or proofs.
A changed topology or policy can invalidate a theorem.
Update the model and its documented scope deliberately; do not alter generated facts to force a proof to pass.
The importer currently supports the two-level IPv4 profile and an explicit subset of FORWARD syntax.
Changing input locations also requires updating the validation script's pinned paths before adopting the new run as the project baseline.

## Install on another machine

Install elan using the [official Lean installation instructions](https://lean-lang.org/install/manual/):

```sh
curl -fsSL https://elan.lean-lang.org/elan-init.sh -o /tmp/elan-init.sh
sh /tmp/elan-init.sh -y --default-toolchain none
source "$HOME/.elan/env"
```

Run `lake build` from the project root.
Elan downloads the exact toolchain listed in `lean-toolchain`.

The generated `.lake/` directory is ignored by Git.
Keep `lean-toolchain`, `lakefile.toml`, and `lake-manifest.json` under version control to reproduce the project setup.

## Run the MSC emulator

The Twinet `tdn` branch extends `dev` with a configurable MSC lab.
The native FRR/OVS deployment runs on node-1.
The default has 35 devices and 44 links, plus seven private FRR control containers.
Node-0 retains the earlier deployment.

```sh
ssh hy@clnode146.clemson.cloudlab.us
cd ~/Twinet
sudo bin/twinet msc console BLACK
sudo bin/twinet msc console G_A1
sudo bin/twinet msc check > /tmp/msc-check.json
sudo bin/twinet msc export --output /tmp/msc-snapshot-001
```

The [Twinet operator guide](https://github.com/HongyuHe/Twinet/blob/tdn/docs/13_msc.md) explains native CLI access, shared Outer Firewalls and Gray networks, layout configuration, exports, faults, and recovery.
Small JSON files under `examples/msc/layouts/` select firewall counts and Gray sharing.
Export bundles separate declared configurations from sampled live facts and include timestamps, image identities, and file hashes for later theory construction.
The [model's verified node-1 snapshot](artifacts/msc-2026-10-01T193731Z/snapshot/manifest.json) is available locally under `artifacts/msc-2026-10-01T193731Z/snapshot/`.
Its `spec.json` and `facts.json` are ready to inspect.
Earlier snapshots remain in `artifacts/`.
