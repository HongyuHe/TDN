# Import network evidence through MCP and Lean commands

The evidence service gives the construction agent one interface for collecting network state, inspecting saved observations, and preparing JSON data for Lean. Device adapters select read commands and interpret their outputs. Lean commands turn the resulting JSON into ordinary definitions that existing proofs can unfold.

The current theory keeps its network models and general proofs. The migration changes how concrete data enter Lean. It borrows lean-batfish's use of Lean commands and typed data conversion. TDN has no dependency on lean-batfish or Batfish.

## Start the server

Install `uv`, then run the launcher from any directory:

```bash
/Users/hongyu/Projects/Formal/TDN/scripts/construction/evidence_service/run.sh
```

The default configuration exposes the saved v3 baseline. The launcher installs the exact Python dependencies in `uv.lock` and starts an MCP server over standard input and output. An MCP client starts that same command as a subprocess. The server needs no listening TCP port.

To select your own configured workers, pass an absolute configuration path as the launcher's first argument. Paths inside the configuration file are resolved relative to that file. Live validation uses `scripts/construction/evidence_service/live-validation.json`. Copy that file before adapting the workers or container names.

Each device identifies its worker, container, optional declared role, and adapters. One device can combine `linux`, `frr`, `ovs`, and `ipsec` adapters. A BIRD router combines `linux` and `bird`. Collection can span workers because each device carries its own worker address. SSH uses existing keys and requires passwordless `sudo docker exec` on each configured worker.

## Ask for evidence

The construction agent can use the following tools:

| Tool | Result |
| --- | --- |
| `list_networks` | Configured live networks, saved snapshots, and completed captures. |
| `describe_capabilities` | Available observations and the interpretation each adapter provides. |
| `collect_evidence` | A collection ID. The collection continues in the background. |
| `collection_status` | Running, complete, cancelled, or failed, with the relevant details. |
| `cancel_collection` | Requests cancellation between bounded collection commands. |
| `query_evidence` | Records, their sources, collection times, coverage, and a pagination cursor. |
| `prepare_lean_bundle` | A JSON file, its SHA-256 hash, and its supported Lean data type or record keys. |

For example, call `collect_evidence` with `network: "bird-validation"` and selected capabilities such as `linux.fib4`, `linux.fib6`, and `bird.routes`. Poll the returned collection ID. Query `bird.routes` to inspect BIRD's candidate routes and selected-route markers. Query `linux.fib4` to inspect the forwarding entries actually installed in Linux.

Every query refers to one saved collection. A query does not silently refresh observations. `total` and `next_offset` show whether more rows remain. Coverage identifies failed or unsupported observations. `devices_without_observation` identifies devices missing a requested live observation.

The resource `evidence://COLLECTION/manifest` exposes the capture manifest. `evidence://COLLECTION/raw/OBSERVATION` exposes the original output for a particular observation. `evidence://COLLECTION/stderr/OBSERVATION` exposes its diagnostic output. The manifest records the device, worker, command, parser version, start and finish times, exit code, and output hashes.

Saved v3 snapshots retain their original validation rules. Their query categories include `devices`, `interfaces`, `links`, `routes`, `filters`, `tunnels`, `credentials`, and `probes`. The server verifies the saved files and references before returning those records.

## Load JSON in Lean

Use `tdn_data` when an evidence record should populate an existing TDN type:

```lean
import TDN.Import.Command
import TDN.Evidence.Types

tdn_data captured : TDN.Evidence.Snapshot
  from "../../evidence/lean/v3-baseline.json" ["snapshot"]

example : TDN.Evidence.HasProvenance captured := by
  unfold TDN.Evidence.HasProvenance captured
  decide
```

The path is relative to the Lean source file. The string in brackets selects a record in the JSON object. The declared Lean type determines how that record is decoded. The command rejects extra fields, incorrect value types, and invalid finite node indices. Its round-trip check also rejects input that a decoder would silently discard.

Use `tdn_snapshot Bird from "file.json"` for a live observed-route bundle. The command defines `Bird.snapshot` with type `TDN.Import.NetworkSnapshot`. The record preserves devices, observation references, routing-table identifiers, route kinds, address families, destinations, gateways, output interfaces, and metrics. It records a configured architectural role separately as `declaredRole`.

A JSON import supplies data. Existing `lemma` and `theorem` declarations still establish their conclusions with checked proofs. The import command does not generate proofs or add axioms. Lean's elaborator runs the decoder and constructs the definition; Lean's kernel checks the resulting term. Parser correctness and faithful collection remain implementation assumptions.

Lake tracks the JSON files under `evidence/lean` through its `evidence_data` input-directory target. Changing those files invalidates the library build. Keep files used by project proofs under that directory. The example server configuration publishes prepared files there automatically. An arbitrary JSON file elsewhere can be loaded explicitly, but its location must also be registered as a Lake dependency before relying on incremental builds.

## Prepare different kinds of saved evidence

`prepare_lean_bundle("v3-baseline", "inventory")` creates a value of the existing `TDN.Evidence.Snapshot` type. The `packet_filters` view checks the saved rules against their raw firewall output, preserves rule order, and exports `List TDN.PacketPolicy.Rule` values. Unsupported chains cause preparation to fail.

The `topology` view validates runtime interface and switch relationships before exporting edges. It also computes candidate region labels after removing the relevant firewall vertices. Lean must still check the labels against every remaining edge. The Python calculation supplies a candidate witness; the reusable path theorem relies on the checked edge condition.

Live collection currently exports typed forwarding inventories. FRR and BIRD configuration text, OVS tables, strongSwan observations, and MACsec channel observations are separately queryable. Their capability descriptions state whether the result has a structured interpretation or preserves the command text. A new live packet-execution configuration still needs the appropriate interpretation and finite checks before it can support the MSC execution theorems.

## Extend device support

Add an `Adapter` with a version and named `Capability` entries. Each capability supplies a fixed command, a parser, an explanation of its meaning, and whether collection should recheck it. Register the adapter with `register_adapter`. Add its module name to `adapter_modules` in the trusted server configuration. The module is ordinary local Python code and should be reviewed before loading.

A vendor can provide `fib4` and `fib6` capabilities using the common forwarding-record fields returned by `linux_routes`. The bundle exporter consumes those capabilities independently of the adapter name. Routing-daemon candidate routes use separate capabilities.

A trusted extension can also call `register_projection(name, version, project)` to add a saved-evidence view. The projection receives a validated snapshot and returns JSON records. Lean checks those records against the types named in the import commands.

Parsers return dictionaries and lists. They never generate Lean source. Preserve unfamiliar information explicitly or reject the observation as unsupported. Preserve distinctions that affect proofs, including configured versus installed state, route-table order, firewall-rule order, and local IPsec identifiers versus identifiers carried on the wire.

The shared parsers under `evidence_service/parsers` retain TDN's snapshot validation, observed topology validation, runtime identity checks, and ordered packet-filter interpretation. The original script entry points retain compatibility with historical replay tests. Their generation code is outside the new MCP import path. New construction should use MCP and JSON import commands. The v3 tag preserves the original Python-generated Lean files and generation tools.

## Understand the checks and limits

A successful collection records what each command returned during its own interval. Selected configuration and forwarding observations are collected again at the end. Equal outputs establish stability at the two observations. They do not establish that no state changed between those observations or that multiple workers were sampled atomically.

Hashes detect changes relative to the retained manifest. They do not authenticate the physical device or prove that a collector reported truthfully. A complete argument about the real network still needs the existing modeling assumptions and the local conditions required by the general theorems.

The BIRD validation creates two isolated containers from Twinet's BIRD image definition, establishes BGP, checks the learned kernel routes, and sends traffic between the advertised networks. The MCP validation exercises tool discovery, collection, polling, pagination, raw resources, and Lean export. A separate collection reads MSC devices on two workers without changing those deployments.

Run the automated checks with:

```bash
uv run --project scripts/construction/evidence_service python -m unittest discover -s tests/evidence_service -v
lake build
```

Replay the live MCP checks with:

```bash
uv run --project scripts/construction/evidence_service python -m scripts.construction.evidence_service.validation.mcp_live
```

The isolated BIRD deployment procedure is `scripts/construction/evidence_service/validation/deploy_bird.sh`. Build its image from Twinet's `images/bird` directory first. The script reserves the `tdn-evidence-bird-*` container names and the `172.30.231.0/24` Docker network.

The historical Python regression suite uses its recorded input manifest:

```bash
TDN_INPUT_MANIFEST=artifacts/construction/2026-10-24T014455Z/source_paths_current.json TDN_OUTPUT_DIR=artifacts/construction/2026-10-24T014455Z uv run --project scripts/construction/evidence_service python -m unittest discover -s tests -p 'test_*.py'
```
