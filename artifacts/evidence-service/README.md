# MCP and Lean import validation

The `v2` tag identifies commit `91a5dfe5967add6d33310b430346a3f35f493750`. Its sources were recovered from the verified pre-v3 checkpoint saved on October 24, 2026 at 01:45:47 UTC. The `v3` tag identifies commit `aaaa3c128c58b0341fb2be8cc1b34246f9d8a9b1`, committed as “Construct proofs for extracted RGs.” Both tags and the `reconstruct` branch were pushed before implementation began.

The migration exported 4,854 concrete Lean values from 156 evidence modules. The active modules now import structured JSON with `tdn_data`. All existing named evidence definitions, lemmas, and theorems remain present. The source comparison is recorded in `declaration-parity.json`. General network semantics and CSfC requirement statements were preserved.

`validation.json` records actual MCP client calls against the live server. The BIRD collection contains routing-daemon output and Linux forwarding entries from two isolated BIRD 2.15.1 containers built from Twinet's image definition. `bird-ping.txt` records successful traffic in both directions with the advertised source addresses. The separate MSC collection reads devices on two CloudLab workers and makes no atomic-capture claim.

`build-invalidation.json` records a three-step Lake test. A local theorem passed with the original JSON value, failed after the value changed, and passed after restoration. The test exposed a limitation of Lake's legacy `extraDepTargets` setting for these input-directory dependencies. The final configuration uses `needs`.

The live MCP test also exposed an SSH input-stream problem. SSH inherited the server's standard input and could consume MCP messages. The transport now supplies `DEVNULL` as stdin and uses `ssh -n`. Connection reuse reduces repeated SSH setup during collection.

The migration tests exposed two Lean command integration requirements. The import command registers each generated definition for simplification and editor navigation. Its record selector uses brackets because introducing `key` as a syntax keyword would conflict with existing variable names. These corrections preserved the original proof bodies.

The original Python script interfaces remain for historical replay and regression testing. New construction uses the MCP server and JSON import commands. Saved-evidence projections support inventory, ordered packet filters, and validated topology. Live typed bundles contain observed forwarding inventories. Additional execution projections can be registered as ordinary Python modules and must be checked against the relevant Lean types and local conditions.
