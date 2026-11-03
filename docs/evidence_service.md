# Import network evidence through MCP and Lean commands

The evidence service gives the construction agent one interface for collecting network state, inspecting saved observations, and preparing JSON data for Lean. Device adapters select read commands and interpret their outputs. Lean commands turn the resulting JSON into ordinary definitions that existing proofs can unfold.

The current theory keeps its network models and general proofs. The migration changes how concrete data enter Lean. Lean commands decode the JSON records into typed definitions.

## Start the server

Install `uv`, then run the launcher from any directory:

```bash
/Users/hongyu/Projects/Formal/TDN/mcp/run.sh
```

The default configuration exposes the saved v3 baseline. The launcher installs the exact Python dependencies in `uv.lock` and starts an MCP server over standard input and output. An MCP client starts that same command as a subprocess. The server needs no listening TCP port.

To select your own configured workers, pass an absolute configuration path as the launcher's first argument. Paths inside the configuration file are resolved relative to that file. Live validation uses `mcp/live-validation.json`. Copy that file before adapting the workers or container names.

Each device identifies its worker, container, optional declared role, and adapters. One device can combine `linux`, `frr`, `ovs`, and `ipsec` adapters. A BIRD router combines `linux` and `bird`. Collection can span workers because each device carries its own worker address. SSH uses existing keys and requires passwordless `sudo docker exec` on each configured worker.

Saved MCP captures and validation reports live under `mcp/artifacts/`. The configured `store` selects `artifacts/local` for default use and `artifacts/live` for live validation. Git ignores routine outputs and retains the selected BIRD capture that backs the Lean import example. The [capture notes](../mcp/artifacts/README.md) identify that capture and its purpose. Lean-ready JSON stays under `data/evidence/`.

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
  from "../../data/evidence/v3-baseline.json" ["snapshot"]

example : TDN.Evidence.HasProvenance captured := by
  unfold TDN.Evidence.HasProvenance captured
  decide
```

The path is relative to the Lean source file. The string in brackets selects a record in the JSON object. The declared Lean type determines how that record is decoded. The command rejects extra fields, incorrect value types, and invalid finite node indices. Its round-trip check also rejects input that a decoder would silently discard.

Use `tdn_snapshot Bird from "file.json"` for a live observed-route bundle. The command defines `Bird.snapshot` with type `TDN.Import.NetworkSnapshot`. The record preserves devices, observation references, routing-table identifiers, route kinds, address families, destinations, gateways, output interfaces, and metrics. It records a configured architectural role separately as `declaredRole`.

A JSON import supplies data. Existing `lemma` and `theorem` declarations still establish their conclusions with checked proofs. The import command does not generate proofs or add axioms. Lean's elaborator runs the decoder and constructs the definition; Lean's kernel checks the resulting term. Parser correctness and faithful collection remain implementation assumptions.

Lake tracks the JSON files under `data/evidence` through its `evidence_data` input-directory target. Changing those files invalidates the library build. Keep files used by project proofs under that directory. The example server configuration publishes prepared files there automatically. An arbitrary JSON file elsewhere can be loaded explicitly, but its location must also be registered as a Lake dependency before relying on incremental builds.

## Prepare different kinds of saved evidence

`prepare_lean_bundle("v3-baseline", "inventory")` creates a value of the existing `TDN.Evidence.Snapshot` type. The `packet_filters` view checks the saved rules against their raw firewall output, preserves rule order, and exports `List TDN.PacketPolicy.Rule` values. Unsupported chains cause preparation to fail.

The `topology` view validates runtime interface and switch relationships before exporting edges. It also computes candidate region labels after removing the relevant firewall vertices. Lean must still check the labels against every remaining edge. The Python calculation supplies a candidate witness; the reusable path theorem relies on the checked edge condition.

The `multi_protocol_execution` view exports the lists used by `MultiProtocolExecution.finiteConfig`: device policies, ports, routes, links, bridge forwarding, MACsec ports, and encapsulation settings. Its current parser covers the retained native IPv4 IPsec and OVS profiles. Their MACsec and encapsulation lists are empty. A different mechanism causes the parser to request a matching extension. The export preserves IPsec request IDs, wire SPIs, endpoint addresses, selectors, priorities, firewall rule order, and default verdicts. It also includes the source identifiers, hashes, role assignments, and scope of the interpretation.

The native export includes `mtu` in each `portBindings` record. The parser checks that the normalized MTU equals the value in the raw interface observation and retains its observation ID. Version `native-ipv4-execution-v3-port-mtu` records that addition. An MTU describes the interface's configured packet-size limit; it does not establish that a larger datagram cannot exist after reassembly. Size proofs must account for the selected encryption overhead and the relevant admission rules.

Execution export requires a processing supplement configured in `saved_execution_supplements`. Each entry maps a saved snapshot ID to the directory containing its additional policy-routing, firewall-table, and IPsec observations. The server validates the supplement's hashes and checks its records against the snapshot before exporting. The default configuration includes the retained baseline supplement.

The optional `execution_epoch_union` list selects snapshots whose export includes every retained IPsec association epoch. That choice supports conservative safety checks across those observed associations. The observations can come from different times, so an execution using associations from several epochs is not evidence of a successful live exchange. Use a coherent captured exchange when proving observed connectivity. Other snapshots use the single selected raw observation for each device.

The `saved_experiments` configuration exposes retained mixed IPsec/MACsec experiments. Each entry has a `path` and `parser: "mixed-protocol-v1"`. The server validates their complete manifests, command bindings, before/after observations, and supported packet operations. Agents can query interfaces, routes, policies, MACsec associations, and carrier sessions, then request the `multi_protocol_execution` view. These experiments retain their supplemental Linux namespace backend in every result.

Mixed exports give each local MACsec association a distinct generation index linked to its observed installed-key identifier. Those indices identify records within the exported configuration. Equal printed key identifiers do not prove equal secret keys. Carrier records explicitly name L2TPv3 over UDP and preserve its endpoints and session identifiers. The view targets the corresponding v3.1 Lean record fields. Operational raw resources expose only the commands bound to the validated capture.

Live collection currently exports typed forwarding inventories. FRR and BIRD configuration text, OVS tables, strongSwan observations, and MACsec channel observations are separately queryable. Their capability descriptions state whether the result has a structured interpretation or preserves the command text. A new live packet-execution configuration still needs the appropriate interpretation and finite checks before it can support the MSC execution theorems.

## Extend device support

Add an `Adapter` with a version and named `Capability` entries. Each capability supplies a fixed command, a parser, an explanation of its meaning, and whether collection should recheck it. Register the adapter with `register_adapter`. Add its module name to `adapter_modules` in the trusted server configuration. The module is ordinary local Python code and should be reviewed before loading.

A vendor can provide `fib4` and `fib6` capabilities using the common forwarding-record fields returned by `linux_routes`. The bundle exporter consumes those capabilities independently of the adapter name. Routing-daemon candidate routes use separate capabilities.

A trusted extension can also call `register_projection(name, version, project)` to add a saved-evidence view. The projection receives a validated snapshot and returns JSON records. Lean checks those records against the types named in the import commands.

Parsers return dictionaries and lists. They never generate Lean source. Preserve unfamiliar information explicitly or reject the observation as unsupported. Preserve distinctions that affect proofs, including configured versus installed state, route-table order, firewall-rule order, and local IPsec identifiers versus identifiers carried on the wire.

The shared parsers under `mcp/tdn_evidence/parsers` retain TDN's snapshot validation, observed topology validation, runtime identity checks, and ordered packet-filter interpretation. The original script entry points retain compatibility with historical replay tests. Their generation code is outside the new MCP import path. New construction should use MCP and JSON import commands. The v3 tag preserves the original Python-generated Lean files and generation tools.

## Understand the checks and limits

Mixed-protocol captures can include `macsec-provisioning.json`. The `key_provisioning` capability checks successful installation commands against the observed MACsec interfaces, SCI values, association numbers and key IDs. The collector compares private key inputs directly and exports equality links between installation records. The execution export preserves distinct local association indices and adds each association's peer and public material reference. Earlier captures without those records provide no key-equality evidence.

The `ipsec_key_provisioning` capability reads the corresponding `ipsec-provisioning.json` records. It matches each observed ESP association to a successful installation and checks the recorded equality of the peers' private key and salt inputs. Local request IDs may differ. The parser currently supports the recorded AES-256-GCM tunnel-mode installations and rejects unsupported state changes or selectors.

IPsec installation records remain separate when a key is replaced. A new key can reuse the same SPI and endpoint addresses, so those public fields alone cannot identify the installed key. The parser replays installation and removal commands up to each observation. The execution export selects the final observed phase and retains earlier phases separately in `ipsecKeyEpochs`. It never combines their keys into one claimed successful exchange. Manual installation evidence establishes neither IKE authentication nor cryptographic implementation correctness.

Saved authentication experiments use `parser: "eap-correlation-v1"` and the `authentication_correlation` export view. The parser checks public session identifiers, certificate fingerprints, key-derivation references, MKA authentication events, installed associations, and subsequent MACsec headers. It rejects mismatched sessions or associations. The export distinguishes the supplicant's TLS exchange with the authentication server from the authenticator's receipt of the session key through RADIUS.

The authentication collector records SHA-256 references to high-entropy keys while keeping the keys private. Equal references connect the recorded steps under the collector and hash assumptions. Each capture covers one successful exchange per arrangement. A general protocol proof needs explicit implementation assumptions beyond those observations.

Detailed captures use `parser: "eap-public-v1"` and the `authentication_exchange` view. That parser requires matching complete TLS 1.3 transcripts from both endpoints, including compressed certificate messages. It exports the exact handshake bytes, hello randoms, public EAP session ID, authenticated RADIUS request and response, and full-MSK references. It checks the certificate fingerprints, backend session, endpoint identities, derivation input and event order. The JSON documents the byte encoding used for each field. Incomplete transcripts are rejected. OpenSSL and hostap remain responsible for cryptographic verification; the parser checks the recorded operations and their connections.

Captures with public MKA messages use `parser: "eap-mka-public-v1"` and the `authentication_causal_history` view. The `mka_messages` category connects each daemon send to its return value, outgoing packet observation, peer receive, and successful integrity check. Matching uses the complete public Ethernet frame. Every record retains its device, source observation, and line number. The `causal_links` category records order within each process and dependencies between matching sends and receives. The parser rejects cycles and missing packet observations. These dependencies support a setup history without requiring a physical total order across the processes. Private keys remain excluded, and the daemon's integrity checks remain implementation observations.

The detailed collector runs in isolated network namespaces. Its instrumentation records public handshake and protected backend records while excluding secret keys, session tickets, application data and key logs. Earlier correlation-only captures remain available through their original parser and do not supply the detailed transcript fields.

Saved management experiments use `parser: "management-session-v1"` and the `management_sessions` view. The parser identifies the initiating AW from the first TCP SYN and the original conntrack tuple. It preserves the reverse-direction replies, packet bytes, sequence and acknowledgment numbers, interface ownership, and application request/reply records. Packet order comes from one observer's monotonic clock. Matching packet hashes connect the second observer's records without assuming that the two capture processes recorded every packet at the same instant.

The management view also retains rejected Outer-side connection attempts and their filter counters. Its session identifier is derived from the capture and initial SYN; the experiment did not capture a numeric kernel connection ID. These observations support reasoning about who initiated a particular exchange. Administrator identity, complete interface coverage, and behavior of future sessions require their own evidence and model connections.

Native IPsec captures use `parser: "native-ipsec-correlation-v1"` and the `native_ipsec_keys` view. The collector privately compares the key and salt material installed at both peers. The parser connects each equality record to the observed kernel association, active CHILD_SA, IKE session, public peer certificate, and daemon authentication log. It requires matching association inventories and installation references in two observation phases. The current parser supports AES-256-GCM tunnel ESP without marks or XFRM interface IDs.

Each native installation reference combines the device, public association fields, reported kernel installation time, and material hash. That reference identifies the captured installation; it is not a kernel-issued identifier. Private key values remain in collector memory. The exported hashes and equality records depend on the collector's truthful execution. Authentication success comes from strongSwan's records and retains the implementation assumption.

The `native-packet-sizing-v1` parser exposes observed source-size errors and packet fragmentation through `native_packet_sizing`. Its packet records retain full captured frame bytes, IPv4 lengths, fragment flags and offsets, interface MTUs, offload settings, and probe intervals. The parser recomputes packet metadata from the bytes. The initial native capture includes a successful large input that fragments again after encryption, so the export cannot be read as proof that MTU settings prevent every fragmentation event.

Repaired size captures also retain filter counters before and after each probe. Literal IPv4 `length` matches become `networkBytesRange` conditions in the execution export. Those conditions use the complete reassembled IPv4 packet length. Captured outcomes distinguish successful replies, local size errors, and failed probes accompanied by observed filter drops. A capture covers the tested inputs; a general size guarantee also requires a proof about the configured checks and encryption overhead.

The `mixed-packet-sizing-v1` parser exposes MACsec, L2TPv3 and ESP boundary measurements through `mixed_packet_sizing`. It checks the complete case and observer inventories, recomputes public header fields from captured bytes, and retains each probe's filter-counter changes. Original rules, Outer-only guards and combined Inner/Outer guards remain separate phases. The accompanying `mixed-protocol-v1` execution export selects the two actual inventories collected after the final repair and verifies their agreement. Packet timing groups observations by probe; encrypted payload identity needs a separate argument.

The `administration-observations-v1` parser exposes retained service permissions, certificate identities, API outcomes and audit records through `administration_observations`. It compares captured service source with the observed runtime hash and role map. Missing account creation, session and logout fields remain explicit. Separate listeners remain separate services.

The `administration-lifecycle-v1` parser adds actual per-user accounts and authenticated TLS-channel records through `administration_lifecycle`. It binds each admitted operation to its earlier certificate authentication, client/server tuple and channel reference. Rejected requests remain in `attempts`. Connection-close and application revocation events retain their actual order. The logical operation credential names the authenticated channel. The experiment issues no bearer token. Configured lab identities do not establish real human identity or organizational approval.

The `native-component-audit-v1` parser exposes public OS, package, account, DNS, service, clock and key-access observations through `native_component_inventory`. It verifies the collector version and exact command inventory. Private-key observations contain access metadata only. Failed commands remain in `unavailable`. File permissions and command listings supply premises for an access model; preventing every private-key export also requires an argument about the supported APIs and implementation.

The `guest-clock-use-v1` parser exposes a separate VM experiment through `clock_synchronization`. Its `sources` records bind each time server to an observed address, interface and bridge. Its `clock_uses` records connect a guest kernel and strongSwan process to the selected time source, actual clock correction, and subsequent certificate authentication. Each guest rejected a certificate while its clock was incorrect and authenticated successfully after synchronization. The parser checks the raw commands, NTP request/reply bytes, guest attachments and observation order. The selected numerical synchronization criterion comes from the experiment's actual `chronyc waitsync` command.

The clock experiment preserves its limits in `coverage`. The four client clocks belong to distinct VM kernels. Both time servers use the worker's unchanged clock, and their own synchronization requirements remain unproved. The `clock_events` records contain the collector's discipline stops, manual clock changes, restarts and authentication outcomes. Those records cover the controlled experiment; a proof about every possible clock change would need a stronger observation or implementation argument. Source trust is an explicit laboratory assignment. Optional workstations are unnecessary for the experiment.

The `os-provider-identity-v1` parser exports the retained ND gateways through `os_provider_identity`. It checks FreeBSD Inner interface addresses, Linux Outer container identities, daemon-loaded plugins, AES-GCM providers and recorded library linkage. Its `phases` and raw observations keep the identity, filtering, certificate, reauthentication and startup captures separate. Packaging those captures together does not establish an atomic snapshot or unchanged configuration. Fields absent from the old captures remain listed as unavailable.

The `key-interface-audit-v1` parser exports fresh key-access observations through `key_access_boundary`. The view includes actual daemon processes and module hashes, loaded plugins, public-key fingerprints, credential-file permissions, mount origins, security profiles and administration-interface observations. OpenSSL derives public fingerprints inside each device; private key bytes and password hashes are excluded. The observations support an assessment of key-access controls. A universal no-export theorem also needs a model of every supported access path and a justified connection to its enforcement.

The `pkcs11-token-boundary-v1` parser exports a separate two-peer VPN experiment through `token_key_boundary`. Each gateway accesses its signing key through a PKCS11 socket. A separate container holds the token files. The capture binds generated public keys to installed certificates, successful IKE authentication, protected traffic, token attributes and actual operation return codes. The parser rejects attempts that failed before reaching the intended protection check, including an uninitialized copy operation or an unsupported wrapping mechanism. It also checks gateway mounts and process namespaces against the recorded backend storage boundary.

The token experiment exposes its trust assumptions in `coverage`. Gateway root can read the user PIN and request signatures. The backend software and host remain trusted. Finite rejected export attempts support the recorded case; a general no-export theorem still needs a complete model of the available interfaces and a justified connection to their implementation.

The `pkcs11-token-extra-v1` parser adds the `token_api_extensions` view for follow-up observations. The view records private-key digest operations, operation-state export, derivation and decryption attempts, and every function listed by the exposed PKCS#11 interfaces. The observed client provides both version 2.40 and version 3.0 interfaces. SHA-384 digesting of the protected key succeeds; the capture retains its length and an opaque reference while withholding the digest bytes. The parser binds the follow-up to the original key, certificate and client binary. A proof must account for the additional private-derived operation and newer interface functions.

The `pkcs11-token-binding-v1` parser exports `token_interface_binding`. The view records the actual backend's version 2.40 interface and a client call through the explicitly selected version 3.0 interface. A normal signature first confirms the session and key; the subsequent `C_MessageSignInit` call returns unsupported. Module hashes connect those observations to the earlier captures. The result supports assessment of the implementation's version guard.

The `l2-filter-admission-v1` parser exports ordered Ethernet filter programs and captured frames through `l2_filter_admission`. The selected rules bind MKA traffic to its peer MAC address, actor SCI, EAPOL version and type, exact declared length, and standard destination address. Separate rules allow encrypted unicast traffic. The parser retains the interface, hook, priority, default verdict, size bounds and every rule condition. An unsupported rule or missing condition causes an error.

The Ethernet experiment installs the filters before fresh MKA authentication. It records successful protected traffic and counter changes for group-addressed data, wrong actors, wrong sources, truncated frames and incorrect declared lengths. Raw Ethernet headers and payload bytes remain available alongside the parsed records. The experiment uses veth interfaces, a 1,500-byte MTU, software MACsec and permanent protected-network neighbors. Additional probes inject VLAN-tagged MKA and encrypted frames. The collector preserves packet-socket auxiliary metadata and reconstructs stripped VLAN headers before decoding the captured bytes. Both allow rules require a 14-byte Ethernet header, so the normalized program rejects the tagged probes just as the observed rules do. The observations do not establish arbitrary VLAN arrangements, hardware offload or every possible Linux execution. A captured outgoing frame records an attempted transmission; rule counters and peer observations determine what happened afterward.

The `cover-sender-v1` parser exposes launch settings, scheduled send attempts, queue observations and observed frame lengths through `cover_sender`. It checks the exact retained sender implementation and preserves failed sends. The attempt sequence supports reasoning about fixed-size output construction. Actual delivery, timing guarantees and complete TRANSEC assurance require additional arguments.

The parser recognizes two exact IPv4 IKEv2/UDP-ESP BPF programs. The original 52-instruction program becomes `ipsecUDPFraming` and requires a 20-byte IPv4 header. The 62-instruction program becomes `ipsecUDPFramingWithOptions` and accepts header lengths from 20 to 60 bytes. Both check the fragment offset, packet length, destination port, and payload framing. Unknown bytecode is rejected. Peer identity, cryptographic authentication, checksum validity, and any separate IPv4-options prohibition require their own conditions. The programs use destination ports 500 and 4500; translated reply ports and NAT keepalives require separate configured allowances. Twinet's optional `strict_ipsec_udp_framing` setting installs the guard while retaining its peer and IPsec-policy restrictions.

A successful collection records what each command returned during its own interval. Selected configuration and forwarding observations are collected again at the end. Equal outputs establish stability at the two observations. They do not establish that no state changed between those observations or that multiple workers were sampled atomically.

Hashes detect changes relative to the retained manifest. They do not authenticate the physical device or prove that a collector reported truthfully. A complete argument about the real network still needs the existing modeling assumptions and the local conditions required by the general theorems.

The BIRD validation creates two isolated containers from Twinet's BIRD image definition, establishes BGP, checks the learned kernel routes, and sends traffic between the advertised networks. The MCP validation exercises tool discovery, collection, polling, pagination, raw resources, and Lean export. A separate collection reads MSC devices on two workers without changing those deployments.

Run the automated checks with:

```bash
uv run --project mcp python -m unittest discover -s tests/evidence_service -v
lake build
```

Replay the live MCP checks with:

```bash
uv run --project mcp python -m tdn_evidence.validation.mcp_live
```

The isolated BIRD deployment procedure is `mcp/tdn_evidence/validation/deploy_bird.sh`. Build its image from Twinet's `images/bird` directory first. The script reserves the `tdn-evidence-bird-*` container names and the `172.30.231.0/24` Docker network.

The historical Python regression suite uses its recorded input manifest:

```bash
TDN_INPUT_MANIFEST=data/construction/2026-10-24T014455Z/source_paths_current.json TDN_OUTPUT_DIR=data/construction/2026-10-24T014455Z uv run --project mcp python -m unittest discover -s tests -p 'test_*.py'
```
