# Evidence schema proposal v1

The importer consumes `manifest.json` and `snapshot.json` from a self-contained bundle. Every referenced path is relative to the bundle root. The schema name is `csfc-evidence/v1`. Missing evidence is explicit and never implies an empty complete inventory.

## Manifest

`schema_version`, `snapshot_id`, `run_id`, `configuration_id`, `emulation_id`, `source_case_ids`, `requirement_group_ids`, `started_at`, `ended_at`, `host`, `software`, `code_hashes`, `configuration_hashes`, `files`, `collection_failures`, `sanitization`, `inventory_complete`, `convergence` are required. `files` contains path, sha256, bytes, category. `inventory_complete` is an object mapping devices, interfaces, links, routes, filters, tunnels, credentials, probes, management to booleans with reasons. `convergence` contains before/after observation IDs, selected stable fields and hashes, consistency result, elapsed interval. A hash proves identity of the captured representation, not truth or perpetual stability.

## Normalized snapshot

Top-level fields: `schema_version`, `snapshot_id`, `scope`, `devices`, `interfaces`, `links`, `routes`, `filters`, `tunnels`, `credentials`, `probes`, `management`, `observations`, `limitations`. Arrays are always present. `scope` lists expected device/interface IDs, selected cases, management applicability and source assumptions.

Every fact record contains `id`, `device_id` where relevant, `status` (`observed`, `configured`, `unavailable`, `failed`, `not_applicable`), and `observation_ids`. Configured intent is kept distinct from observed state. Empty arrays must have a corresponding inventory completeness explanation.

- `devices`: id, role, site, security_level_id or null, implementation, namespace/container identity, host_id, virtualization_kind, physical_independence (`unavailable` unless independently supported).
- `interfaces`: id, device_id, name, zone, address_family, addresses, link_kind, parent_interface, mtu, observed_up, security_level_id.
- `links`: id, endpoint interface IDs, relation (`veth`, `bridge_attachment`, `physical`, `logical_tunnel`, `encapsulation`), physical_claim_supported, observation_ids. Container/veth links never establish separate physical security components.
- `routes`: id, device_id, family, table, destination, gateway, output_interface, priority, protocol, type, observed raw object.
- `filters`: id, device_id, family, table, chain, hook, priority, policy, ordered_rules; each rule has ordinal, matches, action, raw_text, observation_ids. The importer must reject unsupported matches/actions rather than silently treating them as allow or deny.
- `tunnels`: id, device_id, peer_device_id, layer (`inner`, `outer`, `management`), mechanism (`IPsec`, `MACsec`), endpoints, traffic_selectors, mode, algorithms, authentication, replay_protection, lifetimes, observed_state, policies, statistics, encapsulation and observation_ids. XFRM key bytes and MACsec keys are redacted before persistence; algorithm names and lengths remain.
- `credentials`: id, device_id, layer, authentication_kind, public_certificate_sha256, subject, issuer, serial, validity, key_algorithm, key_bits, signature_algorithm, chain_validation, revocation_evidence, observation_ids. Private keys and PSKs never enter exports.
- `probes`: id, source_device, destination, family, protocol, source_case_ids, purpose, expected_result, observed_result, command, start/end UTC, returncode, observation_ids. Positive useful traffic is required alongside negative checks. Probe outcomes describe the tested events only.
- `management`: an object with profile, applicability, records, failures; management-free data paths use profile `none` and applicability `optional_disabled`. No importer should gate data-path validation on management availability.
- `observations`: id, collector, command or redacted command, device_id, start/end UTC, returncode, raw_path, raw_sha256, sanitizer, parse_status.
- `limitations`: id, affected case/group IDs, classification (`external_evidence`, `physical_capability`, `unsupported_observation`, `source_interpretation`, `demonstrated_violation`), precise reason, actionable_change.

## Initial capability decisions

All six authorized servers responded with sudo access and no listed containers or network namespaces. Clemson clnode176 has approximately 250 GiB RAM and 876 GiB free disk. It is the first selected host. Docker and Go are absent and require installation. The export will preserve fresh provenance rather than reuse any previous proof output.

The existing MSC code supports IPv4 IPsec with a single tunnel per appliance. MACsec, mixed IP families, extra security levels, shared/parallel cases, and optional management variants are explicit extension tasks. They remain planned until exercised or rejected after practical investigation.

Physical separation and secure facilities, independent approved products, NSA/AO approvals, approved CDS/High Assurance hardware, personnel actions and perpetual properties cannot be established by namespace or container snapshots. Those requested facts receive unavailable evidence dispositions and actionable requirements for external records. Software behavior that can be exercised remains in scope.
