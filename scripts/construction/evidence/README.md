# Evidence provision tools

The evidence tools and their helper modules live in this directory. Network specifications, device mappings, and diagrams live in [data/extraction/networks/profiles](../../../data/extraction/networks/profiles/README.md). The Twinet Go implementation and image Dockerfiles remain in a separate Twinet checkout.

## Deploy and collect a native profile

Use the Twinet construction source described in the [recorded replay guide](../../../data/construction/2026-10-17T205010Z/agents/evidence/outputs/REPLAY.md). That guide also records image versions, software prerequisites and the limits of each experiment. The commands below use the reorganized script paths.

```sh
TWINET_ROOT=/absolute/path/to/Twinet \
  bash scripts/construction/evidence/build_images.sh /absolute/lab/exports/image-build

sudo python3 scripts/construction/evidence/replay.py up baseline \
  --lab-root /absolute/lab --twinet-root /absolute/path/to/Twinet
sudo python3 scripts/construction/evidence/replay.py check baseline \
  --lab-root /absolute/lab --twinet-root /absolute/path/to/Twinet
sudo python3 scripts/construction/evidence/replay.py collect baseline \
  --lab-root /absolute/lab --twinet-root /absolute/path/to/Twinet \
  --snapshot-name baseline-UTC
```

Build `bin/twinet` in the selected checkout before running the replay helper. The helper defaults to `LAB_ROOT/Twinet` when `--twinet-root` and `TWINET_ROOT` are absent. The supported profile names are `baseline`, `samelevel`, `shared`, `redundant` and `management`. The `inventory` action collects process and namespace observations. The `down` action removes the selected owned deployment using the same profile and lab directory.

Every collection needs a fresh snapshot name. Private deployment state goes under `LAB_ROOT/private`, and public observations go under `LAB_ROOT/exports`. The helper resolves profiles from the repository root, so deployment and collection work from any current directory. `make_native.py` reads the five generator inputs in `data/extraction/networks/profiles/` and regenerates the matching native topology and mapping files there.

## Experiment entry points

| Purpose | Current entry points |
| --- | --- |
| Device snapshots and process inventory | `collect_native_v2.py`, `native_inventory.py` |
| IP families and IPsec/MACsec pairings | `matrix_lab.py` |
| GRE, MPLS and OSPF variants | `routing_variants_v6.py` |
| Management, placement and time-source variants | `utility_variants_v3.py` |
| CA arrangements and revocation services | `ca_variants_v2.py`, `revocation_services.py` |
| PSK MKA and partial EAP-TLS experiments | `mka_psk_v4.py`, `eap_tls_v5.py`, `patch_hostap_offload.py` |
| Correlated EAP-TLS, MKA, and installed-key observations | `patch_hostap_correlation.py`, `collect_eap_correlation.py`, `eap_correlation_lab.py` |
| Exact public TLS handshake and authenticated RADIUS records | `patch_hostap_public_handshake.py` applied after correlation instrumentation |
| Exact MKA send, receive, and integrity-check records | `patch_hostap_mka_messages.py` applied to a fresh copy after public-handshake instrumentation |
| Ordered Ethernet admission, negotiated MACsec and malformed-frame probes | `l2_admission_lab.py`, `Dockerfile.l2-admission` |
| Physical MACsec transmission with protection enabled, disabled and blocked by filtering | `macsec_boundary_lab.py collect --label RUN --output FRESH_PATH` on the Linux worker |
| Mixed IPsec/MACsec cases with private-input key equality records | `manual_pairing_lab.py`, `pairing_boundary_policy_v7.py`, `pairing_headers_v6.py`, `Dockerfile.protocol-lab` |
| Management connection initiation and reply records | `management_session_lab.py --output /absolute/fresh/output` inside the isolated protocol-lab container |
| Active native IPsec keys, CHILD_SAs, and authentication records | `native_ipsec_correlation.py --spec PROFILE --output /absolute/fresh/output` on the worker |
| Device snapshot surrounded by key and authentication observations | `collect_native_cohort.py --spec PROFILE --output FRESH_PATH --configuration-id ID --run-id RUN` on the worker |
| Device packet-size boundaries, source errors and fragmentation | `packet_size_lab.py --spec PROFILE --output FRESH_PATH --source DEVICE --destination IP --ports DEVICE:INTERFACE ...` on the worker |
| Repeated routing, filtering and XFRM processing observations | `collect_processing.py --spec PROFILE --output FRESH_PATH` on the worker |
| Framed IPsec UDP replies | `ike_reply_rules.py --containers DEVICE ... --output FRESH_PATH`; add `--apply` to install the proposed rules |
| Objective IKEv2 exchange | `pq_exchange_v4.py`, `ike_headers.py` |
| Authentication-policy before/after trials | `auth_constraints_v5.py`, `auth_negative.py`, `auth_headers.py` |
| Device redundancy events | `redundancy_native.py` |
| Physical/KVM workstation trials | `boot_aw_vm.py`, `aw_tls_provision_v2.py`, `aw_client.py` |
| Device profile generation and diagrams | `make_native.py`, `draw_profiles.py` |
| Timestamped command records | `run_command.py --output-dir PATH LABEL COMMAND ...` |

The supplemental experiments retain their existing `--root` or `--output` arguments and their documented capability limits. The authentication before/after scripts target the historical Linux profile, while the native replay helper selects the current FRR/OVS profiles. Retained earlier Python revisions are still imported by current helpers. Superseded inventory collectors, intermediate topology generators, and fixed-date collection scripts were removed; Git revision `1a49bb76` preserves those historical versions.

The original recorded source remains unchanged under `data/construction/`. New observations record the hashes of the reorganized tools. Historical source hashes continue to refer to the original copies. The routing-inventory validator recognizes both the historical collector and its relocated version by pinned hashes. New inventory captures include `collector-source.py`; unknown or mismatched versions are rejected.

The correlation collector uses an isolated copy of the retained hostap 2.12 source with the existing MACsec fixes. Apply `patch_hostap_correlation.py` to a fresh source copy and record its manifest. Build the `hostapd` and `wpa_supplicant` targets using the retained OpenSSL 3.5.5 environment. The collector expects those binaries under `ROOT/hostap-v2/`. Run the collector inside a separate privileged container with its own network namespace. It creates fresh experimental credentials, records public logs and certificates, and removes its private credential directory when each case finishes. The v3.1 campaign records the exact build commands, image identity, sources, and results.

Use `--hostap-dir` to select another instrumented source tree and `--label` to give each capture a fresh name. The current collector also records complete public MKA frames. It stops protocol daemons before packet observers so that their final messages remain observable. The `eap-mka-public-v1` MCP parser connects those packets to the instrumented process records. Build manifests and source hashes must accompany the capture because the successful integrity checks depend on the instrumented implementation.

The manual pairing collector exercises six IPsec/MACsec combinations with integrated or standalone encapsulation. Run `manual_pairing_lab.py --output /absolute/fresh/output --pairings` inside the isolated protocol-lab container. Keep `pairing_boundary_policy_v7.py` and `pairing_headers_v6.py` beside the collector. Build the container with `Dockerfile.protocol-lab`, use its own network namespace, and record the resulting image identity. The collector creates and removes its experimental namespaces. Every run needs a fresh output directory.

The collector records permitted traffic, prohibited Red-to-Gray probes, inner-layer loss, and restored traffic. Successful MACsec and ESP installations also produce public key references and direct private-input equality records. Secret key values stay in memory and are redacted from command records. Before and after observations retain separate installation identities, including when restored ESP state reuses an SPI with a different key. The MCP `mixed-protocol-v1` parser checks those records and prepares the corresponding execution data.

`ipsec_framing_lab.py` tests the canonical bytecode in a fresh pair of namespaces. Run it in the privileged isolated lab container with `--bytecode PATH --output FRESH_PATH`. It records exact probe bytes and kernel accept/drop counters. Use `--options` with `ipsec-udp-framing-options-bytecode.txt` to include valid IPv4 options and a malformed payload with options. The original bytecode file retains its 20-byte-header restriction for reproducing earlier captures.

`admin_tls_lifecycle_lab.py --output FRESH_PATH` creates isolated management endpoints, per-user accounts and fresh certificates. It records TLS authentication, channel-bound operations, permission denials, connection closure and application revocation. Run it in an expendable container because it creates local Unix users. Private files are removed after collection.

For the mixed IPsec case, `manual_pairing_lab.py --output FRESH_PATH --pairing-choice ipsec-ipsec --allow-ike` installs and tests same-level peer IKE allowances. Keep `pairing_ike_control.py` and `ipsec-udp-framing-bytecode.txt` beside the collector. The actual positive IKE-shaped packet and malformed negative packet are recorded. The experiment still uses manually provisioned SAs and makes no IKE authentication claim.

`native_component_audit.py --spec PROFILE --output FRESH_PATH` reads public component versions, account/service/DNS inventories, clock status and credential-file access metadata. It uses the native `/etc/swanctl` credential location and supports Debian and Alpine package inventories. Private-key contents are excluded. Every failed command remains an unavailable observation.

`key_interface_audit.py --device INNER --device OUTER --output FRESH_PATH` records the actual strongSwan processes, executable and mapped-module hashes, server-loaded plugins, public key/certificate fingerprints, mounts, account identities, listeners and security profiles. Run it on the native Docker worker with permission to inspect the selected containers. Private key files are read inside the container only to derive public fingerprints. The exported capture contains no private key bytes or password hashes. Host Docker and SSH controls are recorded separately. The `key-interface-audit-v1` MCP adapter preserves failed commands and exposes the observations without claiming complete key confinement.

`mixed_packet_size_lab.py --output FRESH_PATH` measures a ten-device MACsec–L2TPv3–IPsec path before and after packet-length guards. Keep the manual pairing collector and its two helpers beside the script. Run it in a fresh privileged protocol-lab container with `ethtool` installed and the host module directory mounted read-only. It tests eleven sizes in both directions with DF set and clear. Captures include full public frames, MTUs, offload settings, filter counters and the unchanged useful-traffic probes. The experiment removes its namespaces when finished. Its manually installed keys establish no IKE or MKA authentication claim.

## Physical MACsec transmission

`macsec_boundary_lab.py` creates three temporary namespaces: a source host, a router with a MACsec interface, and its peer. The source sends the same UDP payload through the router in three cases. The first case enables protection. The second disables protection and allows the resulting plaintext frame. The third blocks that plaintext at the physical egress filter. Add `--integrity-only` to insert a fourth observation between the first two cases: protection stays on while encryption is disabled. The resulting MACsec frames carry readable payloads and can still pass the peer’s integrity validation. Captures retain the source arrival, logical transmit, physical transmit, physical receive and application delivery separately. Before/after observations include parent and peer interface indices, routes, forwarding state, MACsec settings, public association identifiers, ordered nft programs and counters. Both JSON and textual nft output are collected because some nft versions omit the chain device from JSON.

Keep `l2_admission_lab.py` beside the collector. Run the collector as root on an authorized worker with `ip`, `nft`, Python and kernel MACsec support. Each run needs a fresh output directory and a unique label of up to six lowercase letters or digits. The collector removes only the namespaces it created. Test key bytes stay in memory and are redacted from command records. The manually provisioned associations establish no authentication claim. Register the selected public capture with parser `macsec-boundary-v1` to query its observations and export the `macsec_boundary` view.

## Framed IPsec UDP replies

`ike_reply_rules.py` adds a source-port counterpart to each existing peer-bound UDP 500/4500 allowance that uses the 62-instruction framing guard. It preserves the existing interface, IPsec-policy and header checks, and inserts the counterpart immediately after the original rule. Earlier deny rules keep their order. Repeating the operation adds no duplicate rules. The helper retains the original, proposed and observed rules, commands and hashes. A failed application restores the original rules on devices changed by that invocation.

`ipsec_framing_lab.py --source-port-framing --options --bytecode FILE --output FRESH_PATH` exercises a supplied source-port guard in temporary Linux namespaces. The test sends valid IKE and UDP-ESP packets, malformed packets and IPv4-options cases. After applying a repair, collect a fresh native snapshot and processing supplement, then register both with the evidence MCP server.

`xfrm_forward_policy_lab.py --output FRESH_PATH` creates three temporary namespaces and tests seven XFRM forwarding-policy configurations. The cases distinguish inbound from forwarding policies, required from optional templates, matching from nonmatching selectors, and higher from lower policy priorities. Each case records an IPv4 ICMP probe, installed policies and XFRM counters. The experiment uses empty SA databases and establishes no encryption or IKE authentication claim. The namespaces are removed when the experiment ends. Register the successful capture with the MCP saved-experiment parser `xfrm-forward-policy-v1` to query its cases and raw records.

`red_service_policy.py --spec PROFILE --output FRESH_PATH` prepares a narrow application policy for an existing native profile. Repeat `--spec` to cover several profiles. The default run validates the proposed rules without installing them. Add `--apply` to restrict Inner forwarding to exact paired Red hosts, TCP port 8080 and ICMP echo request/reply types. Existing IPsec-policy and interface guards remain, as do local IKE and Outer/Gray rules. The helper starts a small HTTP endpoint in each Red host, waits for its listener, and checks paired HTTP/ping, wrong-port and cross-level traffic. It records rules, commands, policy declarations and probes. An error restores the original filters; controlled test servers already started remain available for a retry. Compare rules in their order within each chain because `iptables-save` groups chains when exporting them. Register successful captures with MCP parser `red-service-policy-v1`, and collect a fresh native snapshot and processing supplement after the change.

`collect_native_cohort.py` records key and authentication observations before and after collecting a native snapshot and its processing supplement. The four stages remain separate under one fresh output directory, with their commands, times, source hashes and failures in `sequence.json`. Register `snapshot/` with `processing/` in MCP, and register `keys-before/` and `keys-after/` as separate `native-ipsec-correlation-v1` experiments. Compare their installed-association identifiers and key references before combining the observations in a proof. Rekeying can change those values during collection and require a fresh attempt. Matching repeated observations establishes the recorded consistency check; the reads occur sequentially across devices.

For packet-size evidence from the same collection interval, add `--sizing-source DEVICE --sizing-destination ADDRESS --sizing-ports DEVICE:INTERFACE ...`. The collector runs the five cases from `packet_size_lab.py` after the processing reads and before the final key observations. Register the resulting `sizing/` directory as a `native-packet-sizing-v1` experiment. Match the captured ESP identifiers against the installed associations as well as comparing the before/after key records. The collector preserves normal rekeying settings and records any changed associations for a later retry.

## Guest clock-source and certificate-use experiment

`clock_vm_lab.py` creates four isolated KVM guests for Inner and Outer clock-use checks. Run its `bootstrap`, `configure` and `observe` phases on a dedicated Linux worker with KVM, QEMU, `genisoimage` and Python. `clock_ntp_source.py` must be next to the launcher on that worker. The launcher verifies its pinned Ubuntu image, creates separate Red and Gray-management time-service attachments, and retains public observations for every phase. Private credentials and VM disks stay under the worker's `private/` directory.

The observation phase changes only guest clocks. It records certificate rejection with an incorrect clock, actual synchronization with the configured source, and successful authentication using the same strongSwan process. `--label` gives retries separate capture directories. Each phase preserves failures and refuses to overwrite its previous capture. The experiment uses names beginning with `tc31`, guest names beginning with `TC_`, and localhost SSH ports 22610–22613. It does not modify the worker clock or existing MSC deployments.

The evidence MCP server reads the public capture through `guest-clock-use-v1` and exports the `clock_synchronization` view. The source services themselves share the worker clock. Their synchronization requirements, UTC accuracy and complete MSC conformance remain separate obligations.

## Separate token storage and VPN authentication

`key_token_lab.py` creates two VPN gateways and two software-token containers on a dedicated Docker worker. Build `Dockerfile.key-token-lab` as `tdn-key-token:v31-002`, place `token_operations.py` next to the launcher, and run the `bootstrap`, `configure` and `observe` phases with the same `--root` directory. Each phase writes to a fresh directory under `public/`; use `--label` to distinguish retries. The private directory holds the laboratory CA, token files and PINs and must remain on the worker.

The gateways mount token RPC sockets and public credentials. Their signing keys are generated inside the separate token stores. The observation phase checks public-key and certificate correspondence, token attributes, signing, private-value reads, attribute changes, key copying, key wrapping, authentication and protected traffic. The helper uses the PKCS11 function list for copying because the installed Python binding omits that operation. It initializes a separate session and preserves the actual token return code.

The MCP adapter `pkcs11-token-boundary-v1` reads the public phase directories and exports `token_key_boundary`. The experiment uses container names beginning with `KT31_` and the network `tdn-v31-token-001`. It provides evidence about the gateway's available interfaces. Backend-software and host correctness remain explicit assumptions; the software token carries no hardware-certification claim.

`token_extra_lab.py --root ROOT --label LABEL` records additional API behavior on those existing gateways. Place `token_extra_operations.py` next to the launcher and install `nm` on the worker. The helper checks key-digest, operation-state, derivation and decryption calls, records the function-list versions and callable entries, and verifies a fresh signature against the installed certificate. Raw digest bytes stay inside the helper. The worker copies the public client library only to inspect its exported symbols. Package the original capture under `base/` and the follow-up under `extra/` for the `pkcs11-token-extra-v1` adapter.

`token_interface_lab.py --root ROOT --label LABEL` checks the backend's actual interface version and a version 3.0 client call with a valid session and signing key. It uses `token_interface_binding.py` and `token_extra_operations.py` from the same directory. Package the preceding extra-API capture under `prior/` and the new capture under `binding/` for `pkcs11-token-binding-v1`.
