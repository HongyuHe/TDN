# Current evidence tools

The October 24 continuation uses [REPLAY.md](REPLAY.md) for tested commands, exact runtime identities, current Twinet source revision, prerequisites and known failures. The working run is artifacts/construction/2026-10-24T014455Z. The 59 representative cases remain distinct from full requirement compliance.

| Purpose | Current tested entry point and scope |
| --- | --- |
| Fresh native FRR/OVS and actual FreeBSD Inners | replay_v6.py with a public host/run-root configuration; ten jobs pass |
| Persistent guest startup and bounded power events | freebsd_persistent_power_v3.py; ipsec.ko, routes, interfaces and charon startup are explicit |
| Repaired eight address-family combinations | family_execution_v8.py plus gateway_header_policy_v4.py and family_forward_policy_v3.py; supplemental static XFRM, all 80 expected checks pass |
| Objective IKE exchange and offered proposals | pq_exchange_v6.py and ike_headers_v5.py; actual SA transforms and fragment headers |
| Repaired PSK MKA delay behavior | mka_delay_v8.py and hostap-delay-reproduction-v5 bundle; zero-window API interpretation retained |
| Objective EAP and current delay attempt | v3/eap_tls_v17.py and v3/eap_delay_lab_v17.py; correct OpenSSL container runtime required; reverse delay gap remains |
| Independent Gray clocks | Linux Outer VM integration v6 plus independent_gray_clocks_v3.py; actual separate Linux kernels |
| AW power and durable file checks | aw_power_event_v5.py; prior marker-loss failures retained; unused guest ends powered off |

The exact public runtime/image sources are recorded at Twinet revision 01f8f4d632b779dbe78ec67992f5071dc596b00e. Current source files and the dated repository ImageLock do not assert equality with cached runtime images. REPLAY.md records actual image IDs and the saved image archive. Host root, Docker, KVM and namespace operations are trusted laboratory controls. Private credentials stay on the authorized workers.

The earlier instructions below are retained for historical experiments. They are not the current continuation's replay guide.

## Earlier entry points

# Evidence provision tools

The evidence tools and their helper modules live in this directory. Network specifications and device mappings live in `profiles/`. The Twinet Go implementation and image Dockerfiles remain in a separate Twinet checkout.

## Deploy and collect a native profile

Use the Twinet construction source described in the [recorded replay guide](../../../artifacts/construction/2026-10-17T205010Z/agents/evidence/outputs/REPLAY.md). That guide also records image versions, software prerequisites and the limits of each experiment. The commands below use the reorganized script paths.

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

Every collection needs a fresh snapshot name. Private deployment state goes under `LAB_ROOT/private`, and public observations go under `LAB_ROOT/exports`. The helper uses the local `profiles/` files for deployment and collection. `make_native.py` regenerates those native profile files from the supporting specifications in the same directory.

## Experiment entry points

| Purpose | Current entry points |
| --- | --- |
| Native snapshots and process inventory | `collect_native_v2.py`, `native_inventory.py` |
| IP families and IPsec/MACsec pairings | `matrix_lab.py` |
| GRE, MPLS and OSPF variants | `routing_variants_v6.py` |
| Management, placement and time-source variants | `utility_variants_v3.py` |
| CA arrangements and revocation services | `ca_variants_v2.py`, `revocation_services.py` |
| PSK MKA and partial EAP-TLS experiments | `mka_psk_v4.py`, `eap_tls_v5.py`, `patch_hostap_offload.py` |
| Objective IKEv2 exchange | `pq_exchange_v4.py`, `ike_headers.py` |
| Authentication-policy before/after trials | `auth_constraints_v5.py`, `auth_negative.py`, `auth_headers.py` |
| Native redundancy events | `redundancy_native.py` |
| Physical/KVM workstation trials | `boot_aw_vm.py`, `aw_tls_provision_v2.py`, `aw_client.py` |
| Shared, four-level and redundant profile generation | `make_shared.py`, `inline_gray.py`, `make_four_levels.py`, `make_redundant_router.py`, `make_native.py` |
| Timestamped command records | `run_command.py --output-dir PATH LABEL COMMAND ...` |

The supplemental experiments retain their existing `--root` or `--output` arguments and their documented capability limits. The authentication before/after scripts target the historical Linux profile, while the native replay helper selects the current FRR/OVS profiles. Earlier Python revisions remain available beside the current entry points because some helpers import them and past experiments used them. The four fixed-date shell command sequences are grouped under `historical/` for reference.

The original recorded source remains unchanged under `artifacts/construction/`. New observations record the hashes of the reorganized tools. Historical source hashes continue to refer to the original copies.
