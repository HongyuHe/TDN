# Current evidence replay

The tested fresh-root native entry point is replay_v7.py. Its successful controller output is artifacts/snapshots/2026-10-24T014455Z/native-fresh-replay-v7. NATIVE-FRESH-REPLAY-v7.json binds that controller, its exact staged sources and twelve worker export manifests under native-fresh-replay-v7-worker. The new NQ deployment retains native FRR/OVS and actual FreeBSD Inner guests. All thirteen selected jobs and 63 finite controls pass. The earlier ten-job v6 replay remains preserved.

The coverage register contains 59 representative cases. The entry point covers its named native profile and selected alternatives. A single configurable replay of every representative case remains unfinished.

## Worker and inputs

Use an authorized Linux worker with SSH as hy, passwordless sudo -n, Docker, KVM, QEMU, qemu-img, Python 3, OpenSSH, genisoimage, curl, xz, iproute2 and iptables. The tested worker is pc22 with Ubuntu 24.04. Its kernel supplies XFRM, network namespaces, bridges, tun/tap, Open vSwitch and KVM. Each guest uses two virtual CPUs and 2 GiB RAM. Allow disk space for the base image, two guest overlays, native images and guest source builds.

Host root, Docker, namespace administration, tap creation, QEMU and private provisioning are explicit trusted laboratory controls. The tools do not establish confinement from those controls.

The exact generic images used by the successful replay are retained in artifacts/snapshots/2026-10-24T014455Z/replay-runtime-images-v3/images.tar.gz. The archive excludes running-container writable layers and credential bind mounts. Verify its manifest, transfer it to the selected worker and load it:

~~~sh
gzip -dc images.tar.gz | sudo -n docker load
sudo -n docker image inspect twinet-msc:construction-v2 twinet-msc-router:construction-v2 twinet-msc-switch:construction-v2 --format '{{.RepoTags}} {{.Id}}'
~~~

| Tag | Actual content ID |
| --- | --- |
| twinet-msc:construction-v2 | sha256:5eeeb318938d7796b36e10b5914a2b60d6e694667c99fdbfca3f6997207d6cbd |
| twinet-msc-router:construction-v2 | sha256:ee85d675b0bc76e4474ca3ea1ccd9a1fc7cb8a63b16882782d552e39bf28475d |
| twinet-msc-switch:construction-v2 | sha256:c0785b89babe2fc8c3a09192005b1ff56b025dcc2332820c4709fa855829dbd5 |

The runtime-image collector records an auxiliary failure because pc22 lacked the Go tool at that collection time. A later isolated official Go 1.25.0 toolchain is preserved for the audit client build. The image archive completed and has its own hash. The local Go tool captured the executable's embedded metadata in evidence/runtime/twinet-build-info.txt.

The pinned executable is evidence/runtime/twinet-linux under the current construction run. Its SHA-256 is 555098b40130410a5827e2010316a3bc00e77c90eb2cfba1f4a150a32a9ce5dd. The controller verifies that hash. Embedded metadata records Go 1.25.0 and module dependencies, but supplies no VCS revision.

The authorized implementation repository is https://github.com/HongyuHe/Twinet.git, branch tdn. Current source and image build files were collected at revision 01f8f4d632b779dbe78ec67992f5071dc596b00e. The 20 image build files and hashes are under references/twinet-image-source/. Those current sources and the repository's dated ImageLock are separate from the exact cached IDs above. A source rebuild must receive its own identity and observations.

The guest bootstrap downloads the official FreeBSD 14.4 release cloud image or verifies an explicitly supplied cache. Its compressed SHA-256 is d957fe56fb596280428328e78e9e4feae00dd361701caa79a061f9bd289eff67. Guest strongSwan 6.0.3 source is verified against SHA-256 288f2111f5c9f6ec85fc08fa835bf39232f5c4044969bb4de7b4335163b1efa9. The guest repository supplies Botan. Actual package version and plugin linkage are recorded. Future package changes must remain visible.

## Fresh native execution

Create a public JSON configuration with an unused root, names, MAC prefix and ports:

~~~json
{
  "host": "hy@pc22.cloudlab.umass.edu",
  "run_root": "/users/hy/tdn-replay-review-20261024",
  "device_prefix": "RP",
  "bridge_prefix": "rp3",
  "profile_name": "native-replay-review",
  "ssh_port_base": 22622,
  "socket_port": 49702,
  "mac_prefix": "52:54:76:19",
  "image_cache": null
}
~~~

The controller accepts roots below /users/hy/ with letters, digits, underscores and hyphens. Device prefixes use two to four uppercase letters. Bridge prefixes contain three lowercase letters or digits and begin with a letter. The controller refuses existing roots, device prefixes and occupied control ports. It preserves earlier deployments.

Run from the Evidence workspace root:

~~~sh
python3 scripts/construction/evidence/replay_v7.py --config review-config.json --output artifacts/snapshots/2026-10-24T014455Z/replay-review --execute
~~~

The controller stages exact transformed source bytes, the public profile, the public configuration and the pinned executable. Staged hashes remain in its local output. Private SSH and IKE credentials are generated only on the worker.

Its thirteen jobs perform guest bootstrap, native deployment, FreeBSD/Botan builds, guest integration, protected traffic and SA-loss checks, IPv4 and IPv6 DNS hardening, CBC negotiation and GCM restoration, certificate lifecycle events, short automatic reauthentication, independent Red clock correction, abrupt audit/startup power events and effective PF interface-flag collection.

The final integration explicitly loads ipsec.ko, persists its setting and configures IP forwarding before charon starts. Earlier filename, SSH staging and missing-module failures remain preserved. The successful result does not depend on an undocumented prior module load.

Public worker results are under the configured run_root/exports. Collect only that directory. Never collect private. Hash-check every leaf manifest and bind the copied sources and configuration to the handoff response.

## Persistent guest startup and power

The separately tested freebsd_persistent_power_v3.py accepts the same remote configuration. It persists module, interface, route, forwarding and charon startup settings. Restart commands include both data NICs originally hot-plugged into each QEMU process. All eight traffic and marked-file preservation checks passed.

~~~sh
sudo -n python3 RUN_ROOT/scripts/freebsd_persistent_power_v3.py --config RUN_ROOT/scripts/replay-config.json --output RUN_ROOT/exports/freebsd-persistent-power-review
~~~

Stage the preserved helper before running it. The output directory must be new. The helper has not yet been incorporated as an eleventh replay_v6.py job. The bundle preserves the rc.d source and exact final restart commands. Only the two owned guests are power-cycled. Shared worker hosts remain running.

## Repaired family fixtures

Stage family_execution_v9.py, gateway_header_policy_v5.py and family_forward_policy_v3.py together. Run:

~~~sh
sudo -n python3 family_execution_v9.py --output RUN_ROOT/exports/families-review --families all
~~~

The generator uses isolated tcv3f9- namespaces and cleans its fixtures after collection. Do not run two instances with that same prefix concurrently. A creation collision must not be resolved by deleting another deployment's namespaces.

Every Inner and Outer has IPv4 and IPv6 FORWARD default DROP and explicit required-family IPsec-policy permits. Every gateway has literal immediate IPv6 Next Header checks at nftables prerouting and output priority -450, before defragmentation at -400. The earlier raw check remains present. Crafted packets with unassigned claimed source addresses expose plaintext wrong-family egress before repair and blocking afterward. All eight final cases pass all 80 expected checks. Families v4 through v7 remain preserved as before-evidence. The backend is supplemental Linux namespaces with static XFRM.

## Protocol runtime and failures

The PSK MACsec repair has complete official-release source differences, active config and a fresh build-directory script in hostap-delay-reproduction-v5. Its reproduce.sh verifies the official wpa_supplicant 2.12 archive, applies the complete patch and rebuilds. The zero-window Linux RX-SA API interpretation is in evidence/mka-delay-api-interpretation-v3.md.

The separate EAP delay build combines the repaired KAY timer/history and RX-SA callback with the existing EAP-derived 256-bit CAK and objective TLS changes. hostap-pq-delay-build-v4 preserves full hostapd and wpa_supplicant differences from official 2.12 archives, source hashes, active configs, binary hashes and linkage. The first build stopped on hostapd's nonzero version-command status; the harness records that result without treating it as a compilation failure. The first execution directory lacked its Lab module; that startup failure is retained.

Objective EAP requires OpenSSL 3.5.5 with ML-DSA-87 and MLKEM1024. The host OpenSSL 3.0 execution failed before handshake at certificate-key generation. The existing tdn-hostap-pq:20261024-v3 image supplies the correct runtime. The normal tested invocation is:

~~~sh
sudo -n docker run --rm --privileged --network host --pid host --name tcv3-eap-delay-v18 -v RUN_ROOT:RUN_ROOT -v /var/run/netns:/var/run/netns:shared tdn-hostap-pq:20261024-v3 python3 RUN_ROOT/scripts/eap_tls_v18.py --root RUN_ROOT
~~~

Stage v3/eap_tls_v18.py and v3/eap_delay_lab_v18.py together as RUN_ROOT/scripts/eap_tls_v18.py and eap_delay_lab_v18.py. The final binaries are under RUN_ROOT/hostap-pq-delay-auth. First preserve and build the full official-source patches and configs in hostap-pq-delay-build-v4, then apply hostap_auth_lowest_pn_v5.py. The final helper clones the prior source, wires the missing authenticator receive-PN setter and rebuilds hostapd inside the recorded image. Both final binary paths and hashes appear in the v18 collection. The container uses host privileges to create only the named supplemental fixtures. Both arrangements and both traffic directions reject three-second delayed data, accept the 100 ms control and restore useful traffic. All 16 controls pass. The v17 reverse failure remains preserved. Complete IEEE normative conformance and nonzero replay-window or replacement-SA behavior remain separate.

## Other deployments and remaining replay work

The Linux Outer extension uses linux_outer_bootstrap_v3.py, the recorded integration repairs and independent_gray_clocks_v3.py. Only fresh NC replay Outers are replaced. Native FRR/OVS peers and actual FreeBSD Inners remain active. Its official Debian image checksum, default-DROP control-path failures, final explicit laboratory SSH permits, protected traffic and two independent Gray clock corrections are public. A clean combined entry point incorporating every Linux Outer repair remains pending.

The four-worker arrangement was constructed and tested across clnode159 for Inner/Red roles, clnode163 for Outer roles, clnode176 for Outer Firewall/Black roles and pc08 for Gray Firewall roles. Public VXLAN underlay, namespace/hardware bindings, trust bindings and positive protected IPsec observations are preserved. That arrangement has not yet received a second complete fresh-root replay. It must not inherit the single-worker replay result.

The optional AW, administration and management cases retain exact public helpers and response manifests. AW v5 explicitly fsyncs the marked file and its parent directory before abrupt guest power-off. The marker and authenticated management survive restart, and the unused VM is left powered off. Earlier returned write/sync calls and lost-marker attempts remain visible. A complete configurable fresh deployment replay for those optional cases remains pending.

The active WORK_QUEUE.md and all76 assessment separate completed finite observations, confirmed counterexamples, pending implementation and external records. The 59 representative cases do not establish whole requirement compliance.

## Data fragments, PMTU and conventional DNS

The data_fragments_v5.py helper accepts --output RUN_ROOT/exports. Stage family_execution_v8.py, gateway_header_policy_v4.py and gateway_header_policy_v5.py beside it. The helper uses only new tcv3df5- namespaces, records full header metadata and public payload digests, and removes its fixtures. C-FRAGMENT-001.json binds the tested reassembly, overlap rejection and pre-defrag repair.

The ipv6_pmtu_v4.py helper accepts --output RUN_ROOT/exports. Stage family_execution_v9.py and both header-policy modules beside it. Its tcv3pm4- fixture records actual ICMPv6 PTB, socket and route PMTU changes, and protected smaller-payload delivery. The original observer timeout is retained.

The native_dns_hardening_v11.py helper accepts --root RUN_ROOT --device-prefix PREFIX --guest-port-base PORT. It expects the staged native-os-diversity-v3.json profile and existing private guest management key below that root. The tested ND run uses port 22222. The helper adds conventional IPv6 TCP/UDP53 rejection and enables IPv6 loopback only for meaningful counter-bound probes. FreeBSD uses its installed drill tool; Python is not a guest prerequisite. Effective PF state, current state table, local addresses, libc and service inventory are retained. Musl resolver behavior is not inferred from nsswitch configuration alone. The thirteen-job replay_v7.py controller incorporates that extension and passes its fresh NQ collection.

The family-host-binding-v3 supplement links every immutable v9 leaf to its executed controller host argument and exact source hashes. Actual same-run fragment collections retain contemporaneous kernel records. Fresh hardware UUID, boot ID, uptime and Ubuntu build observations are separately labelled supplementary. The leaves did not directly collect a boot ID. Upstream v6.8 explains the implementation family and hook ordering; byte identity with Ubuntu distribution sources is not asserted.


## Actual audit records and corrected startup persistence

The final freebsd_audit_power_v8.py helper accepts the public replay configuration and a new output directory:

~~~sh
sudo -n python3 RUN_ROOT/scripts/freebsd_audit_power_v8.py --config RUN_ROOT/scripts/replay-config.json --output RUN_ROOT/exports/freebsd-audit-power-review
~~~

The helper writes an actual syslogd authentication-facility marker. It fsyncs the audit file, startup files and their parent directories before stopping only the positively identified owned QEMU guest. Both actual FreeBSD Inners pass all eight preservation, useful-traffic and power-loss controls. SSH and charon start automatically. The driver then explicitly terminates stale recorded IKE connections and creates a fresh protected CHILD. Automatic SA recovery is a separate task.

The earlier unclean UFS recovery preserved auth.log but recovered rc.conf and the gateway startup file as zero-length files. A long UART transfer did not restore their bytes. The successful repair transferred the preserved public files with SCP and explicitly fsynced each file and parent directory. A startup-service timeout and a stale-IKE initiation timeout remain preserved. Replaying only a prior manually edited container would omit those fixes.

The fresh replay_v7.py controller stages the same public source transformations as v6 and adds the audit-power helper, native_dns_hardening_v11.py and freebsd_pf_skip_v13.py. Its configuration is profiles/replay-native-freebsd-v7.json. The NQ sequence completed all thirteen jobs and 63 finite controls. The public validation supplement checks every staged source and all thirteen controller/worker manifests. Existing roots and device names are refused.

## Earlier pairing collector and the cover-record experiment

The preserved earlier pairing_execution_v5.py helper and pairing_headers_v5.py run together with --output RUN_ROOT/exports/pairings-review --pairings. All six distinct pairings pass 24 controls. The supplemental backend captures full bridge/link/VLAN/FDB, namespace/peer NSIDs, route rules/tables, ordered filters, TC, MACsec and L2TP state. Packet capture emits explicit fields only. A prior tcpdump version dumped unrecognized MACsec bodies; its public records remove those body lines with a separately preserved sanitizer.

The six v5 captures contain no noninitial IPv4 fragments. The later pairing_headers_v6.py validates IHL/total length and refuses transport decoding on noninitial fragments. Its L2TP parser selects UDP, no cookie and the four-byte default L2-specific sublayer. Other cookies/sublayers and VLAN parsing remain unsupported. The selected tunnel/session state must corroborate that interpretation.

Stage macsec_cover_lab_v4.py, macsec_cover_endpoint_v4.py, pairing_execution_v6.py and pairing_headers_v6.py together. Run:

~~~sh
sudo -n python3 RUN_ROOT/scripts/macsec_cover_lab_v4.py --output RUN_ROOT/exports
~~~

The output name outer-MACsec-cover-v4 and namespace prefix tcv3tf4- must be unused. The helper creates only owned supplemental namespaces and cleans them afterward. Actual Inner IPsec traffic passes through a custom TUN cover-record shim before Outer MACsec. The bridge firewall accepts only MACsec frames. The selected records are 512 bytes every configured 20 ms slot, with a 64 packet FIFO and 488 byte payload limit. Oversized or newly overflowing records are dropped. Idle slots carry padding. A late scheduler skips missed slots. The experiment records actual software and wire timing, useful recovery and both-layer failure/restoration. Its v3 ENETDOWN failure remains visible. The v4 repair preserves its TUN through the deliberate link-down event.

The mechanism demonstrates bounded size/rate masking with explicit clock, scheduling, queue and active-link assumptions. It does not establish hard real-time enforcement, full TRANSEC security or IEEE/RFC conformance. The source interpretation and official references are included in MACSEC-TRANSEC-MECHANISM-v4.json.

## Preserved public FreeBSD runtime

The original public FreeBSD 14.4 release image is retained locally with SHA-256 d957fe56fb596280428328e78e9e4feae00dd361701caa79a061f9bd289eff67. Its size is 659880440 bytes. The public runtime archive contains installed strongSwan 6.0.3/Botan 3.13 binaries and libraries, the verified strongSwan source archive and configure log/status. Its SHA-256 is 613d11e3f7bc54239809bacf4ef65dd3bb14f77e78f94cf1ee16eb754354ee93. Its size is 11560960 bytes. FREEBSD-PUBLIC-RUNTIME-v3.json lists the exact paths and full archive member inventory.

Private guest overlays, credential files and seed images are excluded. The runtime archive relies on the matching FreeBSD base-system libraries; full OS patch/package reproduction remains separate. KVM, root, Docker and guest provisioning remain trusted laboratory prerequisites.

## Repaired six-mechanism boundaries

Stage pairing_execution_v7.py, pairing_headers_v6.py and pairing_boundary_policy_v7.py in the same directory. Run on the authorized worker with a fresh export directory:

~~~sh
sudo -n python3 RUN_ROOT/scripts/pairing_execution_v7.py --output RUN_ROOT/exports/pairings-review --pairings
~~~

The helper owns only the tcv3p7- namespace prefix. It refuses an existing case output and cleans its own fixtures. Do not run another instance with the same prefix concurrently. The replay accepts the export path; its state does not depend on an old run root.

Every nonhost component has IPv4 and IPv6 INPUT, OUTPUT and FORWARD default DROP. Exact Red subnet pairs cross the Inner protected interface. IPsec forwarding also requires the recorded reqid policy. MACsec bridges admit only the known source MACsec frames in the required port direction. Integrated and standalone L2TP endpoints have exact address, port and direction bindings. The static SA fixture needs no IKE or EAPOL exception. Arbitrary Red ICMP or UDP500 receives no protocol-only exception.

The pre-repair probe demonstrates cleartext legitimate-source HA-to-peer-Gray emission on IA and OA in both IPsec-Inner cases. The repaired capture records no such Inner egress. All six cases pass two Gray-destination denials, bidirectional useful traffic, Inner-loss denial and restoration. The 36 controls, complete effective policies and before/after public headers are bound by C-PAIRING-FILTER-006.json. Pairings v5 remains unchanged.

The field parser validates IPv4 IHL and total length before decoding upper headers. It decodes ESP, UDP, ICMP and L2TP payload headers only for fragment offset zero. Earlier published v5 captures contain no affected noninitial fragments. L2TP parsing covers the selected UDP/default four-byte L2 sublayer and no-cookie configuration. VLAN and other cookie layouts remain unsupported.

## Protected audit offload

AUDIT-PROTECTED-OFFLOAD-v8.json binds the actual NC FreeBSD source, distinct pc08 collector, public certificates, exact FreeBSD executable and all helper versions. The collector uses TLS 1.3 mutual authentication and an exact client-CN/device map. It fsyncs the journal and directory before acknowledgement. The source acknowledges only the returned next offset and matching hash, then fsyncs its cursor file, rename and parent directory.

The first invocation transferred only 65,536 bytes. The generated authentication event lay later in the source. The bounded drain now reaches the exact recorded EOF, and the collector retains the event across a second restart. The initial prefix scope and failed drain readback attempts remain explicit. Thirteen finite controls pass, including bad certificate/device rejection, conflict rejection, duplicate retry, capacity backpressure, tested unprivileged key-read denial and useful native traffic.

The source client is built from audit_export_client_v3.go with official Go 1.25.0:

~~~sh
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 GOCACHE=RUN_ROOT/toolchains/go-cache RUN_ROOT/toolchains/go/bin/go build -trimpath -o RUN_ROOT/scripts/audit-export-client-v3 RUN_ROOT/scripts/audit_export_client_v3.go
~~~

The official Linux amd64 toolchain archive has SHA-256 2852af0cb20a13139b3448992e69b868e50ed0f8a1e5940ee1de9e19a123b613. Its isolated archive and metadata are under evidence/runtime/go/go-public-toolchain-v3. The initial extraction guard rejected the legitimate top-level go directory before extraction; the corrected guard permits that directory and safe descendants.

Provision fresh private CA/server/client credentials on the selected owned hosts. Match the collector certificate to its actual URL and the allowed client CN to its device identifier. Never replay published private credential bytes. Start audit_collector_v3.py with --root pointing to a private directory and --ca, --cert and --key pointing to those new credentials. The complete loaded arguments are preserved in audit-collector-readback-v7. Invoke the exact retained FreeBSD client with the URL, log path, cursor and credential paths. Private audit bodies remain in the protected collector store.

The current experiment uses an explicit finite batch and trusted provisioning. Automatic exporter startup, source-log rotation, retention policy and every crash interleaving remain separate actionable tasks. The configured 128-byte capacity test exercises application backpressure. It does not claim physical disk exhaustion. Only that identified test collector is stopped; the primary collector remains running.

## Final repaired hostap runtime restoration

Load the saved protocol image archive and confirm the tdn-hostap-pq:20261024-v3 content ID is sha256:b6bb2db742723c974b511b82c98a4c17238efd6cf5a5b84be37b7f44392a19d5. The base image alone does not include every final bind-mounted callback and timer repair.

FINAL-HOSTAP-RUNTIME-v4.json binds the public hostap-final-public-binaries.tar.gz archive. Its SHA-256 is 6a898a01aa90a35f747aeaf327c477097666d6e8d700550a568e9e5d47e2d00a. The archive preserves six exact binaries and six active build configurations. Verify its manifest and archive hash before extraction. Inspect its retained member list, then restore it below the selected isolated run root:

~~~sh
mkdir -p RUN_ROOT
tar -xzf hostap-final-public-binaries.tar.gz -C RUN_ROOT
~~~

The final EAP paths are RUN_ROOT/hostap-pq-delay-auth/hostapd-2.12/hostapd/hostapd and RUN_ROOT/hostap-pq-delay-auth/wpa_supplicant-2.12/wpa_supplicant/wpa_supplicant. Their SHA-256 values are 23a5f3dfbaee5c2b4b54f16229d8274c3de7a760d30613a95db566a1acd78b1d and aa5af96ee16645430271770a942ceefd2f86d62efbb25f2e76fe3595681d44a6. The EAP v18 helper must use those restored paths with the matching OpenSSL 3.5.5 image. Fresh private test credentials are generated inside the owned worker run. Public binary restoration does not restore old private credentials.

The official hostapd and wpa_supplicant 2.12 source archives, complete final patches and active configurations remain available for rebuilding. IEEE-KDF-REVIEW-v4.json binds exact unchanged derivation and OpenSSL CMAC source bytes to both final runtimes and all 12 matching published Annex G vectors. The result supports the visible derivation clauses with the indexed-publication provenance caveat. It does not establish every standard clause or independent implementation interoperability.

## Bridged opaque Ethernet and protected VLAN tags

Stage bridged_macsec_v8.py, opaque_ethernet_v8.py, pairing_headers_v7.py, pairing_execution_v7.py, pairing_headers_v6.py and pairing_boundary_policy_v7.py together:

~~~sh
sudo -n python3 RUN_ROOT/scripts/bridged_macsec_v8.py --output RUN_ROOT/exports/bridged-review
~~~

The helper owns only tcv3e8- namespaces and cleans its fixtures. A new output directory is required. It constructs a complete bridged Inner MACsec path through integrated L2TPv3 and actual Outer IPsec. Final Red and Inner data ports have no IPv4 addresses or main-table routes; Inner IP forwarding is disabled. Opaque EtherType 0x88b5 frames carry zero, one or two VLAN tags inside Inner protection. All 18 bidirectional useful, both-layer loss and restoration controls match exact payload digests and recovered tag stacks. Two initial routed diagnostics are explicitly separate.

The v7 public-header parser supports up to two 802.1Q/802.1ad tags and reconstructs offloaded tags from Linux PACKET_AUXDATA. It retains the v6 IPv4 length and fragment guards. Original payload and ciphertext bytes are never serialized. Deeper tag stacks and other L2TP cookies or sublayers remain unsupported. C-MACSEC-ETHERNET-007.json binds all effective bridge, carrier, route/filter, MACsec, encapsulation and header observations.
