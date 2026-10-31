# Current evidence replay

The tested fresh-root native entry point is replay_v6.py. Its successful output is artifacts/snapshots/2026-10-24T014455Z/replay-native-freebsd-v6. NATIVE-FREEBSD-REPLAY-v3.json binds the controller, staged source and nine public remote export bundles. The run creates a new native FRR/OVS profile and actual FreeBSD Inner guests. It completed all ten selected jobs.

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

The runtime-image collector records an auxiliary failure because pc22 lacks the Go tool. The image archive completed and has its own hash. The local Go tool captured the executable's embedded metadata in evidence/runtime/twinet-build-info.txt.

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
python3 scripts/construction/evidence/replay_v6.py --config review-config.json --output artifacts/snapshots/2026-10-24T014455Z/replay-review --execute
~~~

The controller stages exact transformed source bytes, the public profile, the public configuration and the pinned executable. Staged hashes remain in its local output. Private SSH and IKE credentials are generated only on the worker.

Its ten jobs perform guest bootstrap, native deployment, FreeBSD/Botan builds, guest integration, protected traffic and SA-loss checks, DNS hardening, CBC negotiation and GCM restoration, certificate lifecycle events, short automatic reauthentication, and independent Red clock correction.

The final integration explicitly loads ipsec.ko, persists its setting and configures IP forwarding before charon starts. Earlier filename, SSH staging and missing-module failures remain preserved. The successful result does not depend on an undocumented prior module load.

Public worker results are under the configured run_root/exports. Collect only that directory. Never collect private. Hash-check every leaf manifest and bind the copied sources and configuration to the handoff response.

## Persistent guest startup and power

The separately tested freebsd_persistent_power_v3.py accepts the same remote configuration. It persists module, interface, route, forwarding and charon startup settings. Restart commands include both data NICs originally hot-plugged into each QEMU process. All eight traffic and marked-file preservation checks passed.

~~~sh
sudo -n python3 RUN_ROOT/scripts/freebsd_persistent_power_v3.py --config RUN_ROOT/scripts/replay-config.json --output RUN_ROOT/exports/freebsd-persistent-power-review
~~~

Stage the preserved helper before running it. The output directory must be new. The helper has not yet been incorporated as an eleventh replay_v6.py job. The bundle preserves the rc.d source and exact final restart commands. Only the two owned guests are power-cycled. Shared worker hosts remain running.

## Repaired family fixtures

Stage family_execution_v8.py, gateway_header_policy_v4.py and family_forward_policy_v3.py together. Run:

~~~sh
sudo -n python3 family_execution_v8.py --output RUN_ROOT/exports/families-review --families all
~~~

The generator uses isolated tcv3f8- namespaces and cleans its fixtures after collection. Do not run two instances with that same prefix concurrently. A creation collision must not be resolved by deleting another deployment's namespaces.

Every Inner and Outer has IPv4 and IPv6 FORWARD default DROP and explicit required-family IPsec-policy permits. Every gateway has literal immediate IPv6 Next Header checks at raw PREROUTING and OUTPUT. Crafted packets with unassigned claimed source addresses expose plaintext wrong-family egress before repair and blocking afterward. All eight final cases pass all 80 expected checks. Families v4 through v7 remain preserved as before-evidence. The backend is supplemental Linux namespaces with static XFRM.

## Protocol runtime and failures

The PSK MACsec repair has complete official-release source differences, active config and a fresh build-directory script in hostap-delay-reproduction-v5. Its reproduce.sh verifies the official wpa_supplicant 2.12 archive, applies the complete patch and rebuilds. The zero-window Linux RX-SA API interpretation is in evidence/mka-delay-api-interpretation-v3.md.

The separate EAP delay build combines the repaired KAY timer/history and RX-SA callback with the existing EAP-derived 256-bit CAK and objective TLS changes. hostap-pq-delay-build-v4 preserves full hostapd and wpa_supplicant differences from official 2.12 archives, source hashes, active configs, binary hashes and linkage. The first build stopped on hostapd's nonzero version-command status; the harness records that result without treating it as a compilation failure. The first execution directory lacked its Lab module; that startup failure is retained.

Objective EAP requires OpenSSL 3.5.5 with ML-DSA-87 and MLKEM1024. The host OpenSSL 3.0 execution failed before handshake at certificate-key generation. The existing tdn-hostap-pq:20261024-v3 image supplies the correct runtime. The normal tested invocation is:

~~~sh
sudo -n docker run --rm --privileged --network host --pid host --name tcv3-eap-delay-v17 -v RUN_ROOT:RUN_ROOT -v /var/run/netns:/var/run/netns:shared tdn-hostap-pq:20261024-v3 python3 RUN_ROOT/scripts/eap_tls_v17.py --root RUN_ROOT
~~~

Stage eap_tls_v17.py and eap_delay_lab_v17.py together, with the recorded repaired build under RUN_ROOT/hostap-pq-delay. The container uses host privileges to create only the named supplemental fixtures. Its actual image ID, OpenSSL version and namespace identities must remain in the collection. Forward v17 rejects the three-second delayed data. Reverse v17 still accepts it. Both carry ordinary and 100 ms traffic. The reverse delay behavior remains an actionable implementation gap. No complete EAP delay-compliance claim follows.

## Other deployments and remaining replay work

The Linux Outer extension uses linux_outer_bootstrap_v3.py, the recorded integration repairs and independent_gray_clocks_v3.py. Only fresh NC replay Outers are replaced. Native FRR/OVS peers and actual FreeBSD Inners remain active. Its official Debian image checksum, default-DROP control-path failures, final explicit laboratory SSH permits, protected traffic and two independent Gray clock corrections are public. A clean combined entry point incorporating every Linux Outer repair remains pending.

The four-worker arrangement was constructed and tested across clnode159 for Inner/Red roles, clnode163 for Outer roles, clnode176 for Outer Firewall/Black roles and pc08 for Gray Firewall roles. Public VXLAN underlay, namespace/hardware bindings, trust bindings and positive protected IPsec observations are preserved. That arrangement has not yet received a second complete fresh-root replay. It must not inherit the single-worker replay result.

The optional AW, administration and management cases retain exact public helpers and response manifests. AW v5 explicitly fsyncs the marked file and its parent directory before abrupt guest power-off. The marker and authenticated management survive restart, and the unused VM is left powered off. Earlier returned write/sync calls and lost-marker attempts remain visible. A complete configurable fresh deployment replay for those optional cases remains pending.

The active WORK_QUEUE.md and all76 assessment separate completed finite observations, confirmed counterexamples, pending implementation and external records. The 59 representative cases do not establish whole requirement compliance.
