# Evidence-side completion assessment

The run remains incomplete. Authorized implementation, collection and proof work remains actionable. The register contains all 76 requirement groups and 749 source passages. No entry asserts whole-group compliance or Lean proof completion.

The 59 representative cases cover the extracted examples and alternatives. Case presence does not establish every applicable requirement. The machine-readable clause register is [assessment-all76-v3.json](assessment-all76-v3.json). The Construction Agent owns general theorems, importer checks, checked applications and proof validation.

## Deployments and observation scope

| Deployment | Runtime backend and scope |
| --- | --- |
| B, S, N, R and M | Native Twinet Linux containers with FRR routing and Open vSwitch. Baseline, shared levels, same-level, redundant and optional management profiles remain separate. |
| MW | Native FRR and Open vSwitch across four physical workers. Inner, Outer, Gray Firewall and Outer Firewall role classes occupy distinct recorded hardware UUIDs. |
| ND | Native Linux FRR and Open vSwitch with two actual FreeBSD 14.4 Inner VMs. The Inners use strongSwan with Botan; the Linux Outers use strongSwan with OpenSSL. |
| EAP, MKA, family and utility experiments | Supplemental Linux namespace or protocol experiments. Their finite results do not become native FRR or Open vSwitch observations. |
| Physical and virtual AW | Physical pc16 workstation and an actual FreeBSD workstation VM relocated to pc16. Both manage dedicated interfaces of native Outers on pc22. The initial shared-host placement remains a recorded violation. |

Official references are retained under references/. Every capture retains its version and format. Indexed official web text is distinct from a downloaded original PDF. Management cases remain optional for the management-free data path.

## Group dispositions

### RG-001: Applicable requirements and policy precedence

Disposition: external policy.

Local policy and applicable government guidance require the organization's authoritative policy and conflict decisions. Actual filters/configurations are collected; no owner or AO policy record is invented.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-002: Validated configuration and component modification

Disposition: external evaluation and actual custom build.

Record deployed model/version and build modifications against the specific NIAP security target and evaluated configuration. Custom Twinet Linux images and the repaired hostapd have no supplied NIAP evaluated-configuration identity. A protocol test cannot supply a certification.

Evidence: [product-inventory-v3](../../../snapshots/2026-10-24T014455Z/product-inventory-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-003: Product eligibility on the CSfC Components List

Disposition: current list comparison.

Exact deployed identities were compared with the complete 420-line captured current official Components List. The custom strongSwan/Linux/hostap builds have no matching listed deployment identity in the relevant captured tables. No actual approval denial or availability/license claim is inferred. Official FAQ supplies an open-source sponsor/evaluation/sustainment approval path; actual approval remains external.

Evidence: [product-inventory-v3](../../../snapshots/2026-10-24T014455Z/product-inventory-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-004: Independent product, operating-system, and cryptographic implementations

Disposition: observed OS and crypto diversity.

The ND native deployment uses actual FreeBSD 14.4 guests with strongSwan 6.0.3 and Botan 3.13 for both Inners. Public Outer container identities, Linux kernel, algorithms, OpenSSL plugin linkage and hashes are separately bound. Useful nested traffic, unchanged SPI identities with increasing directional counters, Inner-SA-loss rejection and restoration pass. The same strongSwan product family and external manufacturer or NSA independence determinations remain unresolved.

Evidence: [product-inventory-v3](../../../snapshots/2026-10-24T014455Z/product-inventory-v3), [freebsd-native-integration-v8](../../../snapshots/2026-10-24T014455Z/freebsd-native-integration-v8), [native-Outer-OS-bindings-v3](../../../snapshots/2026-10-24T014455Z/native-Outer-OS-bindings-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-005: Physical separation of security components

Disposition: fresh separated placement.

Original PDF page 34 requires four applicable role classes on separate physical components. MW places Inner,Outer,GrayFirewall,OuterFirewall role classes on four distinct hardwareUUIDs. Cross-worker links, public trust bindings, all 16 directional SA counters and useful positive/negative traffic are verified. Original single-host deployments remain distinct observed counterexamples. Physical locations alone do not establish certified products or facility/personnel approval.

Evidence: [multiworker-behavior-v3](../../../snapshots/2026-10-24T014455Z/multiworker-behavior-v3), [multiworker-verified-v3](../../../snapshots/2026-10-24T014455Z/multiworker-verified-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-006: Product Supply Chain Threat Assessment

Disposition: external assessment.

An AO-approved product supply-chain assessment process and actual per-product assessments were not supplied. Inventory and software hashes can support that process but cannot create approval or historical assessments.

Evidence: [product-inventory-v3](../../../snapshots/2026-10-24T014455Z/product-inventory-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-007: Two independent encryption layers and allowed tunnel pairings

Disposition: partial processing and repaired boundaries.

Native processing and supplemental pairings support the nested protection model. New mixed-family raw ingress tests show actual plaintext bypass at eight applicable Inner or Outer boundaries before repair. Both IPv4 and IPv6 FORWARD defaults now DROP, with explicit IPsec-policy permits. All eight repaired family cases pass 80 expected controls. Actual fragment observations bind plaintext reassembly before ESP, router fragmentation after ESP and overlap rejection. The six pairings also expose a legitimate-source peer-Gray bypass before filtering. Strict source, destination, interface and IPsec-policy permits or MACsec bridge bounds repair the boundary. All 36 final controls pass. Complete importer and all-execution semantics remain Construction work; physical product independence remains separate.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [native-shared-four-levels-20261024T015300Z-coverage-v1](../../../snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1), [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7), [families-v9](../../../snapshots/2026-10-24T014455Z/families-v9), [multiworker-behavior-v3](../../../snapshots/2026-10-24T014455Z/multiworker-behavior-v3), [data-fragments-v5](../../../snapshots/2026-10-24T014455Z/data-fragments-v5), [bridged-macsec-v8](../../../snapshots/2026-10-24T014455Z/bridged-macsec-v8).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-008: Connectivity restricted to the same security level

Disposition: partial authentication and origin.

Configured per-level roots and80 chain checks support intended same-level authentication. Twenty direct-arrival ICMP cases from actual Red namespaces testsixteen forged-level or unknown sources plusfour legitimate controls; only legitimate controls arrive. Before/after ingress drop counters are retained. Scope is finite IPv4 ICMP with intact gateways, not arbitrary hostile execution or complete all-protocol exclusion.

Evidence: [native-shared-four-levels-20261024T015300Z-coverage-v1](../../../snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1), [native-public-auth-bindings-20261024T020200Z](../../../snapshots/2026-10-24T014455Z/native-public-auth-bindings-20261024T020200Z), [native-source-spoofing-v3](../../../snapshots/2026-10-24T014455Z/native-source-spoofing-v3), [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-009: Gray-network control and classification boundary

Disposition: external control and implementation.

Topology, addresses and traffic boundaries are visible. Organizational ownership/control, classification treatment and authorization require actual owner records. Namespace ownership is not an organizational control determination.

Evidence: [native-shared-four-levels-20261024T015300Z-coverage-v1](../../../snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1), [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-010: Independently managed site administration and trust

Disposition: partial independent sites.

Separate per-site CA service arrangements and public trust are collected. Site-specific administrator identity, authority and independent organization trust decisions require real records; same laboratory operator is not evidence of independent personnel.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [ca-enterprise-v2](../../../snapshots/2026-10-24T014455Z/ca-enterprise-v2).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-011: Central management, CA placement, and intersite protection

Disposition: partial central Gray management.

Native independent management and a separate central Gray case are present. The central Gray AW/CA service reaches an actual remote Outer dedicated management interface through Gray Firewall/Encryption components and Outer protection; separate Red traffic continues during management-layer loss. Eight probes pass. Supplemental manual SAs and bounded TLS do not establish complete EnterpriseGrayAnnex controls, registration, policy or approval.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3), [central-gray-management-v3](../../../snapshots/2026-10-24T014455Z/central-gray-management-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-012: Separate authentication and management for security levels

Disposition: partial per level authentication.

Per-level certificate roots and loaded bindings are observed. Independent per-level management components and traffic paths need full management import; actual administrator separation and organizational trust permissions require owner records.

Evidence: [native-shared-four-levels-20261024T015300Z-coverage-v1](../../../snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1), [native-public-auth-bindings-20261024T020200Z](../../../snapshots/2026-10-24T014455Z/native-public-auth-bindings-20261024T020200Z), [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-013: Gray Firewalls on all paths needing level separation

Disposition: topology and filtering evidence.

Native interfaces, links, OVS flows and Gray Firewall policies support all-path checking. Claims about physical wires beyond recorded VXLAN/veth topology need stated emulation assumptions. Management CA/AW/CDP alternative attachment coverage must be checked explicitly.

Evidence: [native-shared-four-levels-20261024T015300Z-coverage-v1](../../../snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1), [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-014: Gray addressing supports security-level filtering

Disposition: addressing observed.

Per-level Gray address ranges and interface filters are collected. Import exact ranges and establish their association with the source-level relation; source-address provenance remains a separate assumption.

Evidence: [native-shared-four-levels-20261024T015300Z-coverage-v1](../../../snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1), [native-shared-processing-20261024T015500Z](../../../snapshots/2026-10-24T014455Z/native-shared-processing-20261024T015500Z).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-015: MACsec encapsulation and standalone encapsulator obligations

Disposition: partial encapsulation controls.

Integrated and standalone encapsulation are represented with useful layered traffic. Figure 8 and Section 5.5 require source review; a standalone encapsulator is a Solution Component and must receive every applicable Section 11.1 control. The six repaired pairings retain full effective bridge, L2TP, routing, dual-family filter, MACsec and public header state. Exact endpoint and direction permits preserve useful traffic. Current supplemental encapsulators do not establish all applicable Section 11.1 administrative and product controls.

Evidence: [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-016: Permitted MACsec clear VLAN tags and XPN

Disposition: observed MACsec XPN and tag options.

New explicit GCM-AES-XPN-256 cases start at64-bit packet number 4294967297 and separately placezero, one or two clear VLAN tags ahead of MACsec. Public effective state, wire headers, bidirectional positives and receiver-SA-loss negatives pass. A separate complete bridged Inner MACsec, L2TPv3 and Outer ESP arrangement carries opaque non-IP Ethernet with zero, one and two VLAN tags inside protection. Exact recovered tag stacks and payload digests match. All 18 useful, both-layer loss and restoration controls pass. Complete bridge/carrier/route/filter state is retained. Static SAK provisioning does not establish MKA authentication or all-time XPN rollover.

Evidence: [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7), [mka-psk-matching-v4](../../../snapshots/2026-10-24T014455Z/mka-psk-matching-v4), [eap-tls-forward-v10](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v10), [macsec-options-v4](../../../snapshots/2026-10-24T014455Z/macsec-options-v4), [bridged-macsec-v8](../../../snapshots/2026-10-24T014455Z/bridged-macsec-v8).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-017: Mutual authentication and Non-Person Entity certificates

Disposition: public certificates and authentication.

Public NPE certificates, unique public keys, chains, device identities, loaded bindings and successful handshakes are collected. EAP authenticator/AS identity scope and issuance authority need explicit interpretation. No private key is exported.

Evidence: [native-public-auth-bindings-20261024T020200Z](../../../snapshots/2026-10-24T014455Z/native-public-auth-bindings-20261024T020200Z), [ca-enterprise-v2](../../../snapshots/2026-10-24T014455Z/ca-enterprise-v2), [eap-tls-forward-v10](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v10).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-018: CNSS algorithm-policy requirements and choices

Disposition: policy and algorithm evidence.

Observed negotiated and configured algorithms must be checked against exact original tables and cited CNSS policy versions. A functional handshake does not establish all offered algorithms or policy authority.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [ikev2-objective-v6](../../../snapshots/2026-10-24T014455Z/ikev2-objective-v6), [eap-tls-forward-v10](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v10), [mka-psk-matching-v4](../../../snapshots/2026-10-24T014455Z/mka-psk-matching-v4).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-019: IPsec CNSA profile and post-quantum exchange sequence

Disposition: finite PQ exchange and actual offers.

The successful objective exchange records the actual unencrypted IKE_SA_INIT request and response proposals and transform attributes, effective connection configuration, P-384 initial exchange, MLKEM1024 intermediate and MLDSA87 authentication. Actual IKE fragment headers, peer MTUs, routes and useful traffic are retained. Full RFC behavior, future exchanges and every required child-rekey condition remain separate.

Evidence: [ikev2-objective-v6](../../../snapshots/2026-10-24T014455Z/ikev2-objective-v6).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-020: VPN certificate loading and authentication checks

Disposition: finite certificate lifecycle events.

Actual FreeBSD/Botan IKE peers reject a signed certificate-hold revocation with explicit revoked diagnostic and a separately signed expired certificate with validity diagnostic. Both block selected payload traffic; original valid credentials restore useful traffic. The first missing-AKI CRL instead failed strict unavailable-status validation and remains preserved. Unique public keys/chains and HTTP CRL/OCSP events are separate records; production issuance authority and complete vendor-default removal remain unchecked.

Evidence: [native-public-auth-bindings-20261024T020200Z](../../../snapshots/2026-10-24T014455Z/native-public-auth-bindings-20261024T020200Z), [http-crl-v1](../../../snapshots/2026-10-24T014455Z/http-crl-v1), [http-ocsp-v1](../../../snapshots/2026-10-24T014455Z/http-ocsp-v1), [freebsd-certificate-events-v4](../../../snapshots/2026-10-24T014455Z/freebsd-certificate-events-v4).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-021: VPN private-key access confinement

Disposition: finite mandatory key boundary.

A supplemental actual Linux IKEv2 pair loads a complete AppArmor policy. Ordinary container root cannot open private-key files, write the immutable gateway executable or directly enter the gateway profile. Fixed executable transitions permit charon and swanctl to load credentials and establish useful IPsec traffic. Nine checks match. Host root, Docker, policy loading and provisioning remain trusted laboratory controls. The policy is not yet installed across native ND or actual FreeBSD components and does not establish every component interface.

Evidence: [product-inventory-v3](../../../snapshots/2026-10-24T014455Z/product-inventory-v3), [native-all-process-inventory-v3](../../../snapshots/2026-10-24T014455Z/native-all-process-inventory-v3), [lsm-gateway-v6](../../../snapshots/2026-10-24T014455Z/lsm-gateway-v6).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-022: IKEv2 and IKE/ESP encryption-mode alternatives

Disposition: finite CBC and GCM alternatives.

The selected ND deployment negotiates IKEv2 with AES-256-CBC, HMAC-SHA-384 and P-384 in both actual FreeBSD Inners and native Linux Outers. Bidirectional protected traffic, Inner SA loss and GCM restoration are observed. The original threshold CBC and objective GCM alternatives remain independent for IKE and ESP. Complete offered-proposal and product approval checks remain separate.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [ikev2-objective-v6](../../../snapshots/2026-10-24T014455Z/ikev2-objective-v6), [native-CBC-alternative-v4](../../../snapshots/2026-10-24T014455Z/native-CBC-alternative-v4).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-023: VPN SA lifetimes and reauthentication

Disposition: configured lifetimes and scheduled reauth.

Public baseline configurations set IKE reauth3 hours, automatic IKErekey0 and ESP lifetime1 hour. A short20 secondsreauth/40 secondsrekey experiment observes automatic reauthentication: both identities authenticate before new IKE establishment, which precedes old IKE deletion. Both overlapping100-packet streams deliver100/100. Original timers restore. Reauthentication replaces the SA and resets its rekey timer, so no pure IKE rekey is asserted; arbitrary future manual operations remain outside the finite observation.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [native-shared-processing-20261024T015500Z](../../../snapshots/2026-10-24T014455Z/native-shared-processing-20261024T015500Z), [freebsd-reauth-event-v3](../../../snapshots/2026-10-24T014455Z/freebsd-reauth-event-v3), [freebsd-automatic-reauth-v3](../../../snapshots/2026-10-24T014455Z/freebsd-automatic-reauth-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-024: MACsec authentication alternatives and AS scope

Disposition: repaired EAP and PSK.

Matching PSK MKA useful traffic and mismatched-key failure are recorded. Repaired EAP carries useful MACsec traffic in both separately tested supplicant and authenticator arrangements. Original-source review requires both functions; the source does not impose simultaneous operation. Approved-product identity and complete authentication controls remain separate clauses.

Evidence: [eap-tls-forward-v10](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v10), [mka-psk-matching-v4](../../../snapshots/2026-10-24T014455Z/mka-psk-matching-v4).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-025: MACsec encryption and key wrapping algorithms

Disposition: bounded IEEE KDF source and vector review.

Matching PSK MKA and static states use GCM-AES-256. Both final EAP wrappers select the first 32 MSK bytes for the 32-byte CAK and retain the 16-byte CKN. Indexed primary IEEE 802.1X-2020 Sections 6.2.1, 6.2.2 and 9.3 plus Annex G.1 through G.6 are now visible. The university URL returns 404; title, edition and DOI match the official catalog and RFC bibliography, while complete issuer-authenticated PDF bytes are unavailable. Exact final authenticator and supplicant derivation/CMAC source files match the official bytes compiled in the pinned OpenSSL 3.5.5 vector harness. All 12 published 128/256-bit KDF, CAK, CKN, KEK, ICK and SAK examples match. Shared KAY uses agility 00-80-C2-01 and CAK-sized ICK/KEK. The specific derivation reading is supported. Full-standard conformance, all error/lifecycle behavior, independent implementation interoperability and product approval are not inferred.

Evidence: [mka-psk-matching-v4](../../../snapshots/2026-10-24T014455Z/mka-psk-matching-v4), [eap-tls-forward-v10](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v10), [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7), [hostap-kdf-review-v4](../../../snapshots/2026-10-24T014455Z/hostap-kdf-review-v4), [hostap-kdf-vectors-v3](../../../snapshots/2026-10-24T014455Z/hostap-kdf-vectors-v3), [hostap-kdf-bindings-v4](../../../snapshots/2026-10-24T014455Z/hostap-kdf-bindings-v4).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-026: MACsec EAP-TLS CNSA profile alternatives

Disposition: finite objective and threshold EAP observed.

Threshold EAP uses TLS 1.2 with ECDHE-ECDSA-AES256-GCM-SHA384 and P-384. Objective EAP records TLS 1.3, TLS_AES_256_GCM_SHA384 and MLKEM1024 through the actual post-handshake API. Public certificate keys and signatures use MLDSA87. Both separately tested role arrangements carry useful MACsec traffic. The visible IEEE KDF/agility clauses, exact runtime source comparison and all 12 Annex G vectors are separately reviewed with the recorded hosting caveat. Full-standard and independent interoperability claims and actual product or credential approvals remain separate.

Evidence: [eap-tls-forward-v11](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v11), [eap-tls-forward-v14](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v14), [hostap-kdf-review-v4](../../../snapshots/2026-10-24T014455Z/hostap-kdf-review-v4), [hostap-kdf-vectors-v3](../../../snapshots/2026-10-24T014455Z/hostap-kdf-vectors-v3), [hostap-kdf-bindings-v4](../../../snapshots/2026-10-24T014455Z/hostap-kdf-bindings-v4).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-027: MACsec key generation, key-server selection, and rollover

Disposition: finite key server election and timeout.

Public CKN length, priorities zero and one and absent fallback CAK are retained. Actual MKA logs identify the elected priority-zero key server. Stopping that owned process produces peer timeout and loss of useful traffic. Resuming the process restores useful protected traffic. All three checks match. Approved key generation, genuine key ceremonies and all rollover behavior remain separate.

Evidence: [mka-psk-matching-v4](../../../snapshots/2026-10-24T014455Z/mka-psk-matching-v4), [eap-tls-forward-v10](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v10), [mka-events-matching-v6](../../../snapshots/2026-10-24T014455Z/mka-events-matching-v6).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-028: MACsec mandatory protection parameters

Disposition: finite delay repair in both EAP roles.

The PSK zero-window repair rejects three-second frames while 100 ms and ordinary traffic pass. Full source binds computed lowest_pn to the Linux RX-SA packet-number attribute. The same shared repair is built into separate hostapd and wpa_supplicant objective EAP binaries. The v17 reverse role accepts delayed frames because the authenticator callback setter is omitted. The final v18 repair wires that existing driver API. Both EAP arrangements and both directions then reject three-second data, accept 100 ms data and restore useful traffic. All 16 controls match. The earlier counterexample remains preserved. Normal Hello 2000 ms, lifetime 6000 ms, active bounded Hello 500 ms, runtime settings and both failure histories are retained. The visible IEEE KDF/agility clauses and all 12 Annex G vectors are separately reviewed. Full-standard lifecycle scope and replacement-SA overlap remain separate.

Evidence: [mka-psk-matching-v4](../../../snapshots/2026-10-24T014455Z/mka-psk-matching-v4), [eap-tls-forward-v10](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v10), [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7), [mka-events-matching-v6](../../../snapshots/2026-10-24T014455Z/mka-events-matching-v6), [mka-delay-bounded-v8](../../../snapshots/2026-10-24T014455Z/mka-delay-bounded-v8), [eap-tls-forward-v17](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v17), [eap-tls-reverse-v17](../../../snapshots/2026-10-24T014455Z/eap-tls-reverse-v17), [eap-tls-forward-v18](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v18), [eap-tls-reverse-v18](../../../snapshots/2026-10-24T014455Z/eap-tls-reverse-v18), [hostap-kdf-review-v4](../../../snapshots/2026-10-24T014455Z/hostap-kdf-review-v4).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-029: Inner encryption and decryption cannot be bypassed

Disposition: partial Inner processing with confirmed repair.

Native processing is collected. Mixed-family fixtures previously forwarded wrong-family plaintext because the second-family FORWARD hook defaulted to ACCEPT. Captured raw ingress uses unassigned claimed sources, so the finding does not assume truthful source addresses. Both-family default-DROP repairs block those egresses while protected traffic continues. A supplemental AppArmor pair demonstrates bounded key confinement. Native Inner policy installation, actual FreeBSD mandatory policy and complete all-execution checks remain actionable.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [native-shared-four-levels-20261024T015300Z-coverage-v1](../../../snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1), [native-shared-processing-20261024T015500Z](../../../snapshots/2026-10-24T014455Z/native-shared-processing-20261024T015500Z), [families-v9](../../../snapshots/2026-10-24T014455Z/families-v9), [multiworker-behavior-v3](../../../snapshots/2026-10-24T014455Z/multiworker-behavior-v3), [lsm-gateway-v6](../../../snapshots/2026-10-24T014455Z/lsm-gateway-v6), [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7), [bridged-macsec-v8](../../../snapshots/2026-10-24T014455Z/bridged-macsec-v8).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-030: Outer encryption and decryption cannot be bypassed

Disposition: partial Outer processing with confirmed repair.

Mixed-family Outer before-captures show wrong-family plaintext leaving toward Black. Both-family default-DROP forwarding with explicit IPsec-policy permits blocks the crafted egress, while protected traffic and restoration pass. Full local, ingress and egress semantics remain necessary. The supplemental AppArmor result is not yet installed on every native Outer.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [native-shared-four-levels-20261024T015300Z-coverage-v1](../../../snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1), [native-shared-processing-20261024T015500Z](../../../snapshots/2026-10-24T014455Z/native-shared-processing-20261024T015500Z), [families-v9](../../../snapshots/2026-10-24T014455Z/families-v9), [multiworker-behavior-v3](../../../snapshots/2026-10-24T014455Z/multiworker-behavior-v3), [lsm-gateway-v6](../../../snapshots/2026-10-24T014455Z/lsm-gateway-v6), [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7), [bridged-macsec-v8](../../../snapshots/2026-10-24T014455Z/bridged-macsec-v8).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-031: Routing and switching limits on Encryption Components

Disposition: process and native routing observed.

FRR daemon-to-device namespace ownership, Outer processes and active sockets are captured. The Outer profile uses static routes and no routing daemon. Explicit local-process and OVS operation scope must be preserved; future administrative changes are outside a snapshot.

Evidence: [native-all-process-inventory-v3](../../../snapshots/2026-10-24T014455Z/native-all-process-inventory-v3), [native-shared-processing-20261024T015500Z](../../../snapshots/2026-10-24T014455Z/native-shared-processing-20261024T015500Z), [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-032: TRANSEC under the stated deployment conditions

Disposition: finite size rate masking with explicit assumptions.

An explicit custom shim before actual Outer MACsec emits fixed 512-byte records at configured 20 ms slots, carrying one queued protected packet or dummy padding. Both idle windows record 150 frames per endpoint; the useful window records 203, with six data records. Actual Black-side wire frames are 558 bytes and measured intervals/jitter remain public. FIFO capacity is 64 packets with new overflow/oversize drops; the supported payload is 488 bytes. Useful traffic and both-layer loss/restoration pass all six controls after ENETDOWN handling is repaired. Original CP pages 23, 44 and 61, official RFC traffic-flow resources and IEEE MAC-privacy project context support the selected interpretation. Hard real-time timing, arbitrary offered loads, full traffic-analysis protection, anti-jamming, authority sufficiency and standard/product conformance remain unproved. Construction must bind the exact emission/queue model and explicit clock/link/scheduling assumptions; an enabled Boolean alone is insufficient.

Evidence: [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7), [eap-tls-forward-v10](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v10), [outer-MACsec-cover-v4](../../../snapshots/2026-10-24T014455Z/outer-MACsec-cover-v4), [outer-MACsec-cover-analysis-v4](../../../snapshots/2026-10-24T014455Z/outer-MACsec-cover-analysis-v4).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-033: Packet sizing to control fragmentation

Disposition: finite MTU fragment and dynamic PMTU evidence.

Native MTUs and cross-worker VXLAN 1450 settings are recorded. Useful DF traffic passes with SA counters. The all-IPv6 nested fixture carries a 1280-byte Red packet. An actual IPv6 ESP experiment records Black PTB MTU 1400, source PTB 1326 and sender PMTU changing 1500 to 1326. A smaller 1200-byte public payload arrives with exact digest and protected acknowledgement. IPv4 captures distinguish plaintext reassembly, post-ESP fragmentation and outer reassembly. External encapsulator fragmentation and every operating-size condition remain separate actionable scope.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [families-v9](../../../snapshots/2026-10-24T014455Z/families-v9), [multiworker-behavior-v3](../../../snapshots/2026-10-24T014455Z/multiworker-behavior-v3), [multiworker-verified-v3](../../../snapshots/2026-10-24T014455Z/multiworker-verified-v3), [family-headers-v5](../../../snapshots/2026-10-24T014455Z/family-headers-v5), [data-fragments-v5](../../../snapshots/2026-10-24T014455Z/data-fragments-v5), [IPv6-PMTU-v4](../../../snapshots/2026-10-24T014455Z/IPv6-PMTU-v4).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-034: Outer Firewall placement for untrusted Black transport

Disposition: topology observed.

Native paths put Outer Firewalls between Outers and Black. Public-Internet transport is an emulated applicability choice; four-worker public management underlay does not by itself establish the source Black-zone model. Keep logical and actual transport labels traceable.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [multiworker-behavior-v3](../../../snapshots/2026-10-24T014455Z/multiworker-behavior-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-035: Permitted protocols and peers at encryption and firewall boundaries

Disposition: partial boundary filters.

Exact ordered native input/output/forward filters and OVS states are collected. All six supplemental pairings now use dual-family INPUT/OUTPUT/FORWARD default DROP. Exact policy/interface and MACsec bridge permits reject legitimate Red-to-Gray bypass while useful traffic, loss and restoration pass all 36 controls. Control protocols need organization-approved policy. MACsec boundary filtering requires link-layer rule interpretation as well as IP rules; complete execution checks remain Construction work.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [native-shared-processing-20261024T015500Z](../../../snapshots/2026-10-24T014455Z/native-shared-processing-20261024T015500Z), [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-036: Minimal network-interface exposure

Disposition: partial minimal exposure.

All interfaces, addresses, routes, listeners and filters are captured. Minimal possible range is relative to an actual authorized service inventory. Verify unused interfaces are down rather than treating missing traffic as disabled.

Evidence: [native-shared-processing-20261024T015500Z](../../../snapshots/2026-10-24T014455Z/native-shared-processing-20261024T015500Z), [native-all-process-inventory-v3](../../../snapshots/2026-10-24T014455Z/native-all-process-inventory-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-037: Outer-component third-party contact restrictions

Disposition: partial third party contact.

Current services and default-deny Outer output filters are observed. Blocking and disabling are different clauses. No running snapshot proves absence of every dormant feature; inspect startup configuration and test bounded attempted contact.

Evidence: [native-shared-processing-20261024T015500Z](../../../snapshots/2026-10-24T014455Z/native-shared-processing-20261024T015500Z), [native-all-process-inventory-v3](../../../snapshots/2026-10-24T014455Z/native-all-process-inventory-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-038: IP header and multicast filtering

Disposition: finite pre defrag header and dual family repairs.

A valid UDP datagram behind Destination Options passes the upper-layer protocol match before repair. A literal immediate Next Header raw-field policy rejects it while plain UDP and protected traffic continue. A later NH44 test shows reassembly before raw PREROUTING bypasses that raw-only check. The final family v9 generator adds literal nftables checks at priority -450 on every gateway, before defragmentation at -400. Representative fragment rejection and valid controls pass; all 80 family controls match. Both-family FORWARD DROP also closes captured wrong-family plaintext bypasses. Complete multicast, selected IPv4-options behavior and every native installation remain separate tasks.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [native-shared-processing-20261024T015500Z](../../../snapshots/2026-10-24T014455Z/native-shared-processing-20261024T015500Z), [families-v9](../../../snapshots/2026-10-24T014455Z/families-v9), [families-v9](../../../snapshots/2026-10-24T014455Z/families-v9), [family-headers-v5](../../../snapshots/2026-10-24T014455Z/family-headers-v5), [data-fragments-v5](../../../snapshots/2026-10-24T014455Z/data-fragments-v5), [family-host-binding-v3](../../../snapshots/2026-10-24T014455Z/family-host-binding-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-039: Outer Gray-interface allowlist and default denial

Disposition: partial Outer allowlist and origin.

Ordered rules and bounded revocation HTTP exceptions are present. Native per-interface source allowlists need exact reachability comparison and source-spoofing tests. Management initiation and approved control exceptions require source-specific paths/policy.

Evidence: [native-shared-processing-20261024T015500Z](../../../snapshots/2026-10-24T014455Z/native-shared-processing-20261024T015500Z), [http-crl-v1](../../../snapshots/2026-10-24T014455Z/http-crl-v1), [http-ocsp-v1](../../../snapshots/2026-10-24T014455Z/http-ocsp-v1).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-040: Gray Firewall allowlist and cross-level denial

Disposition: partial Gray Firewall processing.

Gray FW rules, routes and management topology are collected. All paths and interface-specific source validation must be checked. Bounded HTTP revocation cases do not establish arbitrary HTTP exclusion without exact rule interpretation and counter traces.

Evidence: [native-shared-four-levels-20261024T015300Z-coverage-v1](../../../snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1), [native-shared-processing-20261024T015500Z](../../../snapshots/2026-10-24T014455Z/native-shared-processing-20261024T015500Z), [http-crl-v1](../../../snapshots/2026-10-24T014455Z/http-crl-v1), [http-ocsp-v1](../../../snapshots/2026-10-24T014455Z/http-ocsp-v1), [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-041: Control-plane approval, defaults, and service location

Disposition: partial inside service location.

Red and Gray inside-network NTP sample services are realized. Current default/startup services and exact approved control protocols need component-level scope. Approval and trust of the time authority require actual policy.

Evidence: [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3), [native-all-process-inventory-v3](../../../snapshots/2026-10-24T014455Z/native-all-process-inventory-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-042: Layer-specific trusted time synchronization

Disposition: finite independent Red and Gray clock correction.

Two actual FreeBSD Inner kernels correct their clocks against separate Red-side sources. Two actual Debian Linux Outer kernels record distinct boot IDs and correct against separate Gray sources. Controlled displacements, measured queries, successful corrective steps, explicit Gray time permits and useful protected traffic are retained. Worker clocks are unchanged. Actual authority approval, authenticated source policy and long-term drift remain separate.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3), [independent-Red-clocks-v3](../../../snapshots/2026-10-24T014455Z/independent-Red-clocks-v3), [independent-Gray-clocks-v3](../../../snapshots/2026-10-24T014455Z/independent-Gray-clocks-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-043: Default credentials, DNS, and remote bootstrap

Disposition: finite selected dual family DNS transport hardening.

Seven Linux network devices in ND retain leading IPv4 and IPv6 conventional DNS rejection prefixes. Both actual FreeBSD Inners retain enabled PF, empty current state tables, exact local-address bindings and expanded source-self rules. All 18 final IPv6 UDP/TCP53 attempts hit rejection rules and both protected-data directions pass. PF skip v13 adds 50 read-only observations with full loaded-interface flags, before/after rules/status and both protected traffic directions. Resolver configuration, libc and socket inventories are separate: the musl routers do not gain disabled libc lookup from nsswitch alone. Read-only mount repair failures remain preserved. MSC-SR-19 is an optional objective; MSC-SR-20 permits specified server addresses or disabled DNS services. Full default-account, password, remote bootstrap and all-component scope remain separate checks.

Evidence: [native-all-process-inventory-v3](../../../snapshots/2026-10-24T014455Z/native-all-process-inventory-v3), [product-inventory-v3](../../../snapshots/2026-10-24T014455Z/product-inventory-v3), [native-DNS-hardening-v7](../../../snapshots/2026-10-24T014455Z/native-DNS-hardening-v7), [native-DNS-hardening-v11](../../../snapshots/2026-10-24T014455Z/native-DNS-hardening-v11), [freebsd-PF-skip-v13](../../../snapshots/2026-10-24T014455Z/freebsd-PF-skip-v13).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-044: Layer-specific administration and management-plane separation

Disposition: partial layer specific management.

Native management links and central Gray protected management are collected. Physical pc16 and a distinct actual FreeBSD AW VM independently reach dedicated native Outer management interfaces with mutual TLS and negative certificate/path controls. These are Gray-side workstation alternatives. Complete layer-specific Red/Gray administrator capabilities, mandatory confinement and all physical/cryptographic plane separation still need evidence or implementation; test workstation identity is not production administrator authority.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3), [central-gray-management-v3](../../../snapshots/2026-10-24T014455Z/central-gray-management-v3), [aw-physical-v4](../../../snapshots/2026-10-24T014455Z/aw-physical-v4), [aw-virtual-v4](../../../snapshots/2026-10-24T014455Z/aw-virtual-v4).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-045: Dedicated, protected, hardened Administrative Workstations

Disposition: finite AW placement and power repair.

The actual FreeBSD AW VM now occupies dedicated pc16 hardware and retains a separate native Outer management interface. Earlier shared-host placement remains a counterexample. Abrupt power tests first lose a newly written marker after write and sync return. Explicit file and directory fsync in v5 preserves the marker, restores authenticated management after reboot and leaves the unused VM powered off. Exact timing and failure records remain visible. Full management functions, approved hardening, facility and personnel controls remain separate.

Evidence: [aw-physical-v4](../../../snapshots/2026-10-24T014455Z/aw-physical-v4), [aw-virtual-v4](../../../snapshots/2026-10-24T014455Z/aw-virtual-v4), [aw-power-event-v5](../../../snapshots/2026-10-24T014455Z/aw-power-event-v5).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-046: Management transport protection and local exceptions

Disposition: partial management transport.

Mutual TLS positive/negative administration and local/same-site paths are available. Actual NSA approval for the remote protection mechanism and organization-approved administration address range require records. Same-site exception must not be expanded into a plaintext-management permission.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-047: Administrator authentication and individual credentials

Disposition: partial admin authentication.

Mutual TLS acceptance/rejection is observed in test management services. Real individual administrator credentials, NIST assurance level, identity proofing and authorization are not supplied. A generated lab certificate is not a person's authorized administrative identity.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-048: Authorized provisioning and initial certificate requests

Disposition: partial provisioning.

Public issuance and loaded chain bindings are available. Solution Owner authorization of named administrators and their actual CSR initiation require workflow records; automated issuance is not that authorization. Gray placement of the Outer CA AW needs the exact management profile.

Evidence: [native-public-auth-bindings-20261024T020200Z](../../../snapshots/2026-10-24T014455Z/native-public-auth-bindings-20261024T020200Z), [ca-enterprise-v2](../../../snapshots/2026-10-24T014455Z/ca-enterprise-v2).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-049: Personnel clearance and Outer administration

Disposition: external clearance.

Clearance records and authorization to administer the highest supported classifications are unavailable. Physical role placement and simulated security-level strings cannot create personnel clearances.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-050: SIEM placement, collection, alerting, and log transport

Disposition: partial log flow.

Native SIEM placement and software CDS relay logs supply finite receipt/rejection traces. Full required event generation, alert handling, protected transport and Continuous Monitoring Annex 1.1.0 clauses need explicit mapping and additional services. Approved CDS and organizational review are separate.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-051: Cross Domain Solution approval conditions

Disposition: external CDS membership and authorization.

Official DISN Connection Process Guide 6.1, March 2023, Appendix G supplies the CDS approval process. Appendix N locates the NCDSMO Baseline List on SIPRNet and explicitly requires an account. No authorized restricted-network access was supplied. The official NSA office page also locates its library on Intelink. The software relay has no demonstrated baseline membership or actual DoDI/DISN authorization. Official DoDI 8540.01 listings and indexed excerpts were found, but the complete direct PDF returned HTTP 403; the DISN quotations are not the complete instruction.

Evidence: [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-052: Physical protection, authorized access, and disposal

Disposition: external physical classification.

Remote hardware identities and access via CloudLab establish placement only. Classified physical protection, cleared/escorted access, classified disposal and protected CAK/config media require facility and lifecycle records. No destructive disposal test is authorized or necessary to infer compliance.

Evidence: [multiworker-behavior-v3](../../../snapshots/2026-10-24T014455Z/multiworker-behavior-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-053: Parallel Inner components and distinct Outer internal interfaces

Disposition: observed NIC capabilities and placement task.

Parallel native Inner placement is recorded. Read-only inventory binds six workers to physical PCI NICs, drivers, firmware diagnostics, link states and addresses. Clemson workers expose two already-used linked ports. Massachusetts workers expose six ports but only management and experiment ports are linked. Disconnected ports alone do not establish per-Red physical cabling. A deployed unique physical internal interface per Red remains unestablished; preserving existing workloads constrains repurposing active links.

Evidence: [native-shared-four-levels-20261024T015300Z-coverage-v1](../../../snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1), [native-redundant-20261024T020100Z](../../../snapshots/2026-10-24T014455Z/native-redundant-20261024T020100Z), [multiworker-behavior-v3](../../../snapshots/2026-10-24T014455Z/multiworker-behavior-v3), [physical-capability-inventory-v4](../../../snapshots/2026-10-24T014455Z/physical-capability-inventory-v4).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-054: Interoperable components across communicating sites

Disposition: finite interoperability.

Positive protected traffic demonstrates selected peer/configuration interoperability, including cross-worker native IPsec and repaired EAP roles. Third-party approved product/version combinations and all operating conditions remain outside finite observations.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [families-v9](../../../snapshots/2026-10-24T014455Z/families-v9), [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7), [ikev2-objective-v6](../../../snapshots/2026-10-24T014455Z/ikev2-objective-v6), [eap-tls-forward-v10](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v10), [multiworker-behavior-v3](../../../snapshots/2026-10-24T014455Z/multiworker-behavior-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-055: Firewall requirements when combining capability packages

Disposition: partial combined CP.

Combined Inner/Gray firewall software structures exist. The other selected CP, its end-user-device scope, required firewall clauses and approved product identities must be specified and checked. A generic filtering bridge does not establish another CP's complete requirements.

Evidence: [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-056: Approved physical paths out of Red Networks

Disposition: partial egress topology.

Native Red paths and supplemental alternate egress are recorded. The alternate egress mutual TLS path has no supplied AO approval. General path closure needs topology/importer checks and physical boundary assumptions.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-057: Operational security updates and TEMPEST policy

Disposition: external policy and actionable lifecycle.

Exact installed versions and public package provenance can be collected. Agency virus-update rules, patch-installation policy and TEMPEST policy are external. A test patch/apply event can illustrate the mechanism but cannot replace actual policy or historical timely maintenance.

Evidence: [product-inventory-v3](../../../snapshots/2026-10-24T014455Z/product-inventory-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-058: Hardware inventory and available baseline configuration

Disposition: partial inventory and baseline.

Configs, image digests and physical worker UUIDs are captured and durably preserved. AO-approved inventory process and evidence that the actual Security Administrator maintains/serves the baseline to the Auditor require records.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [multiworker-behavior-v3](../../../snapshots/2026-10-24T014455Z/multiworker-behavior-v3), [product-inventory-v3](../../../snapshots/2026-10-24T014455Z/product-inventory-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-059: Procurement documentation excludes classified-protection purpose

Disposition: external procurement.

No acquisition/procurement documents were supplied. Runtime observations cannot show whether those documents disclose classified-protection purpose. Request actual redacted documents or an authorized attestation; do not invent a procurement process.

Evidence: [product-inventory-v3](../../../snapshots/2026-10-24T014455Z/product-inventory-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-060: Annual and NSA-authorized compliance audits

Disposition: external audit history.

NSA audit cooperation, annual completed audit, results delivery and AO review require real audit records. Fresh lab checks are not an annual compliance audit.

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-061: Registration, approval, annual renewal, and version updates

Disposition: external registration.

NSA registration, pre-operation approval, complete package submission, annual update and latest-version renewal compliance require actual authoritative records. Software deployment cannot issue an NSA approval.

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-062: Audit retention, storage monitoring, backup, and continuity

Disposition: finite audit power startup and protected offload.

Two owned actual FreeBSD Inner guests persist startup configuration across power cycles and restore protected traffic. The AW v5 abrupt power test preserves a file after explicit file and directory fsync and restores authenticated management. Earlier AW write/sync marker loss is retained. Those bounded events do not establish one-year retention, quarterly review, every failure mode, complete protected log offload or organizational adoption. The actual syslog audit-power v4 event preserves its fsynced auth.log record, verified later through the owned guest console. Unclean UFS recovery exposes zero-length rc.conf and gateway startup files. Exact public startup bytes plus file and directory fsync repair the startup defect. The final v8 run passes all eight controls across both guests: useful before, loss while off, preserved actual audit marker and useful after. SSH and charon start automatically. The driver explicitly resets both IKE connections and initiates a fresh CHILD before the final traffic check; automatic SA recovery is not inferred. Failed UART restoration, service timeout and stale-IKE driver attempts remain preserved. Actual protected offload now transfers the complete retained authentication-log source copy to a distinct worker using TLS 1.3 mutual authentication. The initial 65,536-byte prefix omits the new marker; a bounded drain later acknowledges the exact EOF. The actual event and complete journal hash survive the second collector restart. Duplicate, conflict, untrusted certificate, device binding, capacity backpressure and one unprivileged key-read boundary are recorded. All 13 finite controls match. Exporter startup, source rotation, retention policy, physical disk exhaustion and all crash interleavings remain actionable or unobserved.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3), [freebsd-persistent-power-v3](../../../snapshots/2026-10-24T014455Z/freebsd-persistent-power-v3), [aw-power-event-v5](../../../snapshots/2026-10-24T014455Z/aw-power-event-v5), [freebsd-audit-power-v8](../../../snapshots/2026-10-24T014455Z/freebsd-audit-power-v8), [audit-offload-validation-v8](../../../snapshots/2026-10-24T014455Z/audit-offload-validation-v8), [native-fresh-replay-validation-v7](../../../snapshots/2026-10-24T014455Z/native-fresh-replay-validation-v7).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-063: Infrastructure authentication alternatives

Disposition: partial infrastructure authentication.

Mutual TLS services and default-account status are observed. Native Docker-local root/FRR CLI access is not a verified 112-random-bit approved-password or network authentication-service arrangement. Implement approved-size lab secret mechanism without exporting passwords; approved generator and organization domain authority remain external.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [native-all-process-inventory-v3](../../../snapshots/2026-10-24T014455Z/native-all-process-inventory-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-064: Incident triggers, required report fields, and reporting deadline

Disposition: external reporting and actionable record schema.

No real confirmed incident, acknowledgement letter, CSfC registration number, JIMS receipt or NSA report was supplied. Local event-trigger/report-field and 24-hour deadline checking can be implemented with synthetic events, clearly labeled. Do not send external reports or invent reporting receipts.

Evidence: [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-065: Separation of administrative and auditing personnel

Disposition: finite service role boundary and external personnel.

A source-bound administration service on one ND Outer enforces a public certificate fingerprint role map. All 21 principal and operation outcomes match the complete exposed API permission table. Host root, Docker and VM host controls remain trusted. Distinct actual people, appointment, clearance and an OS mandatory access policy remain separate requirements.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [native-all-process-inventory-v3](../../../snapshots/2026-10-24T014455Z/native-all-process-inventory-v3), [role-admin-matrix-v3](../../../snapshots/2026-10-24T014455Z/role-admin-matrix-v3), [role-admin-effective-v3](../../../snapshots/2026-10-24T014455Z/role-admin-effective-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-066: Personnel training and physical tamper inspections

Disposition: external training and inspections.

Local IA training completions and periodic physical tamper-inspection records require real personnel and hardware inspection evidence. Remote sysfs observations cannot substitute for physical inspection.

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-067: Revocation or CAK destruction before disposal

Disposition: partial revocation mechanism.

Functional signed revocation updates are observed. Component disposal and prior revocation/CAK destruction ordering require a genuine lifecycle event or bounded owned-device simulation. Public snapshots cannot establish destruction of every private copy.

Evidence: [http-crl-v1](../../../snapshots/2026-10-24T014455Z/http-crl-v1), [http-ocsp-v1](../../../snapshots/2026-10-24T014455Z/http-ocsp-v1).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-068: Security Administrator operational duties

Disposition: external duties and finite service mechanisms.

A Security Administrator test principal can read service state and audit records, change one diagnostic filter and rotate retained audit data. Effective filter readback and audit events are collected. Actual assignment, daily execution, incident escalation, compliance responsibility and full component administration require further implementation or organizational records. Every source duty remains individually visible in the clause register.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3), [role-admin-matrix-v3](../../../snapshots/2026-10-24T014455Z/role-admin-matrix-v3), [role-admin-effective-v3](../../../snapshots/2026-10-24T014455Z/role-admin-effective-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-069: Auditor review duties and access boundary

Disposition: finite Auditor service access and external appointment.

The Auditor test principal can read service state and audit records and rotate retained audit data. It cannot change the diagnostic filter. Denied updates preserve the effective rule. These permissions cover one exposed service boundary on one Outer. Actual Auditor appointment, independent people and review history require records; complete component and OS access boundaries remain separate.

Evidence: [native-management-20261024T015900Z](../../../snapshots/2026-10-24T014455Z/native-management-20261024T015900Z), [native-all-process-inventory-v3](../../../snapshots/2026-10-24T014455Z/native-all-process-inventory-v3), [role-admin-matrix-v3](../../../snapshots/2026-10-24T014455Z/role-admin-matrix-v3), [role-admin-effective-v3](../../../snapshots/2026-10-24T014455Z/role-admin-effective-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-070: Optional Integrator involvement and duty scope

Disposition: external optional integrator.

Integrator use is optional. If selected, role scope, clearance and actual integration duties require records. No integrator involvement is inferred from automated deployment.

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-071: AO authorization evidence and lifecycle control

Disposition: external AO authorization.

AO authorization, risk acceptance and lifecycle approvals require authentic AO records. Formal records with synthetic names may illustrate schema only and must not count as deployment authorization.

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-072: Whole-solution testing and preserved results

Disposition: official testing annex retrieval unavailable and finite tests.

The current official capability page and targeted NSA searches did not expose a public MSC Testing Annex download. Exact search and capture records are retained under references/testing-annex-search. Existing finite functional tests remain useful, but no complete Annex test suite is asserted. Obtaining the applicable Annex or an authorized official test procedure would reopen the exact missing test obligations.

Evidence: [native-baseline-20261024T015000Z](../../../snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z), [families-v9](../../../snapshots/2026-10-24T014455Z/families-v9), [pairings-v7](../../../snapshots/2026-10-24T014455Z/pairings-v7), [ikev2-objective-v6](../../../snapshots/2026-10-24T014455Z/ikev2-objective-v6), [eap-tls-forward-v10](../../../snapshots/2026-10-24T014455Z/eap-tls-forward-v10), [multiworker-behavior-v3](../../../snapshots/2026-10-24T014455Z/multiworker-behavior-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-073: Objective software and firmware signing algorithms

Disposition: finite MLDSA software verification and boot inventory.

An actual Twinet executable is bound to a canonical manifest signed with ML-DSA-87. The verifier checks signature and payload bytes before executing the same opened file descriptor. Modified payload and modified signature both prevent execution. All three checks match. The synthetic publisher, verifier and public-key provisioning are trusted controls. Six-worker legacy boot inventory does not establish a signed firmware chain. Signing every component dependency and firmware, enforcing that chain and actual publisher approval remain separate.

Evidence: [physical-capability-inventory-v4](../../../snapshots/2026-10-24T014455Z/physical-capability-inventory-v4), [software-signing-v3](../../../snapshots/2026-10-24T014455Z/software-signing-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-074: Redundant component and load-balancing permission

Disposition: finite load and manual failover.

Four simultaneous native Red flows are split across both Outer pairs. All8 Outer counters increase by 20 packets with unchanged SPIs. Disabling pair 1 blocks levels 1 and 2 while levels 3 and 4 continue; manual FRR route replacement restores all four. Initial restoration timeout and exact-static-route repair with four positive probes are retained. Automatic failover and every component applicable requirement remain unchecked.

Evidence: [native-redundant-20261024T020100Z](../../../snapshots/2026-10-24T014455Z/native-redundant-20261024T020100Z), [native-shared-four-levels-20261024T015300Z-coverage-v1](../../../snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1), [native-redundancy-events-v3](../../../snapshots/2026-10-24T014455Z/native-redundancy-events-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-075: Optional additional controls and screening-router scope

Disposition: partial optional controls.

Existing and added screening-router arrangements pass useful nested traffic/loss/recovery tests. Optional controls cannot bypass required protection. IPS component-list identity and actual organizational approval remain separate if that option is selected.

Evidence: [utility-v3](../../../snapshots/2026-10-24T014455Z/utility-v3).

The exact source clauses and their independent completion status remain in the machine-readable register.

### RG-076: CP user legal undertaking and disclaimer

Disposition: external legal undertaking.

The CP's legal disclaimer and user undertaking are source requirements on actual users/organizations. No click-through or undertaking was supplied. Runtime emulation cannot establish acceptance.

The exact source clauses and their independent completion status remain in the machine-readable register.

