# Reading the ten CSfC requirements in Lean

Each row links a CSfC passage to the Lean condition that implements the chosen reading. Page numbers count from the first page of the PDF. The last column gives a hypothetical failure. The evidence below each table links to actual checked examples.

A recorded input is a field from a saved capture or derived export. A declared input states what the network is meant to do. An assumption supplies a fact the caller must justify. A Lean proof checks what follows from those inputs. An accepted or rejected example shows which conditions a particular deployment actually exercises.

The packet proofs for RG-007, RG-008, RG-029 and RG-030 require a forwarding model that covers the deployment. Coverage binds device steps, eligible sources, valid setup history, links and identities to the model. It also requires a nonempty Red inventory and an emission for each Red network. The processing model adds fixed installed associations and a specific ESP cipher profile. Those are conditions of the proof model. The CSfC passages below supply the network requirements. [`ForwardingModel.CoversDeployment`](../TDN/Requirements/MscComplianceSchema.lean#L1609) [`DeviceExecutionBinding.ProcessingBound`](../TDN/Requirements/MscComplianceSchema.lean#L1485)

A proof under a false condition holds without exercising any traffic. Read each positive example together with its profile and its exclusion example. The IPv4 firewall profiles and the captured link-layer program exercise different portions of the specifications.

## RG-007 Two independent encryption layers and allowed tunnel pairings

Whole-deployment specification [`nested_layer_protection`](../TDN/Requirements/MscRequirements.lean#L6).

A flow names two tunnels and the two Red networks. The trace records which tunnel handled the same payload. Exact layer lists implement the Red, Gray and Black data definitions. The phrase “at least two” on PDF page 22 alone would permit an additional layer. Cryptographic independence is an explicit input. Page 22 also names administrative workstations. This target checks the CA, key generator and Gray Firewall conditions there. Workstation provisioning belongs to the administration requirements. The clause about workstations concerns their presence. Stack and event proofs establish the modeled processing order. Confidentiality and integrity of the encryption operation depend on the supplied primitive. The general flow selector can inspect the complete trace. The two deployed applications fix the flow from the initial state.

An independent agent reviewed these passages, interpretations and evidence examples against the Lean definitions.

| Source | Lean condition | What the condition means | Example failure |
| --- | --- | --- | --- |
| [1](#rg-007-source-1), [2](#rg-007-source-2), [4](#rg-007-source-4), [5](#rg-007-source-5), [11](#rg-007-source-11), [12](#rg-007-source-12), [13](#rg-007-source-13), [14](#rg-007-source-14), [15](#rg-007-source-15), [16](#rg-007-source-16), [18](#rg-007-source-18), [19](#rg-007-source-19) | [`Flow.Valid`](../TDN/Requirements/ScopedMscRequirements.lean#L19) | Choose one Inner and one Outer tunnel and require independent key contexts. IPsec and MACsec can each occupy either layer. Table 1 on PDF page 19 lists all four combinations. | Both named layers use one key context that the independence relation rejects. |
| [3](#rg-007-source-3), [5](#rg-007-source-5), [11](#rg-007-source-11), [14](#rg-007-source-14), [15](#rg-007-source-15) | [`Flow.Valid`](../TDN/Requirements/ScopedMscRequirements.lean#L23) | Each end is infrastructure of the proper kind and layer. A flow joins different sites and uses the Inner devices assigned to its Red networks. | An IPsec tunnel terminates on a device recorded as a MACsec device. |
| [17](#rg-007-source-17) | [`Flow.Valid`](../TDN/Requirements/ScopedMscRequirements.lean#L33) | An Outer MACsec flow limits all in-scope Outer devices to two sites. | A third site has an Outer device in the same solution. |
| [20](#rg-007-source-20) | [`ArchitectureServices`](../TDN/Requirements/ScopedMscRequirements.lean#L48) | Certificate users have a CA, pre-shared CAK users have a key generator, and different-level Inners sharing an Outer require a Gray Firewall. | Two levels share an Outer and the deployment lists no Gray Firewall. |
| [1](#rg-007-source-1), [6](#rg-007-source-6), [8](#rg-007-source-8), [9](#rg-007-source-9), [10](#rg-007-source-10), [11](#rg-007-source-11), [18](#rg-007-source-18), [19](#rg-007-source-19) | [`scoped_nested_layer_protection`](../TDN/Requirements/ScopedMscRequirements.lean#L66) | An injected payload selects a declared flow starting on its actual Red network. On Gray egress it carries exactly the selected Inner layer after Inner encryption. | A Red payload leaves Gray with a different flow’s Inner tunnel. |
| [1](#rg-007-source-1), [6](#rg-007-source-6), [10](#rg-007-source-10), [18](#rg-007-source-18), [19](#rg-007-source-19) | [`scoped_nested_layer_protection`](../TDN/Requirements/ScopedMscRequirements.lean#L75) | Black egress carries the Outer layer around the Inner layer. The two encryption events must already have occurred in that order. Black reception requires the same two identified layers. | The stack has the expected length but the trace records Outer encryption first. |
| [7](#rg-007-source-7), [9](#rg-007-source-9) | [`scoped_nested_layer_protection`](../TDN/Requirements/ScopedMscRequirements.lean#L86) | A delivered payload that was injected and crossed Black reaches its declared destination in plaintext after Outer and then Inner decryption. | A payload reaches a different Red network after its two layers are removed. |

Additional conditions and definitions. [`Flow.Valid`](../TDN/Requirements/ScopedMscRequirements.lean#L16) [`AuthenticationServices`](../TDN/Requirements/ScopedMscRequirements.lean#L37) [`ForwardingModel.CoversDeployment`](../TDN/Requirements/MscComplianceSchema.lean#L1609) [`DeviceExecutionBinding.ProcessingBound`](../TDN/Requirements/MscComplianceSchema.lean#L1485)

### Evidence and assumptions

**Two-level IPsec**

- Recorded inputs. [BaselineIPsec.json](../data/evidence/nestedProtection/BaselineIPsec.json) `authenticationBindings`, [BaselineIPsec.json](../data/evidence/nestedProtection/BaselineIPsec.json) `contexts`
- Declared inputs. The source flow selects the intended Inner and Outer peers.
- Conditions on the result. The caller supplies the GCM implementation and evidence that the two identified key contexts are independent.
- Checked example. [`snapshot_rg007_ipsec_nonempty_payload_delivered`](../TDN/Deployments/NestedProtection_BaselineSampleTrace.lean#L9).
- Rejection or counterexample. [`snapshot_rg007_missing_key_independence_rejected`](../TDN/Deployments/NestedProtection_BaselineSampleTrace.lean#L21).

**Inner IPsec and Outer MACsec**

- Recorded inputs. [MixedIPsecMACsec.json](../data/evidence/nestedProtection/MixedIPsecMACsec.json) `records`, [MixedDeliveryPlans.json](../data/evidence/nestedProtection/MixedDeliveryPlans.json) `plans`
- Declared inputs. The deployment specifies its Red source domains and the two layer roles.
- Conditions on the result. The caller supplies key independence for the declared contexts.
- Checked example. [`snapshot_rg007_hybrid_ipsec_macsec_forward_payload_delivered`](../TDN/Deployments/NestedProtection_HybridIpsecMacsecSampleTrace.lean#L64).
- Rejection or counterexample. [`snapshot_rg007_hybrid_ipsec_macsec_missing_key_independence_rejected`](../TDN/Deployments/NestedProtection_HybridIpsecMacsecSampleTrace.lean#L81).

<details>
<summary>Original passages and page links</summary>

<a id="rg-007-source-1"></a>1. [PDF p. 10](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=10) `p010:u005.s001` The MSC Solution uses two nested, independent encryption tunnels to protect the confidentiality and integrity of data as it transits the untrusted network.

<a id="rg-007-source-2"></a>2. [PDF p. 10](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=10) `p010:u005.s002` The two encryption tunnels protecting a data flow can use either Internet Protocol Security (IPsec) generated by a Virtual Private Network (VPN) Gateway or Media Access Control Security (MACsec) generated by a MACsec Device.

<a id="rg-007-source-3"></a>3. [PDF p. 10](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=10) `p010:u005.s003` VPN Gateways and MACsec Devices are implemented as part of the network infrastructure.

<a id="rg-007-source-4"></a>4. [PDF p. 10](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=10) `p010:u006.s001` Throughout this CP, the term “Encryption Component” refers generically to either a VPN Gateway or a MACsec Device.

<a id="rg-007-source-5"></a>5. [PDF p. 10](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=10) `p010:u006.s002` “Inner Encryption Component” refers to the component that terminates the Inner layer of encryption and “Outer Encryption Component” refers to the component that terminates the Outer layer of encryption.

<a id="rg-007-source-6"></a>6. [PDF p. 10](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=10) `p010:u007.s001` As shown in Figure 1, before being sent across the untrusted network, each packet or frame of classified data is encrypted twice; first by an Inner Encryption Component, and then by an Outer Encryption Component.

<a id="rg-007-source-7"></a>7. [PDF p. 10](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=10) `p010:u007.s002` At the other end of the data flow, the received packet is correspondingly decrypted twice; first by an Outer Encryption Component, and then by an Inner Encryption Component.

<a id="rg-007-source-8"></a>8. [PDF p. 12](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=12) `p012:u006.s001` Data plane traffic is classified information, encrypted or unencrypted, that passes through the MSC Solution.

<a id="rg-007-source-9"></a>9. [PDF p. 12](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=12) `p012:u006.s002` The MSC Solution exists to encrypt and decrypt data plane traffic.

<a id="rg-007-source-10"></a>10. [PDF p. 12](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=12) `p012:u006.s003` All data plane traffic within the Gray and Black Networks is encapsulated within the IPsec’s Encapsulating Security Payload (ESP) and/or MACsec protocols.

<a id="rg-007-source-11"></a>11. [PDF p. 14](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=14) `p014:u002.s001` There are two layers of encryption tunnels between any pair of sites communicating directly with one another; one encryption tunnel between their Outer Encryption Components, and a second encryption tunnel between their Inner Encryption Components.

<a id="rg-007-source-12"></a>12. [PDF p. 14](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=14) `p014:u002.s002` Each set of Inner or Outer Encryption Components can provide encryption using either IPsec or MACsec.

<a id="rg-007-source-13"></a>13. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u007.s001` Each layer of the MSC Solution can use either an IPsec tunnel or MACsec tunnel.

<a id="rg-007-source-14"></a>14. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u007.s002` An IPsec tunnel is established between VPN Gateways.

<a id="rg-007-source-15"></a>15. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u007.s003` A MACsec tunnel is established between MACsec Devices.

<a id="rg-007-source-16"></a>16. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u007.s004` Table 1 identifies four different layering options provided by this CP.

<a id="rg-007-source-17"></a>17. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u007.s005` For configurations 2 and 4 which use an outer MACsec tunnel these solutions would only be point to point solutions instead of a multi-site solution.

<a id="rg-007-source-18"></a>18. [PDF p. 22](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=22) `p022:u004.s001` In the high-level designs discussed in Section 4.

<a id="rg-007-source-19"></a>19. [PDF p. 22](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=22) `p022:u004.s002` 2, all communications flowing across a Black Network are protected by at least two layers of encryption, implemented using IPsec tunnels generated by VPN Gateways or MACsec tunnels generated by MACsec Devices.

<a id="rg-007-source-20"></a>20. [PDF p. 22](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=22) `p022:u004.s003` Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

Additional context

- [PDF p. 19](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=19) `p019:u003` 1 IPsec IPsec
- [PDF p. 19](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=19) `p019:u004` 2 IPsec MACsec
- [PDF p. 19](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=19) `p019:u005` 3 MACsec IPsec
- [PDF p. 19](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=19) `p019:u006` 4 MACsec MACsec

</details>

## RG-008 Connectivity restricted to the same security level

Whole-deployment specification [`security_level_connectivity`](../TDN/Requirements/MscRequirements.lean#L10).

Security level includes classification, compartments, release controls and other controls. The reached safety conclusion compares the entire level. Forwarding, solution references and inherited duties can be inspected separately. For an enclave, Applicable admits all 76 catalog cases and Contains spans all devices. Each case still has its own conditions. The standalone baseline has no unclassified enclave and no referenced solution. The shared example includes an unclassified enclave and exercises the physical-host duty.

An independent agent reviewed these passages, interpretations and evidence examples against the Lean definitions.

| Source | Lean condition | What the condition means | Example failure |
| --- | --- | --- | --- |
| [1](#rg-008-source-1), [2](#rg-008-source-2), [3](#rg-008-source-3), [4](#rg-008-source-4), [5](#rg-008-source-5), [7](#rg-008-source-7), [9](#rg-008-source-9), [10](#rg-008-source-10), [11](#rg-008-source-11), [12](#rg-008-source-12), [13](#rg-008-source-13), [15](#rg-008-source-15) | [`scoped_security_level_connectivity`](../TDN/Requirements/ScopedMscRequirements.lean#L93) | Every Red network has dedicated Inner assignments at its own level. The network list can include several levels, shared Outer infrastructure and unclassified networks. The importer must supply a complete inventory. | Two Red networks share the same dedicated Inner component. |
| [2](#rg-008-source-2), [6](#rg-008-source-6), [8](#rg-008-source-8), [14](#rg-008-source-14), [16](#rg-008-source-16) | [`scoped_security_level_connectivity`](../TDN/Requirements/ScopedMscRequirements.lean#L97) | Every listed authenticated pair and every installed tunnel pair joins Inner devices at equal levels. VG-15 explicitly describes Inner VPN gateways. The model checks every listed Inner pair. | Two recorded Inner peers authenticate across different dissemination controls. |
| [1](#rg-008-source-1), [2](#rg-008-source-2), [5](#rg-008-source-5), [6](#rg-008-source-6), [8](#rg-008-source-8), [14](#rg-008-source-14) | [`scoped_security_level_connectivity`](../TDN/Requirements/ScopedMscRequirements.lean#L101) | For every permitted execution, a packet delivered after injection comes from and ends at recorded Red networks with the same full level. | A packet from Secret/US-only reaches Secret/Coalition. |
| [2](#rg-008-source-2), [8](#rg-008-source-8), [14](#rg-008-source-14) | [`scoped_security_level_connectivity`](../TDN/Requirements/ScopedMscRequirements.lean#L105) | For every intended pair supplied by the deployment, an actual forwarding trace injects and delivers a plaintext payload. The caller must identify the intended pairs. | A required same-level pair can authenticate but has no delivery trace. |
| [12](#rg-008-source-12), [13](#rg-008-source-13) | [`security_level_connectivity`](../TDN/Requirements/MscRequirements.lean#L14) | The model adds a closed list as evidence when relying on another MSC solution. Every declared reference must resolve to a context satisfying the applicable duties of that solution. | A declared referenced solution has no possible context that satisfies its applicable duties. |
| [12](#rg-008-source-12), [13](#rg-008-source-13) | [`security_level_connectivity`](../TDN/Requirements/MscRequirements.lean#L15) | Each included unclassified network is in the Red inventory and satisfies the duties that apply to it. The full target therefore also covers matters outside forwarding. | An included network’s Inner and Outer components share a physical host in violation of PS-11. |

Additional conditions and definitions. [`DedicatedInnerAssignments`](../TDN/Requirements/TwoLayerOverlayArchitecture.lean#L20) [`ForwardingModel.CoversDeployment`](../TDN/Requirements/MscComplianceSchema.lean#L1609) [`ComplianceContext.Applicable`](../TDN/Requirements/CsfcRoleObligations.lean#L383) [`ComplianceContext.ScopedDeployment`](../TDN/Requirements/CsfcRoleObligations.lean#L120) [`VerificationScope.Contains`](../TDN/Requirements/CsfcRoleObligations.lean#L89) [`ReferencesClosed`](../TDN/Requirements/CsfcRoleObligations.lean#L425) [`ComplianceContext.AllApplicableDuties`](../TDN/Requirements/CsfcRoleObligations.lean#L419)

### Evidence and assumptions

**Baseline**

- Recorded inputs. [Baseline.json](../data/evidence/securityLevelConnectivity/Baseline.json) `capture`, [Baseline.json](../data/evidence/securityLevelConnectivity/Baseline.json) `plans`
- Declared inputs. The intended pairs and their full security labels are checked against the roster and assigned networks.
- Conditions on the result. The GCM interface is supplied. The standalone roster declares no referenced solution. Host-based claims depend on the observed placement records.
- Checked example. [`SecurityLevelConnectivity_BaselinePaths.required_pairs_have_forwarding_traces`](../TDN/Deployments/SecurityLevelConnectivity_BaselinePaths.lean#L53).
- Observed cross-level no-reply probes and intended deliveries. [`SecurityLevelConnectivity_Baseline.intended_pairs_and_observed_probe_matrix`](../TDN/Deployments/SecurityLevelConnectivity_Baseline.lean#L27).

**Shared**

- Recorded inputs. [Shared.json](../data/evidence/securityLevelConnectivity/Shared.json) `capture`, [Shared.json](../data/evidence/securityLevelConnectivity/Shared.json) `plans`
- Declared inputs. The intended pairs and their full security labels are checked against the roster and assigned networks.
- Conditions on the result. The GCM interface is supplied. The standalone roster declares no referenced solution. Host-based claims depend on the observed placement records.
- Checked example. [`SecurityLevelConnectivity_SharedPaths.required_pairs_have_forwarding_traces`](../TDN/Deployments/SecurityLevelConnectivity_SharedPaths.lean#L56).
- Rejection or counterexample. [`SecurityLevelConnectivity_Shared.snapshot_rg008_shared_physical_separation_failure`](../TDN/Deployments/SecurityLevelConnectivity_Shared.lean#L100).

<details>
<summary>Original passages and page links</summary>

<a id="rg-008-source-1"></a>1. [PDF p. 10](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=10) `p010:u004.s001` This CP describes a general MSC Solution to protect classified information as it travels across either an untrusted Network, or a different security level network.

<a id="rg-008-source-2"></a>2. [PDF p. 10](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=10) `p010:u004.s002` The solution supports interconnecting two or more networks operating at the same security level via encryption tunnels, where the security level encompasses the classification level, list of compartments, dissemination controls, and other such controls over information.

<a id="rg-008-source-3"></a>3. [PDF p. 10](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=10) `p010:u004.s003` The solution provides sufficient flexibility to be applicable to many use cases of MSC implementations.

<a id="rg-008-source-4"></a>4. [PDF p. 11](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=11) `p011:u005.s002` The Red Network is logically located behind an Inner Encryption Component.

<a id="rg-008-source-5"></a>5. [PDF p. 11](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=11) `p011:u005.s003` The networks connected to one another through the MSC Solution are Red Networks.

<a id="rg-008-source-6"></a>6. [PDF p. 11](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=11) `p011:u005.s004` Red Networks may only communicate with one another through the MSC Solution if the networks operate at the same security level.

<a id="rg-008-source-7"></a>7. [PDF p. 15](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=15) `p015:u007.s001` A single implementation of the MSC Solution may support Red Networks of different security levels.

<a id="rg-008-source-8"></a>8. [PDF p. 15](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=15) `p015:u007.s002` The MSC Solution provides secure connectivity between the Red Networks within each security level while preventing Red Networks of different security levels from communicating with one another.

<a id="rg-008-source-9"></a>9. [PDF p. 15](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=15) `p015:u007.s003` This enables a customer to use the same physical infrastructure to carry traffic from multiple networks.

<a id="rg-008-source-10"></a>10. [PDF p. 15](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=15) `p015:u007.s004` Although each Red Network requires its own Inner Encryption Component, a site may use a single Outer Encryption Component to encrypt and transport traffic that has been encrypted by Inner Encryption Components of varying security levels.

<a id="rg-008-source-11"></a>11. [PDF p. 16](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=16) `p016:u001.s001` There is no limit to the number of different security levels that an MSC Solution may support.

<a id="rg-008-source-12"></a>12. [PDF p. 16](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=16) `p016:u001.s002` An unclassified network can also be included behind the Outer Encryption Component but must be behind its own Inner Encryption Component and meet the requirements in this CP as if it was a Red Network.

<a id="rg-008-source-13"></a>13. [PDF p. 17](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=17) `p017:u003.s001` A single implementation of the MSC Solution may support Red Networks of different security levels, to include unclassified networks.

<a id="rg-008-source-14"></a>14. [PDF p. 17](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=17) `p017:u003.s002` The MSC Solution provides secure connectivity between the Red Networks within each security level while preventing Red Networks of different security levels from communicating with one another.

<a id="rg-008-source-15"></a>15. [PDF p. 17](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=17) `p017:u003.s003` This enables a customer to use the same infrastructure to carry traffic from multiple networks.

<a id="rg-008-source-16"></a>16. [PDF p. 39](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=39) `p039:u007` MSC-VG-15 Inner VPN Gateways must only authenticate and establish an IPsec tunnel with one another if their Red Networks operate at the same security level as defined in this CP. T=O

</details>

## RG-013 Gray Firewalls on all paths needing level separation

Whole-deployment specification [`gray_firewall_path_coverage`](../TDN/Requirements/MscRequirements.lean#L17).

The graph represents physical connectivity. Its edges, the highest security level and the ordering of levels enter as inputs. Bidirectional physical links must be represented in both directions. Lean compares graph roles with the inventory. Local CA identification is supplied in one direction. Policy checks identify peers by address and by their device identities. The authority supplies the physical-protection fact. Packet filtering uses the processing inventory. Without a processing inventory there can be no admitted traffic, even on a connected graph. The examples check positive and rejected traffic separately. Management filtering covers all traffic between identified AW/local CA and non-highest Inner endpoints.

An independent agent reviewed these passages, interpretations and evidence examples against the Lean definitions.

| Source | Lean condition | What the condition means | Example failure |
| --- | --- | --- | --- |
| [1](#rg-013-source-1), [2](#rg-013-source-2), [3](#rg-013-source-3), [4](#rg-013-source-4), [5](#rg-013-source-5), [6](#rg-013-source-6), [7](#rg-013-source-7), [8](#rg-013-source-8), [11](#rg-013-source-11), [12](#rg-013-source-12), [13](#rg-013-source-13), [14](#rg-013-source-14), [15](#rg-013-source-15), [19](#rg-013-source-19), [20](#rg-013-source-20), [21](#rg-013-source-21), [22](#rg-013-source-22), [23](#rg-013-source-23), [26](#rg-013-source-26), [28](#rg-013-source-28) | [`graph_gray_firewall_waypointing`](../TDN/Requirements/MscFirewallWaypointingTheorems.lean#L94) | Every path between different-level Inners crosses a Gray Firewall. At least one firewall exists when the solution has two such levels. The interrupted section reference on page 17 introduces the reason for filtering. | Two different-level Inners have a direct Gray link. |
| [9](#rg-013-source-9), [10](#rg-013-source-10), [24](#rg-013-source-24), [29](#rg-013-source-29) | [`scoped_gray_firewall_path_coverage`](../TDN/Requirements/ScopedMscRequirements.lean#L156) | Gray workstations and local CAs share the highest level. Paths to a different-level Inner from a workstation, Gray CA or revocation service cross a firewall. Firewall rules block any admitted traffic between an identified AW or local CA and a non-highest Inner in either direction. | A Gray revocation server directly reaches an Inner at another level. |
| [8](#rg-013-source-8), [16](#rg-013-source-16), [17](#rg-013-source-17), [23](#rg-013-source-23), [27](#rg-013-source-27) | [`FiltersIntendedPeers`](../TDN/Requirements/ScopedMscRequirements.lean#L136) | Gray Firewalls and Outer devices filter identified Inner peers by intended communication and full security level. The implication starts when both endpoints are identified as Inner devices. | A firewall permits a packet between identified same-level Inners that are not intended peers. |
| [11](#rg-013-source-11), [12](#rg-013-source-12), [15](#rg-013-source-15), [18](#rg-013-source-18), [22](#rg-013-source-22), [25](#rg-013-source-25) | [`graph_gray_firewall_waypointing`](../TDN/Requirements/MscFirewallWaypointingTheorems.lean#L102) | Each Gray Firewall has filtering and physical protection appropriate for classified equipment. The formal placement also asks for paths from an Inner to each firewall and from that firewall to an Outer. | A listed firewall has valid rules but lacks the required physical protection. |

Additional conditions and definitions. [`Deployment.AddressInventoryCoherent`](../TDN/Requirements/MscComplianceSchema.lean#L989) [`GrayManagement`](../TDN/Requirements/ScopedMscRequirements.lean#L124) [`FiltersIntendedPeers`](../TDN/Requirements/ScopedMscRequirements.lean#L132) [`Deployment.SameLevelInner`](../TDN/Requirements/MscComplianceSchema.lean#L1123) [`graph_gray_firewall_waypointing`](../TDN/Requirements/MscFirewallWaypointingTheorems.lean#L90)

### Evidence and assumptions

**Declared Gray network and management-free variant**

- Recorded inputs. The fixture is defined directly in Lean.
- Declared inputs. The Lean example defines its own graph, levels, roles and eligible filter traffic. The management-free variant supplies a separate role inventory.
- Conditions on the result. Classified physical protection is an authority-supplied premise. The complete example is a model witness. The positive packet and bypass regressions use the first graph.
- Checked example. [`same_level_inner_traffic_is_admitted`](../TDN/Deployments/SnapshotProof_GrayFirewall.lean#L168).
- Rejection or counterexample. [`direct_cross_level_bypass_fails_local_edge_check`](../TDN/Deployments/SnapshotProof_GrayFirewall.lean#L219).
- Related proofs. [`management_free_chain_model_rg013`](../TDN/Deployments/SnapshotProof_GrayFirewallReuse.lean#L64)

<details>
<summary>Original passages and page links</summary>

<a id="rg-013-source-1"></a>1. [PDF p. 17](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=17) `p017:u004.s001` For Red Networks of different security levels, the cryptographic separation of their traffic on a Gray Network, as described in Section 4.

<a id="rg-013-source-2"></a>2. [PDF p. 17](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=17) `p017:u004.s002` 2.

<a id="rg-013-source-3"></a>3. [PDF p. 17](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=17) `p017:u004.s003` 2.

<a id="rg-013-source-4"></a>4. [PDF p. 17](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=17) `p017:u004.s004` 1, is still present.

<a id="rg-013-source-5"></a>5. [PDF p. 17](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=17) `p017:u004.s005` However, because the consequences of an unintended data flow between different security levels are more severe than of one with a single security level, an additional mechanism is necessary to prevent such a flow from occurring.

<a id="rg-013-source-6"></a>6. [PDF p. 17](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=17) `p017:u005.s001` This CP uses packet filtering within Gray Networks as an additional mechanism to prevent data flows between networks of different security levels.

<a id="rg-013-source-7"></a>7. [PDF p. 17](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=17) `p017:u005.s002` Any physical path through a Gray Network between multiple Inner Encryption Components supporting Red Networks of different security levels must include at least one filtering component.

<a id="rg-013-source-8"></a>8. [PDF p. 17](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=17) `p017:u005.s003` This filtering component restricts the traffic flow based primarily on the Gray Network source and destination addresses, and only allows a packet through if the source and destination components intend to communicate with one another and drops the packet if they are not.

<a id="rg-013-source-9"></a>9. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u001.s001` Additionally, filtering components are included between the components used for management of the Gray Networks themselves (namely, AWs and locally run CAs) and Inner Encryption Components that support Red Networks of a lower security level than the Red Network with the highest security level supported by the solution.

<a id="rg-013-source-10"></a>10. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u001.s002` In other words, AWs and locally run CAs on Gray Networks are treated as, and grouped with, the Inner Encryption Component for the Red Network with the highest security level.

<a id="rg-013-source-11"></a>11. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u002.s001` One or more Gray Firewalls must be included in the Gray Network to perform filtering.

<a id="rg-013-source-12"></a>12. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u002.s002` Standalone Gray Firewalls have been placed at each site between the Inner Encryption Components and the Outer Encryption Component; these Gray Firewalls are responsible for dropping packets between Inner Encryption Components of different security levels.

<a id="rg-013-source-13"></a>13. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u003.s001` Figure 6.

<a id="rg-013-source-14"></a>14. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u003.s002` MSC Solution for Networks at Different Security Levels

<a id="rg-013-source-15"></a>15. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u004.s001` Figure 6 also shows an example placement of Gray Firewalls, as long as any path between Inner Encryption Components for networks of different security levels includes a Gray Firewall.

<a id="rg-013-source-16"></a>16. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u005.s001` Including one or more standalone Gray Firewalls in a solution does not remove the requirement to perform the filtering on the Outer Encryption Component as well.

<a id="rg-013-source-17"></a>17. [PDF p. 18](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=18) `p018:u005.s002` Outer Encryption Components are uniquely positioned to block traffic between Inner Encryption Components supporting Red Networks of different security levels when one of those Inner Encryption Components is located at a different site.

<a id="rg-013-source-18"></a>18. [PDF p. 24](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=24) `p024:u005.s001` The Gray Firewall is located between the Outer Encryption Component and Inner Encryption Component(s).

<a id="rg-013-source-19"></a>19. [PDF p. 24](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=24) `p024:u005.s002` As described in Section 4.

<a id="rg-013-source-20"></a>20. [PDF p. 24](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=24) `p024:u005.s003` 2.

<a id="rg-013-source-21"></a>21. [PDF p. 24](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=24) `p024:u005.s004` 2.

<a id="rg-013-source-22"></a>22. [PDF p. 24](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=24) `p024:u005.s005` 2, an MSC Solution that supports multiple Red Networks of different security levels must include one or more Gray Firewalls.

<a id="rg-013-source-23"></a>23. [PDF p. 24](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=24) `p024:u005.s006` The Gray Firewall blocks any packets sent between Inner Encryption Components for Red Networks of different security levels.

<a id="rg-013-source-24"></a>24. [PDF p. 24](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=24) `p024:u005.s007` A Gray Firewall also blocks any packets sent between management components on the Gray Network and Inner Encryption Components for Red Networks that operate at a security level other than the highest security level of data protected by the solution.

<a id="rg-013-source-25"></a>25. [PDF p. 24](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=24) `p024:u005.s008` Gray Firewalls are physically protected as classified devices.

<a id="rg-013-source-26"></a>26. [PDF p. 24](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=24) `p024:u006.s002` A Gray Firewall would typically only be used in solutions where the physical design of the Gray Network includes paths between Inner Encryption Components for Red Networks of different security levels that do not pass through the Outer Encryption Components.

<a id="rg-013-source-27"></a>27. [PDF p. 24](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=24) `p024:u006.s003` Effectively, each Gray Firewall is another instance of the Gray Network filtering performed by the Outer Encryption Component.

<a id="rg-013-source-28"></a>28. [PDF p. 35](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=35) `p035:u009` MSC-SR-7 All physical paths within a Gray Network between Inner Encryption Components for Red Networks of different security levels must include a Gray Firewall. T=O

<a id="rg-013-source-29"></a>29. [PDF p. 35](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=35) `p035:u010` MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

</details>

## RG-029 Inner encryption and decryption cannot be bypassed

Whole-deployment specification [`inner_tunnel_no_bypass`](../TDN/Requirements/MscRequirements.lean#L20).

The no-bypass predicate pairs receive and transmit events on the same device and follows a payload identifier. It also checks external transmissions. The shared predicate excludes genuine control in both directions. The IR rows do not state that blanket exception. For split tunneling it checks a listed tunnel at the correct layer and device. Identifying the particular tunnel selected for the payload is a stronger claim. The native application interprets the associated IP tunnel through correlated ESP tunnel-mode evidence. The directional mandatory-access settings are checked separately from packet behavior. The proof does not attribute each individual decision to that setting.

An independent agent reviewed these passages, interpretations and evidence examples against the Lean definitions.

| Source | Lean condition | What the condition means | Example failure |
| --- | --- | --- | --- |
| [2](#rg-029-source-2) | [`scoped_inner_tunnel_no_bypass`](../TDN/Requirements/ScopedMscRequirements.lean#L220) | Every listed Inner IPsec gateway uses ESP tunnel mode with an associated IP tunnel. Every in-scope Inner has a matching protocol record. | An Inner gateway uses transport mode. |
| [1](#rg-029-source-1), [3](#rg-029-source-3), [7](#rg-029-source-7), [8](#rg-029-source-8), [9](#rg-029-source-9) | [`TraceNoBypass`](../TDN/Requirements/ScopedMscRequirements.lean#L190) | A protected Red payload leaving the Inner’s internal zone must be encrypted by a local Inner tunnel before transmission. Every non-control external transmission must show earlier encryption. | An Inner receives a protected packet on Red and sends it to Gray unchanged. |
| [1](#rg-029-source-1), [5](#rg-029-source-5), [7](#rg-029-source-7), [8](#rg-029-source-8), [9](#rg-029-source-9) | [`TraceNoBypass`](../TDN/Requirements/ScopedMscRequirements.lean#L193) | A packet crossing from Gray into Red must arrive with a local receiving Inner tunnel and be decrypted before it leaves on Red. The check covers paired crossings and external egress. | A packet crosses into Red with no Inner decryption event. |
| [4](#rg-029-source-4), [6](#rg-029-source-6) | [`scoped_inner_tunnel_no_bypass`](../TDN/Requirements/ScopedMscRequirements.lean#L221) | When selected, each directional Mandatory Access Control objective requires the corresponding policy setting. The two objective flags are independent. | The inbound objective is selected and the device has no inbound policy. |

Additional conditions and definitions. [`ComponentConfigurationCoverage`](../TDN/Requirements/ScopedMscRequirements.lean#L208) [`LayerNoBypass`](../TDN/Requirements/ScopedMscRequirements.lean#L204) [`ForwardingModel.CoversDeployment`](../TDN/Requirements/MscComplianceSchema.lean#L1609) [`TraceNoBypass`](../TDN/Requirements/ScopedMscRequirements.lean#L181)

### Evidence and assumptions

**Inner IPsec**

- Recorded inputs. [IPsecDelivery.json](../data/evidence/innerTunnelNoBypass/IPsecDelivery.json) `moves`, [IPsecTunnelBindings.json](../data/evidence/innerTunnelNoBypass/IPsecTunnelBindings.json) `bindings`
- Declared inputs. The deployment identifies the Inner boundary and its selected mandatory-access objectives.
- Conditions on the result. The GCM primitive is supplied. The associated IP tunnel is interpreted from the recorded endpoint, policy, SA and tunnel mode.
- Checked example. [`snapshot_rg029_ipsec_nonempty_payload_delivered`](../TDN/Deployments/InnerTunnelNoBypass_IpsecSampleTrace.lean#L27).
- Rejection or counterexample. [`snapshot_rg029_ipsec_uninstalled_spi_blocked`](../TDN/Deployments/InnerTunnelNoBypass_BlockedTrafficTests.lean#L44).

**Inner MACsec**

- Recorded inputs. [MacsecProtectionProfiles.json](../data/evidence/macsecProtection/MacsecProtectionProfiles.json) `direct`
- Declared inputs. The direct MACsec profile specifies its controlled and physical interfaces. Both optional mandatory-access objectives are off.
- Conditions on the result. The MACsec application uses its own link and receiver model.
- Checked example. [`snapshot_rg029_macsec_nonempty_payload_delivered`](../TDN/Deployments/InnerTunnelNoBypass_Macsec.lean#L138).
- Configuration regression for the selected objective. [`snapshot_rg029_inbound_mac_objective_rejects_missing_policy`](../TDN/Deployments/InnerTunnelNoBypass_BlockedTrafficTests.lean#L121).

<details>
<summary>Original passages and page links</summary>

<a id="rg-029-source-1"></a>1. [PDF p. 25](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=25) `p025:u006.s001` The Inner Encryption Component must not route packets between Red and Gray Networks; any packets received on a Red Network interface and sent to a Gray Network interface must be transmitted within an IPsec or MACsec tunnel configured according to this CP.

<a id="rg-029-source-2"></a>2. [PDF p. 42](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=42) `p042:u018` MSC-IR-1 The Inner VPN Gateway must use ESP Tunnel mode IPsec, with an associated IP tunneling protocol. T=O

<a id="rg-029-source-3"></a>3. [PDF p. 43](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=43) `p043:u003` MSC-IR-3 The Inner Encryption Component must not allow packets received on an interface connected to a Red Network to bypass encryption and be forwarded out through an interface connected to a Gray Network. T MSC-IR-4

<a id="rg-029-source-4"></a>4. [PDF p. 43](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=43) `p043:u004` MSC-IR-4 The Inner Encryption Component must use a Mandatory Access Control policy to not allow packets received on an interface connected to a Red Network to bypass encryption and be forwarded out through an interface connected to a Gray Network. O MSC-IR-3

<a id="rg-029-source-5"></a>5. [PDF p. 43](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=43) `p043:u005` MSC-IR-5 The Inner Encryption Component must not allow packets received on an interface connected to a Gray Network to bypass decryption and be forwarded out through an interface connected to a Red Network. T MSC-IR-6

<a id="rg-029-source-6"></a>6. [PDF p. 43](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=43) `p043:u006` MSC-IR-6 The Inner Encryption Component must use Mandatory Access Control policy to not allow packets received on an interface connected to a Gray Network to bypass decryption and be forwarded out through an interface connected to a Red Network. O MSC-IR-5

<a id="rg-029-source-7"></a>7. [PDF p. 43](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=43) `p043:u007` MSC-IR-7 The Inner Encryption Component must not permit split-tunneling. T=O

<a id="rg-029-source-8"></a>8. [PDF p. 61](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=61) `p061:u010.s001` Split-tunneling – Allows network traffic to egress through a path other than the established encryption tunnel (either on the same interface or another network interface.

<a id="rg-029-source-9"></a>9. [PDF p. 61](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=61) `p061:u010.s002` Split-tunneling is explicitly prohibited in MSC CP compliant configurations.

</details>

## RG-030 Outer encryption and decryption cannot be bypassed

Whole-deployment specification [`outer_tunnel_no_bypass`](../TDN/Requirements/MscRequirements.lean#L26).

OR-4 explicitly exempts control traffic at Gray ingress. The general no-bypass predicate also exempts genuine control on the other crossings, where the table does not repeat the exception. Inbound protection checks packets that traverse Black to Gray on the same device. Local termination and other egress paths are outside that implication. OR-7 uses a same-layer local tunnel, as in the Inner case. The directional mandatory-access settings are checked separately from packet behavior. The proof does not attribute each individual decision to that setting.

An independent agent reviewed these passages, interpretations and evidence examples against the Lean definitions.

| Source | Lean condition | What the condition means | Example failure |
| --- | --- | --- | --- |
| [2](#rg-030-source-2) | [`scoped_outer_tunnel_no_bypass`](../TDN/Requirements/ScopedMscRequirements.lean#L229) | Every Outer has a protocol-matched record and each Outer VPN uses ESP tunnel mode. | An Outer VPN is configured in transport mode. |
| [1](#rg-030-source-1), [3](#rg-030-source-3), [8](#rg-030-source-8) | [`TraceNoBypass`](../TDN/Requirements/ScopedMscRequirements.lean#L190) | For a non-control packet crossing out of Gray, the Outer must encrypt before forwarding. External transmissions also require an earlier Outer encryption event. | An Outer forwards an Inner-only protected packet onto Black. |
| [1](#rg-030-source-1), [6](#rg-030-source-6), [8](#rg-030-source-8) | [`TraceNoBypass`](../TDN/Requirements/ScopedMscRequirements.lean#L193) | A packet crossing from Black into Gray must arrive with the receiving Outer tunnel and undergo Outer decryption on that device. | An Outer forwards an arriving Black packet to Gray before decrypting it. |
| [4](#rg-030-source-4), [7](#rg-030-source-7) | [`scoped_outer_tunnel_no_bypass`](../TDN/Requirements/ScopedMscRequirements.lean#L230) | A selected mandatory-access-control objective requires the corresponding directional policy on each Outer component. | The outbound policy is absent while its objective is selected. |
| [5](#rg-030-source-5) | [`scoped_outer_tunnel_no_bypass`](../TDN/Requirements/ScopedMscRequirements.lean#L236) | Every modeled non-control reception on an Outer Gray interface already has exactly one identified Inner encryption layer. | A plaintext data packet arrives at an Outer Gray interface. |

Additional conditions and definitions. [`ComponentConfigurationCoverage`](../TDN/Requirements/ScopedMscRequirements.lean#L208) [`LayerNoBypass`](../TDN/Requirements/ScopedMscRequirements.lean#L204) [`ForwardingModel.CoversDeployment`](../TDN/Requirements/MscComplianceSchema.lean#L1609) [`TraceNoBypass`](../TDN/Requirements/ScopedMscRequirements.lean#L181)

### Evidence and assumptions

**Baseline**

- Recorded inputs. [BaselineIPsecDelivery.json](../data/evidence/outerTunnelNoBypass/BaselineIPsecDelivery.json) `moves`
- Declared inputs. Role and zone assignments select the Outer boundary. Directional objectives select the corresponding configuration clauses.
- Conditions on the result. The GCM interface is supplied. The observed policies and SAs are fixed for the execution.
- Checked example. [`snapshot_rg030_baseline_nonempty_payload_delivered`](../TDN/Deployments/OuterTunnelNoBypass_BaselineSampleTrace.lean#L27).
- Rejection or counterexample. [`snapshot_rg030_baseline_missing_outer_policy_blocked`](../TDN/Deployments/OuterTunnelNoBypass_BlockedTrafficTests.lean#L38).

**Shared**

- Recorded inputs. [SharedIPsecDelivery.json](../data/evidence/outerTunnelNoBypass/SharedIPsecDelivery.json) `moves`
- Declared inputs. Role and zone assignments select the Outer boundary. Directional objectives select the corresponding configuration clauses.
- Conditions on the result. The GCM interface is supplied. The observed policies and SAs are fixed for the execution.
- Checked example. [`snapshot_rg030_shared_nonempty_payload_delivered`](../TDN/Deployments/OuterTunnelNoBypass_SharedSampleTrace.lean#L27).
- Rejection or counterexample. [`snapshot_rg030_shared_missing_outer_policy_blocked`](../TDN/Deployments/OuterTunnelNoBypass_BlockedTrafficTests.lean#L125).

<details>
<summary>Original passages and page links</summary>

<a id="rg-030-source-1"></a>1. [PDF p. 24](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=24) `p024:u002.s001` The Outer Encryption Component cannot route packets between Gray and Black Networks; any packets received on a Gray Network interface and sent out on a Black Network interface must be transmitted within an IPsec or MACsec tunnel configured according to this CP.

<a id="rg-030-source-2"></a>2. [PDF p. 43](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=43) `p043:u012` MSC-OR-1 Outer VPN Gateways must use ESP Tunnel mode IPsec. T=O

<a id="rg-030-source-3"></a>3. [PDF p. 43](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=43) `p043:u013` MSC-OR-2 Outer Encryption Components must not allow packets received on an interface connected to a Gray Network to bypass encryption and be forwarded out through an interface connected to a Black Network. T MSC-OR-3

<a id="rg-030-source-4"></a>4. [PDF p. 43](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=43) `p043:u014` MSC-OR-3 Outer Encryption Components must use Mandatory Access Control policy to not allow packets received on an interface connected to a Gray Network to O MSC-OR-2 bypass encryption and be forwarded out through an interface connected to a Black Network.

<a id="rg-030-source-5"></a>5. [PDF p. 44](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=44) `p044:u003` MSC-OR-4 All traffic received by Outer Encryption Components on an interface connected to a Gray Network, with the exception of control plane traffic, must have already been encrypted once. T=O

<a id="rg-030-source-6"></a>6. [PDF p. 44](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=44) `p044:u004` MSC-OR-5 Outer Encryption Components must not allow any packets received on an interface connected to a Black Network to bypass decryption. T MSC-OR-6

<a id="rg-030-source-7"></a>7. [PDF p. 44](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=44) `p044:u005` MSC-OR-6 Outer Encryption Components must use Mandatory Access Control policy to not allow any packets received on an interface connected to a Black Network to bypass decryption. O MSC-OR-5

<a id="rg-030-source-8"></a>8. [PDF p. 44](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=44) `p044:u006` MSC-OR-7 The Outer Encryption Components must not permit split-tunneling. T=O

</details>

## RG-034 Outer Firewall placement for untrusted Black transport

Whole-deployment specification [`outer_firewall_placement`](../TDN/Requirements/MscRequirements.lean#L32).

The source requires a firewall for untrusted transport and explicitly names the Public Internet for the interface-to-interface arrangement. Attachments imply graph reachability, which can include intermediate nodes. Internal Gray connectivity is supplied separately from the physical edge relation. The deployment must identify the participating devices and provide actual attachments.

An independent agent reviewed these passages, interpretations and evidence examples against the Lean definitions.

| Source | Lean condition | What the condition means | Example failure |
| --- | --- | --- | --- |
| [1](#rg-034-source-1), [2](#rg-034-source-2), [3](#rg-034-source-3), [4](#rg-034-source-4), [5](#rg-034-source-5), [9](#rg-034-source-9) | [`graph_outer_firewall_placement`](../TDN/Requirements/MscFirewallWaypointingTheorems.lean#L17) | Every graph path from an Outer to untrusted Black passes a firewall. Public Internet counts as untrusted. | A second link reaches untrusted Black around the firewall. |
| [5](#rg-034-source-5), [6](#rg-034-source-6), [9](#rg-034-source-9) | [`graph_outer_firewall_placement`](../TDN/Requirements/MscFirewallWaypointingTheorems.lean#L15) | For Public Internet transport, each Outer attaches to the firewall’s inside and the firewall attaches to Black on its outside. | The Outer and Black both attach on the firewall’s outside. |
| [7](#rg-034-source-7) | [`graph_outer_firewall_placement`](../TDN/Requirements/MscFirewallWaypointingTheorems.lean#L16) | For other transports each Outer has an external Black connection supported by graph reachability. | An Outer lists a Black attachment that is disconnected in the graph. |
| [8](#rg-034-source-8) | [`graph_outer_firewall_placement`](../TDN/Requirements/MscFirewallWaypointingTheorems.lean#L19) | Each Outer connects internally to a Gray Firewall when required, or to an Inner otherwise. | A site requiring a Gray Firewall declares only a direct internal connection to an Inner. |

Additional conditions and definitions. [`graph_outer_firewall_placement`](../TDN/Requirements/MscFirewallWaypointingTheorems.lean#L5)

### Evidence and assumptions

**Baseline**

- Recorded inputs. [Topology_Baseline.json](../data/evidence/Topology_Baseline.json) `TDN.Deployments.native_baseline_20261017T2237Z_topology.insideAttachments`
- Declared inputs. The transport is declared public and untrusted. A Gray Firewall is required.
- Conditions on the result. The graph represents the included physical connections and the side assignments are checked on that graph.
- Checked example. [`SnapshotProof_TopologyWaypointing.Baseline.nonempty_outer_inventory`](../TDN/Deployments/SnapshotProof_TopologyWaypointing.lean#L19).
- Separate four-node regression with an extra link. [`bypass_edge_rejected`](../TDN/Deployments/SnapshotProof_TopologyWaypointing.lean#L77).
- Related proofs. [`SnapshotProof_TopologyWaypointing.Baseline.configured_graph_rg034`](../TDN/Deployments/SnapshotProof_TopologyWaypointing.lean#L10) [`native_baseline_20261017T2237Z_topology.outer_firewall_waypointing`](../TDN/Deployments/Topology_Baseline.lean#L49)

**Shared**

- Recorded inputs. [Topology_SharedOuter.json](../data/evidence/Topology_SharedOuter.json) `TDN.Deployments.native_shared_four_levels_20261017T2240Z_scope_v2_topology.insideAttachments`
- Declared inputs. The transport is declared public and untrusted. A Gray Firewall is required.
- Conditions on the result. The graph represents the included physical connections and the side assignments are checked on that graph.
- Checked example. [`SnapshotProof_TopologyWaypointing.Shared.nonempty_outer_inventory`](../TDN/Deployments/SnapshotProof_TopologyWaypointing.lean#L35).
- Separate four-node regression with an extra link. [`bypass_edge_rejected`](../TDN/Deployments/SnapshotProof_TopologyWaypointing.lean#L77).
- Related proofs. [`SnapshotProof_TopologyWaypointing.Shared.configured_graph_rg034`](../TDN/Deployments/SnapshotProof_TopologyWaypointing.lean#L26) [`native_shared_four_levels_20261017T2240Z_scope_v2_topology.outer_firewall_waypointing`](../TDN/Deployments/Topology_SharedOuter.lean#L49)

<details>
<summary>Original passages and page links</summary>

<a id="rg-034-source-1"></a>1. [PDF p. 12](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=12) `p012:u003.s005` As shown in Figure 2, if the Black Network is an untrusted network such as the Public Internet, an Outer Firewall is required between the Black Network and the Outer Encryption Component.

<a id="rg-034-source-2"></a>2. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u002.s001` An MSC Solution that uses an untrusted network such as the Public Internet as its Black Network must include an Outer Firewall (see Section 4.

<a id="rg-034-source-3"></a>3. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u002.s002` 1.

<a id="rg-034-source-4"></a>4. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u002.s003` 3).

<a id="rg-034-source-5"></a>5. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u002.s004` The Outer Firewall is located at the edge of the MSC Solution and is connected to the Black Network.

<a id="rg-034-source-6"></a>6. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u008.s001` If the Black Network is the Public Internet, the external interface of the Outer Encryption Component is connected to the internal interface of the Outer Firewall.

<a id="rg-034-source-7"></a>7. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u008.s002` Otherwise, the external interface of the Outer Encryption Component is connected to the Black Network.

<a id="rg-034-source-8"></a>8. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u008.s003` The internal interface of the Outer Encryption Component is connected to Gray Firewalls, if required, or Inner Encryption Components.

<a id="rg-034-source-9"></a>9. [PDF p. 36](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=36) `p036:u002` MSC-SR-12 If the MSC Solution uses the Public Internet for its Black transport network, an Outer Firewall must be located between the Black transport network and the Outer Encryption Component. T=O

</details>

## RG-035 Permitted protocols and peers at encryption and firewall boundaries

Whole-deployment specification [`boundary_interface_filtering`](../TDN/Requirements/MscRequirements.lean#L34).

Scope follows the role and side of each interface. Permitted control services and intended peers are policy inputs. Outer Firewall address restrictions are tested on inbound admission outside the approved-control exception on each face. Approval for Inner Gray control applies in both directions in Lean. The page 25 narrative explicitly names approval for egress.

An independent agent reviewed these passages, interpretations and evidence examples against the Lean definitions.

| Source | Lean condition | What the condition means | Example failure |
| --- | --- | --- | --- |
| [3](#rg-035-source-3), [4](#rg-035-source-4), [5](#rg-035-source-5), [6](#rg-035-source-6), [7](#rg-035-source-7), [8](#rg-035-source-8), [9](#rg-035-source-9), [10](#rg-035-source-10), [13](#rg-035-source-13), [14](#rg-035-source-14), [15](#rg-035-source-15) | [`scoped_boundary_interface_filtering`](../TDN/Requirements/ScopedMscRequirements.lean#L263) | Check every Outer Black interface in both directions. A VPN admits IPsec traffic or approved control. A MACsec device admits MACsec or approved control. Egress also requires an intended peer. | An Outer VPN allows an outbound connection to an unrelated destination. |
| [11](#rg-035-source-11), [16](#rg-035-source-16) | [`scoped_boundary_interface_filtering`](../TDN/Requirements/ScopedMscRequirements.lean#L265) | Inner Gray interfaces admit the allowed tunnel protocols or control approved by both policy and the authorizing official. | An Inner Gray interface admits control approved only by a local rule. |
| [12](#rg-035-source-12) | [`scoped_boundary_interface_filtering`](../TDN/Requirements/ScopedMscRequirements.lean#L267) | Inner Red traffic must match a declared Red service address and transport port at either endpoint. | A packet with an arbitrary address and port at each end is admitted. |
| [1](#rg-035-source-1), [2](#rg-035-source-2), [17](#rg-035-source-17) | [`scoped_boundary_interface_filtering`](../TDN/Requirements/ScopedMscRequirements.lean#L272) | A required Outer Firewall admits tunnel traffic or approved control. Inbound packets outside the approved-control exception name the local Outer as source on the inside or destination on the outside. | A packet arriving on the firewall’s outside names another Outer as its destination. |

Additional conditions and definitions. [`Deployment.AddressInventoryCoherent`](../TDN/Requirements/MscComplianceSchema.lean#L989) [`Deployment.ProcessingCoherent`](../TDN/Requirements/MscComplianceSchema.lean#L1280) [`Deployment.UDPBindingsCoherent`](../TDN/Requirements/MscComplianceSchema.lean#L1474) [`Deployment.BoundaryAdmission`](../TDN/Requirements/PerimeterInterfaceSlice.lean#L63) [`AOApprovedControl`](../TDN/Requirements/ScopedMscRequirements.lean#L241) [`LocalOuterAddress`](../TDN/Requirements/ScopedMscRequirements.lean#L244)

### Evidence and assumptions

**Baseline**

- Recorded inputs. [BoundaryBaselineFields.json](../data/evidence/continuation/BoundaryBaselineFields.json) `policies`, [Perimeter_Baseline.json](../data/evidence/continuation/Perimeter_Baseline.json) `controls`, [BoundaryApplicationBaseline.json](../data/evidence/continuation/BoundaryApplicationBaseline.json) `redHTTP`, [BoundaryApplicationBaseline.json](../data/evidence/continuation/BoundaryApplicationBaseline.json) `redWrongPort`
- Declared inputs. Red services, intended peers and approved control traffic are inputs to the policy. Checking a firewall rule alone cannot establish approval.
- Conditions on the result. The example specializes the policy-relevant fields of a deployment supplied as a parameter.
- Checked example. [`Perimeter_Baseline.red_http_is_accepted_at_actual_forward_hook`](../TDN/Deployments/Perimeter_BaselinePolicyChecks.lean#L9).
- Rejection or counterexample. [`Perimeter_Baseline.red_wrong_port_has_real_context_and_is_denied`](../TDN/Deployments/Perimeter_BaselinePolicyChecks.lean#L33).

**Shared**

- Recorded inputs. [BoundarySharedFields.json](../data/evidence/continuation/BoundarySharedFields.json) `policies`, [Perimeter_Shared.json](../data/evidence/continuation/Perimeter_Shared.json) `controls`, [BoundaryApplicationShared.json](../data/evidence/continuation/BoundaryApplicationShared.json) `redHTTP`, [BoundaryApplicationShared.json](../data/evidence/continuation/BoundaryApplicationShared.json) `redWrongPort`
- Declared inputs. Red services, intended peers and approved control traffic are inputs to the policy. Checking a firewall rule alone cannot establish approval.
- Conditions on the result. The example specializes the policy-relevant fields of a deployment supplied as a parameter.
- Checked example. [`Perimeter_Shared.red_http_is_accepted_at_actual_forward_hook`](../TDN/Deployments/Perimeter_SharedPolicyChecks.lean#L9).
- Rejection or counterexample. [`Perimeter_Shared.red_wrong_port_has_real_context_and_is_denied`](../TDN/Deployments/Perimeter_SharedPolicyChecks.lean#L33).

<details>
<summary>Original passages and page links</summary>

<a id="rg-035-source-1"></a>1. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u003.s001` The external interface of the Outer Firewall only permits IPsec or MACsec traffic with a destination address of the Outer Encryption Component.

<a id="rg-035-source-2"></a>2. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u004.s001` The internal interface of the Outer Firewall only permits IPsec or MACsec traffic with a source address of the Outer Encryption Component and any necessary control plane traffic.

<a id="rg-035-source-3"></a>3. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u004.s002` The minimum requirements for port filtering on the Outer Firewall can be found in Section 10.

<a id="rg-035-source-4"></a>4. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u004.s003` 6.

<a id="rg-035-source-5"></a>5. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u009.s001` The Outer Encryption Component may be a perimeter device (if the Outer Firewall is not present) and more exposed to external attacks.

<a id="rg-035-source-6"></a>6. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u009.s002` The Outer Encryption Component may use internal filtering to help protect the network from unauthenticated traffic.

<a id="rg-035-source-7"></a>7. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u009.s003` This allows specification of rules that prohibit unauthorized data flows, which helps mitigate Denial of Service attacks and resource exhaustion.

<a id="rg-035-source-8"></a>8. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u009.s004` This CP does not require that the Outer Encryption Component terminate all tunnels on a single physical interface; however, all such external interfaces must conform to the port filtering requirements in Section 10.

<a id="rg-035-source-9"></a>9. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u009.s005` 6.

<a id="rg-035-source-10"></a>10. [PDF p. 23](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=23) `p023:u009.s006` The Outer Encryption Component is implemented identically for all the high-level designs covered in this CP.

<a id="rg-035-source-11"></a>11. [PDF p. 25](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=25) `p025:u005.s001` Similar to the Outer Encryption Component, the external interface of the Inner Encryption Component only permits egress of IPsec/MACsec traffic and AO-approved control plane traffic.

<a id="rg-035-source-12"></a>12. [PDF p. 25](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=25) `p025:u005.s002` The internal interface of the Inner Encryption Component is configured to only permit traffic with an IP address and port associated with Red Network services.

<a id="rg-035-source-13"></a>13. [PDF p. 44](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=44) `p044:u009` MSC-OR-10 Packets leaving the external interface of the Outer Encryption Component must only make connections with the remote Outer Encryption Component or the other intended device. T=O

<a id="rg-035-source-14"></a>14. [PDF p. 44](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=44) `p044:u016` MSC-PF-3 For all Outer VPN Gateway interfaces connected to a Black Network, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, ESP, and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed. T=O

<a id="rg-035-source-15"></a>15. [PDF p. 44](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=44) `p044:u017` MSC-PF-4 For all Outer MACsec Device interfaces connected to a Black Network, traffic filtering rules must be T=O applied to both inbound and outbound traffic, such that only MACsec Protocol Data Units and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed.

<a id="rg-035-source-16"></a>16. [PDF p. 45](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=45) `p045:u003` MSC-PF-5 For all Inner Encryption Component interfaces connected to a Gray Network, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, IPsec, MKA, MACsec, and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed. T=O

<a id="rg-035-source-17"></a>17. [PDF p. 46](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=46) `p046:u009` MSC-PF-22 If an Outer Firewall is required, for all Outer Firewall interfaces, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, ESP, MKA, MACsec and control plane protocols (as defined in this CP) approved by organization- defined policy are allowed. T=O

</details>

## RG-038 IP header and multicast filtering

Whole-deployment specification [`ip_header_and_multicast_filtering`](../TDN/Requirements/MscRequirements.lean#L39).

The IP protocol checks cover inbound admissions for each VPN. The IPv6 test reads the immediate Next Header. For PF-9, the model interprets the general necessary Layer 2 control allowance as a narrow exception for approved, peer-bound MKA. The literal multicast row states a drop. PF-10 has an Objective designation and a blank alternative cell. The deployment selects the objective per Outer VPN.

An independent agent reviewed these passages, interpretations and evidence examples against the Lean definitions.

| Source | Lean condition | What the condition means | Example failure |
| --- | --- | --- | --- |
| [1](#rg-038-source-1), [2](#rg-038-source-2) | [`NecessaryApprovedL2Control`](../TDN/Requirements/ScopedMscRequirements.lean#L285) | An Outer Black interface drops multicast unless the model establishes approved MKA control with the expected group address, framing, peer and Outer MACsec tunnel. | A matching Ethernet group address alone lets an unrelated sender through. |
| [3](#rg-038-source-3) | [`scoped_ip_header_and_multicast_filtering`](../TDN/Requirements/ScopedMscRequirements.lean#L307) | An Outer VPN that selects PF-10 admits only a five-word IPv4 header. | A packet with a six-word IPv4 header is admitted on that gateway. |
| [4](#rg-038-source-4) | [`scoped_ip_header_and_multicast_filtering`](../TDN/Requirements/ScopedMscRequirements.lean#L303) | A VPN admits IPv4 only with TCP, UDP, ESP or ICMP in its protocol field. | A VPN accepts IPv4 protocol 47. |
| [5](#rg-038-source-5) | [`scoped_ip_header_and_multicast_filtering`](../TDN/Requirements/ScopedMscRequirements.lean#L305) | A VPN admits IPv6 only with ESP, TCP, UDP or ICMPv6 in its immediate Next Header field. | An IPv6 packet presents an extension header first and is admitted because its later payload is TCP. |

Additional conditions and definitions. [`HeaderFilterApplies`](../TDN/Requirements/ScopedMscRequirements.lean#L276) [`NecessaryApprovedL2Control`](../TDN/Requirements/ScopedMscRequirements.lean#L279) [`Deployment.PolicyCoverage`](../TDN/Requirements/MscComplianceSchema.lean#L1235) [`Deployment.LinkPoliciesComplete`](../TDN/Requirements/MscComplianceSchema.lean#L1334)

### Evidence and assumptions

**Routed IPv4 example**

- Recorded inputs. The fixture is defined directly in Lean.
- Declared inputs. The routed IPv4 example turns PF-10 off and constructs the rules in Lean. A separate regression turns the objective on to check the required guard.
- Conditions on the result. The base deployment and processing inventory parameterize the model.
- Checked example. [`permitted_esp_is_accepted`](../TDN/Deployments/SnapshotProof_HeaderFiltering.lean#L42).
- Rejection or counterexample. [`gre_is_rejected`](../TDN/Deployments/SnapshotProof_HeaderFiltering.lean#L62).
- Related proofs. [`selected_options_need_actual_atom`](../TDN/Deployments/SnapshotProof_HeaderFiltering.lean#L95)

**Captured link-layer programs**

- Recorded inputs. [CapturedProgramsAndFrames.json](../data/evidence/proof010-link-header/CapturedProgramsAndFrames.json) `programs`, [InstalledAssociations-v2.json](../data/evidence/proof010-link-header/InstalledAssociations-v2.json) `ATx`
- Declared inputs. The control exception is explicitly limited to the approved MKA group and binding.
- Conditions on the result. The program and installed-association results apply to the captured interfaces.
- Checked example. [`captured_bootstrap_mka_is_fully_admitted`](../TDN/Deployments/SnapshotProof_LinkHeaderFiltering.lean#L130).
- Rejection or counterexample. [`captured_negative_group_actor_length_and_vlan`](../TDN/Deployments/SnapshotProof_LinkHeaderFiltering.lean#L121).
- Related proofs. [`captured_installed_data_is_fully_admitted`](../TDN/Deployments/SnapshotProof_LinkHeaderFiltering.lean#L230)

<details>
<summary>Original passages and page links</summary>

<a id="rg-038-source-1"></a>1. [PDF p. 21](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=21) `p021:u004.s004` Multicast messages received on external interfaces of the Outer Encryption Component must be dropped.

<a id="rg-038-source-2"></a>2. [PDF p. 45](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=45) `p045:u007` MSC-PF-9 Multicast messages received on external interfaces of Outer Encryption Components must be dropped. T=O

<a id="rg-038-source-3"></a>3. [PDF p. 45](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=45) `p045:u008` MSC-PF-10 For solutions using IPv4, Outer VPN Gateways using IPsec must drop all packets that use IP options. O

<a id="rg-038-source-4"></a>4. [PDF p. 45](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=45) `p045:u009` MSC-PF-11 For solutions using IPv4, each VPN Gateway must only accept packets with Transmission Control Protocol (TCP), User Datagram Protocol (UDP), ESP, or ICMP in the IPv4 Protocol field and drop all other packets. T=O

<a id="rg-038-source-5"></a>5. [PDF p. 45](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=45) `p045:u010` MSC-PF-12 For solutions using IPv6, each VPN Gateway must only accept packets with ESP, TCP, UDP, or ICMPv6 in the IPv6 Next Header field and drop all other packets. T=O

Additional context

- [PDF p. 21](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=21) `p021:u004.s001` Public standards conformant Layer 2 control protocols, such as ARP, are allowed as necessary to ensure the operational usability of the network.

</details>

## RG-039 Outer Gray-interface allowlist and default denial

Whole-deployment specification [`outer_gray_interface_policy`](../TDN/Requirements/MscRequirements.lean#L43).

The check applies on Outer Gray interfaces. A source address must be reachable on ingress. Eligible traffic must be admitted at the applicable local processing hook. HTTP revocation is identified by the transport service and an Inner revocation endpoint. That classifier alone cannot identify the other endpoint as an Inner VPN or establish the request’s contents. The management initiation clause has this same interface scope. A carrier may identify a pair through adjacent encapsulators. The closure and case rules treat approved control as a separate allowance.

An independent agent reviewed these passages, interpretations and evidence examples against the Lean definitions.

| Source | Lean condition | What the condition means | Example failure |
| --- | --- | --- | --- |
| [1](#rg-039-source-1) | [`OuterManagementInitiation`](../TDN/Requirements/ScopedMscRequirements.lean#L311) | Management starts at a Gray workstation. An Outer may initiate logging or authentication. | An Outer initiates an unrelated management service. |
| [2](#rg-039-source-2), [4](#rg-039-source-4) | [`OuterTunnelAllowance`](../TDN/Requirements/ScopedMscRequirements.lean#L316) | Allow an appropriate tunnel exchange between intended same-level Inner peers, or one used for Gray management. Inspect the embedded Inner pair for a recognized carrier. | Protected user traffic goes to an Inner at a different release level. |
| [2](#rg-039-source-2), [4](#rg-039-source-4) | [`OuterGrayRestrictions`](../TDN/Requirements/ScopedMscRequirements.lean#L334) | An admitted protected payload other than revocation HTTP must match the intended same-level Inner pair. An appropriate Gray management tunnel also qualifies. | A cross-level protected packet is admitted through a catch-all ACL. |
| [3](#rg-039-source-3) | [`OuterGrayRestrictions`](../TDN/Requirements/ScopedMscRequirements.lean#L338) | With a Gray data-plane revocation service, allow necessary Inner revocation HTTP on an Outer VPN. The implementation recognizes the service by its address and port. | Ordinary HTTP to an unrelated server is admitted as revocation traffic. |
| [5](#rg-039-source-5) | [`OuterGrayRestrictions`](../TDN/Requirements/ScopedMscRequirements.lean#L333) | Inbound packets must have a source reachable on the receiving interface. | An admitted packet claims an address reachable only through another interface. |
| [6](#rg-039-source-6) | [`OuterPolicyAllowance`](../TDN/Requirements/ScopedMscRequirements.lean#L327) | The separate management and control allowance requires approval for the Outer. A tunnel exchange may independently qualify under the tunnel allowance. | The Outer Gray interface admits unapproved standalone NTP that qualifies under no other allowance. |
| [7](#rg-039-source-7) | [`scoped_outer_gray_interface_policy`](../TDN/Requirements/ScopedMscRequirements.lean#L350) | Every admitted packet must meet both the restrictions and an allowance. Every eligible packet satisfying both must pass its local hook. | A deny-all ruleset blocks an eligible, intended same-level tunnel exchange. |

Additional conditions and definitions. [`Deployment.PacketEligibleAt`](../TDN/Requirements/MscComplianceSchema.lean#L1459) [`Deployment.RevocationEndpoint`](../TDN/Requirements/MscComplianceSchema.lean#L967) [`Deployment.SameLevelInner`](../TDN/Requirements/MscComplianceSchema.lean#L1123) [`OuterGrayRestrictions`](../TDN/Requirements/ScopedMscRequirements.lean#L329) [`OuterPolicyAllowance`](../TDN/Requirements/ScopedMscRequirements.lean#L322)

### Evidence and assumptions

**Baseline**

- Recorded inputs. [OuterGrayBaselineFields.json](../data/evidence/continuation/OuterGrayBaselineFields.json) `policies`, [OuterToGray_BaselineCases.json](../data/evidence/continuation/OuterToGray_BaselineCases.json) `plaintextBlack`, [OuterToGray_BaselineCases.json](../data/evidence/continuation/OuterToGray_BaselineCases.json) `reply`
- Declared inputs. These profiles have no Gray revocation service on the data plane and no Gray management workstation in the modeled profile. The reachable source prefixes determine admissible ingress.
- Conditions on the result. The two examples use the native IPv4 IPsec processing and filtering model.
- Checked example. [`OuterToGray_Baseline.framed_reply_is_eligible_and_accepted`](../TDN/Deployments/OuterToGray_BaselineTestVectors.lean#L33).
- Rejection or counterexample. [`OuterToGray_Baseline.plaintext_black_is_denied_by_raw_gray_forward_program`](../TDN/Deployments/OuterToGray_BaselineBlockedTrafficTests.lean#L37).

**Shared**

- Recorded inputs. [OuterGraySharedFields.json](../data/evidence/continuation/OuterGraySharedFields.json) `policies`, [OuterToGray_SharedCases.json](../data/evidence/continuation/OuterToGray_SharedCases.json) `plaintextBlack`, [OuterToGray_SharedCases.json](../data/evidence/continuation/OuterToGray_SharedCases.json) `reply`
- Declared inputs. These profiles have no Gray revocation service on the data plane and no Gray management workstation in the modeled profile. The reachable source prefixes determine admissible ingress.
- Conditions on the result. The two examples use the native IPv4 IPsec processing and filtering model.
- Checked example. [`OuterToGray_Shared.framed_reply_is_eligible_and_accepted`](../TDN/Deployments/OuterToGray_SharedTestVectors.lean#L33).
- Rejection or counterexample. [`OuterToGray_Shared.plaintext_black_is_denied_by_raw_gray_forward_program`](../TDN/Deployments/OuterToGray_SharedBlockedTrafficTests.lean#L37).

<details>
<summary>Original passages and page links</summary>

<a id="rg-039-source-1"></a>1. [PDF p. 45](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=45) `p045:u006` MSC-PF-8 Management plane traffic must only be initiated from a Gray AW with the exception of logging or authentication traffic that may be initiated from Outer Encryption Components. T=O

<a id="rg-039-source-2"></a>2. [PDF p. 45](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=45) `p045:u011` MSC-PF-13 The Gray Network interfaces of Outer Encryption Components must allow IKE and IPsec, or MKA and MACsec traffic, as appropriate, between two Inner Encryption Components protecting networks of the same security level or that is being used for management of the Gray Network. T=O

<a id="rg-039-source-3"></a>3. [PDF p. 45](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=45) `p045:u013` MSC-PF-15 If the CDP/OCSP is on the gray data plane, the Gray Network interfaces of Outer VPN Gateways must T=O allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and the CDPs/OCSP Responders) and block all other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

<a id="rg-039-source-4"></a>4. [PDF p. 46](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=46) `p046:u004` MSC-PF-17 The Gray Network interfaces of Outer Encryption Components must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

<a id="rg-039-source-5"></a>5. [PDF p. 46](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=46) `p046:u005` MSC-PF-18 The Gray Network interfaces of Outer Encryption Components must block all packets whose source address does not match a list of addresses or address ranges known to be reachable from the interface where the packet was received. T=O

<a id="rg-039-source-6"></a>6. [PDF p. 46](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=46) `p046:u006` MSC-PF-19 The Gray Network interfaces of Outer Encryption Components must allow management and control plane protocols (as defined in this CP) that have been approved by policy. T=O

<a id="rg-039-source-7"></a>7. [PDF p. 46](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=46) `p046:u007` MSC-PF-20 The Gray Network interfaces of Outer Encryption Components must deny all traffic that is not explicitly allowed by requirements MSC-PF-8, MSC- PF-13, MSC-PF-15, or MSC-PF-19. T=O

</details>

## RG-040 Gray Firewall allowlist and cross-level denial

Whole-deployment specification [`gray_firewall_allowlist`](../TDN/Requirements/MscRequirements.lean#L46).

The allowlist applies when a Gray Firewall is required. The separate prohibition on identified Inner VPN pairs of different classifications applies to every listed Gray Firewall. Requirements about a full security level also account for release controls. The HTTP classifier uses endpoints and transport service. Positive forwarding additionally needs the modeled forwarding permission. The management-port test covers both directions. Endpoint interpretation can use a bound carrier between devices adjacent to the intended Inner peers.

An independent agent reviewed these passages, interpretations and evidence examples against the Lean definitions.

| Source | Lean condition | What the condition means | Example failure |
| --- | --- | --- | --- |
| [1](#rg-040-source-1), [4](#rg-040-source-4) | [`GrayPolicyAllowance`](../TDN/Requirements/ScopedMscRequirements.lean#L359) | Allow appropriate tunnel traffic between identified intended Inner peers at the same full security level. | Two Secret peers with incompatible release controls exchange protected traffic. |
| [1](#rg-040-source-1), [4](#rg-040-source-4) | [`GrayFirewallRestrictions`](../TDN/Requirements/ScopedMscRequirements.lean#L374) | An admitted protected payload other than revocation HTTP must match the intended same-level Inner pair. | A cross-level protected packet is admitted through a catch-all ACL. |
| [2](#rg-040-source-2) | [`GrayFirewallRestrictions`](../TDN/Requirements/ScopedMscRequirements.lean#L376) | Allow necessary Inner revocation HTTP and reject other HTTP under the model’s service classifier. | The firewall admits ordinary web traffic to an unrelated server. |
| [3](#rg-040-source-3) | [`GrayManagementAllowance`](../TDN/Requirements/ScopedMscRequirements.lean#L353) | Management admission needs a physical Gray management port, a recognized service and approval. | The same management flow is admitted on a data-only port. |
| [5](#rg-040-source-5) | [`GrayFirewallRestrictions`](../TDN/Requirements/ScopedMscRequirements.lean#L375) | On ingress, reject a source outside the reachable addresses or prefixes for that interface. | An admitted source prefix belongs on the opposite side of the firewall. |
| [6](#rg-040-source-6) | [`GrayPolicyAllowance`](../TDN/Requirements/ScopedMscRequirements.lean#L361) | The separate control allowance requires policy approval. A control packet may also qualify as an appropriate tunnel exchange. | Unapproved standalone NTP passes despite qualifying under no other allowance. |
| [7](#rg-040-source-7) | [`scoped_gray_firewall_allowlist`](../TDN/Requirements/ScopedMscRequirements.lean#L388) | Reject traffic outside the allowed classes. Eligible allowed traffic with forwarding permission must pass the local hook. | A catch-all rule admits an unlisted application or drops an eligible and explicitly allowed exchange. |
| [8](#rg-040-source-8) | [`scoped_gray_firewall_allowlist`](../TDN/Requirements/ScopedMscRequirements.lean#L394) | Block traffic between identified Inner VPN gateways at different classifications on any listed Gray Firewall. | A routed packet from a Secret Inner VPN to a Top Secret Inner VPN is admitted. |

Additional conditions and definitions. [`Deployment.PacketEligibleAt`](../TDN/Requirements/MscComplianceSchema.lean#L1459) [`Deployment.GrayForwardPermission`](../TDN/Requirements/PermittedGrayForwardingFlows.lean#L23) [`Deployment.RevocationEndpoint`](../TDN/Requirements/MscComplianceSchema.lean#L967) [`DifferentClassificationVPNs`](../TDN/Requirements/ScopedMscRequirements.lean#L363) [`GrayFirewallRestrictions`](../TDN/Requirements/ScopedMscRequirements.lean#L370) [`GrayPolicyAllowance`](../TDN/Requirements/ScopedMscRequirements.lean#L357)

### Evidence and assumptions

**Baseline**

- Recorded inputs. [BoundaryBaselineFields.json](../data/evidence/continuation/BoundaryBaselineFields.json) `policies`, [GrayFirewallCases.json](../data/evidence/continuation/GrayFirewallCases.json) `baselineCross`
- Declared inputs. The scenario requires a Gray Firewall. The declared policy identifies intended pairs, allowed management ports and control flows.
- Conditions on the result. The baseline rejection has an explicit eligible packet. The separate successful IKE forwarding example uses the shared profile.
- Proof of the full allowlist for the baseline. [`Perimeter_Baseline.complete_native_gray_firewall_allowlist`](../TDN/Deployments/GrayFirewall_Baseline.lean#L7).
- An eligible packet exercises the cross-classification rule. [`baseline_cross_classification_is_eligible_and_denied`](../TDN/Deployments/GrayFirewall_PermittedFlowTraces.lean#L71).

**Shared**

- Recorded inputs. [GrayFirewallSharedFields.json](../data/evidence/continuation/GrayFirewallSharedFields.json) `policies`, [GrayFirewallCases.json](../data/evidence/continuation/GrayFirewallCases.json) `sharedCross`, [GrayFirewallCases.json](../data/evidence/continuation/GrayFirewallCases.json) `ordinaryIKE`
- Declared inputs. The scenario requires a Gray Firewall. The declared policy identifies intended pairs, allowed management ports and control flows.
- Conditions on the result. Traffic is assessed at a modeled eligible hook. The positive IKE trace uses the shared fixture.
- Checked example. [`shared_ordinary_ike_is_eligible_and_accepted`](../TDN/Deployments/GrayFirewall_PermittedFlowTraces.lean#L31).
- Rejection or counterexample. [`shared_cross_classification_is_eligible_and_denied`](../TDN/Deployments/GrayFirewall_PermittedFlowTraces.lean#L91).

<details>
<summary>Original passages and page links</summary>

<a id="rg-040-source-1"></a>1. [PDF p. 46](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=46) `p046:u010` MSC-PF-23 If a Gray Firewall is required (i.e., networks of multiple protection levels are included in the solution) the Gray Firewall must allow appropriate traffic (IKE, IPsec, MKA and MACsec) between Red Networks operating at the same security level. T=O

<a id="rg-040-source-2"></a>2. [PDF p. 46](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=46) `p046:u012` MSC-PF-25 If a Gray Firewall is required, the Gray Firewall must allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and CDPs/OCSP Responders) and block all T=O other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

<a id="rg-040-source-3"></a>3. [PDF p. 47](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=47) `p047:u004` MSC-PF-27 If a Gray Firewall is required, the Gray Firewall must only accept management traffic on the physical ports connected to the Gray Management Network. T=O

<a id="rg-040-source-4"></a>4. [PDF p. 47](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=47) `p047:u005` MSC-PF-28 If a Gray Firewall is required, the Gray Firewall must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

<a id="rg-040-source-5"></a>5. [PDF p. 47](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=47) `p047:u006` MSC-PF-29 If a Gray Firewall is required, the Gray Firewall must block all packets whose source address does not match a list of addresses or address ranges known to be reachable from the interface where the packet was received. T=O

<a id="rg-040-source-6"></a>6. [PDF p. 47](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=47) `p047:u007` MSC-PF-30 If a Gray Firewall is required, the Gray Firewall must allow control plane traffic (e.g., NTP and DHCP). T=O

<a id="rg-040-source-7"></a>7. [PDF p. 47](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=47) `p047:u008` MSC-PF-31 If a Gray Firewall is required, the Gray Firewall must deny all traffic that is not explicitly allowed by requirements MSC-PF-23, MSC-PF-25, MSC-PF-27 or MSC-PF-30. T=O

<a id="rg-040-source-8"></a>8. [PDF p. 47](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=47) `p047:u009` MSC-PF-32 The Gray Firewall must block all traffic routed to and between two or more Inner VPN Gateways of different classification levels. T=O

</details>
