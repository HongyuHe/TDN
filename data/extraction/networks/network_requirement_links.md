# Example to requirement-group assessments

Every assessment names the selected clause and its applicability. Statuses describe source presentation or outstanding evidence for that clause. They do not certify every clause in a group or a deployed solution.

Browse [network topologies](networks.md), [partial configurations and alternatives](configurations.md), or [protocol exchanges](protocol_exchanges.md). Numbered requirement links in examples.json are a compatibility projection of these assessments.

The extraction subagent authored the original judgments in [mapping_decisions.json](mapping_decisions.json). An [independent audit](../validation/plan_audit/independent_review.md) reviewed that version. The decision file separately records later user-directed corrections by the coordinator. The scripts validate and render the saved judgments.

Explicit textual descriptions and applicable requirements supply details omitted from figures. Ambiguous means the source wording, applicability, or example-to-requirement relationship remains unresolved after applying that rule. Missing symbols alone do not create ambiguity. A clear requirement with missing implementation evidence is labeled required_but_not_demonstrated.

<a id="net-001"></a>

## NET-001: Two encryption tunnels across an untrusted network

### Requirement-group assessment

Figure 1 presents nested encryption across untrusted transport. The explicit text supplies the required Outer Firewall omitted from the schematic. Product independence and physical implementation remain separate obligations.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-007: Two independent encryption layers and allowed tunnel pairings](../requirements/requirement_groups.md#rg-007) | Encrypt classified data first at the Inner component and then at the Outer component; decrypt in reverse order. | [Presented as satisfying](network_requirement_links.md#net-001-map-01) |
| [RG-008: Connectivity restricted to the same security level](../requirements/requirement_groups.md#rg-008) | Allow Red-to-Red communication only at the same security level. | [Required; implementation not demonstrated](network_requirement_links.md#net-001-map-02) |
| [RG-004: Independent product, operating-system, and cryptographic implementations](../requirements/requirement_groups.md#rg-004) | Use independent products, operating systems, and cryptographic implementations for the two layers. | [Required; implementation not demonstrated](network_requirement_links.md#net-001-map-03) |
| [RG-005: Physical separation of security components](../requirements/requirement_groups.md#rg-005) | Use physically separate Inner and Outer components. | [Required; implementation not demonstrated](network_requirement_links.md#net-001-map-04) |
| [RG-034: Outer Firewall placement for untrusted Black transport](../requirements/requirement_groups.md#rg-034) | Include an Outer Firewall when the Black transport meets the untrusted/Public Internet condition. | [Presented as satisfying](network_requirement_links.md#net-001-map-05) |

<a id="net-001-map-01"></a>

#### NET-001-MAP-01: [RG-007 - Two independent encryption layers and allowed tunnel pairings](../requirements/requirement_groups.md#rg-007)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Encrypt classified data first at the Inner component and then at the Outer component; decrypt in reverse order.

**Applicability:** Classified data crossing the illustrated Black Network.

**Reasoning:** The prose expressly identifies Figure 1 and describes both encryption and decryption sequences.

**Requirement strength:** Architectural requirements and permitted alternatives; Table 1 enumerates four permitted layer combinations.

**Qualifications and exceptions:** The sequence does not establish product diversity or every permitted control-plane exception.

Group interpretation issues: REQ-I12.

Group scope notes: REQ-I14.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s001`

> As shown in Figure 1, before being sent across the untrusted network, each packet or frame of classified data is encrypted twice; first by an Inner Encryption Component, and then by an Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s002`

> At the other end of the data flow, the received packet is correspondingly decrypted twice; first by an Outer Encryption Component, and then by an Inner Encryption Component.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s001`

> As shown in Figure 1, before being sent across the untrusted network, each packet or frame of classified data is encrypted twice; first by an Inner Encryption Component, and then by an Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s002`

> At the other end of the data flow, the received packet is correspondingly decrypted twice; first by an Outer Encryption Component, and then by an Inner Encryption Component.

<a id="net-001-map-02"></a>

#### NET-001-MAP-02: [RG-008 - Connectivity restricted to the same security level](../requirements/requirement_groups.md#rg-008)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Allow Red-to-Red communication only at the same security level.

**Applicability:** The two Red Networks linked through the encrypted path.

**Reasoning:** The setup states the same-level condition, but the figure does not identify classification, compartments, or dissemination controls for either network.

**Requirement strength:** Mandatory separation and conditional permission to share infrastructure.

**Qualifications and exceptions:** A matching Red label alone does not establish equal security levels.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s004`

> Red Networks may only communicate with one another through the MSC Solution if the networks operate at the same security level.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u004.s002`

> The solution supports interconnecting two or more networks operating at the same security level via encryption tunnels, where the security level encompasses the classification level, list of compartments, dissemination controls, and other such controls over information.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s004`

> Red Networks may only communicate with one another through the MSC Solution if the networks operate at the same security level.

<a id="net-001-map-03"></a>

#### NET-001-MAP-03: [RG-004 - Independent product, operating-system, and cryptographic implementations](../requirements/requirement_groups.md#rg-004)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Use independent products, operating systems, and cryptographic implementations for the two layers.

**Applicability:** The illustrated Inner and Outer Encryption Components.

**Reasoning:** Nested tunnels establish two layers; the example gives no manufacturer, operating system, or cryptographic-library identities.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-PS-6`: `T=O`; alternatives: `none stated`.
- `MSC-PS-7`: `T=O`; alternatives: `none stated`.
- `MSC-PS-8`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** Preserve the NSA-determined same-manufacturer product and library alternatives. Version differences alone do not satisfy the operating-system clause.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u010`

> MSC-PS-6 The Inner Encryption Component and the Outer Encryption Component must either; come from different manufacturers, where neither manufacturer is a subsidiary of the other; or be different products from the same manufacturer, where NSA has determined that the products meet the CSfC criteria for implementation independence. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u011`

> MSC-PS-7 The Inner Encryption Component and the Outer Encryption Component must not use the same Operating System. Differences between Service Packs and version numbers for a particular vendor's OS do not provide adequate diversity. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u012`

> MSC-PS-8 The cryptographic libraries used by the Inner Encryption Component and Outer Encryption Component must either; come from different manufacturers, where neither manufacturer is a subsidiary of the other; or be different libraries from the same manufacturer, where NSA has determined that the libraries meet the CSfC criteria for implementation independence. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u005.s001`

> The MSC Solution uses two nested, independent encryption tunnels to protect the confidentiality and integrity of data as it transits the untrusted network.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u006.s002`

> “Inner Encryption Component” refers to the component that terminates the Inner layer of encryption and “Outer Encryption Component” refers to the component that terminates the Outer layer of encryption.

<a id="net-001-map-04"></a>

#### NET-001-MAP-04: [RG-005 - Physical separation of security components](../requirements/requirement_groups.md#rg-005)

**required_but_not_demonstrated** | Basis: `visual_interpretation` | Scope: selected clause only.

**Clause assessed:** Use physically separate Inner and Outer components.

**Applicability:** The two encryption roles at each side.

**Reasoning:** Separate symbols distinguish roles, but Figure 1 does not document a hardware deployment or exclusive physical functions.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-PS-11`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** Physical separation remains required; symbolic separation does not demonstrate it.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u003`

> MSC-PS-11 The Inner Encryption Component and Outer Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label001`

> Black Network

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label002`

> Red Network

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label003`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label004`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label005`

> Red Network

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label007`

> Outer Encryption Component

<a id="net-001-map-05"></a>

#### NET-001-MAP-05: [RG-034 - Outer Firewall placement for untrusted Black transport](../requirements/requirement_groups.md#rg-034)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Include an Outer Firewall when the Black transport meets the untrusted/Public Internet condition.

**Applicability:** Figure 1 explicitly uses an untrusted Black Network, which meets the prose condition for an Outer Firewall.

**Reasoning:** The explicit untrusted-network requirement supplies the Outer Firewall omitted from Figure 1. MSC-SR-12 additionally names the Public Internet; that narrower statement does not cancel the broader prose requirement. The described design includes the required firewall under the text-precedence policy.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-12`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The assessment covers the intended design including explicit textual requirements. The figure does not supply a firewall model, rule configuration, or deployment evidence.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s001`

> An MSC Solution that uses an untrusted network such as the Public Internet as its Black Network must include an Outer Firewall (see Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s002`

> 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s003`

> 3).

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u002`

> MSC-SR-12 If the MSC Solution uses the Public Internet for its Black transport network, an Outer Firewall must be located between the Black transport network and the Outer Encryption Component. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u005.s001`

> The MSC Solution uses two nested, independent encryption tunnels to protect the confidentiality and integrity of data as it transits the untrusted network.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u008.s002`

> Two Encryption Tunnels Protect Data Across an Untrusted Network

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u004.s001`

> This CP describes a general MSC Solution to protect classified information as it travels across either an untrusted Network, or a different security level network.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u004.s002`

> The solution supports interconnecting two or more networks operating at the same security level via encryption tunnels, where the security level encompasses the classification level, list of compartments, dissemination controls, and other such controls over information.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u004.s003`

> The solution provides sufficient flexibility to be applicable to many use cases of MSC implementations.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u005.s001`

> The MSC Solution uses two nested, independent encryption tunnels to protect the confidentiality and integrity of data as it transits the untrusted network.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u005.s002`

> The two encryption tunnels protecting a data flow can use either Internet Protocol Security (IPsec) generated by a Virtual Private Network (VPN) Gateway or Media Access Control Security (MACsec) generated by a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u005.s003`

> VPN Gateways and MACsec Devices are implemented as part of the network infrastructure.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u006.s001`

> Throughout this CP, the term “Encryption Component” refers generically to either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u006.s002`

> “Inner Encryption Component” refers to the component that terminates the Inner layer of encryption and “Outer Encryption Component” refers to the component that terminates the Outer layer of encryption.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s001`

> As shown in Figure 1, before being sent across the untrusted network, each packet or frame of classified data is encrypted twice; first by an Inner Encryption Component, and then by an Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s002`

> At the other end of the data flow, the received packet is correspondingly decrypted twice; first by an Outer Encryption Component, and then by an Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s001`

> Red data consists of unencrypted classified data.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s002`

> The Red Network is logically located behind an Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s003`

> The networks connected to one another through the MSC Solution are Red Networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s004`

> Red Networks may only communicate with one another through the MSC Solution if the networks operate at the same security level.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s005`

> Red Networks are under the control of the Solution Owner or a trusted third party using a Red Administrative Workstation (AW).

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s006`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s007`

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u007.s001`

> Gray data is classified data that has been encrypted once.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u007.s002`

> Gray Networks are composed of Gray data and Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u007.s003`

> Gray Networks are under the physical and logical control of the Solution Owner or a trusted third party.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s001`

> An MSC Solution that uses an untrusted network such as the Public Internet as its Black Network must include an Outer Firewall (see Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s002`

> 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s003`

> 3).

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s004`

> The Outer Firewall is located at the edge of the MSC Solution and is connected to the Black Network.

<a id="net-002"></a>

## NET-002: Public Internet as Black transport

### Requirement-group assessment

Figure 2 presents Outer Firewall placement and separation for Public Internet transport. Configured filtering and product eligibility require additional evidence.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-034: Outer Firewall placement for untrusted Black transport](../requirements/requirement_groups.md#rg-034) | Place an Outer Firewall between the Public Internet and each Outer Encryption Component. | [Presented as satisfying](network_requirement_links.md#net-002-map-01) |
| [RG-005: Physical separation of security components](../requirements/requirement_groups.md#rg-005) | Make the Outer Firewall physically separate from the Outer Encryption Component. | [Presented as satisfying](network_requirement_links.md#net-002-map-02) |
| [RG-035: Permitted protocols and peers at encryption and firewall boundaries](../requirements/requirement_groups.md#rg-035) | Describe the Outer Firewall ingress/egress protocol and Outer-component address restrictions. | [Presented as satisfying](network_requirement_links.md#net-002-map-03) |
| [RG-035: Permitted protocols and peers at encryption and firewall boundaries](../requirements/requirement_groups.md#rg-035) | Apply the complete MSC-PF-22 allowlist bidirectionally on all Outer Firewall interfaces. | [Required; implementation not demonstrated](network_requirement_links.md#net-002-map-04) |

<a id="net-002-map-01"></a>

#### NET-002-MAP-01: [RG-034 - Outer Firewall placement for untrusted Black transport](../requirements/requirement_groups.md#rg-034)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Place an Outer Firewall between the Public Internet and each Outer Encryption Component.

**Applicability:** Public Internet is explicitly the Black transport.

**Reasoning:** The prose links Figure 2 to the mandatory placement and states the external-to-internal interface relationship.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-12`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The assessment covers firewall location and connection only.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s005`

> As shown in Figure 2, if the Black Network is an untrusted network such as the Public Internet, an Outer Firewall is required between the Black Network and the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s001`

> If the Black Network is the Public Internet, the external interface of the Outer Encryption Component is connected to the internal interface of the Outer Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u002`

> MSC-SR-12 If the MSC Solution uses the Public Internet for its Black transport network, an Outer Firewall must be located between the Black transport network and the Outer Encryption Component. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s005`

> As shown in Figure 2, if the Black Network is an untrusted network such as the Public Internet, an Outer Firewall is required between the Black Network and the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s001`

> If the Black Network is the Public Internet, the external interface of the Outer Encryption Component is connected to the internal interface of the Outer Firewall.

<a id="net-002-map-02"></a>

#### NET-002-MAP-02: [RG-005 - Physical separation of security components](../requirements/requirement_groups.md#rg-005)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Make the Outer Firewall physically separate from the Outer Encryption Component.

**Applicability:** The illustrated firewall/outer-component pair.

**Reasoning:** The Figure 2 discussion expressly says the firewall must be physically separate and presents the figure as that arrangement.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-PS-12`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** MSC-PS-12 also covers other required components; the mapping assesses only the illustrated pair.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u005.s001`

> As shown in Figure 2, the Outer Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u004`

> MSC-PS-12 If an Outer Firewall and/or Gray Firewall is required, the Outer Firewall, Outer Encryption Component, Gray Firewall and Inner Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u005.s001`

> As shown in Figure 2, the Outer Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component.

<a id="net-002-map-03"></a>

#### NET-002-MAP-03: [RG-035 - Permitted protocols and peers at encryption and firewall boundaries](../requirements/requirement_groups.md#rg-035)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Describe the Outer Firewall ingress/egress protocol and Outer-component address restrictions.

**Applicability:** The Outer Firewall interfaces described with Figure 2.

**Reasoning:** The setup gives an intended filter policy for both interfaces, including necessary control-plane traffic on the internal side.

**Requirement strength:** Mandatory for the stated applicability.

**Qualifications and exceptions:** The clauses present a policy design. No live rule table or traffic test is supplied.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u003.s001`

> The external interface of the Outer Firewall only permits IPsec or MACsec traffic with a destination address of the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s001`

> The internal interface of the Outer Firewall only permits IPsec or MACsec traffic with a source address of the Outer Encryption Component and any necessary control plane traffic.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u003.s001`

> The external interface of the Outer Firewall only permits IPsec or MACsec traffic with a destination address of the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s001`

> The internal interface of the Outer Firewall only permits IPsec or MACsec traffic with a source address of the Outer Encryption Component and any necessary control plane traffic.

<a id="net-002-map-04"></a>

#### NET-002-MAP-04: [RG-035 - Permitted protocols and peers at encryption and firewall boundaries](../requirements/requirement_groups.md#rg-035)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Apply the complete MSC-PF-22 allowlist bidirectionally on all Outer Firewall interfaces.

**Applicability:** The required Outer Firewalls in Figure 2.

**Reasoning:** The example gives a prose policy, but it does not enumerate all configured IKE, ESP, MKA, MACsec, and approved control-plane rules on every interface.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-PF-22`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** Do not treat the narrower prose list as proof of a rule violation; protocol choice and policy approval remain unspecified.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u009`

> MSC-PF-22 If an Outer Firewall is required, for all Outer Firewall interfaces, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, ESP, MKA, MACsec and control plane protocols (as defined in this CP) approved by organization- defined policy are allowed. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s005`

> As shown in Figure 2, if the Black Network is an untrusted network such as the Public Internet, an Outer Firewall is required between the Black Network and the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s002`

> The minimum requirements for port filtering on the Outer Firewall can be found in Section 10.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s003`

> 6.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s001`

> Black data is classified data that has been encrypted twice.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s002`

> The network connecting the Outer Encryption Components together is a Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s003`

> Black Networks may be referred to as Black transport networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s004`

> Black Networks are not necessarily (and often will not be) under the control of the Solution Owner, and may be operated by an untrusted third party.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s005`

> As shown in Figure 2, if the Black Network is an untrusted network such as the Public Internet, an Outer Firewall is required between the Black Network and the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s001`

> An MSC Solution that uses an untrusted network such as the Public Internet as its Black Network must include an Outer Firewall (see Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s002`

> 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s003`

> 3).

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s004`

> The Outer Firewall is located at the edge of the MSC Solution and is connected to the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u003.s001`

> The external interface of the Outer Firewall only permits IPsec or MACsec traffic with a destination address of the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s001`

> The internal interface of the Outer Firewall only permits IPsec or MACsec traffic with a source address of the Outer Encryption Component and any necessary control plane traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s002`

> The minimum requirements for port filtering on the Outer Firewall can be found in Section 10.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s003`

> 6.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u005.s001`

> As shown in Figure 2, the Outer Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s001`

> The Outer Encryption Component can be either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s002`

> The Outer Encryption Component establishes an encrypted tunnel using IPsec or MACsec with peer Outer Encryption Components, which provides device authentication, confidentiality, and integrity of information traversing Black Networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s001`

> If the Black Network is the Public Internet, the external interface of the Outer Encryption Component is connected to the internal interface of the Outer Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s002`

> Otherwise, the external interface of the Outer Encryption Component is connected to the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s003`

> The internal interface of the Outer Encryption Component is connected to Gray Firewalls, if required, or Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s004`

> If the Black Network is the Public Internet, Transmission Security (TRANSEC) must be enabled to provide additional security.

<a id="net-003"></a>

## NET-003: Two independently managed sites

### Requirement-group assessment

Figure 3 presents independent site administration and nested tunnels. Peer interoperability, trust material, and authentication-server attachment depend on the selected components.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-010: Independently managed site administration and trust](../requirements/requirement_groups.md#rg-010) | Administer each site locally without management traffic crossing the Black Network. | [Presented as satisfying](network_requirement_links.md#net-003-map-01) |
| [RG-007: Two independent encryption layers and allowed tunnel pairings](../requirements/requirement_groups.md#rg-007) | Provide an Inner tunnel and an Outer tunnel between directly communicating sites. | [Presented as satisfying](network_requirement_links.md#net-003-map-02) |
| [RG-010: Independently managed site administration and trust](../requirements/requirement_groups.md#rg-010) | Provide peer signing certificates and revocation information, or a shared peer CAK under the selected authentication method. | [Required; implementation not demonstrated](network_requirement_links.md#net-003-map-03) |
| [RG-054: Interoperable components across communicating sites](../requirements/requirement_groups.md#rg-054) | Ensure the components selected at communicating sites interoperate. | [Required; implementation not demonstrated](network_requirement_links.md#net-003-map-04) |
| [RG-008: Connectivity restricted to the same security level](../requirements/requirement_groups.md#rg-008) | Restrict Inner VPN peers to Red Networks at the same security level. | [Required; implementation not demonstrated](network_requirement_links.md#net-003-map-05) |
| [RG-024: MACsec authentication alternatives and AS scope](../requirements/requirement_groups.md#rg-024) | Connect each MACsec Authentication Server to only one site network. | [Required; implementation not demonstrated](network_requirement_links.md#net-003-map-06) |

<a id="net-003-map-01"></a>

#### NET-003-MAP-01: [RG-010 - Independently managed site administration and trust](../requirements/requirement_groups.md#rg-010)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Administer each site locally without management traffic crossing the Black Network.

**Applicability:** The independently managed site design.

**Reasoning:** The source explicitly assigns local administration to each site and states that management traffic does not cross Black transport.

**Requirement strength:** Conditional design requirements and permission to use locally managed or enterprise CAs.

**Qualifications and exceptions:** Locally run and enterprise CAs are alternatives; the source does not assign every management service to a specific device.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s001`

> For independently managed sites, each site performs the administration of its own Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s001`

> When using independent managed sites, management traffic will not cross the Black Network, encrypted or unencrypted.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s001`

> For independently managed sites, each site performs the administration of its own Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s001`

> When using independent managed sites, management traffic will not cross the Black Network, encrypted or unencrypted.

<a id="net-003-map-02"></a>

#### NET-003-MAP-02: [RG-007 - Two independent encryption layers and allowed tunnel pairings](../requirements/requirement_groups.md#rg-007)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Provide an Inner tunnel and an Outer tunnel between directly communicating sites.

**Applicability:** The communicating sites in Figure 3.

**Reasoning:** The discussion expressly describes both layers and permits either IPsec or MACsec at each layer.

**Requirement strength:** Architectural requirements and permitted alternatives; Table 1 enumerates four permitted layer combinations.

**Qualifications and exceptions:** Outer MACsec remains subject to the point-to-point limitation in RG-007.

Group interpretation issues: REQ-I12.

Group scope notes: REQ-I14.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s001`

> There are two layers of encryption tunnels between any pair of sites communicating directly with one another; one encryption tunnel between their Outer Encryption Components, and a second encryption tunnel between their Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s002`

> Each set of Inner or Outer Encryption Components can provide encryption using either IPsec or MACsec.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s001`

> There are two layers of encryption tunnels between any pair of sites communicating directly with one another; one encryption tunnel between their Outer Encryption Components, and a second encryption tunnel between their Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s002`

> Each set of Inner or Outer Encryption Components can provide encryption using either IPsec or MACsec.

<a id="net-003-map-03"></a>

#### NET-003-MAP-03: [RG-010 - Independently managed site administration and trust](../requirements/requirement_groups.md#rg-010)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Provide peer signing certificates and revocation information, or a shared peer CAK under the selected authentication method.

**Applicability:** Certificate or CAK authentication at independently managed sites.

**Reasoning:** The source states the required trust relationships but supplies no certificate stores, revocation data, or CAK values.

**Requirement strength:** Conditional design requirements and permission to use locally managed or enterprise CAs.

**Qualifications and exceptions:** Certificate and CAK clauses are conditional alternatives; cross-site trust does not erase layer or security-level separation.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s002`

> In the MSC Solution, Encryption Components at each site using public key certificates need to have the signing certificates and revocation information for the corresponding CAs used by the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s003`

> This high-level design requires cooperation between the various sites in the solution to ensure that all CAs used by each site are trusted at all the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s004`

> Similarly, MACsec Devices using a Connectivity Association Key (CAK) need to have the same CAK used by the other site in the MSC Solution.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s002`

> If Certification Authorities (CAs) are part of the MSC Solution, each site has the option to use either locally run CAs that they manage and control or, where available, enterprise CAs that are not necessarily managed by the Solution Owner.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s002`

> In the MSC Solution, Encryption Components at each site using public key certificates need to have the signing certificates and revocation information for the corresponding CAs used by the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s004`

> Similarly, MACsec Devices using a Connectivity Association Key (CAK) need to have the same CAK used by the other site in the MSC Solution.

<a id="net-003-map-04"></a>

#### NET-003-MAP-04: [RG-054 - Interoperable components across communicating sites](../requirements/requirement_groups.md#rg-054)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Ensure the components selected at communicating sites interoperate.

**Applicability:** Each illustrated intersite tunnel.

**Reasoning:** The setup requires interoperability but identifies no products or compatibility results.

**Requirement strength:** Interoperability is T=O; testing in §4 is recommended.

- `MSC-SR-2`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** Drawing a tunnel does not demonstrate successful interoperability testing.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u004`

> MSC-SR-2 Sites that need to communicate must ensure that Encryption Components selected by each site for each tunnel are interoperable. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s003`

> Each site needs to ensure that the Encryption Components selected interoperate with those at the other sites.

<a id="net-003-map-05"></a>

#### NET-003-MAP-05: [RG-008 - Connectivity restricted to the same security level](../requirements/requirement_groups.md#rg-008)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Restrict Inner VPN peers to Red Networks at the same security level.

**Applicability:** Only the IPsec Inner-layer alternative.

**Reasoning:** Neither Red security-level details nor an Inner VPN authentication policy are supplied.

**Requirement strength:** Mandatory separation and conditional permission to share infrastructure.

- `MSC-VG-15`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** MSC-VG-15 is conditional on using Inner VPN Gateways; MACsec alternatives retain the general same-level rule.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u007`

> MSC-VG-15 Inner VPN Gateways must only authenticate and establish an IPsec tunnel with one another if their Red Networks operate at the same security level as defined in this CP. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s002`

> Each set of Inner or Outer Encryption Components can provide encryption using either IPsec or MACsec.

<a id="net-003-map-06"></a>

#### NET-003-MAP-06: [RG-024 - MACsec authentication alternatives and AS scope](../requirements/requirement_groups.md#rg-024)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Connect each MACsec Authentication Server to only one site network.

**Applicability:** The certificate-authenticated MACsec alternative.

**Reasoning:** The setup mentions the AS but gives no concrete attachment diagram sufficient to check MSC-AA-2.

**Requirement strength:** MSC-MD-3 and MSC-MD-14 are both marked Threshold alternatives. AA-1 and AA-2 are T=O within certificate-based MACsec.

- `MSC-AA-2`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The separate phrase "both Gray and/or Red Networks" is ambiguous and does not authorize a multi-site attachment.

Group interpretation issues: REQ-I08, REQ-I15.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u011`

> MSC-AA-2 The AS must only connect to one site’s network when a MACsec device is an Outer or Inner Encryption Component. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s005`

> If MACsec Devices are authenticating using certificates, the authentication server (AS) must not connect to both Gray and/or Red Networks.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u001.s001`

> Figure 3 shows two Red Networks at different sites that operate at the same security level and connected to one another through the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u001.s002`

> Here, each Red Network has two Encryption Components associated with it; an Inner Encryption Component connected to the Red Network, and an Outer Encryption Component between the Inner Encryption Component and the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s001`

> There are two layers of encryption tunnels between any pair of sites communicating directly with one another; one encryption tunnel between their Outer Encryption Components, and a second encryption tunnel between their Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s002`

> Each set of Inner or Outer Encryption Components can provide encryption using either IPsec or MACsec.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u004.s001`

> There is no limit to the number of sites that may be incorporated into a single MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s001`

> For independently managed sites, each site performs the administration of its own Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s002`

> If Certification Authorities (CAs) are part of the MSC Solution, each site has the option to use either locally run CAs that they manage and control or, where available, enterprise CAs that are not necessarily managed by the Solution Owner.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s003`

> Each site needs to ensure that the Encryption Components selected interoperate with those at the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s001`

> When using independent managed sites, management traffic will not cross the Black Network, encrypted or unencrypted.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s002`

> In the MSC Solution, Encryption Components at each site using public key certificates need to have the signing certificates and revocation information for the corresponding CAs used by the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s003`

> This high-level design requires cooperation between the various sites in the solution to ensure that all CAs used by each site are trusted at all the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s004`

> Similarly, MACsec Devices using a Connectivity Association Key (CAK) need to have the same CAK used by the other site in the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s005`

> If MACsec Devices are authenticating using certificates, the authentication server (AS) must not connect to both Gray and/or Red Networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u008.s001`

> This model has the advantage of allowing communication between larger organizations that have a need to share information while maintaining independence.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u009.s001`

> Note that while Figure 3 shows only two sites, this solution can scale to include numerous sites, with each additional site having the same design as that in Figure 3.

<a id="net-004"></a>

## NET-004: Central Management Site and Remote Site

### Requirement-group assessment

Figure 4 presents central administration and protected intersite management. CA/AS deployment, annex requirements, and MACsec Key Server configuration remain conditional obligations.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-011: Central management, CA placement, and intersite protection](../requirements/requirement_groups.md#rg-011) | Use one central management site and encrypt intersite management at least twice before Black transport. | [Presented as satisfying](network_requirement_links.md#net-004-map-01) |
| [RG-044: Layer-specific administration and management-plane separation](../requirements/requirement_groups.md#rg-044) | Place Red management with the Inner layer and Gray management with the Outer layer. | [Presented as satisfying](network_requirement_links.md#net-004-map-02) |
| [RG-011: Central management, CA placement, and intersite protection](../requirements/requirement_groups.md#rg-011) | Provide the applicable per-layer CAs, central EAP-TLS AS, and central Gray annex controls. | [Required; implementation not demonstrated](network_requirement_links.md#net-004-map-03) |
| [RG-027: MACsec key generation, key-server selection, and rollover](../requirements/requirement_groups.md#rg-027) | Configure the central-site MACsec peer as Key Server with value 0 and the other peer with value 1. | [Required; implementation not demonstrated](network_requirement_links.md#net-004-map-04) |

<a id="net-004-map-01"></a>

#### NET-004-MAP-01: [RG-011 - Central management, CA placement, and intersite protection](../requirements/requirement_groups.md#rg-011)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Use one central management site and encrypt intersite management at least twice before Black transport.

**Applicability:** Central management of the remote site in Figure 4.

**Reasoning:** The source explicitly names the centralized arrangement and describes the protected Red management path.

**Requirement strength:** Conditional design requirements; enterprise-CA use is recommended; a PSK-authenticated layer may omit its CA.

**Qualifications and exceptions:** Detailed central Gray management follows the external Enterprise Gray annex.

Group interpretation issues: REQ-I03, REQ-I12.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s001`

> As shown in Figure 4, if remote management is used, personnel at a single geographic site administer and perform keying and device management for all the sites included in the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s003`

> Red management traffic is encrypted before being routed through the Inner and Outer Encryption Components to another site.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s004`

> As a result, all management traffic between sites is encrypted at least twice before traversing the Black Network.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s001`

> As shown in Figure 4, if remote management is used, personnel at a single geographic site administer and perform keying and device management for all the sites included in the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s003`

> Red management traffic is encrypted before being routed through the Inner and Outer Encryption Components to another site.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s004`

> As a result, all management traffic between sites is encrypted at least twice before traversing the Black Network.

<a id="net-004-map-02"></a>

#### NET-004-MAP-02: [RG-044 - Layer-specific administration and management-plane separation](../requirements/requirement_groups.md#rg-044)

**presented_as_satisfying** | Basis: `visual_interpretation` | Scope: selected clause only.

**Clause assessed:** Place Red management with the Inner layer and Gray management with the Outer layer.

**Applicability:** The central site management-services connections.

**Reasoning:** The figure places Red and Gray Management Services on their respective sides of the encryption layers.

**Requirement strength:** Mandatory administrative separation; administrative functionality may be distributed across the AW set.

- `MSC-DM-4`: `T=O`; alternatives: `none stated`.
- `MSC-DM-5`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The mapping covers intended placement only. AW exclusivity, ACLs, and every management interface are not depicted.

Group scope notes: REQ-I07.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u003`

> MSC-DM-4 The Red Management Network must be used exclusively for all management of Inner Encryption Components and Solution Components within the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u004`

> MSC-DM-5 The Gray Network must be used exclusively for all management of the Outer Encryption Component, Gray Firewall, if present, and Solution Components within the Gray Network. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label001`

> Black Network

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label002`

> Site A

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label003`

> Site B

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label004`

> Solution Boundary

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label005`

> Red Network

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label007`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label008`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label009`

> Gray Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label010`

> Red Network

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label011`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label012`

> Outer Encryption Component

<a id="net-004-map-03"></a>

#### NET-004-MAP-03: [RG-011 - Central management, CA placement, and intersite protection](../requirements/requirement_groups.md#rg-011)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Provide the applicable per-layer CAs, central EAP-TLS AS, and central Gray annex controls.

**Applicability:** The selected certificate or PSK authentication alternatives.

**Reasoning:** The source prescribes the components and annex, but aggregate management symbols do not identify their instances or configuration.

**Requirement strength:** Conditional design requirements; enterprise-CA use is recommended; a PSK-authenticated layer may omit its CA.

**Qualifications and exceptions:** The PSK layer does not require a CA. Enterprise CAs are recommended when available. EAP-TLS makes central CAs and an AS necessary.

Group interpretation issues: REQ-I03, REQ-I12.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003`

> At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s004`

> If available, enterprise CAs should be used.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005`

> If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s002`

> Central Management of the Gray Network must be done in accordance with the CSfC Enterprise Gray Implementation Requirements Annex.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003`

> At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005`

> If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s002`

> Central Management of the Gray Network must be done in accordance with the CSfC Enterprise Gray Implementation Requirements Annex.

<a id="net-004-map-04"></a>

#### NET-004-MAP-04: [RG-027 - MACsec key generation, key-server selection, and rollover](../requirements/requirement_groups.md#rg-027)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Configure the central-site MACsec peer as Key Server with value 0 and the other peer with value 1.

**Applicability:** Any MACsec tunnel using the Central Management Site.

**Reasoning:** The setup allows MACsec but gives no Key Server values or role labels.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-MD-6`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The clause does not apply to an all-IPsec selection.

Group interpretation issues: REQ-I15.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u011`

> MSC-MD-6 For each pair of MACsec Devices establishing an encryption tunnel, one of the two must be configured to be the Key Server by setting its Key Server value to 0 (zero). The other MACsec Device must have its Key Server value set to 1. If a Central Management Site is part of the MSC Solution, it must be the Key Server. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005`

> If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s001`

> As shown in Figure 4, if remote management is used, personnel at a single geographic site administer and perform keying and device management for all the sites included in the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s002`

> In this case, because the administration is done by one group of Security Administrators, CA Administrators, and Key Generation Solution Administrators (see Section 12), they ensure the interoperability of each site as new sites are added.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003`

> At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s004`

> If available, enterprise CAs should be used.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005`

> If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s001`

> Because the central management site manages the Encryption Components at the other sites over the network, encryption is used to logically separate data and management traffic as it passes between sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s002`

> Central Management of the Gray Network must be done in accordance with the CSfC Enterprise Gray Implementation Requirements Annex.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s003`

> Red management traffic is encrypted before being routed through the Inner and Outer Encryption Components to another site.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s004`

> As a result, all management traffic between sites is encrypted at least twice before traversing the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s005`

> See the CSfC Enterprise Gray Implementation Requirements Annex for additional details and requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u005.s001`

> While Figure 4 shows only two sites, this solution can scale to include numerous sites, with each additional site having the same high-level design as the remotely managed site.

<a id="net-005"></a>

## NET-005: Two networks at the same security level

### Requirement-group assessment

Figure 5 presents two same-security-level Red Networks sharing an Outer component. Per-network management is depicted, while authentication wording and physical interface details remain unresolved.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-012: Separate authentication and management for security levels](../requirements/requirement_groups.md#rg-012) | Provide distinct Red Management Services and allow singly encrypted same-level traffic on the shared Gray Network. | [Presented as satisfying](network_requirement_links.md#net-005-map-01) |
| [RG-012: Separate authentication and management for security levels](../requirements/requirement_groups.md#rg-012) | Interpret the authentication separation intended for the two illustrated same-level networks. | [Ambiguous](network_requirement_links.md#net-005-map-02) |
| [RG-013: Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013) | Require Gray Firewalls on paths between Inner components of different security levels. | [Not applicable to selected alternative](network_requirement_links.md#net-005-map-03) |
| [RG-053: Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053) | Place multiple Inner components in parallel when sharing an Outer component. | [Presented as satisfying](network_requirement_links.md#net-005-map-04) |
| [RG-053: Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053) | Give each Red Network a unique physical internal Outer-component interface. | [Required; implementation not demonstrated](network_requirement_links.md#net-005-map-05) |
| [RG-039: Outer Gray-interface allowlist and default denial](../requirements/requirement_groups.md#rg-039) | Permit only the appropriate same-security-level source/destination addresses on Outer Gray interfaces. | [Required; implementation not demonstrated](network_requirement_links.md#net-005-map-06) |

<a id="net-005-map-01"></a>

#### NET-005-MAP-01: [RG-012 - Separate authentication and management for security levels](../requirements/requirement_groups.md#rg-012)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Provide distinct Red Management Services and allow singly encrypted same-level traffic on the shared Gray Network.

**Applicability:** Network 1 and Network 2 are both Secret U.S.-only.

**Reasoning:** The prose names Figure 5, assigns each network its own management services, and expressly permits the shared Gray transport without extra separation controls.

**Requirement strength:** Mandatory separation across levels; additional same-level security is permitted.

**Qualifications and exceptions:** The permission concerns same-level networks; optional additional controls remain allowed.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s009`

> For example, Figure 5 shows a Central Management Site (Site A) and a Remote Site (Site B), but network 1 and network 2 each has its own Red Management Services, which prevents the Inner Encryption Components of the two networks from being able to authenticate with one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s006`

> Because Network 1 and Network 2 both operate at the same security level, their singly-encrypted traffic can be carried over the Gray Network without any additional security controls in place.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s009`

> For example, Figure 5 shows a Central Management Site (Site A) and a Remote Site (Site B), but network 1 and network 2 each has its own Red Management Services, which prevents the Inner Encryption Components of the two networks from being able to authenticate with one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s006`

> Because Network 1 and Network 2 both operate at the same security level, their singly-encrypted traffic can be carried over the Gray Network without any additional security controls in place.

<a id="net-005-map-02"></a>

#### NET-005-MAP-02: [RG-012 - Separate authentication and management for security levels](../requirements/requirement_groups.md#rg-012)

**ambiguous** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Interpret the authentication separation intended for the two illustrated same-level networks.

**Applicability:** The same-security-level subsection accompanying Figure 5.

**Reasoning:** The subsection moves from same-level networks to a sentence about different-level components and their distinct CAs or CAKs. The exact authentication assignment for the illustrated same-level pair is unresolved.

**Requirement strength:** Mandatory separation across levels; additional same-level security is permitted.

**Qualifications and exceptions:** Retain the source wording. Do not relabel the two Secret U.S.-only networks as different levels.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s001`

> When Red Networks that operate at the same security level are implemented, the cryptographic separation provided by the Inner Encryption Components is sufficient to protect against unintended data flows between the two networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s002`

> Two Inner Encryption Components for networks of different security levels will be unable to mutually authenticate with each other because they trust different CAs that do not have a trust relationship with one another or they use different CAKs that will not provide authentication.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s003`

> This difference prevents the establishment of an encryption tunnel between the two components.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s001`

> When Red Networks that operate at the same security level are implemented, the cryptographic separation provided by the Inner Encryption Components is sufficient to protect against unintended data flows between the two networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s002`

> Two Inner Encryption Components for networks of different security levels will be unable to mutually authenticate with each other because they trust different CAs that do not have a trust relationship with one another or they use different CAKs that will not provide authentication.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s003`

> This difference prevents the establishment of an encryption tunnel between the two components.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s006`

> Because Network 1 and Network 2 both operate at the same security level, their singly-encrypted traffic can be carried over the Gray Network without any additional security controls in place.

<a id="net-005-map-03"></a>

#### NET-005-MAP-03: [RG-013 - Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013)

**not_applicable** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Require Gray Firewalls on paths between Inner components of different security levels.

**Applicability:** The depicted pair has the same security level.

**Reasoning:** The different-level antecedent is false for the stated Network 1/Network 2 pair, and the setup expressly says additional controls are unnecessary.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-7`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** Another CP, management path, or a changed security-level assignment can introduce firewall obligations. The mapping concerns the depicted pair only.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u009`

> MSC-SR-7 All physical paths within a Gray Network between Inner Encryption Components for Red Networks of different security levels must include a Gray Firewall. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s006`

> Because Network 1 and Network 2 both operate at the same security level, their singly-encrypted traffic can be carried over the Gray Network without any additional security controls in place.

<a id="net-005-map-04"></a>

#### NET-005-MAP-04: [RG-053 - Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053)

**presented_as_satisfying** | Basis: `visual_interpretation` | Scope: selected clause only.

**Clause assessed:** Place multiple Inner components in parallel when sharing an Outer component.

**Applicability:** The two Inner components at each site.

**Reasoning:** The diagram branches the shared Gray path toward the two Inner components and shows neither Inner component in series with the other.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-16`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The mapping does not establish unique Outer physical interfaces under MSC-SR-10.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u006`

> MSC-SR-16 When multiple Inner Encryption Components share an Outer Encryption Component, they must be placed in parallel. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label001`

> Black Network

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label002`

> Site A

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label003`

> Site B

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label004`

> Solution Boundary

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label005`

> Network 1 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label007`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label008`

> Network 2 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label009`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label010`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label011`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label012`

> Gray Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label013`

> Gray Data Network

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label014`

> Network 1 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label015`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label016`

> Network 2 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label017`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label018`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label019`

> Gray Data Network

<a id="net-005-map-05"></a>

#### NET-005-MAP-05: [RG-053 - Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053)

**required_but_not_demonstrated** | Basis: `visual_interpretation` | Scope: selected clause only.

**Clause assessed:** Give each Red Network a unique physical internal Outer-component interface.

**Applicability:** Each site shares an Outer Encryption Component across two Red Networks.

**Reasoning:** The Gray Data Network symbol does not identify physical Outer interface counts or exclude VLAN trunking.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-10`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** A shared Gray segment is not sufficient evidence of either satisfaction or violation of the interface requirement.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u012`

> MSC-SR-10 The Outer Encryption Component must use a unique physical internal interface for each Red Network in the MSC Solution (i.e., VLAN trunking of multiple enclaves is not permitted). T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label001`

> Black Network

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label002`

> Site A

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label003`

> Site B

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label004`

> Solution Boundary

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label005`

> Network 1 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label007`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label008`

> Network 2 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label009`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label010`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label011`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label012`

> Gray Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label013`

> Gray Data Network

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label014`

> Network 1 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label015`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label016`

> Network 2 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label017`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label018`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label019`

> Gray Data Network

<a id="net-005-map-06"></a>

#### NET-005-MAP-06: [RG-039 - Outer Gray-interface allowlist and default denial](../requirements/requirement_groups.md#rg-039)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Permit only the appropriate same-security-level source/destination addresses on Outer Gray interfaces.

**Applicability:** The shared Outer components.

**Reasoning:** The source permits same-level transport, but supplies no addresses or packet-filter rules.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-PF-17`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** Separate network names do not identify approved peer address pairs.

Group interpretation issues: REQ-I02, REQ-I09.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u004`

> MSC-PF-17 The Gray Network interfaces of Outer Encryption Components must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s006`

> Because Network 1 and Network 2 both operate at the same security level, their singly-encrypted traffic can be carried over the Gray Network without any additional security controls in place.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s001`

> A single implementation of the MSC Solution may support Red Networks of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s002`

> The MSC Solution provides secure connectivity between the Red Networks within each security level while preventing Red Networks of different security levels from communicating with one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s003`

> This enables a customer to use the same physical infrastructure to carry traffic from multiple networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s004`

> Although each Red Network requires its own Inner Encryption Component, a site may use a single Outer Encryption Component to encrypt and transport traffic that has been encrypted by Inner Encryption Components of varying security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s001`

> There is no limit to the number of different security levels that an MSC Solution may support.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s002`

> An unclassified network can also be included behind the Outer Encryption Component but must be behind its own Inner Encryption Component and meet the requirements in this CP as if it was a Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s001`

> MSC Solutions supporting multiple security levels may include independently managed sites (see Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s002`

> 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s003`

> 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s004`

> 1) or centrally managed sites (see Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s005`

> 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s006`

> 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s007`

> 2).

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s008`

> Given both cases, separate CAs, CAKs, and management devices are needed to manage the Inner Encryption Components at each security level.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s009`

> For example, Figure 5 shows a Central Management Site (Site A) and a Remote Site (Site B), but network 1 and network 2 each has its own Red Management Services, which prevents the Inner Encryption Components of the two networks from being able to authenticate with one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s001`

> When Red Networks that operate at the same security level are implemented, the cryptographic separation provided by the Inner Encryption Components is sufficient to protect against unintended data flows between the two networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s002`

> Two Inner Encryption Components for networks of different security levels will be unable to mutually authenticate with each other because they trust different CAs that do not have a trust relationship with one another or they use different CAKs that will not provide authentication.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s003`

> This difference prevents the establishment of an encryption tunnel between the two components.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s001`

> Figure 5 shows an MSC Solution between two sites that carries traffic between two Red Networks; a Secret U.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s002`

> S.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s003`

> -only Network (Network 1), and a Secret U.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s004`

> S.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s005`

> -only Network (Network 2).

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s006`

> Because Network 1 and Network 2 both operate at the same security level, their singly-encrypted traffic can be carried over the Gray Network without any additional security controls in place.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u006.s001`

> Although not required by this CP, a Solution Owner may choose to implement the additional security described in Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u006.s002`

> 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u006.s003`

> 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u006.s004`

> 2 to provide additional protection against unintended data flows between Red Networks at the same security level.

<a id="net-006"></a>

## NET-006: Networks at different security levels

### Requirement-group assessment

Figure 6 presents different-level isolation with Gray Firewalls and separate management. Address assignments, full ACLs, and unique Outer physical interfaces still need evidence.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-013: Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013) | Place Gray Firewalls on physical Gray paths between Inner components of different security levels. | [Presented as satisfying](network_requirement_links.md#net-006-map-01) |
| [RG-008: Connectivity restricted to the same security level](../requirements/requirement_groups.md#rg-008) | Provide connectivity within each security level and prevent communication across levels. | [Presented as satisfying](network_requirement_links.md#net-006-map-02) |
| [RG-005: Physical separation of security components](../requirements/requirement_groups.md#rg-005) | Use standalone Gray Firewalls physically separate from Inner and Outer Encryption Components. | [Presented as satisfying](network_requirement_links.md#net-006-map-03) |
| [RG-040: Gray Firewall allowlist and cross-level denial](../requirements/requirement_groups.md#rg-040) | Configure the Gray Firewall same-level allowlist and cross-level denial rules. | [Required; implementation not demonstrated](network_requirement_links.md#net-006-map-04) |
| [RG-039: Outer Gray-interface allowlist and default denial](../requirements/requirement_groups.md#rg-039) | Apply the Outer Gray-interface same-level allowlist and default denial despite the Gray Firewalls. | [Required; implementation not demonstrated](network_requirement_links.md#net-006-map-05) |
| [RG-014: Gray addressing supports security-level filtering](../requirements/requirement_groups.md#rg-014) | Assign addresses unique to each security level to support the required peer filtering. | [Required; implementation not demonstrated](network_requirement_links.md#net-006-map-06) |
| [RG-053: Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053) | Provide a unique physical Outer internal interface for each Red Network. | [Required; implementation not demonstrated](network_requirement_links.md#net-006-map-07) |

<a id="net-006-map-01"></a>

#### NET-006-MAP-01: [RG-013 - Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Place Gray Firewalls on physical Gray paths between Inner components of different security levels.

**Applicability:** Top Secret, Secret U.S.-only, and Secret Coalition networks share Gray infrastructure.

**Reasoning:** The prose identifies Figure 6 as an example firewall placement and explicitly ties that placement to all paths between different-level Inner components.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-7`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** MSC-SR-8 adds management and revocation-service path conditions; unshown service placements are not established.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s002`

> Standalone Gray Firewalls have been placed at each site between the Inner Encryption Components and the Outer Encryption Component; these Gray Firewalls are responsible for dropping packets between Inner Encryption Components of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u004.s001`

> Figure 6 also shows an example placement of Gray Firewalls, as long as any path between Inner Encryption Components for networks of different security levels includes a Gray Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u009`

> MSC-SR-7 All physical paths within a Gray Network between Inner Encryption Components for Red Networks of different security levels must include a Gray Firewall. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s002`

> Standalone Gray Firewalls have been placed at each site between the Inner Encryption Components and the Outer Encryption Component; these Gray Firewalls are responsible for dropping packets between Inner Encryption Components of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u004.s001`

> Figure 6 also shows an example placement of Gray Firewalls, as long as any path between Inner Encryption Components for networks of different security levels includes a Gray Firewall.

<a id="net-006-map-02"></a>

#### NET-006-MAP-02: [RG-008 - Connectivity restricted to the same security level](../requirements/requirement_groups.md#rg-008)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Provide connectivity within each security level and prevent communication across levels.

**Applicability:** The different-level design described with Figure 6.

**Reasoning:** The prose expressly describes the intended allowed and prohibited communication pattern.

**Requirement strength:** Mandatory separation and conditional permission to share infrastructure.

**Qualifications and exceptions:** The assessment records the presented isolation design, not verified packet-filter behavior.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u003.s002`

> The MSC Solution provides secure connectivity between the Red Networks within each security level while preventing Red Networks of different security levels from communicating with one another.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u003.s002`

> The MSC Solution provides secure connectivity between the Red Networks within each security level while preventing Red Networks of different security levels from communicating with one another.

<a id="net-006-map-03"></a>

#### NET-006-MAP-03: [RG-005 - Physical separation of security components](../requirements/requirement_groups.md#rg-005)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Use standalone Gray Firewalls physically separate from Inner and Outer Encryption Components.

**Applicability:** The required Gray Firewalls in Figure 6.

**Reasoning:** The component discussion directly refers to Figure 6 and states the physical separation.

**Requirement strength:** Mandatory for the stated applicability.

**Qualifications and exceptions:** Product eligibility and actual device identities remain outside the demonstrated placement.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s001`

> As shown in Figure 6, a standalone Gray Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component and Inner Encryption Component.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s001`

> As shown in Figure 6, a standalone Gray Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component and Inner Encryption Component.

<a id="net-006-map-04"></a>

#### NET-006-MAP-04: [RG-040 - Gray Firewall allowlist and cross-level denial](../requirements/requirement_groups.md#rg-040)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Configure the Gray Firewall same-level allowlist and cross-level denial rules.

**Applicability:** Each required Gray Firewall.

**Reasoning:** The prose gives the intended filtering effect, but no address assignments, rule ordering, or protocol-specific rules establish the complete numbered clauses.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-PF-23`: `T=O`; alternatives: `none stated`.
- `MSC-PF-28`: `T=O`; alternatives: `none stated`.
- `MSC-PF-32`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** MSC-PF-32 names Inner VPN Gateways and classification levels; the broader security-level clauses also account for dissemination controls.

Group interpretation issues: REQ-I02, REQ-I09.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u010`

> MSC-PF-23 If a Gray Firewall is required (i.e., networks of multiple protection levels are included in the solution) the Gray Firewall must allow appropriate traffic (IKE, IPsec, MKA and MACsec) between Red Networks operating at the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u005`

> MSC-PF-28 If a Gray Firewall is required, the Gray Firewall must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u009`

> MSC-PF-32 The Gray Firewall must block all traffic routed to and between two or more Inner VPN Gateways of different classification levels. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u005.s003`

> This filtering component restricts the traffic flow based primarily on the Gray Network source and destination addresses, and only allows a packet through if the source and destination components intend to communicate with one another and drops the packet if they are not.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s006`

> The Gray Firewall blocks any packets sent between Inner Encryption Components for Red Networks of different security levels.

<a id="net-006-map-05"></a>

#### NET-006-MAP-05: [RG-039 - Outer Gray-interface allowlist and default denial](../requirements/requirement_groups.md#rg-039)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Apply the Outer Gray-interface same-level allowlist and default denial despite the Gray Firewalls.

**Applicability:** Every Outer Encryption Component in the design.

**Reasoning:** The source expressly retains Outer filtering obligations. The example does not supply Outer ACLs.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-PF-17`: `T=O`; alternatives: `none stated`.
- `MSC-PF-20`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** A Gray Firewall does not discharge Outer-component filtering obligations.

Group interpretation issues: REQ-I02, REQ-I09.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u004`

> MSC-PF-17 The Gray Network interfaces of Outer Encryption Components must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u007`

> MSC-PF-20 The Gray Network interfaces of Outer Encryption Components must deny all traffic that is not explicitly allowed by requirements MSC-PF-8, MSC- PF-13, MSC-PF-15, or MSC-PF-19. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s001`

> Including one or more standalone Gray Firewalls in a solution does not remove the requirement to perform the filtering on the Outer Encryption Component as well.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s002`

> Outer Encryption Components are uniquely positioned to block traffic between Inner Encryption Components supporting Red Networks of different security levels when one of those Inner Encryption Components is located at a different site.

<a id="net-006-map-06"></a>

#### NET-006-MAP-06: [RG-014 - Gray addressing supports security-level filtering](../requirements/requirement_groups.md#rg-014)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Assign addresses unique to each security level to support the required peer filtering.

**Applicability:** The multiple security levels in the example.

**Reasoning:** The setup states the address-assignment obligation but supplies no ranges or addresses.

**Requirement strength:** Mandatory for the stated applicability.

**Qualifications and exceptions:** The same-level wording conflict in the other RG-014 passage remains open; no conflicting sentence is silently repaired.

Group interpretation issues: REQ-I02.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s001`

> When multiple security levels are used, it is critical to enforce proper IP address assignment and firewall rule sets.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s002`

> The IP address assigned must be unique to that security level such that each network’s Inner Encryption Component is only able to send and receive traffic to its respective Inner Encryption Component at the other site.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s001`

> When multiple security levels are used, it is critical to enforce proper IP address assignment and firewall rule sets.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s002`

> The IP address assigned must be unique to that security level such that each network’s Inner Encryption Component is only able to send and receive traffic to its respective Inner Encryption Component at the other site.

<a id="net-006-map-07"></a>

#### NET-006-MAP-07: [RG-053 - Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053)

**required_but_not_demonstrated** | Basis: `visual_interpretation` | Scope: selected clause only.

**Clause assessed:** Provide a unique physical Outer internal interface for each Red Network.

**Applicability:** Three Red Networks share each Outer component.

**Reasoning:** The figure shows an aggregate connection through a Gray Firewall without physical port identities or counts.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-10`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** Do not infer VLAN trunking or a missing interface from a high-level line.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u012`

> MSC-SR-10 The Outer Encryption Component must use a unique physical internal interface for each Red Network in the MSC Solution (i.e., VLAN trunking of multiple enclaves is not permitted). T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label001`

> Black Network

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label002`

> Site A

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label003`

> Site B

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label004`

> Solution Boundary

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label005`

> Network 1 Top Secret

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label007`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label008`

> Network 2 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label009`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label010`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label011`

> Network 3 Secret (Coalition)

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label012`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label013`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label014`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label015`

> Gray Firewall

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label016`

> Gray Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label017`

> Network 1 Top Secret

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label018`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label019`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label020`

> Network 2 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label021`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label022`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label023`

> Network 3 Secret (Coalition)

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label024`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label025`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label026`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label027`

> Gray Firewall

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label028`

> Gray Management Services

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u003.s001`

> A single implementation of the MSC Solution may support Red Networks of different security levels, to include unclassified networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u003.s002`

> The MSC Solution provides secure connectivity between the Red Networks within each security level while preventing Red Networks of different security levels from communicating with one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u003.s003`

> This enables a customer to use the same infrastructure to carry traffic from multiple networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u004.s001`

> For Red Networks of different security levels, the cryptographic separation of their traffic on a Gray Network, as described in Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u004.s002`

> 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u004.s003`

> 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u004.s004`

> 1, is still present.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u004.s005`

> However, because the consequences of an unintended data flow between different security levels are more severe than of one with a single security level, an additional mechanism is necessary to prevent such a flow from occurring.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u005.s001`

> This CP uses packet filtering within Gray Networks as an additional mechanism to prevent data flows between networks of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u005.s002`

> Any physical path through a Gray Network between multiple Inner Encryption Components supporting Red Networks of different security levels must include at least one filtering component.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u005.s003`

> This filtering component restricts the traffic flow based primarily on the Gray Network source and destination addresses, and only allows a packet through if the source and destination components intend to communicate with one another and drops the packet if they are not.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s001`

> When multiple security levels are used, it is critical to enforce proper IP address assignment and firewall rule sets.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s002`

> The IP address assigned must be unique to that security level such that each network’s Inner Encryption Component is only able to send and receive traffic to its respective Inner Encryption Component at the other site.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s001`

> Additionally, filtering components are included between the components used for management of the Gray Networks themselves (namely, AWs and locally run CAs) and Inner Encryption Components that support Red Networks of a lower security level than the Red Network with the highest security level supported by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s002`

> In other words, AWs and locally run CAs on Gray Networks are treated as, and grouped with, the Inner Encryption Component for the Red Network with the highest security level.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s001`

> One or more Gray Firewalls must be included in the Gray Network to perform filtering.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s002`

> Standalone Gray Firewalls have been placed at each site between the Inner Encryption Components and the Outer Encryption Component; these Gray Firewalls are responsible for dropping packets between Inner Encryption Components of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u004.s001`

> Figure 6 also shows an example placement of Gray Firewalls, as long as any path between Inner Encryption Components for networks of different security levels includes a Gray Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s001`

> Including one or more standalone Gray Firewalls in a solution does not remove the requirement to perform the filtering on the Outer Encryption Component as well.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s002`

> Outer Encryption Components are uniquely positioned to block traffic between Inner Encryption Components supporting Red Networks of different security levels when one of those Inner Encryption Components is located at a different site.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s001`

> The Gray Firewall is located between the Outer Encryption Component and Inner Encryption Component(s).

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s002`

> As described in Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s003`

> 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s004`

> 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s005`

> 2, an MSC Solution that supports multiple Red Networks of different security levels must include one or more Gray Firewalls.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s006`

> The Gray Firewall blocks any packets sent between Inner Encryption Components for Red Networks of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s007`

> A Gray Firewall also blocks any packets sent between management components on the Gray Network and Inner Encryption Components for Red Networks that operate at a security level other than the highest security level of data protected by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s008`

> Gray Firewalls are physically protected as classified devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s001`

> As shown in Figure 6, a standalone Gray Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component and Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s002`

> A Gray Firewall would typically only be used in solutions where the physical design of the Gray Network includes paths between Inner Encryption Components for Red Networks of different security levels that do not pass through the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s003`

> Effectively, each Gray Firewall is another instance of the Gray Network filtering performed by the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s004`

> For load balancing or other performance reasons, multiple Gray Firewalls that comply with the requirements of this CP are acceptable.

<a id="net-007"></a>

## NET-007: MACsec encapsulation at the outer component internal interface

### Requirement-group assessment

Figure 7 presents encapsulation on the Outer component incoming interface. The separate-encapsulator condition is absent; protocol approval and deployed parameters remain unspecified.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-015: MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015) | Encapsulate Inner MACsec traffic at the Outer incoming interface before applying Outer encryption. | [Presented as satisfying](network_requirement_links.md#net-007-map-01) |
| [RG-015: MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015) | Treat a required standalone encapsulator as a Solution Component for Section 11.1. | [Not applicable to selected alternative](network_requirement_links.md#net-007-map-02) |
| [RG-015: MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015) | Use an AO-approved encapsulation protocol. | [Required; implementation not demonstrated](network_requirement_links.md#net-007-map-03) |

<a id="net-007-map-01"></a>

#### NET-007-MAP-01: [RG-015 - MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Encapsulate Inner MACsec traffic at the Outer incoming interface before applying Outer encryption.

**Applicability:** The integrated-encapsulation alternative in Figure 7.

**Reasoning:** The text explicitly identifies Figure 7 as the internal-interface pseudowire arrangement and permits integrated encapsulation on VPN or MACsec Outer devices.

**Requirement strength:** Encapsulation is required; any AO-approved encapsulation protocol is permitted. The extent of standalone-device obligations is disputed by the source.

**Qualifications and exceptions:** The clause does not specify one encapsulation protocol or a concrete configuration.

Group interpretation issues: REQ-I01.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s001`

> The MACsec-encrypted traffic needs to be encapsulated if the MACsec Device is the first layer of encryption in the MSC Solution or if the MACsec-encrypted traffic needs to traverse an IP-based network.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s001`

> In some commercial MACsec Devices, encapsulation can be applied on the internal interface by creating a pseudowire (see Figure 7), which emulates a point-to-point connection.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s002`

> Some VPN Gateways and MACsec Devices allow this encapsulation to occur on the incoming interface, prior to encrypting traffic for the outer tunnel.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s001`

> In some commercial MACsec Devices, encapsulation can be applied on the internal interface by creating a pseudowire (see Figure 7), which emulates a point-to-point connection.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s002`

> Some VPN Gateways and MACsec Devices allow this encapsulation to occur on the incoming interface, prior to encrypting traffic for the outer tunnel.

<a id="net-007-map-02"></a>

#### NET-007-MAP-02: [RG-015 - MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015)

**not_applicable** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Treat a required standalone encapsulator as a Solution Component for Section 11.1.

**Applicability:** Figure 7 uses the integrated feature and does not require a standalone encapsulator.

**Reasoning:** MSC-MD-13 has a standalone-device antecedent. The illustrated integrated alternative does not meet that antecedent.

**Requirement strength:** Encapsulation is required; any AO-approved encapsulation protocol is permitted. The extent of standalone-device obligations is disputed by the source.

- `MSC-MD-13`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The exemption is limited to the standalone-device clause; normal requirements still apply to the Outer Encryption Component.

Group interpretation issues: REQ-I01.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s001`

> In some commercial MACsec Devices, encapsulation can be applied on the internal interface by creating a pseudowire (see Figure 7), which emulates a point-to-point connection.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s002`

> If this feature is not supported, a standalone device is needed to encapsulate the MACsec-encrypted data (see Figure 8).

<a id="net-007-map-03"></a>

#### NET-007-MAP-03: [RG-015 - MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Use an AO-approved encapsulation protocol.

**Applicability:** The pseudowire carrying Inner MACsec traffic.

**Reasoning:** The setup lists protocol examples but gives no selected protocol or AO approval.

**Requirement strength:** Encapsulation is required; any AO-approved encapsulation protocol is permitted. The extent of standalone-device obligations is disputed by the source.

**Qualifications and exceptions:** L2TPv3 and Ethernet over MPLS are examples, not mandatory protocol choices.

Group interpretation issues: REQ-I01.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s004`

> Any AO-approved encapsulation protocol may be used.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u010.s001`

> This CP does not mandate the use of a specific protocol for encapsulation.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u010.s002`

> Options include, but are not limited to, Layer 2 Tunneling Protocol version 3, and Ethernet over Multiprotocol Label Switching.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s001`

> Each layer of the MSC Solution can use either an IPsec tunnel or MACsec tunnel.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s002`

> An IPsec tunnel is established between VPN Gateways.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s003`

> A MACsec tunnel is established between MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s004`

> Table 1 identifies four different layering options provided by this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s005`

> For configurations 2 and 4 which use an outer MACsec tunnel these solutions would only be point to point solutions instead of a multi-site solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u003`

> 1 IPsec IPsec

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u004`

> 2 IPsec MACsec

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u005`

> 3 MACsec IPsec

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u006`

> 4 MACsec MACsec

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u007.s001`

> MACsec was designed to provide hop-to-hop security within a Local Area Network (LAN).

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u007.s002`

> As MACsec- encrypted traffic arrives at an interface, it is typically decrypted, examined, and re-encrypted after determining its destination.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s001`

> The MACsec-encrypted traffic needs to be encapsulated if the MACsec Device is the first layer of encryption in the MSC Solution or if the MACsec-encrypted traffic needs to traverse an IP-based network.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s002`

> Encapsulation creates a new packet by adding a new header, and sometimes trailer, to the MACsec-encrypted traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s003`

> Encapsulation ensures the MACsec-encrypted traffic is not decrypted prior to reaching its destination and ensures the second layer of encryption can be applied.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s001`

> In some commercial MACsec Devices, encapsulation can be applied on the internal interface by creating a pseudowire (see Figure 7), which emulates a point-to-point connection.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s002`

> If this feature is not supported, a standalone device is needed to encapsulate the MACsec-encrypted data (see Figure 8).

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s003`

> If using a standalone device, the internal interface will be connected to the Inner MACsec Device and the external interface will be connected to the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s004`

> Since this device resides in the Gray Network, all requirements for Solution Components must be implemented.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u010.s001`

> This CP does not mandate the use of a specific protocol for encapsulation.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u010.s002`

> Options include, but are not limited to, Layer 2 Tunneling Protocol version 3, and Ethernet over Multiprotocol Label Switching.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s002`

> Some VPN Gateways and MACsec Devices allow this encapsulation to occur on the incoming interface, prior to encrypting traffic for the outer tunnel.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s004`

> Any AO-approved encapsulation protocol may be used.

<a id="net-008"></a>

## NET-008: MACsec encapsulation by a separate device

### Requirement-group assessment

Figure 8 presents a standalone encapsulator and its two interfaces. The scope and strength of the encapsulator controls conflict across prose and MSC-MD-13.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-015: MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015) | Insert the standalone encapsulator between Inner MACsec and Outer encryption, with the stated internal/external attachments. | [Presented as satisfying](network_requirement_links.md#net-008-map-01) |
| [RG-015: MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015) | Determine the standalone encapsulator boundary and applicable Solution Component controls. | [Ambiguous](network_requirement_links.md#net-008-map-02) |
| [RG-036: Minimal network-interface exposure](../requirements/requirement_groups.md#rg-036) | Apply minimal address/port/protocol exposure and disable unused interfaces on the standalone encapsulator. | [Ambiguous](network_requirement_links.md#net-008-map-03) |
| [RG-015: MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015) | Use an AO-approved encapsulation protocol. | [Required; implementation not demonstrated](network_requirement_links.md#net-008-map-04) |

<a id="net-008-map-01"></a>

#### NET-008-MAP-01: [RG-015 - MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Insert the standalone encapsulator between Inner MACsec and Outer encryption, with the stated internal/external attachments.

**Applicability:** The selected Outer component lacks integrated encapsulation.

**Reasoning:** The source explicitly names Figure 8 and specifies both interface attachments.

**Requirement strength:** Encapsulation is required; any AO-approved encapsulation protocol is permitted. The extent of standalone-device obligations is disputed by the source.

**Qualifications and exceptions:** The arrangement establishes the encapsulation location only.

Group interpretation issues: REQ-I01.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s002`

> If this feature is not supported, a standalone device is needed to encapsulate the MACsec-encrypted data (see Figure 8).

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s003`

> If using a standalone device, the internal interface will be connected to the Inner MACsec Device and the external interface will be connected to the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s002`

> If this feature is not supported, a standalone device is needed to encapsulate the MACsec-encrypted data (see Figure 8).

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s003`

> If using a standalone device, the internal interface will be connected to the Inner MACsec Device and the external interface will be connected to the Outer Encryption Component.

<a id="net-008-map-02"></a>

#### NET-008-MAP-02: [RG-015 - MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015)

**ambiguous** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Determine the standalone encapsulator boundary and applicable Solution Component controls.

**Applicability:** The separate encapsulation device in Figure 8.

**Reasoning:** Pages 19 and 25 require all Solution Component requirements; page 20 places the step outside the solution and highly recommends DM and filtering; MSC-MD-13 explicitly applies Section 11.1. The source does not reconcile those scopes.

**Requirement strength:** Encapsulation is required; any AO-approved encapsulation protocol is permitted. The extent of standalone-device obligations is disputed by the source.

- `MSC-MD-13`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** No single mandatory scope is substituted for the conflicting passages. Section 11.1 remains explicit in MSC-MD-13.

Group interpretation issues: REQ-I01.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s004`

> Since this device resides in the Gray Network, all requirements for Solution Components must be implemented.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s002`

> This additional step falls outside the boundary of the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s003`

> However, it is highly recommended to apply the general device management (DM) and port filtering requirements for Solution Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s004`

> Since this device resides in the Gray Network, all requirements for Solution Components must be implemented.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s002`

> This additional step falls outside the boundary of the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s003`

> However, it is highly recommended to apply the general device management (DM) and port filtering requirements for Solution Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

<a id="net-008-map-03"></a>

#### NET-008-MAP-03: [RG-036 - Minimal network-interface exposure](../requirements/requirement_groups.md#rg-036)

**ambiguous** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Apply minimal address/port/protocol exposure and disable unused interfaces on the standalone encapsulator.

**Applicability:** Applicability depends on the unresolved standalone Solution Component scope.

**Reasoning:** The broad prose would impose MSC-PF-1 and MSC-PF-2; the outside-boundary passage recommends filtering. The figure supplies no interface restriction settings under either reading.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-PF-1`: `T=O`; alternatives: `none stated`.
- `MSC-PF-2`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The mapping records ambiguous applicability and unshown configuration. It does not turn the recommendation into an unconditional mandate.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u014`

> MSC-PF-1 All Solution Components must have all network interfaces restricted to the smallest address ranges, ports, and protocols possible. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u015`

> MSC-PF-2 All Solution Components must have all unused network interfaces disabled. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s004`

> Since this device resides in the Gray Network, all requirements for Solution Components must be implemented.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s003`

> However, it is highly recommended to apply the general device management (DM) and port filtering requirements for Solution Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

<a id="net-008-map-04"></a>

#### NET-008-MAP-04: [RG-015 - MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Use an AO-approved encapsulation protocol.

**Applicability:** The selected standalone device and protocol.

**Reasoning:** The source permits any AO-approved protocol, but the example identifies neither the selected protocol nor approval evidence.

**Requirement strength:** Encapsulation is required; any AO-approved encapsulation protocol is permitted. The extent of standalone-device obligations is disputed by the source.

**Qualifications and exceptions:** The named protocol options are non-exhaustive.

Group interpretation issues: REQ-I01.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s004`

> Any AO-approved encapsulation protocol may be used.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s004`

> Any AO-approved encapsulation protocol may be used.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u010.s002`

> Options include, but are not limited to, Layer 2 Tunneling Protocol version 3, and Ethernet over Multiprotocol Label Switching.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u007.s001`

> MACsec was designed to provide hop-to-hop security within a Local Area Network (LAN).

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u007.s002`

> As MACsec- encrypted traffic arrives at an interface, it is typically decrypted, examined, and re-encrypted after determining its destination.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s001`

> The MACsec-encrypted traffic needs to be encapsulated if the MACsec Device is the first layer of encryption in the MSC Solution or if the MACsec-encrypted traffic needs to traverse an IP-based network.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s002`

> Encapsulation creates a new packet by adding a new header, and sometimes trailer, to the MACsec-encrypted traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s003`

> Encapsulation ensures the MACsec-encrypted traffic is not decrypted prior to reaching its destination and ensures the second layer of encryption can be applied.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s001`

> In some commercial MACsec Devices, encapsulation can be applied on the internal interface by creating a pseudowire (see Figure 7), which emulates a point-to-point connection.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s002`

> If this feature is not supported, a standalone device is needed to encapsulate the MACsec-encrypted data (see Figure 8).

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s003`

> If using a standalone device, the internal interface will be connected to the Inner MACsec Device and the external interface will be connected to the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s004`

> Since this device resides in the Gray Network, all requirements for Solution Components must be implemented.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u010.s001`

> This CP does not mandate the use of a specific protocol for encapsulation.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u010.s002`

> Options include, but are not limited to, Layer 2 Tunneling Protocol version 3, and Ethernet over Multiprotocol Label Switching.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s001`

> When the Inner Encryption Component is a MACsec Device the traffic requires additional encapsulation before it is passed through the Outer Encryption Component to the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s002`

> This additional step falls outside the boundary of the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s003`

> However, it is highly recommended to apply the general device management (DM) and port filtering requirements for Solution Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s002`

> Some VPN Gateways and MACsec Devices allow this encapsulation to occur on the incoming interface, prior to encrypting traffic for the outer tunnel.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s004`

> Any AO-approved encapsulation protocol may be used.

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

<a id="net-009"></a>

## NET-009: Redundant Outer Encryption Components

### Requirement-group assessment

Figure 9 presents redundant outer components and shared Gray routing. MSC-SR-7 supplies the required Gray Firewalls on paths between different security levels. Device counts, exact placement, filtering rules, and failover settings remain unspecified.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-074: Redundant component and load-balancing permission](../requirements/requirement_groups.md#rg-074) | Add parallel redundant Outer components with two Outer tunnels and a Gray router selecting an outbound component. | [Presented as satisfying](network_requirement_links.md#net-009-map-01) |
| [RG-013: Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013) | Include a Gray Firewall on paths between Inner components of different security levels. | [Presented as satisfying](network_requirement_links.md#net-009-map-02) |
| [RG-031: Routing and switching limits on Encryption Components](../requirements/requirement_groups.md#rg-031) | Keep routing protocols off Outer Encryption Components. | [Required; implementation not demonstrated](network_requirement_links.md#net-009-map-03) |
| [RG-074: Redundant component and load-balancing permission](../requirements/requirement_groups.md#rg-074) | Apply Solution Component security requirements to the ordinary Gray router solely because it forwards redundancy traffic. | [Not applicable to selected alternative](network_requirement_links.md#net-009-map-04) |
| [RG-053: Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053) | Place the multiple Inner components in parallel when sharing Outer components. | [Presented as satisfying](network_requirement_links.md#net-009-map-05) |
| [RG-053: Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053) | Use a unique physical Outer internal interface for each Red Network. | [Required; implementation not demonstrated](network_requirement_links.md#net-009-map-06) |

<a id="net-009-map-01"></a>

#### NET-009-MAP-01: [RG-074 - Redundant component and load-balancing permission](../requirements/requirement_groups.md#rg-074)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Add parallel redundant Outer components with two Outer tunnels and a Gray router selecting an outbound component.

**Applicability:** The availability arrangement in Figure 9.

**Reasoning:** The prose explicitly describes those components and paths as the redundancy example.

**Requirement strength:** Conditional permission; automatic high availability and failover design are not guaranteed by this CP.

**Qualifications and exceptions:** Every redundant component must still meet applicable requirements. No concrete failover mechanism or availability test is supplied.

Group scope notes: REQ-I14.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s004`

> However, this CP does not prohibit adding redundant components in parallel to allow for component failover or to increase the throughput of the MSC Solution, as long as each redundant component adheres to the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s001`

> Figure 9 shows an MSC Solution between two sites where each site has a redundant Outer Encryption Component (Management components are omitted from the figure for clarity).

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s002`

> There are two outer encryption tunnels that transit the Black Network: one between the upper pair of Outer Encryption Components, and one between the lower pair of Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003`

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s001`

> Figure 9 shows an MSC Solution between two sites where each site has a redundant Outer Encryption Component (Management components are omitted from the figure for clarity).

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s002`

> There are two outer encryption tunnels that transit the Black Network: one between the upper pair of Outer Encryption Components, and one between the lower pair of Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003`

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.

<a id="net-009-map-02"></a>

#### NET-009-MAP-02: [RG-013 - Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Include a Gray Firewall on paths between Inner components of different security levels.

**Applicability:** The figure labels Secret U.S.-only and Secret Coalition networks and connects their Inner components through shared Gray routers.

**Reasoning:** MSC-SR-7 explicitly requires a Gray Firewall on every physical Gray path between Inner components for different security levels. The requirement supplies the missing firewall detail in the simplified redundancy diagram. The described design includes that path constraint under the text-precedence policy.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-7`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The drawing records schematic connectivity. It does not establish a direct physical bypass of the textually required Gray Firewall. The number of firewalls, their exact attachment points, and their rules remain unspecified.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u009`

> MSC-SR-7 All physical paths within a Gray Network between Inner Encryption Components for Red Networks of different security levels must include a Gray Firewall. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label001`

> Black Network

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label002`

> Site A

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label003`

> Site B

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label004`

> Solution Boundary

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label005`

> Network 1 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label007`

> Network 2 Secret (Coalition)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label008`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label009`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label010`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label011`

> Router

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label012`

> Network 1 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label013`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label014`

> Network 2 Secret (Coalition)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label015`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label016`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label017`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label018`

> Router

<a id="net-009-map-03"></a>

#### NET-009-MAP-03: [RG-031 - Routing and switching limits on Encryption Components](../requirements/requirement_groups.md#rg-031)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Keep routing protocols off Outer Encryption Components.

**Applicability:** The Outer components in the redundancy design.

**Reasoning:** The source assigns route selection to separate Gray routers, but gives no Outer routing-protocol configuration.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-OR-8`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** An ordinary Gray router is outside the component-specific MSC-OR-8 prohibition; moving the routing role does not verify disabled Outer routing protocols.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u007`

> MSC-OR-8 Outer Encryption Components must not use routing protocols (e.g., OSPF, BGP). T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003`

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.

<a id="net-009-map-04"></a>

#### NET-009-MAP-04: [RG-074 - Redundant component and load-balancing permission](../requirements/requirement_groups.md#rg-074)

**not_applicable** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Apply Solution Component security requirements to the ordinary Gray router solely because it forwards redundancy traffic.

**Applicability:** The ordinary router in Figure 9.

**Reasoning:** The source explicitly says the CP levies no security requirements on that router/switch.

**Requirement strength:** Conditional permission; automatic high availability and failover design are not guaranteed by this CP.

**Qualifications and exceptions:** A router that also performs standalone MACsec encapsulation has a different scope under RG-015.

Group scope notes: REQ-I14.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s004`

> This router is part of the solution only in the sense that it is part of the network infrastructure of the Gray Network; this CP does not levy any security requirements on the router/switch.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003`

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s004`

> This router is part of the solution only in the sense that it is part of the network infrastructure of the Gray Network; this CP does not levy any security requirements on the router/switch.

<a id="net-009-map-05"></a>

#### NET-009-MAP-05: [RG-053 - Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053)

**presented_as_satisfying** | Basis: `visual_interpretation` | Scope: selected clause only.

**Clause assessed:** Place the multiple Inner components in parallel when sharing Outer components.

**Applicability:** The two Inner components at each site.

**Reasoning:** Each Inner component has its own branch to the Gray router; neither is placed behind the other.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-16`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The assertion is limited to the drawn parallel arrangement.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u006`

> MSC-SR-16 When multiple Inner Encryption Components share an Outer Encryption Component, they must be placed in parallel. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label001`

> Black Network

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label002`

> Site A

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label003`

> Site B

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label004`

> Solution Boundary

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label005`

> Network 1 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label007`

> Network 2 Secret (Coalition)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label008`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label009`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label010`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label011`

> Router

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label012`

> Network 1 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label013`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label014`

> Network 2 Secret (Coalition)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label015`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label016`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label017`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label018`

> Router

<a id="net-009-map-06"></a>

#### NET-009-MAP-06: [RG-053 - Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053)

**required_but_not_demonstrated** | Basis: `visual_interpretation` | Scope: selected clause only.

**Clause assessed:** Use a unique physical Outer internal interface for each Red Network.

**Applicability:** The two Red Networks sharing each Outer component.

**Reasoning:** The schematic does not enumerate physical Outer interfaces or reveal how the shared router reaches those interfaces.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-10`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The single drawn connection does not prove an interface-count violation.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u012`

> MSC-SR-10 The Outer Encryption Component must use a unique physical internal interface for each Red Network in the MSC Solution (i.e., VLAN trunking of multiple enclaves is not permitted). T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label001`

> Black Network

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label002`

> Site A

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label003`

> Site B

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label004`

> Solution Boundary

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label005`

> Network 1 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label007`

> Network 2 Secret (Coalition)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label008`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label009`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label010`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label011`

> Router

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label012`

> Network 1 Secret (US Only)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label013`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label014`

> Network 2 Secret (Coalition)

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label015`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label016`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label017`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label018`

> Router

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s001`

> The high-level designs described in Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s002`

> 2 are not designed with the intent of automatically providing high availability.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s003`

> Supporting solution implementations where high availability is important is not a goal of this version of the CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s004`

> However, this CP does not prohibit adding redundant components in parallel to allow for component failover or to increase the throughput of the MSC Solution, as long as each redundant component adheres to the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s001`

> Figure 9 shows an MSC Solution between two sites where each site has a redundant Outer Encryption Component (Management components are omitted from the figure for clarity).

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s002`

> There are two outer encryption tunnels that transit the Black Network: one between the upper pair of Outer Encryption Components, and one between the lower pair of Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003`

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s004`

> This router is part of the solution only in the sense that it is part of the network infrastructure of the Gray Network; this CP does not levy any security requirements on the router/switch.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s005`

> The MSC Solution can maintain connectivity between the two sites even if one of the Outer Encryption Components fails because traffic will be routed through the tunnel that has not failed.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u002.s001`

> Figure 9 shows a simple example of how redundancy could be added, if needed, for an MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u002.s002`

> Implementing standby or failover Encryption Components, performing load balancing between Encryption Components, or other techniques to improve the availability or throughput of the solution are outside the scope of this CP and are not discussed further.

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u009`

> MSC-SR-7 All physical paths within a Gray Network between Inner Encryption Components for Red Networks of different security levels must include a Gray Firewall. T=O

<a id="net-010"></a>

## NET-010: CNSA 2.0 IKEv2 peer exchange

### Requirement-group assessment

Figure 10 presents the CNSA 2.0 Objective exchange sequence. Full profile conformance and all tunnel algorithm settings are not established by the exchange arrows.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-019: IPsec CNSA profile and post-quantum exchange sequence](../requirements/requirement_groups.md#rg-019) | Use CNSA 1.0 in IKE_SA_INIT and ML-KEM in a subsequent IKE_INTERMEDIATE exchange. | [Presented as satisfying](network_requirement_links.md#net-010-map-01) |
| [RG-019: IPsec CNSA profile and post-quantum exchange sequence](../requirements/requirement_groups.md#rg-019) | Implement the complete Objective profile, including RFC 9370, RFC 9242, and RFC 7383. | [Required; implementation not demonstrated](network_requirement_links.md#net-010-map-02) |
| [RG-019: IPsec CNSA profile and post-quantum exchange sequence](../requirements/requirement_groups.md#rg-019) | Use the complete Table 7 algorithm suite for all IPsec tunnels except IKE_SA_INIT. | [Required; implementation not demonstrated](network_requirement_links.md#net-010-map-03) |

<a id="net-010-map-01"></a>

#### NET-010-MAP-01: [RG-019 - IPsec CNSA profile and post-quantum exchange sequence](../requirements/requirement_groups.md#rg-019)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Use CNSA 1.0 in IKE_SA_INIT and ML-KEM in a subsequent IKE_INTERMEDIATE exchange.

**Applicability:** The illustrated CNSA 2.0 IPsec Objective alternative.

**Reasoning:** The text explicitly describes Figure 10 and the order of the two key establishments. The preceding profile text specifies ML-KEM-1024.

**Requirement strength:** MSC-VG-1 is Threshold; MSC-VG-19/20/21 are the corresponding Objective profile. Current objective status is distinct from prospective future requirements.

- `MSC-VG-19`: `O`; alternatives: `MSC-VG-1`.

**Qualifications and exceptions:** MSC-VG-19 is Objective and an alternative to Threshold MSC-VG-1. The example does not make the Objective profile a current universal mandate.

Group scope notes: REQ-I14.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s002`

> The key- establishment algorithm used in the Initial IKE SA (IKE_SA_INIT) exchange must be constrained enough in size as to not induce IP fragmentation.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s003`

> The ML-KEM-1024 public key and ciphertext sizes are too large for this initial exchange and thus the IKE_SA_INIT exchange must use a CNSA 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s004`

> 0-compliant key establishment algorithm.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s005`

> A subsequent Intermediate IKE (IKE_INTERMEDIATE) exchange (as specified in RFC 9242) is then used to perform an ML-KEM key establishment.

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u011`

> MSC-VG-19 All IPsec connections must use multiple key exchanges with an initial IKEv2 SA key exchange and an intermediate IKEv2 key exchange: • IKE_SA_INIT: The IKEv2 SA key exchange performed in IKE_SA_INIT must use a CNSA 1.0 key establishment algorithm (as specified in Table 6). • IKE_INTERMEDIATE: The IKEv2 SA key establishment performed in the IKE_INTERMEDIATE exchange must use ML- KEM-1024 (as specified in Table 7). O MSC-VG-1

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u001.s002`

> 0-compliant algorithms ML-KEM-1024 [FIPS203] for key establishment and ML-DSA-87 [FIPS204] for digital signatures within IPsec.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s002`

> The key- establishment algorithm used in the Initial IKE SA (IKE_SA_INIT) exchange must be constrained enough in size as to not induce IP fragmentation.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s003`

> The ML-KEM-1024 public key and ciphertext sizes are too large for this initial exchange and thus the IKE_SA_INIT exchange must use a CNSA 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s004`

> 0-compliant key establishment algorithm.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s005`

> A subsequent Intermediate IKE (IKE_INTERMEDIATE) exchange (as specified in RFC 9242) is then used to perform an ML-KEM key establishment.

<a id="net-010-map-02"></a>

#### NET-010-MAP-02: [RG-019 - IPsec CNSA profile and post-quantum exchange sequence](../requirements/requirement_groups.md#rg-019)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Implement the complete Objective profile, including RFC 9370, RFC 9242, and RFC 7383.

**Applicability:** An implementation selecting the CNSA 2.0 Objective profile.

**Reasoning:** The explanation describes the RFC mechanisms and permitted IKEv2 fragmentation, but supplies no implementation-conformance evidence.

**Requirement strength:** MSC-VG-1 is Threshold; MSC-VG-19/20/21 are the corresponding Objective profile. Current objective status is distinct from prospective future requirements.

- `MSC-VG-20`: `O`; alternatives: `MSC-VG-1`.

**Qualifications and exceptions:** The document references a draft profile. The extraction preserves the versioned source claim without updating it to a later standard.

Group scope notes: REQ-I14.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u012`

> MSC-VG-20 All IPsec connections must use IETF standards compliant with IKE implementations as specified in Commercial National Security Algorithm (CNSA) Suite 2.0 Profile for IPsec (draft-guthrie-cnsa2- ipsec-profile) including RFC 9370, RFC 9242, and RFC 7383. O MSC-VG-1

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u003.s001`

> • RFC 9242 Intermediate Key Exchanges in IKEv2

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u004.s001`

> • RFC 9370 Multiple Key Exchanges in IKEv2

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u009.s001`

> RFC 7383 IKEv2 Fragmentation: Describes a way to prevent IP fragmentation of large encrypted IKEv2 messages by fragmenting at the IKEv2 layer.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s006`

> This second exchange, encrypted using keys established by IKE_SA_INIT, can leverage the IKEv2-level fragmentation mechanism specified in RFC 7383.

<a id="net-010-map-03"></a>

#### NET-010-MAP-03: [RG-019 - IPsec CNSA profile and post-quantum exchange sequence](../requirements/requirement_groups.md#rg-019)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Use the complete Table 7 algorithm suite for all IPsec tunnels except IKE_SA_INIT.

**Applicability:** The Objective profile represented by the exchange.

**Reasoning:** The source names ML-KEM-1024 and ML-DSA-87 but the example does not show every ESP or IKE algorithm setting for every tunnel.

**Requirement strength:** MSC-VG-1 is Threshold; MSC-VG-19/20/21 are the corresponding Objective profile. Current objective status is distinct from prospective future requirements.

- `MSC-VG-21`: `O`; alternatives: `MSC-VG-1`.

**Qualifications and exceptions:** The IKE_SA_INIT exception remains explicit; Objective status is preserved.

Group scope notes: REQ-I14.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u013`

> MSC-VG-21 The VPN Components must use algorithms from the algorithm suite in Table 7 for all IPsec VPN O MSC-VG-1 tunnels, with the exception of the IKE_SA_INIT exchange.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u001.s001`

> The draft profile (draft-guthrie-cnsa2-ipsec-profile) specifies the use of the CNSA 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u001.s002`

> 0-compliant algorithms ML-KEM-1024 [FIPS203] for key establishment and ML-DSA-87 [FIPS204] for digital signatures within IPsec.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s001`

> As part of the CNSA 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s002`

> 0 migration, the VPN Gateways will have to implement CNSA 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s003`

> 0-compliant key establishment and digital signatures.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s004`

> As of now, this is an objective design feature but will be required in the future for the use of IPsec in MSC.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s005`

> The CNSA Suite 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s006`

> 0 is relevant to the choice of cryptography employed in IPsec and especially affects the Internet Key Exchange Protocol Version 2 (IKEv2) key establishment construction, requiring support for several new RFCs.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s007`

> NSA has worked with industry to develop an implementation profile, CNSA Suite 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s008`

> 0 Profile for IPsec (draft-guthrie-cnsa2-ipsec-profile).

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u001.s001`

> The draft profile (draft-guthrie-cnsa2-ipsec-profile) specifies the use of the CNSA 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u001.s002`

> 0-compliant algorithms ML-KEM-1024 [FIPS203] for key establishment and ML-DSA-87 [FIPS204] for digital signatures within IPsec.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u001.s003`

> It describes the use of RFCs that are required in order to support the large ML- KEM-1024 public key and ciphertext sizes, including:

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u002.s001`

> • RFC 7383 IKEv2 Message Fragmentation

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u003.s001`

> • RFC 9242 Intermediate Key Exchanges in IKEv2

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u004.s001`

> • RFC 9370 Multiple Key Exchanges in IKEv2

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u005.s001`

> • draft-ietf-ipsecme-ikev2-pqc-auth Signature Authentication in the IKEv2 using PQC

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u006.s001`

> • RFC 9881 Internet X.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u006.s002`

> 509 Public Key Infrastructure - Algorithm Identifiers for the Module-Lattice- Based Digital Signature Algorithm (ML-DSA)

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u007.s001`

> • draft-ietf-ipsecme-ikev2-mlkem Post-quantum Key Exchange with ML-KEM in the IKEv2

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s001`

> These additional RFCs facilitate the use of ML-KEM-1024 without causing IP-level fragmentation, which can create operational challenges and prevent the establishment of a connection.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s002`

> In particular, if ML- KEM-1024 were used in the initial IKEv2 Security Association (SA) key exchange (IKE_SA_INIT), the sizes of its public key and ciphertext would cause the initiator and responder messages to exceed the typical path Maximum Transmission Unit (MTU) and necessitate IP-level fragmentation.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s003`

> In order to prevent this issue, the solution leveraged first performs a CNSA 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s004`

> 0-compliant key establishment that does not exceed PMTU and subsequently performs an additional key establishment using a newly-defined exchange called Intermediate Exchange (IKE_INTERMEDIATE).

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s005`

> IKE_INTERMEDIATE exchanges can circumvent IP-level fragmentation by using IKEv2-level fragmentation, which does not incur the same operational issues.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s006`

> The specifications of which this solution is comprised work as follows:

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u009.s001`

> RFC 7383 IKEv2 Fragmentation: Describes a way to prevent IP fragmentation of large encrypted IKEv2 messages by fragmenting at the IKEv2 layer.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u009.s002`

> This allows IKEv2 messages to traverse network devices that do not allow IP fragments to pass through.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u010.s001`

> RFC 9242 Intermediate Key Exchanges: Specifies a new exchange type called IKE_INTERMEDIATE.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u010.s002`

> IKE_INTERMEDIATE exchanges can be used for transferring large amounts of data in the process of establishing an IKEv2 Security Association.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u010.s003`

> It is sent after IKE_SA_INIT and before IKE_AUTH.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u011.s001`

> RFC 9370 Multiple Key Exchanges: Leverages the IKE_INTERMEDIATE exchange specified in RFC 9242 in order to perform multiple key establishments.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u011.s002`

> In particular, this document enables the use of a quantum resistant key establishment algorithm whose public key and ciphertexts would exceed MTU and cause IP fragmentation of the IKE_SA_INIT messages.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u011.s003`

> The document resolves this issue by specifying how to perform such large key establishments in IKE_INTERMEDIATE which can benefit from the IKEv2 fragmentation mechanism specified in RFC 7383.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u011.s004`

> An initial key establishment that does not cause IP fragmentation is first performed in IKE_SA_INIT, followed by additional key establishment(s) using IKE_INTERMEDIATE message(s).

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s001`

> As detailed in Figure 10, RFC 9370 enables peers to perform multiple key exchanges.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s002`

> The key- establishment algorithm used in the Initial IKE SA (IKE_SA_INIT) exchange must be constrained enough in size as to not induce IP fragmentation.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s003`

> The ML-KEM-1024 public key and ciphertext sizes are too large for this initial exchange and thus the IKE_SA_INIT exchange must use a CNSA 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s004`

> 0-compliant key establishment algorithm.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s005`

> A subsequent Intermediate IKE (IKE_INTERMEDIATE) exchange (as specified in RFC 9242) is then used to perform an ML-KEM key establishment.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s006`

> This second exchange, encrypted using keys established by IKE_SA_INIT, can leverage the IKEv2-level fragmentation mechanism specified in RFC 7383.

<a id="net-011"></a>

## NET-011: Four layering configurations

### Requirement-group assessment

Table 1 presents four permitted layer pairings. Outer MACsec point-to-point scope and Inner MACsec encapsulation are conditional requirements for the selected row.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-007: Two independent encryption layers and allowed tunnel pairings](../requirements/requirement_groups.md#rg-007) | Select one of the four Inner/Outer IPsec and MACsec pairings. | [Presented as satisfying](network_requirement_links.md#net-011-map-01) |
| [RG-015: MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015) | Encapsulate Inner MACsec before Outer encryption; apply MSC-MD-13 if a standalone device is required. | [Required; implementation not demonstrated](network_requirement_links.md#net-011-map-02) |

<a id="net-011-map-01"></a>

#### NET-011-MAP-01: [RG-007 - Two independent encryption layers and allowed tunnel pairings](../requirements/requirement_groups.md#rg-007)

**presented_as_satisfying** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Select one of the four Inner/Outer IPsec and MACsec pairings.

**Applicability:** The four Table 1 configuration alternatives.

**Reasoning:** The table enumerates all four pairings identified by the grouped prose.

**Requirement strength:** Architectural requirements and permitted alternatives; Table 1 enumerates four permitted layer combinations.

**Qualifications and exceptions:** Rows 2 and 4 use Outer MACsec and are limited to point-to-point solutions. The table does not identify deployed sites or protocols beyond the layer choices.

Group interpretation issues: REQ-I12.

Group scope notes: REQ-I14.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s001`

> Each layer of the MSC Solution can use either an IPsec tunnel or MACsec tunnel.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s004`

> Table 1 identifies four different layering options provided by this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s005`

> For configurations 2 and 4 which use an outer MACsec tunnel these solutions would only be point to point solutions instead of a multi-site solution.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u003`

> 1 IPsec IPsec

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u004`

> 2 IPsec MACsec

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u005`

> 3 MACsec IPsec

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u006`

> 4 MACsec MACsec

<a id="net-011-map-02"></a>

#### NET-011-MAP-02: [RG-015 - MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Encapsulate Inner MACsec before Outer encryption; apply MSC-MD-13 if a standalone device is required.

**Applicability:** Table 1 configurations 3 and 4.

**Reasoning:** The table identifies Inner MACsec but gives no encapsulation location or device capability.

**Requirement strength:** Encapsulation is required; any AO-approved encapsulation protocol is permitted. The extent of standalone-device obligations is disputed by the source.

- `MSC-MD-13`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** Rows 1 and 2 have Inner IPsec. MSC-MD-13 is conditional on a standalone device and retains the scope issue documented in NET-008.

Group interpretation issues: REQ-I01.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u005`

> 3 MACsec IPsec

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u006`

> 4 MACsec MACsec

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u003`

> 1 IPsec IPsec

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u004`

> 2 IPsec MACsec

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u005`

> 3 MACsec IPsec

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u006`

> 4 MACsec MACsec

<a id="net-012"></a>

## NET-012: Separated Gray data and management networks

### Requirement-group assessment

The prose presents separate Gray data and management networks. Physical separation, cryptographic separation, and minimum ACL separation are cumulative controls whose implementation is not shown.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-044: Layer-specific administration and management-plane separation](../requirements/requirement_groups.md#rg-044) | Separate Gray data and management traffic physically and cryptographically, with management components administering data components. | [Presented as satisfying](network_requirement_links.md#net-012-map-01) |
| [RG-044: Layer-specific administration and management-plane separation](../requirements/requirement_groups.md#rg-044) | Satisfy physical and cryptographic traffic separation together with minimum Gray Firewall ACL separation. | [Required; implementation not demonstrated](network_requirement_links.md#net-012-map-02) |

<a id="net-012-map-01"></a>

#### NET-012-MAP-01: [RG-044 - Layer-specific administration and management-plane separation](../requirements/requirement_groups.md#rg-044)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Separate Gray data and management traffic physically and cryptographically, with management components administering data components.

**Applicability:** The separated-network configuration described in the prose.

**Reasoning:** The source directly presents separate Gray networks as the resulting architecture and explicitly rejects VLAN-only separation.

**Requirement strength:** Mandatory administrative separation; administrative functionality may be distributed across the AW set.

**Qualifications and exceptions:** Control-plane traffic has no general matching separation obligation unless another clause specifies one.

Group scope notes: REQ-I07.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s001`

> Data plane and management plane traffic must be physically and cryptographically separated from one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s002`

> Use of a Virtual Local Area Network (VLAN) alone is not sufficient to separate data plane and management plane traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s003`

> As a result, a solution may have a Gray Data Network and a Gray Management Network that are separate from one another, where the components on the Gray Management Network are used to manage the components on the Gray Data Network.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s001`

> Data plane and management plane traffic must be physically and cryptographically separated from one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s002`

> Use of a Virtual Local Area Network (VLAN) alone is not sufficient to separate data plane and management plane traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s003`

> As a result, a solution may have a Gray Data Network and a Gray Management Network that are separate from one another, where the components on the Gray Management Network are used to manage the components on the Gray Data Network.

<a id="net-012-map-02"></a>

#### NET-012-MAP-02: [RG-044 - Layer-specific administration and management-plane separation](../requirements/requirement_groups.md#rg-044)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Satisfy physical and cryptographic traffic separation together with minimum Gray Firewall ACL separation.

**Applicability:** Gray Management and Gray Data Networks.

**Reasoning:** The clauses impose cumulative restrictions: MSC-DM-25 requires at least logical ACL separation, and the prose adds physical and cryptographic separation. The partial configuration supplies no implementation evidence for all three controls.

**Requirement strength:** Mandatory administrative separation; administrative functionality may be distributed across the AW set.

- `MSC-DM-25`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** VLAN or ACL separation alone does not discharge the physical and cryptographic requirements. No source conflict is inferred merely because the requirements operate at different levels.

Group scope notes: REQ-I07.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u013`

> MSC-DM-25 The Gray Management and Gray Data Networks must be at minimum logically separated by the Gray Firewall using ACL. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s001`

> Data plane and management plane traffic must be physically and cryptographically separated from one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s002`

> Use of a Virtual Local Area Network (VLAN) alone is not sufficient to separate data plane and management plane traffic.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u013`

> MSC-DM-25 The Gray Management and Gray Data Networks must be at minimum logically separated by the Gray Firewall using ACL. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s001`

> Data plane and management plane traffic must be physically and cryptographically separated from one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s002`

> Use of a Virtual Local Area Network (VLAN) alone is not sufficient to separate data plane and management plane traffic.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s001`

> Data plane and management plane traffic must be physically and cryptographically separated from one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s002`

> Use of a Virtual Local Area Network (VLAN) alone is not sufficient to separate data plane and management plane traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s003`

> As a result, a solution may have a Gray Data Network and a Gray Management Network that are separate from one another, where the components on the Gray Management Network are used to manage the components on the Gray Data Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s004`

> Unless otherwise specified given that some control plane traffic is necessary for a network to function, there is no general requirement that control plane traffic be similarly separated.

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u013`

> MSC-DM-25 The Gray Management and Gray Data Networks must be at minimum logically separated by the Gray Firewall using ACL. T=O

<a id="net-013"></a>

## NET-013: Unclassified network behind its own inner component

### Requirement-group assessment

The text permits an unclassified network behind its own Inner component. Treating that network as Red triggers the same conditional isolation and parallel-placement obligations as other shared-Outer networks.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-008: Connectivity restricted to the same security level](../requirements/requirement_groups.md#rg-008) | Place the included unclassified network behind its own Inner component and apply Red Network requirements. | [Presented as satisfying](network_requirement_links.md#net-013-map-01) |
| [RG-013: Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013) | Include Gray Firewalls on shared paths to Inner components of different security levels. | [Required; implementation not demonstrated](network_requirement_links.md#net-013-map-02) |
| [RG-053: Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053) | Use parallel Inner components and unique physical Outer internal interfaces when sharing an Outer component. | [Required; implementation not demonstrated](network_requirement_links.md#net-013-map-03) |

<a id="net-013-map-01"></a>

#### NET-013-MAP-01: [RG-008 - Connectivity restricted to the same security level](../requirements/requirement_groups.md#rg-008)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Place the included unclassified network behind its own Inner component and apply Red Network requirements.

**Applicability:** An unclassified network included behind an Outer Encryption Component.

**Reasoning:** The source expressly gives the permitted arrangement and the Red-equivalent requirement condition.

**Requirement strength:** Mandatory separation and conditional permission to share infrastructure.

**Qualifications and exceptions:** Unclassified status does not waive the Inner layer or other applicable CP requirements.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s002`

> An unclassified network can also be included behind the Outer Encryption Component but must be behind its own Inner Encryption Component and meet the requirements in this CP as if it was a Red Network.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s002`

> An unclassified network can also be included behind the Outer Encryption Component but must be behind its own Inner Encryption Component and meet the requirements in this CP as if it was a Red Network.

<a id="net-013-map-02"></a>

#### NET-013-MAP-02: [RG-013 - Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Include Gray Firewalls on shared paths to Inner components of different security levels.

**Applicability:** If the unclassified network shares Gray paths with classified networks.

**Reasoning:** The text permits inclusion but supplies no full path diagram or firewall placement for the conditional mixed-level deployment.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-7`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The condition depends on actual shared paths and other networks. Missing details are not evidence of a violation.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u009`

> MSC-SR-7 All physical paths within a Gray Network between Inner Encryption Components for Red Networks of different security levels must include a Gray Firewall. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s002`

> An unclassified network can also be included behind the Outer Encryption Component but must be behind its own Inner Encryption Component and meet the requirements in this CP as if it was a Red Network.

<a id="net-013-map-03"></a>

#### NET-013-MAP-03: [RG-053 - Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Use parallel Inner components and unique physical Outer internal interfaces when sharing an Outer component.

**Applicability:** If the included unclassified network shares its Outer component with other Red-equivalent networks.

**Reasoning:** The prose supplies the own-Inner condition but not a physical interface or parallel-path implementation.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-10`: `T=O`; alternatives: `none stated`.
- `MSC-SR-16`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The two numbered clauses apply when their stated shared/multiple-network conditions hold.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u006`

> MSC-SR-16 When multiple Inner Encryption Components share an Outer Encryption Component, they must be placed in parallel. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u012`

> MSC-SR-10 The Outer Encryption Component must use a unique physical internal interface for each Red Network in the MSC Solution (i.e., VLAN trunking of multiple enclaves is not permitted). T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s002`

> An unclassified network can also be included behind the Outer Encryption Component but must be behind its own Inner Encryption Component and meet the requirements in this CP as if it was a Red Network.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s001`

> There is no limit to the number of different security levels that an MSC Solution may support.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s002`

> An unclassified network can also be included behind the Outer Encryption Component but must be behind its own Inner Encryption Component and meet the requirements in this CP as if it was a Red Network.

<a id="net-014"></a>

## NET-014: Gray logs transferred to Red SIEM through CDS

### Requirement-group assessment

The text permits Gray logs to reach a Red SIEM through an approved CDS. Required external CDS approval conditions and concrete monitoring configuration remain separate evidence needs.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-050: SIEM placement, collection, alerting, and log transport](../requirements/requirement_groups.md#rg-050) | Use a Red SIEM with an approved CDS as the alternative to a Gray SIEM for Gray log functions. | [Presented as satisfying](network_requirement_links.md#net-014-map-01) |
| [RG-051: Cross Domain Solution approval conditions](../requirements/requirement_groups.md#rg-051) | Meet DoDI 8540.01, the DISN Connection Process Guide, and the NCDSMO CDS Baseline condition. | [Required; implementation not demonstrated](network_requirement_links.md#net-014-map-02) |

<a id="net-014-map-01"></a>

#### NET-014-MAP-01: [RG-050 - SIEM placement, collection, alerting, and log transport](../requirements/requirement_groups.md#rg-050)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Use a Red SIEM with an approved CDS as the alternative to a Gray SIEM for Gray log functions.

**Applicability:** The Gray-to-Red log transfer arrangement.

**Reasoning:** The source explicitly permits the Red SIEM/CDS alternative and states that a Gray SIEM is not mandatory.

**Requirement strength:** Conditional configuration descriptions; log encryption is stated as should; Gray SIEM deployment is explicitly optional.

**Qualifications and exceptions:** The Continuous Monitoring Annex supplies additional requirements; the example does not establish all alert rules or log-transport protection.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s003`

> These functions can also be performed on a Red SIEM using an approved CDS, as described in the CSfC Continuous Monitoring Annex.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s004`

> A Gray SIEM is not a mandatory component of the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s003`

> Implementations may employ a SIEM in the Gray Management Services for log management of Gray infrastructure components except where AOs use a CDS to move Gray Network log data to a Red SIEM.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s003`

> These functions can also be performed on a Red SIEM using an approved CDS, as described in the CSfC Continuous Monitoring Annex.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s004`

> A Gray SIEM is not a mandatory component of the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s003`

> Implementations may employ a SIEM in the Gray Management Services for log management of Gray infrastructure components except where AOs use a CDS to move Gray Network log data to a Red SIEM.

<a id="net-014-map-02"></a>

#### NET-014-MAP-02: [RG-051 - Cross Domain Solution approval conditions](../requirements/requirement_groups.md#rg-051)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Meet DoDI 8540.01, the DISN Connection Process Guide, and the NCDSMO CDS Baseline condition.

**Applicability:** Any CDS selected for the illustrated transfer.

**Reasoning:** Calling the CDS approved describes the required class, but the example names no product, baseline entry, or approval record.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-22`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** All three external conditions are conjunctive. The mapping does not infer approval evidence from the word approved.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u012`

> MSC-SR-22 If a CDS is being leveraged within the solution, then it must adhere with DoDI 8540.01, the DISN Connection Process Guide, and the CDS must be on the National Cross Domain Strategy Management Office CDS Baseline. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s003`

> These functions can also be performed on a Red SIEM using an approved CDS, as described in the CSfC Continuous Monitoring Annex.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u012`

> MSC-SR-22 If a CDS is being leveraged within the solution, then it must adhere with DoDI 8540.01, the DISN Connection Process Guide, and the CDS must be on the National Cross Domain Strategy Management Office CDS Baseline. T=O

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s001`

> Gray Network components consist of the Outer Encryption Component, Gray Firewall, and Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s002`

> All Gray Network components are physically protected at the same level as the Red Network components of the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s003`

> Gray Management Services are physically connected to the Gray Firewall and include, at a minimum, a AW that can be a physical workstation or Virtual Machine (VM).

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s004`

> The Gray Management Services may also include a Security Information and Event Management (SIEM) unless the SIEM is implemented in the Red Network in conjunction with a cross domain solution (CDS) (see CSfC Continuous Monitoring Annex).

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s005`

> This CP requires the management of Gray Network components through a Gray AW.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s006`

> As a result, neither Red nor Black AWs are permitted to manage the Outer Encryption Component, Gray Firewall, or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s007`

> Additionally, the Gray AWs are prohibited from managing Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s002`

> The SIEM is configured to provide alerts for specific events including if the Outer Encryption Component or Gray Firewall receives and drops any unexpected traffic that could indicate a compromise.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s003`

> These functions can also be performed on a Red SIEM using an approved CDS, as described in the CSfC Continuous Monitoring Annex.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s004`

> A Gray SIEM is not a mandatory component of the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s001`

> Each component in the solution has one or more AWs that maintain, monitor, and control all security functions for that component.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s002`

> It should be noted that all of the required administrative functionality does not need to be present in each individual management component, but the entire set of AWs must collectively meet administrative functionality requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s003`

> Implementations may employ a SIEM in the Gray Management Services for log management of Gray infrastructure components except where AOs use a CDS to move Gray Network log data to a Red SIEM.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u012`

> MSC-SR-22 If a CDS is being leveraged within the solution, then it must adhere with DoDI 8540.01, the DISN Connection Process Guide, and the CDS must be on the National Cross Domain Strategy Management Office CDS Baseline. T=O

<a id="net-015"></a>

## NET-015: Screening router on the Black Network

### Requirement-group assessment

The screening-router example is an optional Black Network control outside the MSC Solution. It does not replace the conditional Outer Firewall requirement.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-075: Optional additional controls and screening-router scope](../requirements/requirement_groups.md#rg-075) | Use an existing or added screening router to filter Black packets before Outer components. | [Presented as satisfying](network_requirement_links.md#net-015-map-01) |
| [RG-034: Outer Firewall placement for untrusted Black transport](../requirements/requirement_groups.md#rg-034) | Add the required Outer Firewall if the Black transport is the Public Internet. | [Required; implementation not demonstrated](network_requirement_links.md#net-015-map-02) |

<a id="net-015-map-01"></a>

#### NET-015-MAP-01: [RG-075 - Optional additional controls and screening-router scope](../requirements/requirement_groups.md#rg-075)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Use an existing or added screening router to filter Black packets before Outer components.

**Applicability:** The optional screening-router alternatives.

**Reasoning:** The source directly describes both locations and places the router outside the MSC Solution.

**Requirement strength:** Permissions with explicit component-scope limitations.

**Qualifications and exceptions:** A Customer Edge Router is an example of the screening role, not an additional mandatory device.

Group interpretation issues: REQ-I12.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002`

> A screening router can be used to filter packets from Black Networks before they arrive at Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s003`

> The screening router could be part of an existing Black Network (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s004`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s005`

> , Customer Edge Router), or could be added between Outer Encryption Components and existing Black Network components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s006`

> However, since the screening router would become part of a Black Network, it is not considered to be part of the MSC Solution itself.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002`

> A screening router can be used to filter packets from Black Networks before they arrive at Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s003`

> The screening router could be part of an existing Black Network (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s004`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s005`

> , Customer Edge Router), or could be added between Outer Encryption Components and existing Black Network components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s006`

> However, since the screening router would become part of a Black Network, it is not considered to be part of the MSC Solution itself.

<a id="net-015-map-02"></a>

#### NET-015-MAP-02: [RG-034 - Outer Firewall placement for untrusted Black transport](../requirements/requirement_groups.md#rg-034)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Add the required Outer Firewall if the Black transport is the Public Internet.

**Applicability:** Conditional on the unspecified Black transport being the Public Internet.

**Reasoning:** The screening passage does not identify the transport type or an Outer Firewall. Its optional screening control does not demonstrate the mandatory firewall placement under that condition.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-12`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** No violation is asserted when the antecedent is unknown. The screening router is not silently reclassified as an Outer Firewall.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u002`

> MSC-SR-12 If the MSC Solution uses the Public Internet for its Black transport network, an Outer Firewall must be located between the Black transport network and the Outer Encryption Component. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002`

> A screening router can be used to filter packets from Black Networks before they arrive at Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s006`

> However, since the screening router would become part of a Black Network, it is not considered to be part of the MSC Solution itself.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s001`

> There are additional controls that could be used within this solution to potentially reduce the overall risk.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002`

> A screening router can be used to filter packets from Black Networks before they arrive at Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s003`

> The screening router could be part of an existing Black Network (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s004`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s005`

> , Customer Edge Router), or could be added between Outer Encryption Components and existing Black Network components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s006`

> However, since the screening router would become part of a Black Network, it is not considered to be part of the MSC Solution itself.

<a id="net-016"></a>

## NET-016: Dedicated physical and virtual administrative workstations

### Requirement-group assessment

The text presents physical and virtual AW alternatives with dedication and cohosting constraints. Facility protection and operating policy compliance require evidence beyond a permitted arrangement.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-045: Dedicated, protected, hardened Administrative Workstations](../requirements/requirement_groups.md#rg-045) | Use dedicated physical AWs or dedicated AW VM hosts and exclude the listed non-AW and non-CSfC functions. | [Presented as satisfying](network_requirement_links.md#net-016-map-01) |
| [RG-045: Dedicated, protected, hardened Administrative Workstations](../requirements/requirement_groups.md#rg-045) | Keep provisioning, enrollment, registration, and SIEM functions off AW hosts even when those functions use separate VMs. | [Required; implementation not demonstrated](network_requirement_links.md#net-016-map-02) |
| [RG-045: Dedicated, protected, hardened Administrative Workstations](../requirements/requirement_groups.md#rg-045) | Protect the AW facility, apply required hardening and operating policies, and power off AWs when idle. | [Required; implementation not demonstrated](network_requirement_links.md#net-016-map-03) |

<a id="net-016-map-01"></a>

#### NET-016-MAP-01: [RG-045 - Dedicated, protected, hardened Administrative Workstations](../requirements/requirement_groups.md#rg-045)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Use dedicated physical AWs or dedicated AW VM hosts and exclude the listed non-AW and non-CSfC functions.

**Applicability:** The physical-AW and virtual-AW alternatives.

**Reasoning:** The source presents both realization choices together with their explicit restrictions. The extracted configurations preserve those restrictions.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-DM-1`: `T=O`; alternatives: `none stated`.
- `MSC-DM-23`: `T=O`; alternatives: `none stated`.
- `MSC-DM-28`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The example is a constrained design alternative. It does not attest the applications installed on a real workstation.

Group scope notes: REQ-I06.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s001`

> AWs may be virtual machines (VMs) on a physical host/server that is dedicated to hosting AWs VMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s003`

> A physical host/server that hosts AWs VMs may not host VMs used for non-CSfC purposes.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004`

> If an AW is a physical workstation, then that workstation cannot also be used for provisioning, enrollment, certificate registrations, SIEM services, or for any non- CSfC functions.

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u016`

> MSC-DM-1 If using physical AWs, they must be dedicated for the purposes given in this CP and must be physically separated from workstations used to manage non-CSfC solutions. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u011`

> MSC-DM-23 Hosts/servers for management VMs may not host VMs that perform non-CSfC functions. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u016`

> MSC-DM-28 The AW must not also be used for provisioning, certificate registrations, and SIEM services. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s001`

> AWs may be virtual machines (VMs) on a physical host/server that is dedicated to hosting AWs VMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s003`

> A physical host/server that hosts AWs VMs may not host VMs used for non-CSfC purposes.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004`

> If an AW is a physical workstation, then that workstation cannot also be used for provisioning, enrollment, certificate registrations, SIEM services, or for any non- CSfC functions.

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u016`

> MSC-DM-1 If using physical AWs, they must be dedicated for the purposes given in this CP and must be physically separated from workstations used to manage non-CSfC solutions. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u011`

> MSC-DM-23 Hosts/servers for management VMs may not host VMs that perform non-CSfC functions. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u016`

> MSC-DM-28 The AW must not also be used for provisioning, certificate registrations, and SIEM services. T=O

<a id="net-016-map-02"></a>

#### NET-016-MAP-02: [RG-045 - Dedicated, protected, hardened Administrative Workstations](../requirements/requirement_groups.md#rg-045)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Keep provisioning, enrollment, registration, and SIEM functions off AW hosts even when those functions use separate VMs.

**Applicability:** The virtual-AW hosting alternative.

**Reasoning:** The clauses impose cumulative restrictions. Separate service VMs satisfy functional separation only when their placement also respects the explicit AW-host prohibition. The example gives no host-to-VM allocation to verify both conditions.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-DM-24`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The allowance for separate workstations or VMs does not authorize otherwise prohibited cohosting on an AW host.

Group scope notes: REQ-I06.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u012`

> MSC-DM-24 VMs that perform management services must not also perform other functions within the solution (i.e., provisioning, enrollment, CA registration, SIEM, etc. must be performed by separate workstations or VMs). T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u012`

> MSC-DM-24 VMs that perform management services must not also perform other functions within the solution (i.e., provisioning, enrollment, CA registration, SIEM, etc. must be performed by separate workstations or VMs). T=O

<a id="net-016-map-03"></a>

#### NET-016-MAP-03: [RG-045 - Dedicated, protected, hardened Administrative Workstations](../requirements/requirement_groups.md#rg-045)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Protect the AW facility, apply required hardening and operating policies, and power off AWs when idle.

**Applicability:** Both physical and virtual AW realizations.

**Reasoning:** The setup states operating and facility obligations but gives no protected-facility, hardening, patching, or power-state evidence.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-DM-2`: `T=O`; alternatives: `none stated`.
- `MSC-DM-26`: `T=O`; alternatives: `none stated`.
- `MSC-DM-27`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The requirements apply to the selected realization; hosting permissions do not discharge operational duties.

Group scope notes: REQ-I06.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u017`

> MSC-DM-2 AWs (or hosts/servers hosting VMs serving as AWs) must physically reside within a protected facility where CSfC solution(s) are managed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u014`

> MSC-DM-26 AWs (physical or virtual) must be configured, patched, and operated in accordance with applicable Operating System vendor hardening guide and the organizational or local policy. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u015`

> MSC-DM-27 AWs (physical or virtual) must be powered off when not in use. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u017`

> MSC-DM-2 AWs (or hosts/servers hosting VMs serving as AWs) must physically reside within a protected facility where CSfC solution(s) are managed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s005`

> AWs (physical or virtual) must be configured, patched, and operated in accordance to the organizational or local policy.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s006`

> AWs must also be powered off when not in use.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s001`

> AWs may be virtual machines (VMs) on a physical host/server that is dedicated to hosting AWs VMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s003`

> A physical host/server that hosts AWs VMs may not host VMs used for non-CSfC purposes.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004`

> If an AW is a physical workstation, then that workstation cannot also be used for provisioning, enrollment, certificate registrations, SIEM services, or for any non- CSfC functions.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s005`

> AWs (physical or virtual) must be configured, patched, and operated in accordance to the organizational or local policy.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s006`

> AWs must also be powered off when not in use.

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u016`

> MSC-DM-1 If using physical AWs, they must be dedicated for the purposes given in this CP and must be physically separated from workstations used to manage non-CSfC solutions. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u017`

> MSC-DM-2 AWs (or hosts/servers hosting VMs serving as AWs) must physically reside within a protected facility where CSfC solution(s) are managed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u011`

> MSC-DM-23 Hosts/servers for management VMs may not host VMs that perform non-CSfC functions. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u012`

> MSC-DM-24 VMs that perform management services must not also perform other functions within the solution (i.e., provisioning, enrollment, CA registration, SIEM, etc. must be performed by separate workstations or VMs). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u016`

> MSC-DM-28 The AW must not also be used for provisioning, certificate registrations, and SIEM services. T=O

<a id="net-017"></a>

## NET-017: Local Gray AW direct or same-site management

### Requirement-group assessment

The source distinguishes the direct physical management exception from the same-site CNSA algorithm exception. Neither exception establishes an unrestricted plaintext LAN management option.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-046: Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046) | Allow local management through a direct physical connection, exemplified by a serial cable from Gray AW to Outer component. | [Presented as satisfying](network_requirement_links.md#net-017-map-01) |
| [RG-046: Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046) | Permit the same-site Gray AW example to omit CNSA Suite algorithms when traffic avoids an untrusted network. | [Presented as satisfying](network_requirement_links.md#net-017-map-02) |
| [RG-046: Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046) | Interpret the LAN/VLAN exception relative to the preceding Black-network two-layer requirement. | [Ambiguous](network_requirement_links.md#net-017-map-03) |

<a id="net-017-map-01"></a>

#### NET-017-MAP-01: [RG-046 - Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Allow local management through a direct physical connection, exemplified by a serial cable from Gray AW to Outer component.

**Applicability:** The direct-cable local-management alternative.

**Reasoning:** The source explicitly gives the serial-cable example as the exception to management encryption.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-DM-8`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The permission is tied to a direct physical connection. It does not cover an arbitrary same-site network path.

Group interpretation issues: REQ-I03.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s001`

> Management traffic for all MSC Solution Components is always encrypted to protect confidentially and integrity, except in the case where components are locally managed through a direct physical connection (i.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s002`

> e.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s003`

> , serial cable from a Gray AW to the Outer Encryption Component).

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u007`

> MSC-DM-8 All administration of Solution Components must securely be performed from an AW remotely using an NSA-approved solution (e.g., CP or High Assurance encryptor), or by managing the Solution Components locally. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s001`

> Management traffic for all MSC Solution Components is always encrypted to protect confidentially and integrity, except in the case where components are locally managed through a direct physical connection (i.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s002`

> e.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s003`

> , serial cable from a Gray AW to the Outer Encryption Component).

<a id="net-017-map-02"></a>

#### NET-017-MAP-02: [RG-046 - Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Permit the same-site Gray AW example to omit CNSA Suite algorithms when traffic avoids an untrusted network.

**Applicability:** The Gray AW and Outer component are at the same site in the stated example.

**Reasoning:** The source expressly states the algorithm exception and its transport rationale.

**Requirement strength:** Mandatory for the stated applicability.

**Qualifications and exceptions:** The exception concerns CNSA algorithms; the listed secure management protocols and other applicable controls remain separate obligations.

Group interpretation issues: REQ-I03.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s008`

> For example, a Gray AW residing within the Gray Management Services at the same site as the Outer Encryption Component need not use CNSA Suite algorithms since this traffic does not traverse an untrusted network.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s008`

> For example, a Gray AW residing within the Gray Management Services at the same site as the Outer Encryption Component need not use CNSA Suite algorithms since this traffic does not traverse an untrusted network.

<a id="net-017-map-03"></a>

#### NET-017-MAP-03: [RG-046 - Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046)

**ambiguous** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Interpret the LAN/VLAN exception relative to the preceding Black-network two-layer requirement.

**Applicability:** The same-LAN/VLAN management alternative.

**Reasoning:** The phrase "This requirement" immediately follows the two-layer Black-network sentence. The source does not explicitly say that all same-LAN management can be plaintext.

**Requirement strength:** Mandatory for the stated applicability.

**Qualifications and exceptions:** The extraction retains the ambiguity and makes no broad plaintext permission.

Group interpretation issues: REQ-I03.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s004`

> Management traffic must be encrypted with SSHv2, TLS 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s005`

> 2 or later, IPsec or MACsec.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s006`

> When components are managed over the Black Network, a CSfC Solution must be implemented to provide two layers of approved encryption.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s007`

> This requirement is not applicable if the MSC Solution Components are managed from the same LAN or VLAN.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s004`

> Management traffic must be encrypted with SSHv2, TLS 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s005`

> 2 or later, IPsec or MACsec.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s006`

> When components are managed over the Black Network, a CSfC Solution must be implemented to provide two layers of approved encryption.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s007`

> This requirement is not applicable if the MSC Solution Components are managed from the same LAN or VLAN.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s001`

> Management traffic for all MSC Solution Components is always encrypted to protect confidentially and integrity, except in the case where components are locally managed through a direct physical connection (i.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s002`

> e.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s003`

> , serial cable from a Gray AW to the Outer Encryption Component).

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s004`

> Management traffic must be encrypted with SSHv2, TLS 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s005`

> 2 or later, IPsec or MACsec.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s006`

> When components are managed over the Black Network, a CSfC Solution must be implemented to provide two layers of approved encryption.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s007`

> This requirement is not applicable if the MSC Solution Components are managed from the same LAN or VLAN.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s008`

> For example, a Gray AW residing within the Gray Management Services at the same site as the Outer Encryption Component need not use CNSA Suite algorithms since this traffic does not traverse an untrusted network.

<a id="net-018"></a>

## NET-018: Alternative approved egress alongside the MSC Solution

### Requirement-group assessment

The footnote permits two approved egress alternatives at one site. Authorization and conformity of particular products or a complete CSfC deployment are not supplied.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-056: Approved physical paths out of Red Networks](../requirements/requirement_groups.md#rg-056) | Provide parallel protected egress through an NSA-certified product and through a CP-conforming CSfC solution. | [Presented as satisfying](network_requirement_links.md#net-018-map-01) |
| [RG-056: Approved physical paths out of Red Networks](../requirements/requirement_groups.md#rg-056) | Establish AO approval or CP conformity for every actual physical path leaving Red. | [Required; implementation not demonstrated](network_requirement_links.md#net-018-map-02) |

<a id="net-018-map-01"></a>

#### NET-018-MAP-01: [RG-056 - Approved physical paths out of Red Networks](../requirements/requirement_groups.md#rg-056)

**presented_as_satisfying** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Provide parallel protected egress through an NSA-certified product and through a CP-conforming CSfC solution.

**Applicability:** The two physical egress alternatives in the MSC-SR-14 footnote.

**Reasoning:** The footnote explicitly permits both paths at one site, so the alternatives illustrate the approved-path condition.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-14`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The CSfC path denotes a whole solution, not a single component. No unprotected egress is permitted.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u004`

> MSC-SR-14 The only approved physical paths leaving the Red Network must be through an MSC Solution in accordance with this CP or via an AO-approved solution for protecting data in transit1. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u015.s001`

> In some cases, the customer will need to communicate with other sites that have NSA-certified Government-off- the-Shelf products.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u015.s002`

> In particular, it is acceptable for a given site to have both an egress path via an NSA-certified product and an egress path via a CSfC Solution conforming to a CP.

<a id="net-018-map-02"></a>

#### NET-018-MAP-02: [RG-056 - Approved physical paths out of Red Networks](../requirements/requirement_groups.md#rg-056)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Establish AO approval or CP conformity for every actual physical path leaving Red.

**Applicability:** A deployment selecting the described egress alternatives.

**Reasoning:** The footnote identifies permitted solution classes but gives no actual authorization record, conformity evidence, or exhaustive inventory of egress links.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-14`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** Permitted coexistence does not certify every path in a deployed network.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u004`

> MSC-SR-14 The only approved physical paths leaving the Red Network must be through an MSC Solution in accordance with this CP or via an AO-approved solution for protecting data in transit1. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u015.s001`

> In some cases, the customer will need to communicate with other sites that have NSA-certified Government-off- the-Shelf products.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u015.s002`

> In particular, it is acceptable for a given site to have both an egress path via an NSA-certified product and an egress path via a CSfC Solution conforming to a CP.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u015.s001`

> In some cases, the customer will need to communicate with other sites that have NSA-certified Government-off- the-Shelf products.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u015.s002`

> In particular, it is acceptable for a given site to have both an egress path via an NSA-certified product and an egress path via a CSfC Solution conforming to a CP.

<a id="net-019"></a>

## NET-019: Combining MSC with another CSfC solution

### Requirement-group assessment

The combined-CP example describes inherited firewall conditions and Inner Firewall placement. The companion CP and complete combined topology remain unspecified.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-055: Firewall requirements when combining capability packages](../requirements/requirement_groups.md#rg-055) | Place an Inner Firewall between the Red Network and Inner Encryption Component when an Inner Firewall is deployed. | [Presented as satisfying](network_requirement_links.md#net-019-map-01) |
| [RG-055: Firewall requirements when combining capability packages](../requirements/requirement_groups.md#rg-055) | Implement a required companion-CP Gray Firewall and follow companion Inner Firewall requirements for combined data-in-transit solutions with end-user devices. | [Required; implementation not demonstrated](network_requirement_links.md#net-019-map-02) |

<a id="net-019-map-01"></a>

#### NET-019-MAP-01: [RG-055 - Firewall requirements when combining capability packages](../requirements/requirement_groups.md#rg-055)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Place an Inner Firewall between the Red Network and Inner Encryption Component when an Inner Firewall is deployed.

**Applicability:** The conditional Inner Firewall arrangement.

**Reasoning:** The source states the two-sided placement directly.

**Requirement strength:** Mandatory for the stated applicability.

**Qualifications and exceptions:** The MSC CP alone does not require an Inner Firewall; companion CP conditions determine deployment.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s001`

> An Inner Firewall is located between the Inner Encryption Component and the Red Network.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s001`

> An Inner Firewall is located between the Inner Encryption Component and the Red Network.

<a id="net-019-map-02"></a>

#### NET-019-MAP-02: [RG-055 - Firewall requirements when combining capability packages](../requirements/requirement_groups.md#rg-055)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Implement a required companion-CP Gray Firewall and follow companion Inner Firewall requirements for combined data-in-transit solutions with end-user devices.

**Applicability:** The combined solution when the respective antecedents hold.

**Reasoning:** The source gives conditional inheritance rules, but identifies no companion CP, device set, or implemented firewall policy.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-11`: `T=O`; alternatives: `none stated`.
- `MSC-SR-13`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** A combined solution does not automatically trigger every firewall condition. The other CP must require a Gray Firewall, or the data-in-transit solution must include end-user devices as specified.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u013`

> MSC-SR-11 A Gray Firewall must be implemented if the MSC Solution is combined with another CSfC solution that requires a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u003`

> MSC-SR-13 If the MSC Solution is combined with other CSfC data-in-transit solutions that include end user devices, the Inner Firewall requirements from that CP must be followed. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s003`

> If the MSC Solution is deployed with solutions from other CSfC CPs then those CPs will specify the Inner Firewall requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u013`

> MSC-SR-11 A Gray Firewall must be implemented if the MSC Solution is combined with another CSfC solution that requires a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u003`

> MSC-SR-13 If the MSC Solution is combined with other CSfC data-in-transit solutions that include end user devices, the Inner Firewall requirements from that CP must be followed. T=O

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s001`

> An Inner Firewall is located between the Inner Encryption Component and the Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s002`

> In this CP, an Inner Firewall is not required.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s003`

> If the MSC Solution is deployed with solutions from other CSfC CPs then those CPs will specify the Inner Firewall requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u013`

> MSC-SR-11 A Gray Firewall must be implemented if the MSC Solution is combined with another CSfC solution that requires a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u003`

> MSC-SR-13 If the MSC Solution is combined with other CSfC data-in-transit solutions that include end user devices, the Inner Firewall requirements from that CP must be followed. T=O

<a id="net-020"></a>

## NET-020: Parallel components for load or availability

### Requirement-group assessment

The text permits parallel redundancy and load balancing. It does not demonstrate all redundant-component controls or an implementation of failover.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-074: Redundant component and load-balancing permission](../requirements/requirement_groups.md#rg-074) | Add parallel redundant components or multiple Outer components, Gray Firewalls, and Inner components for performance. | [Presented as satisfying](network_requirement_links.md#net-020-map-01) |
| [RG-053: Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053) | Place shared-Outer Inner components in parallel and preserve unique physical internal interfaces for each Red Network. | [Required; implementation not demonstrated](network_requirement_links.md#net-020-map-02) |

<a id="net-020-map-01"></a>

#### NET-020-MAP-01: [RG-074 - Redundant component and load-balancing permission](../requirements/requirement_groups.md#rg-074)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Add parallel redundant components or multiple Outer components, Gray Firewalls, and Inner components for performance.

**Applicability:** The redundancy and load-balancing alternatives.

**Reasoning:** The source expressly permits the alternatives subject to each component meeting CP requirements.

**Requirement strength:** Conditional permission; automatic high availability and failover design are not guaranteed by this CP.

**Qualifications and exceptions:** Standby, failover, and load-balancing mechanisms are outside the described CP design scope.

Group scope notes: REQ-I14.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s004`

> However, this CP does not prohibit adding redundant components in parallel to allow for component failover or to increase the throughput of the MSC Solution, as long as each redundant component adheres to the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u003.s001`

> For load balancing or other performance reasons, multiple Outer Encryption Components that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s004`

> For load balancing or other performance reasons, multiple Gray Firewalls that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s002`

> For load balance or other performance reasons, multiple Inner Encryption Components that comply with the requirements of this CP are acceptable.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s004`

> However, this CP does not prohibit adding redundant components in parallel to allow for component failover or to increase the throughput of the MSC Solution, as long as each redundant component adheres to the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u003.s001`

> For load balancing or other performance reasons, multiple Outer Encryption Components that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s004`

> For load balancing or other performance reasons, multiple Gray Firewalls that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s002`

> For load balance or other performance reasons, multiple Inner Encryption Components that comply with the requirements of this CP are acceptable.

<a id="net-020-map-02"></a>

#### NET-020-MAP-02: [RG-053 - Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Place shared-Outer Inner components in parallel and preserve unique physical internal interfaces for each Red Network.

**Applicability:** Any selected redundancy arrangement that shares an Outer component across multiple Red Networks.

**Reasoning:** The text permits multiple components but gives no concrete shared-Outer interface or per-network wiring plan.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-10`: `T=O`; alternatives: `none stated`.
- `MSC-SR-16`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The generic permission does not establish that every possible redundancy layout meets the conditional constraints.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u006`

> MSC-SR-16 When multiple Inner Encryption Components share an Outer Encryption Component, they must be placed in parallel. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u012`

> MSC-SR-10 The Outer Encryption Component must use a unique physical internal interface for each Red Network in the MSC Solution (i.e., VLAN trunking of multiple enclaves is not permitted). T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s002`

> For load balance or other performance reasons, multiple Inner Encryption Components that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u003.s001`

> For load balancing or other performance reasons, multiple Outer Encryption Components that comply with the requirements of this CP are acceptable.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s001`

> The high-level designs described in Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s002`

> 2 are not designed with the intent of automatically providing high availability.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s003`

> Supporting solution implementations where high availability is important is not a goal of this version of the CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s004`

> However, this CP does not prohibit adding redundant components in parallel to allow for component failover or to increase the throughput of the MSC Solution, as long as each redundant component adheres to the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s001`

> Figure 9 shows an MSC Solution between two sites where each site has a redundant Outer Encryption Component (Management components are omitted from the figure for clarity).

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s002`

> There are two outer encryption tunnels that transit the Black Network: one between the upper pair of Outer Encryption Components, and one between the lower pair of Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003`

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s004`

> This router is part of the solution only in the sense that it is part of the network infrastructure of the Gray Network; this CP does not levy any security requirements on the router/switch.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s005`

> The MSC Solution can maintain connectivity between the two sites even if one of the Outer Encryption Components fails because traffic will be routed through the tunnel that has not failed.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u002.s001`

> Figure 9 shows a simple example of how redundancy could be added, if needed, for an MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u002.s002`

> Implementing standby or failover Encryption Components, performing load balancing between Encryption Components, or other techniques to improve the availability or throughput of the solution are outside the scope of this CP and are not discussed further.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u003.s001`

> For load balancing or other performance reasons, multiple Outer Encryption Components that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s001`

> As shown in Figure 6, a standalone Gray Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component and Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s002`

> A Gray Firewall would typically only be used in solutions where the physical design of the Gray Network includes paths between Inner Encryption Components for Red Networks of different security levels that do not pass through the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s003`

> Effectively, each Gray Firewall is another instance of the Gray Network filtering performed by the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s004`

> For load balancing or other performance reasons, multiple Gray Firewalls that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s001`

> Inner Encryption Components can either be VPN Gateways or MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s002`

> For load balance or other performance reasons, multiple Inner Encryption Components that comply with the requirements of this CP are acceptable.

<a id="net-021"></a>

## NET-021: Existing Black and Red routing protocols

### Requirement-group assessment

The text permits existing Black/Red routing protocols with AO approval. That permission does not authorize routing protocols on Outer Encryption Components.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-041: Control-plane approval, defaults, and service location](../requirements/requirement_groups.md#rg-041) | Continue using existing GRE, MPLS, or OSPF in Black and/or Red Networks when the AO approves. | [Presented as satisfying](network_requirement_links.md#net-021-map-01) |
| [RG-031: Routing and switching limits on Encryption Components](../requirements/requirement_groups.md#rg-031) | Keep routing protocols disabled on Outer Encryption Components. | [Required; implementation not demonstrated](network_requirement_links.md#net-021-map-02) |

<a id="net-021-map-01"></a>

#### NET-021-MAP-01: [RG-041 - Control-plane approval, defaults, and service location](../requirements/requirement_groups.md#rg-041)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Continue using existing GRE, MPLS, or OSPF in Black and/or Red Networks when the AO approves.

**Applicability:** The existing-protocol configuration example.

**Reasoning:** The source explicitly states the continuation permission and its approval condition.

**Requirement strength:** Mandatory service placement, approval restrictions, and Layer-3 default; conditional protocol permissions.

**Qualifications and exceptions:** No specific protocol deployment or AO approval record is supplied; the status concerns the permitted alternative.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u005.s001`

> The MSC Solution can be implemented to take advantage of standards-based routing protocols that are already used in the Black and/or Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u005.s002`

> For example, networks that currently use Generic Routing Encapsulation (GRE), Multiprotocol Label Switching or OSPF protocols can continue to use these in conjunction with this solution to provide routing as long as the AO approves their use.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u005.s001`

> The MSC Solution can be implemented to take advantage of standards-based routing protocols that are already used in the Black and/or Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u005.s002`

> For example, networks that currently use Generic Routing Encapsulation (GRE), Multiprotocol Label Switching or OSPF protocols can continue to use these in conjunction with this solution to provide routing as long as the AO approves their use.

<a id="net-021-map-02"></a>

#### NET-021-MAP-02: [RG-031 - Routing and switching limits on Encryption Components](../requirements/requirement_groups.md#rg-031)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Keep routing protocols disabled on Outer Encryption Components.

**Applicability:** Any Outer components in the solution using the permitted surrounding-network routing.

**Reasoning:** The example locates routing in Black/Red networks but supplies no Outer component configuration.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-OR-8`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The permission for existing network protocols does not repeal the component-specific prohibition.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u007`

> MSC-OR-8 Outer Encryption Components must not use routing protocols (e.g., OSPF, BGP). T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u005.s001`

> The MSC Solution can be implemented to take advantage of standards-based routing protocols that are already used in the Black and/or Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u005.s002`

> For example, networks that currently use Generic Routing Encapsulation (GRE), Multiprotocol Label Switching or OSPF protocols can continue to use these in conjunction with this solution to provide routing as long as the AO approves their use.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u005.s001`

> The MSC Solution can be implemented to take advantage of standards-based routing protocols that are already used in the Black and/or Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u005.s002`

> For example, networks that currently use Generic Routing Encapsulation (GRE), Multiprotocol Label Switching or OSPF protocols can continue to use these in conjunction with this solution to provide routing as long as the AO approves their use.

<a id="net-022"></a>

## NET-022: Independent IPv4 or IPv6 choice by network

### Requirement-group assessment

The text presents independent IP-version choice for Red, Gray, and Black Networks. It supplies no deployed addressing or filtering configuration.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-041: Control-plane approval, defaults, and service location](../requirements/requirement_groups.md#rg-041) | Choose IPv4 or IPv6 independently for each Red, Gray, and Black Network. | [Presented as satisfying](network_requirement_links.md#net-022-map-01) |

<a id="net-022-map-01"></a>

#### NET-022-MAP-01: [RG-041 - Control-plane approval, defaults, and service location](../requirements/requirement_groups.md#rg-041)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Choose IPv4 or IPv6 independently for each Red, Gray, and Black Network.

**Applicability:** The IP-version alternatives described in the source.

**Reasoning:** The source directly permits independent network choices.

**Requirement strength:** Mandatory service placement, approval restrictions, and Layer-3 default; conditional protocol permissions.

**Qualifications and exceptions:** Other protocol-specific, addressing, and filtering requirements remain applicable to the chosen versions; the permission does not claim translation or interoperability between arbitrary endpoints.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u003.s001`

> Throughout this CP, when IP traffic is discussed, it may refer to either Internet Protocol version 4 (IPv4) or Internet Protocol version 6 (IPv6) traffic, unless otherwise specified, as the MSC Solution is agnostic to most named data handling protocols.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u003.s002`

> In addition, Red, Gray and Black Networks can run either IPv4 or IPv6, and each network can independently make that decision.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u003.s001`

> Throughout this CP, when IP traffic is discussed, it may refer to either Internet Protocol version 4 (IPv4) or Internet Protocol version 6 (IPv6) traffic, unless otherwise specified, as the MSC Solution is agnostic to most named data handling protocols.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u003.s002`

> In addition, Red, Gray and Black Networks can run either IPv4 or IPv6, and each network can independently make that decision.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u003.s001`

> Throughout this CP, when IP traffic is discussed, it may refer to either Internet Protocol version 4 (IPv4) or Internet Protocol version 6 (IPv6) traffic, unless otherwise specified, as the MSC Solution is agnostic to most named data handling protocols.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u003.s002`

> In addition, Red, Gray and Black Networks can run either IPv4 or IPv6, and each network can independently make that decision.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u003.s003`

> In the remainder of the CP, if no protocols or standards are specified then any appropriate protocols may be used to achieve the objective.

<a id="net-023"></a>

## NET-023: Certificate or CAK authentication variants

### Requirement-group assessment

The text presents alternative certificate and CAK arrangements and provisioning procedures. AS attachment wording, actual trust material, and concrete key settings remain incomplete.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-024: MACsec authentication alternatives and AS scope](../requirements/requirement_groups.md#rg-024) | Select MACsec CAK/PSK authentication or certificate-based EAP-TLS with an AS providing mutual authentication. | [Presented as satisfying](network_requirement_links.md#net-023-map-01) |
| [RG-010: Independently managed site administration and trust](../requirements/requirement_groups.md#rg-010) | Supply peer CA signing certificates and revocation information or the shared peer CAK. | [Required; implementation not demonstrated](network_requirement_links.md#net-023-map-02) |
| [RG-011: Central management, CA placement, and intersite protection](../requirements/requirement_groups.md#rg-011) | Use the required per-layer CAs and central AS in the centralized EAP-TLS design. | [Required; implementation not demonstrated](network_requirement_links.md#net-023-map-03) |
| [RG-024: MACsec authentication alternatives and AS scope](../requirements/requirement_groups.md#rg-024) | Apply the one-site AS attachment constraint together with the prose Gray/Red attachment wording. | [Ambiguous](network_requirement_links.md#net-023-map-04) |
| [RG-027: MACsec key generation, key-server selection, and rollover](../requirements/requirement_groups.md#rg-027) | Generate CAKs and CKNs through an NSA-approved KGS and provision the symmetric key out of band. | [Presented as satisfying](network_requirement_links.md#net-023-map-05) |
| [RG-048: Authorized provisioning and initial certificate requests](../requirements/requirement_groups.md#rg-048) | Provision out of band in a physically secured area and deliver Inner/Outer VPN CSRs to their respective CAs for device certificates. | [Presented as satisfying](network_requirement_links.md#net-023-map-06) |
| [RG-027: MACsec key generation, key-server selection, and rollover](../requirements/requirement_groups.md#rg-027) | Set CKN length and generation, Key Server values, and disabled Fallback CAKs. | [Required; implementation not demonstrated](network_requirement_links.md#net-023-map-07) |

<a id="net-023-map-01"></a>

#### NET-023-MAP-01: [RG-024 - MACsec authentication alternatives and AS scope](../requirements/requirement_groups.md#rg-024)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Select MACsec CAK/PSK authentication or certificate-based EAP-TLS with an AS providing mutual authentication.

**Applicability:** The MACsec authentication alternatives.

**Reasoning:** The source explicitly describes the alternatives and AS role. The paired Threshold rows identify CAK and EAP-TLS as alternatives.

**Requirement strength:** MSC-MD-3 and MSC-MD-14 are both marked Threshold alternatives. AA-1 and AA-2 are T=O within certificate-based MACsec.

- `MSC-MD-3`: `T`; alternatives: `MSC-MD-14`.
- `MSC-MD-14`: `T`; alternatives: `MSC-MD-3`.
- `MSC-AA-1`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The mapping does not require both methods on the same tunnel or establish the full EAP-TLS algorithm profile.

Group interpretation issues: REQ-I08, REQ-I15.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s001`

> MACsec Devices authenticate using a PSK called a CAK or using EAP-TLS over 802.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s002`

> 1X to pass public key device certificates for mutual authentication between devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s003`

> The EAP-TLS mechanism is used to mutually authenticate and get the Master Session Key (MSK) from which the Connectivity Association Key (CAK) is derived for the MACsec Key Agreement (MKA) protocol.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s001`

> The MSC AS is responsible for mutual authentication between MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s002`

> Authentication must be established between the MACsec device and the AS, where each MACsec device must perform the functions of a supplicant and authenticator.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s003`

> This communication is used throughout the EAP-TLS negotiation to mutually authenticate two MACsec Devices to pass MACsec traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u008`

> MSC-MD-3 MACsec Devices must authenticate using Pre-Shared Keys (PSKs), known as Connectivity Association Keys (CAKs). T MSC-MD-14

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u005`

> MSC-MD-14 MACsec Devices must authenticate using EAP-TLS (certificate based). T MSC-MD-3

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u010`

> MSC-AA-1 The AS must be used to provide mutual authentication using EAP-TLS with device certificates between MACsec Devices. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s001`

> MACsec Devices authenticate using a PSK called a CAK or using EAP-TLS over 802.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s002`

> 1X to pass public key device certificates for mutual authentication between devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s003`

> The EAP-TLS mechanism is used to mutually authenticate and get the Master Session Key (MSK) from which the Connectivity Association Key (CAK) is derived for the MACsec Key Agreement (MKA) protocol.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s001`

> The MSC AS is responsible for mutual authentication between MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s002`

> Authentication must be established between the MACsec device and the AS, where each MACsec device must perform the functions of a supplicant and authenticator.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s003`

> This communication is used throughout the EAP-TLS negotiation to mutually authenticate two MACsec Devices to pass MACsec traffic.

<a id="net-023-map-02"></a>

#### NET-023-MAP-02: [RG-010 - Independently managed site administration and trust](../requirements/requirement_groups.md#rg-010)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Supply peer CA signing certificates and revocation information or the shared peer CAK.

**Applicability:** Independently managed-site alternatives.

**Reasoning:** The text prescribes trust and key relationships without concrete stores, revocation state, or CAK equality evidence.

**Requirement strength:** Conditional design requirements and permission to use locally managed or enterprise CAs.

**Qualifications and exceptions:** Apply the clause for the selected authentication method. Cross-site trust must preserve layer and security-level separation.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s002`

> In the MSC Solution, Encryption Components at each site using public key certificates need to have the signing certificates and revocation information for the corresponding CAs used by the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s003`

> This high-level design requires cooperation between the various sites in the solution to ensure that all CAs used by each site are trusted at all the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s004`

> Similarly, MACsec Devices using a Connectivity Association Key (CAK) need to have the same CAK used by the other site in the MSC Solution.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s002`

> In the MSC Solution, Encryption Components at each site using public key certificates need to have the signing certificates and revocation information for the corresponding CAs used by the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s003`

> This high-level design requires cooperation between the various sites in the solution to ensure that all CAs used by each site are trusted at all the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s004`

> Similarly, MACsec Devices using a Connectivity Association Key (CAK) need to have the same CAK used by the other site in the MSC Solution.

<a id="net-023-map-03"></a>

#### NET-023-MAP-03: [RG-011 - Central management, CA placement, and intersite protection](../requirements/requirement_groups.md#rg-011)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Use the required per-layer CAs and central AS in the centralized EAP-TLS design.

**Applicability:** The central-site authentication alternative.

**Reasoning:** The source describes required roles but gives no actual CA/AS deployment or trust hierarchy.

**Requirement strength:** Conditional design requirements; enterprise-CA use is recommended; a PSK-authenticated layer may omit its CA.

**Qualifications and exceptions:** A PSK-selected layer need not have a CA. Enterprise CAs are recommended when available.

Group interpretation issues: REQ-I03, REQ-I12.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003`

> At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s004`

> If available, enterprise CAs should be used.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005`

> If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003`

> At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s004`

> If available, enterprise CAs should be used.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005`

> If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.

<a id="net-023-map-04"></a>

#### NET-023-MAP-04: [RG-024 - MACsec authentication alternatives and AS scope](../requirements/requirement_groups.md#rg-024)

**ambiguous** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Apply the one-site AS attachment constraint together with the prose Gray/Red attachment wording.

**Applicability:** Certificate-authenticated MACsec with an AS.

**Reasoning:** MSC-AA-2 clearly limits the AS to one site network, while the independent-site prose says the AS must not connect to "both Gray and/or Red Networks". The example provides no attachments that resolve that phrase.

**Requirement strength:** MSC-MD-3 and MSC-MD-14 are both marked Threshold alternatives. AA-1 and AA-2 are T=O within certificate-based MACsec.

- `MSC-AA-2`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The ambiguity does not erase the clear one-site requirement or authorize combined Gray/Red connectivity.

Group interpretation issues: REQ-I08, REQ-I15.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u011`

> MSC-AA-2 The AS must only connect to one site’s network when a MACsec device is an Outer or Inner Encryption Component. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s005`

> If MACsec Devices are authenticating using certificates, the authentication server (AS) must not connect to both Gray and/or Red Networks.

<a id="net-023-map-05"></a>

#### NET-023-MAP-05: [RG-027 - MACsec key generation, key-server selection, and rollover](../requirements/requirement_groups.md#rg-027)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Generate CAKs and CKNs through an NSA-approved KGS and provision the symmetric key out of band.

**Applicability:** The MACsec PSK provisioning alternative.

**Reasoning:** The text describes the prescribed KGS-based key acquisition and application procedure.

**Requirement strength:** Mandatory for the stated applicability.

**Qualifications and exceptions:** The mapping records the procedure; it does not establish actual KGS approval, key values, CKN length, or rollover configuration.

Group interpretation issues: REQ-I15.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s002`

> This CP also requires all CAKs and their associated Connectivity Key Names (CKNs) to be generated using an NSA-approved Key Generation Solution (KGS).

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u012.s001`

> For provisioning MACsec PSK Encryption Components, the Security Administrator obtains a Symmetric Key from an NSA-approved KGS and applies them to each Encryption Component.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s002`

> This CP also requires all CAKs and their associated Connectivity Key Names (CKNs) to be generated using an NSA-approved Key Generation Solution (KGS).

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u012.s001`

> For provisioning MACsec PSK Encryption Components, the Security Administrator obtains a Symmetric Key from an NSA-approved KGS and applies them to each Encryption Component.

<a id="net-023-map-06"></a>

#### NET-023-MAP-06: [RG-048 - Authorized provisioning and initial certificate requests](../requirements/requirement_groups.md#rg-048)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Provision out of band in a physically secured area and deliver Inner/Outer VPN CSRs to their respective CAs for device certificates.

**Applicability:** The certificate-based provisioning procedure.

**Reasoning:** The source expressly describes the secured provisioning location, layer-specific CSR delivery, and CA response.

**Requirement strength:** Mandatory for the stated applicability.

**Qualifications and exceptions:** The MACsec paragraph calls an inner device an Inner VPN Gateway; that terminology issue remains unresolved. Installing an initial CRL is optional in the prose.

Group interpretation issues: REQ-I11.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s001`

> Provisioning is an out-of-band process performed in a physically secured area (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s002`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s003`

> , the Red Network location) where MSC Solution Components are configured and initialized before their first use.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s001`

> For provisioning IPsec Outer VPN Gateways and Inner VPN Gateways generate a public/private key pair and output the public key in a Certificate Signing Request (CSR).

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s003`

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s004`

> 509 certificate.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s001`

> Provisioning is an out-of-band process performed in a physically secured area (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s002`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s003`

> , the Red Network location) where MSC Solution Components are configured and initialized before their first use.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s001`

> For provisioning IPsec Outer VPN Gateways and Inner VPN Gateways generate a public/private key pair and output the public key in a Certificate Signing Request (CSR).

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s003`

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s004`

> 509 certificate.

<a id="net-023-map-07"></a>

#### NET-023-MAP-07: [RG-027 - MACsec key generation, key-server selection, and rollover](../requirements/requirement_groups.md#rg-027)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Set CKN length and generation, Key Server values, and disabled Fallback CAKs.

**Applicability:** The selected MACsec tunnel configuration.

**Reasoning:** The source describes KGS and Key Server roles but supplies no configured values or rollover state.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-MD-5`: `T=O`; alternatives: `none stated`.
- `MSC-MD-6`: `T=O`; alternatives: `none stated`.
- `MSC-MD-15`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The Central Management Site must be Key Server when present; the selected authentication variant does not demonstrate that setting.

Group interpretation issues: REQ-I15.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u010`

> MSC-MD-5 MACsec Devices must have the length of the CKN set to a minimum of 16 bytes (128 bits) and generate the CKN using an NSA-approved KGS. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u011`

> MSC-MD-6 For each pair of MACsec Devices establishing an encryption tunnel, one of the two must be configured to be the Key Server by setting its Key Server value to 0 (zero). The other MACsec Device must have its Key Server value set to 1. If a Central Management Site is part of the MSC Solution, it must be the Key Server. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u006`

> MSC-MD-15 Must disable Fallback (rollover) CAKs. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s004`

> For each MACsec tunnel, a Key Server is identified.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s005`

> The Key Server authenticates the other MACsec Device and issues a Secure Association Key to provide confidentiality and integrity for the MACsec tunnel.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s002`

> This CP also requires all CAKs and their associated Connectivity Key Names (CKNs) to be generated using an NSA-approved Key Generation Solution (KGS).

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s001`

> For independently managed sites, each site performs the administration of its own Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s002`

> If Certification Authorities (CAs) are part of the MSC Solution, each site has the option to use either locally run CAs that they manage and control or, where available, enterprise CAs that are not necessarily managed by the Solution Owner.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s003`

> Each site needs to ensure that the Encryption Components selected interoperate with those at the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s001`

> When using independent managed sites, management traffic will not cross the Black Network, encrypted or unencrypted.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s002`

> In the MSC Solution, Encryption Components at each site using public key certificates need to have the signing certificates and revocation information for the corresponding CAs used by the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s003`

> This high-level design requires cooperation between the various sites in the solution to ensure that all CAs used by each site are trusted at all the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s004`

> Similarly, MACsec Devices using a Connectivity Association Key (CAK) need to have the same CAK used by the other site in the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s005`

> If MACsec Devices are authenticating using certificates, the authentication server (AS) must not connect to both Gray and/or Red Networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s001`

> As shown in Figure 4, if remote management is used, personnel at a single geographic site administer and perform keying and device management for all the sites included in the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s002`

> In this case, because the administration is done by one group of Security Administrators, CA Administrators, and Key Generation Solution Administrators (see Section 12), they ensure the interoperability of each site as new sites are added.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003`

> At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s004`

> If available, enterprise CAs should be used.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005`

> If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u006.s001`

> The MSC Solution provides mutual device authentication between Outer Encryption Components and between Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u006.s002`

> The method of authentication is different for VPN Gateways and MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u007.s001`

> VPN Gateways authenticate via public key certificates.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u007.s002`

> VPN Gateways may also implement Internet Engineering Task Force (IETF) Request for Comments (RFC) 8784-compliant IKEv2 and use Pre-Shared Key (PSK) in addition to public key certificates to provide quantum resistant confidentiality.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s001`

> MACsec Devices authenticate using a PSK called a CAK or using EAP-TLS over 802.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s002`

> 1X to pass public key device certificates for mutual authentication between devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s003`

> The EAP-TLS mechanism is used to mutually authenticate and get the Master Session Key (MSK) from which the Connectivity Association Key (CAK) is derived for the MACsec Key Agreement (MKA) protocol.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s004`

> For each MACsec tunnel, a Key Server is identified.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s005`

> The Key Server authenticates the other MACsec Device and issues a Secure Association Key to provide confidentiality and integrity for the MACsec tunnel.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s001`

> This CP requires all authentication certificates issued to VPN Gateways and MACsec Devices to be Non- Person Entity certificates.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s002`

> This CP also requires all CAKs and their associated Connectivity Key Names (CKNs) to be generated using an NSA-approved Key Generation Solution (KGS).

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s003`

> Guidance and requirements for using PSKs, including RFC 8784 compliance, can be found in the CSfC Symmetric Key Management Requirements Annex, and guidance and requirements for using public key certificates can be found in the CSfC Key Management Requirements Annex.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s001`

> The MSC AS is responsible for mutual authentication between MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s002`

> Authentication must be established between the MACsec device and the AS, where each MACsec device must perform the functions of a supplicant and authenticator.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s003`

> This communication is used throughout the EAP-TLS negotiation to mutually authenticate two MACsec Devices to pass MACsec traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s004`

> Objectively, the MSC Authentication Server should use CNSA 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s005`

> 0-compliant algorithms as part of the EAP-TLS negotiation to mutually authenticate the MACsec Devices with ML-KEM 1024 for key establishment and ML-DSA 87 for digital signatures as vendors enable support for these algorithms.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s001`

> Provisioning is an out-of-band process performed in a physically secured area (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s002`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s003`

> , the Red Network location) where MSC Solution Components are configured and initialized before their first use.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s004`

> During the provisioning process, the Security Administrator configures the Outer Firewall, Outer Encryption Component, Gray Firewall, Gray Management Services, Inner Encryption Component, Red Management Services and Inner Firewall in accordance with the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s001`

> For provisioning IPsec Outer VPN Gateways and Inner VPN Gateways generate a public/private key pair and output the public key in a Certificate Signing Request (CSR).

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s003`

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s004`

> 509 certificate.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s005`

> The Security Administrator then installs the unique signed certificate and the certificate chain, which consists of the signing CA’s certificate and the Trust Anchor certificate (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s006`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s007`

> , Root CA certificate).

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s008`

> The Security Administrator may also install an initial CRL.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u012.s001`

> For provisioning MACsec PSK Encryption Components, the Security Administrator obtains a Symmetric Key from an NSA-approved KGS and applies them to each Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s001`

> For provisioning Certificate-based MACsec, Outer Encryption Components and/or Inner Encryption Components generate a public/private key pair and output the public key in a CSR.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s002`

> The Security Administrator delivers the Outer Encryption’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s002`

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s003`

> 509 certificate.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s004`

> The Security Administrator then installs the unique signed certificate and the certificate chain, which consists of the signing CA’s certificate and the Trust Anchor certificate (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s005`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s006`

> , Root CA certificate).

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s007`

> The Security Administrator may also install an initial CRL.

<a id="net-024"></a>

## NET-024: Separate address ranges on Gray interfaces

### Requirement-group assessment

The source gives separate Gray-interface address ranges as a filtering aid. Its adjacent same-level denial sentence conflicts with the same-level allowlist and leaves filter semantics unresolved.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-014: Gray addressing supports security-level filtering](../requirements/requirement_groups.md#rg-014) | Use separate Gray-interface address ranges for Inner components supporting each Red Network as an addressing-scheme example. | [Presented as satisfying](network_requirement_links.md#net-024-map-01) |
| [RG-014: Gray addressing supports security-level filtering](../requirements/requirement_groups.md#rg-014) | Determine which same-level peer traffic the proposed addressing supports or prevents. | [Ambiguous](network_requirement_links.md#net-024-map-02) |
| [RG-039: Outer Gray-interface allowlist and default denial](../requirements/requirement_groups.md#rg-039) | Configure the Outer Gray-interface same-security-level endpoint allowlist. | [Required; implementation not demonstrated](network_requirement_links.md#net-024-map-03) |

<a id="net-024-map-01"></a>

#### NET-024-MAP-01: [RG-014 - Gray addressing supports security-level filtering](../requirements/requirement_groups.md#rg-014)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Use separate Gray-interface address ranges for Inner components supporting each Red Network as an addressing-scheme example.

**Applicability:** The proposed Gray addressing arrangement.

**Reasoning:** The source explicitly gives separate ranges as an example supporting the necessary filtering.

**Requirement strength:** Mandatory for the stated applicability.

**Qualifications and exceptions:** The example does not assign actual ranges or require that every permitted addressing scheme use ranges in the same manner.

Group interpretation issues: REQ-I02.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s002`

> Since this filtering is primarily based on the source and destination addresses in the packet on a Gray Network, the Gray Network itself must use an addressing scheme that supports the necessary filtering (such as using separate address ranges for the Gray interfaces of Inner Encryption Components supporting each Red Network).

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s002`

> Since this filtering is primarily based on the source and destination addresses in the packet on a Gray Network, the Gray Network itself must use an addressing scheme that supports the necessary filtering (such as using separate address ranges for the Gray interfaces of Inner Encryption Components supporting each Red Network).

<a id="net-024-map-02"></a>

#### NET-024-MAP-02: [RG-014 - Gray addressing supports security-level filtering](../requirements/requirement_groups.md#rg-014)

**ambiguous** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Determine which same-level peer traffic the proposed addressing supports or prevents.

**Applicability:** The Outer Gray-interface filtering explanation.

**Reasoning:** The preceding sentence says to prevent same-security-level traffic, while MSC-PF-17 permits only matching same-level endpoint addresses. The document does not reconcile that tension.

**Requirement strength:** Mandatory for the stated applicability.

**Qualifications and exceptions:** The wording is retained verbatim; the source is not silently changed to different security levels.

Group interpretation issues: REQ-I02.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s001`

> Outer Encryption Components are also responsible for filtering traffic on its Gray Network interfaces to prevent Inner Encryption Components for networks of the same security level from being able to send packets to one another.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s001`

> Outer Encryption Components are also responsible for filtering traffic on its Gray Network interfaces to prevent Inner Encryption Components for networks of the same security level from being able to send packets to one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s002`

> Since this filtering is primarily based on the source and destination addresses in the packet on a Gray Network, the Gray Network itself must use an addressing scheme that supports the necessary filtering (such as using separate address ranges for the Gray interfaces of Inner Encryption Components supporting each Red Network).

<a id="net-024-map-03"></a>

#### NET-024-MAP-03: [RG-039 - Outer Gray-interface allowlist and default denial](../requirements/requirement_groups.md#rg-039)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Configure the Outer Gray-interface same-security-level endpoint allowlist.

**Applicability:** Any implementation of the example address-range scheme.

**Reasoning:** Separate ranges aid policy expression but do not supply addresses, peer identities, or ACL rules establishing MSC-PF-17.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-PF-17`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The conflicting prose in RG-014 remains a separate ambiguity.

Group interpretation issues: REQ-I02, REQ-I09.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u004`

> MSC-PF-17 The Gray Network interfaces of Outer Encryption Components must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s002`

> Since this filtering is primarily based on the source and destination addresses in the packet on a Gray Network, the Gray Network itself must use an addressing scheme that supports the necessary filtering (such as using separate address ranges for the Gray interfaces of Inner Encryption Components supporting each Red Network).

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s001`

> Outer Encryption Components are also responsible for filtering traffic on its Gray Network interfaces to prevent Inner Encryption Components for networks of the same security level from being able to send packets to one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s002`

> Since this filtering is primarily based on the source and destination addresses in the packet on a Gray Network, the Gray Network itself must use an addressing scheme that supports the necessary filtering (such as using separate address ranges for the Gray interfaces of Inner Encryption Components supporting each Red Network).

<a id="net-025"></a>

## NET-025: Revocation service on the Gray data plane

### Requirement-group assessment

The rows describe revocation-service placement and conditional HTTP allowances. They supply policy specifications without a complete physical firewall layout or tested ACL implementation.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-039: Outer Gray-interface allowlist and default denial](../requirements/requirement_groups.md#rg-039) | Allow only necessary Inner-layer revocation HTTP through Outer VPN Gray interfaces when CDP/OCSP is on the Gray data plane. | [Presented as satisfying](network_requirement_links.md#net-025-map-01) |
| [RG-040: Gray Firewall allowlist and cross-level denial](../requirements/requirement_groups.md#rg-040) | Allow necessary Inner-layer revocation HTTP through a required Gray Firewall and block other HTTP. | [Presented as satisfying](network_requirement_links.md#net-025-map-02) |
| [RG-013: Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013) | Place a Gray Firewall on every qualifying path between a CDP/OCSP responder and an Inner component of a different security level. | [Required; implementation not demonstrated](network_requirement_links.md#net-025-map-03) |

<a id="net-025-map-01"></a>

#### NET-025-MAP-01: [RG-039 - Outer Gray-interface allowlist and default denial](../requirements/requirement_groups.md#rg-039)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Allow only necessary Inner-layer revocation HTTP through Outer VPN Gray interfaces when CDP/OCSP is on the Gray data plane.

**Applicability:** The stated Gray-data-plane revocation-service arrangement.

**Reasoning:** MSC-PF-15 directly defines the allowed requests/replies and requires all other HTTP to be blocked.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-PF-15`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The clause is conditional on Gray-data-plane placement and Outer VPN Gateways. The assessment concerns the prescribed policy, not an installed rule table.

Group interpretation issues: REQ-I02, REQ-I09.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u013`

> MSC-PF-15 If the CDP/OCSP is on the gray data plane, the Gray Network interfaces of Outer VPN Gateways must T=O allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and the CDPs/OCSP Responders) and block all other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u013`

> MSC-PF-15 If the CDP/OCSP is on the gray data plane, the Gray Network interfaces of Outer VPN Gateways must T=O allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and the CDPs/OCSP Responders) and block all other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

<a id="net-025-map-02"></a>

#### NET-025-MAP-02: [RG-040 - Gray Firewall allowlist and cross-level denial](../requirements/requirement_groups.md#rg-040)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Allow necessary Inner-layer revocation HTTP through a required Gray Firewall and block other HTTP.

**Applicability:** The revocation arrangement when a Gray Firewall is required.

**Reasoning:** MSC-PF-25 directly provides the conditional HTTP exception and denial rule.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-PF-25`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The allowance does not make arbitrary HTTP acceptable; its precedence relative to other filtering clauses remains part of the broader group interpretation.

Group interpretation issues: REQ-I02, REQ-I09.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u012`

> MSC-PF-25 If a Gray Firewall is required, the Gray Firewall must allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and CDPs/OCSP Responders) and block all T=O other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u012`

> MSC-PF-25 If a Gray Firewall is required, the Gray Firewall must allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and CDPs/OCSP Responders) and block all T=O other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

<a id="net-025-map-03"></a>

#### NET-025-MAP-03: [RG-013 - Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Place a Gray Firewall on every qualifying path between a CDP/OCSP responder and an Inner component of a different security level.

**Applicability:** The service and Inner component have different security levels under MSC-SR-8.

**Reasoning:** The extracted rows specify the path obligation but do not identify service levels or physical paths.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-8`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The revocation HTTP allowance does not waive the required physical filtering path. Missing placement evidence is not a violation.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u010`

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u010`

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u013`

> MSC-PF-15 If the CDP/OCSP is on the gray data plane, the Gray Network interfaces of Outer VPN Gateways must T=O allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and the CDPs/OCSP Responders) and block all other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u010`

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u013`

> MSC-PF-15 If the CDP/OCSP is on the gray data plane, the Gray Network interfaces of Outer VPN Gateways must T=O allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and the CDPs/OCSP Responders) and block all other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u007`

> MSC-PF-20 The Gray Network interfaces of Outer Encryption Components must deny all traffic that is not explicitly allowed by requirements MSC-PF-8, MSC- PF-13, MSC-PF-15, or MSC-PF-19. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u012`

> MSC-PF-25 If a Gray Firewall is required, the Gray Firewall must allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and CDPs/OCSP Responders) and block all T=O other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u008`

> MSC-PF-31 If a Gray Firewall is required, the Gray Firewall must deny all traffic that is not explicitly allowed by requirements MSC-PF-23, MSC-PF-25, MSC-PF-27 or MSC-PF-30. T=O

<a id="net-026"></a>

## NET-026: Trusted control-plane services on inside networks

### Requirement-group assessment

The rows prescribe inside-network service placement and layer-specific trusted time sources. Concrete source trust, addresses, and achieved synchronization remain unspecified.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-041: Control-plane approval, defaults, and service location](../requirements/requirement_groups.md#rg-041) | Locate control-plane services on Gray for Outer components and Red for Inner components. | [Presented as satisfying](network_requirement_links.md#net-026-map-01) |
| [RG-042: Layer-specific trusted time synchronization](../requirements/requirement_groups.md#rg-042) | Use a Red trusted time source for Inner/Red management and a Gray Management trusted time source for Outer/Gray components. | [Presented as satisfying](network_requirement_links.md#net-026-map-02) |
| [RG-042: Layer-specific trusted time synchronization](../requirements/requirement_groups.md#rg-042) | Establish that each listed component actually synchronizes its time to the required trusted source. | [Required; implementation not demonstrated](network_requirement_links.md#net-026-map-03) |

<a id="net-026-map-01"></a>

#### NET-026-MAP-01: [RG-041 - Control-plane approval, defaults, and service location](../requirements/requirement_groups.md#rg-041)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Locate control-plane services on Gray for Outer components and Red for Inner components.

**Applicability:** The stated inside-network service configuration.

**Reasoning:** MSC-SR-1 directly supplies the placement arrangement, with NTP as an example service.

**Requirement strength:** Mandatory service placement, approval restrictions, and Layer-3 default; conditional protocol permissions.

- `MSC-SR-1`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The document does not require NTP as the only time protocol or identify concrete servers.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u003`

> MSC-SR-1 Network services provided by control plane protocols (such as NTP) must be located on the inside network (i.e., Gray Network for Outer Encryption Component and Red Network for Inner Encryption Component). T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u003`

> MSC-SR-1 Network services provided by control plane protocols (such as NTP) must be located on the inside network (i.e., Gray Network for Outer Encryption Component and Red Network for Inner Encryption Component). T=O

<a id="net-026-map-02"></a>

#### NET-026-MAP-02: [RG-042 - Layer-specific trusted time synchronization](../requirements/requirement_groups.md#rg-042)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Use a Red trusted time source for Inner/Red management and a Gray Management trusted time source for Outer/Gray components.

**Applicability:** The layer-specific time-source placement alternative described by the rows.

**Reasoning:** Both rows directly state the intended source placement and the components that synchronize to each source.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-3`: `T=O`; alternatives: `none stated`.
- `MSC-SR-4`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** The status concerns the prescribed arrangement. Source trust and actual synchronization accuracy are not demonstrated.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u005`

> MSC-SR-3 The time of day on the Inner Encryption Component and Red Management Services must be synchronized to a trusted time source located in the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u006`

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u005`

> MSC-SR-3 The time of day on the Inner Encryption Component and Red Management Services must be synchronized to a trusted time source located in the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u006`

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

<a id="net-026-map-03"></a>

#### NET-026-MAP-03: [RG-042 - Layer-specific trusted time synchronization](../requirements/requirement_groups.md#rg-042)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Establish that each listed component actually synchronizes its time to the required trusted source.

**Applicability:** A deployed instance of the prescribed arrangement.

**Reasoning:** No source identity, trust evidence, synchronization state, or timing measurements are given.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-SR-3`: `T=O`; alternatives: `none stated`.
- `MSC-SR-4`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** A stated configuration requirement is not an observation of operational synchronization.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u005`

> MSC-SR-3 The time of day on the Inner Encryption Component and Red Management Services must be synchronized to a trusted time source located in the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u006`

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u005`

> MSC-SR-3 The time of day on the Inner Encryption Component and Red Management Services must be synchronized to a trusted time source located in the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u006`

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u003`

> MSC-SR-1 Network services provided by control plane protocols (such as NTP) must be located on the inside network (i.e., Gray Network for Outer Encryption Component and Red Network for Inner Encryption Component). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u005`

> MSC-SR-3 The time of day on the Inner Encryption Component and Red Management Services must be synchronized to a trusted time source located in the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u006`

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

<a id="net-027"></a>

## NET-027: Remote administration through approved protection

### Requirement-group assessment

MSC-DM-8 presents approved remote administration and local management as alternatives. The chosen remote product, authorization, and transport details remain unspecified.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-046: Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046) | Perform remote administration from an AW through an NSA-approved solution, exemplified by a CP or High Assurance encryptor. | [Presented as satisfying](network_requirement_links.md#net-027-map-01) |
| [RG-046: Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046) | Provide two approved encryption layers when component management crosses the Black Network. | [Required; implementation not demonstrated](network_requirement_links.md#net-027-map-02) |

<a id="net-027-map-01"></a>

#### NET-027-MAP-01: [RG-046 - Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046)

**presented_as_satisfying** | Basis: `explicit_source_statement` | Scope: selected clause only.

**Clause assessed:** Perform remote administration from an AW through an NSA-approved solution, exemplified by a CP or High Assurance encryptor.

**Applicability:** The remote-management alternative in MSC-DM-8.

**Reasoning:** The row explicitly presents the approved protection classes and the AW requirement.

**Requirement strength:** Mandatory for the stated applicability.

- `MSC-DM-8`: `T=O`; alternatives: `none stated`.

**Qualifications and exceptions:** Local management is an alternative in the same row; the example does not impose a High Assurance encryptor on every solution.

Group interpretation issues: REQ-I03.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u007`

> MSC-DM-8 All administration of Solution Components must securely be performed from an AW remotely using an NSA-approved solution (e.g., CP or High Assurance encryptor), or by managing the Solution Components locally. T=O

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u007`

> MSC-DM-8 All administration of Solution Components must securely be performed from an AW remotely using an NSA-approved solution (e.g., CP or High Assurance encryptor), or by managing the Solution Components locally. T=O

<a id="net-027-map-02"></a>

#### NET-027-MAP-02: [RG-046 - Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046)

**required_but_not_demonstrated** | Basis: `interpreted_source_presentation` | Scope: selected clause only.

**Clause assessed:** Provide two approved encryption layers when component management crosses the Black Network.

**Applicability:** The remote-administration path if it crosses Black transport.

**Reasoning:** MSC-DM-8 does not specify the route or complete protection stack, so the Black-network two-layer condition cannot be demonstrated from the named protection class alone.

**Requirement strength:** Mandatory for the stated applicability.

**Qualifications and exceptions:** The relationship between NSA-approved alternatives and the Black-network CSfC sentence remains subject to the group qualifications. Local and same-LAN/VLAN exceptions are retained in NET-017.

Group interpretation issues: REQ-I03.

Selected requirement clauses, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s006`

> When components are managed over the Black Network, a CSfC Solution must be implemented to provide two layers of approved encryption.

Example evidence, quoted verbatim:

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u007`

> MSC-DM-8 All administration of Solution Components must securely be performed from an AW remotely using an NSA-approved solution (e.g., CP or High Assurance encryptor), or by managing the Solution Components locally. T=O

### Verbatim indexed setup passages

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u007`

> MSC-DM-8 All administration of Solution Components must securely be performed from an AW remotely using an NSA-approved solution (e.g., CP or High Assurance encryptor), or by managing the Solution Components locally. T=O
