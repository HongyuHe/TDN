# Partial configurations and alternatives

Partial arrangements and design alternatives described in prose or tables, without a concrete network topology. Entries: 17.

[Example networks](networks.md) | [Protocol exchanges](protocol_exchanges.md)

Detailed assessments and verbatim source passages are in [network_requirement_links.md](network_requirement_links.md). Stable NET identifiers preserve references across categories.

The original assessments were authored by the extraction subagent and independently reviewed. Later user-directed corrections are recorded in [mapping decisions](mapping_decisions.json). The scripts replay those decisions, verify source references, and render the reports.

Statuses apply to the selected clauses and alternatives. Unmapped groups remain unassessed. General procurement, personnel, lifecycle, audit, and testing duties are not repeated for every schematic.

Explicit textual descriptions and applicable requirements supply details omitted from figures. Schematic connections do not establish a physical bypass of a textually required component. Genuine conflicts between textual statements remain open.

## NET-011: Four layering configurations

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

Table 1 presents four permitted layer pairings. Outer MACsec point-to-point scope and Inner MACsec encapsulation are conditional requirements for the selected row.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-007: Two independent encryption layers and allowed tunnel pairings](../requirements/requirement_groups.md#rg-007) | Select one of the four Inner/Outer IPsec and MACsec pairings. | [Presented as satisfying](network_requirement_links.md#net-011-map-01) |
| [RG-015: MACsec encapsulation and standalone encapsulator obligations](../requirements/requirement_groups.md#rg-015) | Encapsulate Inner MACsec before Outer encryption; apply MSC-MD-13 if a standalone device is required. | [Required; implementation not demonstrated](network_requirement_links.md#net-011-map-02) |

[Detailed assessments and source passages](network_requirement_links.md#net-011).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-011-vpn-gateway | VPN Gateway | Placement only as stated in setup passages. | ROLE-vpn-gateway | source_stated |
| NET-011-macsec-device | MACsec Device | Placement only as stated in setup passages. | ROLE-macsec-device | source_stated |
| NET-011-inner-encryption | Inner Encryption Component | Placement only as stated in setup passages. | ROLE-inner-encryption | source_stated |
| NET-011-outer-encryption | Outer Encryption Component | Placement only as stated in setup passages. | ROLE-outer-encryption | source_stated |

### Configuration alternatives

| Name | Meaning |
| --- | --- |
| IPsec/IPsec | {"inner_tunnel": "IPsec", "outer_tunnel": "IPsec", "outer_MACsec_point_to_point": false} |
| IPsec/MACsec | {"inner_tunnel": "IPsec", "outer_tunnel": "MACsec", "outer_MACsec_point_to_point": true} |
| MACsec/IPsec | {"inner_tunnel": "MACsec", "outer_tunnel": "IPsec", "outer_MACsec_point_to_point": false} |
| MACsec/MACsec | {"inner_tunnel": "MACsec", "outer_tunnel": "MACsec", "outer_MACsec_point_to_point": true} |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| Table 1 permits inner/outer IPsec/IPsec, IPsec/MACsec, MACsec/IPsec, and MACsec/MACsec. Outer MACsec cases are point to point. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-011-inner-encryption ↔ NET-011-outer-encryption | The inner tunnel is nested inside the outer tunnel; physical intermediary devices are unspecified. | source_stated |

## NET-012: Separated Gray data and management networks

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The prose presents separate Gray data and management networks. Physical separation, cryptographic separation, and minimum ACL separation are cumulative controls whose implementation is not shown.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-044: Layer-specific administration and management-plane separation](../requirements/requirement_groups.md#rg-044) | Separate Gray data and management traffic physically and cryptographically, with management components administering data components. | [Presented as satisfying](network_requirement_links.md#net-012-map-01) |
| [RG-044: Layer-specific administration and management-plane separation](../requirements/requirement_groups.md#rg-044) | Satisfy physical and cryptographic traffic separation together with minimum Gray Firewall ACL separation. | [Required; implementation not demonstrated](network_requirement_links.md#net-012-map-02) |

[Detailed assessments and source passages](network_requirement_links.md#net-012).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-012-gray-aw | Gray Administrative Workstation | Placement only as stated in setup passages. | ROLE-gray-aw | source_stated |
| NET-012-gray-management | Gray Management Services | Placement only as stated in setup passages. | ROLE-gray-management | source_stated |
| NET-012-outer-encryption | Outer Encryption Component | Placement only as stated in setup passages. | ROLE-outer-encryption | source_stated |
| NET-012-gray-firewall | Gray Firewall | Placement only as stated in setup passages. | ROLE-gray-firewall | source_stated |

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-012-gray-data | Gray Data Network | Gray | Placement described by the cited configuration. | source_stated |
| NET-012-gray-management-network | Gray Management Network | Gray | Placement described by the cited configuration. | source_stated |

### Interfaces

| Summary | Evidence basis |
| --- | --- |
| Data and management traffic require physical and cryptographic separation; VLAN separation alone is insufficient. | source_stated |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| Data and management networks may be separate; management components administer data-network components. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-012-gray-aw ↔ NET-012-gray-management-network | Gray AW is a Gray management component. | source_stated |
| NET-012-gray-management ↔ NET-012-gray-data | Management-network components administer data-network components. | source_stated |

## NET-013: Unclassified network behind its own inner component

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1, required_but_not_demonstrated: 2}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The text permits an unclassified network behind its own Inner component. Treating that network as Red triggers the same conditional isolation and parallel-placement obligations as other shared-Outer networks.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-008: Connectivity restricted to the same security level](../requirements/requirement_groups.md#rg-008) | Place the included unclassified network behind its own Inner component and apply Red Network requirements. | [Presented as satisfying](network_requirement_links.md#net-013-map-01) |
| [RG-013: Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013) | Include Gray Firewalls on shared paths to Inner components of different security levels. | [Required; implementation not demonstrated](network_requirement_links.md#net-013-map-02) |
| [RG-053: Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053) | Use parallel Inner components and unique physical Outer internal interfaces when sharing an Outer component. | [Required; implementation not demonstrated](network_requirement_links.md#net-013-map-03) |

[Detailed assessments and source passages](network_requirement_links.md#net-013).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-013-inner-encryption | Inner Encryption Component | Placement only as stated in setup passages. | ROLE-inner-encryption | source_stated |
| NET-013-outer-encryption | Outer Encryption Component | Placement only as stated in setup passages. | ROLE-outer-encryption | source_stated |

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-013-unclassified | Unclassified network treated as a Red Network for CP requirements | Unclassified | Placement described by the cited configuration. | source_stated |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| An unclassified network can share an outer component if it has its own inner component and meets requirements as a Red Network. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-013-unclassified ↔ NET-013-inner-encryption | The unclassified network must be behind its own Inner Encryption Component. | source_stated |
| NET-013-inner-encryption ↔ NET-013-outer-encryption | Its inner component is behind the shared outer component. | source_stated |

## NET-014: Gray logs transferred to Red SIEM through CDS

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The text permits Gray logs to reach a Red SIEM through an approved CDS. Required external CDS approval conditions and concrete monitoring configuration remain separate evidence needs.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-050: SIEM placement, collection, alerting, and log transport](../requirements/requirement_groups.md#rg-050) | Use a Red SIEM with an approved CDS as the alternative to a Gray SIEM for Gray log functions. | [Presented as satisfying](network_requirement_links.md#net-014-map-01) |
| [RG-051: Cross Domain Solution approval conditions](../requirements/requirement_groups.md#rg-051) | Meet DoDI 8540.01, the DISN Connection Process Guide, and the NCDSMO CDS Baseline condition. | [Required; implementation not demonstrated](network_requirement_links.md#net-014-map-02) |

[Detailed assessments and source passages](network_requirement_links.md#net-014).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-014-gray-management | Gray Management Services | Placement only as stated in setup passages. | ROLE-gray-management | source_stated |
| NET-014-red-siem | Red SIEM | Placement only as stated in setup passages. | ROLE-red-siem | source_stated |
| NET-014-cds | Cross Domain Solution | Placement only as stated in setup passages. | ROLE-cds | source_stated |

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-014-gray | Gray Network | Gray | Placement described by the cited configuration. | source_stated |
| NET-014-red | Red Network | Red | Placement described by the cited configuration. | source_stated |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| An approved CDS can support Gray log transfer to a Red SIEM. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-014-gray-management ↔ NET-014-cds | Gray log data is transferred through an approved CDS. | source_stated |
| NET-014-cds ↔ NET-014-red-siem | The Red SIEM receives the transferred Gray log data. | source_stated |
| NET-014-red-siem ↔ NET-014-red | The receiving SIEM is located in the Red Network. | source_stated |

## NET-015: Screening router on the Black Network

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The screening-router example is an optional Black Network control outside the MSC Solution. It does not replace the conditional Outer Firewall requirement.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-075: Optional additional controls and screening-router scope](../requirements/requirement_groups.md#rg-075) | Use an existing or added screening router to filter Black packets before Outer components. | [Presented as satisfying](network_requirement_links.md#net-015-map-01) |
| [RG-034: Outer Firewall placement for untrusted Black transport](../requirements/requirement_groups.md#rg-034) | Add the required Outer Firewall if the Black transport is the Public Internet. | [Required; implementation not demonstrated](network_requirement_links.md#net-015-map-02) |

[Detailed assessments and source passages](network_requirement_links.md#net-015).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-015-screening-router | Screening router | Placement only as stated in setup passages. | ROLE-screening-router | source_stated |
| NET-015-customer-edge-router | Customer Edge Router | Placement only as stated in setup passages. | ROLE-customer-edge-router | source_stated |
| NET-015-outer-encryption | Outer Encryption Component | Placement only as stated in setup passages. | ROLE-outer-encryption | source_stated |

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-015-black | Black Network | Black | Placement described by the cited configuration. | source_stated |

### Sites and boundaries

| Summary | Evidence basis |
| --- | --- |
| The screening router belongs to the Black Network and is outside the MSC Solution boundary. | source_stated |

### Configuration alternatives

| Name | Meaning |
| --- | --- |
| Existing screening router | The screening router could be part of an existing Black Network; a Customer Edge Router is an example of that same role. |
| Added screening router | The screening router could be added between Outer Encryption Components and existing Black Network components. |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| An optional screening router filters Black Network packets before they reach outer components; it is outside the MSC Solution. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-015-black ↔ NET-015-screening-router | Screening filters packets from the Black Network before they reach an Outer Encryption Component. | source_stated |
| NET-015-screening-router ↔ NET-015-outer-encryption | Screened packets continue toward the Outer Encryption Component. | source_stated |

## NET-016: Dedicated physical and virtual administrative workstations

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1, required_but_not_demonstrated: 2}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The text presents physical and virtual AW alternatives with dedication and cohosting constraints. Facility protection and operating policy compliance require evidence beyond a permitted arrangement.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-045: Dedicated, protected, hardened Administrative Workstations](../requirements/requirement_groups.md#rg-045) | Use dedicated physical AWs or dedicated AW VM hosts and exclude the listed non-AW and non-CSfC functions. | [Presented as satisfying](network_requirement_links.md#net-016-map-01) |
| [RG-045: Dedicated, protected, hardened Administrative Workstations](../requirements/requirement_groups.md#rg-045) | Keep provisioning, enrollment, registration, and SIEM functions off AW hosts even when those functions use separate VMs. | [Required; implementation not demonstrated](network_requirement_links.md#net-016-map-02) |
| [RG-045: Dedicated, protected, hardened Administrative Workstations](../requirements/requirement_groups.md#rg-045) | Protect the AW facility, apply required hardening and operating policies, and power off AWs when idle. | [Required; implementation not demonstrated](network_requirement_links.md#net-016-map-03) |

[Detailed assessments and source passages](network_requirement_links.md#net-016).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-016-aw | Administrative Workstation | Placement only as stated in setup passages. | ROLE-aw | source_stated |
| NET-016-aw-host | Host/server for AW virtual machines | Placement only as stated in setup passages. | ROLE-aw-host | source_stated |
| NET-016-virtual-machine | Virtual Machine | Placement only as stated in setup passages. | ROLE-virtual-machine | source_stated |
| NET-016-physical-workstation | Physical workstation | Placement only as stated in setup passages. | ROLE-physical-workstation | source_stated |

### Configuration alternatives

| Name | Meaning |
| --- | --- |
| Physical AW | An AW can be a physical workstation, subject to restrictions on additional uses. |
| Virtual AW | An AW can be a VM on a physical host/server, subject to the stated hosting and separation restrictions. |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| AWs may be physical or virtual, with stated cohosting restrictions. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-016-aw-host ↔ NET-016-virtual-machine | The physical host/server hosts the AW VM in the virtual-AW alternative. | source_stated |

## NET-017: Local Gray AW direct or same-site management

Kind: textual_configuration. Requirement assessment: {ambiguous: 1, presented_as_satisfying: 2}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The source distinguishes the direct physical management exception from the same-site CNSA algorithm exception. Neither exception establishes an unrestricted plaintext LAN management option.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-046: Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046) | Allow local management through a direct physical connection, exemplified by a serial cable from Gray AW to Outer component. | [Presented as satisfying](network_requirement_links.md#net-017-map-01) |
| [RG-046: Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046) | Permit the same-site Gray AW example to omit CNSA Suite algorithms when traffic avoids an untrusted network. | [Presented as satisfying](network_requirement_links.md#net-017-map-02) |
| [RG-046: Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046) | Interpret the LAN/VLAN exception relative to the preceding Black-network two-layer requirement. | [Ambiguous](network_requirement_links.md#net-017-map-03) |

[Detailed assessments and source passages](network_requirement_links.md#net-017).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-017-gray-aw | Gray Administrative Workstation | Placement only as stated in setup passages. | ROLE-gray-aw | source_stated |
| NET-017-outer-encryption | Outer Encryption Component | Placement only as stated in setup passages. | ROLE-outer-encryption | source_stated |
| NET-017-locally-managed-device | Locally Managed Device | Placement only as stated in setup passages. | ROLE-locally-managed-device | source_stated |

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-017-gray-management-network | Gray Management Services local LAN or VLAN | Gray | Placement described by the cited configuration. | source_stated |

### Interfaces

| Summary | Evidence basis |
| --- | --- |
| Serial cable is the stated direct physical interface example; the document supplies no serial port identifier. | source_stated |

### Sites and boundaries

| Summary | Evidence basis |
| --- | --- |
| The same-site example locates the Gray AW and Outer Encryption Component at one site. It does not grant a general plaintext-management exception. | source_stated |

### Configuration alternatives

| Name | Meaning |
| --- | --- |
| Same-site LAN or VLAN | The Gray AW resides in Gray Management Services at the same site as the Outer Encryption Component; the stated exception concerns CNSA Suite algorithms. |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| A direct serial cable is the local encryption exception. A same-site Gray AW example does not need CNSA Suite algorithms because its traffic does not traverse an untrusted network. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-017-gray-aw ↔ NET-017-outer-encryption | A direct physical serial cable is the explicit local-management example. | source_stated |
| NET-017-gray-aw ↔ NET-017-gray-management-network | Same-site Gray AW resides in Gray Management Services. | source_stated |

### Open issues

| ID | Summary |
| --- | --- |
| NET-017-distinct-exceptions | The direct-connection exception to management encryption and the same-site exception to CNSA Suite algorithms are separate statements, not a general same-site plaintext permission. |

## NET-018: Alternative approved egress alongside the MSC Solution

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The footnote permits two approved egress alternatives at one site. Authorization and conformity of particular products or a complete CSfC deployment are not supplied.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-056: Approved physical paths out of Red Networks](../requirements/requirement_groups.md#rg-056) | Provide parallel protected egress through an NSA-certified product and through a CP-conforming CSfC solution. | [Presented as satisfying](network_requirement_links.md#net-018-map-01) |
| [RG-056: Approved physical paths out of Red Networks](../requirements/requirement_groups.md#rg-056) | Establish AO approval or CP conformity for every actual physical path leaving Red. | [Required; implementation not demonstrated](network_requirement_links.md#net-018-map-02) |

[Detailed assessments and source passages](network_requirement_links.md#net-018).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-018-government-product | NSA-certified Government-off-the-Shelf product | Placement only as stated in setup passages. | ROLE-government-product | source_stated |

### Solution aggregates

| ID | Name | Evidence basis |
| --- | --- | --- |
| NET-018-csfc-solution | CSfC Solution conforming to a CP | source_stated |

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-018-red | Red Network | Red | Placement described by the cited configuration. | source_stated |

### Sites and boundaries

| Summary | Evidence basis |
| --- | --- |
| The footnote permits both egress paths at the same site. | source_stated |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| A site may have both an NSA-certified-product egress and an egress through a CP-conforming CSfC solution. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-018-red ↔ NET-018-government-product | One approved egress path may use an NSA-certified product. | source_stated |
| NET-018-red ↔ NET-018-csfc-solution | Another egress path may use a whole CSfC Solution conforming to a CP; the passage does not reduce that solution to one device. | source_stated |

## NET-019: Combining MSC with another CSfC solution

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The combined-CP example describes inherited firewall conditions and Inner Firewall placement. The companion CP and complete combined topology remain unspecified.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-055: Firewall requirements when combining capability packages](../requirements/requirement_groups.md#rg-055) | Place an Inner Firewall between the Red Network and Inner Encryption Component when an Inner Firewall is deployed. | [Presented as satisfying](network_requirement_links.md#net-019-map-01) |
| [RG-055: Firewall requirements when combining capability packages](../requirements/requirement_groups.md#rg-055) | Implement a required companion-CP Gray Firewall and follow companion Inner Firewall requirements for combined data-in-transit solutions with end-user devices. | [Required; implementation not demonstrated](network_requirement_links.md#net-019-map-02) |

[Detailed assessments and source passages](network_requirement_links.md#net-019).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-019-gray-firewall | Gray Firewall | Placement only as stated in setup passages. | ROLE-gray-firewall | source_stated |
| NET-019-inner-firewall | Inner Firewall | Placement only as stated in setup passages. | ROLE-inner-firewall | source_stated |
| NET-019-end-user-device | End user device | Placement only as stated in setup passages. | ROLE-end-user-device | source_stated |
| NET-019-inner-encryption | Inner Encryption Component | Placement only as stated in setup passages. | ROLE-inner-encryption | source_stated |

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-019-red | Red Network | Red | Placement described by the cited configuration. | source_stated |

### Sites and boundaries

| Summary | Evidence basis |
| --- | --- |
| The MSC text supplies Inner Firewall placement. Additional requirements and topology details of the combined deployment depend on the companion CP. | source_stated |

### Configuration alternatives

| Name | Meaning |
| --- | --- |
| Combined data-in-transit solution | If another CSfC data-in-transit solution includes end-user devices, its Inner Firewall requirements must be followed. |
| Combined solution Gray Firewall | A Gray Firewall may be required by the other CP. The paragraph does not specify a complete combined topology. |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| Combined deployments may inherit Gray Firewall or Inner Firewall requirements from the other CP. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-019-red ↔ NET-019-inner-firewall | When deployed, the Inner Firewall is between the Red Network and Inner Encryption Component. | source_stated |
| NET-019-inner-firewall ↔ NET-019-inner-encryption | The Inner Firewall faces the Inner Encryption Component on the other side of the stated placement. | source_stated |

## NET-020: Parallel components for load or availability

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The text permits parallel redundancy and load balancing. It does not demonstrate all redundant-component controls or an implementation of failover.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-074: Redundant component and load-balancing permission](../requirements/requirement_groups.md#rg-074) | Add parallel redundant components or multiple Outer components, Gray Firewalls, and Inner components for performance. | [Presented as satisfying](network_requirement_links.md#net-020-map-01) |
| [RG-053: Parallel Inner components and distinct Outer internal interfaces](../requirements/requirement_groups.md#rg-053) | Place shared-Outer Inner components in parallel and preserve unique physical internal interfaces for each Red Network. | [Required; implementation not demonstrated](network_requirement_links.md#net-020-map-02) |

[Detailed assessments and source passages](network_requirement_links.md#net-020).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-020-inner-encryption | Inner Encryption Component | Placement only as stated in setup passages. | ROLE-inner-encryption | source_stated |
| NET-020-outer-encryption | Outer Encryption Component | Placement only as stated in setup passages. | ROLE-outer-encryption | source_stated |
| NET-020-gray-firewall | Gray Firewall | Placement only as stated in setup passages. | ROLE-gray-firewall | source_stated |

### Shared components

| Summary | Evidence basis |
| --- | --- |
| The outer component may be shared by multiple inner components; no instance count or failover configuration is supplied. | source_stated |

### Configuration alternatives

| Name | Meaning |
| --- | --- |
| Parallel redundancy | Redundant components may be added in parallel if every redundant component follows applicable CP requirements. |
| Multiple inner components | When multiple inner components share an outer component, they must be in parallel. |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| Parallel components and load-balancing or standby designs are permitted subject to stated requirements; implementation mechanisms are outside scope. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-020-inner-encryption ↔ NET-020-outer-encryption | Multiple instances of the inner role can share the outer component in parallel. | source_stated |

## NET-021: Existing Black and Red routing protocols

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The text permits existing Black/Red routing protocols with AO approval. That permission does not authorize routing protocols on Outer Encryption Components.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-041: Control-plane approval, defaults, and service location](../requirements/requirement_groups.md#rg-041) | Continue using existing GRE, MPLS, or OSPF in Black and/or Red Networks when the AO approves. | [Presented as satisfying](network_requirement_links.md#net-021-map-01) |
| [RG-031: Routing and switching limits on Encryption Components](../requirements/requirement_groups.md#rg-031) | Keep routing protocols disabled on Outer Encryption Components. | [Required; implementation not demonstrated](network_requirement_links.md#net-021-map-02) |

[Detailed assessments and source passages](network_requirement_links.md#net-021).

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-021-black | Black Network | Black | Placement described by the cited configuration. | source_stated |
| NET-021-red | Red Network | Red | Placement described by the cited configuration. | source_stated |

### Sites and boundaries

| Summary | Evidence basis |
| --- | --- |
| The text places routing-protocol use in Black and/or Red Networks. It does not identify a particular router location or connection. | source_stated |

### Configuration alternatives

| Name | Meaning |
| --- | --- |
| Existing routing protocols | Existing GRE, MPLS or OSPF use in the Black and/or Red Network may continue with AO approval. |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| Existing GRE, MPLS, or OSPF use may continue in Black/Red networks with AO approval. | source_stated |

## NET-022: Independent IPv4 or IPv6 choice by network

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The text presents independent IP-version choice for Red, Gray, and Black Networks. It supplies no deployed addressing or filtering configuration.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-041: Control-plane approval, defaults, and service location](../requirements/requirement_groups.md#rg-041) | Choose IPv4 or IPv6 independently for each Red, Gray, and Black Network. | [Presented as satisfying](network_requirement_links.md#net-022-map-01) |

[Detailed assessments and source passages](network_requirement_links.md#net-022).

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-022-red | Red Network | Red | Placement described by the cited configuration. | source_stated |
| NET-022-gray | Gray Network | Gray | Placement described by the cited configuration. | source_stated |
| NET-022-black | Black Network | Black | Placement described by the cited configuration. | source_stated |

### Configuration alternatives

| Name | Meaning |
| --- | --- |
| Red IP version | {"network_id": "NET-022-red", "allowed_choices": ["IPv4", "IPv6"], "independent_of_other_networks": true} |
| Gray IP version | {"network_id": "NET-022-gray", "allowed_choices": ["IPv4", "IPv6"], "independent_of_other_networks": true} |
| Black IP version | {"network_id": "NET-022-black", "allowed_choices": ["IPv4", "IPv6"], "independent_of_other_networks": true} |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| Red, Gray, and Black Networks can independently use IPv4 or IPv6. | source_stated |

## NET-023: Certificate or CAK authentication variants

Kind: textual_configuration. Requirement assessment: {ambiguous: 1, presented_as_satisfying: 3, required_but_not_demonstrated: 3}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

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

[Detailed assessments and source passages](network_requirement_links.md#net-023).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-023-ca | Certification Authority | Placement only as stated in setup passages. | ROLE-ca | source_stated |
| NET-023-inner-ca | Inner CA | Placement only as stated in setup passages. | ROLE-inner-ca | source_stated |
| NET-023-outer-ca | Outer CA | Placement only as stated in setup passages. | ROLE-outer-ca | source_stated |
| NET-023-authentication-server | Authentication Server | Placement only as stated in setup passages. | ROLE-authentication-server | source_stated |
| NET-023-kgs | Key Generation Solution | Placement only as stated in setup passages. | ROLE-kgs | source_stated |
| NET-023-macsec-device | MACsec Device | Placement only as stated in setup passages. | ROLE-macsec-device | source_stated |
| NET-023-vpn-gateway | VPN Gateway | Placement only as stated in setup passages. | ROLE-vpn-gateway | source_stated |

### Sites and boundaries

| Summary | Evidence basis |
| --- | --- |
| Provisioning occurs out of band in a physically secured area. The authentication server must not connect to both Gray and/or Red Networks; the source wording is retained without inventing a topology. | source_stated |

### Configuration alternatives

| Name | Meaning |
| --- | --- |
| Independent sites | Each site may use locally run or enterprise CAs and must ensure required peer signing certificates and revocation information are available. MACsec CAK peers use the same CAK. |
| Central site | At least separate inner and outer CAs are needed when applicable. For MACsec EAP-TLS the CAs and AS are at the central site; the stated PSK alternative for one layer does not require a CA for that layer. |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| Independent and central site designs describe certificate, CAK, CA, AS, and KGS options; exact assignments depend on the chosen layer. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-023-ca ↔ NET-023-vpn-gateway | A CA processes the VPN Gateway CSR and issues its device certificate. | source_stated |
| NET-023-ca ↔ NET-023-macsec-device | A CA issues the device certificate in the certificate-based MACsec alternative. | source_stated |
| NET-023-authentication-server ↔ NET-023-macsec-device | The AS and each MACsec Device mutually authenticate for EAP-TLS negotiation. | source_stated |
| NET-023-kgs ↔ NET-023-macsec-device | A Security Administrator obtains the symmetric key from an NSA-approved KGS and applies it to the component. | source_stated |

## NET-024: Separate address ranges on Gray interfaces

Kind: textual_configuration. Requirement assessment: {ambiguous: 1, presented_as_satisfying: 1, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The source gives separate Gray-interface address ranges as a filtering aid. Its adjacent same-level denial sentence conflicts with the same-level allowlist and leaves filter semantics unresolved.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-014: Gray addressing supports security-level filtering](../requirements/requirement_groups.md#rg-014) | Use separate Gray-interface address ranges for Inner components supporting each Red Network as an addressing-scheme example. | [Presented as satisfying](network_requirement_links.md#net-024-map-01) |
| [RG-014: Gray addressing supports security-level filtering](../requirements/requirement_groups.md#rg-014) | Determine which same-level peer traffic the proposed addressing supports or prevents. | [Ambiguous](network_requirement_links.md#net-024-map-02) |
| [RG-039: Outer Gray-interface allowlist and default denial](../requirements/requirement_groups.md#rg-039) | Configure the Outer Gray-interface same-security-level endpoint allowlist. | [Required; implementation not demonstrated](network_requirement_links.md#net-024-map-03) |

[Detailed assessments and source passages](network_requirement_links.md#net-024).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-024-inner-encryption | Inner Encryption Component | Placement only as stated in setup passages. | ROLE-inner-encryption | source_stated |
| NET-024-outer-encryption | Outer Encryption Component | Placement only as stated in setup passages. | ROLE-outer-encryption | source_stated |

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-024-gray | Gray Network | Gray | Placement described by the cited configuration. | source_stated |

### Interfaces

| Summary | Evidence basis |
| --- | --- |
| Separate address ranges are an example addressing scheme supporting source/destination filtering. Actual ranges are unspecified. | source_stated |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| The source gives separate address ranges for each Red Network inner component as an addressing-scheme example supporting filtering. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-024-inner-encryption ↔ NET-024-gray | Gray interfaces of inner components can use separate address ranges for each supported Red Network. | source_stated |

## NET-025: Revocation service on the Gray data plane

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 2, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The rows describe revocation-service placement and conditional HTTP allowances. They supply policy specifications without a complete physical firewall layout or tested ACL implementation.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-039: Outer Gray-interface allowlist and default denial](../requirements/requirement_groups.md#rg-039) | Allow only necessary Inner-layer revocation HTTP through Outer VPN Gray interfaces when CDP/OCSP is on the Gray data plane. | [Presented as satisfying](network_requirement_links.md#net-025-map-01) |
| [RG-040: Gray Firewall allowlist and cross-level denial](../requirements/requirement_groups.md#rg-040) | Allow necessary Inner-layer revocation HTTP through a required Gray Firewall and block other HTTP. | [Presented as satisfying](network_requirement_links.md#net-025-map-02) |
| [RG-013: Gray Firewalls on all paths needing level separation](../requirements/requirement_groups.md#rg-013) | Place a Gray Firewall on every qualifying path between a CDP/OCSP responder and an Inner component of a different security level. | [Required; implementation not demonstrated](network_requirement_links.md#net-025-map-03) |

[Detailed assessments and source passages](network_requirement_links.md#net-025).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-025-cdp | CRL Distribution Point | Placement only as stated in setup passages. | ROLE-cdp | source_stated |
| NET-025-ocsp-responder | OCSP Responder | Placement only as stated in setup passages. | ROLE-ocsp-responder | source_stated |
| NET-025-inner-vpn | Inner VPN Gateway | Placement only as stated in setup passages. | ROLE-inner-vpn | source_stated |
| NET-025-outer-vpn | Outer VPN Gateway | Placement only as stated in setup passages. | ROLE-outer-vpn | source_stated |
| NET-025-gray-firewall | Gray Firewall | Placement only as stated in setup passages. | ROLE-gray-firewall | source_stated |

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-025-gray-data | Gray Data Plane | Gray | Placement described by the cited configuration. | source_stated |

### Interfaces

| Summary | Evidence basis |
| --- | --- |
| MSC-PF-15 requires the Outer Encryption Component Gray interfaces to allow HTTP traffic between Inner VPN Gateways and CDP/OCSP responders. The Outer component is a filtering/transit component in that rule, not a stated revocation endpoint. | source_stated |
| Filtering rules constrain HTTP revocation traffic; the row descriptions retain the exact component/interface conditions. | source_stated |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| Requirements describe CDP/OCSP placement on the Gray data plane and HTTP revocation-check traffic through filtering components. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-025-cdp ↔ NET-025-gray-data | A CDP may be located on the Gray data plane under the stated filtering arrangement. | source_stated |
| NET-025-ocsp-responder ↔ NET-025-gray-data | An OCSP responder is the stated alternative revocation service. | source_stated |
| NET-025-inner-vpn ↔ NET-025-cdp | The component can exchange HTTP revocation traffic with the CDP/OCSP responder according to its applicable filter rules. | source_stated |

## NET-026: Trusted control-plane services on inside networks

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 2, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

The rows prescribe inside-network service placement and layer-specific trusted time sources. Concrete source trust, addresses, and achieved synchronization remain unspecified.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-041: Control-plane approval, defaults, and service location](../requirements/requirement_groups.md#rg-041) | Locate control-plane services on Gray for Outer components and Red for Inner components. | [Presented as satisfying](network_requirement_links.md#net-026-map-01) |
| [RG-042: Layer-specific trusted time synchronization](../requirements/requirement_groups.md#rg-042) | Use a Red trusted time source for Inner/Red management and a Gray Management trusted time source for Outer/Gray components. | [Presented as satisfying](network_requirement_links.md#net-026-map-02) |
| [RG-042: Layer-specific trusted time synchronization](../requirements/requirement_groups.md#rg-042) | Establish that each listed component actually synchronizes its time to the required trusted source. | [Required; implementation not demonstrated](network_requirement_links.md#net-026-map-03) |

[Detailed assessments and source passages](network_requirement_links.md#net-026).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-026-control-plane-service | Control plane network service | Placement only as stated in setup passages. | ROLE-control-plane-service | source_stated |
| NET-026-trusted-time-source | Trusted time source | Placement only as stated in setup passages. | ROLE-trusted-time-source | source_stated |
| NET-026-inner-encryption | Inner Encryption Component | Placement only as stated in setup passages. | ROLE-inner-encryption | source_stated |
| NET-026-outer-encryption | Outer Encryption Component | Placement only as stated in setup passages. | ROLE-outer-encryption | source_stated |

### Networks and zones

| ID | Name | Zone | Location | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-026-red | Red Network | Red | Placement described by the cited configuration. | source_stated |
| NET-026-gray-management-network | Gray Management Network | Gray | Placement described by the cited configuration. | source_stated |

### Configuration alternatives

| Name | Meaning |
| --- | --- |
| Red time source | {"network_id": "NET-026-red", "requirement": "MSC-SR-3", "meaning": "Components on the Red Network synchronize to a trusted time source on the Red Network."} |
| Gray time source | {"network_id": "NET-026-gray-management-network", "requirement": "MSC-SR-4", "meaning": "Components on the Gray Network synchronize to a trusted time source on the Gray Management Network."} |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| Control-plane services such as NTP belong on the corresponding inside network; the Red trusted time source is on the Red Network and the Gray trusted time source is on the Gray Management Network. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-026-inner-encryption ↔ NET-026-trusted-time-source | Red component time synchronization uses its Red Network trusted time source. | source_stated |
| NET-026-outer-encryption ↔ NET-026-trusted-time-source | Gray component time synchronization uses its Gray Management Network trusted time source; the role reference does not assert the same device as the Red source. | source_stated |

## NET-027: Remote administration through approved protection

Kind: textual_configuration. Requirement assessment: {presented_as_satisfying: 1, required_but_not_demonstrated: 1}.

Figure: none assigned. Extracted from prose or tables as a partial configuration.

MSC-DM-8 presents approved remote administration and local management as alternatives. The chosen remote product, authorization, and transport details remain unspecified.

| Requirement group | Selected clause | Assessment |
| --- | --- | --- |
| [RG-046: Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046) | Perform remote administration from an AW through an NSA-approved solution, exemplified by a CP or High Assurance encryptor. | [Presented as satisfying](network_requirement_links.md#net-027-map-01) |
| [RG-046: Management transport protection and local exceptions](../requirements/requirement_groups.md#rg-046) | Provide two approved encryption layers when component management crosses the Black Network. | [Required; implementation not demonstrated](network_requirement_links.md#net-027-map-02) |

[Detailed assessments and source passages](network_requirement_links.md#net-027).

### Devices and aggregate services

| ID | Name | Location | Roles | Evidence basis |
| --- | --- | --- | --- | --- |
| NET-027-aw | Administrative Workstation | Placement only as stated in setup passages. | ROLE-aw | source_stated |
| NET-027-high-assurance-encryptor | High Assurance encryptor | Placement only as stated in setup passages. | ROLE-high-assurance-encryptor | source_stated |
| NET-027-solution-component | Solution Component | Placement only as stated in setup passages. | ROLE-solution-component | source_stated |

### Configuration alternatives

| Name | Meaning |
| --- | --- |
| Other approved CP solution | An approved CP is another example of NSA-approved protection. The exact remote management network topology is unspecified. |

### Recorded facts

| Summary | Evidence basis |
| --- | --- |
| Remote AW administration uses an NSA-approved solution; a CP or High Assurance encryptor is given as an example. | source_stated |

### Connections

| Endpoints | Description | Evidence basis |
| --- | --- | --- |
| NET-027-aw ↔ NET-027-high-assurance-encryptor | The High Assurance encryptor is an example of NSA-approved protection for remote administration. | source_stated |
| NET-027-high-assurance-encryptor ↔ NET-027-solution-component | Remote management reaches the managed component through the chosen approved protection. | source_stated |
