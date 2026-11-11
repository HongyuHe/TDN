# CSfC role ontology

The hierarchy organizes all extracted roles and preserves source evidence for each subtype relationship. A role can have multiple parents. The navigation families group related topics for browsing and add no OWL subclass claims.

[Interactive explorer](ontology.html) | [OWL in RDF/XML](ontology.owl) | [Turtle](ontology.ttl) | [Structured graph](ontology.json) | [Curation decisions](ontology_decisions.json)

A class describes entities matching an extracted role or realization concept. Classes may overlap and may have multiple parents. No device existence, class disjointness, or class equivalence is asserted.

Non-subtype links are OWL annotation assertions between class IRIs. They preserve source context without imposing object-property restrictions or asserting a relationship for every class member.

OWL uses an open-world interpretation: an absent relationship remains unasserted. The extraction validators separately check that every extracted role and every declared evidence reference is present.

The transitive parent lists are computed for the exported subclass graph. The pipeline validates its supported serialization and hierarchy; it does not run a general OWL DL reasoner or prove CSfC compliance.

## Counts

- extracted roles: 76
- owl classes: 77
- source backed subclass edges: 40
- organizational root edges: 44
- annotation associations: 31
- multiple parent roles: 8
- explicit lean roles: 17
- combined lean roles: 24
- contextual roles: 21
- unrepresented roles: 14

## Representation in TDN v3.3

These annotations explain how source roles are represented by the current Lean model. Device kind, encryption layer and interface zone are separate fields. The local zone represents device-internal interfaces. Device roles remain classified separately. Namespace-local addresses belong to their recorded device, including loopback addresses shared by several devices. Source subtype relationships remain unchanged. Role mappings alone do not establish requirement compliance.

[Curated Lean mappings](ontology_theory.json) records all 76 source roles, code references, chosen interpretations and pinned Lean source hashes.

| Role | Representation | Meaning | Code |
| --- | --- | --- | --- |
| Solution Component | Related model only | Applicable duties are selected from a device’s kind, encryption layer, deployment membership, and standalone-encapsulator status. V3.1 has no single SolutionComponent membership type. | [MscComplianceContext.ComponentApplies](../../../TDN/Requirements/CsfcRoleObligations.lean), [MscComplianceContext.AllApplicableDuties](../../../TDN/Requirements/CsfcRoleObligations.lean) |
| Encryption Component | Combination of Lean fields | The layer field selects Inner or Outer encryption components. Flow validity separately checks whether their mechanism is VPN or MACsec. | [Device](../../../TDN/Requirements/MscComplianceSchema.lean), [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Flow.Valid](../../../TDN/Requirements/CoreMscRequirements.lean), [PacketSizingInventory](../../../TDN/Requirements/CoreMscRequirements.lean), [SizingInterface](../../../TDN/Requirements/TunnelMtuAndFragmentationSpec.lean), [msc_packet_size_configuration](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Inner Encryption Component | Combination of Lean fields | The encryption layer identifies the component’s position in the protection sequence. Its mechanism remains a separate device kind. Its Gray-facing interfaces appear in the packet-size inventory with the Inner external role. | [Device](../../../TDN/Requirements/MscComplianceSchema.lean), [Flow.Valid](../../../TDN/Requirements/CoreMscRequirements.lean), [msc_nested_layer_protection](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [PacketSizingInventory](../../../TDN/Requirements/CoreMscRequirements.lean), [SizingInterface](../../../TDN/Requirements/TunnelMtuAndFragmentationSpec.lean), [msc_packet_size_configuration](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [msc_boundary_interface_filtering](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Outer Encryption Component | Combination of Lean fields | The encryption layer identifies the component’s position in the protection sequence. Its mechanism remains a separate device kind. Its Black-facing interfaces appear in the packet-size inventory with the encryption external role. | [Device](../../../TDN/Requirements/MscComplianceSchema.lean), [Flow.Valid](../../../TDN/Requirements/CoreMscRequirements.lean), [msc_nested_layer_protection](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [PacketSizingInventory](../../../TDN/Requirements/CoreMscRequirements.lean), [SizingInterface](../../../TDN/Requirements/TunnelMtuAndFragmentationSpec.lean), [msc_packet_size_configuration](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [msc_boundary_interface_filtering](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [msc_outer_gray_interface_policy](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| VPN Gateway | Explicit Lean representation | VPN gateways have a dedicated device kind. The layer field identifies Inner and Outer gateways. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Device](../../../TDN/Requirements/MscComplianceSchema.lean), [Flow.Valid](../../../TDN/Requirements/CoreMscRequirements.lean) |
| Inner VPN Gateway | Combination of Lean fields | The device kind identifies the mechanism and the layer identifies its Inner or Outer role. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Device](../../../TDN/Requirements/MscComplianceSchema.lean), [Flow.Valid](../../../TDN/Requirements/CoreMscRequirements.lean), [PacketSizingInventory](../../../TDN/Requirements/CoreMscRequirements.lean), [SizingInterface](../../../TDN/Requirements/TunnelMtuAndFragmentationSpec.lean), [msc_packet_size_configuration](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [msc_boundary_interface_filtering](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Outer VPN Gateway | Combination of Lean fields | The device kind identifies the mechanism and the layer identifies its Inner or Outer role. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Device](../../../TDN/Requirements/MscComplianceSchema.lean), [Flow.Valid](../../../TDN/Requirements/CoreMscRequirements.lean), [PacketSizingInventory](../../../TDN/Requirements/CoreMscRequirements.lean), [SizingInterface](../../../TDN/Requirements/TunnelMtuAndFragmentationSpec.lean), [msc_packet_size_configuration](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [msc_boundary_interface_filtering](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [msc_outer_gray_interface_policy](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| MACsec Device | Explicit Lean representation | MACsec devices have a dedicated kind. Authentication records separately describe their EAP functions and key-server behavior. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [MACsecAuthentication](../../../TDN/Requirements/CoreMscRequirements.lean), [EAPRole](../../../TDN/Requirements/CoreMscRequirements.lean) |
| Inner MACsec Device | Combination of Lean fields | The device kind identifies the mechanism and the layer identifies its Inner or Outer role. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Device](../../../TDN/Requirements/MscComplianceSchema.lean), [Flow.Valid](../../../TDN/Requirements/CoreMscRequirements.lean), [PacketSizingInventory](../../../TDN/Requirements/CoreMscRequirements.lean), [SizingInterface](../../../TDN/Requirements/TunnelMtuAndFragmentationSpec.lean), [msc_packet_size_configuration](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [msc_boundary_interface_filtering](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Outer MACsec Device | Combination of Lean fields | The device kind identifies the mechanism and the layer identifies its Inner or Outer role. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Device](../../../TDN/Requirements/MscComplianceSchema.lean), [Flow.Valid](../../../TDN/Requirements/CoreMscRequirements.lean), [PacketSizingInventory](../../../TDN/Requirements/CoreMscRequirements.lean), [SizingInterface](../../../TDN/Requirements/TunnelMtuAndFragmentationSpec.lean), [msc_packet_size_configuration](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [msc_boundary_interface_filtering](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [msc_outer_gray_interface_policy](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Firewall | Combination of Lean fields | The model distinguishes Gray, Outer, and Inner firewalls with separate device kinds. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Outer Firewall | Explicit Lean representation | The firewall’s architectural role has a dedicated device kind. Actual filtering comes from the deployment’s policy and processing records. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean), [msc_boundary_interface_filtering](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Gray Firewall | Explicit Lean representation | The firewall’s architectural role has a dedicated device kind. Actual filtering comes from the deployment’s policy and processing records. Its applicable external interfaces also appear in the packet-size inventory. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean), [msc_gray_firewall_path_coverage](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [PacketSizingInventory](../../../TDN/Requirements/CoreMscRequirements.lean), [SizingInterface](../../../TDN/Requirements/TunnelMtuAndFragmentationSpec.lean), [msc_packet_size_configuration](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [msc_gray_firewall_allowlist](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Inner Firewall | Explicit Lean representation | The firewall’s architectural role has a dedicated device kind. Actual filtering comes from the deployment’s policy and processing records. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Administrative Workstation | Explicit Lean representation | Administrative Workstations use the workstation device kind. Their administrator accounts and sessions are represented separately. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [AdministrativeAccount](../../../TDN/Requirements/ManagementPlaneRequirements.lean), [msc_administrator_authentication](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Red Administrative Workstation | Combination of Lean fields | A Red workstation combines the workstation kind with a Red management attachment. Zone information belongs to its interfaces and deployment attachments. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Interface](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean), [msc_administrator_authentication](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Gray Administrative Workstation | Combination of Lean fields | A Gray workstation combines the workstation kind with a Gray management attachment. The deployment also provides the grayWorkstation predicate. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Interface](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean), [msc_gray_firewall_path_coverage](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Black Administrative Workstation | Related model only | The model can record a workstation and Black interface, but has no separate Black-workstation role or complete Black-workstation specification. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Interface](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Management component | Related model only | Management roles are represented through service instances and component attachments. There is no single management-component device kind. | [ManagementServiceInstance](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Red Management Services | Combination of Lean fields | Each management service records its function, hosting device, process, interface, and Red management domain. | [ManagementServiceInstance](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementDomain](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementServiceFunction](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Gray Management Services | Combination of Lean fields | Each management service records its function, hosting device, process, interface, and Gray management domain. | [ManagementServiceInstance](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementDomain](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementServiceFunction](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Security Information and Event Management | Explicit Lean representation | SIEM has a dedicated device kind. Monitoring and logging registrations describe its service use. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementServiceFunction](../../../TDN/Requirements/MscComplianceSchema.lean), [ServiceKind](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Red SIEM | Combination of Lean fields | The SIEM kind combines with a Red interface or management-service domain. The zone is recorded separately from the device kind. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Interface](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementServiceInstance](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Gray SIEM | Combination of Lean fields | The SIEM kind combines with a Gray interface or management-service domain. The zone is recorded separately from the device kind. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Interface](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementServiceInstance](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Authentication Server | Explicit Lean representation | Authentication Servers have a dedicated device kind. MACsec authentication records identify the server and its site/network attachments. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [MACsecAuthentication](../../../TDN/Requirements/CoreMscRequirements.lean), [msc_macsec_authentication_choice_and_as](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Supplicant | Explicit Lean representation | The EAP role is a protocol function recorded separately from device kind. A MACsec device can support both functions across different arrangements. | [EAPRole](../../../TDN/Requirements/CoreMscRequirements.lean), [MACsecAuthentication](../../../TDN/Requirements/CoreMscRequirements.lean), [msc_macsec_authentication_choice_and_as](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Authenticator | Explicit Lean representation | The EAP role is a protocol function recorded separately from device kind. A MACsec device can support both functions across different arrangements. | [EAPRole](../../../TDN/Requirements/CoreMscRequirements.lean), [MACsecAuthentication](../../../TDN/Requirements/CoreMscRequirements.lean), [msc_macsec_authentication_choice_and_as](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Key Server | Combination of Lean fields | The key server is an endpoint selected in MACsec authentication and key-server-pair records. The role is not a separate DeviceKind. | [MACsecAuthentication](../../../TDN/Requirements/CoreMscRequirements.lean), [MACsecServerPair](../../../TDN/Requirements/CoreMscRequirements.lean), [msc_macsec_key_generation_and_server](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Certification Authority | Explicit Lean representation | Certification Authorities have a dedicated device kind and are associated with authenticated components through key-management records. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean), [InnerAuthentication](../../../TDN/Requirements/CrossEnclavePkiIsolationSpec.lean) |
| Inner CA | Combination of Lean fields | The CA serves Inner components through keyManagementCA relations. The component’s encryption layer identifies the CA’s architectural use. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean), [Device](../../../TDN/Requirements/MscComplianceSchema.lean), [InnerAuthentication](../../../TDN/Requirements/CrossEnclavePkiIsolationSpec.lean) |
| Outer CA | Combination of Lean fields | The CA serves Outer components through keyManagementCA relations. The component’s encryption layer identifies the CA’s architectural use. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean), [Device](../../../TDN/Requirements/MscComplianceSchema.lean), [InnerAuthentication](../../../TDN/Requirements/CrossEnclavePkiIsolationSpec.lean) |
| Locally run CA | Related model only | The CA kind and its placement can be recorded. GrayTopology separately lists locally run CA nodes for the selected Gray management security-level convention. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [msc_gray_firewall_path_coverage](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Enterprise CA | Related model only | Enterprise CAs can be listed as CA devices and Gray service nodes. V3.1 does not give enterprise CAs a distinct DeviceKind. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [msc_gray_firewall_path_coverage](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Root CA | Related model only | The authentication model records certificate issuers and trusted issuer identifiers. It does not encode the full CA hierarchy or every distinction among these source roles. | [InnerAuthentication](../../../TDN/Requirements/CrossEnclavePkiIsolationSpec.lean), [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Signing CA | Related model only | The authentication model records certificate issuers and trusted issuer identifiers. It does not encode the full CA hierarchy or every distinction among these source roles. | [InnerAuthentication](../../../TDN/Requirements/CrossEnclavePkiIsolationSpec.lean), [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Key Generation Solution | Explicit Lean representation | The key-generation solution has a device kind. Approved-generator status is supplied as an explicit authority fact. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [AuthorityFacts](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean), [msc_macsec_key_generation_and_server](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Encapsulation/Decapsulation Device | Combination of Lean fields | The encapsulation role uses EncapsulationUse records and the standaloneEncapsulator predicate. A device kind is available, while the actual specification checks the selected use, attachments and applicable duties. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [EncapsulationUse](../../../TDN/Requirements/CoreMscRequirements.lean), [MACsecEncapsulationCore](../../../TDN/Requirements/CoreMscRequirements.lean), [msc_macsec_encapsulation](../../../TDN/Requirements/MasterMscRequirementSpecs.lean), [MscComplianceContext.AllApplicableDuties](../../../TDN/Requirements/CsfcRoleObligations.lean) |
| Router | Related model only | The model distinguishes ordinary Gray routers and screening routers. General packet routing is represented by processing records; there is no unrestricted router DeviceKind. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment.OrdinaryGray](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Gray Network router | Combination of Lean fields | An ordinary Gray router has the router kind, no encryption layer and no infrastructure flag. It has at least one Gray interface; every other interface is Gray or local. Local includes device-internal interfaces such as loopback. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment.OrdinaryGray](../../../TDN/Requirements/MscComplianceSchema.lean), [Zone](../../../TDN/Requirements/TwoLayerOverlayArchitecture.lean) |
| Screening router | Explicit Lean representation | Screening routers have a dedicated device kind. Source-defined placement and filtering still require the corresponding configuration. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Customer Edge Router | Related model only | The source’s customer-edge example can realize a router role. V3.1 has no customer-edge-specific device kind or automatic equivalence with screeningRouter. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Switch | Related model only | An ordinary Gray switch has a dedicated kind, no encryption layer and no infrastructure flag. It has at least one Gray interface and only Gray or local interfaces. Other switching behavior is represented through packet-processing records. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment.OrdinaryGray](../../../TDN/Requirements/MscComplianceSchema.lean), [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean), [Zone](../../../TDN/Requirements/TwoLayerOverlayArchitecture.lean) |
| Cross Domain Solution | Explicit Lean representation | Cross Domain Solutions have a device kind. Requirement applicability also uses the recorded cross-domain-solution inventory. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [MscComplianceContext.ComponentApplies](../../../TDN/Requirements/CsfcRoleObligations.lean) |
| CRL Distribution Point | Related model only | Both roles are represented through the broader revocationService kind and revocation service information. DeviceKind does not distinguish CDP from OCSP responders. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementServiceFunction](../../../TDN/Requirements/MscComplianceSchema.lean), [msc_gray_firewall_path_coverage](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| OCSP Responder | Related model only | Both roles are represented through the broader revocationService kind and revocation service information. DeviceKind does not distinguish CDP from OCSP responders. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementServiceFunction](../../../TDN/Requirements/MscComplianceSchema.lean), [msc_gray_firewall_path_coverage](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Intrusion Prevention System | Explicit Lean representation | Intrusion Prevention Systems have a dedicated device kind. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [MscComplianceContext.ComponentApplies](../../../TDN/Requirements/CsfcRoleObligations.lean) |
| Host/server for AW virtual machines | No distinct representation | V3.1 does not define the host/guest virtualization or physical-workstation realization hierarchy. The source role remains available for future modeling. |  |
| Virtual Machine | No distinct representation | V3.1 does not define the host/guest virtualization or physical-workstation realization hierarchy. The source role remains available for future modeling. |  |
| Physical workstation | No distinct representation | V3.1 does not define the host/guest virtualization or physical-workstation realization hierarchy. The source role remains available for future modeling. |  |
| Enrollment server | No distinct representation | V3.1 does not define a separate role or protocol model for this certificate-provisioning function. |  |
| Provisioning server | No distinct representation | V3.1 does not define a separate role or protocol model for this certificate-provisioning function. |  |
| Certificate registration component | No distinct representation | V3.1 does not define a separate role or protocol model for this certificate-provisioning function. |  |
| Registration Authority | No distinct representation | V3.1 does not define a separate role or protocol model for this certificate-provisioning function. |  |
| Trusted time source | Explicit Lean representation | A time-source endpoint records the actual source component and interface. Placement and client synchronization use the time model. | [TimeSourceEndpoint](../../../TDN/Requirements/TrustedClockSynchronization.lean), [ManagementServiceFunction](../../../TDN/Requirements/MscComplianceSchema.lean) |
| DNS server | Combination of Lean fields | DNS service use is represented by the name-resolution management function and configuration records. DeviceKind has no separate DNS-server constructor. | [ManagementServiceFunction](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementServiceInstance](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Control plane network service | Combination of Lean fields | Control service registrations identify protocol and port. Their kind is recorded separately from the hosting device. | [ServiceKind](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Third-party server | Related model only | Third-party behavior is represented by feature and emitted-traffic records. The remote server is not a dedicated device kind. | [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean) |
| End user device | Related model only | Red network records and modeled payload origins identify source and destination networks. DeviceKind has no separate end-user-host constructor. | [RedNetworkIdentity](../../../TDN/Requirements/TwoLayerOverlayArchitecture.lean) |
| High Assurance encryptor | No distinct representation | The extracted assurance/product category is not a distinct device kind in the current theory. Product eligibility and external assurance remain separate evidence obligations. | [ExternalFacts](../../../TDN/Requirements/CsfcRoleObligationRecords.lean) |
| NSA-certified Government-off-the-Shelf product | No distinct representation | The extracted assurance/product category is not a distinct device kind in the current theory. Product eligibility and external assurance remain separate evidence obligations. | [ExternalFacts](../../../TDN/Requirements/CsfcRoleObligationRecords.lean) |
| Locally Managed Device | Related model only | Administrative operation and connection records describe management access. V3.1 does not divide devices into local-management and remote-management kinds. | [AdministrativeAccount](../../../TDN/Requirements/ManagementPlaneRequirements.lean), [ManagementExchange](../../../TDN/Requirements/MscComplianceSchema.lean), [msc_administrator_authentication](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Remotely Managed Device | Related model only | Administrative operation and connection records describe management access. V3.1 does not divide devices into local-management and remote-management kinds. | [AdministrativeAccount](../../../TDN/Requirements/ManagementPlaneRequirements.lean), [ManagementExchange](../../../TDN/Requirements/MscComplianceSchema.lean), [msc_administrator_authentication](../../../TDN/Requirements/MasterMscRequirementSpecs.lean) |
| Auxiliary network device | No distinct representation | The broad source grouping has no dedicated role predicate. Specific member functions must be mapped separately. |  |
| Infrastructure authentication service | Combination of Lean fields | Authentication is a registered service function hosted by a component. The hosting device may also have the authenticationServer kind. | [ManagementServiceFunction](../../../TDN/Requirements/MscComplianceSchema.lean), [ServiceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Network administration device | Related model only | The source role may be realized by workstation or administration services. V3.1 has no separate network-administration-device kind. | [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementServiceFunction](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Infrastructure component | Explicit Lean representation | The device record has an infrastructure flag. Flow.Valid requires both encryption endpoints to carry that flag. | [Device](../../../TDN/Requirements/MscComplianceSchema.lean), [Flow.Valid](../../../TDN/Requirements/CoreMscRequirements.lean) |
| Network device | Related model only | Device is the general inventory record for all modeled device kinds. Source role membership beyond that inventory remains contextual. | [Device](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Perimeter device | No distinct representation | The broad source grouping has no dedicated role predicate. Specific member functions must be mapped separately. |  |
| Key and certificate management component | Combination of Lean fields | Key management combines CA and key-generation device records, service functions, and component-to-service relations. | [Deployment](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementServiceFunction](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Trust Anchor CA | Related model only | The authentication model records certificate issuers and trusted issuer identifiers. It does not encode the full CA hierarchy or every distinction among these source roles. | [InnerAuthentication](../../../TDN/Requirements/CrossEnclavePkiIsolationSpec.lean), [DeviceKind](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Approved password generator | No distinct representation | Password-generator approval is an external configuration/authority requirement. V3.1 has no separate password-generator behavior model. | [ExternalFacts](../../../TDN/Requirements/CsfcRoleObligationRecords.lean) |
| Log and status repository | Combination of Lean fields | Logging and monitoring registrations represent the service role. A repository-specific device kind is not required by the model. | [ServiceKind](../../../TDN/Requirements/MscComplianceSchema.lean), [ManagementServiceFunction](../../../TDN/Requirements/MscComplianceSchema.lean) |
| Testing equipment | No distinct representation | These source roles describe the testing process. V3.1 does not formalize them as network device roles. |  |
| Testing software | No distinct representation | These source roles describe the testing process. V3.1 does not formalize them as network device roles. |  |
| IKEv2 initiator | Related model only | The retained model records tunnel and authentication endpoints. It does not introduce an IKE initiator/responder role type; ManagementExchange.responder concerns management traffic. | [Flow.Valid](../../../TDN/Requirements/CoreMscRequirements.lean), [InnerAuthentication](../../../TDN/Requirements/CrossEnclavePkiIsolationSpec.lean) |
| IKEv2 responder | Related model only | The retained model records tunnel and authentication endpoints. It does not introduce an IKE initiator/responder role type; ManagementExchange.responder concerns management traffic. | [Flow.Valid](../../../TDN/Requirements/CoreMscRequirements.lean), [InnerAuthentication](../../../TDN/Requirements/CrossEnclavePkiIsolationSpec.lean) |

## Associated proof obligations

Associations connect a role to the current formalized requirement in which it participates. Applicability conditions, selected objectives, external evidence, and whole-network quantifiers remain part of each statement. Child roles inherit associations from every subclass ancestor; documented associations do not transmit obligations. Listing a requirement does not assert that a device or deployment satisfies it.

The explorer shows each selected role’s obligations below its name. Every entry includes a plain-English summary, its current Lean code, source links, and the recorded proof status. Parent-role obligations are included once and identify the roles from which they were inherited.

[Curated obligation mappings and translations](ontology_obligations.json) connect roles to requirement groups. The generator reads the code and proof status from the current sources. Source changes require reviewing the translations before regeneration.

| Role | Directly associated RGs | Inherited RGs |
| --- | --- | --- |
| Solution Component | RG-001, RG-002, RG-003, RG-006, RG-036, RG-041, RG-043, RG-046, RG-047, RG-049, RG-052, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 | None |
| Encryption Component | RG-004, RG-005, RG-007, RG-017, RG-018, RG-031, RG-032, RG-033, RG-035, RG-042, RG-048, RG-053, RG-054, RG-056 | RG-001, RG-002, RG-003, RG-006, RG-036, RG-041, RG-043, RG-046, RG-047, RG-049, RG-052, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Inner Encryption Component | RG-008, RG-012, RG-013, RG-014, RG-029 | RG-001, RG-002, RG-003, RG-004, RG-005, RG-006, RG-007, RG-017, RG-018, RG-031, RG-032, RG-033, RG-035, RG-036, RG-041, RG-042, RG-043, RG-046, RG-047, RG-048, RG-049, RG-052, RG-053, RG-054, RG-056, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Outer Encryption Component | RG-013, RG-014, RG-030, RG-034, RG-037, RG-038, RG-039 | RG-001, RG-002, RG-003, RG-004, RG-005, RG-006, RG-007, RG-017, RG-018, RG-031, RG-032, RG-033, RG-035, RG-036, RG-041, RG-042, RG-043, RG-046, RG-047, RG-048, RG-049, RG-052, RG-053, RG-054, RG-056, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| VPN Gateway | RG-019, RG-020, RG-021, RG-022, RG-023, RG-038 | RG-001, RG-002, RG-003, RG-004, RG-005, RG-006, RG-007, RG-017, RG-018, RG-031, RG-032, RG-033, RG-035, RG-036, RG-041, RG-042, RG-043, RG-046, RG-047, RG-048, RG-049, RG-052, RG-053, RG-054, RG-056, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Inner VPN Gateway | None recorded | RG-001, RG-002, RG-003, RG-004, RG-005, RG-006, RG-007, RG-008, RG-012, RG-013, RG-014, RG-017, RG-018, RG-019, RG-020, RG-021, RG-022, RG-023, RG-029, RG-031, RG-032, RG-033, RG-035, RG-036, RG-038, RG-041, RG-042, RG-043, RG-046, RG-047, RG-048, RG-049, RG-052, RG-053, RG-054, RG-056, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Outer VPN Gateway | None recorded | RG-001, RG-002, RG-003, RG-004, RG-005, RG-006, RG-007, RG-013, RG-014, RG-017, RG-018, RG-019, RG-020, RG-021, RG-022, RG-023, RG-030, RG-031, RG-032, RG-033, RG-034, RG-035, RG-036, RG-037, RG-038, RG-039, RG-041, RG-042, RG-043, RG-046, RG-047, RG-048, RG-049, RG-052, RG-053, RG-054, RG-056, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| MACsec Device | RG-015, RG-016, RG-024, RG-025, RG-026, RG-027, RG-028 | RG-001, RG-002, RG-003, RG-004, RG-005, RG-006, RG-007, RG-017, RG-018, RG-031, RG-032, RG-033, RG-035, RG-036, RG-041, RG-042, RG-043, RG-046, RG-047, RG-048, RG-049, RG-052, RG-053, RG-054, RG-056, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Inner MACsec Device | None recorded | RG-001, RG-002, RG-003, RG-004, RG-005, RG-006, RG-007, RG-008, RG-012, RG-013, RG-014, RG-015, RG-016, RG-017, RG-018, RG-024, RG-025, RG-026, RG-027, RG-028, RG-029, RG-031, RG-032, RG-033, RG-035, RG-036, RG-041, RG-042, RG-043, RG-046, RG-047, RG-048, RG-049, RG-052, RG-053, RG-054, RG-056, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Outer MACsec Device | None recorded | RG-001, RG-002, RG-003, RG-004, RG-005, RG-006, RG-007, RG-013, RG-014, RG-015, RG-016, RG-017, RG-018, RG-024, RG-025, RG-026, RG-027, RG-028, RG-030, RG-031, RG-032, RG-033, RG-034, RG-035, RG-036, RG-037, RG-038, RG-039, RG-041, RG-042, RG-043, RG-046, RG-047, RG-048, RG-049, RG-052, RG-053, RG-054, RG-056, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Firewall | RG-035, RG-055 | None |
| Outer Firewall | RG-034, RG-038 | RG-001, RG-002, RG-003, RG-006, RG-035, RG-036, RG-041, RG-043, RG-046, RG-047, RG-049, RG-052, RG-055, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Gray Firewall | RG-005, RG-013, RG-014, RG-033, RG-040 | RG-001, RG-002, RG-003, RG-006, RG-035, RG-036, RG-041, RG-043, RG-046, RG-047, RG-049, RG-052, RG-055, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Inner Firewall | RG-055 | RG-035, RG-055 |
| Administrative Workstation | RG-044, RG-045, RG-046, RG-047 | RG-010, RG-011, RG-044, RG-046 |
| Red Administrative Workstation | RG-012 | RG-001, RG-002, RG-003, RG-006, RG-010, RG-011, RG-036, RG-041, RG-043, RG-044, RG-045, RG-046, RG-047, RG-049, RG-052, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Gray Administrative Workstation | RG-013, RG-039, RG-040 | RG-001, RG-002, RG-003, RG-006, RG-010, RG-011, RG-036, RG-041, RG-043, RG-044, RG-045, RG-046, RG-047, RG-049, RG-052, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Black Administrative Workstation | None recorded | RG-010, RG-011, RG-044, RG-045, RG-046, RG-047 |
| Management component | RG-010, RG-011, RG-044, RG-046 | None |
| Red Management Services | RG-011, RG-012, RG-041, RG-042, RG-044 | None |
| Gray Management Services | RG-011, RG-013, RG-039, RG-040, RG-041, RG-042, RG-044 | None |
| Security Information and Event Management | RG-050, RG-062 | None |
| Red SIEM | None recorded | RG-050, RG-062 |
| Gray SIEM | None recorded | RG-050, RG-062 |
| Authentication Server | RG-024, RG-026 | RG-001, RG-002, RG-003, RG-006, RG-036, RG-041, RG-043, RG-046, RG-047, RG-049, RG-052, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Supplicant | RG-024 | None |
| Authenticator | RG-024 | None |
| Key Server | RG-027 | RG-001, RG-002, RG-003, RG-004, RG-005, RG-006, RG-007, RG-015, RG-016, RG-017, RG-018, RG-024, RG-025, RG-026, RG-027, RG-028, RG-031, RG-032, RG-033, RG-035, RG-036, RG-041, RG-042, RG-043, RG-046, RG-047, RG-048, RG-049, RG-052, RG-053, RG-054, RG-056, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Certification Authority | RG-007, RG-017, RG-020, RG-024, RG-048, RG-067 | None |
| Inner CA | RG-012 | RG-007, RG-017, RG-020, RG-024, RG-048, RG-067 |
| Outer CA | None recorded | RG-007, RG-017, RG-020, RG-024, RG-048, RG-067 |
| Locally run CA | RG-013 | RG-007, RG-017, RG-020, RG-024, RG-048, RG-067 |
| Enterprise CA | RG-011 | RG-007, RG-017, RG-020, RG-024, RG-048, RG-067 |
| Root CA | RG-020 | RG-007, RG-017, RG-020, RG-024, RG-048, RG-067 |
| Signing CA | RG-020 | RG-007, RG-017, RG-020, RG-024, RG-048, RG-067 |
| Key Generation Solution | RG-007, RG-027 | RG-001, RG-002, RG-003, RG-006, RG-036, RG-041, RG-043, RG-046, RG-047, RG-049, RG-052, RG-057, RG-058, RG-062, RG-063, RG-066, RG-067, RG-073, RG-074 |
| Encapsulation/Decapsulation Device | RG-015, RG-033 | None |
| Router | RG-075 | None |
| Gray Network router | None recorded | RG-075 |
| Screening router | RG-075 | RG-075 |
| Customer Edge Router | RG-032 | RG-075 |
| Switch | None recorded | None |
| Cross Domain Solution | RG-051, RG-056 | None |
| CRL Distribution Point | RG-013, RG-020, RG-039, RG-040, RG-067 | None |
| OCSP Responder | RG-013, RG-020, RG-067 | None |
| Intrusion Prevention System | RG-003, RG-055 | None |
| Host/server for AW virtual machines | RG-045 | None |
| Virtual Machine | RG-045 | None |
| Physical workstation | RG-045 | None |
| Enrollment server | RG-048 | None |
| Provisioning server | RG-043, RG-048 | None |
| Certificate registration component | RG-048 | None |
| Registration Authority | RG-048 | None |
| Trusted time source | RG-042 | None |
| DNS server | RG-043 | None |
| Control plane network service | RG-035, RG-039, RG-040, RG-041 | None |
| Third-party server | RG-037 | None |
| End user device | RG-008, RG-055, RG-056 | None |
| High Assurance encryptor | RG-056 | None |
| NSA-certified Government-off-the-Shelf product | RG-056 | None |
| Locally Managed Device | RG-044, RG-046 | None |
| Remotely Managed Device | RG-011, RG-044, RG-046 | None |
| Auxiliary network device | RG-068 | None |
| Infrastructure authentication service | RG-063 | None |
| Network administration device | RG-044, RG-046, RG-047 | None |
| Infrastructure component | RG-041, RG-043, RG-044, RG-046, RG-063 | None |
| Network device | RG-036 | None |
| Perimeter device | RG-055 | None |
| Key and certificate management component | RG-007, RG-017, RG-027, RG-048, RG-067 | RG-010, RG-011, RG-044, RG-046 |
| Trust Anchor CA | RG-020 | RG-007, RG-017, RG-020, RG-024, RG-048, RG-067 |
| Approved password generator | RG-063 | None |
| Log and status repository | RG-050, RG-062 | None |
| Testing equipment | RG-072 | None |
| Testing software | RG-072 | None |
| IKEv2 initiator | RG-017, RG-019, RG-020, RG-022, RG-023 | None |
| IKEv2 responder | RG-017, RG-019, RG-020, RG-022, RG-023 | None |

## Chosen v3.3 interpretations

### V31-007: data-plane protection, tunnel endpoints, and services

V3.1 separates encryption mechanism, Inner/Outer layer, interface zone and full security level. Flow.Valid binds the two tunnel endpoints and independent key contexts. AuthenticationServices requires a CA or key-generation service according to each component’s selected authentication method. Workstations are optional under the current scope.

Recorded decision: `data/construction/v3.2-20261031T231942Z/interpretations.md:67`.

### V31-012: authentication alternatives and management deployment

Credential separation applies to the selected certificate or shared-key method. Management-device presence and separation are required only when managementSelected is true. Different network names do not imply different full security levels.

Recorded decision: `data/construction/v3.2-20261031T231942Z/interpretations.md:81`.

### V31-013: all Gray paths, filtering, and management services

The Gray path specification distinguishes Inner components, Gray Firewalls, workstations, locally run CAs, all CAs and revocation services. Gray AWs and locally run CAs follow the highest-level convention. The broader service-path requirements retain each service’s actual level.

Recorded decision: `data/construction/v3.2-20261031T231942Z/interpretations.md:87`.

### V31-015: carrier placement and standalone obligations

When built-in encapsulation is unavailable, the selected standalone encapsulator must have the required Inner-side and Outer-side attachments and satisfy its applicable component duties. The current RG-015 definition preserves those duties despite the source passage describing encapsulation as outside the solution boundary.

Recorded decision: `data/construction/v3.2-20261031T231942Z/interpretations.md:99`.

### V31-024: certificate roles and AS network scope

A MACsec device supports supplicant and authenticator functions across arrangements. EAPRole describes those functions separately from DeviceKind. The AS is bound to one site network in the selected interpretation; one AS must not bridge Red and Gray or several site networks.

Recorded decision: `data/construction/v3.2-20261031T231942Z/interpretations.md:109`.

### V31-027: key generation, provisioning, central servers, fallback

The key server is an endpoint function. MACsecServerPair and the actual central-management-site declaration determine the server’s placement. Approved key-generation provenance remains an explicit authority condition, including the chosen EAP-derived CAK interpretation.

Recorded decision: `data/construction/v3.2-20261031T231942Z/interpretations.md:117`.

### V31-047: live sessions and individual credentials

Administrative Workstations are optional. When deployed, administrator accounts and active sessions must bind each accepted operation to the appropriate individual and prior authentication. Certificate and NIST objectives add their selected assurance conditions.

Recorded decision: `data/construction/v3.2-20261031T231942Z/interpretations.md:173`.

### V31-056-074: whole-solution protection and redundant duties

Ordinary Gray routing and switching infrastructure has a narrowly defined exemption from component duties. OrdinaryGray requires the matching kind, no encryption layer or infrastructure flag, at least one Gray interface, and only Gray or local interfaces. Standalone encapsulators retain their applicable duties.

Recorded decision: `data/construction/v3.2-20261031T231942Z/interpretations.md:185`.

### RG-033: external interface sizes and optional Inner reduction

Mandatory MTU bounds include Inner Gray interfaces, Outer Black interfaces and applicable Gray Firewall external interfaces. The separate Inner fragmentation-reduction objective remains optional.

Recorded decision: `data/construction/v3.2-20261104-continuation/source-review/RG-033.md:3`.


## Encryption

| Role | Direct broader roles |
| --- | --- |
| Encryption Component | Solution Component |
| Inner Encryption Component | Encryption Component |
| Outer Encryption Component | Encryption Component |
| VPN Gateway | Encryption Component |
| Inner VPN Gateway | VPN Gateway, Inner Encryption Component |
| Outer VPN Gateway | VPN Gateway, Outer Encryption Component |
| MACsec Device | Encryption Component |
| Inner MACsec Device | MACsec Device, Inner Encryption Component |
| Outer MACsec Device | MACsec Device, Outer Encryption Component |
| High Assurance encryptor | Extracted role or concept realization |
| NSA-certified Government-off-the-Shelf product | Extracted role or concept realization |

## Filtering and routing

| Role | Direct broader roles |
| --- | --- |
| Firewall | Extracted role or concept realization |
| Outer Firewall | Firewall, Solution Component |
| Gray Firewall | Firewall, Solution Component |
| Inner Firewall | Firewall |
| Router | Extracted role or concept realization |
| Gray Network router | Router |
| Screening router | Router |
| Customer Edge Router | Router |
| Switch | Extracted role or concept realization |
| Encapsulation/Decapsulation Device | Extracted role or concept realization |
| Intrusion Prevention System | Extracted role or concept realization |
| Perimeter device | Extracted role or concept realization |

## Administration and realization

| Role | Direct broader roles |
| --- | --- |
| Administrative Workstation | Management component |
| Red Administrative Workstation | Administrative Workstation, Solution Component |
| Gray Administrative Workstation | Administrative Workstation, Solution Component |
| Black Administrative Workstation | Administrative Workstation |
| Host/server for AW virtual machines | Extracted role or concept realization |
| Virtual Machine | Extracted role or concept realization |
| Physical workstation | Extracted role or concept realization |
| Locally Managed Device | Extracted role or concept realization |
| Remotely Managed Device | Extracted role or concept realization |
| Network administration device | Extracted role or concept realization |

## Management and monitoring

| Role | Direct broader roles |
| --- | --- |
| Management component | Extracted role or concept realization |
| Red Management Services | Extracted role or concept realization |
| Gray Management Services | Extracted role or concept realization |
| Security Information and Event Management | Extracted role or concept realization |
| Red SIEM | Security Information and Event Management |
| Gray SIEM | Security Information and Event Management |
| Log and status repository | Extracted role or concept realization |
| Cross Domain Solution | Extracted role or concept realization |

## Authentication and protocol roles

| Role | Direct broader roles |
| --- | --- |
| Authentication Server | Solution Component |
| Supplicant | Extracted role or concept realization |
| Authenticator | Extracted role or concept realization |
| Key Server | MACsec Device |
| Infrastructure authentication service | Extracted role or concept realization |
| IKEv2 initiator | Extracted role or concept realization |
| IKEv2 responder | Extracted role or concept realization |

## Keys and certificates

| Role | Direct broader roles |
| --- | --- |
| Certification Authority | Extracted role or concept realization |
| Inner CA | Certification Authority |
| Outer CA | Certification Authority |
| Locally run CA | Certification Authority |
| Enterprise CA | Certification Authority |
| Root CA | Certification Authority |
| Signing CA | Certification Authority |
| Trust Anchor CA | Certification Authority |
| Key Generation Solution | Solution Component |
| Key and certificate management component | Management component |
| CRL Distribution Point | Extracted role or concept realization |
| OCSP Responder | Extracted role or concept realization |
| Registration Authority | Extracted role or concept realization |
| Enrollment server | Extracted role or concept realization |
| Provisioning server | Extracted role or concept realization |
| Certificate registration component | Extracted role or concept realization |

## Infrastructure and supporting services

| Role | Direct broader roles |
| --- | --- |
| Solution Component | Extracted role or concept realization |
| Infrastructure component | Extracted role or concept realization |
| Network device | Extracted role or concept realization |
| Auxiliary network device | Extracted role or concept realization |
| Trusted time source | Extracted role or concept realization |
| DNS server | Extracted role or concept realization |
| Control plane network service | Extracted role or concept realization |
| Third-party server | Extracted role or concept realization |
| End user device | Extracted role or concept realization |

## Utilities and testing

| Role | Direct broader roles |
| --- | --- |
| Approved password generator | Extracted role or concept realization |
| Testing equipment | Extracted role or concept realization |
| Testing software | Extracted role or concept realization |

## Role scope notes

- **Registration Authority**: The glossary includes individuals as well as hardware/software. Only the hardware/software function is within the device-role inventory.

## Subtype evidence

### Encryption Component → Solution Component

Section 5 presents the encryption components as components of the MSC Solution. The edge applies to the source-context Encryption Component category.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p022:u003`

> 5 SOLUTION COMPONENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s002`

> 2, all communications flowing across a Black Network are protected by at least two layers of encryption, implemented using IPsec tunnels generated by VPN Gateways or MACsec tunnels generated by MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u005.s001`

> Each Solution Component is described in more detail below.
### VPN Gateway → Encryption Component

The glossary defines an Encryption Component as either a VPN Gateway or a MACsec Device. Each named alternative is included under the defined category.

Basis: source_stated.


`CSFC-MSC-1.3.0-4e40e3d83708:p060:u004.s001`

> Encryption Component – Either a VPN Gateway or a MACsec Device.
### MACsec Device → Encryption Component

The glossary includes MACsec Devices in the Encryption Component category.

Basis: source_stated.


`CSFC-MSC-1.3.0-4e40e3d83708:p060:u004.s001`

> Encryption Component – Either a VPN Gateway or a MACsec Device.
### Inner Encryption Component → Encryption Component

Inner Encryption Components use the VPN Gateway or MACsec Device alternatives that define an Encryption Component.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s001`

> Inner Encryption Components can either be VPN Gateways or MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u004.s001`

> Encryption Component – Either a VPN Gateway or a MACsec Device.
### Outer Encryption Component → Encryption Component

Outer Encryption Components use the VPN Gateway or MACsec Device alternatives that define an Encryption Component.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s001`

> The Outer Encryption Component can be either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u004.s001`

> Encryption Component – Either a VPN Gateway or a MACsec Device.
### Inner VPN Gateway → VPN Gateway

The provisioning text names Inner VPN Gateways as the inner specialization of VPN Gateways.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s001`

> For provisioning IPsec Outer VPN Gateways and Inner VPN Gateways generate a public/private key pair and output the public key in a Certificate Signing Request (CSR).
### Inner VPN Gateway → Inner Encryption Component

The Inner Encryption Component requirements identify the Inner VPN Gateway as their VPN realization.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p042:u016.s002`

> Additional Inner Encryption Component (IR) Requirements

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u018`

> MSC-IR-1 The Inner VPN Gateway must use ESP Tunnel mode IPsec, with an associated IP tunneling protocol. T=O
### Outer VPN Gateway → VPN Gateway

The provisioning text names Outer VPN Gateways as the outer specialization of VPN Gateways.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s001`

> For provisioning IPsec Outer VPN Gateways and Inner VPN Gateways generate a public/private key pair and output the public key in a Certificate Signing Request (CSR).
### Outer VPN Gateway → Outer Encryption Component

The Outer Encryption Component requirements identify Outer VPN Gateways as their VPN realization.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p043:u010.s002`

> Additional Outer Encryption Components (OR) Requirements

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u012`

> MSC-OR-1 Outer VPN Gateways must use ESP Tunnel mode IPsec. T=O
### Inner MACsec Device → MACsec Device

The source names an Inner MACsec Device as the inner specialization of a MACsec Device.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.
### Inner MACsec Device → Inner Encryption Component

Section 5.5 identifies MACsec Devices as an Inner Encryption Component realization and then describes the Inner MACsec Device.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s001`

> Inner Encryption Components can either be VPN Gateways or MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.
### Outer MACsec Device → MACsec Device

MSC-PF-4 names the Outer MACsec Device specialization.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p044:u017`

> MSC-PF-4 For all Outer MACsec Device interfaces connected to a Black Network, traffic filtering rules must be T=O applied to both inbound and outbound traffic, such that only MACsec Protocol Data Units and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed.
### Outer MACsec Device → Outer Encryption Component

The outer component can be a MACsec Device; MSC-PF-4 names the Outer MACsec Device and its Black Network interfaces.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s001`

> The Outer Encryption Component can be either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u017`

> MSC-PF-4 For all Outer MACsec Device interfaces connected to a Black Network, traffic filtering rules must be T=O applied to both inbound and outbound traffic, such that only MACsec Protocol Data Units and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed.
### Outer Firewall → Firewall

The source names the firewall at the outer edge as the Outer Firewall.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p023:u001`

> 5.1 OUTER FIREWALL

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s004`

> The Outer Firewall is located at the edge of the MSC Solution and is connected to the Black Network.
### Gray Firewall → Firewall

The glossary explicitly defines a Gray Firewall as a traffic filtering firewall.

Basis: source_stated.


`CSFC-MSC-1.3.0-4e40e3d83708:p060:u009.s001`

> Gray Firewall – A traffic filtering firewall placed on the Gray Network to provide additional separation between flows of singly-encrypted data of different security levels.
### Inner Firewall → Firewall

Section 5.6 names the firewall between the Inner Encryption Component and Red Network as the Inner Firewall.

Basis: source_interpretation.

- The edge does not make an Inner Firewall mandatory. Requirements can come from another CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u008`

> 5.6 INNER FIREWALL

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s001`

> An Inner Firewall is located between the Inner Encryption Component and the Red Network.
### Outer Firewall → Solution Component

The source describes individual solution components and identifies the Outer Firewall as an exception to their physical-protection requirement.

Basis: source_interpretation.

- Membership does not imply presence in every MSC deployment.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u006.s001`

> All the individual components within the solution must be physically protected to the level of the connected network with the highest classification/protection level.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u006.s002`

> The only exception to this requirement would be the Outer Firewall if one is present in the solution.
### Gray Firewall → Solution Component

Section 5 includes Gray Firewalls among the solution components.

Basis: source_interpretation.

- The source makes Gray Firewall deployment depend on the network design. The subtype axiom expresses category membership only.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003`

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u005.s001`

> Each Solution Component is described in more detail below.
### Administrative Workstation → Management component

The administration section describes AWs as the components whose combined management functions satisfy the administrative requirements.

Basis: source_interpretation.

- The superclass is the generic extracted Management component category. No universal Solution Component membership follows.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s001`

> Each component in the solution has one or more AWs that maintain, monitor, and control all security functions for that component.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s002`

> It should be noted that all of the required administrative functionality does not need to be present in each individual management component, but the entire set of AWs must collectively meet administrative functionality requirements.
### Red Administrative Workstation → Administrative Workstation

The Red AW is the named Red-side specialization of the Administrative Workstation.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.
### Gray Administrative Workstation → Administrative Workstation

The Gray Administrative Workstation subsection defines the Gray AW specialization.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p024:u009`

> 5.4.1 GRAY ADMINISTRATIVE WORKSTATION (AW)

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.
### Black Administrative Workstation → Administrative Workstation

The prohibition names Black AWs alongside Red AWs, supporting the workstation specialization without supplying a positive MSC assignment.

Basis: source_interpretation.

- The subtype axiom does not authorize Black AW management of Gray components or place Black AWs inside the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s006`

> As a result, neither Red nor Black AWs are permitted to manage the Outer Encryption Component, Gray Firewall, or Gray Management Services.
### Red Administrative Workstation → Solution Component

The source includes AWs among solution components and requires at least one Red AW in every MSC Solution.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003`

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s003`

> All MSC Solutions will have at least one Red AW.
### Gray Administrative Workstation → Solution Component

The source includes AWs among solution components and requires at least one Gray AW in every MSC Solution.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003`

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s003`

> All MSC Solutions must have at least one Gray AW.
### Red SIEM → Security Information and Event Management

Section 5.7.2 identifies the Red SIEM specialization of Security Information and Event Management.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p026:u003`

> 5.7.2 RED SECURITY INFORMATION AND EVENT MANAGEMENT (SIEM)

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.
### Gray SIEM → Security Information and Event Management

Section 5.4.2 identifies the Gray SIEM specialization of Security Information and Event Management.

Basis: source_interpretation.

- Gray SIEM membership does not make a Gray SIEM mandatory.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u011`

> 5.4.2 GRAY SECURITY INFORMATION AND EVENT MANAGEMENT (SIEM)

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.
### Inner CA → Certification Authority

The provisioning text names the CA receiving Inner VPN Gateway certificate signing requests as the Inner CA.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.
### Outer CA → Certification Authority

The provisioning text names the CA receiving Outer VPN Gateway certificate signing requests as the Outer CA.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.
### Locally run CA → Certification Authority

The source explicitly presents locally run CAs as one CA option.

Basis: source_stated.

- The ontology does not declare local and enterprise CAs disjoint.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s002`

> If Certification Authorities (CAs) are part of the MSC Solution, each site has the option to use either locally run CAs that they manage and control or, where available, enterprise CAs that are not necessarily managed by the Solution Owner.
### Enterprise CA → Certification Authority

The source explicitly presents enterprise CAs as another CA option.

Basis: source_stated.

- The source says enterprise CAs are not necessarily managed by the Solution Owner. No Solution Component subclass is asserted for the generic CA category.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s002`

> If Certification Authorities (CAs) are part of the MSC Solution, each site has the option to use either locally run CAs that they manage and control or, where available, enterprise CAs that are not necessarily managed by the Solution Owner.
### Root CA → Certification Authority

The certificate-chain example names a Root CA certificate, preserving Root CA as a CA specialization.

Basis: source_interpretation.

- The example does not establish Root CA and Trust Anchor CA equivalence or a universal subclass relationship between them.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s005`

> The Security Administrator then installs the unique signed certificate and the certificate chain, which consists of the signing CA’s certificate and the Trust Anchor certificate (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s006`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s007`

> , Root CA certificate).
### Signing CA → Certification Authority

The certificate-chain passage names the signing CA as the authority whose certificate appears in the chain.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s005`

> The Security Administrator then installs the unique signed certificate and the certificate chain, which consists of the signing CA’s certificate and the Trust Anchor certificate (e.
### Trust Anchor CA → Certification Authority

MSC-VG-4 names the Trust Anchor CA certificate within the corresponding CA certificate chain.

Basis: source_interpretation.


`CSFC-MSC-1.3.0-4e40e3d83708:p038:u009`

> MSC-VG-4 When using certificate-based authentication, a unique device certificate must be loaded onto each VPN Gateway along with the corresponding CA certificate chain, to include the Trust Anchor CA certificate. T=O
### Key Server → MACsec Device

The glossary defines a Key Server as the MACsec Device designated to distribute Secure Association Keys.

Basis: source_stated.

- The class denotes a MACsec Device bearing the designated key-server role. No assertion makes every MACsec Device a Key Server.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u013.s001`

> Key Server – The MACsec Device designated as the one responsible for distribution Secure Association Keys to the other MACsec Device.
### Gray Network router → Router

The availability example identifies an ordinary router on each Gray Network as the device that selects an outer component.

Basis: source_stated.

- The edge does not impose general Solution Component requirements on the Gray Network router.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003`

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.
### Screening router → Router

The source describes a screening router as a router used to filter packets from Black Networks.

Basis: source_interpretation.

- The source excludes the screening router from the MSC Solution itself.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002`

> A screening router can be used to filter packets from Black Networks before they arrive at Outer Encryption Components.
### Customer Edge Router → Router

The source names a Customer Edge Router as an existing Black Network router that can provide the screening realization.

Basis: source_interpretation.

- The example does not make all Customer Edge Routers Screening Routers.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s003`

> The screening router could be part of an existing Black Network (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s004`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s005`

> , Customer Edge Router), or could be added between Outer Encryption Components and existing Black Network components.
### Authentication Server → Solution Component

MSC-SR-24 lists Authentication Servers among solution components. The extracted category is the MSC Authentication Server described in Section 5.8.

Basis: source_stated.


`CSFC-MSC-1.3.0-4e40e3d83708:p037:u003`

> MSC-SR-24 All solution components (Firewalls, VPN Gateways, Authentication Servers, etc) must use software and firmware signing algorithms in Table 2. O Optional
### Key Generation Solution → Solution Component

Section 5 includes a KGS among solution components for generating pre-shared CAKs.

Basis: source_interpretation.

- The edge identifies the KGS category in the source solution. It does not require the pre-shared-key option in every deployment.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003`

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u005.s001`

> Each Solution Component is described in more detail below.
### Key and certificate management component → Management component

The named Key and Certificate Management Components category specializes the extracted generic Management component category.

Basis: source_interpretation.

- The heading supplies the category, while detailed requirements are relocated to annexes. No device realization or CA membership follows from the heading alone.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u007`

> 5.9 KEY AND CERTIFICATE MANAGEMENT COMPONENTS

## Documented associations

### Red Administrative Workstation — administers — Inner Encryption Component

The source assigns maintenance, monitoring, and security control of the named target to the Red AW.

Basis: source_stated. The relationship is an annotation assertion.

- Annotation of the source assignment; no universal or existential property restriction is asserted.
- The target can comprise multiple deployed components. Presence and management exclusions remain in the source requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.
### Red Administrative Workstation — administers — Inner Firewall

The source assigns maintenance, monitoring, and security control of the named target to the Red AW.

Basis: source_stated. The relationship is an annotation assertion.

- Annotation of the source assignment; no universal or existential property restriction is asserted.
- The target can comprise multiple deployed components. Presence and management exclusions remain in the source requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.
### Red Administrative Workstation — administers — Red Management Services

The source assigns maintenance, monitoring, and security control of the named target to the Red AW.

Basis: source_stated. The relationship is an annotation assertion.

- Annotation of the source assignment; no universal or existential property restriction is asserted.
- The target can comprise multiple deployed components. Presence and management exclusions remain in the source requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.
### Gray Administrative Workstation — administers — Outer Encryption Component

The source assigns maintenance, monitoring, and security control of the named target to the Gray AW.

Basis: source_stated. The relationship is an annotation assertion.

- Annotation of the source assignment; no universal or existential property restriction is asserted.
- The target can comprise multiple deployed components. Presence and management exclusions remain in the source requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.
### Gray Administrative Workstation — administers — Gray Firewall

The source assigns maintenance, monitoring, and security control of the named target to the Gray AW.

Basis: source_stated. The relationship is an annotation assertion.

- Annotation of the source assignment; no universal or existential property restriction is asserted.
- The target can comprise multiple deployed components. Presence and management exclusions remain in the source requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.
### Gray Administrative Workstation — administers — Gray Management Services

The source assigns maintenance, monitoring, and security control of the named target to the Gray AW.

Basis: source_stated. The relationship is an annotation assertion.

- Annotation of the source assignment; no universal or existential property restriction is asserted.
- The target can comprise multiple deployed components. Presence and management exclusions remain in the source requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.
### Administrative Workstation — may be realized as — Virtual Machine

The source permits an AW to be a VM on a physical host/server dedicated to AW VMs.

Basis: source_stated. The relationship is an annotation assertion.

- Optional realization only. The host and VM are separate entities.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s001`

> AWs may be virtual machines (VMs) on a physical host/server that is dedicated to hosting AWs VMs.
### Administrative Workstation — may be realized as — Physical workstation

The source permits a physical-workstation AW and applies dedicated-function restrictions to that realization.

Basis: source_stated. The relationship is an annotation assertion.

- Optional realization only; no AW-to-physical-device subclass is asserted.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s003`

> Gray Management Services are physically connected to the Gray Firewall and include, at a minimum, a AW that can be a physical workstation or Virtual Machine (VM).

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004`

> If an AW is a physical workstation, then that workstation cannot also be used for provisioning, enrollment, certificate registrations, SIEM services, or for any non- CSfC functions.
### Host/server for AW virtual machines — hosts — Virtual Machine

The host/server houses VMs used as AWs.

Basis: source_stated. The relationship is an annotation assertion.

- The referenced VMs are AW VMs. The source prohibits cohosting the listed enrollment, provisioning, registration, and SIEM VMs.
- The annotation does not identify the physical host with the VM or AW.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s001`

> AWs may be virtual machines (VMs) on a physical host/server that is dedicated to hosting AWs VMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.
### MACsec Device — performs role — Supplicant

The source requires each MACsec Device to perform the supplicant function during the described authentication process.

Basis: source_stated. The relationship is an annotation assertion.

- The function is retained separately from its device bearer; no subtype is asserted.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s002`

> Authentication must be established between the MACsec device and the AS, where each MACsec device must perform the functions of a supplicant and authenticator.
### MACsec Device — performs role — Authenticator

The source requires each MACsec Device to perform the authenticator function during the described authentication process.

Basis: source_stated. The relationship is an annotation assertion.

- The function is retained separately from its device bearer and from the Authentication Server.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s002`

> Authentication must be established between the MACsec device and the AS, where each MACsec device must perform the functions of a supplicant and authenticator.
### Authentication Server — supports authentication of — MACsec Device

The MSC Authentication Server supports EAP-TLS mutual authentication between MACsec Devices.

Basis: source_stated. The relationship is an annotation assertion.

- The annotation does not identify the server with a supplicant or authenticator.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s001`

> The MSC AS is responsible for mutual authentication between MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s003`

> This communication is used throughout the EAP-TLS negotiation to mutually authenticate two MACsec Devices to pass MACsec traffic.
### Key Server — distributes keys to — MACsec Device

The designated Key Server distributes Secure Association Keys to the other MACsec Device.

Basis: source_stated. The relationship is an annotation assertion.

- The target is the peer in the applicable MACsec pair; no universal relation to every MACsec Device is asserted.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u013.s001`

> Key Server – The MACsec Device designated as the one responsible for distribution Secure Association Keys to the other MACsec Device.
### Root CA — example realization of role — Trust Anchor CA

The certificate-chain passage gives a Root CA certificate as an example Trust Anchor certificate.

Basis: source_interpretation. The relationship is an annotation assertion.

- Certificate-level example supports a role association only. It does not make every Root CA a Trust Anchor CA or equate the categories.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s005`

> The Security Administrator then installs the unique signed certificate and the certificate chain, which consists of the signing CA’s certificate and the Trust Anchor certificate (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s006`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s007`

> , Root CA certificate).
### Outer Encryption Component — may perform role — Perimeter device

An Outer Encryption Component may serve as a perimeter device when no Outer Firewall is present.

Basis: source_stated. The relationship is an annotation assertion.

- Conditional on the Outer Firewall being absent. No unconditional subclass is asserted.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s001`

> The Outer Encryption Component may be a perimeter device (if the Outer Firewall is not present) and more exposed to external attacks.
### Screening router — may be realized as — Customer Edge Router

The source gives an existing Customer Edge Router as an example screening-router realization.

Basis: source_stated. The relationship is an annotation assertion.

- Example only. No Customer Edge Router subclass of Screening Router is asserted.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s003`

> The screening router could be part of an existing Black Network (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s004`

> g.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s005`

> , Customer Edge Router), or could be added between Outer Encryption Components and existing Black Network components.
### Encapsulation/Decapsulation Device — may be realized as — Router

A separate standalone router or switch can provide the required encapsulation when the selected encryption component lacks the feature.

Basis: source_stated. The relationship is an annotation assertion.

- The standalone device is conditional. Encapsulation may instead be a feature of an encryption component.
- Source-scope issue REQ-I01 remains unresolved; the annotation does not settle universal Solution Component membership.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.
### Encapsulation/Decapsulation Device — may be realized as — Switch

A separate standalone router or switch can provide the required encapsulation when the selected encryption component lacks the feature.

Basis: source_stated. The relationship is an annotation assertion.

- The standalone device is conditional. Encapsulation may instead be a feature of an encryption component.
- Source-scope issue REQ-I01 remains unresolved; the annotation does not settle universal Solution Component membership.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.
### Red SIEM — collects logs from — Inner Encryption Component

The source assigns collection and analysis of the named target logs to the Red SIEM.

Basis: source_stated. The relationship is an annotation assertion.

- The association records the source configuration without asserting deployment or a property restriction.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.
### Red SIEM — collects logs from — Inner Firewall

The source assigns collection and analysis of the named target logs to the Red SIEM.

Basis: source_stated. The relationship is an annotation assertion.

- The association records the source configuration without asserting deployment or a property restriction.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.
### Red SIEM — collects logs from — Red Management Services

The source assigns collection and analysis of the named target logs to the Red SIEM.

Basis: source_stated. The relationship is an annotation assertion.

- The association records the source configuration without asserting deployment or a property restriction.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.
### Gray SIEM — collects logs from — Outer Encryption Component

The source assigns collection and analysis of the named target logs to the Gray SIEM.

Basis: source_stated. The relationship is an annotation assertion.

- The association records the source configuration without asserting deployment or a property restriction.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.
### Gray SIEM — collects logs from — Gray Firewall

The source assigns collection and analysis of the named target logs to the Gray SIEM.

Basis: source_stated. The relationship is an annotation assertion.

- The association records the source configuration without asserting deployment or a property restriction.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.
### Gray SIEM — collects logs from — Gray Management Services

The source assigns collection and analysis of the named target logs to the Gray SIEM.

Basis: source_stated. The relationship is an annotation assertion.

- The association records the source configuration without asserting deployment or a property restriction.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.
### Cross Domain Solution — supports — Red SIEM

An approved CDS can move Gray Network log data to a Red SIEM.

Basis: source_stated. The relationship is an annotation assertion.

- The source permits the Red-side alternative under the stated approval and annex conditions.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s003`

> These functions can also be performed on a Red SIEM using an approved CDS, as described in the CSfC Continuous Monitoring Annex.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s003`

> Implementations may employ a SIEM in the Gray Management Services for log management of Gray infrastructure components except where AOs use a CDS to move Gray Network log data to a Red SIEM.
### Red Management Services — comprises — Management component

The source describes Red Management Services as an aggregate of components.

Basis: source_stated. The relationship is an annotation assertion.

- Composition is recorded as an annotation. The aggregate is not made a subclass of its constituent Management component category.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u011.s002`

> Red Management Services are composed of a number of components that provide distinct security to the solution.
### Gray Management Services — comprises — Management component

The source describes Gray Management Services as an aggregate of components.

Basis: source_stated. The relationship is an annotation assertion.

- Composition is recorded as an annotation. The aggregate is not made a subclass of its constituent Management component category.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u008.s002`

> Gray Management Services are composed of multiple components that provide distinct security to the solution.
### Inner CA — supports certificate provisioning of — Inner VPN Gateway

The Security Administrator delivers the inner gateway CSR to the corresponding CA, which returns a signed certificate.

Basis: source_stated. The relationship is an annotation assertion.

- The relation records the certificate-based provisioning passage. No CA administration or device identity is inferred.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s003`

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s004`

> 509 certificate.
### Outer CA — supports certificate provisioning of — Outer VPN Gateway

The Security Administrator delivers the outer gateway CSR to the corresponding CA, which returns a signed certificate.

Basis: source_stated. The relationship is an annotation assertion.

- The relation records the certificate-based provisioning passage. No CA administration or device identity is inferred.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s003`

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s004`

> 509 certificate.
### CRL Distribution Point — provides revocation information to — VPN Gateway

The CDP hosts a CRL issued by a CA for VPN Gateways to download.

Basis: source_stated. The relationship is an annotation assertion.

- The relation describes the CDP function. No location or deployment cardinality is asserted.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u001.s001`

> CRL Distribution Point (CDP) – A web server that hosts a copy of a CRL issued by a CA for VPN Gateways to download (see CSfC Key Management Requirements Annex).
### Registration Authority — supports — Certification Authority

The RA collects, verifies, and submits certificate information under CA authorization.

Basis: source_stated. The relationship is an annotation assertion.

- The RA can comprise hardware, software, and personnel. The annotation does not type the RA as a physical device or equate it with the certificate registration component.

`CSFC-MSC-1.3.0-4e40e3d83708:p061:u005.s001`

> Registration Authority (RA) – An entity authorized by the CA to collect, verify, and submit information that is to be entered into public key certificates.

`CSFC-MSC-1.3.0-4e40e3d83708:p061:u005.s002`

> The term RA refers to hardware, software, and individuals that collectively perform this function.

## Inferences deliberately left unasserted

- **Every Router or Screening Router is a Solution Component.**: The Gray Network redundancy router has no CP security requirements, and the screening router is explicitly outside the MSC Solution.
- **Every Customer Edge Router is a Screening Router.**: The source supplies an example realization, which does not establish universal class inclusion.
- **Every Encapsulation/Decapsulation Device is a Solution Component.**: The source assigns duties to selected standalone encapsulators while another passage places the additional encapsulation step outside the solution boundary. V3.1 adopts the mandatory applicable device duties for the standalone case. That conditional interpretation is recorded in the Lean mapping; it does not assert universal class membership for every encapsulation realization.
- **Root CA and Trust Anchor CA are equivalent, or every Root CA is a Trust Anchor CA.**: The provisioning passage gives a Root CA certificate as an example Trust Anchor certificate. MSC-VG-4 names the Trust Anchor CA separately.
- **Locally run CA and Enterprise CA are disjoint classes.**: The source offers operating/management choices without establishing a universal logical partition of CA realizations.
- **Every CA is a Solution Component.**: The source conditionally says CAs can be part of an MSC Solution and permits enterprise CAs outside Solution Owner management. The general CA category is broader than the explicitly scoped component subclasses.
- **Every AW is a Solution Component.**: The source also mentions prohibited Black AW management. Positive MSC component membership is asserted for Red and Gray AW specializations only.
- **Supplicant, Authenticator, IKEv2 initiator, and IKEv2 responder are physical-device subclasses.**: The authentication passage describes performed functions. The IKE exchange passage describes protocol endpoint roles without defining physical-device categories or identifying the named illustrative participants.
- **AW is universally a Virtual Machine or Physical workstation, or the AW host is the AW.**: The source permits alternative realizations and distinguishes the physical host/server from hosted VMs.
- **Outer Encryption Component is universally a Perimeter device.**: The source makes the perimeter-device role conditional on Outer Firewall absence.
- **Red or Gray Management Services are subclasses of their Management components.**: The source describes aggregates composed of components. Composition does not imply subclass membership.
- **A device that administers another category inherits that category.**: The Red and Gray AW descriptions assign administration of encryption components, firewalls, and services. Those functional relationships do not establish class inclusion.
- **Registration Authority is equivalent to Certificate registration component or is a physical-device subclass.**: The RA definition collectively includes hardware, software, and people; the cohosting passages mention certificate registration functions without equating the terms.
- **Source aliases, example alternatives, and UI families define equivalent or disjoint OWL classes.**: Lexical aliases, examples, and navigation groups do not establish equality or a logical partition. No equivalence, disjointness, or exhaustive covering axiom is introduced.

## Regenerate and check

Run from the repository root:

```bash
python3 scripts/preprocess/run_csfc_preprocessing.py --stage ontology
python3 scripts/preprocess/preprocess_csfc_ontology.py --check
```

The pipeline uses explicit curated decisions for the pinned source. Changes to the role inventory or source index invalidate the decision hashes and require updating the hierarchy evidence.

An optional independent RDF parser check is available after installing the package in `scripts/preprocess/requirements-csfc-ontology.txt`:

```bash
python3 scripts/preprocess/preprocess_csfc_ontology.py --check --rdf-check
```

OWL semantics and RDF/XML mapping follow the [W3C OWL 2 Primer](https://www.w3.org/TR/owl2-primer/) and [OWL 2 Mapping to RDF Graphs](https://www.w3.org/TR/owl2-mapping-to-rdf/).
