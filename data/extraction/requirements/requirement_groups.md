# Requirement groups

Document: `CSFC-MSC-1.3.0-4e40e3d83708`. Source interpretation and scope questions remain unresolved. See the [plan audit](../validation/plan_audit/independent_review.md), [historical review](../validation/review/review.md), and [current status](../validation/final_status.json).

76 groups each target one encompassing top-level Lean theorem. No proofs are constructed. The source quotation and AI interpretation fields remain separate.

Threshold and Objective alternatives are choices within the stated applicability. Optional objectives are not unconditional requirements. Figures can illustrate satisfaction of selected clauses. Whole-solution implementation compliance requires further evidence.

<a id="rg-001"></a>

## RG-001: Applicable requirements and policy precedence

Original requirement IDs: MSC-SR-6.

**Applicability:** Every implementation and its selected capabilities; Solution Owner, customer, and Authorizing Official.

**Requirement strength and applicability:** Mandatory compliance; preferred Objective variants are encouraged; optional capabilities need not be selected.

**Single theorem target:** `msc_applicable_requirements_and_policy`

**AI interpretation for later formalization:** An MSC implementation provides the functions needed by its selected capabilities and satisfies every applicable threshold requirement or its stated objective alternative, together with applicable CNSS and local policy; CP requirements take precedence over conflicting local policy.

**Qualifications and exceptions:**

- The term security level includes classification, compartments, dissemination controls, and other controls.
- External CNSS policy content is not imported into the extraction.
- Feedback and conflict reporting in §2 use request/should wording, not table T=O requirement strength.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u007.s001` (PDF page 8):

> This CP provides high-level reference designs and corresponding configuration requirements that allow customers to select COTS products from the CSfC Components List, available on the CSfC web page (https://www.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u007.s002` (PDF page 8):

> nsa.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u007.s003` (PDF page 8):

> gov/resources/commercial-solutions-for-classified-program), for their MSC Solution and properly configure products to achieve a level of assurance sufficient to protect classified data while in transit.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u007.s004` (PDF page 8):

> As described in Section 10, customers must ensure that the components selected from the CSfC Components List provide the necessary functionality for the selected capabilities.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u007.s005` (PDF page 8):

> To successfully implement a solution based on this CP, all Threshold (T) Requirements, or the corresponding Objective (O) Requirements applicable to the selected capabilities, must be implemented, as described in Sections 9 & 11.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u002.s001` (PDF page 9):

> Please provide comments on usability, applicability, and/or shortcomings to your NSA Client Advocate and the MSC CP Maintenance Team at msc_cp@nsa.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u002.s002` (PDF page 9):

> gov.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u002.s003` (PDF page 9):

> MSC CP solutions must also comply with Committee on National Security Systems (CNSS) Policies and Instructions.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u002.s004` (PDF page 9):

> Any conflicts identified between this CP and the CNSS or local policy should be provided to the MSC CP Maintenance Team.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u010.s001` (PDF page 13):

> Depending on the needs of the customer implementing the solution, the MSC Solution is adaptable to support capabilities for multiple sites and/or multiple security levels.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u010.s002` (PDF page 13):

> If a customer does not have a need to support multiple sites or multiple security levels, then those elements need not be included as part of the implementation.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u010.s003` (PDF page 13):

> As explained in Section 8, any implementation of the MSC Solution must satisfy all of the applicable requirements specified in this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u009.s001` (PDF page 31):

> Multiple versions of a requirement may exist in this CP, with alternative versions designated as being either a Threshold requirement or an Objective requirement.

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u010.s001` (PDF page 31):

> • A Threshold (T) requirement specifies a feature or function that provides the minimal acceptable capability for the security of the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u011.s001` (PDF page 31):

> • An Objective (O) requirement specifies a feature or function that provides the preferred capability for the security of the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u012.s001` (PDF page 31):

> In general, when separate, Threshold and Objective versions of a requirement exist, the Objective requirement provides a higher degree of security for the solution than the corresponding Threshold requirement.

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u012.s002` (PDF page 31):

> However, in these cases meeting the Objective requirement may not be feasible in some environments or may require components to implement features that are not yet widely available.

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u012.s003` (PDF page 31):

> Solution Owners are encouraged to implement the Objective version of a requirement, but in cases where this is not feasible Solution Owners may implement the Threshold version of the requirement instead.

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u012.s004` (PDF page 31):

> These Threshold and Objective versions are mapped to each other in the “Alternatives” column.

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u012.s005` (PDF page 31):

> Objective requirements that have no related Threshold requirement are marked as “Optional” in the “Alternatives” column.

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u013.s001` (PDF page 31):

> In most cases there is no distinction between the Threshold and Objective versions of a requirement.

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u013.s002` (PDF page 31):

> In these cases, the “Threshold/Objective” column indicates that the Threshold equals the Objective (T=O).

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u014.s001` (PDF page 31):

> Requirements listed as Objective in this CP may become Threshold requirements in a future version of this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p031:u014.s002` (PDF page 31):

> Solution Owners are encouraged to implement Objective requirements where possible to facilitate compliance with future versions of this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u008` (PDF page 35):

> MSC-SR-6 All components must be properly configured in accordance with local policy and applicable U.S. Government guidance. In the event of conflict between the requirements in this CP and local policy, this CP takes precedence. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u003.s001` (PDF page 56):

> • The customer, possibly with support from an Integrator, instantiates a solution implementation that follows the NSA-approved CP.

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-6 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u002`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-002"></a>

## RG-002: Validated configuration and component modification

Original requirement IDs: MSC-PS-16.

**Applicability:** All Solution Components and customers or Integrators modifying them.

**Requirement strength and applicability:** Evaluated configuration and NIAP statement are required; pre-modification consultation is recommended.

**Single theorem target:** `msc_validated_configuration_and_modification`

**AI interpretation for later formalization:** Every Solution Component uses its NIAP-certified evaluated configuration, and an actual modification has the NIAP statement required by the CSfC PMO. Consultation with the vendor and NIAP continuity process is recommended for a proposed modification.

**Qualifications and exceptions:**

- Configuration changes outside the evaluated configuration and OEM-code changes, including code signing, are stated revalidation triggers.
- The source does not guarantee that a modification will retain certification.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u004.s001` (PDF page 8):

> While CSfC encourages industry innovation, trustworthiness of the components is paramount.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u004.s002` (PDF page 8):

> Customers and their Integrators are advised that modifying a NIAP-validated component in a CSfC solution may invalidate its certification and require a revalidation process.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u004.s003` (PDF page 8):

> To avoid delays, customers and Integrators who feel it is necessary to modify a component should engage the component vendor and consult NIAP through their Assurance Continuity Process, entitled “Assurance Continuity: Guidance for Maintenance and Re-evaluation” (https://www.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u004.s004` (PDF page 8):

> niapccevs.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u004.s005` (PDF page 8):

> org/Documents_and_Guidance/ccevs/scheme-pub-6.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u004.s006` (PDF page 8):

> pdf) to determine whether such a modification will affect the component’s certification.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u005.s001` (PDF page 8):

> In the case of a modification to a component, the NSA’s CSfC Program Management Office (PMO) requires a statement from NIAP that the modification does not alter the certification, or the security of the component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u005.s002` (PDF page 8):

> Modifications that trigger the revalidation process include, but are not limited to, configuring the component in a manner different from its NIAP-validated configuration and modifying the Original Equipment Manufacturer’s code (to include digitally signing the code).

- `CSFC-MSC-1.3.0-4e40e3d83708:p034:u008` (PDF page 34):

> MSC-PS-16 MSC Solution Components must be configured to use the NIAP-certified evaluated configuration. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-PS-16 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u003.s001`: Table 4.
- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u003.s002`: Product Selection (PS) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p034:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-003"></a>

## RG-003: Product eligibility on the CSfC Components List

Original requirement IDs: MSC-PS-1, MSC-PS-2, MSC-PS-3, MSC-PS-5, MSC-PS-17.

**Applicability:** Product selection for VPN Gateways, MACsec Devices, firewalls, ASs, and optional IPSs.

**Requirement strength and applicability:** T=O for listed mandatory device categories; MSC-PS-5 is Objective/Optional.

**Single theorem target:** `msc_listed_product_eligibility`

**AI interpretation for later formalization:** Selected VPN Gateways, MACsec Devices, firewalls, and Authentication Servers belong to their specified CSfC product lists; selecting the optional IPS capability requires the IPS list, and NIAP certification alone does not establish list eligibility.

**Qualifications and exceptions:**

- Eligibility depends on the listed product model and version.
- The CP prohibits protecting classified data with a single commercial product; the approved CP composition is required.
- Contacting a vendor to seek listing is encouragement, not evidence that the product is eligible.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u009.s001` (PDF page 10):

> The MSC CP instantiations are built using products from the CSfC Components List (see Section 9).

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u009.s002` (PDF page 10, 11):

> Customers who are concerned that their desired products are not yet on the CSfC Components List are encouraged to contact the appropriate vendors to encourage them to sign a Memorandum of Agreement with the NSA and commence evaluation against a NIAP-approved Protection Profile using the CSfC mandated selections that will enable them to be listed on the CSfC Components List.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u001.s002` (PDF page 11):

> NIAP Certification alone does not guarantee inclusion on the CSfC Components List.

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u005.s001` (PDF page 22):

> Each Solution Component is described in more detail below.

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u005.s002` (PDF page 22):

> The descriptions include information about the security provided by the components as evidence for why they are deemed necessary for the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u005.s003` (PDF page 22):

> Components are selected from the CSfC Components List in accordance with the Product Selection requirements of this CP (see Section 9).

- `CSFC-MSC-1.3.0-4e40e3d83708:p032:u023.s001` (PDF page 32):

> CPs provide architecture and configuration information that allows customers to select COTS products from the CSfC Components List for their solution and then to properly configure those products to achieve a level of assurance sufficient for protecting classified data.

- `CSFC-MSC-1.3.0-4e40e3d83708:p032:u023.s002` (PDF page 32):

> The CSfC Components List consists of eligible COTS products identified by model/version numbers that have met appropriate Protection Profile requirements.

- `CSFC-MSC-1.3.0-4e40e3d83708:p032:u024.s001` (PDF page 32):

> The CSfC Components List, contains the approved products for use in this solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p032:u024.s002` (PDF page 32):

> No single commercial product must be used to protect classified information.

- `CSFC-MSC-1.3.0-4e40e3d83708:p032:u024.s003` (PDF page 32):

> The only approved method for using COTS products to protect classified information in transit is through an approved CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u005` (PDF page 33):

> MSC-PS-1 The products used for any VPN Gateway must be chosen from the list of IPsec VPN Gateways on the CSfC Components List. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u006` (PDF page 33):

> MSC-PS-2 The products used for any MACsec Device must be chosen from the list of MACsec Ethernet Encryptors on the CSfC Components List. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u007` (PDF page 33):

> MSC-PS-3 The products used for any Firewalls must be chosen from the list of Traffic Filtering Firewalls on the CSfC Components List. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u009` (PDF page 33):

> MSC-PS-5 Intrusion Prevention Systems (IPSs) must be chosen from the list of IPSs on the CSfC Components List. O Optional

- `CSFC-MSC-1.3.0-4e40e3d83708:p034:u009` (PDF page 34):

> MSC-PS-17 Products used for the AS must be chosen from the list of ASs on the CSfC Components List. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u009.s001` (PDF page 59):

> Capability Package – The set of guidance provided by the NSA that describes recommended approaches to composing COTS solutions to protect classified information for a particular class of security problem.

- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u009.s002` (PDF page 59):

> CP instantiations are built using products selected from the CSfC Components List.

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-PS-1 | T=O | (blank) |
| MSC-PS-2 | T=O | (blank) |
| MSC-PS-3 | T=O | (blank) |
| MSC-PS-5 | O | Optional |
| MSC-PS-17 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u003.s001`: Table 4.
- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u003.s002`: Product Selection (PS) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u004`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p034:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-004"></a>

## RG-004: Independent product, operating-system, and cryptographic implementations

Original requirement IDs: MSC-PS-6, MSC-PS-7, MSC-PS-8, MSC-PS-10.

**Applicability:** Inner/Outer pairs and any Gray Firewall paired with Inner Encryption Components.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_implementation_diversity`

**AI interpretation for later formalization:** Inner and Outer Encryption Components satisfy manufacturer or NSA-approved product independence, use different operating systems beyond service-pack or version differences, and use independent cryptographic libraries; any Gray Firewall also satisfies the specified independence relationship with Inner Encryption Components.

**Alternative logic:**

- Manufacturer independence and NSA-determined same-manufacturer product independence are disjunctive choices, not cumulative requirements.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u010` (PDF page 33):

> MSC-PS-6 The Inner Encryption Component and the Outer Encryption Component must either; come from different manufacturers, where neither manufacturer is a subsidiary of the other; or be different products from the same manufacturer, where NSA has determined that the products meet the CSfC criteria for implementation independence. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u011` (PDF page 33):

> MSC-PS-7 The Inner Encryption Component and the Outer Encryption Component must not use the same Operating System. Differences between Service Packs and version numbers for a particular vendor's OS do not provide adequate diversity. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u012` (PDF page 33):

> MSC-PS-8 The cryptographic libraries used by the Inner Encryption Component and Outer Encryption Component must either; come from different manufacturers, where neither manufacturer is a subsidiary of the other; or be different libraries from the same manufacturer, where NSA has determined that the libraries meet the CSfC criteria for implementation independence. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u014` (PDF page 33, 34):

> MSC-PS-10 If Gray Firewalls are used, the Gray Firewalls and Inner Encryption Components must either; come T=O from different manufacturers, where neither manufacturer is a subsidiary of the other; or be two different products from the same manufacturer, where NSA has determined that the two products meet the CSfC criteria for implementation independence.

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-PS-6 | T=O | (blank) |
| MSC-PS-7 | T=O | (blank) |
| MSC-PS-8 | T=O | (blank) |
| MSC-PS-10 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u003.s001`: Table 4.
- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u003.s002`: Product Selection (PS) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u004`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p034:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-005"></a>

## RG-005: Physical separation of security components

Original requirement IDs: MSC-PS-11, MSC-PS-12.

**Applicability:** Inner/Outer Encryption Components; required Outer, Gray, and Inner firewalls.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_physically_distinct_security_components`

**AI interpretation for later formalization:** Inner and Outer Encryption Components use distinct physical devices, and the required firewalls and encryption components use separate devices with no device serving more than one of the specified functions.

**Qualifications and exceptions:**

- The prose includes a required Inner Firewall, while PS-12 enumerates Outer and Gray Firewalls.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u005.s001` (PDF page 23):

> As shown in Figure 2, the Outer Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u001.s002` (PDF page 24):

> The Outer Encryption Component, selected from the CSfC Components List, must be physically separate from the Outer Firewall and Gray Firewall.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s001` (PDF page 24):

> As shown in Figure 6, a standalone Gray Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component and Inner Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u006.s002` (PDF page 25):

> The Inner Encryption Component, selected from the CSfC Components List, must be physically separate from the Gray Firewall and Inner Firewall, if either are required by this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p034:u003` (PDF page 34):

> MSC-PS-11 The Inner Encryption Component and Outer Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p034:u004` (PDF page 34):

> MSC-PS-12 If an Outer Firewall and/or Gray Firewall is required, the Outer Firewall, Outer Encryption Component, Gray Firewall and Inner Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-PS-11 | T=O | (blank) |
| MSC-PS-12 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u003.s001`: Table 4.
- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u003.s002`: Product Selection (PS) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p034:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-006"></a>

## RG-006: Product Supply Chain Threat Assessment

Original requirement IDs: MSC-PS-15.

**Applicability:** Every selected component and the procuring organization.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_supply_chain_assessment`

**AI interpretation for later formalization:** Every selected component undergoes the organization’s AO-approved Product Supply Chain Threat Assessment so that mitigations are determined for its intended application.

**Qualifications and exceptions:**

- CNSSD 505 is a referenced external dependency; no assessment outcome is assumed.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p032:u025.s001` (PDF page 32, 33):

> Once the products for the solution are selected, each product must go through a Product Supply Chain Threat Assessment to determine the appropriate mitigations for the intended application of the component per the organization’s AO-approved Product Supply Chain Threat Assessment process (see CNSSD 505 Supply Chain Risk Management (SCRM) for additional guidance).

- `CSFC-MSC-1.3.0-4e40e3d83708:p034:u007` (PDF page 34):

> MSC-PS-15 Each component selected from the CSfC Components List must go through a Product Supply Chain Threat Assessment to determine the appropriate mitigations for the intended application of the component per the organization’s AO- approved Product Supply Chain Threat Assessment process (see CNSSD 505 SCRM for additional guidance). T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-PS-15 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u003.s001`: Table 4.
- `CSFC-MSC-1.3.0-4e40e3d83708:p033:u003.s002`: Product Selection (PS) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p034:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-007"></a>

## RG-007: Two independent encryption layers and allowed tunnel pairings

Original requirement IDs: Prose-only.

**Applicability:** Protected data-plane packets or frames crossing the Black Network and directly communicating sites.

**Requirement strength and applicability:** Architectural requirements and permitted alternatives; Table 1 enumerates four permitted layer combinations.

**Single theorem target:** `msc_nested_layer_protection`

**AI interpretation for later formalization:** Every protected data flow across the untrusted Black Network passes through independent Inner then Outer encryption and the reverse decryption sequence using the IPsec/MACsec pairings in Table 1; each layer terminates on its matching encryption components, and Outer MACsec configurations are limited to point-to-point use.

**Qualifications and exceptions:**

- Figures illustrate arrangements and do not prove compliance.
- The blanket statement about all Black-Network communications is qualified elsewhere by permitted control-plane traffic; it must not erase those explicit exceptions.

Open issues: REQ-I12.

Scope or resolved-interpretation notes: REQ-I14.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u005.s001` (PDF page 10):

> The MSC Solution uses two nested, independent encryption tunnels to protect the confidentiality and integrity of data as it transits the untrusted network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u005.s002` (PDF page 10):

> The two encryption tunnels protecting a data flow can use either Internet Protocol Security (IPsec) generated by a Virtual Private Network (VPN) Gateway or Media Access Control Security (MACsec) generated by a MACsec Device.

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u005.s003` (PDF page 10):

> VPN Gateways and MACsec Devices are implemented as part of the network infrastructure.

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u006.s001` (PDF page 10):

> Throughout this CP, the term “Encryption Component” refers generically to either a VPN Gateway or a MACsec Device.

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u006.s002` (PDF page 10):

> “Inner Encryption Component” refers to the component that terminates the Inner layer of encryption and “Outer Encryption Component” refers to the component that terminates the Outer layer of encryption.

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s001` (PDF page 10):

> As shown in Figure 1, before being sent across the untrusted network, each packet or frame of classified data is encrypted twice; first by an Inner Encryption Component, and then by an Outer Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s002` (PDF page 10):

> At the other end of the data flow, the received packet is correspondingly decrypted twice; first by an Outer Encryption Component, and then by an Inner Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u006.s001` (PDF page 12):

> Data plane traffic is classified information, encrypted or unencrypted, that passes through the MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u006.s002` (PDF page 12):

> The MSC Solution exists to encrypt and decrypt data plane traffic.

- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u006.s003` (PDF page 12):

> All data plane traffic within the Gray and Black Networks is encapsulated within the IPsec’s Encapsulating Security Payload (ESP) and/or MACsec protocols.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s001` (PDF page 14):

> There are two layers of encryption tunnels between any pair of sites communicating directly with one another; one encryption tunnel between their Outer Encryption Components, and a second encryption tunnel between their Inner Encryption Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s002` (PDF page 14):

> Each set of Inner or Outer Encryption Components can provide encryption using either IPsec or MACsec.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s001` (PDF page 18):

> Each layer of the MSC Solution can use either an IPsec tunnel or MACsec tunnel.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s002` (PDF page 18):

> An IPsec tunnel is established between VPN Gateways.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s003` (PDF page 18):

> A MACsec tunnel is established between MACsec Devices.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s004` (PDF page 18):

> Table 1 identifies four different layering options provided by this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s005` (PDF page 18):

> For configurations 2 and 4 which use an outer MACsec tunnel these solutions would only be point to point solutions instead of a multi-site solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s001` (PDF page 22):

> In the high-level designs discussed in Section 4.

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s002` (PDF page 22):

> 2, all communications flowing across a Black Network are protected by at least two layers of encryption, implemented using IPsec tunnels generated by VPN Gateways or MACsec tunnels generated by MACsec Devices.

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003` (PDF page 22):

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u011`: [Image-only figure; see source location and network artifact.]
- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u008.s001`: Figure 1.
- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u008.s002`: Two Encryption Tunnels Protect Data Across an Untrusted Network
- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s001`: Red data consists of unencrypted classified data.
- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u007.s001`: Gray data is classified data that has been encrypted once.
- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s001`: Black data is classified data that has been encrypted twice.
- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u001.s001`: Table 1.
- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u001.s002`: Layering Options
- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u002`: Configuration Inner Outer Tunnel
- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u003`: 1 IPsec IPsec
- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u004`: 2 IPsec MACsec
- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u005`: 3 MACsec IPsec
- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u006`: 4 MACsec MACsec
- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u008.s001`: Black Network – A network that contains classified data that has been encrypted twice.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u004.s001`: Encryption Component – Either a VPN Gateway or a MACsec Device.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u008.s001`: Gray Network – A network that contains classified data that has been encrypted once.
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u004.s001`: Red Network – A network that contains unencrypted classified data.

<a id="rg-008"></a>

## RG-008: Connectivity restricted to the same security level

Original requirement IDs: MSC-VG-15.

**Applicability:** Red Networks, included unclassified networks, Inner Encryption Components, and shared Outer infrastructure.

**Requirement strength and applicability:** Mandatory separation and conditional permission to share infrastructure.

**Single theorem target:** `msc_security_level_connectivity`

**AI interpretation for later formalization:** Red Networks communicate through MSC only within the same security level, and Inner VPN Gateways authenticate and establish tunnels only for Red Networks of that level; multiple levels can share Outer infrastructure while each Red or included unclassified network retains its own Inner Encryption Component and applicable Red-network protections.

**Qualifications and exceptions:**

- Security level is richer than a classification label.
- No limit on the number of levels is stated; Outer MACsec remains point-to-point under RG-007.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u004.s001` (PDF page 10):

> This CP describes a general MSC Solution to protect classified information as it travels across either an untrusted Network, or a different security level network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u004.s002` (PDF page 10):

> The solution supports interconnecting two or more networks operating at the same security level via encryption tunnels, where the security level encompasses the classification level, list of compartments, dissemination controls, and other such controls over information.

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u004.s003` (PDF page 10):

> The solution provides sufficient flexibility to be applicable to many use cases of MSC implementations.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s002` (PDF page 11):

> The Red Network is logically located behind an Inner Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s003` (PDF page 11):

> The networks connected to one another through the MSC Solution are Red Networks.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s004` (PDF page 11):

> Red Networks may only communicate with one another through the MSC Solution if the networks operate at the same security level.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s001` (PDF page 15):

> A single implementation of the MSC Solution may support Red Networks of different security levels.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s002` (PDF page 15):

> The MSC Solution provides secure connectivity between the Red Networks within each security level while preventing Red Networks of different security levels from communicating with one another.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s003` (PDF page 15):

> This enables a customer to use the same physical infrastructure to carry traffic from multiple networks.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s004` (PDF page 15):

> Although each Red Network requires its own Inner Encryption Component, a site may use a single Outer Encryption Component to encrypt and transport traffic that has been encrypted by Inner Encryption Components of varying security levels.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s001` (PDF page 16):

> There is no limit to the number of different security levels that an MSC Solution may support.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s002` (PDF page 16):

> An unclassified network can also be included behind the Outer Encryption Component but must be behind its own Inner Encryption Component and meet the requirements in this CP as if it was a Red Network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u003.s001` (PDF page 17):

> A single implementation of the MSC Solution may support Red Networks of different security levels, to include unclassified networks.

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u003.s002` (PDF page 17):

> The MSC Solution provides secure connectivity between the Red Networks within each security level while preventing Red Networks of different security levels from communicating with one another.

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u003.s003` (PDF page 17):

> This enables a customer to use the same infrastructure to carry traffic from multiple networks.

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u007` (PDF page 39):

> MSC-VG-15 Inner VPN Gateways must only authenticate and establish an IPsec tunnel with one another if their Red Networks operate at the same security level as defined in this CP. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-VG-15 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s001`: Table 8.
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s002`: VPN Gateway (VG) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u009.s001`: Security Level – The combination of classification level, list of compartments, dissemination controls, and other controls applied to the information within a network.

<a id="rg-009"></a>

## RG-009: Gray-network control and classification boundary

Original requirement IDs: Prose-only.

**Applicability:** Solution Owner, classification authority, Red/Gray Networks and exposed Gray metadata.

**Requirement strength and applicability:** Architectural ownership condition and explicit prohibition on implementing the design under the stated classification determination.

**Single theorem target:** `msc_gray_network_classification_boundary`

**AI interpretation for later formalization:** The Solution Owner or a trusted third party controls the Red and Gray Networks, and the MSC design is inapplicable if the classification authority classifies exposed Gray information that the design does not protect with two encryption layers.

**Qualifications and exceptions:**

- The text distinguishes singly encrypted classified payload from Gray information such as addresses; the exact classification decision remains external.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s005` (PDF page 11):

> Red Networks are under the control of the Solution Owner or a trusted third party using a Red Administrative Workstation (AW).

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u007.s001` (PDF page 11):

> Gray data is classified data that has been encrypted once.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u007.s002` (PDF page 11):

> Gray Networks are composed of Gray data and Gray Management Services.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u007.s003` (PDF page 11):

> Gray Networks are under the physical and logical control of the Solution Owner or a trusted third party.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u008.s001` (PDF page 11):

> The Gray Network is physically treated as a classified network even though all classified data is singly encrypted.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u008.s002` (PDF page 11):

> If a Solution Owner’s classification authority determines that the data on a Gray Network is classified, perhaps by determining the Internet Protocol (IP) addresses used on the Gray Network interfaces are classified at some level, then the MSC Solution described in this CP cannot be implemented.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u008.s003` (PDF page 11):

> The MSC Solutions are not designed to ensure that such information will be afforded two layers of protection.

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u008.s001`: Gray Network – A network that contains classified data that has been encrypted once.

<a id="rg-010"></a>

## RG-010: Independently managed site administration and trust

Original requirement IDs: Prose-only.

**Applicability:** Sites choosing independent management and their certificate or CAK trust relationships.

**Requirement strength and applicability:** Conditional design requirements and permission to use locally managed or enterprise CAs.

**Single theorem target:** `msc_independently_managed_sites`

**AI interpretation for later formalization:** In the independently managed design, each site administers its own Encryption Components without management traffic crossing the Black Network, maintains interoperable peers, and provides the appropriate cross-site CA signing and revocation information or shared CAK for each communicating encryption relationship.

**Qualifications and exceptions:**

- The AS wording “both Gray and/or Red Networks” is retained without silently resolving its ambiguity; RG-024 includes the one-site AS table constraint.
- Cross-site trust does not override per-layer or per-security-level CA separation.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u012.s001` (PDF page 13):

> Sites in the solution may be managed independently of one another or may be remotely managed from a central site.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u004.s001` (PDF page 14):

> There is no limit to the number of sites that may be incorporated into a single MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s001` (PDF page 14):

> For independently managed sites, each site performs the administration of its own Encryption Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s002` (PDF page 14):

> If Certification Authorities (CAs) are part of the MSC Solution, each site has the option to use either locally run CAs that they manage and control or, where available, enterprise CAs that are not necessarily managed by the Solution Owner.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s003` (PDF page 14):

> Each site needs to ensure that the Encryption Components selected interoperate with those at the other sites.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s001` (PDF page 14):

> When using independent managed sites, management traffic will not cross the Black Network, encrypted or unencrypted.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s002` (PDF page 14):

> In the MSC Solution, Encryption Components at each site using public key certificates need to have the signing certificates and revocation information for the corresponding CAs used by the other sites.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s003` (PDF page 14):

> This high-level design requires cooperation between the various sites in the solution to ensure that all CAs used by each site are trusted at all the other sites.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s004` (PDF page 14):

> Similarly, MACsec Devices using a Connectivity Association Key (CAK) need to have the same CAK used by the other site in the MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s005` (PDF page 14):

> If MACsec Devices are authenticating using certificates, the authentication server (AS) must not connect to both Gray and/or Red Networks.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u008.s001` (PDF page 14):

> This model has the advantage of allowing communication between larger organizations that have a need to share information while maintaining independence.

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u009.s001` (PDF page 14):

> Note that while Figure 3 shows only two sites, this solution can scale to include numerous sites, with each additional site having the same design as that in Figure 3.

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u001.s001`: Figure 3 shows two Red Networks at different sites that operate at the same security level and connected to one another through the MSC Solution.
- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u001.s002`: Here, each Red Network has two Encryption Components associated with it; an Inner Encryption Component connected to the Red Network, and an Outer Encryption Component between the Inner Encryption Component and the Black Network.
- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u011`: [Image-only figure; see source location and network artifact.]
- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u003.s001`: Figure 3.
- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u003.s002`: MSC Solution Connecting Two Independently Managed Sites
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u010.s001`: Independently Managed Site – A site within a MSC Solution where Solution Components are locally managed and that does not remotely manage other sites’ Solution Components.

<a id="rg-011"></a>

## RG-011: Central management, CA placement, and intersite protection

Original requirement IDs: Prose-only.

**Applicability:** Centrally managed sites, central administrators, CAs, AS, and intersite management traffic.

**Requirement strength and applicability:** Conditional design requirements; enterprise-CA use is recommended; a PSK-authenticated layer may omit its CA.

**Single theorem target:** `msc_centrally_managed_sites`

**AI interpretation for later formalization:** In the central-management design, the central personnel administer and key the sites with interoperable components, separate Inner and Outer CA functions, central CAs and an AS for certificate-based MACsec, and the required protection of management traffic across sites; enterprise CAs are preferred when available.

**Qualifications and exceptions:**

- Central Gray management depends on the external CSfC Enterprise Gray Implementation Requirements Annex.
- The prose states at least two CAs and then allows a PSK layer without a CA; the exception remains explicit.
- At least two encryption layers protect management traffic on the Black Network; local exceptions are in RG-046.

Open issues: REQ-I03, REQ-I12.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s001` (PDF page 15):

> As shown in Figure 4, if remote management is used, personnel at a single geographic site administer and perform keying and device management for all the sites included in the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s002` (PDF page 15):

> In this case, because the administration is done by one group of Security Administrators, CA Administrators, and Key Generation Solution Administrators (see Section 12), they ensure the interoperability of each site as new sites are added.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003` (PDF page 15):

> At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s004` (PDF page 15):

> If available, enterprise CAs should be used.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005` (PDF page 15):

> If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s001` (PDF page 15):

> Because the central management site manages the Encryption Components at the other sites over the network, encryption is used to logically separate data and management traffic as it passes between sites.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s002` (PDF page 15):

> Central Management of the Gray Network must be done in accordance with the CSfC Enterprise Gray Implementation Requirements Annex.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s003` (PDF page 15):

> Red management traffic is encrypted before being routed through the Inner and Outer Encryption Components to another site.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s004` (PDF page 15):

> As a result, all management traffic between sites is encrypted at least twice before traversing the Black Network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s005` (PDF page 15):

> See the CSfC Enterprise Gray Implementation Requirements Annex for additional details and requirements.

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u005.s001` (PDF page 15):

> While Figure 4 shows only two sites, this solution can scale to include numerous sites, with each additional site having the same high-level design as the remotely managed site.

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u009`: [Image-only figure; see source location and network artifact.]
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u003.s001`: Figure 4.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u003.s002`: MSC Solution Connecting a Central Management Site and a Remote Site
- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u010.s001`: Central Management Site – A site within a MSC Solution that is responsible for remotely managing the Solution Components located at other sites.
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u007.s001`: Remote Site – A site within a MSC Solution where Solution Components are remotely managed by a Central Management Site.

<a id="rg-012"></a>

## RG-012: Separate authentication and management for security levels

Original requirement IDs: Prose-only.

**Applicability:** Inner Encryption Components and management services for multiple Red security levels.

**Requirement strength and applicability:** Mandatory separation across levels; additional same-level security is permitted.

**Single theorem target:** `msc_security_level_key_and_management_separation`

**AI interpretation for later formalization:** Distinct Red security levels have separate CAs, CAKs, and management devices for their Inner Encryption Components so that components at different levels cannot mutually authenticate; same-level designs may elect the additional filtering controls described for multiple levels.

**Qualifications and exceptions:**

- CA and CAK clauses apply to the chosen authentication method, not to a requirement to deploy both methods.
- Figure 5 is an illustration and does not establish complete compliance.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s001` (PDF page 16):

> MSC Solutions supporting multiple security levels may include independently managed sites (see Section 4.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s002` (PDF page 16):

> 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s003` (PDF page 16):

> 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s004` (PDF page 16):

> 1) or centrally managed sites (see Section 4.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s005` (PDF page 16):

> 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s006` (PDF page 16):

> 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s007` (PDF page 16):

> 2).

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s008` (PDF page 16):

> Given both cases, separate CAs, CAKs, and management devices are needed to manage the Inner Encryption Components at each security level.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s009` (PDF page 16):

> For example, Figure 5 shows a Central Management Site (Site A) and a Remote Site (Site B), but network 1 and network 2 each has its own Red Management Services, which prevents the Inner Encryption Components of the two networks from being able to authenticate with one another.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s001` (PDF page 16):

> When Red Networks that operate at the same security level are implemented, the cryptographic separation provided by the Inner Encryption Components is sufficient to protect against unintended data flows between the two networks.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s002` (PDF page 16):

> Two Inner Encryption Components for networks of different security levels will be unable to mutually authenticate with each other because they trust different CAs that do not have a trust relationship with one another or they use different CAKs that will not provide authentication.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s003` (PDF page 16):

> This difference prevents the establishment of an encryption tunnel between the two components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s001` (PDF page 16):

> Figure 5 shows an MSC Solution between two sites that carries traffic between two Red Networks; a Secret U.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s002` (PDF page 16):

> S.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s003` (PDF page 16):

> -only Network (Network 1), and a Secret U.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s004` (PDF page 16):

> S.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s005` (PDF page 16):

> -only Network (Network 2).

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u005.s006` (PDF page 16):

> Because Network 1 and Network 2 both operate at the same security level, their singly-encrypted traffic can be carried over the Gray Network without any additional security controls in place.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u006.s001` (PDF page 16):

> Although not required by this CP, a Solution Owner may choose to implement the additional security described in Section 4.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u006.s002` (PDF page 16):

> 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u006.s003` (PDF page 16):

> 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p016:u006.s004` (PDF page 16):

> 2 to provide additional protection against unintended data flows between Red Networks at the same security level.

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u009.s001`: Security Level – The combination of classification level, list of compartments, dissemination controls, and other controls applied to the information within a network.

<a id="rg-013"></a>

## RG-013: Gray Firewalls on all paths needing level separation

Original requirement IDs: MSC-SR-7, MSC-SR-8.

**Applicability:** Multi-level Gray networks, AWs, locally run CAs, CDP/OCSP services, and Inner/Outer Encryption Components.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_gray_firewall_path_coverage`

**AI interpretation for later formalization:** All Gray-network paths between Inner Encryption Components for different security levels, and the specified paths between Gray management services and lower-level Inner components, include Gray Firewalls that block the prohibited flows; Outer filtering remains required even when standalone Gray Firewalls are present.

**Qualifications and exceptions:**

- Gray AWs and locally run CAs are grouped with the highest Red security level in §4.2.2.2.
- SR-8 refers to different security levels while the prose specifies lower-than-highest targets; both scopes are retained.
- The word “typically” in §5.3 does not cancel the all-path requirements.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u004.s001` (PDF page 17):

> For Red Networks of different security levels, the cryptographic separation of their traffic on a Gray Network, as described in Section 4.

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u004.s002` (PDF page 17):

> 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u004.s003` (PDF page 17):

> 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u004.s004` (PDF page 17):

> 1, is still present.

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u004.s005` (PDF page 17):

> However, because the consequences of an unintended data flow between different security levels are more severe than of one with a single security level, an additional mechanism is necessary to prevent such a flow from occurring.

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u005.s001` (PDF page 17):

> This CP uses packet filtering within Gray Networks as an additional mechanism to prevent data flows between networks of different security levels.

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u005.s002` (PDF page 17):

> Any physical path through a Gray Network between multiple Inner Encryption Components supporting Red Networks of different security levels must include at least one filtering component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u005.s003` (PDF page 17):

> This filtering component restricts the traffic flow based primarily on the Gray Network source and destination addresses, and only allows a packet through if the source and destination components intend to communicate with one another and drops the packet if they are not.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s001` (PDF page 18):

> Additionally, filtering components are included between the components used for management of the Gray Networks themselves (namely, AWs and locally run CAs) and Inner Encryption Components that support Red Networks of a lower security level than the Red Network with the highest security level supported by the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s002` (PDF page 18):

> In other words, AWs and locally run CAs on Gray Networks are treated as, and grouped with, the Inner Encryption Component for the Red Network with the highest security level.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s001` (PDF page 18):

> One or more Gray Firewalls must be included in the Gray Network to perform filtering.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s002` (PDF page 18):

> Standalone Gray Firewalls have been placed at each site between the Inner Encryption Components and the Outer Encryption Component; these Gray Firewalls are responsible for dropping packets between Inner Encryption Components of different security levels.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u003.s001` (PDF page 18):

> Figure 6.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u003.s002` (PDF page 18):

> MSC Solution for Networks at Different Security Levels

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u004.s001` (PDF page 18):

> Figure 6 also shows an example placement of Gray Firewalls, as long as any path between Inner Encryption Components for networks of different security levels includes a Gray Firewall.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s001` (PDF page 18):

> Including one or more standalone Gray Firewalls in a solution does not remove the requirement to perform the filtering on the Outer Encryption Component as well.

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s002` (PDF page 18):

> Outer Encryption Components are uniquely positioned to block traffic between Inner Encryption Components supporting Red Networks of different security levels when one of those Inner Encryption Components is located at a different site.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s001` (PDF page 24):

> The Gray Firewall is located between the Outer Encryption Component and Inner Encryption Component(s).

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s002` (PDF page 24):

> As described in Section 4.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s003` (PDF page 24):

> 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s004` (PDF page 24):

> 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s005` (PDF page 24):

> 2, an MSC Solution that supports multiple Red Networks of different security levels must include one or more Gray Firewalls.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s006` (PDF page 24):

> The Gray Firewall blocks any packets sent between Inner Encryption Components for Red Networks of different security levels.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s007` (PDF page 24):

> A Gray Firewall also blocks any packets sent between management components on the Gray Network and Inner Encryption Components for Red Networks that operate at a security level other than the highest security level of data protected by the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s008` (PDF page 24):

> Gray Firewalls are physically protected as classified devices.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s002` (PDF page 24):

> A Gray Firewall would typically only be used in solutions where the physical design of the Gray Network includes paths between Inner Encryption Components for Red Networks of different security levels that do not pass through the Outer Encryption Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s003` (PDF page 24):

> Effectively, each Gray Firewall is another instance of the Gray Network filtering performed by the Outer Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u009` (PDF page 35):

> MSC-SR-7 All physical paths within a Gray Network between Inner Encryption Components for Red Networks of different security levels must include a Gray Firewall. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u010` (PDF page 35):

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-7 | T=O | (blank) |
| MSC-SR-8 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u009`: [Image-only figure; see source location and network artifact.]
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u002`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u009.s001`: Gray Firewall – A traffic filtering firewall placed on the Gray Network to provide additional separation between flows of singly-encrypted data of different security levels.
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u009.s001`: Security Level – The combination of classification level, list of compartments, dissemination controls, and other controls applied to the information within a network.

<a id="rg-014"></a>

## RG-014: Gray addressing supports security-level filtering

Original requirement IDs: Prose-only.

**Applicability:** Address assignment on Gray interfaces and rules on Outer Encryption Components and Gray Firewalls.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_gray_addressing_for_level_filtering`

**AI interpretation for later formalization:** Gray addresses and address ranges distinguish security levels so that the specified packet filters can admit only intended same-level Inner peers and reject cross-level paths.

**Qualifications and exceptions:**

- The §5.2 sentence says to prevent same-security-level communication, conflicting with the same-level allowances elsewhere; the theorem target is provisional and the conflict remains open.

Open issues: REQ-I02.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s001` (PDF page 17):

> When multiple security levels are used, it is critical to enforce proper IP address assignment and firewall rule sets.

- `CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s002` (PDF page 17):

> The IP address assigned must be unique to that security level such that each network’s Inner Encryption Component is only able to send and receive traffic to its respective Inner Encryption Component at the other site.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s001` (PDF page 23):

> Outer Encryption Components are also responsible for filtering traffic on its Gray Network interfaces to prevent Inner Encryption Components for networks of the same security level from being able to send packets to one another.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s002` (PDF page 23):

> Since this filtering is primarily based on the source and destination addresses in the packet on a Gray Network, the Gray Network itself must use an addressing scheme that supports the necessary filtering (such as using separate address ranges for the Gray interfaces of Inner Encryption Components supporting each Red Network).

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s001`: Including one or more standalone Gray Firewalls in a solution does not remove the requirement to perform the filtering on the Outer Encryption Component as well.
- `CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s002`: Outer Encryption Components are uniquely positioned to block traffic between Inner Encryption Components supporting Red Networks of different security levels when one of those Inner Encryption Components is located at a different site.
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u009.s001`: Security Level – The combination of classification level, list of compartments, dissemination controls, and other controls applied to the information within a network.

<a id="rg-015"></a>

## RG-015: MACsec encapsulation and standalone encapsulator obligations

Original requirement IDs: MSC-MD-13.

**Applicability:** Inner MACsec Devices, Outer Encryption Components, and any standalone encapsulation/decapsulation router or switch.

**Requirement strength and applicability:** Encapsulation is required; any AO-approved encapsulation protocol is permitted. The extent of standalone-device obligations is disputed by the source.

**Single theorem target:** `msc_macsec_encapsulation`

**AI interpretation for later formalization:** Inner MACsec traffic, and MACsec traffic crossing an IP network, receives encapsulation before Outer encryption without premature MACsec decryption; an unsupported built-in encapsulation feature requires a correctly connected standalone encapsulator, and its applicable Solution Component obligations are resolved explicitly from the conflicting source passages.

**Qualifications and exceptions:**

- §4.2.3 and §5.5 require all Solution Component requirements, but the paragraph below Figure 8 places the step outside the boundary and highly recommends DM/port filtering.
- MSC-MD-13 explicitly requires Solution Component treatment for §11.1.
- No exemption or precedence rule is invented. The final formal target needs a documented interpretation decision.

Open issues: REQ-I01.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u007.s001` (PDF page 19):

> MACsec was designed to provide hop-to-hop security within a Local Area Network (LAN).

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u007.s002` (PDF page 19):

> As MACsec- encrypted traffic arrives at an interface, it is typically decrypted, examined, and re-encrypted after determining its destination.

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s001` (PDF page 19):

> The MACsec-encrypted traffic needs to be encapsulated if the MACsec Device is the first layer of encryption in the MSC Solution or if the MACsec-encrypted traffic needs to traverse an IP-based network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s002` (PDF page 19):

> Encapsulation creates a new packet by adding a new header, and sometimes trailer, to the MACsec-encrypted traffic.

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s003` (PDF page 19):

> Encapsulation ensures the MACsec-encrypted traffic is not decrypted prior to reaching its destination and ensures the second layer of encryption can be applied.

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s001` (PDF page 19):

> In some commercial MACsec Devices, encapsulation can be applied on the internal interface by creating a pseudowire (see Figure 7), which emulates a point-to-point connection.

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s002` (PDF page 19):

> If this feature is not supported, a standalone device is needed to encapsulate the MACsec-encrypted data (see Figure 8).

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s003` (PDF page 19):

> If using a standalone device, the internal interface will be connected to the Inner MACsec Device and the external interface will be connected to the Outer Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s004` (PDF page 19):

> Since this device resides in the Gray Network, all requirements for Solution Components must be implemented.

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u010.s001` (PDF page 19):

> This CP does not mandate the use of a specific protocol for encapsulation.

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u010.s002` (PDF page 19):

> Options include, but are not limited to, Layer 2 Tunneling Protocol version 3, and Ethernet over Multiprotocol Label Switching.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s001` (PDF page 20):

> When the Inner Encryption Component is a MACsec Device the traffic requires additional encapsulation before it is passed through the Outer Encryption Component to the Black Network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s002` (PDF page 20):

> This additional step falls outside the boundary of the MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s003` (PDF page 20):

> However, it is highly recommended to apply the general device management (DM) and port filtering requirements for Solution Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001` (PDF page 25):

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s002` (PDF page 25):

> Some VPN Gateways and MACsec Devices allow this encapsulation to occur on the incoming interface, prior to encrypting traffic for the outer tunnel.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003` (PDF page 25):

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s004` (PDF page 25):

> Any AO-approved encapsulation protocol may be used.

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u004` (PDF page 42):

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-MD-13 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u013`: [Image-only figure; see source location and network artifact.]
- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u011.s001`: Figure 7.
- `CSFC-MSC-1.3.0-4e40e3d83708:p019:u011.s002`: Encapsulating MACsec on an Internal Interface
- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u011`: [Image-only figure; see source location and network artifact.]
- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u001.s001`: Figure 8.
- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u001.s002`: Encapsulating MACsec with a Separate Device
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s001`: Table 12.
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s002`: MACsec Device (MD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u003.s001`: Encapsulation – Packaging a packet/frame into a new packet/frame by adding a header and sometimes a trailer.
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u002.s001`: Pseudowire – Emulation of a point-to-point connection.

<a id="rg-016"></a>

## RG-016: Permitted MACsec clear VLAN tags and XPN

Original requirement IDs: Prose-only.

**Applicability:** MACsec Devices supporting clear VLAN ID tags or extended packet numbers.

**Requirement strength and applicability:** Conditional permissions, not requirements to enable the features.

**Single theorem target:** `msc_macsec_optional_clear_vlan_and_xpn`

**AI interpretation for later formalization:** A MACsec implementation may expose the VLAN ID tag and may use XPN when its device supports those features, while retaining the other applicable MACsec protection requirements.

**Qualifications and exceptions:**

- The source discusses high speeds of 100 GB/s or higher; the extracted permission does not impose a new speed threshold.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u003.s001` (PDF page 20):

> In the current MACsec standard, the entire frame is encrypted with the exception of the source and destination addresses.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u003.s002` (PDF page 20):

> Institute of Electrical and Electronics Engineers (IEEE) 802.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u003.s003` (PDF page 20):

> 1AE-2018 provides the option of moving the Virtual Local Area Network (VLAN) identification (ID) tag out of the encrypted payload and into the clear in the header.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u003.s004` (PDF page 20):

> The benefits of moving the VLAN ID tag into the clear include service multiplexing (i.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u003.s005` (PDF page 20):

> e.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u003.s006` (PDF page 20):

> , multiple point-to-point or multipoint services existing on a single physical interface) and providing quality of service across a Service Provider’s network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u003.s007` (PDF page 20):

> If supported in the MACsec Device, this CP allows VLAN ID tags to be used in the clear.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u004.s001` (PDF page 20):

> At high speeds (100 GB/s or higher), some MACsec Devices may be configured to use an extended Packet Number (XPN), as described in IEEE 802.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u004.s002` (PDF page 20):

> 1AE-2018.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u004.s003` (PDF page 20):

> Without XPN, the unique packet numbers may be exhausted quickly at high speeds and re-keying at high speeds may interrupt traffic flow.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u004.s004` (PDF page 20):

> If supported in the MACsec Device, this CP allows the XPN feature to be used.

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u005.s001`: Table 9.
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u005.s002`: Approved Algorithms for MACsec Encryption
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u006`: Security Service Algorithm Suite Specifications
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u007`: Confidentiality (Encryption) Galois Counter Mode (GCM)- AES-256 GCM-AES-XPN-256 FIPS PUB 197 IEEE 802.1AE-2018
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u008`: Key Wrap AES Key Wrap IETF RFC 3394

<a id="rg-017"></a>

## RG-017: Mutual authentication and Non-Person Entity certificates

Original requirement IDs: Prose-only.

**Applicability:** Peer encryption devices and all authentication certificates issued to them.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_mutual_device_authentication_and_npe`

**AI interpretation for later formalization:** Inner peers and Outer peers mutually authenticate using the method appropriate to VPN or MACsec, and every issued device authentication certificate for those components is a Non-Person Entity certificate.

**Qualifications and exceptions:**

- Detailed certificate validation, MACsec alternatives, and key handling are separate theorem groups.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u006.s001` (PDF page 20):

> The MSC Solution provides mutual device authentication between Outer Encryption Components and between Inner Encryption Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u006.s002` (PDF page 20):

> The method of authentication is different for VPN Gateways and MACsec Devices.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s001` (PDF page 20):

> This CP requires all authentication certificates issued to VPN Gateways and MACsec Devices to be Non- Person Entity certificates.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s001` (PDF page 23):

> The Outer Encryption Component can be either a VPN Gateway or a MACsec Device.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s002` (PDF page 23):

> The Outer Encryption Component establishes an encrypted tunnel using IPsec or MACsec with peer Outer Encryption Components, which provides device authentication, confidentiality, and integrity of information traversing Black Networks.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u004.s001` (PDF page 25):

> Similar to an Outer Encryption Component, an Inner Encryption Component provides authentication of peer VPN Gateways or MACsec Devices, cryptographic protection of data in transit, and configuration and enforcement of network packet handling rules.

<a id="rg-018"></a>

## RG-018: CNSS algorithm-policy requirements and choices

Original requirement IDs: Prose-only.

**Applicability:** Protection of National Security Systems up to Top Secret using this CP.

**Requirement strength and applicability:** The paragraph says required; authentication/key establishment distinguish Threshold and Objective; signing is Objective.

**Single theorem target:** `msc_cnss_algorithm_policy`

**AI interpretation for later formalization:** The solution satisfies the §2 algorithm-policy choices for confidentiality, authentication, key establishment, integrity, and objective software/firmware signing, respecting the listed threshold and objective alternatives and the detailed protocol tables.

**Qualifications and exceptions:**

- Only the algorithms stated in the supplied PDF are represented.
- Detailed protocol tables include additional parameters and choices, including DH group 16; §2 is not silently substituted for those tables.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u003.s001` (PDF page 9):

> CNSS Policy No.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u003.s002` (PDF page 9):

> 15, Use of Public Standards for Secure Information Sharing, identifies additional public algorithms to protect information within NSS.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u003.s003` (PDF page 9):

> Specifically, the following algorithms are required to protect all NSS up to Top Secret:

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u004.s001` (PDF page 9):

> • Confidentiality

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u005.s001` (PDF page 9):

>  AES 256

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u006.s001` (PDF page 9):

> • Digital Signatures and Authentication

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u007.s001` (PDF page 9):

>  RSA 3072 or ECDSA P-384 (Threshold)

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u008.s001` (PDF page 9):

>  ML-DSA 87 (Objective)

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u009.s001` (PDF page 9):

> • Key Establishment

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u010.s001` (PDF page 9):

>  DH 3072 or ECDH P-384 (Threshold)

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u011.s001` (PDF page 9):

>  ML-KEM 1024 (Objective)

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u012.s001` (PDF page 9):

> • Hashing and Integrity

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u013.s001` (PDF page 9):

>  SHA-384 or SHA-512

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u014.s001` (PDF page 9):

> • Software and Firmware Signing

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u015.s001` (PDF page 9):

>  Leighton-Micali Signature (LMS), Xtended Merkle Signature Scheme (XMSS) or ML-DSA 87 (Objective)

<a id="rg-019"></a>

## RG-019: IPsec CNSA profile and post-quantum exchange sequence

Original requirement IDs: MSC-VG-1, MSC-VG-19, MSC-VG-20, MSC-VG-21.

**Applicability:** Inner and Outer VPN Gateways and every IPsec connection using the selected CNSA profile.

**Requirement strength and applicability:** MSC-VG-1 is Threshold; MSC-VG-19/20/21 are the corresponding Objective profile. Current objective status is distinct from prospective future requirements.

**Single theorem target:** `msc_ipsec_algorithm_profile_choice`

**AI interpretation for later formalization:** Each VPN tunnel follows either the threshold CNSA 1.0 proposal profile or the corresponding CNSA 2.0 objective profile, whose initial IKE_SA_INIT uses a size-bounded CNSA 1.0 exchange and whose encrypted IKE_INTERMEDIATE uses ML-KEM-1024 with the specified IKE extensions and Table 7 algorithms outside the initial exchange.

**Alternative logic:**

- Interpret the “MSC-VG-19, MSC-VG-20, and MSC-VG-21” alternative as the three-part CNSA 2.0 profile, not as three independently sufficient substitutes.

**Qualifications and exceptions:**

- Referenced RFCs and drafts remain external dependencies; no external version is silently substituted.
- Figure 10 supports the exchange ordering and does not prove a protocol implementation.

Scope or resolved-interpretation notes: REQ-I14.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s001` (PDF page 26):

> As part of the CNSA 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s002` (PDF page 26):

> 0 migration, the VPN Gateways will have to implement CNSA 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s003` (PDF page 26):

> 0-compliant key establishment and digital signatures.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s004` (PDF page 26):

> As of now, this is an objective design feature but will be required in the future for the use of IPsec in MSC.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s005` (PDF page 26):

> The CNSA Suite 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s006` (PDF page 26):

> 0 is relevant to the choice of cryptography employed in IPsec and especially affects the Internet Key Exchange Protocol Version 2 (IKEv2) key establishment construction, requiring support for several new RFCs.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s007` (PDF page 26):

> NSA has worked with industry to develop an implementation profile, CNSA Suite 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s008` (PDF page 26):

> 0 Profile for IPsec (draft-guthrie-cnsa2-ipsec-profile).

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u001.s001` (PDF page 27):

> The draft profile (draft-guthrie-cnsa2-ipsec-profile) specifies the use of the CNSA 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u001.s002` (PDF page 27):

> 0-compliant algorithms ML-KEM-1024 [FIPS203] for key establishment and ML-DSA-87 [FIPS204] for digital signatures within IPsec.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u001.s003` (PDF page 27):

> It describes the use of RFCs that are required in order to support the large ML- KEM-1024 public key and ciphertext sizes, including:

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u002.s001` (PDF page 27):

> • RFC 7383 IKEv2 Message Fragmentation

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u003.s001` (PDF page 27):

> • RFC 9242 Intermediate Key Exchanges in IKEv2

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u004.s001` (PDF page 27):

> • RFC 9370 Multiple Key Exchanges in IKEv2

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u005.s001` (PDF page 27):

> • draft-ietf-ipsecme-ikev2-pqc-auth Signature Authentication in the IKEv2 using PQC

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u006.s001` (PDF page 27):

> • RFC 9881 Internet X.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u006.s002` (PDF page 27):

> 509 Public Key Infrastructure - Algorithm Identifiers for the Module-Lattice- Based Digital Signature Algorithm (ML-DSA)

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u007.s001` (PDF page 27):

> • draft-ietf-ipsecme-ikev2-mlkem Post-quantum Key Exchange with ML-KEM in the IKEv2

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s001` (PDF page 27):

> These additional RFCs facilitate the use of ML-KEM-1024 without causing IP-level fragmentation, which can create operational challenges and prevent the establishment of a connection.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s002` (PDF page 27):

> In particular, if ML- KEM-1024 were used in the initial IKEv2 Security Association (SA) key exchange (IKE_SA_INIT), the sizes of its public key and ciphertext would cause the initiator and responder messages to exceed the typical path Maximum Transmission Unit (MTU) and necessitate IP-level fragmentation.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s003` (PDF page 27):

> In order to prevent this issue, the solution leveraged first performs a CNSA 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s004` (PDF page 27):

> 0-compliant key establishment that does not exceed PMTU and subsequently performs an additional key establishment using a newly-defined exchange called Intermediate Exchange (IKE_INTERMEDIATE).

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s005` (PDF page 27):

> IKE_INTERMEDIATE exchanges can circumvent IP-level fragmentation by using IKEv2-level fragmentation, which does not incur the same operational issues.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s006` (PDF page 27):

> The specifications of which this solution is comprised work as follows:

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u009.s001` (PDF page 27):

> RFC 7383 IKEv2 Fragmentation: Describes a way to prevent IP fragmentation of large encrypted IKEv2 messages by fragmenting at the IKEv2 layer.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u009.s002` (PDF page 27):

> This allows IKEv2 messages to traverse network devices that do not allow IP fragments to pass through.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u010.s001` (PDF page 27):

> RFC 9242 Intermediate Key Exchanges: Specifies a new exchange type called IKE_INTERMEDIATE.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u010.s002` (PDF page 27):

> IKE_INTERMEDIATE exchanges can be used for transferring large amounts of data in the process of establishing an IKEv2 Security Association.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u010.s003` (PDF page 27):

> It is sent after IKE_SA_INIT and before IKE_AUTH.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u011.s001` (PDF page 27):

> RFC 9370 Multiple Key Exchanges: Leverages the IKE_INTERMEDIATE exchange specified in RFC 9242 in order to perform multiple key establishments.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u011.s002` (PDF page 27):

> In particular, this document enables the use of a quantum resistant key establishment algorithm whose public key and ciphertexts would exceed MTU and cause IP fragmentation of the IKE_SA_INIT messages.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u011.s003` (PDF page 27):

> The document resolves this issue by specifying how to perform such large key establishments in IKE_INTERMEDIATE which can benefit from the IKEv2 fragmentation mechanism specified in RFC 7383.

- `CSFC-MSC-1.3.0-4e40e3d83708:p027:u011.s004` (PDF page 27):

> An initial key establishment that does not cause IP fragmentation is first performed in IKE_SA_INIT, followed by additional key establishment(s) using IKE_INTERMEDIATE message(s).

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s001` (PDF page 28):

> As detailed in Figure 10, RFC 9370 enables peers to perform multiple key exchanges.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s002` (PDF page 28):

> The key- establishment algorithm used in the Initial IKE SA (IKE_SA_INIT) exchange must be constrained enough in size as to not induce IP fragmentation.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s003` (PDF page 28):

> The ML-KEM-1024 public key and ciphertext sizes are too large for this initial exchange and thus the IKE_SA_INIT exchange must use a CNSA 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s004` (PDF page 28):

> 0-compliant key establishment algorithm.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s005` (PDF page 28):

> A subsequent Intermediate IKE (IKE_INTERMEDIATE) exchange (as specified in RFC 9242) is then used to perform an ML-KEM key establishment.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s006` (PDF page 28):

> This second exchange, encrypted using keys established by IKE_SA_INIT, can leverage the IKEv2-level fragmentation mechanism specified in RFC 7383.

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u006` (PDF page 38):

> MSC-VG-1 The proposals offered by VPN Gateways in the course of establishing the Internet Key Exchange (IKE) Security Association and the Encapsulating Security Payload (ESP) SA for inner and outer tunnels must be configured to offer algorithm suite(s) containing only CNSA 1.0 algorithms as detailed in Table 6. T MSC-VG-19, MSC-VG-20, and MSC-VG- 21

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u011` (PDF page 39):

> MSC-VG-19 All IPsec connections must use multiple key exchanges with an initial IKEv2 SA key exchange and an intermediate IKEv2 key exchange: • IKE_SA_INIT: The IKEv2 SA key exchange performed in IKE_SA_INIT must use a CNSA 1.0 key establishment algorithm (as specified in Table 6). • IKE_INTERMEDIATE: The IKEv2 SA key establishment performed in the IKE_INTERMEDIATE exchange must use ML- KEM-1024 (as specified in Table 7). O MSC-VG-1

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u012` (PDF page 39):

> MSC-VG-20 All IPsec connections must use IETF standards compliant with IKE implementations as specified in Commercial National Security Algorithm (CNSA) Suite 2.0 Profile for IPsec (draft-guthrie-cnsa2- ipsec-profile) including RFC 9370, RFC 9242, and RFC 7383. O MSC-VG-1

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u013` (PDF page 39, 40):

> MSC-VG-21 The VPN Components must use algorithms from the algorithm suite in Table 7 for all IPsec VPN O MSC-VG-1 tunnels, with the exception of the IKE_SA_INIT exchange.

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-VG-1 | T | MSC-VG-19, MSC-VG-20, and MSC-VG- 21 |
| MSC-VG-19 | O | MSC-VG-1 |
| MSC-VG-20 | O | MSC-VG-1 |
| MSC-VG-21 | O | MSC-VG-1 |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u008`: [Image-only figure; see source location and network artifact.]
- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u001.s001`: Figure 10.
- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u001.s002`: CNSA 2.
- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u001.s003`: 0 IKEv2 Exchanges
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u006.s001`: Table 6.
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u006.s002`: Approved CNSA 1.
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u006.s003`: 0 Algorithms for IPsec
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u007`: Security Service Algorithm Suite Specifications
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u008`: Confidentiality (Encryption) Advanced Encryption Standard (AES)-256 FIPS PUB 197 IETF RFC 7296 IETF RFC 9206
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u009`: Authentication (Digital Signature) Rivest Shamir Adelman (RSA) 3072 or Elliptic Curve Digital Signature Algorithm over the curve P-384 with SHA-384 FIPS PUB 186-5 IETF RFC 4754 IETF RFC 7427 IETF RFC 7296 IETF RFC 9206
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u010`: Key Exchange/ Establishment Elliptic Curve Diffie-Hellman over the curve P-384 (Diffie- Hellman (DH) Group 20) or DH with prime modulus of 3072 bits (group 15) or 4096 bits (group 16) NIST SP 800-56A IETF RFC 3526 IETF RFC 5903 IETF RFC 7296 IETF RFC 9206
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u011`: Integrity (Hashing) SHA-384 or SHA-512 FIPS PUB 180-4 IETF RFC 6234 IETF RFC 9206
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u012.s001`: Table 7.
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u012.s002`: Approved CNSA 2.
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u012.s003`: 0 Algorithms for IPsec
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u013`: Security Service Algorithm Suite Specifications
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u014`: Confidentiality (Encryption) AES-256-GCM FIPS PUB 197
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u015`: Authentication (Digital Signature) ML-DSA-87 FIPS 204
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u001`: Security Service Algorithm Suite Specifications
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u002`: Key Establishment ML-KEM-1024 FIPS 203
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u003`: Integrity (Hashing) SHA-384 or SHA-512 FIPS PUB 180-4 IETF RFC 6239 IETF RFC 6379 IETF RFC 6380 IETF RFC 6460
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s001`: Table 8.
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s002`: VPN Gateway (VG) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u005`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-020"></a>

## RG-020: VPN certificate loading and authentication checks

Original requirement IDs: MSC-VG-2, MSC-VG-3, MSC-VG-4, MSC-VG-6, MSC-VG-7, MSC-VG-8.

**Applicability:** Every VPN Gateway and its IKE authentication.

**Requirement strength and applicability:** T=O for certificate loading and checks; non-use is Threshold and removal is Objective. RFC 8784 PSK augmentation is permitted.

**Single theorem target:** `msc_vpn_certificate_authentication`

**AI interpretation for later formalization:** VPN Gateways authenticate during IKE using unique device certificates and the corresponding CA chain through its trust anchor, reject revoked or expired certificates, and either do not use preinstalled default/self-signed/proprietary certificates or remove them under the objective alternative.

**Alternative logic:**

- MSC-VG-2 or MSC-VG-3 governs preinstalled certificates; the two rows must not be represented as mandatory simultaneous branches.

**Qualifications and exceptions:**

- CRL, OCSP, and similar mechanisms are permitted ways to check revocation.
- RFC 8784 PSKs supplement certificates and depend on the Symmetric Key Management Annex.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u007.s001` (PDF page 20):

> VPN Gateways authenticate via public key certificates.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u007.s002` (PDF page 20):

> VPN Gateways may also implement Internet Engineering Task Force (IETF) Request for Comments (RFC) 8784-compliant IKEv2 and use Pre-Shared Key (PSK) in addition to public key certificates to provide quantum resistant confidentiality.

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u007` (PDF page 38):

> MSC-VG-2 Default, self-signed or proprietary device certificates, which are frequently preinstalled by the vendor, for any VPN Gateway must not be used for establishing SAs. T MSC-VG-3

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u008` (PDF page 38):

> MSC-VG-3 Default, self-signed or proprietary device certificates, which are frequently preinstalled by the vendor, for any VPN Gateway must be removed. O MSC-VG-2

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u009` (PDF page 38):

> MSC-VG-4 When using certificate-based authentication, a unique device certificate must be loaded onto each VPN Gateway along with the corresponding CA certificate chain, to include the Trust Anchor CA certificate. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u011` (PDF page 38):

> MSC-VG-6 A device certificate must be used for VPN Gateway authentication during IKE. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u012` (PDF page 38):

> MSC-VG-7 VPN Gateway authentication must include a check that the certificate is not revoked, which can include a CRL, OCSP Responder, or other similar revocation reporting mechanism. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u013` (PDF page 38):

> MSC-VG-8 The VPN Gateway authentication must include a check that certificates are not expired. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-VG-2 | T | MSC-VG-3 |
| MSC-VG-3 | O | MSC-VG-2 |
| MSC-VG-4 | T=O | (blank) |
| MSC-VG-6 | T=O | (blank) |
| MSC-VG-7 | T=O | (blank) |
| MSC-VG-8 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s001`: Table 8.
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s002`: VPN Gateway (VG) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u005`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-021"></a>

## RG-021: VPN private-key access confinement

Original requirement IDs: MSC-VG-5, MSC-VG-17.

**Applicability:** Stored VPN private keys and optional access-control policy.

**Requirement strength and applicability:** MSC-VG-5 is T=O; MSC-VG-17 is Objective/Optional.

**Single theorem target:** `msc_vpn_private_key_confinement`

**AI interpretation for later formalization:** A VPN Gateway private key is inaccessible through an interface, and the optional objective Mandatory Access Control policy permits only that VPN Gateway to access its key.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u010` (PDF page 38):

> MSC-VG-5 The private key stored on VPN Gateways must not be accessible through an interface. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u009` (PDF page 39):

> MSC-VG-17 The Mandatory Access Control policy must only allow the VPN Gateway to access the private key of the VPN Gateway. O Optional

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-VG-5 | T=O | (blank) |
| MSC-VG-17 | O | Optional |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s001`: Table 8.
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s002`: VPN Gateway (VG) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u005`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-022"></a>

## RG-022: IKEv2 and IKE/ESP encryption-mode alternatives

Original requirement IDs: MSC-VG-9, MSC-VG-10, MSC-VG-11, MSC-VG-12, MSC-VG-18.

**Applicability:** All VPN Gateways, IKE encryption, and ESP encryption.

**Requirement strength and applicability:** IKEv2 is T=O. IKE and ESP each have their own independent Threshold/Objective choice.

**Single theorem target:** `msc_ike_version_and_encryption_modes`

**AI interpretation for later formalization:** Every VPN Gateway uses IKEv2 and selects a permitted IKE encryption mode and a permitted ESP encryption mode: CBC at threshold or GCM at objective, with HMAC integrity when ESP CBC is selected.

**Alternative logic:**

- IKE: MSC-VG-10 or MSC-VG-18.
- ESP: MSC-VG-11 or MSC-VG-12.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u014` (PDF page 38):

> MSC-VG-9 All VPN Gateways must use IKEv2 (IETF RFC 7296) key exchange. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u002` (PDF page 39):

> MSC-VG-10 All VPN Gateways must use Cipher Block Chaining for IKE encryption. T MSC-VG-18

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u003` (PDF page 39):

> MSC-VG-11 All VPN Gateways must use Cipher Block Chaining for ESP encryption with a Host-based Message Authentication Code for integrity. T MSC-VG-12

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u004` (PDF page 39):

> MSC-VG-12 All VPN Gateways must use Galois Counter Mode for ESP encryption. O MSC-VG-11

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u010` (PDF page 39):

> MSC-VG-18 All VPN Gateways must use Galois Counter Mode (GCM) for IKE encryption. O MSC-VG-10

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-VG-9 | T=O | (blank) |
| MSC-VG-10 | T | MSC-VG-18 |
| MSC-VG-11 | T | MSC-VG-12 |
| MSC-VG-12 | O | MSC-VG-11 |
| MSC-VG-18 | O | MSC-VG-10 |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s001`: Table 8.
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s002`: VPN Gateway (VG) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u005`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-023"></a>

## RG-023: VPN SA lifetimes and reauthentication

Original requirement IDs: MSC-VG-13, MSC-VG-14, MSC-VG-16.

**Applicability:** All VPN Gateways and established IKE/ESP Security Associations.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_vpn_sa_lifetimes_and_reauthentication`

**AI interpretation for later formalization:** Every VPN Gateway configures an IKE SA lifetime of at most 24 hours and an ESP SA lifetime of at most 8 hours, and reauthenticates its tunnel peer before rekeying an IKE SA.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u005` (PDF page 39):

> MSC-VG-13 All VPN Gateways must set the IKE SA lifetime to at most 24 hours. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u006` (PDF page 39):

> MSC-VG-14 All VPN Gateways must set the ESP SA lifetime to no more than 8 hours. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u008` (PDF page 39):

> MSC-VG-16 All VPN Gateways must re-authenticate the identity of the VPN Gateway at the other end of the established tunnel before rekeying the IKE SA. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-VG-13 | T=O | (blank) |
| MSC-VG-14 | T=O | (blank) |
| MSC-VG-16 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s001`: Table 8.
- `CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s002`: VPN Gateway (VG) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p039:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-024"></a>

## RG-024: MACsec authentication alternatives and AS scope

Original requirement IDs: MSC-MD-3, MSC-MD-14, MSC-AA-1, MSC-AA-2.

**Applicability:** MACsec Devices; the AS when certificate-based authentication is selected.

**Requirement strength and applicability:** MSC-MD-3 and MSC-MD-14 are both marked Threshold alternatives. AA-1 and AA-2 are T=O within certificate-based MACsec.

**Single theorem target:** `msc_macsec_authentication_choice_and_as`

**AI interpretation for later formalization:** MACsec peers authenticate using either PSK CAKs or certificate-based EAP-TLS; the certificate branch uses an AS for mutual device-certificate authentication, each MACsec device acts as supplicant and authenticator, and the AS obeys the stated one-site and Red/Gray network connection restrictions.

**Alternative logic:**

- Choose MSC-MD-3 CAK authentication or MSC-MD-14 EAP-TLS authentication; do not relabel EAP-TLS as Objective.

**Qualifications and exceptions:**

- The AS may connect to only one site’s network; §4.2.1.1 additionally uses ambiguous “both Gray and/or Red Networks” wording.

Open issues: REQ-I08, REQ-I15.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s001` (PDF page 20):

> MACsec Devices authenticate using a PSK called a CAK or using EAP-TLS over 802.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s002` (PDF page 20):

> 1X to pass public key device certificates for mutual authentication between devices.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s003` (PDF page 20):

> The EAP-TLS mechanism is used to mutually authenticate and get the Master Session Key (MSK) from which the Connectivity Association Key (CAK) is derived for the MACsec Key Agreement (MKA) protocol.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s004` (PDF page 20):

> For each MACsec tunnel, a Key Server is identified.

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s005` (PDF page 20):

> The Key Server authenticates the other MACsec Device and issues a Secure Association Key to provide confidentiality and integrity for the MACsec tunnel.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s001` (PDF page 26):

> The MSC AS is responsible for mutual authentication between MACsec Devices.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s002` (PDF page 26):

> Authentication must be established between the MACsec device and the AS, where each MACsec device must perform the functions of a supplicant and authenticator.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s003` (PDF page 26):

> This communication is used throughout the EAP-TLS negotiation to mutually authenticate two MACsec Devices to pass MACsec traffic.

- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u008` (PDF page 41):

> MSC-MD-3 MACsec Devices must authenticate using Pre-Shared Keys (PSKs), known as Connectivity Association Keys (CAKs). T MSC-MD-14

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u005` (PDF page 42):

> MSC-MD-14 MACsec Devices must authenticate using EAP-TLS (certificate based). T MSC-MD-3

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u010` (PDF page 42):

> MSC-AA-1 The AS must be used to provide mutual authentication using EAP-TLS with device certificates between MACsec Devices. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u011` (PDF page 42):

> MSC-AA-2 The AS must only connect to one site’s network when a MACsec device is an Outer or Inner Encryption Component. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-MD-3 | T | MSC-MD-14 |
| MSC-MD-14 | T | MSC-MD-3 |
| MSC-AA-1 | T=O | (blank) |
| MSC-AA-2 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s005`: If MACsec Devices are authenticating using certificates, the authentication server (AS) must not connect to both Gray and/or Red Networks.
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s001`: Table 12.
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s002`: MACsec Device (MD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u005`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u008.s001`: Table 13.
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u008.s002`: Certificate-based MACsec Authentication and Authorization (AA) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u009`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-025"></a>

## RG-025: MACsec encryption and key wrapping algorithms

Original requirement IDs: MSC-MD-1, MSC-MD-2.

**Applicability:** MACsec data encryption and key distribution.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_macsec_encryption_and_key_wrap`

**AI interpretation for later formalization:** MACsec Devices use 256-bit AES Key Wrap for key distribution and 256-bit AES GCM for MACsec protection with the algorithms specified in Table 9.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u006` (PDF page 41):

> MSC-MD-1 MACsec Devices must use AES Key Wrap for key distribution with a cryptographic key size of 256 bits. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u007` (PDF page 41):

> MSC-MD-2 MACsec Devices must use AES GCM for MACsec with a cryptographic key size of 256 bits. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-MD-1 | T=O | (blank) |
| MSC-MD-2 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u005.s001`: Table 9.
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u005.s002`: Approved Algorithms for MACsec Encryption
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u006`: Security Service Algorithm Suite Specifications
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u007`: Confidentiality (Encryption) Galois Counter Mode (GCM)- AES-256 GCM-AES-XPN-256 FIPS PUB 197 IEEE 802.1AE-2018
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u008`: Key Wrap AES Key Wrap IETF RFC 3394
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s001`: Table 12.
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s002`: MACsec Device (MD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u005`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-026"></a>

## RG-026: MACsec EAP-TLS CNSA profile alternatives

Original requirement IDs: MSC-AA-3, MSC-AA-4.

**Applicability:** MACsec Devices and AS participating in EAP-TLS.

**Requirement strength and applicability:** AA-3 is Threshold and AA-4 is Objective; prose future migration statements do not make the Objective branch universally mandatory in this version.

**Single theorem target:** `msc_macsec_eap_tls_profile_choice`

**AI interpretation for later formalization:** Certificate-authenticated MACsec Devices and their AS use either the Table 10 CNSA 1.0 EAP-TLS suite or the objective Table 11 CNSA 2.0 suite, with ML-KEM-1024, ML-DSA-87, and TLS 1.3 in the CNSA 2.0 branch.

**Alternative logic:**

- Select MSC-AA-3 or MSC-AA-4 as the corresponding cipher-suite profile.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s004` (PDF page 26):

> Objectively, the MSC Authentication Server should use CNSA 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s005` (PDF page 26):

> 0-compliant algorithms as part of the EAP-TLS negotiation to mutually authenticate the MACsec Devices with ML-KEM 1024 for key establishment and ML-DSA 87 for digital signatures as vendors enable support for these algorithms.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s001` (PDF page 28):

> As part of the CNSA 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s002` (PDF page 28):

> 0 migration, MACsec Devices will have to implement CNSA 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s003` (PDF page 28):

> 0-compliant key establishment and digital signatures when utilizing EAP-TLS for mutual authentication.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s004` (PDF page 28):

> As of now, this is an objective design feature but will be required in the future for the use of MACsec in MSC.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s005` (PDF page 28):

> The EAP-TLS negotiation to mutually authenticate MACsec Devices will need to use ML-KEM 1024 for key establishment and ML-DSA 87 for digital signatures.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s006` (PDF page 28):

> For implementations of EAP-TLS to use CNSA 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s007` (PDF page 28):

> 0- compliant algorithms, TLS 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s008` (PDF page 28):

> 3 will be required per RFC 9190 EAP-TLS 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s009` (PDF page 28):

> 3 Using the Extensible Authentication Protocol with TLS 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s010` (PDF page 28):

> 3 and CNSA 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s011` (PDF page 28):

> 0 Suite Profile for TLS 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s012` (PDF page 28):

> 3 (draft-becker-cnsa2-tls- profile).

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u012` (PDF page 42):

> MSC-AA-3 The MACsec Devices and the AS must use the CNSA 1.0 EAP-TLS Ciphersuite in Table 10. T MSC-AA-4

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u013` (PDF page 42):

> MSC-AA-4 The MACsec Devices and the AS must use the CNSA 2.0 EAP-TLS Ciphersuite in Table 11. O MSC-AA-3

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-AA-3 | T | MSC-AA-4 |
| MSC-AA-4 | O | MSC-AA-3 |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u009.s001`: Table 10.
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u009.s002`: Approved CNSA 1.
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u009.s003`: 0 Algorithms for MACsec EAP-TLS
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u010`: Security Service Algorithm Suite Specifications
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u011`: Confidentiality (Encryption) AES-256-GCM FIPS PUB 197
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u012`: Authentication (Digital Signature) RSA 3072 or ECDSA over the curve P-384 with SHA- 384 FIPS PUB 186-5 IETF RFC 5216 IETF RFC 6460
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u013`: Key Exchange/ Establishment ECDH over the curve P-384 (DH group 20) or DH with prime modulus of 3072 bits (group 15) or 4096 bits (group 16) NIST SP 800-56A IETF RFC 5216 IETF RFC 6460
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u014`: Integrity (Hashing) SHA-384 or SHA-512 FIPS PUB 180-4 IETF RFC 5216 IETF RFC 6234 IETF RFC 6460
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u015.s001`: Table 11.
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u015.s002`: Approved CNSA 2.
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u015.s003`: 0 Algorithms for MACsec EAP-TLS
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u016`: Security Service Algorithm Suite Specifications
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u017`: Confidentiality (Encryption) AES-256-GCM FIPS PUB 197
- `CSFC-MSC-1.3.0-4e40e3d83708:p040:u018`: Authentication (Digital Signature) ML-DSA-87 FIPS 204
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u001`: Security Service Algorithm Suite Specifications
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u002`: Key Establishment ML-KEM-1024 FIPS 203
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u003`: Integrity (Hashing) SHA-384 or SHA-512 FIPS PUB 180-4 IETF RFC 6239 IETF RFC 6379 IETF RFC 6380 IETF RFC 6460
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u008.s001`: Table 13.
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u008.s002`: Certificate-based MACsec Authentication and Authorization (AA) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u009`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-027"></a>

## RG-027: MACsec key generation, key-server selection, and rollover

Original requirement IDs: MSC-MD-5, MSC-MD-6, MSC-MD-15.

**Applicability:** MACsec CAKs/CKNs and each pair forming a MACsec tunnel.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_macsec_key_generation_and_server`

**AI interpretation for later formalization:** MACsec CKNs come from an NSA-approved KGS and are at least 16 bytes. The applicable CAK-generation constraint remains provisional for the EAP-TLS branch because the source states both MSK derivation and KGS generation of all CAKs; the PSK branch uses the stated approved-KGS generation. Each pair sets the prescribed key-server values with the central site serving when present, and fallback CAKs are disabled.

**Qualifications and exceptions:**

- Key Server value is 0 for the server and 1 for the other device.
- External key-management details are not reconstructed from relocated rows.

Open issues: REQ-I15.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s002` (PDF page 20):

> This CP also requires all CAKs and their associated Connectivity Key Names (CKNs) to be generated using an NSA-approved Key Generation Solution (KGS).

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u012.s001` (PDF page 29):

> For provisioning MACsec PSK Encryption Components, the Security Administrator obtains a Symmetric Key from an NSA-approved KGS and applies them to each Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u010` (PDF page 41):

> MSC-MD-5 MACsec Devices must have the length of the CKN set to a minimum of 16 bytes (128 bits) and generate the CKN using an NSA-approved KGS. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u011` (PDF page 41):

> MSC-MD-6 For each pair of MACsec Devices establishing an encryption tunnel, one of the two must be configured to be the Key Server by setting its Key Server value to 0 (zero). The other MACsec Device must have its Key Server value set to 1. If a Central Management Site is part of the MSC Solution, it must be the Key Server. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u006` (PDF page 42):

> MSC-MD-15 Must disable Fallback (rollover) CAKs. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-MD-5 | T=O | (blank) |
| MSC-MD-6 | T=O | (blank) |
| MSC-MD-15 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s003`: The EAP-TLS mechanism is used to mutually authenticate and get the Master Session Key (MSK) from which the Connectivity Association Key (CAK) is derived for the MACsec Key Agreement (MKA) protocol.
- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s004`: For each MACsec tunnel, a Key Server is identified.
- `CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s005`: The Key Server authenticates the other MACsec Device and issues a Secure Association Key to provide confidentiality and integrity for the MACsec tunnel.
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s001`: Table 12.
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s002`: MACsec Device (MD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u005`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u013.s001`: Key Server – The MACsec Device designated as the one responsible for distribution Secure Association Keys to the other MACsec Device.

<a id="rg-028"></a>

## RG-028: MACsec mandatory protection parameters

Original requirement IDs: MSC-MD-7, MSC-MD-8, MSC-MD-9, MSC-MD-10, MSC-MD-12, MSC-MD-16.

**Applicability:** All MACsec Devices and their external data ports.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_macsec_protection_parameters`

**AI interpretation for later formalization:** MACsec Devices enable MKA data-delay protection, set lifetime and hello timeouts to 6.0 and 2.0 seconds, set the replay window to 2 or the lowest value possible for the Black Network, encrypt all external data traffic, set confidentiality offset to zero, and operate in must-secure mode.

**Qualifications and exceptions:**

- The replay-window clause retains its network-dependent qualification; no fixed value of 2 is imposed when the source permits another minimum.
- MD-10 and MD-16 overlap but are both preserved.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u012` (PDF page 41):

> MSC-MD-7 MACsec Devices must enable data delay protection for MACsec Key Agreement (MKA). T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u013` (PDF page 41):

> MSC-MD-8 MACsec Devices must have an MKA Lifetime Timeout limit set to 6.0 seconds and Hello Timeout limit set to 2.0 seconds. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u014` (PDF page 41):

> MSC-MD-9 MACsec Devices must have the replay window set to 2 or as low as possible given the nature of the Black Network being traversed. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u015` (PDF page 41):

> MSC-MD-10 MACsec Devices must require all data traffic on an external facing port to be encrypted (e.g., must- secure). T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u003` (PDF page 42):

> MSC-MD-12 MACsec Devices must have the Confidentiality Offset set to 0 (zero). T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u007` (PDF page 42):

> MSC-MD-16 MACsec Devices must be configured to “must- secure”. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-MD-7 | T=O | (blank) |
| MSC-MD-8 | T=O | (blank) |
| MSC-MD-9 | T=O | (blank) |
| MSC-MD-10 | T=O | (blank) |
| MSC-MD-12 | T=O | (blank) |
| MSC-MD-16 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s001`: Table 12.
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s002`: MACsec Device (MD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u005`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-029"></a>

## RG-029: Inner encryption and decryption cannot be bypassed

Original requirement IDs: MSC-IR-1, MSC-IR-3, MSC-IR-4, MSC-IR-5, MSC-IR-6, MSC-IR-7.

**Applicability:** Inner Encryption Components, their Red/Gray interfaces, and all corresponding traffic.

**Requirement strength and applicability:** Tunnel mode and no split tunneling are T=O; each bypass direction has a Threshold rule or Objective Mandatory Access Control implementation.

**Single theorem target:** `msc_inner_tunnel_no_bypass`

**AI interpretation for later formalization:** Inner VPN Gateways use ESP tunnel mode with an associated IP tunneling protocol; Inner Encryption Components never bypass encryption from Red to Gray or decryption from Gray to Red and never permit split tunneling, using Mandatory Access Control in each selected objective branch.

**Alternative logic:**

- Red-to-Gray: MSC-IR-3 or MSC-IR-4.
- Gray-to-Red: MSC-IR-5 or MSC-IR-6.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u006.s001` (PDF page 25):

> The Inner Encryption Component must not route packets between Red and Gray Networks; any packets received on a Red Network interface and sent to a Gray Network interface must be transmitted within an IPsec or MACsec tunnel configured according to this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u018` (PDF page 42):

> MSC-IR-1 The Inner VPN Gateway must use ESP Tunnel mode IPsec, with an associated IP tunneling protocol. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u003` (PDF page 43):

> MSC-IR-3 The Inner Encryption Component must not allow packets received on an interface connected to a Red Network to bypass encryption and be forwarded out through an interface connected to a Gray Network. T MSC-IR-4

- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u004` (PDF page 43):

> MSC-IR-4 The Inner Encryption Component must use a Mandatory Access Control policy to not allow packets received on an interface connected to a Red Network to bypass encryption and be forwarded out through an interface connected to a Gray Network. O MSC-IR-3

- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u005` (PDF page 43):

> MSC-IR-5 The Inner Encryption Component must not allow packets received on an interface connected to a Gray Network to bypass decryption and be forwarded out through an interface connected to a Red Network. T MSC-IR-6

- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u006` (PDF page 43):

> MSC-IR-6 The Inner Encryption Component must use Mandatory Access Control policy to not allow packets received on an interface connected to a Gray Network to bypass decryption and be forwarded out through an interface connected to a Red Network. O MSC-IR-5

- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u007` (PDF page 43):

> MSC-IR-7 The Inner Encryption Component must not permit split-tunneling. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u010.s001` (PDF page 61):

> Split-tunneling – Allows network traffic to egress through a path other than the established encryption tunnel (either on the same interface or another network interface.

- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u010.s002` (PDF page 61):

> Split-tunneling is explicitly prohibited in MSC CP compliant configurations.

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-IR-1 | T=O | (blank) |
| MSC-IR-3 | T | MSC-IR-4 |
| MSC-IR-4 | O | MSC-IR-3 |
| MSC-IR-5 | T | MSC-IR-6 |
| MSC-IR-6 | O | MSC-IR-5 |
| MSC-IR-7 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u016.s001`: Table 14.
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u016.s002`: Additional Inner Encryption Component (IR) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u017`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u005.s001`: External Interface – The interface on an Encryption Component that connects to the outer network (i.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u005.s002`: e.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u005.s003`: , the Gray Network on the Inner Encryption Component or the Black Network on the Outer Encryption Component).
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u012.s001`: Internal Interface – The interface on an Encryption Component that connects to the inner network (i.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u012.s002`: e.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u012.s003`: , the Gray Network on the Outer Encryption Component or the Red Network on the Inner Encryption Component).

<a id="rg-030"></a>

## RG-030: Outer encryption and decryption cannot be bypassed

Original requirement IDs: MSC-OR-1, MSC-OR-2, MSC-OR-3, MSC-OR-4, MSC-OR-5, MSC-OR-6, MSC-OR-7.

**Applicability:** Outer Encryption Components and Gray/Black interface traffic.

**Requirement strength and applicability:** OR-1/4/7 are T=O; OR-2/3 and OR-5/6 are Threshold/Objective alternatives.

**Single theorem target:** `msc_outer_tunnel_no_bypass`

**AI interpretation for later formalization:** Outer VPN Gateways use ESP tunnel mode; Outer Encryption Components accept already-encrypted Gray traffic except permitted control-plane traffic, never bypass encryption to Black or decryption from Black, and never permit split tunneling, using Mandatory Access Control in each selected objective branch.

**Alternative logic:**

- Gray-to-Black encryption: MSC-OR-2 or MSC-OR-3.
- Black ingress decryption: MSC-OR-5 or MSC-OR-6.

**Qualifications and exceptions:**

- OR-4 expressly excepts control-plane traffic; that exception must survive the encompassing theorem.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u002.s001` (PDF page 24):

> The Outer Encryption Component cannot route packets between Gray and Black Networks; any packets received on a Gray Network interface and sent out on a Black Network interface must be transmitted within an IPsec or MACsec tunnel configured according to this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u012` (PDF page 43):

> MSC-OR-1 Outer VPN Gateways must use ESP Tunnel mode IPsec. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u013` (PDF page 43):

> MSC-OR-2 Outer Encryption Components must not allow packets received on an interface connected to a Gray Network to bypass encryption and be forwarded out through an interface connected to a Black Network. T MSC-OR-3

- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u014` (PDF page 43, 44):

> MSC-OR-3 Outer Encryption Components must use Mandatory Access Control policy to not allow packets received on an interface connected to a Gray Network to O MSC-OR-2 bypass encryption and be forwarded out through an interface connected to a Black Network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u003` (PDF page 44):

> MSC-OR-4 All traffic received by Outer Encryption Components on an interface connected to a Gray Network, with the exception of control plane traffic, must have already been encrypted once. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u004` (PDF page 44):

> MSC-OR-5 Outer Encryption Components must not allow any packets received on an interface connected to a Black Network to bypass decryption. T MSC-OR-6

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u005` (PDF page 44):

> MSC-OR-6 Outer Encryption Components must use Mandatory Access Control policy to not allow any packets received on an interface connected to a Black Network to bypass decryption. O MSC-OR-5

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u006` (PDF page 44):

> MSC-OR-7 The Outer Encryption Components must not permit split-tunneling. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-OR-1 | T=O | (blank) |
| MSC-OR-2 | T | MSC-OR-3 |
| MSC-OR-3 | O | MSC-OR-2 |
| MSC-OR-4 | T=O | (blank) |
| MSC-OR-5 | T | MSC-OR-6 |
| MSC-OR-6 | O | MSC-OR-5 |
| MSC-OR-7 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u010.s001`: Table 15.
- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u010.s002`: Additional Outer Encryption Components (OR) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u011`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u005.s001`: External Interface – The interface on an Encryption Component that connects to the outer network (i.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u005.s002`: e.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u005.s003`: , the Gray Network on the Inner Encryption Component or the Black Network on the Outer Encryption Component).
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u012.s001`: Internal Interface – The interface on an Encryption Component that connects to the inner network (i.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u012.s002`: e.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u012.s003`: , the Gray Network on the Outer Encryption Component or the Red Network on the Inner Encryption Component).
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u010.s001`: Split-tunneling – Allows network traffic to egress through a path other than the established encryption tunnel (either on the same interface or another network interface.
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u010.s002`: Split-tunneling is explicitly prohibited in MSC CP compliant configurations.

<a id="rg-031"></a>

## RG-031: Routing and switching limits on Encryption Components

Original requirement IDs: MSC-OR-8, MSC-SR-17.

**Applicability:** Outer internal/external interfaces and Inner Encryption Components.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_encryption_component_routing_limits`

**AI interpretation for later formalization:** Outer Encryption Components do not implement routing protocols or routing functionality as stated in the prose, while permitted firewall infrastructure supplies dynamic routing; Inner Encryption Components do not switch or route for other Encryption Components.

**Qualifications and exceptions:**

- Routing between protected domains remains prohibited by RG-029 and RG-030; the prose’s broad “routing functionality” requires review against infrastructure routing descriptions.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s005` (PDF page 13):

> Restrictions are also placed on control plane traffic for the Outer Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s006` (PDF page 13):

> The Outer Encryption Component is prohibited from implementing routing protocols on external and internal interfaces.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s007` (PDF page 13):

> The Outer Encryption Component may not perform routing functionality.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s008` (PDF page 13):

> If an Outer Firewall is present, the Outer Firewall can perform routing functions.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u011.s001` (PDF page 23, 24):

> The Outer Encryption Component is prohibited from implementing routing protocols on external and internal interfaces and must rely on an Outer Firewall or Gray Firewall to provide dynamic routing functionality.

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u007` (PDF page 36):

> MSC-SR-17 Inner Encryption Components must not perform switching or routing for other Encryption Components. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u007` (PDF page 44):

> MSC-OR-8 Outer Encryption Components must not use routing protocols (e.g., OSPF, BGP). T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-OR-8 | T=O | (blank) |
| MSC-SR-17 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u010.s001`: Table 15.
- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u010.s002`: Additional Outer Encryption Components (OR) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-032"></a>

## RG-032: TRANSEC under the stated deployment conditions

Original requirement IDs: MSC-OR-9.

**Applicability:** Outer Encryption Components using the Public Internet or a MACsec external interface connected to an Outer Firewall.

**Requirement strength and applicability:** §5.2 says must for Public Internet. MSC-OR-9 is Objective with a blank Alternatives cell for a MACsec interface connected to an Outer Firewall.

**Single theorem target:** `msc_transec_conditions`

**AI interpretation for later formalization:** TRANSEC is enabled under the applicable Public-Internet and MACsec-to-Outer-Firewall conditions once the conflicting prose and objective-table requirement strength are resolved explicitly.

**Qualifications and exceptions:**

- The differing requirement strength and conditions are retained as an open source conflict; a blank Alternatives cell is not silently changed to Optional.

Open issues: REQ-I04.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s004` (PDF page 23):

> If the Black Network is the Public Internet, Transmission Security (TRANSEC) must be enabled to provide additional security.

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u008` (PDF page 44):

> MSC-OR-9 Outer Encryption must enable TRANSEC when external interface is MACsec enabled and connected to the Outer Firewall. O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-OR-9 | O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u010.s001`: Table 15.
- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u010.s002`: Additional Outer Encryption Components (OR) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u011.s001`: Transmission Security (TRANSEC) – Measures (security controls) applied to transmissions in order to prevent interception, disruption of reception, communications deception, and/ or derivation of intelligence by analysis of transmission characteristics such as signal parameters or message externals.
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u011.s002`: (CNSSI 4009)

<a id="rg-033"></a>

## RG-033: Packet sizing to control fragmentation

Original requirement IDs: MSC-SR-23, MSC-IR-2.

**Applicability:** External interfaces of Gray Firewalls and Encryption Components; optional Inner interface sizing objective.

**Requirement strength and applicability:** SR-23 is T=O; IR-2 is Objective/Optional. “Should consider” clauses remain recommendations.

**Single theorem target:** `msc_packet_size_configuration`

**AI interpretation for later formalization:** Gray Firewall/Encryption Component external packet sizes satisfy the required IPv4 MTU or IPv6 PMTU configuration, and the optional Inner interface objective sizes packets or frames with the Black Network and Outer Component limits in view.

**Qualifications and exceptions:**

- The source distinguishes avoiding fragmentation in SR-23 from reducing fragmentation in IR-2.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u013` (PDF page 36, 37):

> MSC-SR-23 The packet size for packets leaving the external interface of the Gray Firewall/Encryption Component must be configured to keep the packets T=O from being fragmented and impacting performance. This requires proper configuration of the Maximum Transmission Unit (MTU) for IPv4 or Path MTU (PMTU) for IPv6 and should consider the Outer VPN Gateway MTU/PMTU values for achievement.

- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u019` (PDF page 42, 43):

> MSC-IR-2 Packet sizes, or frames leaving the external interface of the Inner Encryption Component must be configured to reduce fragmentation and lessen the impact on performance. This requires proper O Optional configuration of the Maximum Transmission Unit (MTU) (for IPv4 or MACsec) or Path MTU (PMTU) (for IPv6) and should consider Black Network and Outer Encryption Component MTU/PMTU values to achieve this.

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-23 | T=O | (blank) |
| MSC-IR-2 | O | Optional |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u016.s001`: Table 14.
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u016.s002`: Additional Inner Encryption Component (IR) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u017`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-034"></a>

## RG-034: Outer Firewall placement for untrusted Black transport

Original requirement IDs: MSC-SR-12.

**Applicability:** Untrusted Black transport and Public-Internet deployments.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_outer_firewall_placement`

**AI interpretation for later formalization:** An MSC solution using an untrusted Black network such as the Public Internet places an Outer Firewall between that network and the Outer Encryption Component, with the stated internal and external connections.

**Qualifications and exceptions:**

- The prose uses the broader “untrusted network such as Public Internet” condition; SR-12 explicitly names Public Internet.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s005` (PDF page 12):

> As shown in Figure 2, if the Black Network is an untrusted network such as the Public Internet, an Outer Firewall is required between the Black Network and the Outer Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s001` (PDF page 23):

> An MSC Solution that uses an untrusted network such as the Public Internet as its Black Network must include an Outer Firewall (see Section 4.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s002` (PDF page 23):

> 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s003` (PDF page 23):

> 3).

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s004` (PDF page 23):

> The Outer Firewall is located at the edge of the MSC Solution and is connected to the Black Network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s001` (PDF page 23):

> If the Black Network is the Public Internet, the external interface of the Outer Encryption Component is connected to the internal interface of the Outer Firewall.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s002` (PDF page 23):

> Otherwise, the external interface of the Outer Encryption Component is connected to the Black Network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s003` (PDF page 23):

> The internal interface of the Outer Encryption Component is connected to Gray Firewalls, if required, or Inner Encryption Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u002` (PDF page 36):

> MSC-SR-12 If the MSC Solution uses the Public Internet for its Black transport network, an Outer Firewall must be located between the Black transport network and the Outer Encryption Component. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-12 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u010`: [Image-only figure; see source location and network artifact.]
- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u004.s001`: Figure 2.
- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u004.s002`: MSC Solution Using the Public Internet as the Black Transport Network
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-035"></a>

## RG-035: Permitted protocols and peers at encryption and firewall boundaries

Original requirement IDs: MSC-PF-3, MSC-PF-4, MSC-PF-5, MSC-PF-22, MSC-OR-10.

**Applicability:** All Outer Black interfaces, Inner Gray interfaces and Red service interfaces, and required Outer Firewalls.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_boundary_interface_filtering`

**AI interpretation for later formalization:** Outer VPN Black interfaces permit IKE/ESP and approved control traffic, Outer MACsec Black interfaces permit MACsec PDUs and approved control traffic, and Inner Gray interfaces permit the listed tunnel/control protocols in both directions. Inner Red interfaces permit only addresses and ports associated with Red services. A required Outer Firewall applies its protocol allowlist, with its external interface using the local Outer Encryption Component as the permitted destination and its internal interface using that local component as the permitted source, subject to the stated control-plane allowances. Packets leaving the Outer Encryption Component make connections only to the remote Outer Encryption Component or other intended device.

**Qualifications and exceptions:**

- Multiple external tunnel interfaces are allowed, but each obeys port filtering.
- The §5.1 prose lists IPsec/MACsec while PF-22 also names IKE/MKA and approved control traffic; retain the table’s detailed allowances.
- Inner internal interfaces permit only addresses and ports associated with Red services.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u003.s001` (PDF page 23):

> The external interface of the Outer Firewall only permits IPsec or MACsec traffic with a destination address of the Outer Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s001` (PDF page 23):

> The internal interface of the Outer Firewall only permits IPsec or MACsec traffic with a source address of the Outer Encryption Component and any necessary control plane traffic.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s002` (PDF page 23):

> The minimum requirements for port filtering on the Outer Firewall can be found in Section 10.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s003` (PDF page 23):

> 6.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s001` (PDF page 23):

> The Outer Encryption Component may be a perimeter device (if the Outer Firewall is not present) and more exposed to external attacks.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s002` (PDF page 23):

> The Outer Encryption Component may use internal filtering to help protect the network from unauthenticated traffic.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s003` (PDF page 23):

> This allows specification of rules that prohibit unauthorized data flows, which helps mitigate Denial of Service attacks and resource exhaustion.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s004` (PDF page 23):

> This CP does not require that the Outer Encryption Component terminate all tunnels on a single physical interface; however, all such external interfaces must conform to the port filtering requirements in Section 10.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s005` (PDF page 23):

> 6.

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s006` (PDF page 23):

> The Outer Encryption Component is implemented identically for all the high-level designs covered in this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u005.s001` (PDF page 25):

> Similar to the Outer Encryption Component, the external interface of the Inner Encryption Component only permits egress of IPsec/MACsec traffic and AO-approved control plane traffic.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u005.s002` (PDF page 25):

> The internal interface of the Inner Encryption Component is configured to only permit traffic with an IP address and port associated with Red Network services.

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u009` (PDF page 44):

> MSC-OR-10 Packets leaving the external interface of the Outer Encryption Component must only make connections with the remote Outer Encryption Component or the other intended device. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u016` (PDF page 44):

> MSC-PF-3 For all Outer VPN Gateway interfaces connected to a Black Network, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, ESP, and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u017` (PDF page 44, 45):

> MSC-PF-4 For all Outer MACsec Device interfaces connected to a Black Network, traffic filtering rules must be T=O applied to both inbound and outbound traffic, such that only MACsec Protocol Data Units and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed.

- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u003` (PDF page 45):

> MSC-PF-5 For all Inner Encryption Component interfaces connected to a Gray Network, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, IPsec, MKA, MACsec, and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p046:u009` (PDF page 46):

> MSC-PF-22 If an Outer Firewall is required, for all Outer Firewall interfaces, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, ESP, MKA, MACsec and control plane protocols (as defined in this CP) approved by organization- defined policy are allowed. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-PF-3 | T=O | (blank) |
| MSC-PF-4 | T=O | (blank) |
| MSC-PF-5 | T=O | (blank) |
| MSC-PF-22 | T=O | (blank) |
| MSC-OR-10 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u010.s001`: Table 15.
- `CSFC-MSC-1.3.0-4e40e3d83708:p043:u010.s002`: Additional Outer Encryption Components (OR) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s001`: Table 16.
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s002`: Port Filtering (PF) Solution Components Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u013`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p046:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-036"></a>

## RG-036: Minimal network-interface exposure

Original requirement IDs: MSC-PF-1, MSC-PF-2.

**Applicability:** All network interfaces of all Solution Components.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_minimal_interface_exposure`

**AI interpretation for later formalization:** Each Solution Component restricts every network interface to the smallest possible address ranges, ports, and protocols and disables every unused network interface.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u014` (PDF page 44):

> MSC-PF-1 All Solution Components must have all network interfaces restricted to the smallest address ranges, ports, and protocols possible. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u015` (PDF page 44):

> MSC-PF-2 All Solution Components must have all unused network interfaces disabled. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-PF-1 | T=O | (blank) |
| MSC-PF-2 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s001`: Table 16.
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s002`: Port Filtering (PF) Solution Components Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u013`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-037"></a>

## RG-037: Outer-component third-party contact restrictions

Original requirement IDs: MSC-PF-6, MSC-PF-7.

**Applicability:** Outer Encryption Component features, including manufacturer-server contact.

**Requirement strength and applicability:** Threshold blocking or corresponding Objective disabling.

**Single theorem target:** `msc_outer_third_party_services`

**AI interpretation for later formalization:** Every service or feature enabling an Outer Encryption Component to contact a third-party server is blocked at threshold or disabled at objective.

**Alternative logic:**

- MSC-PF-6 or MSC-PF-7.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u004` (PDF page 45):

> MSC-PF-6 Any service or feature that allows an Outer Encryption Component to contact a third-party server (such as one maintained by the manufacturer) must be blocked. T MSC-PF-7

- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u005` (PDF page 45):

> MSC-PF-7 Any service or feature that allows an Outer Encryption Component to contact a third party server (such as one maintained by the manufacturer) must be disabled. O MSC-PF-6

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-PF-6 | T | MSC-PF-7 |
| MSC-PF-7 | O | MSC-PF-6 |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s001`: Table 16.
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s002`: Port Filtering (PF) Solution Components Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-038"></a>

## RG-038: IP header and multicast filtering

Original requirement IDs: MSC-PF-9, MSC-PF-10, MSC-PF-11, MSC-PF-12.

**Applicability:** External Outer traffic; all VPN Gateways according to deployed IP version.

**Requirement strength and applicability:** PF-9/11/12 are T=O; PF-10 is Objective with a blank Alternatives cell.

**Single theorem target:** `msc_ip_header_and_multicast_filtering`

**AI interpretation for later formalization:** Outer Encryption Components drop external multicast, VPN Gateways admit only the specified IPv4 Protocol or IPv6 Next Header values, and the selected IPv4 Outer-IPsec objective drops packets containing IP options.

**Qualifications and exceptions:**

- PF-10 has no stated threshold alternative; its blank table cell remains visible for review.

Open issues: REQ-I10.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u004.s004` (PDF page 21):

> Multicast messages received on external interfaces of the Outer Encryption Component must be dropped.

- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u007` (PDF page 45):

> MSC-PF-9 Multicast messages received on external interfaces of Outer Encryption Components must be dropped. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u008` (PDF page 45):

> MSC-PF-10 For solutions using IPv4, Outer VPN Gateways using IPsec must drop all packets that use IP options. O

- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u009` (PDF page 45):

> MSC-PF-11 For solutions using IPv4, each VPN Gateway must only accept packets with Transmission Control Protocol (TCP), User Datagram Protocol (UDP), ESP, or ICMP in the IPv4 Protocol field and drop all other packets. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u010` (PDF page 45):

> MSC-PF-12 For solutions using IPv6, each VPN Gateway must only accept packets with ESP, TCP, UDP, or ICMPv6 in the IPv6 Next Header field and drop all other packets. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-PF-9 | T=O | (blank) |
| MSC-PF-10 | O | (blank) |
| MSC-PF-11 | T=O | (blank) |
| MSC-PF-12 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s001`: Table 16.
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s002`: Port Filtering (PF) Solution Components Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-039"></a>

## RG-039: Outer Gray-interface allowlist and default denial

Original requirement IDs: MSC-PF-8, MSC-PF-13, MSC-PF-15, MSC-PF-17, MSC-PF-18, MSC-PF-19, MSC-PF-20.

**Applicability:** Gray interfaces of Outer Encryption Components; HTTP clause applies when CDP/OCSP is on the Gray data plane.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_outer_gray_interface_policy`

**AI interpretation for later formalization:** Outer Gray interfaces admit the specified same-level Inner tunnel traffic, approved management/control traffic, and conditional revocation HTTP; restrict management initiation to Gray AWs except Outer logging/authentication; enforce source reachability and peer addressing; and deny traffic outside PF-8, PF-13, PF-15, and PF-19.

**Qualifications and exceptions:**

- The source’s same-level permit rules conflict with §5.2’s same-level prevention sentence.
- PF-17’s address-only restriction must be reconciled with explicit management/control and revocation exceptions, rather than erasing those exceptions.
- The PF-20 reference list is preserved exactly.

Open issues: REQ-I02, REQ-I09.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u006` (PDF page 45):

> MSC-PF-8 Management plane traffic must only be initiated from a Gray AW with the exception of logging or authentication traffic that may be initiated from Outer Encryption Components. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u011` (PDF page 45):

> MSC-PF-13 The Gray Network interfaces of Outer Encryption Components must allow IKE and IPsec, or MKA and MACsec traffic, as appropriate, between two Inner Encryption Components protecting networks of the same security level or that is being used for management of the Gray Network. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u013` (PDF page 45, 46):

> MSC-PF-15 If the CDP/OCSP is on the gray data plane, the Gray Network interfaces of Outer VPN Gateways must T=O allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and the CDPs/OCSP Responders) and block all other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

- `CSFC-MSC-1.3.0-4e40e3d83708:p046:u004` (PDF page 46):

> MSC-PF-17 The Gray Network interfaces of Outer Encryption Components must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p046:u005` (PDF page 46):

> MSC-PF-18 The Gray Network interfaces of Outer Encryption Components must block all packets whose source address does not match a list of addresses or address ranges known to be reachable from the interface where the packet was received. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p046:u006` (PDF page 46):

> MSC-PF-19 The Gray Network interfaces of Outer Encryption Components must allow management and control plane protocols (as defined in this CP) that have been approved by policy. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p046:u007` (PDF page 46):

> MSC-PF-20 The Gray Network interfaces of Outer Encryption Components must deny all traffic that is not explicitly allowed by requirements MSC-PF-8, MSC- PF-13, MSC-PF-15, or MSC-PF-19. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-PF-8 | T=O | (blank) |
| MSC-PF-13 | T=O | (blank) |
| MSC-PF-15 | T=O | (blank) |
| MSC-PF-17 | T=O | (blank) |
| MSC-PF-18 | T=O | (blank) |
| MSC-PF-19 | T=O | (blank) |
| MSC-PF-20 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s001`: Outer Encryption Components are also responsible for filtering traffic on its Gray Network interfaces to prevent Inner Encryption Components for networks of the same security level from being able to send packets to one another.
- `CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s002`: Since this filtering is primarily based on the source and destination addresses in the packet on a Gray Network, the Gray Network itself must use an addressing scheme that supports the necessary filtering (such as using separate address ranges for the Gray interfaces of Inner Encryption Components supporting each Red Network).
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s001`: Table 16.
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s002`: Port Filtering (PF) Solution Components Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p045:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p046:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u001.s001`: CRL Distribution Point (CDP) – A web server that hosts a copy of a CRL issued by a CA for VPN Gateways to download (see CSfC Key Management Requirements Annex).
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u009.s001`: Security Level – The combination of classification level, list of compartments, dissemination controls, and other controls applied to the information within a network.

<a id="rg-040"></a>

## RG-040: Gray Firewall allowlist and cross-level denial

Original requirement IDs: MSC-PF-23, MSC-PF-25, MSC-PF-27, MSC-PF-28, MSC-PF-29, MSC-PF-30, MSC-PF-31, MSC-PF-32.

**Applicability:** Required Gray Firewalls and their data/management interfaces.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_gray_firewall_allowlist`

**AI interpretation for later formalization:** A required Gray Firewall permits the listed same-level tunnel, revocation HTTP, physical-management-port, and control-plane traffic; enforces peer address and source-reachability restrictions; denies traffic outside the enumerated exceptions; and blocks traffic between Inner VPN Gateways of different classification levels.

**Qualifications and exceptions:**

- PF-32 says classification levels, while other clauses use the broader security-level definition; both are retained.
- PF-28 address restrictions coexist with the explicit management/control/HTTP exceptions.
- HTTP beyond revocation checking is blocked.

Open issues: REQ-I02, REQ-I09.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p046:u010` (PDF page 46):

> MSC-PF-23 If a Gray Firewall is required (i.e., networks of multiple protection levels are included in the solution) the Gray Firewall must allow appropriate traffic (IKE, IPsec, MKA and MACsec) between Red Networks operating at the same security level. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p046:u012` (PDF page 46, 47):

> MSC-PF-25 If a Gray Firewall is required, the Gray Firewall must allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and CDPs/OCSP Responders) and block all T=O other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u004` (PDF page 47):

> MSC-PF-27 If a Gray Firewall is required, the Gray Firewall must only accept management traffic on the physical ports connected to the Gray Management Network. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u005` (PDF page 47):

> MSC-PF-28 If a Gray Firewall is required, the Gray Firewall must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u006` (PDF page 47):

> MSC-PF-29 If a Gray Firewall is required, the Gray Firewall must block all packets whose source address does not match a list of addresses or address ranges known to be reachable from the interface where the packet was received. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u007` (PDF page 47):

> MSC-PF-30 If a Gray Firewall is required, the Gray Firewall must allow control plane traffic (e.g., NTP and DHCP). T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u008` (PDF page 47):

> MSC-PF-31 If a Gray Firewall is required, the Gray Firewall must deny all traffic that is not explicitly allowed by requirements MSC-PF-23, MSC-PF-25, MSC-PF-27 or MSC-PF-30. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u009` (PDF page 47):

> MSC-PF-32 The Gray Firewall must block all traffic routed to and between two or more Inner VPN Gateways of different classification levels. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-PF-23 | T=O | (blank) |
| MSC-PF-25 | T=O | (blank) |
| MSC-PF-27 | T=O | (blank) |
| MSC-PF-28 | T=O | (blank) |
| MSC-PF-29 | T=O | (blank) |
| MSC-PF-30 | T=O | (blank) |
| MSC-PF-31 | T=O | (blank) |
| MSC-PF-32 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s001`: The Gray AWs along with all Gray Management Services, are physically connected to the Gray Firewall, if required, or the Outer Encryption Component.
- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s002`: The Gray Firewall maintains separate Access Control Lists (ACLs) to permit management traffic to/from the Gray Management Services but prohibits such traffic from all other components.
- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s003`: These ACLs ensure that approved management traffic is only capable of flowing in the intended direction.
- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s004`: This architecture provides the separation necessary for two independent layers of protection.
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s001`: Table 16.
- `CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s002`: Port Filtering (PF) Solution Components Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p046:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u001.s001`: CRL Distribution Point (CDP) – A web server that hosts a copy of a CRL issued by a CA for VPN Gateways to download (see CSfC Key Management Requirements Annex).
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u009.s001`: Gray Firewall – A traffic filtering firewall placed on the Gray Network to provide additional separation between flows of singly-encrypted data of different security levels.
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u009.s001`: Security Level – The combination of classification level, list of compartments, dissemination controls, and other controls applied to the information within a network.

<a id="rg-041"></a>

## RG-041: Control-plane approval, defaults, and service location

Original requirement IDs: MSC-SR-1.

**Applicability:** Control-plane services and protocols, Red/Gray/Black networks, and Solution Owner/AO approvals.

**Requirement strength and applicability:** Mandatory service placement, approval restrictions, and Layer-3 default; conditional protocol permissions.

**Single theorem target:** `msc_control_plane_policy_and_services`

**AI interpretation for later formalization:** Control-plane services reside inside the relevant encryption layer; unapproved protocols are blocked or disabled; necessary standards-conformant Layer 2 protocols are permitted, Layer 3 defaults to disabled unless AO policy allows it, and Red/Gray multicast and existing routing protocols follow their stated AO conditions. Networks may independently select IPv4 or IPv6, and appropriate protocols may be selected where the CP does not specify one.

**Qualifications and exceptions:**

- Red, Gray, and Black can independently use IPv4 or IPv6 unless a specific clause says otherwise.
- The general absence of a prescribed protocol does not override specific IPsec, revocation, or Outer-routing restrictions.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s001` (PDF page 13):

> In general, this CP does not impose detailed requirements on control plane traffic, although control plane protocols may be used to implement certain requirements.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s002` (PDF page 13):

> For example, requirements MSC-SR-3 and MSC-SR-4 (see Section 10.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s003` (PDF page 13):

> 1) require that time synchronization be performed but does not require the use of any particular time synchronization protocol or technique.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s004` (PDF page 13):

> Notable exceptions are for IPsec session establishment and for certain certificate status distribution scenarios where, given their impact on the security of the solution, this CP does provide detailed requirements.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u007.s001` (PDF page 13):

> Except as otherwise specified in this CP, the use of specific control plane protocols is left to the Solution Owner to approve.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u007.s002` (PDF page 13):

> The Solution Owner must disable or block any unapproved control plane protocols.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u003.s001` (PDF page 21):

> Throughout this CP, when IP traffic is discussed, it may refer to either Internet Protocol version 4 (IPv4) or Internet Protocol version 6 (IPv6) traffic, unless otherwise specified, as the MSC Solution is agnostic to most named data handling protocols.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u003.s002` (PDF page 21):

> In addition, Red, Gray and Black Networks can run either IPv4 or IPv6, and each network can independently make that decision.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u003.s003` (PDF page 21):

> In the remainder of the CP, if no protocols or standards are specified then any appropriate protocols may be used to achieve the objective.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u004.s001` (PDF page 21):

> Public standards conformant Layer 2 control protocols, such as ARP, are allowed as necessary to ensure the operational usability of the network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u004.s002` (PDF page 21):

> Public standards conformant Layer 3 control protocols, such as Internet Control Message Protocol (ICMP), may be allowed based on local Authorizing Official (AO) policy, but the default configuration of this solution is for all Layer 3 control protocols to be disabled.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u004.s003` (PDF page 21):

> Red and Gray Network multicast messages and Internet Group Management Protocol or Multicast Listener Discovery may also be allowed depending on local AO policy.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u005.s001` (PDF page 21):

> The MSC Solution can be implemented to take advantage of standards-based routing protocols that are already used in the Black and/or Red Network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u005.s002` (PDF page 21):

> For example, networks that currently use Generic Routing Encapsulation (GRE), Multiprotocol Label Switching or OSPF protocols can continue to use these in conjunction with this solution to provide routing as long as the AO approves their use.

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u003` (PDF page 35):

> MSC-SR-1 Network services provided by control plane protocols (such as NTP) must be located on the inside network (i.e., Gray Network for Outer Encryption Component and Red Network for Inner Encryption Component). T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u011.s001` (PDF page 56):

> • The AO ensures that any Layer 2 or Layer 3 control plane protocols that are used in the solution are necessary for the operation of the network and that local policy supports their use.

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-1 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u008.s001`: Control plane traffic consists of standard protocols necessary for the network to function.
- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u008.s002`: Unlike data or management plane traffic, control plane traffic is typically not initiated directly on behalf of a user or a system administrator.
- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u008.s003`: Examples of control plane traffic include, but are not limited to the following: • Network address configuration (e.
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u001.s002`: g.
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u001.s003`: , Dynamic Host Configuration Protocol (DHCP), Neighbor Discovery Protocol (NDP))
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u002.s001`: • Address resolution (e.
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u002.s002`: g.
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u002.s003`: , Address Resolution Protocol (ARP), NDP)
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u003.s001`: • Time synchronization (e.
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u003.s002`: g.
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u003.s003`: , Network Time Protocol (NTP), Precision Time Protocol)
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u004.s001`: • Route advertisement (e.
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u004.s002`: g.
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u004.s003`: , Routing Information Protocol, Open Shortest Path First (OSPF), Intermediate System to Intermediate System, Border Gateway Protocol (BGP))
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u005.s001`: • Certificate status distribution (e.
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u005.s002`: g.
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u005.s003`: , Online Certificate Status Protocol (OCSP), Hypertext Transfer Protocol (HTTP) download of Certificate Revocation Lists (CRLs))
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u002`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-042"></a>

## RG-042: Layer-specific trusted time synchronization

Original requirement IDs: MSC-SR-3, MSC-SR-4.

**Applicability:** Encryption Components and layer-specific management services; Gray Firewall when present.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_trusted_time_synchronization`

**AI interpretation for later formalization:** Inner Encryption Components and Red Management Services synchronize to a trusted Red time source, while Outer Encryption Components, Gray Management Services, and any Gray Firewall synchronize to a trusted source in the Gray Management Network.

**Qualifications and exceptions:**

- No specific synchronization protocol or technique is required by the source.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u005` (PDF page 35):

> MSC-SR-3 The time of day on the Inner Encryption Component and Red Management Services must be synchronized to a trusted time source located in the Red Network. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u006` (PDF page 35):

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-3 | T=O | (blank) |
| MSC-SR-4 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s002`: For example, requirements MSC-SR-3 and MSC-SR-4 (see Section 10.
- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s003`: 1) require that time synchronization be performed but does not require the use of any particular time synchronization protocol or technique.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u002`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-043"></a>

## RG-043: Default credentials, DNS, and remote bootstrap

Original requirement IDs: MSC-SR-5, MSC-SR-19, MSC-SR-20, MSC-SR-21.

**Applicability:** All Solution Components and network-device DNS lookup.

**Requirement strength and applicability:** SR-5/20/21 are T=O; SR-19 is Objective/Optional.

**Single theorem target:** `msc_defaults_dns_and_boot_configuration`

**AI interpretation for later formalization:** Solution Components change or remove default access-control values, specify DNS server addresses or disable DNS services, and disable automatic remote boot-time configuration; the optional objective disables network-device DNS lookup.

**Qualifications and exceptions:**

- Specified DNS servers and disabled DNS are alternatives in SR-20.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u007` (PDF page 35):

> MSC-SR-5 Default accounts, passwords, community strings, and other default access control mechanisms for all Solution Components must be changed or removed. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u009` (PDF page 36):

> MSC-SR-19 DNS lookup services on network devices must be disabled. O Optional

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u010` (PDF page 36):

> MSC-SR-20 DNS server addresses on Solution Components must be specified or DNS services must be disabled. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u011` (PDF page 36):

> MSC-SR-21 Automatic remote boot-time configuration services must be disabled on all solution components (i.e., automatic configuration via Trivial File Transfer Protocol on boot). T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-5 | T=O | (blank) |
| MSC-SR-19 | O | Optional |
| MSC-SR-20 | T=O | (blank) |
| MSC-SR-21 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u002`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-044"></a>

## RG-044: Layer-specific administration and management-plane separation

Original requirement IDs: MSC-SR-18, MSC-DM-3, MSC-DM-4, MSC-DM-5, MSC-DM-6, MSC-DM-17, MSC-DM-25.

**Applicability:** All AWs, Solution Components, and Red/Gray management and data planes.

**Requirement strength and applicability:** Mandatory administrative separation; administrative functionality may be distributed across the AW set.

**Single theorem target:** `msc_layered_administrative_separation`

**AI interpretation for later formalization:** Each component has adequate AW administration, with at least one Red AW and one Gray AW; Inner/Red and Outer/Gray management use their respective networks and distinct AWs, dedicated management interfaces, and the stated physical, cryptographic, and ACL separation from data traffic; Gray Management has no direct connection to NIPRNet or another unclassified network not dedicated to CSfC administration.

**Qualifications and exceptions:**

- Physical and cryptographic separation in §4.1.4 and the minimum Gray Firewall ACL separation in DM-25 apply together. The minimum ACL condition does not waive the stronger separation conditions.
- Control-plane traffic has no general separation requirement unless specified.
- Gray management attachment is to the required Gray Firewall or otherwise the Outer Component.

Scope or resolved-interpretation notes: REQ-I07.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s006` (PDF page 11):

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s007` (PDF page 11):

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s003` (PDF page 11):

> Gray Management Services are physically connected to the Gray Firewall and include, at a minimum, a AW that can be a physical workstation or Virtual Machine (VM).

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s005` (PDF page 11):

> This CP requires the management of Gray Network components through a Gray AW.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s006` (PDF page 11):

> As a result, neither Red nor Black AWs are permitted to manage the Outer Encryption Component, Gray Firewall, or Gray Management Services.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s007` (PDF page 11, 12):

> Additionally, the Gray AWs are prohibited from managing Inner Encryption Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u001.s002` (PDF page 12):

> Inner Encryption Components must be managed from a Red AW.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s001` (PDF page 13):

> Data plane and management plane traffic must be physically and cryptographically separated from one another.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s002` (PDF page 13):

> Use of a Virtual Local Area Network (VLAN) alone is not sufficient to separate data plane and management plane traffic.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s003` (PDF page 13):

> As a result, a solution may have a Gray Data Network and a Gray Management Network that are separate from one another, where the components on the Gray Management Network are used to manage the components on the Gray Data Network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s004` (PDF page 13):

> Unless otherwise specified given that some control plane traffic is necessary for a network to function, there is no general requirement that control plane traffic be similarly separated.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001` (PDF page 24):

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s002` (PDF page 24):

> The Gray AW is not permitted to maintain, monitor, or control Inner Encryption Components or Red Management Services.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s003` (PDF page 24):

> All MSC Solutions must have at least one Gray AW.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001` (PDF page 26):

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s002` (PDF page 26):

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s003` (PDF page 26):

> All MSC Solutions will have at least one Red AW.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s001` (PDF page 30):

> Each component in the solution has one or more AWs that maintain, monitor, and control all security functions for that component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s002` (PDF page 30):

> It should be noted that all of the required administrative functionality does not need to be present in each individual management component, but the entire set of AWs must collectively meet administrative functionality requirements.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u005.s001` (PDF page 30):

> Given the architecture of the solution, each layer has its own distinct administration LAN or VLAN; the Inner Encryption Component and supporting components are managed from the Red Management Services, and the Outer Encryption Component and supporting components are managed from the Gray Management Services.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s001` (PDF page 30):

> The Gray AWs along with all Gray Management Services, are physically connected to the Gray Firewall, if required, or the Outer Encryption Component.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s002` (PDF page 30):

> The Gray Firewall maintains separate Access Control Lists (ACLs) to permit management traffic to/from the Gray Management Services but prohibits such traffic from all other components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s003` (PDF page 30):

> These ACLs ensure that approved management traffic is only capable of flowing in the intended direction.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s004` (PDF page 30):

> This architecture provides the separation necessary for two independent layers of protection.

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u008` (PDF page 36):

> MSC-SR-18 Solution Components must only be configured over an interface dedicated for management. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u002` (PDF page 48):

> MSC-DM-3 AWs must connect from an internal port. Specifically, the Inner Encryption Component must be managed from the Red Network, and the Outer Encryption Component and Gray Firewall, if present, must be managed from the Gray Network. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u003` (PDF page 48):

> MSC-DM-4 The Red Management Network must be used exclusively for all management of Inner Encryption Components and Solution Components within the Red Network. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u004` (PDF page 48):

> MSC-DM-5 The Gray Network must be used exclusively for all management of the Outer Encryption Component, Gray Firewall, if present, and Solution Components within the Gray Network. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u005` (PDF page 48):

> MSC-DM-6 The Gray Management Network must not be directly connected to the Non-secure Internet Protocol Router Network (NIPRNet) or any other Unclassified network not dedicated to the administration of CSfC solutions. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u005` (PDF page 49):

> MSC-DM-17 The same AW must not be used to manage Inner Encryption Components and Outer Encryption Components. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u013` (PDF page 49):

> MSC-DM-25 The Gray Management and Gray Data Networks must be at minimum logically separated by the Gray Firewall using ACL. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-18 | T=O | (blank) |
| MSC-DM-3 | T=O | (blank) |
| MSC-DM-4 | T=O | (blank) |
| MSC-DM-5 | T=O | (blank) |
| MSC-DM-6 | T=O | (blank) |
| MSC-DM-17 | T=O | (blank) |
| MSC-DM-25 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s001`: Table 17.
- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s002`: Device Management (DM) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-045"></a>

## RG-045: Dedicated, protected, hardened Administrative Workstations

Original requirement IDs: MSC-DM-1, MSC-DM-2, MSC-DM-23, MSC-DM-24, MSC-DM-26, MSC-DM-27, MSC-DM-28.

**Applicability:** Physical AWs, AW VMs, and their hosts/servers.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_dedicated_and_hardened_aws`

**AI interpretation for later formalization:** Physical AWs and AW virtual machines use the stated dedicated hardware/VM boundaries, reside in protected facilities, exclude prohibited functions and non-CSfC uses, follow vendor and organizational hardening/patching policy, and power off when unused.

**Qualifications and exceptions:**

- §6.2 prohibits AW hosts from hosting provisioning/enrollment/registration/SIEM VMs. DM-24 requires separate workstations or VMs for those functions. Both restrictions apply: a separate VM must also respect the AW host restriction.
- No provisioner or SIEM function is silently assigned to an AW.

Scope or resolved-interpretation notes: REQ-I06.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s001` (PDF page 30):

> AWs may be virtual machines (VMs) on a physical host/server that is dedicated to hosting AWs VMs.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002` (PDF page 30):

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s003` (PDF page 30):

> A physical host/server that hosts AWs VMs may not host VMs used for non-CSfC purposes.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004` (PDF page 30):

> If an AW is a physical workstation, then that workstation cannot also be used for provisioning, enrollment, certificate registrations, SIEM services, or for any non- CSfC functions.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s005` (PDF page 30):

> AWs (physical or virtual) must be configured, patched, and operated in accordance to the organizational or local policy.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s006` (PDF page 30):

> AWs must also be powered off when not in use.

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u016` (PDF page 47):

> MSC-DM-1 If using physical AWs, they must be dedicated for the purposes given in this CP and must be physically separated from workstations used to manage non-CSfC solutions. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u017` (PDF page 47):

> MSC-DM-2 AWs (or hosts/servers hosting VMs serving as AWs) must physically reside within a protected facility where CSfC solution(s) are managed. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u011` (PDF page 49):

> MSC-DM-23 Hosts/servers for management VMs may not host VMs that perform non-CSfC functions. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u012` (PDF page 49):

> MSC-DM-24 VMs that perform management services must not also perform other functions within the solution (i.e., provisioning, enrollment, CA registration, SIEM, etc. must be performed by separate workstations or VMs). T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u014` (PDF page 49):

> MSC-DM-26 AWs (physical or virtual) must be configured, patched, and operated in accordance with applicable Operating System vendor hardening guide and the organizational or local policy. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u015` (PDF page 49):

> MSC-DM-27 AWs (physical or virtual) must be powered off when not in use. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u016` (PDF page 49):

> MSC-DM-28 The AW must not also be used for provisioning, certificate registrations, and SIEM services. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-DM-1 | T=O | (blank) |
| MSC-DM-2 | T=O | (blank) |
| MSC-DM-23 | T=O | (blank) |
| MSC-DM-24 | T=O | (blank) |
| MSC-DM-26 | T=O | (blank) |
| MSC-DM-27 | T=O | (blank) |
| MSC-DM-28 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s001`: Table 17.
- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s002`: Device Management (DM) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u015`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-046"></a>

## RG-046: Management transport protection and local exceptions

Original requirement IDs: MSC-DM-7, MSC-DM-8.

**Applicability:** All administrative and monitoring traffic, local direct connections, same-LAN/VLAN traffic, and remote Black transport.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_secure_management_transport`

**AI interpretation for later formalization:** Solution Components are managed securely through an AW over an NSA-approved remote solution or locally; management addresses are minimized, network management uses the listed secure protocols, direct physical local management has its stated exception, and Black-network management receives two approved encryption layers with the local LAN/VLAN qualification retained.

**Qualifications and exceptions:**

- §5.2 broadly says Gray AW traffic must include two layers, while §6.2 gives local and LAN/VLAN qualifications.
- The LAN/VLAN exception most immediately follows the Black-network two-layer sentence; it is not silently interpreted as permission for all same-LAN management to be plaintext.
- The same-site example says CNSA algorithms are unnecessary there; listed secure protocols remain separately stated.

Open issues: REQ-I03.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u007.s001` (PDF page 12):

> Management plane traffic is used to configure and monitor Solution Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u007.s002` (PDF page 12):

> It includes the communications between a system administrator and a component, as well as the logs and other status information forwarded from a Solution Component to a SIEM, or similar repository.

- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u007.s003` (PDF page 12):

> Management plane traffic on Red and Gray Networks is encapsulated within the Secure Shell version 2 (SSHv2), IPsec, MACsec, or Transport Layer Security (TLS) 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p012:u007.s004` (PDF page 12):

> 2 or later protocols.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u002.s002` (PDF page 24):

> As described in this CP, Management traffic on a Gray Network, which originates from the AW, must include two layers of encryption.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s001` (PDF page 30):

> Management traffic for all MSC Solution Components is always encrypted to protect confidentially and integrity, except in the case where components are locally managed through a direct physical connection (i.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s002` (PDF page 30):

> e.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s003` (PDF page 30):

> , serial cable from a Gray AW to the Outer Encryption Component).

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s004` (PDF page 30):

> Management traffic must be encrypted with SSHv2, TLS 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s005` (PDF page 30):

> 2 or later, IPsec or MACsec.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s006` (PDF page 30):

> When components are managed over the Black Network, a CSfC Solution must be implemented to provide two layers of approved encryption.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s007` (PDF page 30):

> This requirement is not applicable if the MSC Solution Components are managed from the same LAN or VLAN.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s008` (PDF page 30):

> For example, a Gray AW residing within the Gray Management Services at the same site as the Outer Encryption Component need not use CNSA Suite algorithms since this traffic does not traverse an untrusted network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u006` (PDF page 48):

> MSC-DM-7 All components must be configured to restrict the IP address range for the network administration device to the smallest range possible. Note that locally managing Solution Components is also acceptable. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u007` (PDF page 48):

> MSC-DM-8 All administration of Solution Components must securely be performed from an AW remotely using an NSA-approved solution (e.g., CP or High Assurance encryptor), or by managing the Solution Components locally. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-DM-7 | T=O | (blank) |
| MSC-DM-8 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s001`: Because the central management site manages the Encryption Components at the other sites over the network, encryption is used to logically separate data and management traffic as it passes between sites.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s002`: Central Management of the Gray Network must be done in accordance with the CSfC Enterprise Gray Implementation Requirements Annex.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s003`: Red management traffic is encrypted before being routed through the Inner and Outer Encryption Components to another site.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s004`: As a result, all management traffic between sites is encrypted at least twice before traversing the Black Network.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s005`: See the CSfC Enterprise Gray Implementation Requirements Annex for additional details and requirements.
- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s001`: Table 17.
- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s002`: Device Management (DM) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u014.s001`: Locally Managed Device – A device that is being managed by the direct connection of the AW to the device in a hardwired fashion (such as a console cable).
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u006.s001`: Remotely Managed Device – A device that is being managed by any other method besides that given in the definition of a Locally Managed Device.

<a id="rg-047"></a>

## RG-047: Administrator authentication and individual credentials

Original requirement IDs: MSC-DM-9, MSC-DM-10, MSC-DM-13, MSC-DM-29.

**Applicability:** Security Administrators, Solution Component administration, and AW accounts.

**Requirement strength and applicability:** DM-9/10 are Threshold/Objective alternatives; DM-29 is T=O; DM-13 is Objective/Optional.

**Single theorem target:** `msc_administrator_authentication`

**AI interpretation for later formalization:** Security Administrators authenticate before administrative functions, using CNSA certificates under the objective alternative; each AW administrator has unique credentials without group accounts, and the optional NIST SP 800-63 objective applies when selected.

**Alternative logic:**

- MSC-DM-9 or MSC-DM-10.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u008` (PDF page 48):

> MSC-DM-9 Security Administrators must authenticate to Solution Components before performing administrative functions. T MSC-DM-10

- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u009` (PDF page 48):

> MSC-DM-10 Security Administrators must authenticate to Solution Components with CNSA Suite compliant certificates before performing administrative functions. O MSC-DM-9

- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u012` (PDF page 48):

> MSC-DM-13 Security Administrators must use authentication methods in accordance with NIST SP 800-63. O Optional

- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u017` (PDF page 49):

> MSC-DM-29 Each AW admin must have a unique login credential. Group accounts are prohibited. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-DM-9 | T | MSC-DM-10 |
| MSC-DM-10 | O | MSC-DM-9 |
| MSC-DM-13 | O | Optional |
| MSC-DM-29 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s001`: Table 17.
- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s002`: Device Management (DM) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-048"></a>

## RG-048: Authorized provisioning and initial certificate requests

Original requirement IDs: MSC-DM-11, MSC-DM-12, MSC-DM-14.

**Applicability:** Initial provisioning of VPN and certificate-based MACsec components and their administrators.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_authorized_initial_provisioning`

**AI interpretation for later formalization:** The Solution Owner identifies authorized Security Administrators, who provision components out of band in a secured area before first use, initiate the required CSRs, deliver them to the appropriate Inner or Outer CA, and install unique signed certificates with their chains; AWs interacting with the Outer VPN CA reside on Gray.

**Qualifications and exceptions:**

- Installing an initial CRL is permitted rather than universally mandated by the provisioning prose.
- The certificate-based MACsec paragraph calls the inner device an “Inner VPN Gateway”; the source wording is retained as a terminology issue.
- PSK provisioning is covered by RG-027.

Open issues: REQ-I11.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u008.s001` (PDF page 29):

> This CP includes design details for the provisioning and management of Solution Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u008.s002` (PDF page 29):

> The MSC Solution Owner must identify authorized Security Administrators to perform configuration and management tasks.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u008.s003` (PDF page 29):

> The following sections describe the design in detail and Section 10.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u008.s004` (PDF page 29):

> 8 states specific configuration requirements that must be met to comply with this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s001` (PDF page 29):

> Provisioning is an out-of-band process performed in a physically secured area (e.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s002` (PDF page 29):

> g.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s003` (PDF page 29):

> , the Red Network location) where MSC Solution Components are configured and initialized before their first use.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s004` (PDF page 29):

> During the provisioning process, the Security Administrator configures the Outer Firewall, Outer Encryption Component, Gray Firewall, Gray Management Services, Inner Encryption Component, Red Management Services and Inner Firewall in accordance with the requirements of this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s001` (PDF page 29):

> For provisioning IPsec Outer VPN Gateways and Inner VPN Gateways generate a public/private key pair and output the public key in a Certificate Signing Request (CSR).

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002` (PDF page 29):

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s003` (PDF page 29):

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s004` (PDF page 29):

> 509 certificate.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s005` (PDF page 29):

> The Security Administrator then installs the unique signed certificate and the certificate chain, which consists of the signing CA’s certificate and the Trust Anchor certificate (e.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s006` (PDF page 29):

> g.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s007` (PDF page 29):

> , Root CA certificate).

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s008` (PDF page 29):

> The Security Administrator may also install an initial CRL.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s001` (PDF page 29):

> For provisioning Certificate-based MACsec, Outer Encryption Components and/or Inner Encryption Components generate a public/private key pair and output the public key in a CSR.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s002` (PDF page 29, 30):

> The Security Administrator delivers the Outer Encryption’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s002` (PDF page 30):

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s003` (PDF page 30):

> 509 certificate.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s004` (PDF page 30):

> The Security Administrator then installs the unique signed certificate and the certificate chain, which consists of the signing CA’s certificate and the Trust Anchor certificate (e.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s005` (PDF page 30):

> g.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s006` (PDF page 30):

> , Root CA certificate).

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s007` (PDF page 30):

> The Security Administrator may also install an initial CRL.

- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u010` (PDF page 48):

> MSC-DM-11 The MSC Solution Owner must identify the authorized Security Administrators to initiate certificate requests. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u011` (PDF page 48):

> MSC-DM-12 Authorized Security Administrators must initiate certificate signing requests for Solution Components as part of their initial keying within the solution. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u002` (PDF page 49):

> MSC-DM-14 AWs that interact with the Certificate Authority for the Outer VPN Gateways must be located on the Gray Network. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-DM-11 | T=O | (blank) |
| MSC-DM-12 | T=O | (blank) |
| MSC-DM-14 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s001`: Table 17.
- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s002`: Device Management (DM) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p048:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-049"></a>

## RG-049: Personnel clearance and Outer administration

Original requirement IDs: MSC-DM-22, MSC-RB-1.

**Applicability:** Security Administrators, Auditors, Integrators, Black Network Administrators, and Outer Component administration.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_personnel_clearance`

**AI interpretation for later formalization:** Security Administrators, Auditors, and Integrators hold the highest protected-data clearance, subject to the stated Black Network Administrator exception, and Outer administrators meet the highest Red classification at the Outer Component’s site.

**Qualifications and exceptions:**

- The site-scoped Outer rule and solution-scoped personnel rule remain separately visible.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u010` (PDF page 49):

> MSC-DM-22 Outer Encryption Components must only be managed by Security Administrators cleared to at least the highest level of classification of each Red Network supported by the Outer Encryption Component at the physical site the Outer Encryption Component is located. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u009` (PDF page 55):

> MSC-RB-1 The Security Administrators, Auditors, and Integrators must be cleared to the highest level of data protected by the MSC Solution. Black Network Administrators may be cleared at the Black Network security level. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-DM-22 | T=O | (blank) |
| MSC-RB-1 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s001`: Table 17.
- `CSFC-MSC-1.3.0-4e40e3d83708:p047:u014.s002`: Device Management (DM) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p049:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u007.s001`: Table 20.
- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u007.s002`: Role-Based (RB) Personnel Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u008`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-050"></a>

## RG-050: SIEM placement, collection, alerting, and log transport

Original requirement IDs: Prose-only.

**Applicability:** Deployed SIEMs, source components, and approved CDS-based Gray-to-Red monitoring.

**Requirement strength and applicability:** Conditional configuration descriptions; log encryption is stated as should; Gray SIEM deployment is explicitly optional.

**Single theorem target:** `msc_siem_collection_alerting_and_protection`

**AI interpretation for later formalization:** Deployed Red and Gray SIEM functions collect the stated component logs and flow data and provide the specified alerts. Log transport is recommended to use SSHv2, TLS 1.2 or later, IPsec, or MACsec encryption. Gray functions may move to a Red SIEM through an approved CDS, and a Gray SIEM is optional.

**Qualifications and exceptions:**

- Red SIEM mandatory status is not established merely by its description.
- The Continuous Monitoring Annex supplies additional monitoring obligations not present in this PDF.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s004` (PDF page 11):

> The Gray Management Services may also include a Security Information and Event Management (SIEM) unless the SIEM is implemented in the Red Network in conjunction with a cross domain solution (CDS) (see CSfC Continuous Monitoring Annex).

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u008.s001` (PDF page 24):

> Secure administration of components in the Gray Network and continuous monitoring of the Gray Network are essential roles provided by the Gray Management Services.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u008.s002` (PDF page 24):

> Gray Management Services are composed of multiple components that provide distinct security to the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u008.s003` (PDF page 24):

> This CP allows flexibility in the placement of some Gray Management Services as described below.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001` (PDF page 24):

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s002` (PDF page 24):

> Log data should be encrypted between the originating component and the Gray SIEM with SSHv2, TLS 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s003` (PDF page 24, 25):

> 2 or later, IPsec, or MACsec to maintain confidentiality and integrity of the log data.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s002` (PDF page 25):

> The SIEM is configured to provide alerts for specific events including if the Outer Encryption Component or Gray Firewall receives and drops any unexpected traffic that could indicate a compromise.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s003` (PDF page 25):

> These functions can also be performed on a Red SIEM using an approved CDS, as described in the CSfC Continuous Monitoring Annex.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s004` (PDF page 25):

> A Gray SIEM is not a mandatory component of the MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u011.s001` (PDF page 25):

> Secure administration of Inner Encryption Components and continuous monitoring of the Red Network are essential roles provided by the Red Management Services.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u011.s002` (PDF page 25):

> Red Management Services are composed of a number of components that provide distinct security to the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u011.s003` (PDF page 25):

> As described below, this CP allows flexibility in the placement of some Red Management Services.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001` (PDF page 26):

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s002` (PDF page 26):

> Log data should be encrypted between the originating component and the Red SIEM with SSHv2, TLS 1.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s003` (PDF page 26):

> 2 or later, IPsec, or MACsec to ensure confidentiality and integrity.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s004` (PDF page 26):

> The SIEM is configured to provide alerts for specific events.

- `CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s003` (PDF page 30):

> Implementations may employ a SIEM in the Gray Management Services for log management of Gray infrastructure components except where AOs use a CDS to move Gray Network log data to a Red SIEM.

<a id="rg-051"></a>

## RG-051: Cross Domain Solution approval conditions

Original requirement IDs: MSC-SR-22.

**Applicability:** Any deployed CDS, including SIEM-log transfer use.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_cross_domain_solution_conditions`

**AI interpretation for later formalization:** Any CDS used in the solution adheres to DoDI 8540.01 and the DISN Connection Process Guide and is on the National Cross Domain Strategy Management Office CDS Baseline.

**Qualifications and exceptions:**

- The three external conditions are conjunctive; their external contents are not reproduced.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u012` (PDF page 36):

> MSC-SR-22 If a CDS is being leveraged within the solution, then it must adhere with DoDI 8540.01, the DISN Connection Process Guide, and the CDS must be on the National Cross Domain Strategy Management Office CDS Baseline. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-22 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u002.s001`: Cross Domain Solution (CDS) – A form of controlled interface that provides the ability to manually and/or automatically access and/or transfer information between different security domains.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u002.s002`: [CNSSI 4009]

<a id="rg-052"></a>

## RG-052: Physical protection, authorized access, and disposal

Original requirement IDs: MSC-GD-1, MSC-GD-2, MSC-GD-3, MSC-SR-9, MSC-MD-11.

**Applicability:** Solution hardware, MACsec configuration files and physical access/disposal operations.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_physical_protection_access_and_disposal`

**AI interpretation for later formalization:** Solution Components other than the stated Outer Firewall exception receive the highest required classified physical protection, only authorized cleared or escorted personnel gain physical access, MACsec configuration copies receive CAK-level protection, and components are disposed of as classified unless AO-approved declassification procedures apply.

**Qualifications and exceptions:**

- GD-1 includes the highest level in interconnected MSC solutions; the narrower prose is not substituted for that clause.
- The Outer Firewall exception is attached to physical-protection classification; no blanket exception from every handling clause is inferred.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s002` (PDF page 11):

> All Gray Network components are physically protected at the same level as the Red Network components of the MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u006.s001` (PDF page 22):

> All the individual components within the solution must be physically protected to the level of the connected network with the highest classification/protection level.

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u006.s002` (PDF page 22):

> The only exception to this requirement would be the Outer Firewall if one is present in the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u008.s004` (PDF page 24):

> The Gray Management Services are physically protected as classified devices.

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u011` (PDF page 35):

> MSC-SR-9 Gray Network components must be physically protected to the level of the highest classified network. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u016` (PDF page 41, 42):

> MSC-MD-11 MACsec Device configuration files, whether printed or electronically copied, must be physically T=O protected to the highest classification of the MACsec Device's CAK.

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u013` (PDF page 50):

> MSC-GD-1 All Solution Components, with the exception of the Outer Firewall (if present), must be physically protected as classified devices, classified at the level of the network with the highest classification in the solution or in any other MSC Solutions with which it is interconnected. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u014` (PDF page 50):

> MSC-GD-2 Only authorized and appropriately cleared (or escorted) administrators and security personnel must have physical access to the Solution Components. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u015` (PDF page 50):

> MSC-GD-3 All components of the solution must be disposed of as classified devices, unless declassified using AO-approved procedures. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-GD-1 | T=O | (blank) |
| MSC-GD-2 | T=O | (blank) |
| MSC-GD-3 | T=O | (blank) |
| MSC-SR-9 | T=O | (blank) |
| MSC-MD-11 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u002`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s001`: Table 12.
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s002`: MACsec Device (MD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p041:u005`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p042:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s001`: Table 18.
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s002`: Use and Handling of Solutions (GD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u012`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-053"></a>

## RG-053: Parallel Inner components and distinct Outer internal interfaces

Original requirement IDs: MSC-SR-10, MSC-SR-16.

**Applicability:** A site with multiple Red Networks or multiple Inner Encryption Components sharing an Outer Component.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_shared_outer_interface_topology`

**AI interpretation for later formalization:** Inner Encryption Components sharing an Outer Encryption Component are arranged in parallel, and that Outer Component has a unique physical internal interface for each Red Network without VLAN trunking of multiple enclaves.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u012` (PDF page 35):

> MSC-SR-10 The Outer Encryption Component must use a unique physical internal interface for each Red Network in the MSC Solution (i.e., VLAN trunking of multiple enclaves is not permitted). T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u006` (PDF page 36):

> MSC-SR-16 When multiple Inner Encryption Components share an Outer Encryption Component, they must be placed in parallel. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-10 | T=O | (blank) |
| MSC-SR-16 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s001`: A single implementation of the MSC Solution may support Red Networks of different security levels.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s002`: The MSC Solution provides secure connectivity between the Red Networks within each security level while preventing Red Networks of different security levels from communicating with one another.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s003`: This enables a customer to use the same physical infrastructure to carry traffic from multiple networks.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s004`: Although each Red Network requires its own Inner Encryption Component, a site may use a single Outer Encryption Component to encrypt and transport traffic that has been encrypted by Inner Encryption Components of varying security levels.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u002`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-054"></a>

## RG-054: Interoperable components across communicating sites

Original requirement IDs: MSC-SR-2.

**Applicability:** Communicating sites and their Inner and Outer tunnels.

**Requirement strength and applicability:** Interoperability is T=O; testing in §4 is recommended.

**Single theorem target:** `msc_site_interoperability`

**AI interpretation for later formalization:** Every pair of sites that needs to communicate selects interoperable components for each tunnel, with interoperability testing recommended despite product-list eligibility.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u001.s003` (PDF page 11):

> Products listed on the CSfC Components List are not guaranteed to be interoperable with all other products on the CSfC Components List.

- `CSFC-MSC-1.3.0-4e40e3d83708:p011:u001.s004` (PDF page 11):

> Customers and Integrators should perform interoperability testing to ensure the components selected for their MSC Solution are interoperable.

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u004` (PDF page 35):

> MSC-SR-2 Sites that need to communicate must ensure that Encryption Components selected by each site for each tunnel are interoperable. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-2 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s001`: For independently managed sites, each site performs the administration of its own Encryption Components.
- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s002`: If Certification Authorities (CAs) are part of the MSC Solution, each site has the option to use either locally run CAs that they manage and control or, where available, enterprise CAs that are not necessarily managed by the Solution Owner.
- `CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s003`: Each site needs to ensure that the Encryption Components selected interoperate with those at the other sites.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s001`: As shown in Figure 4, if remote management is used, personnel at a single geographic site administer and perform keying and device management for all the sites included in the solution.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s002`: In this case, because the administration is done by one group of Security Administrators, CA Administrators, and Key Generation Solution Administrators (see Section 12), they ensure the interoperability of each site as new sites are added.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003`: At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s004`: If available, enterprise CAs should be used.
- `CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005`: If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u002`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-055"></a>

## RG-055: Firewall requirements when combining capability packages

Original requirement IDs: MSC-SR-11, MSC-SR-13.

**Applicability:** Solutions combining MSC with other CSfC capability packages.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_combined_cp_firewalls`

**AI interpretation for later formalization:** When MSC is combined with another CSfC solution, a required Gray Firewall is included and any Inner Firewall requirements imposed by a combined data-in-transit/end-user-device CP are followed; the standalone MSC CP does not itself require an Inner Firewall.

**Qualifications and exceptions:**

- Applicable companion-CP requirements remain external dependencies.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s001` (PDF page 25):

> An Inner Firewall is located between the Inner Encryption Component and the Red Network.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s002` (PDF page 25):

> In this CP, an Inner Firewall is not required.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s003` (PDF page 25):

> If the MSC Solution is deployed with solutions from other CSfC CPs then those CPs will specify the Inner Firewall requirements.

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u013` (PDF page 35):

> MSC-SR-11 A Gray Firewall must be implemented if the MSC Solution is combined with another CSfC solution that requires a Gray Firewall. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u003` (PDF page 36):

> MSC-SR-13 If the MSC Solution is combined with other CSfC data-in-transit solutions that include end user devices, the Inner Firewall requirements from that CP must be followed. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-11 | T=O | (blank) |
| MSC-SR-13 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u002`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-056"></a>

## RG-056: Approved physical paths out of Red Networks

Original requirement IDs: MSC-SR-14.

**Applicability:** All Red-network egress paths.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_approved_red_egress_paths`

**AI interpretation for later formalization:** Every physical path leaving a Red Network uses a conforming MSC solution or an AO-approved data-in-transit protection solution, allowing the stated coexistence of an NSA-certified product path and a CP-conforming CSfC path.

**Qualifications and exceptions:**

- The source footnote permits parallel government-certified and CSfC protected egress paths; it does not authorize unprotected paths.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u004` (PDF page 36):

> MSC-SR-14 The only approved physical paths leaving the Red Network must be through an MSC Solution in accordance with this CP or via an AO-approved solution for protecting data in transit1. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-14 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u014.s001`: 1
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u015.s001`: In some cases, the customer will need to communicate with other sites that have NSA-certified Government-off- the-Shelf products.
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u015.s002`: In particular, it is acceptable for a given site to have both an egress path via an NSA-certified product and an egress path via a CSfC Solution conforming to a CP.

<a id="rg-057"></a>

## RG-057: Operational security updates and TEMPEST policy

Original requirement IDs: MSC-SR-15, MSC-GD-22, MSC-GD-23, MSC-GD-24.

**Applicability:** All components and their patch/update operation.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_patches_virus_updates_and_tempest`

**AI interpretation for later formalization:** Solution Components receive virus updates as required by policy and the AO, security-critical patches are tested then applied according to policy and this CP, local policy specifies patch installation, and components comply with local TEMPEST policy.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u005` (PDF page 36):

> MSC-SR-15 Solution Components must receive virus signature updates as required by the local agency policy and the AO. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u004` (PDF page 52):

> MSC-GD-22 The implementing organization must test and subsequently apply security critical patches to all components in the solution in accordance with local policy and this CP. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u005` (PDF page 52):

> MSC-GD-23 Local policy must dictate how the Security Administrator installs patches to Solution Components. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u006` (PDF page 52):

> MSC-GD-24 Solution Components must comply with local TEMPEST policy. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-15 | T=O | (blank) |
| MSC-GD-22 | T=O | (blank) |
| MSC-GD-23 | T=O | (blank) |
| MSC-GD-24 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p036:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s001`: Table 18.
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s002`: Use and Handling of Solutions (GD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u008.s001`: 1) Ensure the latest security-critical software patches and updates (such as Information Assurance Vulnerability Alerts) are applied to each product.
- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u013.s001`: The system AO maintains configuration control of the approved solution implementation over the lifecycle of the solution.
- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u013.s002`: Additionally, the AO must ensure that the solution remains properly configured with all required security updates implemented.

<a id="rg-058"></a>

## RG-058: Hardware inventory and available baseline configuration

Original requirement IDs: MSC-GD-25, MSC-GD-26.

**Applicability:** All hardware and component configurations.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_inventory_and_baseline_configuration`

**AI interpretation for later formalization:** Every hardware component is tracked by the AO-approved inventory process as part of a CSfC solution, and the Security Administrator maintains a baseline configuration available to the Auditor.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u007` (PDF page 52):

> MSC-GD-25 All hardware components must be tracked through an AO-approved inventory management process that identifies each component as part of a CSfC solution. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u008` (PDF page 52):

> MSC-GD-26 A baseline configuration for all components must be maintained by the Security Administrator and be available to the Auditor. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-GD-25 | T=O | (blank) |
| MSC-GD-26 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s001`: Table 18.
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s002`: Use and Handling of Solutions (GD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-059"></a>

## RG-059: Procurement documentation excludes classified-protection purpose

Original requirement IDs: MSC-GD-4.

**Applicability:** Acquisition and procurement records for solution equipment.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_procurement_purpose_nondisclosure`

**AI interpretation for later formalization:** Acquisition and procurement documentation omits the equipment purpose, including its use to protect classified information.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u016` (PDF page 50):

> MSC-GD-4 Acquisition and procurement documentation must not include information concerning the purpose of the equipment, to include that it will be used to protect classified information. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-GD-4 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s001`: Table 18.
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s002`: Use and Handling of Solutions (GD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u012`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-060"></a>

## RG-060: Annual and NSA-authorized compliance audits

Original requirement IDs: MSC-GD-5, MSC-GD-6, MSC-GD-7.

**Applicability:** Solution Owner, AO, annual renewal, and authorized audit requests.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_compliance_audits`

**AI interpretation for later formalization:** The Solution Owner permits and fully cooperates with NSA-authorized compliance audits, the AO ensures an annual audit against the latest CP as part of re-registration, and the AO receives and reviews the results.

**Qualifications and exceptions:**

- Inspection, testing, observation, and interviewing are non-exhaustive audit methods.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u017` (PDF page 50):

> MSC-GD-5 The Solution Owner must allow, and fully cooperate with, the NSA or its authorized agent to perform an Information Assurance (IA) compliance audit (including, but not limited to, inspection, testing, observation, and interviewing) of the solution implementation to ensure it meets the latest version of this CP. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u018` (PDF page 50):

> MSC-GD-6 As part of the annual solution re-registration process, the AO will ensure that a compliance audit must be conducted every year against the latest version of this CP. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u002` (PDF page 51):

> MSC-GD-7 Results of the compliance audit must be provided to, and reviewed by, the AO. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u009.s001` (PDF page 56):

> • The AO ensures that a compliance audit must be conducted every year against the latest version of the MSC CP, and the results must be provided to the AO.

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-GD-5 | T=O | (blank) |
| MSC-GD-6 | T=O | (blank) |
| MSC-GD-7 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s001`: Table 18.
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s002`: Use and Handling of Solutions (GD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u012`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-061"></a>

## RG-061: Registration, approval, annual renewal, and version updates

Original requirement IDs: MSC-GD-8, MSC-GD-9, MSC-GD-10, MSC-GD-11, MSC-GD-12.

**Applicability:** All customers using CSfC on NSS; Solution Owner and AO; initial use and changes/renewals.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_registration_and_version_updates`

**AI interpretation for later formalization:** Before operational use the customer obtains NSA registration approval and submits the complete registration package and AO compliance matrix, then renews annually and updates changed registration information; new-version compliance follows an explicitly resolved deadline preserving both the table and §13.3 statements.

**Qualifications and exceptions:**

- GD-11 says compliance at next registration renewal, whereas §13.3 says six months from notification and re-registration. Neither deadline is silently discarded.
- Top Secret solutions are considered case by case.
- The annual validity starts from approval.
- The registration acknowledgement describes approval; no artifact here is an actual registration approval.

Open issues: REQ-I05.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u008.s001` (PDF page 8):

> Customers who want to use this CP must register their solution with the NSA.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u008.s002` (PDF page 8):

> Additional information about the CSfC process is available on the CSfC web page (https://www.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u008.s003` (PDF page 8):

> nsa.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u008.s004` (PDF page 8):

> gov/resources/commercial- solutions-for-classified-program).

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u009.s001` (PDF page 8):

> This CP will be reviewed twice a year to ensure that the defined capabilities and other instructions still provide the security services and robustness required.

- `CSFC-MSC-1.3.0-4e40e3d83708:p008:u009.s002` (PDF page 8, 9):

> Solutions designed according to this CP must be registered with the NSA.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u001.s002` (PDF page 9):

> Once successfully registered, a registration acknowledgement letter will be sent validating that the MSC solution is registered as a CSfC solution and is approved to protect classified information.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u001.s003` (PDF page 9):

> Any solution designed according to this CP may be used for one year and then be revalidated against the most recently published version of this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u001.s004` (PDF page 9):

> Top Secret Solutions will be considered on a case-by-case basis.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u001.s005` (PDF page 9):

> Customers are encouraged to engage their Client Advocate or the CSfC PMO team early in the process to ensure the solutions are properly scoped, vetted, and that the customers understand the risks and available mitigations.

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u003` (PDF page 51):

> MSC-GD-8 Customers interested in registering their solution against this CP must register with the NSA and receive approval prior to operating the solution. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u004` (PDF page 51):

> MSC-GD-9 The implementing organization must complete and submit an MSC CP requirements compliance matrix to their respective AO. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u005` (PDF page 51):

> MSC-GD-10 Registration and re-registration against this CP must include submission of a complete CSfC solution registration package to the NSA. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u006` (PDF page 51):

> MSC-GD-11 The AO must ensure that when the NSA publishes a new approved MSC CP that their organization must be in compliance upon the next registration renewal. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u007` (PDF page 51):

> MSC-GD-12 Solution implementation information that was provided to the NSA during solution registration must be updated annually (in accordance with Section 13.3) as part of the annual re-registration process. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u007.s001` (PDF page 56):

> • The customer registers the solution with the NSA and re-registers yearly to validate its continued use as detailed in Section 13.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u007.s002` (PDF page 56):

> 3.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u014.s001` (PDF page 57):

> All customers using CSfC solutions to protect information on National Security Systems must register their solution with the NSA prior to operational use.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u014.s002` (PDF page 57):

> This registration allows the NSA to track where MSC Solutions are instantiated and to provide the AOs at those sites with appropriate information, including any significant vulnerabilities that may be discovered in components or high-level designs approved for these solutions.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u014.s003` (PDF page 57, 58):

> The CSfC solution registration process is available on the CSfC web page under the “Solution Registration” tab (https://www.

- `CSFC-MSC-1.3.0-4e40e3d83708:p058:u001.s002` (PDF page 58):

> nsa.

- `CSFC-MSC-1.3.0-4e40e3d83708:p058:u001.s003` (PDF page 58):

> gov/resources/commercial-solutions-for- classified-program/solution-registration).

- `CSFC-MSC-1.3.0-4e40e3d83708:p058:u002.s001` (PDF page 58):

> Solution registrations are valid for one year from the date the solution registration is approved, at which time customers are required to re-register their solution to continue using it.

- `CSFC-MSC-1.3.0-4e40e3d83708:p058:u002.s002` (PDF page 58):

> Approved CPs will be reviewed twice a year, or as events warrant.

- `CSFC-MSC-1.3.0-4e40e3d83708:p058:u002.s003` (PDF page 58):

> Registered users of this CP will be notified when a new version is published.

- `CSFC-MSC-1.3.0-4e40e3d83708:p058:u002.s004` (PDF page 58):

> When a new version of this NSA-approved CP is published, customers have six months from the date they are notified, to bring their solutions into compliance with the new version of this CP and re-register their solution (see requirement MSC-GD-11).

- `CSFC-MSC-1.3.0-4e40e3d83708:p058:u002.s005` (PDF page 58):

> Customers are also required to update their registrations whenever the information provided on the registration form changes.

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-GD-8 | T=O | (blank) |
| MSC-GD-9 | T=O | (blank) |
| MSC-GD-10 | T=O | (blank) |
| MSC-GD-11 | T=O | (blank) |
| MSC-GD-12 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s001`: Table 18.
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s002`: Use and Handling of Solutions (GD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-062"></a>

## RG-062: Audit retention, storage monitoring, backup, and continuity

Original requirement IDs: MSC-GD-13, MSC-GD-14, MSC-GD-15, MSC-GD-16, MSC-GD-17, MSC-GD-18, MSC-GD-19, MSC-GD-20.

**Applicability:** Audit storage, Security Administrators, and the implementing organization.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_audit_log_retention_and_continuity`

**AI interpretation for later formalization:** Audit data is retained for at least one year, remaining capacity is assessed quarterly, frequent backups occur, incident-reporting guidance is documented, and the organization maintains an audit continuity plan covering capacity warnings, long-term offload, overflow response, and power events.

**Qualifications and exceptions:**

- The source gives no numeric backup frequency beyond “frequently”; no interval is invented.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u008` (PDF page 51):

> MSC-GD-13 Audit log data must be maintained for a minimum of 1 year. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u009` (PDF page 51):

> MSC-GD-14 The amount of storage remaining for audit events must be assessed by the Security Administrator quarterly to ensure that adequate memory space is available to continue recording new audit events. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u010` (PDF page 51):

> MSC-GD-15 Audit data must be frequently off-loaded to a backup storage medium. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u011` (PDF page 51):

> MSC-GD-16 The implementing organization must develop a set of procedures to provide guidance for identifying and reporting security incidents associated with the audit events to the proper authorities and to the data owners. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u012` (PDF page 51):

> MSC-GD-17 The implementing organization must develop a continuity of operations plan for auditing capability that includes a mechanism or method for determining when the audit log is reaching its maximum storage capacity. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u013` (PDF page 51):

> MSC-GD-18 The implementing organization must develop a continuity of operations plan for auditing capability that includes a mechanism or method for off-loading audit log data for long-term storage. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u014` (PDF page 51):

> MSC-GD-19 The implementing organization must develop a continuity of operations plan for auditing capability that includes a mechanism or method for responding to an overflow of audit log data within a product. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u015` (PDF page 51, 52):

> MSC-GD-20 The implementing organization must develop a continuity of operations plan for auditing capability that T=O includes a mechanism or method for ensuring the audit log can be maintained during power events.

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-GD-13 | T=O | (blank) |
| MSC-GD-14 | T=O | (blank) |
| MSC-GD-15 | T=O | (blank) |
| MSC-GD-16 | T=O | (blank) |
| MSC-GD-17 | T=O | (blank) |
| MSC-GD-18 | T=O | (blank) |
| MSC-GD-19 | T=O | (blank) |
| MSC-GD-20 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s001`: Table 18.
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s002`: Use and Handling of Solutions (GD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p051:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u001`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u003.s001`: Audit – The activity of monitoring the operation of a product from within the product.
- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u003.s002`: It includes monitoring of a product for a set of pre-determined events.
- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u003.s003`: Each audit event may indicate rogue behavior, or a condition that is detrimental to security, or provide necessary forensics to identify the source of rogue behavior.
- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u004.s001`: Audit Log – A chronological record of the audit events that have been deemed critical to security.
- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u004.s002`: The audit log can be used to identify potentially malicious activity that may further identify the source of an attack, as well as potential vulnerabilities where additional countermeasures or corrective actions are required.

<a id="rg-063"></a>

## RG-063: Infrastructure authentication alternatives

Original requirement IDs: MSC-GD-21, MSC-GD-27.

**Applicability:** All infrastructure components and their access mechanisms.

**Requirement strength and applicability:** Threshold password requirement or Objective domain authentication service; password-generator use is recommended.

**Single theorem target:** `msc_infrastructure_authentication_choice`

**AI interpretation for later formalization:** Infrastructure components use either threshold passwords containing at least 112 random bits or the objective authentication service on their respective network/domain, with an approved password generator recommended for the password branch.

**Alternative logic:**

- MSC-GD-21 or MSC-GD-27.

**Qualifications and exceptions:**

- The external Key Management Annex Appendix A is a dependency; no password-generation algorithm is invented.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u003` (PDF page 52):

> MSC-GD-21 All infrastructure components must implement a password of at least 112 random bits. Passwords should be generated using an approved password generator. See CSfC Key Management Requirements Annex, Appendix A for more information. T MSC-GD-27

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u009` (PDF page 52):

> MSC-GD-27 All infrastructure components must use an authentication service on their respective network/domain in order to access the Infrastructure component of the respective network/domain. O MSC-GD-21

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-GD-21 | T | MSC-GD-27 |
| MSC-GD-27 | O | MSC-GD-21 |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s001`: Table 18.
- `CSFC-MSC-1.3.0-4e40e3d83708:p050:u011.s002`: Use and Handling of Solutions (GD) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u001`: Req. # Requirement Description Threshold / Objective Alternative

<a id="rg-064"></a>

## RG-064: Incident triggers, required report fields, and reporting deadline

Original requirement IDs: MSC-RP-1, MSC-RP-2, MSC-RP-3, MSC-RP-4, MSC-RP-5, MSC-RP-6, MSC-RP-7, MSC-RP-8, MSC-RP-9, MSC-RP-10, MSC-RP-11, MSC-RP-12, MSC-RP-13, MSC-RP-14, MSC-RP-15.

**Applicability:** Solution Owners, AO reporting duties, and incidents affecting the solution.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_incident_reporting`

**AI interpretation for later formalization:** For every reportable incident under RP-3 through RP-15, the Solution Owner reports the confirmed incident within 24 hours of detection through the stated NSA channel and supplies at least all RP-2 fields, treating unexplained activity as malicious unless known non-malicious and preserving the Black-connectivity exception.

**Qualifications and exceptions:**

- The trigger is the disjunction of RP-3 through RP-15, not a requirement that every condition occur.
- RP-13 excludes connectivity issues associated with the Black Network.
- RP-1 says confirmed incidents while the malicious definition includes unexplained activity; reporting certainty must not be tightened silently.
- Local incident procedures remain in force; the CP adds its reporting obligations.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u011.s001` (PDF page 52):

> Table 19 lists incident reporting requirements for reporting security incidents to the NSA.

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u011.s002` (PDF page 52):

> These requirements must be followed in the event that a Solution Owner identifies a security incident that affects the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u011.s003` (PDF page 52):

> These reporting requirements are intended to augment, not replace incident reporting procedures already in use within the Solution Owner’s organization.

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u011.s004` (PDF page 52):

> It is critical that Security Administrators and Auditors are familiar with maintaining the solution in accordance with this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u011.s005` (PDF page 52):

> Familiarity with the known-good configuration of the solution will better equip personnel responsible for the operations and maintenance of the solution to identify reportable incidents.

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u012.s001` (PDF page 52):

> For the purposes of incident reporting, “malicious” activity includes not only events that have been attributed to activity by an adversary, but also events that are unexplained.

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u012.s002` (PDF page 52):

> In other words, an activity is assumed to be malicious unless it has been determined to be the result of known non-malicious activity.

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u013.s001` (PDF page 52):

> Table 19 only provides requirements directly related to the incident reporting process.

- `CSFC-MSC-1.3.0-4e40e3d83708:p052:u013.s002` (PDF page 52):

> See the CSfC Continuous Monitoring Annex for requirements supporting the detection of events that may reveal that a reportable incident has occurred.

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u003` (PDF page 53):

> MSC-RP-1 Solution Owners must report confirmed incidents meeting the criteria in MSC-RP-3 through MSC-RP-15 within 24-hours of detection via the Joint Incident Management System or contacting the NSA as specified in the CSfC Acknowledgement Letter issued for the solution. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u004` (PDF page 53):

> MSC-RP-2 At a minimum, the organization must provide the following information when reporting security incidents: • CSfC Registration Number • Primary POC name, phone, email • Alternate POC name, phone, email • Security level of affected solution • Name of affected network(s) • Affected component(s) manufacturer/ vendor • Affected component(s) model number • Affected component(s) version number • Date and time of incident • Description of incident • Description of remediation activities • Is Technical Support from the NSA requested? (Yes/No) T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u005` (PDF page 53):

> MSC-RP-3 Solution Owners must report a security failure in any of the CSfC Solution Components. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u006` (PDF page 53):

> MSC-RP-4 Solution Owners must report any evidence of a compromise or spillage of classified data caused by a failure of the CSfC solution. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u007` (PDF page 53):

> MSC-RP-5 For Gray Network interfaces, Solution Owners must report any malicious inbound and outbound traffic. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u008` (PDF page 53):

> MSC-RP-6 Solution Owners must report any evidence of an unauthorized device/user gaining access to the classified network via the solution. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u009` (PDF page 53):

> MSC-RP-7 Solution Owners must report if a Solution Component sends traffic with an unauthorized destination address. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u010` (PDF page 53):

> MSC-RP-8 Solution Owners must report any malicious configuration changes to the components. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u011` (PDF page 53):

> MSC-RP-9 Solution Owners must report any unauthorized escalation of privileges to any of the CSfC Solution Components. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u012` (PDF page 53):

> MSC-RP-10 Solution Owners must report if two or more simultaneous VPN connections from different IP addresses are established using the same device certificate. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u013` (PDF page 53):

> MSC-RP-11 Solution Owners must report any evidence of malicious physical tampering with Solution Components. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u014` (PDF page 53):

> MSC-RP-12 Solution Owners must report any evidence that one or both layers of the solution failed to protect the data. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u002` (PDF page 54):

> MSC-RP-13 Solution Owners must report any significant degradation of services provided by the solution excluding connectivity issues associated with the Black Network. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u003` (PDF page 54):

> MSC-RP-14 Solution Owners must report malicious discrepancies in the number of connections established by the Outer Encryption Component. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u004` (PDF page 54):

> MSC-RP-15 Solution Owners must report malicious discrepancies in the number of connections established by the Inner Encryption Component. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u012.s001` (PDF page 56):

> • The AO reports incidents affecting the solution in accordance with Section 11.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u012.s002` (PDF page 56):

> 2.

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-RP-1 | T=O | (blank) |
| MSC-RP-2 | T=O | (blank) |
| MSC-RP-3 | T=O | (blank) |
| MSC-RP-4 | T=O | (blank) |
| MSC-RP-5 | T=O | (blank) |
| MSC-RP-6 | T=O | (blank) |
| MSC-RP-7 | T=O | (blank) |
| MSC-RP-8 | T=O | (blank) |
| MSC-RP-9 | T=O | (blank) |
| MSC-RP-10 | T=O | (blank) |
| MSC-RP-11 | T=O | (blank) |
| MSC-RP-12 | T=O | (blank) |
| MSC-RP-13 | T=O | (blank) |
| MSC-RP-14 | T=O | (blank) |
| MSC-RP-15 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u001.s001`: Table 19.
- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u001.s002`: Incident Reporting (RP) Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p053:u002`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u001`: Req. # Requirement Description Threshold/ Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u015.s001`: Malicious – Any unauthorized events that are either unexplained or in any way indicate adversary activity.

<a id="rg-065"></a>

## RG-065: Separation of administrative and auditing personnel

Original requirement IDs: MSC-RB-2, MSC-RB-5, MSC-RB-11.

**Applicability:** Security Administrators, Auditors, and optional Integrator-role separation.

**Requirement strength and applicability:** RB-2/5 are T=O; RB-11 is Objective/Optional; Integrator separation is a customer permission.

**Single theorem target:** `msc_separation_of_personnel_roles`

**AI interpretation for later formalization:** Different people perform Security Administrator and Auditor roles, different administrators manage Inner/Red and Outer/Gray components, and optional Mandatory Access Control role definitions apply when selected; customers may also require Red/Gray separation among Integrator personnel.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u011.s001` (PDF page 26):

> Additionally, if an Integrator is used for implementation of this solution, the customer can require separation of roles between individuals working on Red and Gray components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u011.s002` (PDF page 26):

> The separation of roles ensures that during the development of the solution no single individual can compromise Red and Gray components simultaneously.

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u010` (PDF page 55):

> MSC-RB-2 The Security Administrator and Auditor roles must be performed by different people. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u013` (PDF page 55):

> MSC-RB-5 The Security Administrator(s) for the Inner Encryption Components and supporting components on the Red Network must be different individuals from the Security Administrator(s) for the Outer Encryption Components and supporting components on the Gray Network. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u019` (PDF page 55):

> MSC-RB-11 Mandatory Access Control policy must specify roles for Security Administrator and Auditor using role-based access controls. O Optional

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-RB-2 | T=O | (blank) |
| MSC-RB-5 | T=O | (blank) |
| MSC-RB-11 | O | Optional |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u007.s001`: Table 20.
- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u007.s002`: Role-Based (RB) Personnel Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u008`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-066"></a>

## RG-066: Personnel training and physical tamper inspections

Original requirement IDs: MSC-RB-3, MSC-RB-6.

**Applicability:** Security Administrators, Auditors, and infrastructure hardware.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_training_and_hardware_inspection`

**AI interpretation for later formalization:** Security Administrators and Auditors meet local IA training requirements, and administrators periodically inspect infrastructure hardware for tampering or unauthorized physical changes.

**Qualifications and exceptions:**

- “Periodically” is preserved without inventing an interval.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u011` (PDF page 55):

> MSC-RB-3 All Security Administrators and Auditors must meet local IA training requirements. T=O

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u014` (PDF page 55):

> MSC-RB-6 Administrators must periodically inspect the physical attributes of infrastructure hardware for signs of tampering or other unauthorized changes. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-RB-3 | T=O | (blank) |
| MSC-RB-6 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u007.s001`: Table 20.
- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u007.s002`: Role-Based (RB) Personnel Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u008`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-067"></a>

## RG-067: Revocation or CAK destruction before disposal

Original requirement IDs: MSC-RB-8.

**Applicability:** Any Solution Component scheduled for disposal and its administrators.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_predisposal_key_revocation`

**AI interpretation for later formalization:** Security Administrators initiate the certificate-revocation or CAK-destruction process before disposal of any Solution Component.

**Qualifications and exceptions:**

- Initiating the applicable process is the exact stated timing obligation; completion criteria belong to external key-management requirements.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u016` (PDF page 55):

> MSC-RB-8 Security Administrators must initiate the certificate revocation/CAK destruction process prior to disposal of any Solution Component. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-RB-8 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u007.s001`: Table 20.
- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u007.s002`: Role-Based (RB) Personnel Requirements
- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u008`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-068"></a>

## RG-068: Security Administrator operational duties

Original requirement IDs: Prose-only.

**Applicability:** Security Administrators for the solution and auxiliary network devices.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_security_administrator_duties`

**AI interpretation for later formalization:** Security Administrators maintain, monitor, and control solution security, apply critical updates, document/report incidents, support integration and maintenance logistics with necessary escorts, defend auxiliary network devices, and maintain CP-version compliance according to GD-11.

**Qualifications and exceptions:**

- The role may also be called Information System Security Officer.
- The listed duties are non-exhaustive.
- Version-transition conflict remains in RG-061.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u007.s001` (PDF page 54):

> Security Administrator – The Security Administrator must maintain, monitor, and control all security functions for the entire suite of products composing the MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u007.s002` (PDF page 54):

> In some organizations, the Security Administrator may be known as the Information System Security Officer.

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u007.s003` (PDF page 54):

> Security Administrator duties include, but are not limited to:

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u008.s001` (PDF page 54):

> 1) Ensure the latest security-critical software patches and updates (such as Information Assurance Vulnerability Alerts) are applied to each product.

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u009.s001` (PDF page 54):

> 2) Document and report security-related incidents to the appropriate authorities.

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u010.s001` (PDF page 54):

> 3) Coordinate and support product logistic support activities including integration and maintenance.

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u010.s002` (PDF page 54):

> Some logistic support activities may require that the Security Administrator escort uncleared personnel.

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u011.s001` (PDF page 54):

> 4) Employ adequate defenses of auxiliary network devices to enable proper and secure functionality of the MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u012.s001` (PDF page 54):

> 5) Ensure that the implemented MSC Solution remains compliant with the latest version of this CP, as specified by MSC-GD-11.

<a id="rg-069"></a>

## RG-069: Auditor review duties and access boundary

Original requirement IDs: Prose-only.

**Applicability:** Auditor role and audit/administration systems.

**Requirement strength and applicability:** Mandatory for the stated applicability.

**Single theorem target:** `msc_auditor_duties_and_access`

**AI interpretation for later formalization:** The Auditor reviews administrator actions and audit events for compromise, manages audit log data, documents and reports incidents, develops and reports a System Audit Capability Survey, and is authorized access only to Inner and Outer administration components.

**Qualifications and exceptions:**

- The duties are stated as non-exhaustive.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u013.s001` (PDF page 54):

> Auditor – The Auditor must review the actions performed by the Security Administrator and events recorded in the audit logs to ensure that no action or event represents a compromise to the security of the MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u013.s002` (PDF page 54):

> The Auditor will only be authorized access to Outer and Inner administration components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u013.s003` (PDF page 54):

> Auditor duties include, but are not limited to:

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u014.s001` (PDF page 54):

> 1) Review, manage, control, and maintain security audit log data.

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u015.s001` (PDF page 54):

> 2) Document and report security-related incidents to the appropriate authorities.

- `CSFC-MSC-1.3.0-4e40e3d83708:p054:u016.s001` (PDF page 54):

> 3) Develop, maintain and report a System Audit Capability Survey.

<a id="rg-070"></a>

## RG-070: Optional Integrator involvement and duty scope

Original requirement IDs: Prose-only.

**Applicability:** Customers choosing an external Integrator and that Integrator’s assigned duties.

**Requirement strength and applicability:** Optional engagement and non-exhaustive possible duties; no mandatory Integrator role is invented.

**Single theorem target:** `msc_integrator_permitted_duties`

**AI interpretation for later formalization:** A customer may engage an external Integrator to implement the CP, with the possible duties of acquiring products, configuring the solution, documenting/testing/maintaining it, and responding to incidents, subject to the applicable CP obligations.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u001.s001` (PDF page 55):

> Integrator – In certain cases, an external Integrator may be hired to implement a MSC Solution based on this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u001.s002` (PDF page 55):

> Solution Integrator duties may include, but are not limited to:

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u002.s001` (PDF page 55):

> 1) Acquire the products that compose the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u003.s001` (PDF page 55):

> 2) Configure the MSC Solution in accordance with this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u004.s001` (PDF page 55):

> 3) Document, test, and maintain the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p055:u005.s001` (PDF page 55):

> 4) Respond to incidents affecting the solution.

<a id="rg-071"></a>

## RG-071: AO authorization evidence and lifecycle control

Original requirement IDs: Prose-only.

**Applicability:** Customer, testing/assessment team, AO, proposed variants, and compromise response.

**Requirement strength and applicability:** Stated customer/AO obligations, must for risk-assessment delivery, and should for obtaining the risk document through the stated route.

**Single theorem target:** `msc_ao_authorization_and_lifecycle_control`

**AI interpretation for later formalization:** The customer obtains security assessment and authorization using the referenced risk information and provides the results and NSA Risk Assessment to the AO. A customer wanting a solution variant contacts its NSA External Engagement Representative to determine how to obtain approval. The AO verifies proper implementation, maintains lifecycle configuration/update control, and ensures that certificate/CAK revocation information is updated on all Solution Components after compromise.

**Qualifications and exceptions:**

- The NSA Risk Assessment is external and not included; its findings are not inferred.
- The AO’s formal approval is not replaced by a theorem or by the source figures.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u002.s001` (PDF page 56):

> This section details items that will likely be necessary for the customer to obtain approval from the system AO.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u002.s002` (PDF page 56):

> The customer and AO have obligations to perform the following:

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u005.s001` (PDF page 56):

> • The customer has the security control assessment and system authorization performed using the risk assessment information referenced in Section 13.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u005.s002` (PDF page 56):

> 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u006.s001` (PDF page 56):

> • The customer provides the results from the security control assessment and system authorization to the AO for use in making an approval decision.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u006.s002` (PDF page 56):

> The AO is ultimately responsible to ensure all requirements from this CP have been properly implemented in accordance with this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u008.s001` (PDF page 56):

> • Customers who want to use a variant of the solution detailed in this CP will contact their NSA External Engagement Representative to determine ways to obtain NSA approval.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u010.s001` (PDF page 56):

> • In case of a compromise, the AO ensures that certificate and CAK revocation information is updated on all the Solution Components in the MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u013.s001` (PDF page 56):

> The system AO maintains configuration control of the approved solution implementation over the lifecycle of the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u013.s002` (PDF page 56):

> Additionally, the AO must ensure that the solution remains properly configured with all required security updates implemented.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u012.s001` (PDF page 57):

> The Risk Assessment of the MSC Solution presented in this CP focuses on the types of attacks that are feasible against this solution and the mitigations that can be employed.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u012.s002` (PDF page 57):

> Customers should contact their NSA External Engagement Representative to request this document, or visit the CSfC Secret Internet Protocol Router Network (SIPRNet) site for information.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u012.s003` (PDF page 57):

> The process to obtain the Risk Assessment can be obtained via the CSfC PMO.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u012.s004` (PDF page 57):

> The AO must be provided a copy of the NSA Risk Assessment for their consideration in approving the use of the solution.

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u005.s001`: Authorizing Official – A senior (Federal) official or executive with the authority to authorize (i.
- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u005.s002`: e.
- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u005.s003`: , assume responsibility for) the operation of an information system or the use of a designated set of common controls at an acceptable level of risk to agency operations (including mission, functions, image, or reputation), agency assets, individuals, other organizations, and the Nation.
- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u005.s004`: (NIST SP 800-37)
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u008.s001`: Security Control Assessment – The testing or evaluation of security controls to determine the extent to which the controls are implemented correctly, operating as intended, and producing the desired outcome with respect to meeting the security requirements for an information system or organization.
- `CSFC-MSC-1.3.0-4e40e3d83708:p061:u008.s002`: (NIST SP 800-37)

<a id="rg-072"></a>

## RG-072: Whole-solution testing and preserved results

Original requirement IDs: MSC-TR-1.

**Applicability:** The entire solution and all §5 components; implementing organization and test team.

**Requirement strength and applicability:** TR-1 and explicit must clauses are mandatory; two-person testing and some methodology clauses are recommendations.

**Single theorem target:** `msc_solution_testing_and_evidence`

**AI interpretation for later formalization:** The implementing organization tests every security feature and operational capability, executes all Testing Annex tests, documents the baseline and discrepancies, uses Black- and Gray-Box tests, checks that local requirements do not impair security, retains test artifacts, and delivers the final report to the AO, with two-person testing recommended.

**Qualifications and exceptions:**

- The Testing Annex is an external dependency, so its individual tests are not invented.
- The minimum baseline record includes model/serial numbers, software versions, and configuration settings.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u004.s001` (PDF page 56):

> • The customer’s testing team develops a test plan and performs testing of the MSC Solution (see Section 13.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u004.s002` (PDF page 56):

> 1).

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u015.s001` (PDF page 56):

> This section provides a framework for a Test and Evaluation (T&E) plan and procedures to validate the implementation of an MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u015.s002` (PDF page 56):

> T&E is a critical part of the approval process for the AO, providing a robust body of evidence that shows compliance with this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u016.s001` (PDF page 56):

> The security features and operational capabilities associated with the use of the solution must be tested.

- `CSFC-MSC-1.3.0-4e40e3d83708:p056:u016.s002` (PDF page 56, 57):

> The following is a general high-level methodology for developing the T&E plan and procedures and for the execution of those procedures to validate the implementation and functionality of the MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u001.s002` (PDF page 57):

> The entire solution, to include each component described in Section 5, is addressed by this test plan, including the following:

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u002.s001` (PDF page 57):

> 1) Set up the baseline network and configure all components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u003.s001` (PDF page 57):

> 2) Document the baseline network configuration.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u003.s002` (PDF page 57):

> Include product model and serial numbers, software version numbers, and software configuration settings, at a minimum.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u004.s001` (PDF page 57):

> 3) Develop a test plan for the specific implementation using the test requirements from the MSC CP Testing Annex.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u004.s002` (PDF page 57):

> Any additional requirements imposed by the local AO should also be tested, and the test plan must include tests to ensure that these requirements do not interfere with the security of this solution as described in this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u005.s001` (PDF page 57):

> 4) Perform testing using the test plan derived in Step 3.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u005.s002` (PDF page 57):

> Network testing will consist of both Black Box testing and Gray Box testing.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u005.s003` (PDF page 57):

> A two-person testing approach should be used to administer the tests.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u005.s004` (PDF page 57):

> During test execution, security and non-security related discrepancies with the solution must be documented.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u006.s001` (PDF page 57):

> 5) Compile findings, to include comments and vulnerability details as well as possible countermeasure information, into a Final Test Report to be delivered to the AO for approval of the solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u007.s001` (PDF page 57):

> The test requirement in Table 21 was developed to ensure that the MSC Solution functions properly and meets the configuration requirements in Section 10.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u007.s002` (PDF page 57):

> Testing of these requirements should be used as a minimum framework for the development of the detailed T&E plan and procedures.

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u010` (PDF page 57):

> MSC-TR-1 The organization implementing the CP must perform all tests listed in the CSfC MSC CP Testing Annex and maintain artifacts of the testing results. T=O

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-TR-1 | T=O | (blank) |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u008.s001`: Table 21.
- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u008.s002`: Test (TR) Requirement
- `CSFC-MSC-1.3.0-4e40e3d83708:p057:u009`: Req. # Requirement Description Threshold / Objective Alternative
- `CSFC-MSC-1.3.0-4e40e3d83708:p059:u007.s001`: Black Box Testing – Testing the functionality of a component of the solution, such that testing is limited to the subset of functionality that is available from the external interfaces of the box during its normal operational configuration without any additional privileges (such as given to the Security Administrator or Auditor).
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u007.s001`: Gray Box Testing – The ability to test functionality within a component of the solution, such that full management privileges are granted (i.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u007.s002`: e.
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u007.s003`: , knowing passwords for Security Administrator and Auditor and access to the capabilities associated with those privileges).
- `CSFC-MSC-1.3.0-4e40e3d83708:p060:u007.s004`: In addition, the use of any and all testing equipment and/or testing software used inside and outside the developed solution is available.

<a id="rg-073"></a>

## RG-073: Objective software and firmware signing algorithms

Original requirement IDs: MSC-SR-24.

**Applicability:** All Solution Components, including firewalls, VPN Gateways, and Authentication Servers, under the objective branch.

**Requirement strength and applicability:** MSC-SR-24 is Objective/Optional in this version; future implementation dates are not inferred.

**Single theorem target:** `msc_software_firmware_signature_choice`

**AI interpretation for later formalization:** When the software/firmware signing objective is selected, every Solution Component uses one of the Table 2 approved algorithms and its stated parameters; one permitted algorithm is sufficient for the requirement.

**Alternative logic:**

- LMS, XMSS, or ML-DSA-87; the algorithms are alternatives, not three simultaneous obligations.

**Qualifications and exceptions:**

- LMS SHA-256/192 is recommended in Table 2; all approved parameters are stated.
- The source says migration timelines may change.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u006.s001` (PDF page 28):

> As part of the requirement laid out in NSM-10, the CSfC Program has added Software and Firmware Signing requirements for all components listed on the CSfC Components list.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u006.s002` (PDF page 28):

> As of now this is an objective security feature but the implementation timeline for these requirements will be the same as the CNSA 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u006.s003` (PDF page 28):

> 0 timeline in CSfC.

- `CSFC-MSC-1.3.0-4e40e3d83708:p028:u006.s004` (PDF page 28):

> These timelines are subject to change depending on market acceptance, vendor and customer feedback for these new requirements.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u001.s001` (PDF page 29):

> There are three acceptable algorithms for software and firmware digital signatures, which are all included as part of the CNSA 2.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u001.s002` (PDF page 29):

> 0 cipher suites.

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u001.s003` (PDF page 29):

> These algorithms are enumerated within Table 2 and only one of the algorithms will be required to meet this requirement.

- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u003` (PDF page 37):

> MSC-SR-24 All solution components (Firewalls, VPN Gateways, Authentication Servers, etc) must use software and firmware signing algorithms in Table 2. O Optional

**Original Threshold/Objective designation and alternatives:**

| Requirement | Threshold / Objective | Alternative |
| --- | --- | --- |
| MSC-SR-24 | O | Optional |

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u002.s001`: Table 2.
- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u002.s002`: CNSA 2.
- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u002.s003`: 0 Algorithms for Software and Firmware Signing
- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u003`: Algorithm Function Specification Parameters
- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u004`: Leighton-Micali Signature (LMS) Asymmetric algorithm for digitally signing firmware and software NIST SP 800-208 All parameters approved for all classification levels. SHA-256/192 recommended.
- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u005`: Xtended Merkle Signature Scheme (XMSS) Asymmetric algorithm for digitally signing firmware and software NIST SP 800-208 All parameters approved for all classification levels.
- `CSFC-MSC-1.3.0-4e40e3d83708:p029:u006`: ML-DSA Asymmetric algorithm for digital signatures FIPS 204 Category 5 parameter, ML-DSA-87.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s001`: Table 5.
- `CSFC-MSC-1.3.0-4e40e3d83708:p035:u001.s002`: Overall Solution Requirements (SR)
- `CSFC-MSC-1.3.0-4e40e3d83708:p037:u001`: Req. # Requirement Description Threshold/ Objective Alternative

<a id="rg-074"></a>

## RG-074: Redundant component and load-balancing permission

Original requirement IDs: Prose-only.

**Applicability:** Optional redundant Inner/Outer Encryption Components, Gray Firewalls, and the Figure 9 router/switch.

**Requirement strength and applicability:** Conditional permission; automatic high availability and failover design are not guaranteed by this CP.

**Single theorem target:** `msc_redundant_component_permission`

**AI interpretation for later formalization:** An implementation may add parallel redundant encryption components or multiple compliant firewalls for failover or throughput only while every added security component meets its applicable CP requirements; the shown infrastructure router carries only the explicitly stated CP scope.

**Qualifications and exceptions:**

- §4.4 says the ordinary Gray router/switch has no CP security requirements; an encapsulating router/switch has a different treatment in RG-015.
- A picture of redundant tunnels does not establish complete compliance or implemented failover.

Scope or resolved-interpretation notes: REQ-I14.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s001` (PDF page 21):

> The high-level designs described in Section 4.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s002` (PDF page 21):

> 2 are not designed with the intent of automatically providing high availability.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s003` (PDF page 21):

> Supporting solution implementations where high availability is important is not a goal of this version of the CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s004` (PDF page 21):

> However, this CP does not prohibit adding redundant components in parallel to allow for component failover or to increase the throughput of the MSC Solution, as long as each redundant component adheres to the requirements of this CP.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s001` (PDF page 21):

> Figure 9 shows an MSC Solution between two sites where each site has a redundant Outer Encryption Component (Management components are omitted from the figure for clarity).

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s002` (PDF page 21):

> There are two outer encryption tunnels that transit the Black Network: one between the upper pair of Outer Encryption Components, and one between the lower pair of Outer Encryption Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003` (PDF page 21):

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s004` (PDF page 21):

> This router is part of the solution only in the sense that it is part of the network infrastructure of the Gray Network; this CP does not levy any security requirements on the router/switch.

- `CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s005` (PDF page 21):

> The MSC Solution can maintain connectivity between the two sites even if one of the Outer Encryption Components fails because traffic will be routed through the tunnel that has not failed.

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u002.s001` (PDF page 22):

> Figure 9 shows a simple example of how redundancy could be added, if needed, for an MSC Solution.

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u002.s002` (PDF page 22):

> Implementing standby or failover Encryption Components, performing load balancing between Encryption Components, or other techniques to improve the availability or throughput of the solution are outside the scope of this CP and are not discussed further.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u003.s001` (PDF page 24):

> For load balancing or other performance reasons, multiple Outer Encryption Components that comply with the requirements of this CP are acceptable.

- `CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s004` (PDF page 24):

> For load balancing or other performance reasons, multiple Gray Firewalls that comply with the requirements of this CP are acceptable.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s001` (PDF page 25):

> Inner Encryption Components can either be VPN Gateways or MACsec Devices.

- `CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s002` (PDF page 25):

> For load balance or other performance reasons, multiple Inner Encryption Components that comply with the requirements of this CP are acceptable.

**Shared context, definitions, and illustrations:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u009`: [Image-only figure; see source location and network artifact.]
- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u001.s001`: Figure 9.
- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u001.s002`: MSC Solution with Redundant Outer Encryption Components

<a id="rg-075"></a>

## RG-075: Optional additional controls and screening-router scope

Original requirement IDs: Prose-only.

**Applicability:** Optional screening router, existing Black infrastructure, and optional key-management-annex components.

**Requirement strength and applicability:** Permissions with explicit component-scope limitations.

**Single theorem target:** `msc_additional_control_permissions`

**AI interpretation for later formalization:** An implementation may add the stated risk-reducing controls, including a screening router on the Black Network; the router is outside the MSC Solution boundary and optional annex components receive only the scope expressly stated by the source.

**Qualifications and exceptions:**

- The scope statement is not a general exemption for other routers or all annex-related components.

Open issues: REQ-I12.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u007.s001` (PDF page 22):

> Additional components, discussed in the CSfC Key Management Requirements Annex and CSfC Symmetric Key Management Requirements Annex can be added to the solution to help reduce the overall risk.

- `CSFC-MSC-1.3.0-4e40e3d83708:p022:u007.s002` (PDF page 22):

> However, these are not considered mandatory components for the security of the solution; therefore, this CP does not place configuration or security requirements on those components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s001` (PDF page 26):

> There are additional controls that could be used within this solution to potentially reduce the overall risk.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002` (PDF page 26):

> A screening router can be used to filter packets from Black Networks before they arrive at Outer Encryption Components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s003` (PDF page 26):

> The screening router could be part of an existing Black Network (e.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s004` (PDF page 26):

> g.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s005` (PDF page 26):

> , Customer Edge Router), or could be added between Outer Encryption Components and existing Black Network components.

- `CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s006` (PDF page 26):

> However, since the screening router would become part of a Black Network, it is not considered to be part of the MSC Solution itself.

<a id="rg-076"></a>

## RG-076: CP user legal undertaking and disclaimer

Original requirement IDs: Prose-only.

**Applicability:** The CP user and the legal undertaking in §3, not network packet behavior.

**Requirement strength and applicability:** Legal disclaimer and contractual undertaking, separate from T/O technical compliance.

**Single theorem target:** `msc_cp_user_legal_undertaking`

**AI interpretation for later formalization:** Use of the CP is associated with the source’s disclaimer and user undertaking to hold harmless and indemnify the U.S. Government, its agents, and employees for the listed claims; any formal representation must preserve the stated scope and receive legal-domain review.

**Qualifications and exceptions:**

- Retained because the plan does not exclude process or non-network obligations.
- No legal validity or enforceability is established by this interpretation; a legal-domain model is unresolved.

Scope or resolved-interpretation notes: REQ-I13.

**Verbatim indexed evidence:**

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u017.s001` (PDF page 9):

> This CP is provided “as is.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u017.s002` (PDF page 9):

> ” Any express or implied warranties, including but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u017.s003` (PDF page 9):

> In no event must the United States (U.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u017.s004` (PDF page 9):

> S.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u017.s005` (PDF page 9):

> ) Government be liable for any direct, indirect, incidental, special, exemplary or consequential damages (including, but not limited to, procurement of substitute goods or services, loss of use, data, or profits, or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this CP, even if advised of the possibility of such damage.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u018.s001` (PDF page 9):

> The User of this CP agrees to hold harmless and indemnify the U.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u018.s002` (PDF page 9):

> S.

- `CSFC-MSC-1.3.0-4e40e3d83708:p009:u018.s003` (PDF page 9, 10):

> Government, its agents and employees from every claim or liability (whether in tort or in contract), including attorney’s fees, court costs, and expenses, arising in direct consequence of Recipient’s use of the item, including, but not limited to, claims or liabilities made for injury to or death of personnel of User or third parties, damage to or destruction of property of User or third parties, and infringement or other violations of intellectual property or technical data rights.

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u002.s001` (PDF page 10):

> Nothing in this CP is intended to constitute an endorsement, explicit or implied, by the U.

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u002.s002` (PDF page 10):

> S.

- `CSFC-MSC-1.3.0-4e40e3d83708:p010:u002.s003` (PDF page 10):

> Government of any particular manufacturer’s product or service.

## Open interpretation issues

### REQ-I01: Standalone encapsulator boundary and requirement strength conflict

§4.2.3 and §5.5 require all Solution Component obligations; below Figure 8 the encapsulation step is outside the solution with DM/PF highly recommended; MD-13 mandates §11.1 treatment. Resolve applicability without silently deleting any passage.

Groups: RG-015.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s004`, `CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s004`, `CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`.

### REQ-I02: Same-level filtering sentence conflicts with the permitted peers

§5.2 says to prevent same-security-level communication. Other provisions allow same-level tunnels and prohibit different-level communication. The original words remain uncorrected.

Groups: RG-014, RG-039, RG-040.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p045:u011`, `CSFC-MSC-1.3.0-4e40e3d83708:p046:u004`, `CSFC-MSC-1.3.0-4e40e3d83708:p046:u010`, `CSFC-MSC-1.3.0-4e40e3d83708:p047:u005`.

### REQ-I03: Management encryption and local exceptions

Broad two-layer Gray-management wording coexists with direct physical-management exceptions, LAN/VLAN qualification, and a same-site CNSA exemption. The scope of each exception needs a formal applicability decision.

Groups: RG-046, RG-011.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p024:u002.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s004`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s005`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s006`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s007`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s008`, `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s004`, `CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s005`, `CSFC-MSC-1.3.0-4e40e3d83708:p048:u007`.

### REQ-I04: TRANSEC requirement strength and applicability differ

Public-Internet prose says must, while OR-9 is Objective for MACsec connected to an Outer Firewall and has a blank Alternatives cell.

Groups: RG-032.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s004`, `CSFC-MSC-1.3.0-4e40e3d83708:p044:u008`.

### REQ-I05: New-version compliance deadline conflict

§13.3 specifies six months from notification; GD-11 specifies the next registration renewal. No precedence is supplied.

Groups: RG-061.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p058:u002.s004`, `CSFC-MSC-1.3.0-4e40e3d83708:p051:u006`.

### REQ-I08: AS connection scope wording

The prose says AS must not connect to both Gray and/or Red Networks; AA-2 says only one site’s network. Network/layer/site cardinality needs a source-faithful formal definition.

Groups: RG-024.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s005`, `CSFC-MSC-1.3.0-4e40e3d83708:p042:u011`.

### REQ-I09: Gray address-only restrictions and explicit non-tunnel exceptions

Only-peer-address rules must be interpreted with the separately enumerated management/control/revocation allowances; blindly conjoining unqualified allowlists would lose allowed traffic.

Groups: RG-039, RG-040.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p046:u004`, `CSFC-MSC-1.3.0-4e40e3d83708:p046:u006`, `CSFC-MSC-1.3.0-4e40e3d83708:p046:u007`, `CSFC-MSC-1.3.0-4e40e3d83708:p046:u012`, `CSFC-MSC-1.3.0-4e40e3d83708:p047:u004`, `CSFC-MSC-1.3.0-4e40e3d83708:p047:u005`, `CSFC-MSC-1.3.0-4e40e3d83708:p047:u007`, `CSFC-MSC-1.3.0-4e40e3d83708:p047:u008`.

### REQ-I10: Objective table row has no Alternative marker

PF-10 is Objective with a blank Alternatives cell despite §8.1 describing optional objectives as marked Optional. Preserve the blank and seek review.

Groups: RG-038.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p045:u008`.

### REQ-I11: MACsec provisioning paragraph uses VPN terminology

The certificate-based MACsec paragraph names the Inner VPN Gateway CSR. Do not silently correct the quotation; identify the intended device in later formalization.

Groups: RG-048.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s002`.

### REQ-I12: External annex dependencies are not supplied

Key management, symmetric key management, continuous monitoring, enterprise Gray implementation, and testing annex contents are outside the supplied PDF. Relocation markers are preserved in background, with referents; their substantive obligations cannot be recovered here.

Groups: RG-007, RG-011, RG-075.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p026:u008.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p031:u003.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p031:u003.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p031:u005.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p031:u007.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p031:u007.s002`.

### REQ-I15: EAP-TLS CAK derivation and blanket KGS generation wording

The authentication prose derives a CAK from the EAP-TLS MSK, then says all CAKs and CKNs must be generated by an NSA-approved KGS. The applicability of the KGS requirement to the certificate-derived branch must be resolved without changing either quotation.

Groups: RG-024, RG-027.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s002`.

## Evidence scope notes

### REQ-I14: Figures and protocol examples do not prove compliance

Figures and protocol examples support source-grounded, clause-specific requirement assessments. Implementation tests and theorem proofs require later evidence and models. That ordinary evidence boundary does not prevent extracting the requirements illustrated by an example.

Groups: RG-007, RG-074, RG-019.

Status: acknowledged_limit.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p010:u008.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p010:u008.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p022:u002.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p022:u002.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s004`, `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s005`, `CSFC-MSC-1.3.0-4e40e3d83708:p028:u002.s006`.

## Domain review scope

### REQ-I13: Legal-domain interpretation remains unreviewed

The legal undertaking is retained as a non-network obligation. Its formal applicability and any legal meaning need dedicated review; the extraction makes no enforceability claim.

Groups: RG-076.

Status: legal_formalization_unreviewed.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p009:u017.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p009:u017.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p009:u017.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p009:u017.s004`, `CSFC-MSC-1.3.0-4e40e3d83708:p009:u017.s005`, `CSFC-MSC-1.3.0-4e40e3d83708:p009:u018.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p009:u018.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p009:u018.s003`.

## Resolved interpretations

### REQ-I06: AW host and VM restrictions apply together

Separate service VMs must also respect the AW host restriction. Distinct VMs do not authorize provisioning, enrollment, registration, or SIEM VMs on an AW-dedicated host.

Groups: RG-045.

Status: resolved_by_cumulative_applicability.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s005`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s006`, `CSFC-MSC-1.3.0-4e40e3d83708:p049:u011`, `CSFC-MSC-1.3.0-4e40e3d83708:p049:u012`, `CSFC-MSC-1.3.0-4e40e3d83708:p049:u016`.

### REQ-I07: Physical, cryptographic, and ACL separation apply together

The minimum logical separation required by DM-25 does not waive the physical and cryptographic separation in §4.1.4. The conditions can be imposed together.

Groups: RG-044.

Status: resolved_by_cumulative_applicability.

Sources: `CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p013:u008.s004`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u005.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s001`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s002`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s003`, `CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s004`, `CSFC-MSC-1.3.0-4e40e3d83708:p049:u013`.
