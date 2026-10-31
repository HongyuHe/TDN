# CSfC role ontology curation notes

The curated decisions cover all 76 role records in the current extraction. The decision file contains 40 source-backed subclass edges, 31 nonlogical association annotations, and 14 excluded inferences. Eight navigational families assign every role exactly once. The source-backed subclass graph is acyclic; adding the 44 generated root edges connects every role to the analyst-defined root.

## Class interpretation

Each role class denotes the entities or bearers that realize the extracted role or concept in its source context. The inventory includes devices, services, aggregates, mixed authorities, and protocol functions. The ontology preserves those distinctions without introducing one physical-device superclass for every record. The existing role IDs, descriptions, lexical aliases, and source records remain unchanged.

The root `ExtractedRole` is an analyst-defined organizational category. The root does not reproduce a definition from the CP. A generated subclass edge connects each role without a curated parent to the root. Generated edges must remain visibly and structurally distinguishable from the source-backed decisions in `subclass_edges`.

Every curated subclass edge asserts inclusion throughout the intended source-context class. A qualification records scope or explains what the edge does not entail; a qualification cannot weaken an OWL subclass axiom into a conditional statement. Conditional source relationships therefore appear as annotations or excluded inferences. No class-equivalence, disjointness, exhaustive-covering, existential, cardinality, or universal-property restriction is introduced.

Association records annotate relationships between the role class IRIs. The exporter must declare the relation predicates as OWL annotation properties and preserve each record's evidence and qualifications. The records do not assert relationships between every possible class member or require any deployed individual. The OWL specification distinguishes subclass axioms from annotations and states that annotations do not change logical consequences. See [W3C subclass axioms](https://www.w3.org/TR/owl2-syntax/#Subclass_Axioms) and [W3C annotations](https://www.w3.org/TR/owl2-syntax/#Annotations).

Navigational families organize the viewer only. Family membership must not generate an OWL class, subclass edge, disjointness constraint, or equivalence. In particular, a family can group entities that provide related functions without claiming a common source-defined superclass.

## Evidence and decisions

Subtype decisions use the source glossary, explicit component descriptions, and named specializations. A `source_stated` basis marks direct inclusion or a definition. A `source_interpretation` basis marks the curator's conversion of a named specialization or section context into class inclusion. Both bases remain reviewable, and every decision cites a minimal relevant set of complete source IDs.

| Decision | Evidence and interpretation |
| --- | --- |
| VPN Gateway and MACsec Device are Encryption Component subtypes. | `CSFC-MSC-1.3.0-4e40e3d83708:p060:u004.s001` directly includes both alternatives in the glossary definition. No converse union or equivalence axiom is added. |
| Inner and outer VPN/MACsec specializations have two parents. | The gateway/device parent captures type. The inner/outer Encryption Component parent captures the source layer specialization. Inner requirements are identified by `p042:u016.s002` and `p042:u018`; outer requirements by `p043:u010.s002` and `p043:u012`. Full IDs appear in the JSON. |
| Key Server is a MACsec Device subtype. | `CSFC-MSC-1.3.0-4e40e3d83708:p060:u013.s001` defines the role as the designated MACsec Device. The edge does not make every MACsec Device a Key Server. |
| AW is a Management component subtype. | `CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s001` and `.s002` describe AWs and the management components whose collective functionality satisfies administration needs. The generic Management component parent does not imply Solution Component membership. |
| Red and Gray AWs are Solution Components. | Section 5 includes AWs among solution components, and `p024:u010.s003` and `p026:u002.s003` require Gray and Red AWs. The generic AW class has no Solution Component parent because the inventory also includes the Black AW prohibition. |
| Core encryption, selected firewalls, MSC AS, and KGS are Solution Components. | Section 5 introduces encryption components and KGS. The Outer Firewall exception presupposes membership among individual solution components. Gray Firewalls are listed among the components. `CSFC-MSC-1.3.0-4e40e3d83708:p037:u003` explicitly lists Authentication Servers among solution components. Membership does not assert mandatory deployment. |
| CA specializations remain distinct. | Inner, outer, local, enterprise, root, signing, and trust-anchor categories each have CA as their parent. Generic CA membership in Solution Component is not asserted. Local/enterprise options are not made disjoint. |
| Root CA is an example realization of the trust-anchor role. | `CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s005` through `.s007` provide the certificate-level example. The association is qualified and nonlogical. Root CA has no Trust Anchor CA subclass or equivalence assertion. |
| Gray, screening, and customer-edge router categories are Router subtypes. | The source calls the first an ordinary router and names the other router specializations. Router has no Solution Component parent. Customer Edge Router has no Screening Router parent. |
| Key and certificate management component specializes Management component. | `CSFC-MSC-1.3.0-4e40e3d83708:p026:u007` names the category. The edge interprets the category name only. It supplies no annex content, physical realization, or CA membership. |

The nonlogical associations retain relationships that would be misleading as subclass edges. Those relationships include AW administration, optional VM or physical-workstation realization, host-to-VM hosting, MACsec authentication functions, peer key distribution, conditional perimeter placement, log collection, management-service composition, certificate provisioning, and RA support for a CA. Every association retains its source conditions in the decision file.

## Source limitations preserved

The standalone encapsulator retains the unresolved boundary issue `REQ-I01`. The source applies Solution Component requirements in `CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s004`, `p025:u007.s003`, and `p042:u004`. The source also places the additional encapsulation step outside the solution and recommends device-management and port-filtering requirements in `p020:u002.s002` and `.s003`. The ontology does not resolve the conflict through a universal Encapsulation/Decapsulation Device subclass of Solution Component.

The router exclusions prevent requirement inheritance from spreading to external or supporting devices. `CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s004` withholds CP security requirements from the ordinary Gray Network router in the redundancy example. `CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s006` excludes the screening router from the MSC Solution. The subtype graph preserves both distinctions.

The administration annotations preserve realization and hosting boundaries. AWs can be virtual or physical, and their physical hosts are separate entities. The current requirement review resolves REQ-I06 by applying AW-host exclusivity and VM-separation requirements together. The ontology does not encode those operational constraints or derive class disjointness from cohosting prohibitions. The management-service aggregates remain separate from their constituent components.

The protocol endpoint roles remain separate from the encryption hardware categories. The source describes IKE initiator/responder messages and MACsec supplicant/authenticator functions. Those passages support protocol/function annotations, but they do not establish a physical-device taxonomy for every endpoint or function. No individual participant or deployed device is created.

The ontology curation does not resolve the extraction's outstanding source-interpretation issues or prove deployment compliance. Missing subtype edges mean that inclusion was not established in the curated evidence. Missing edges do not assert disjointness, negation, absence, or impossibility.

## Verification performed

Mechanical verification resolved every decision source ID against the current source index. Every child, parent, association endpoint, and family member resolves to an existing role ID. Family membership is an exact partition of the 76 roles. The subtype graph contains no duplicate edges or cycles, and every connected component reaches an unparented role that the exporter can attach to the organizational root.

The input SHA-256 fields bind the decisions to the current role inventory and source index. The curation read the relevant source passages in the component, management, provisioning, requirements, and glossary sections. Rendered physical PDF pages 22 and 30 were inspected to confirm the Section 5 component context and the administration, virtualization, and certificate-chain context. Source snippets split by the literal-period extraction rule were read with their adjacent fragments.

The checks establish reference integrity and a reviewable conservative hierarchy. Independent semantic review and export/visualization verification remain separate tasks. No existing source, role inventory, requirement, script, test, manifest, or Git state was edited by the curation task.
