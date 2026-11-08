# Selected v3.1 interpretation records

These decisions accompany the role-to-theory mapping. The records preserve the chosen reading used during v3.1 construction.

## V31-007 — V31-007: data-plane protection, tunnel endpoints, and services

Affected groups: RG-007, RG-008, RG-029, RG-030, RG-035. Original pages 10–14, 18–19, 22–25, 42–47. Page 10 requires Inner encryption followed by Outer encryption and reverse Outer/Inner decryption. Pages 12–13 distinguish protected data from permitted control traffic. Arbitrary classified payloads cannot be labelled harmless control.

The selected reading tracks protected payload identities through complete executions. Gray transmission carries Inner protection. Black transmission carries Outer around Inner, with ordered encryption and matching configured endpoints. A completed cross-Black plaintext delivery has ordered reverse decryption. Local Red deliveries that never cross Black do not acquire a fictitious two-decryption duty. The mechanism type admits exactly the four IPsec/MACsec combinations. Outer MACsec restricts the solution to two sites.

The page-22 service clause remains recorded. Under the explicit user optional-management scope, actual management deployment requires its workstations and method-specific CA/KGS infrastructure. Different levels sharing an Outer still require a Gray Firewall. These facts do not gate the packet-transition relation. Management-free packet results have no administrative service-presence prerequisite. The user scope is a stated modeling choice, not a claim that the source's unconditional architectural wording disappeared. Cryptographic confidentiality, integrity, key independence, and faithful operation labels require separately justified primitive and implementation correspondence. Event ordering alone does not establish cryptographic secrecy. Affected declarations: ArchitectureServices, Flow.Valid, CrossedBlack, msc_nested_layer_protection, LayerNoBypass. Inherited decision: INT-007.

## V31-012 — V31-012: authentication alternatives and management deployment

Affected group: RG-012. Original page 16, with pages 15–18. Separate CAs, CAKs, and management devices apply to the chosen certificate or shared-key method. Certificate authorities and effective trust closures differ across full levels. PSK identities differ across full levels. Cross-level mutual authentication and established tunnels are both prohibited.

Management presence and separation apply when management is deployed. A packet-only snapshot cannot establish management-device presence. Figure 5 has two Secret U.S.-only networks at the same full level. Different names do not create different levels. Additional same-level filtering is permitted. Inherited decision: INT-012.

## V31-013 — V31-013: all Gray paths, filtering, and management services

Affected group: RG-013. Original pages 17–18, 24, 35. SR-7 covers every physical Gray path between different-level Inners. SR-8 separately names a CA, AW, and CDP/OCSP responder at a different level. The page-18 highest-level convention names Gray AWs and locally run CAs. It does not assign every CDP/OCSP service to the highest level.

The selected reading assigns the highest level to Gray AWs and locally run CAs, retains the broader SR-8 cut for each named service when its actual level differs, and includes enterprise CAs in SR-8. Actual filtering rejects unintended or cross-level Inner endpoints. Highest-group management traffic to lower Inners is rejected. Outer filtering remains mandatory with standalone Gray Firewalls. Gray Firewalls retain classified-device physical protection and placement between Inner and Outer. The word typically does not cancel SR-7 or SR-8. Physical protection and the classification ordering require authoritative external facts.

## V31-015 — V31-015: carrier placement and standalone obligations

Affected group: RG-015. Original pages 19–20, 25, 42. Encapsulation is required when MACsec is Inner or crosses IP. Inner encapsulation precedes Outer encryption. A carrier preserves the MACsec body until its destination. Unsupported built-in encapsulation requires a standalone device with the stated internal/Inner and external/Outer attachments. The protocol needs AO approval.

Pages 19 and 25 impose all applicable Solution Component duties on the standalone device. MD-13 separately confirms Section 11.1 inclusion. Page 20 places the additional step outside the boundary and recommends DM/filtering. Those passages do not cancel the explicit mandatory device duties. Fixed technical meanings and typed external duties replace the caller-supplied catalogue. External records and concrete implementation bindings remain unresolved proof/evidence obligations. The encapsulate event denotes wrapping the exact existing body. Refinement must connect that event to the active carrier operation and the actual remote decapsulator. Inherited decision: INT-015.

## V31-024 — V31-024: certificate roles and AS network scope

Affected group: RG-024. Original pages 14, 20, 26, 41–42. MD-3 and MD-14 are both Threshold alternatives. PSK uses a shared CAK. EAP-TLS uses device certificates, mutual AS admission, MSK-derived CAKs, and both supplicant and authenticator functions at each device. Both functions are supported across arrangements; simultaneity is not imposed.

AA-2 limits the AS to one site network. The ambiguous page-14 both Gray and/or Red wording is read as forbidding one AS from bridging Red and Gray or several site networks. A nonempty attachment list identifies one site and one zone, either Red or Gray. A ban on every Red and every Gray attachment would prevent the described architecture and is rejected.

Key-server peer authentication and SAK issuance remain explicit. Every MACsec encryption history has key-server authentication before SAK issuance. A trust-list entry alone does not prove an EAP-TLS handshake. The implementation connection remains outstanding. Inherited decision: INT024.

## V31-027 — V31-027: key generation, provisioning, central servers, fallback

Affected group: RG-027. Original pages 20, 29, 41–42. Page 20 explicitly requires all CAKs and CKNs from an NSA-approved KGS while also describing EAP-MSK-derived CAKs. Both duties are retained: an EAP-derived CAK needs an approved generation mechanism. An arbitrary EAP implementation is not assumed approved. Exempting all EAP CAKs from the word all is rejected. Approval remains external.

Each CKN has at least 16 bytes and approved generator provenance. PSK provisioning identifies an authorized Security Administrator obtaining the key before applying it to both endpoints. Each actual tunnel has values 0 and 1 for its key-server pair. A present central management site supplies the server endpoint. The pair central-site declaration must bind the actual deployment; omitting that fact cannot establish the conditional duty.

Fallback means configured alternate CAKs for fallback or rollover. Fresh CAKs from a new authenticated EAP exchange remain permitted. The current INT-MD15-20261024 input was reviewed with the original page-42 row. Its fresh-process and unchanged-configuration assumptions remain explicit. No approval fact is inferred from that interpretation.

## V31-047 — V31-047: live sessions and individual credentials

Affected group: RG-047. Original pages 48–49. Every operation has earlier authentication bound to the same person, component, account, session, and operation token. Logout/revocation invalidates subsequent operations. Selected CNSA/NIST objectives require actual conformity facts in addition to captured flags. Every declared AW administrator has an individual account. AW group accounts are prohibited. Different people have distinct credentials.

A captured certificate identity is not automatically a verified person. Person/account/session ownership and complete lifecycle inventories remain application obligations. Packet behavior does not require an administrative application. Inherited decisions: INT-047-SESSION and INT-047-service-history.

## V31-056-074 — V31-056-074: whole-solution protection and redundant duties

Affected groups: RG-056 and RG-074. Original pages 21–25, 36 and the SR-14 footnote. Every physical Red egress crosses a CP-conforming MSC solution or AO-approved data-in-transit solution. Crossing an Inner alone is insufficient. Government-certified and CSfC paths may coexist without an unprotected path.

Every actual redundant solution component retains its fixed applicable CP duties, including Outer Firewalls and selected management components. Ordinary Gray routing infrastructure receives no invented CP security obligation. Standalone encapsulators keep RG-015 duties. Possible failover does not create an automatic availability guarantee. The fixed duty expansion and external assumption boundary remain visible. No whole-group proof completion is claimed.

## V31R-033 — RG-033: external interface sizes and optional Inner reduction

The source review uses SR-23 on physical PDF pages 36–37 and IR-2 on pages 42–43. The original [CSfC document](../../extraction/source/CSfC_documentation_v1.3.0.pdf) preserves both passages.

SR-23 requires packet-size configuration that prevents further fragmentation at the external interface of a Gray Firewall or Encryption Component. The selected interpretation includes the Inner encryptor’s Gray-facing interface and the Outer encryptor’s Black-facing interface. Both interfaces are external interfaces of encryption components. The source provides no Inner exclusion. The Gray Firewall’s applicable external interfaces are included as well.

IR-2 adds an optional objective for Inner components: reduce fragmentation and its performance impact while considering Outer and Black limits. That comparison remains separate from the mandatory local MTU bound. The concrete baseline and shared applications leave the optional comparison unselected.

Round 001 exposed an incorrect separation: the mandatory no-further-fragmentation clause selected only the Gray-Firewall/Outer sizing role. The corrected clause also selects the Inner external role. The existing recorded size limits already covered both roles. The correction therefore strengthens the specification and general proof without weakening the recorded checks.

The sizing inventory links each record to the actual device, interface and zone. Inner Gray interfaces use `innerExternal`; Outer Black interfaces and applicable Gray Firewall external interfaces use `grayFirewallOrEncryptionExternal`. These names classify interfaces for the proof. Device kinds and the source ontology remain unchanged.

The accepted interpretation requires a proof about actual represented emissions. A stored MTU or a count of sizing records alone cannot establish the requirement. Source preparation, subsequent processing, header and encryption overhead, and final transmission must satisfy the corresponding size bounds. The instantiated applications cover the selected IPv4/IPsec processing model and retain its explicit implementation assumptions.
