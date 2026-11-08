# Requirement groups and their Lean formalizations

Every group in [requirement_groups.md](requirement_groups.md) appears once in the two tables below: [24 RGs targeted for proof](#24-rgs-targeted-for-proof) and [52 remaining RGs](#52-remaining-rgs). The links point to the current v3.1 code and its source lines, checked on November 5, 2026.

The active theory has **24 dedicated top-level specifications** in [CompleteSpecifications.lean](../TDN/Targets/CompleteSpecifications.lean). All 24 belong to the namespace `TDN.Targets.Complete`. Fourteen have passed complete-candidate proof review, and ten remain deferred. The other **52 groups are represented by cases in the shared [CPContext.BaseSourceMeaning](../TDN/Targets/CPDuties.lean#L209) definition**. Those cases retain configuration conditions, external-evidence requirements, or permission conditions. They are not separate complete-specification declarations.

A specification states a proposition that a network must satisfy. A supporting theorem proves that proposition under stated assumptions. The tables link to the specification or shared condition. “Review passed” means the recorded model applications have complete proofs under their explicit assumptions. “Proof deferred” means the dedicated specification exists, but its complete proof remains unfinished. The treatment of the other groups follows [proof_scope.json](proof_scope.json); their shared cases do not imply that every original requirement clause has been proved or fully represented.

## 24 RGs targeted for proof

These groups are the proof targets selected in [proof_scope.json](proof_scope.json). Each has a dedicated specification in `TDN.Targets.Complete`. Fourteen have passed review, and ten remain deferred. The RG links open the original requirement groups.

| RG | Requirement group | Current formalization in Lean | Proof status or workflow treatment |
| --- | --- | --- | --- |
| [RG-007](requirement_groups.md#rg-007) | Two independent encryption layers and allowed tunnel pairings | [msc_nested_layer_protection](../TDN/Targets/CompleteSpecifications.lean#L6) | Proof deferred |
| [RG-008](requirement_groups.md#rg-008) | Connectivity restricted to the same security level | [msc_security_level_connectivity](../TDN/Targets/CompleteSpecifications.lean#L10) | Proof deferred |
| [RG-012](requirement_groups.md#rg-012) | Separate authentication and management for security levels | [msc_security_level_key_and_management_separation](../TDN/Targets/CompleteSpecifications.lean#L17) | Review passed |
| [RG-013](requirement_groups.md#rg-013) | Gray Firewalls on all paths needing level separation | [msc_gray_firewall_path_coverage](../TDN/Targets/CompleteSpecifications.lean#L20) | Review passed |
| [RG-014](requirement_groups.md#rg-014) | Gray addressing supports security-level filtering | [msc_gray_addressing_for_level_filtering](../TDN/Targets/CompleteSpecifications.lean#L23) | Review passed |
| [RG-015](requirement_groups.md#rg-015) | MACsec encapsulation and standalone encapsulator obligations | [msc_macsec_encapsulation](../TDN/Targets/CompleteSpecifications.lean#L27) | Proof deferred |
| [RG-021](requirement_groups.md#rg-021) | VPN private-key access confinement | [msc_vpn_private_key_confinement](../TDN/Targets/CompleteSpecifications.lean#L33) | Review passed |
| [RG-024](requirement_groups.md#rg-024) | MACsec authentication alternatives and AS scope | [msc_macsec_authentication_choice_and_as](../TDN/Targets/CompleteSpecifications.lean#L38) | Proof deferred |
| [RG-027](requirement_groups.md#rg-027) | MACsec key generation, key-server selection, and rollover | [msc_macsec_key_generation_and_server](../TDN/Targets/CompleteSpecifications.lean#L43) | Review passed |
| [RG-028](requirement_groups.md#rg-028) | MACsec mandatory protection parameters | [msc_macsec_protection_parameters](../TDN/Targets/CompleteSpecifications.lean#L49) | Proof deferred |
| [RG-029](requirement_groups.md#rg-029) | Inner encryption and decryption cannot be bypassed | [msc_inner_tunnel_no_bypass](../TDN/Targets/CompleteSpecifications.lean#L53) | Proof deferred |
| [RG-030](requirement_groups.md#rg-030) | Outer encryption and decryption cannot be bypassed | [msc_outer_tunnel_no_bypass](../TDN/Targets/CompleteSpecifications.lean#L59) | Proof deferred |
| [RG-032](requirement_groups.md#rg-032) | TRANSEC under the stated deployment conditions | [msc_transec_conditions](../TDN/Targets/CompleteSpecifications.lean#L65) | Review passed |
| [RG-033](requirement_groups.md#rg-033) | Packet sizing to control fragmentation | [msc_packet_size_configuration](../TDN/Targets/CompleteSpecifications.lean#L67) | Review passed |
| [RG-034](requirement_groups.md#rg-034) | Outer Firewall placement for untrusted Black transport | [msc_outer_firewall_placement](../TDN/Targets/CompleteSpecifications.lean#L73) | Review passed |
| [RG-035](requirement_groups.md#rg-035) | Permitted protocols and peers at encryption and firewall boundaries | [msc_boundary_interface_filtering](../TDN/Targets/CompleteSpecifications.lean#L75) | Review passed |
| [RG-037](requirement_groups.md#rg-037) | Outer-component third-party contact restrictions | [msc_outer_third_party_services](../TDN/Targets/CompleteSpecifications.lean#L80) | Review passed |
| [RG-038](requirement_groups.md#rg-038) | IP header and multicast filtering | [msc_ip_header_and_multicast_filtering](../TDN/Targets/CompleteSpecifications.lean#L84) | Review passed |
| [RG-039](requirement_groups.md#rg-039) | Outer Gray-interface allowlist and default denial | [msc_outer_gray_interface_policy](../TDN/Targets/CompleteSpecifications.lean#L88) | Review passed |
| [RG-040](requirement_groups.md#rg-040) | Gray Firewall allowlist and cross-level denial | [msc_gray_firewall_allowlist](../TDN/Targets/CompleteSpecifications.lean#L91) | Review passed |
| [RG-047](requirement_groups.md#rg-047) | Administrator authentication and individual credentials | [msc_administrator_authentication](../TDN/Targets/CompleteSpecifications.lean#L94) | Review passed |
| [RG-054](requirement_groups.md#rg-054) | Interoperable components across communicating sites | [msc_site_interoperability](../TDN/Targets/CompleteSpecifications.lean#L101) | Proof deferred |
| [RG-056](requirement_groups.md#rg-056) | Approved physical paths out of Red Networks | [msc_approved_red_egress_paths](../TDN/Targets/CompleteSpecifications.lean#L106) | Proof deferred |
| [RG-074](requirement_groups.md#rg-074) | Redundant component and load-balancing permission | [msc_redundant_component_permission](../TDN/Targets/CompleteSpecifications.lean#L114) | Proof deferred |

## 52 remaining RGs

These groups are assigned to direct checks, external evidence, or permission and applicability assessment. Each link points to the corresponding `| N =>` branch of `TDN.Targets.Complete.CPContext.BaseSourceMeaning`.

| RG | Requirement group | Current formalization in Lean | Proof status or workflow treatment |
| --- | --- | --- | --- |
| [RG-001](requirement_groups.md#rg-001) | Applicable requirements and policy precedence | No dedicated top-level spec; [BaseSourceMeaning — shared case 1](../TDN/Targets/CPDuties.lean#L216) | Assigned to direct checks |
| [RG-002](requirement_groups.md#rg-002) | Validated configuration and component modification | No dedicated top-level spec; [BaseSourceMeaning — shared case 2](../TDN/Targets/CPDuties.lean#L217) | Requires external evidence |
| [RG-003](requirement_groups.md#rg-003) | Product eligibility on the CSfC Components List | No dedicated top-level spec; [BaseSourceMeaning — shared case 3](../TDN/Targets/CPDuties.lean#L222) | Requires external evidence |
| [RG-004](requirement_groups.md#rg-004) | Independent product, operating-system, and cryptographic implementations | No dedicated top-level spec; [BaseSourceMeaning — shared case 4](../TDN/Targets/CPDuties.lean#L226) | Assigned to direct checks |
| [RG-005](requirement_groups.md#rg-005) | Physical separation of security components | No dedicated top-level spec; [BaseSourceMeaning — shared case 5](../TDN/Targets/CPDuties.lean#L227) | Assigned to direct checks |
| [RG-006](requirement_groups.md#rg-006) | Product Supply Chain Threat Assessment | No dedicated top-level spec; [BaseSourceMeaning — shared case 6](../TDN/Targets/CPDuties.lean#L228) | Requires external evidence |
| [RG-009](requirement_groups.md#rg-009) | Gray-network control and classification boundary | No dedicated top-level spec; [BaseSourceMeaning — shared case 9](../TDN/Targets/CPDuties.lean#L233) | Requires external evidence |
| [RG-010](requirement_groups.md#rg-010) | Independently managed site administration and trust | No dedicated top-level spec; [BaseSourceMeaning — shared case 10](../TDN/Targets/CPDuties.lean#L234) | Assigned to direct checks |
| [RG-011](requirement_groups.md#rg-011) | Central management, CA placement, and intersite protection | No dedicated top-level spec; [BaseSourceMeaning — shared case 11](../TDN/Targets/CPDuties.lean#L241) | Assigned to direct checks |
| [RG-016](requirement_groups.md#rg-016) | Permitted MACsec clear VLAN tags and XPN | No dedicated top-level spec; [BaseSourceMeaning — shared case 16](../TDN/Targets/CPDuties.lean#L242) | Assigned to direct checks |
| [RG-017](requirement_groups.md#rg-017) | Mutual authentication and Non-Person Entity certificates | No dedicated top-level spec; [BaseSourceMeaning — shared case 17](../TDN/Targets/CPDuties.lean#L245) | Assigned to direct checks |
| [RG-018](requirement_groups.md#rg-018) | CNSS algorithm-policy requirements and choices | No dedicated top-level spec; [BaseSourceMeaning — shared case 18](../TDN/Targets/CPDuties.lean#L246) | Assigned to direct checks |
| [RG-019](requirement_groups.md#rg-019) | IPsec CNSA profile and post-quantum exchange sequence | No dedicated top-level spec; [BaseSourceMeaning — shared case 19](../TDN/Targets/CPDuties.lean#L250) | Assigned to direct checks |
| [RG-020](requirement_groups.md#rg-020) | VPN certificate loading and authentication checks | No dedicated top-level spec; [BaseSourceMeaning — shared case 20](../TDN/Targets/CPDuties.lean#L251) | Assigned to direct checks |
| [RG-022](requirement_groups.md#rg-022) | IKEv2 and IKE/ESP encryption-mode alternatives | No dedicated top-level spec; [BaseSourceMeaning — shared case 22](../TDN/Targets/CPDuties.lean#L253) | Assigned to direct checks |
| [RG-023](requirement_groups.md#rg-023) | VPN SA lifetimes and reauthentication | No dedicated top-level spec; [BaseSourceMeaning — shared case 23](../TDN/Targets/CPDuties.lean#L254) | Assigned to direct checks |
| [RG-025](requirement_groups.md#rg-025) | MACsec encryption and key wrapping algorithms | No dedicated top-level spec; [BaseSourceMeaning — shared case 25](../TDN/Targets/CPDuties.lean#L262) | Assigned to direct checks |
| [RG-026](requirement_groups.md#rg-026) | MACsec EAP-TLS CNSA profile alternatives | No dedicated top-level spec; [BaseSourceMeaning — shared case 26](../TDN/Targets/CPDuties.lean#L265) | Assigned to direct checks |
| [RG-031](requirement_groups.md#rg-031) | Routing and switching limits on Encryption Components | No dedicated top-level spec; [BaseSourceMeaning — shared case 31](../TDN/Targets/CPDuties.lean#L268) | Assigned to direct checks |
| [RG-036](requirement_groups.md#rg-036) | Minimal network-interface exposure | No dedicated top-level spec; [BaseSourceMeaning — shared case 36](../TDN/Targets/CPDuties.lean#L272) | Assigned to direct checks |
| [RG-041](requirement_groups.md#rg-041) | Control-plane approval, defaults, and service location | No dedicated top-level spec; [BaseSourceMeaning — shared case 41](../TDN/Targets/CPDuties.lean#L274) | Assigned to direct checks |
| [RG-042](requirement_groups.md#rg-042) | Layer-specific trusted time synchronization | No dedicated top-level spec; [BaseSourceMeaning — shared case 42](../TDN/Targets/CPDuties.lean#L275) | Assigned to direct checks |
| [RG-043](requirement_groups.md#rg-043) | Default credentials, DNS, and remote bootstrap | No dedicated top-level spec; [BaseSourceMeaning — shared case 43](../TDN/Targets/CPDuties.lean#L276) | Assigned to direct checks |
| [RG-044](requirement_groups.md#rg-044) | Layer-specific administration and management-plane separation | No dedicated top-level spec; [BaseSourceMeaning — shared case 44](../TDN/Targets/CPDuties.lean#L277) | Assigned to direct checks |
| [RG-045](requirement_groups.md#rg-045) | Dedicated, protected, hardened Administrative Workstations | No dedicated top-level spec; [BaseSourceMeaning — shared case 45](../TDN/Targets/CPDuties.lean#L278) | Assigned to direct checks |
| [RG-046](requirement_groups.md#rg-046) | Management transport protection and local exceptions | No dedicated top-level spec; [BaseSourceMeaning — shared case 46](../TDN/Targets/CPDuties.lean#L282) | Assigned to direct checks |
| [RG-048](requirement_groups.md#rg-048) | Authorized provisioning and initial certificate requests | No dedicated top-level spec; [BaseSourceMeaning — shared case 48](../TDN/Targets/CPDuties.lean#L283) | Assigned to direct checks |
| [RG-049](requirement_groups.md#rg-049) | Personnel clearance and Outer administration | No dedicated top-level spec; [BaseSourceMeaning — shared case 49](../TDN/Targets/CPDuties.lean#L284) | Requires external evidence |
| [RG-050](requirement_groups.md#rg-050) | SIEM placement, collection, alerting, and log transport | No dedicated top-level spec; [BaseSourceMeaning — shared case 50](../TDN/Targets/CPDuties.lean#L285) | Requires external evidence |
| [RG-051](requirement_groups.md#rg-051) | Cross Domain Solution approval conditions | No dedicated top-level spec; [BaseSourceMeaning — shared case 51](../TDN/Targets/CPDuties.lean#L286) | Requires external evidence |
| [RG-052](requirement_groups.md#rg-052) | Physical protection, authorized access, and disposal | No dedicated top-level spec; [BaseSourceMeaning — shared case 52](../TDN/Targets/CPDuties.lean#L290) | Requires external evidence |
| [RG-053](requirement_groups.md#rg-053) | Parallel Inner components and distinct Outer internal interfaces | No dedicated top-level spec; [BaseSourceMeaning — shared case 53](../TDN/Targets/CPDuties.lean#L297) | Assigned to direct checks |
| [RG-055](requirement_groups.md#rg-055) | Firewall requirements when combining capability packages | No dedicated top-level spec; [BaseSourceMeaning — shared case 55](../TDN/Targets/CPDuties.lean#L303) | Requires external evidence |
| [RG-057](requirement_groups.md#rg-057) | Operational security updates and TEMPEST policy | No dedicated top-level spec; [BaseSourceMeaning — shared case 57](../TDN/Targets/CPDuties.lean#L307) | Requires external evidence |
| [RG-058](requirement_groups.md#rg-058) | Hardware inventory and available baseline configuration | No dedicated top-level spec; [BaseSourceMeaning — shared case 58](../TDN/Targets/CPDuties.lean#L310) | Assigned to direct checks |
| [RG-059](requirement_groups.md#rg-059) | Procurement documentation excludes classified-protection purpose | No dedicated top-level spec; [BaseSourceMeaning — shared case 59](../TDN/Targets/CPDuties.lean#L313) | Requires external evidence |
| [RG-060](requirement_groups.md#rg-060) | Annual and NSA-authorized compliance audits | No dedicated top-level spec; [BaseSourceMeaning — shared case 60](../TDN/Targets/CPDuties.lean#L314) | Requires external evidence |
| [RG-061](requirement_groups.md#rg-061) | Registration, approval, annual renewal, and version updates | No dedicated top-level spec; [BaseSourceMeaning — shared case 61](../TDN/Targets/CPDuties.lean#L315) | Requires external evidence |
| [RG-062](requirement_groups.md#rg-062) | Audit retention, storage monitoring, backup, and continuity | No dedicated top-level spec; [BaseSourceMeaning — shared case 62](../TDN/Targets/CPDuties.lean#L317) | Assigned to direct checks |
| [RG-063](requirement_groups.md#rg-063) | Infrastructure authentication alternatives | No dedicated top-level spec; [BaseSourceMeaning — shared case 63](../TDN/Targets/CPDuties.lean#L320) | Requires external evidence |
| [RG-064](requirement_groups.md#rg-064) | Incident triggers, required report fields, and reporting deadline | No dedicated top-level spec; [BaseSourceMeaning — shared case 64](../TDN/Targets/CPDuties.lean#L322) | Requires external evidence |
| [RG-065](requirement_groups.md#rg-065) | Separation of administrative and auditing personnel | No dedicated top-level spec; [BaseSourceMeaning — shared case 65](../TDN/Targets/CPDuties.lean#L329) | Requires external evidence |
| [RG-066](requirement_groups.md#rg-066) | Personnel training and physical tamper inspections | No dedicated top-level spec; [BaseSourceMeaning — shared case 66](../TDN/Targets/CPDuties.lean#L331) | Requires external evidence |
| [RG-067](requirement_groups.md#rg-067) | Revocation or CAK destruction before disposal | No dedicated top-level spec; [BaseSourceMeaning — shared case 67](../TDN/Targets/CPDuties.lean#L332) | Requires external evidence |
| [RG-068](requirement_groups.md#rg-068) | Security Administrator operational duties | No dedicated top-level spec; [BaseSourceMeaning — shared case 68](../TDN/Targets/CPDuties.lean#L335) | Assigned to direct checks |
| [RG-069](requirement_groups.md#rg-069) | Auditor review duties and access boundary | No dedicated top-level spec; [BaseSourceMeaning — shared case 69](../TDN/Targets/CPDuties.lean#L338) | Assigned to direct checks |
| [RG-070](requirement_groups.md#rg-070) | Optional Integrator involvement and duty scope | No dedicated top-level spec; [BaseSourceMeaning — shared case 70](../TDN/Targets/CPDuties.lean#L340); currently `True` | Requires external evidence |
| [RG-071](requirement_groups.md#rg-071) | AO authorization evidence and lifecycle control | No dedicated top-level spec; [BaseSourceMeaning — shared case 71](../TDN/Targets/CPDuties.lean#L341) | Requires external evidence |
| [RG-072](requirement_groups.md#rg-072) | Whole-solution testing and preserved results | No dedicated top-level spec; [BaseSourceMeaning — shared case 72](../TDN/Targets/CPDuties.lean#L344) | Assigned to direct checks |
| [RG-073](requirement_groups.md#rg-073) | Objective software and firmware signing algorithms | No dedicated top-level spec; [BaseSourceMeaning — shared case 73](../TDN/Targets/CPDuties.lean#L347) | Requires external evidence |
| [RG-075](requirement_groups.md#rg-075) | Optional additional controls and screening-router scope | No dedicated top-level spec; [BaseSourceMeaning — shared case 75](../TDN/Targets/CPDuties.lean#L349) | Permission / applicability only |
| [RG-076](requirement_groups.md#rg-076) | CP user legal undertaking and disclaimer | No dedicated top-level spec; [BaseSourceMeaning — shared case 76](../TDN/Targets/CPDuties.lean#L351) | Requires external evidence |

## Reading the shared cases

`BaseSourceMeaning` takes a context, a subject, and a group number. The context contains the deployment, execution model, and supporting records. The subject selects a whole solution, a network, or a component. The group argument has type `Fin 76`, which represents numbers from 0 through 75. The implementation matches on `group.val + 1`, so RG-001 uses index 0 and branch 1; RG-076 uses index 75 and branch 76.

For example, RG-023 maps to [case 23](../TDN/Targets/CPDuties.lean#L254). That case requires the recorded IPsec mode and lifetime conditions and relates each recorded rekey to an earlier authenticated peer observation. RG-003 maps to [case 3](../TDN/Targets/CPDuties.lean#L222), which requires external confirmation of Components List eligibility for the specified device and product. The confirmation is an input obligation whose authority must come from outside Lean.

RG-070 currently maps to [case 70 returning `True`](../TDN/Targets/CPDuties.lean#L340). That branch adds no condition. It should not be read as a substantive formalization or proof of Integrator duties. RG-075 has a concrete [case 75](../TDN/Targets/CPDuties.lean#L349) restricting selected screening routers to devices without an encryption-layer assignment.

The shared cases are assembled by [AllApplicableDuties](../TDN/Targets/CPDuties.lean#L424), which also requires a known subject, complete supporting inventories, and the applicable Enterprise Gray conditions. The complete definitions for RG-008, RG-015, RG-056, and RG-074 use that broader obligation machinery. For those groups, follow the dedicated specification in the first table to see the full formalized statement.

Older definitions with similar short names remain elsewhere in `TDN/Targets`. The first table selects the current `TDN.Targets.Complete` specification whenever one exists, matching the [publication register](../data/publication/v3.1/register.json). Its [proof map](../data/publication/v3.1/proof_map.json) names the accepted general theorems and model applications.

## Maintenance

Update the tables when a dedicated specification is added, a shared case changes, source lines move, or a proof review changes status. Compare against the original group headings, the current Lean source, [proof_scope.json](proof_scope.json), and the publication register. The requirement-group document preserves the proposed names and interpretations from extraction; the links here identify their current implementation.
