# Requirement groups and their Lean formalizations

TDN v3.4 selects 10 of the 76 CSfC requirement groups for proof. 10 have reviewed complete proofs under their recorded model assumptions.

The [proof scope](proof_scope.json) identifies the selected groups. The [review record](../data/publication/v3.4/verdict.json) identifies which proofs passed review. The [clause guide](requirement_clauses.md) links individual passages to their Lean conditions, examples and assumptions.

## 10 proof targets

| RG | Requirement | Top-level Lean specification | Proof status |
| --- | --- | --- | --- |
| [RG-007](requirement_groups.md#rg-007) | Two independent encryption layers and allowed tunnel pairings | [nested_layer_protection](../TDN/Requirements/MscRequirements.lean#L6) | Complete model proof reviewed |
| [RG-008](requirement_groups.md#rg-008) | Connectivity restricted to the same security level | [security_level_connectivity](../TDN/Requirements/MscRequirements.lean#L10) | Complete model proof reviewed. The two-level baseline satisfies RG-008. The four-level shared deployment preserves security levels but violates physical separation for an included unclassified network. |
| [RG-013](requirement_groups.md#rg-013) | Gray Firewalls on all paths needing level separation | [gray_firewall_path_coverage](../TDN/Requirements/MscRequirements.lean#L17) | Complete model proof reviewed |
| [RG-029](requirement_groups.md#rg-029) | Inner encryption and decryption cannot be bypassed | [inner_tunnel_no_bypass](../TDN/Requirements/MscRequirements.lean#L20) | Complete model proof reviewed |
| [RG-030](requirement_groups.md#rg-030) | Outer encryption and decryption cannot be bypassed | [outer_tunnel_no_bypass](../TDN/Requirements/MscRequirements.lean#L26) | Complete model proof reviewed |
| [RG-034](requirement_groups.md#rg-034) | Outer Firewall placement for untrusted Black transport | [outer_firewall_placement](../TDN/Requirements/MscRequirements.lean#L32) | Complete model proof reviewed |
| [RG-035](requirement_groups.md#rg-035) | Permitted protocols and peers at encryption and firewall boundaries | [boundary_interface_filtering](../TDN/Requirements/MscRequirements.lean#L34) | Complete model proof reviewed |
| [RG-038](requirement_groups.md#rg-038) | IP header and multicast filtering | [ip_header_and_multicast_filtering](../TDN/Requirements/MscRequirements.lean#L39) | Complete model proof reviewed |
| [RG-039](requirement_groups.md#rg-039) | Outer Gray-interface allowlist and default denial | [outer_gray_interface_policy](../TDN/Requirements/MscRequirements.lean#L43) | Complete model proof reviewed |
| [RG-040](requirement_groups.md#rg-040) | Gray Firewall allowlist and cross-level denial | [gray_firewall_allowlist](../TDN/Requirements/MscRequirements.lean#L46) | Complete model proof reviewed |

## 66 other catalog requirements

Each group keeps its original CSfC text and its place in the shared catalog. RG-008 refers to this catalog when it requires included networks to satisfy their applicable duties. A catalog entry can supply a condition to another proof. Its presence does not establish compliance.

| RG | Requirement | Catalog condition | Treatment |
| --- | --- | --- | --- |
| [RG-001](requirement_groups.md#rg-001) | Applicable requirements and policy precedence | [Case 1](../TDN/Requirements/CsfcRoleObligations.lean#L164) | Direct check of recorded facts |
| [RG-002](requirement_groups.md#rg-002) | Validated configuration and component modification | [Case 2](../TDN/Requirements/CsfcRoleObligations.lean#L165) | External evidence |
| [RG-003](requirement_groups.md#rg-003) | Product eligibility on the CSfC Components List | [Case 3](../TDN/Requirements/CsfcRoleObligations.lean#L170) | External evidence |
| [RG-004](requirement_groups.md#rg-004) | Independent product, operating-system, and cryptographic implementations | [Case 4](../TDN/Requirements/CsfcRoleObligations.lean#L174) | Direct check of recorded facts |
| [RG-005](requirement_groups.md#rg-005) | Physical separation of security components | [Case 5](../TDN/Requirements/CsfcRoleObligations.lean#L175) | Direct check of recorded facts |
| [RG-006](requirement_groups.md#rg-006) | Product Supply Chain Threat Assessment | [Case 6](../TDN/Requirements/CsfcRoleObligations.lean#L176) | External evidence |
| [RG-009](requirement_groups.md#rg-009) | Gray-network control and classification boundary | [Case 9](../TDN/Requirements/CsfcRoleObligations.lean#L186) | External evidence |
| [RG-010](requirement_groups.md#rg-010) | Independently managed site administration and trust | [Case 10](../TDN/Requirements/CsfcRoleObligations.lean#L187) | Direct check of recorded facts |
| [RG-011](requirement_groups.md#rg-011) | Central management, CA placement, and intersite protection | [Case 11](../TDN/Requirements/CsfcRoleObligations.lean#L194) | Direct check of recorded facts |
| [RG-012](requirement_groups.md#rg-012) | Separate authentication and management for security levels | [Case 12](../TDN/Requirements/CsfcRoleObligations.lean#L195) | Check the trust and management assignments for each level. Cross-level peer isolation also contributes to RG-008. |
| [RG-014](requirement_groups.md#rg-014) | Gray addressing supports security-level filtering | [Case 14](../TDN/Requirements/CsfcRoleObligations.lean#L200) | Check Gray address ownership and intended peers. The active Gray interface and firewall proofs use the relevant address constraints. |
| [RG-015](requirement_groups.md#rg-015) | MACsec encapsulation and standalone encapsulator obligations | [Case 15](../TDN/Requirements/CsfcRoleObligations.lean#L201) | Record the carrier configuration and applicable standalone-device duties. Retain encapsulation semantics used by the selected packet proofs. |
| [RG-016](requirement_groups.md#rg-016) | Permitted MACsec clear VLAN tags and XPN | [Case 16](../TDN/Requirements/CsfcRoleObligations.lean#L202) | Direct check of recorded facts |
| [RG-017](requirement_groups.md#rg-017) | Mutual authentication and Non-Person Entity certificates | [Case 17](../TDN/Requirements/CsfcRoleObligations.lean#L205) | Direct check of recorded facts |
| [RG-018](requirement_groups.md#rg-018) | CNSS algorithm-policy requirements and choices | [Case 18](../TDN/Requirements/CsfcRoleObligations.lean#L206) | Direct check of recorded facts |
| [RG-019](requirement_groups.md#rg-019) | IPsec CNSA profile and post-quantum exchange sequence | [Case 19](../TDN/Requirements/CsfcRoleObligations.lean#L210) | Direct check of recorded facts |
| [RG-020](requirement_groups.md#rg-020) | VPN certificate loading and authentication checks | [Case 20](../TDN/Requirements/CsfcRoleObligations.lean#L211) | Direct check of recorded facts |
| [RG-021](requirement_groups.md#rg-021) | VPN private-key access confinement | [Case 21](../TDN/Requirements/CsfcRoleObligations.lean#L213) | Assess key access at the deployed key store and its exposed interfaces. |
| [RG-022](requirement_groups.md#rg-022) | IKEv2 and IKE/ESP encryption-mode alternatives | [Case 22](../TDN/Requirements/CsfcRoleObligations.lean#L215) | Direct check of recorded facts |
| [RG-023](requirement_groups.md#rg-023) | VPN SA lifetimes and reauthentication | [Case 23](../TDN/Requirements/CsfcRoleObligations.lean#L216) | Direct check of recorded facts |
| [RG-024](requirement_groups.md#rg-024) | MACsec authentication alternatives and AS scope | [Case 24](../TDN/Requirements/CsfcRoleObligations.lean#L224) | Check the authentication method, server attachment and peer-to-key evidence for the selected MACsec implementation. |
| [RG-025](requirement_groups.md#rg-025) | MACsec encryption and key wrapping algorithms | [Case 25](../TDN/Requirements/CsfcRoleObligations.lean#L225) | Direct check of recorded facts |
| [RG-026](requirement_groups.md#rg-026) | MACsec EAP-TLS CNSA profile alternatives | [Case 26](../TDN/Requirements/CsfcRoleObligations.lean#L228) | Direct check of recorded facts |
| [RG-027](requirement_groups.md#rg-027) | MACsec key generation, key-server selection, and rollover | [Case 27](../TDN/Requirements/CsfcRoleObligations.lean#L231) | Check key-server priorities, key-name length, fallback settings and approved provisioning records. |
| [RG-028](requirement_groups.md#rg-028) | MACsec mandatory protection parameters | [Case 28](../TDN/Requirements/CsfcRoleObligations.lean#L233) | Inspect MACsec settings and check the protected transmission paths where the selected boundary proofs use them. |
| [RG-031](requirement_groups.md#rg-031) | Routing and switching limits on Encryption Components | [Case 31](../TDN/Requirements/CsfcRoleObligations.lean#L238) | Direct check of recorded facts |
| [RG-032](requirement_groups.md#rg-032) | TRANSEC under the stated deployment conditions | [Case 32](../TDN/Requirements/CsfcRoleObligations.lean#L242) | Check whether TRANSEC applies and whether the selected mechanism is active. |
| [RG-033](requirement_groups.md#rg-033) | Packet sizing to control fragmentation | [Case 33](../TDN/Requirements/CsfcRoleObligations.lean#L244) | Check packet sizing against the selected links and encapsulation overhead. Retain size and encoding facts needed by the active packet proofs. |
| [RG-036](requirement_groups.md#rg-036) | Minimal network-interface exposure | [Case 36](../TDN/Requirements/CsfcRoleObligations.lean#L257) | Direct check of recorded facts |
| [RG-037](requirement_groups.md#rg-037) | Outer-component third-party contact restrictions | [Case 37](../TDN/Requirements/CsfcRoleObligations.lean#L259) | Inventory third-party features and check the selected disabling or outbound blocking policy. |
| [RG-041](requirement_groups.md#rg-041) | Control-plane approval, defaults, and service location | [Case 41](../TDN/Requirements/CsfcRoleObligations.lean#L263) | Direct check of recorded facts |
| [RG-042](requirement_groups.md#rg-042) | Layer-specific trusted time synchronization | [Case 42](../TDN/Requirements/CsfcRoleObligations.lean#L264) | Direct check of recorded facts |
| [RG-043](requirement_groups.md#rg-043) | Default credentials, DNS, and remote bootstrap | [Case 43](../TDN/Requirements/CsfcRoleObligations.lean#L265) | Direct check of recorded facts |
| [RG-044](requirement_groups.md#rg-044) | Layer-specific administration and management-plane separation | [Case 44](../TDN/Requirements/CsfcRoleObligations.lean#L266) | Direct check of recorded facts |
| [RG-045](requirement_groups.md#rg-045) | Dedicated, protected, hardened Administrative Workstations | [Case 45](../TDN/Requirements/CsfcRoleObligations.lean#L267) | Direct check of recorded facts |
| [RG-046](requirement_groups.md#rg-046) | Management transport protection and local exceptions | [Case 46](../TDN/Requirements/CsfcRoleObligations.lean#L271) | Direct check of recorded facts |
| [RG-047](requirement_groups.md#rg-047) | Administrator authentication and individual credentials | [Case 47](../TDN/Requirements/CsfcRoleObligations.lean#L272) | Check individual accounts and bind administrative operations to authenticated sessions where management is deployed. |
| [RG-048](requirement_groups.md#rg-048) | Authorized provisioning and initial certificate requests | [Case 48](../TDN/Requirements/CsfcRoleObligations.lean#L274) | Direct check of recorded facts |
| [RG-049](requirement_groups.md#rg-049) | Personnel clearance and Outer administration | [Case 49](../TDN/Requirements/CsfcRoleObligations.lean#L275) | External evidence |
| [RG-050](requirement_groups.md#rg-050) | SIEM placement, collection, alerting, and log transport | [Case 50](../TDN/Requirements/CsfcRoleObligations.lean#L276) | External evidence |
| [RG-051](requirement_groups.md#rg-051) | Cross Domain Solution approval conditions | [Case 51](../TDN/Requirements/CsfcRoleObligations.lean#L277) | External evidence |
| [RG-052](requirement_groups.md#rg-052) | Physical protection, authorized access, and disposal | [Case 52](../TDN/Requirements/CsfcRoleObligations.lean#L281) | External evidence |
| [RG-053](requirement_groups.md#rg-053) | Parallel Inner components and distinct Outer internal interfaces | [Case 53](../TDN/Requirements/CsfcRoleObligations.lean#L288) | Direct check of recorded facts |
| [RG-054](requirement_groups.md#rg-054) | Interoperable components across communicating sites | [Case 54](../TDN/Requirements/CsfcRoleObligations.lean#L294) | Test each required Inner and Outer tunnel in both directions on the selected devices and record the recovered payload. |
| [RG-055](requirement_groups.md#rg-055) | Firewall requirements when combining capability packages | [Case 55](../TDN/Requirements/CsfcRoleObligations.lean#L297) | External evidence |
| [RG-056](requirement_groups.md#rg-056) | Approved physical paths out of Red Networks | [Case 56](../TDN/Requirements/CsfcRoleObligations.lean#L301) | Check Red exits against conforming solutions or recorded approvals for data-in-transit protection. |
| [RG-057](requirement_groups.md#rg-057) | Operational security updates and TEMPEST policy | [Case 57](../TDN/Requirements/CsfcRoleObligations.lean#L302) | External evidence |
| [RG-058](requirement_groups.md#rg-058) | Hardware inventory and available baseline configuration | [Case 58](../TDN/Requirements/CsfcRoleObligations.lean#L305) | Direct check of recorded facts |
| [RG-059](requirement_groups.md#rg-059) | Procurement documentation excludes classified-protection purpose | [Case 59](../TDN/Requirements/CsfcRoleObligations.lean#L308) | External evidence |
| [RG-060](requirement_groups.md#rg-060) | Annual and NSA-authorized compliance audits | [Case 60](../TDN/Requirements/CsfcRoleObligations.lean#L309) | External evidence |
| [RG-061](requirement_groups.md#rg-061) | Registration, approval, annual renewal, and version updates | [Case 61](../TDN/Requirements/CsfcRoleObligations.lean#L310) | External evidence |
| [RG-062](requirement_groups.md#rg-062) | Audit retention, storage monitoring, backup, and continuity | [Case 62](../TDN/Requirements/CsfcRoleObligations.lean#L312) | Direct check of recorded facts |
| [RG-063](requirement_groups.md#rg-063) | Infrastructure authentication alternatives | [Case 63](../TDN/Requirements/CsfcRoleObligations.lean#L315) | External evidence |
| [RG-064](requirement_groups.md#rg-064) | Incident triggers, required report fields, and reporting deadline | [Case 64](../TDN/Requirements/CsfcRoleObligations.lean#L317) | External evidence |
| [RG-065](requirement_groups.md#rg-065) | Separation of administrative and auditing personnel | [Case 65](../TDN/Requirements/CsfcRoleObligations.lean#L324) | External evidence |
| [RG-066](requirement_groups.md#rg-066) | Personnel training and physical tamper inspections | [Case 66](../TDN/Requirements/CsfcRoleObligations.lean#L326) | External evidence |
| [RG-067](requirement_groups.md#rg-067) | Revocation or CAK destruction before disposal | [Case 67](../TDN/Requirements/CsfcRoleObligations.lean#L327) | External evidence |
| [RG-068](requirement_groups.md#rg-068) | Security Administrator operational duties | [Case 68](../TDN/Requirements/CsfcRoleObligations.lean#L330) | Direct check of recorded facts |
| [RG-069](requirement_groups.md#rg-069) | Auditor review duties and access boundary | [Case 69](../TDN/Requirements/CsfcRoleObligations.lean#L333) | Direct check of recorded facts |
| [RG-070](requirement_groups.md#rg-070) | Optional Integrator involvement and duty scope | [Case 70](../TDN/Requirements/CsfcRoleObligations.lean#L335) | External evidence |
| [RG-071](requirement_groups.md#rg-071) | AO authorization evidence and lifecycle control | [Case 71](../TDN/Requirements/CsfcRoleObligations.lean#L336) | External evidence |
| [RG-072](requirement_groups.md#rg-072) | Whole-solution testing and preserved results | [Case 72](../TDN/Requirements/CsfcRoleObligations.lean#L339) | Direct check of recorded facts |
| [RG-073](requirement_groups.md#rg-073) | Objective software and firmware signing algorithms | [Case 73](../TDN/Requirements/CsfcRoleObligations.lean#L342) | External evidence |
| [RG-074](requirement_groups.md#rg-074) | Redundant component and load-balancing permission | [Case 74](../TDN/Requirements/CsfcRoleObligations.lean#L343) | List redundant devices, apply the duties for their roles and rerun the selected path and packet checks on the expanded network. |
| [RG-075](requirement_groups.md#rg-075) | Optional additional controls and screening-router scope | [Case 75](../TDN/Requirements/CsfcRoleObligations.lean#L344) | Permission or applicability |
| [RG-076](requirement_groups.md#rg-076) | CP user legal undertaking and disclaimer | [Case 76](../TDN/Requirements/CsfcRoleObligations.lean#L346) | External evidence |

The shared function takes the deployment, the component or network being assessed, and the group number. Cases 70 and 74 add no separate condition. For RG-074, assess redundant devices under the existing duties for their roles. The [source catalog](requirement_groups.md) retains the complete text, including conditions involving external evidence.
