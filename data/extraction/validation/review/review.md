# Independent CSfC extraction review

The reviewed extraction has no remaining material extraction defects identified within the stated scope. All 12 reviewer findings were addressed. Eleven were corrected and checked again. One was addressed by retaining an explicit source ambiguity. The overall verdict is **partial**, because 15 source interpretation or scope issues remain. The artifacts are **not ready for downstream formalization**.

The reviewer did not produce or edit the source, requirement, network, or role artifacts. Review work was limited to findings, pixel evidence, reports, and artifact-hash binding. The review followed `docs/specification_preprocessing_plan.md` and the PDF skill.

## Scope and pixel evidence

The reviewer read the original document text on all 66 physical PDF pages through `baseline/page-NNN.txt`. The reviewer compared all 76 requirement theorem targets and their force, alternatives, applicability, exceptions, and source context with that reading. The background review covered prose, definitions, navigation records, and the 20 relocated or withdrawn requirement rows. The role review used the full document, including requirements and glossary entries outside the example networks.

- Full original page renders viewed: 8, 19, 20, 23, 36, and 56 at 120 dpi.
- All ten final figure crops viewed at 200 dpi, covering Figures 1-10 on physical PDF pages 10, 12, 14, 15, 17, 18, 19, 20, 22, and 28. Labels, captions, and shown legends were readable and complete.
- All ten continued requirement rows and both associated column headers viewed as original-pixel montages: MSC-PS-10, MSC-SR-23, MSC-VG-21, MSC-MD-11, MSC-IR-2, MSC-OR-3, MSC-PF-4, MSC-PF-15, MSC-PF-25, and MSC-GD-20. `pixel_manifest.json` records the page regions.
- Table 1 on page 19 confirms the corrected first-row Inner value is IPsec. The hidden/displaced Tunnel text explains the baseline overlap. The raw extraction and correction record remain preserved.
- Page 36 confirms MSC-SR-14 and its complete egress footnote. The row links the footnote source units.

## Mechanical checks

The independent quotation and assignment check passed for 1,597 source units. All indexed quotations matched exactly. Each of the 76 groups has one nonempty proposed theorem target with a unique name. The background group has no theorem. The source producer report separately records 688 literal-period sentences, 407 logical table rows, and ten cross-page row continuations. The reported exhaustive character/span check was inspected; the reviewer did not substitute those counts for semantic review.

## Resolved extraction findings

The revised artifacts preserve the source distinctions that the initial extraction lost. Network quotations now exclude unrelated page context and include relevant cross-page continuations. Textual examples record stated relationships, conditional placement, and alternatives. Figure 5 now contains its labelled Gray Data Network segments. The Red trusted time source remains on the Red Network, while the Gray trusted source remains on the Gray Management Network.

The corrected network model distinguishes a filtering device from a revocation endpoint and a whole CSfC solution from a single component. NET-025 represents the Outer VPN Gateway as a transit/filter component. NET-019 preserves conditional Inner Firewall placement. NET-018 represents CP-conforming egress through a solution aggregate. Figure 5 and Figure 6 retain their different security labels, management placement, and firewall roles.

The corrected role inventory contains 74 roles and 1,326 indexed mentions. Password generation, log repositories, and testing equipment/software have source-backed records. Backup storage medium has an explicit storage-asset exclusion. Root CA remains an example distinct from Trust Anchor CA. CDP/OCSP compound wording no longer asserts an OCSP synonym. Human administrator roles remain separate from device roles, and the mixed Registration Authority definition is qualified.

The corrected theorem summaries preserve recommendation strength, customer/AO responsibilities, and local-versus-remote address restrictions. RG-002 and RG-050 retain should-level advice. RG-071 assigns variant contact to the customer. RG-035 distinguishes firewall addresses of the local Outer Component from the Outer Component remote-peer requirement. RG-027 retains the conflicting EAP-TLS derivation and blanket KGS-generation wording as REQ-I15. `findings.json` gives exact source/artifact IDs, evidence, corrections, and verification dispositions for all 12 findings.

## Remaining source issues

The original source still requires interpretation decisions for 13 issues and supplies insufficient scope for two others. The review preserves those issues without inventing precedence. Figure 9 also retains its visible US-only/Coalition labels and absent Gray Firewalls as an explicit network issue; filtering implementation and compliance remain unknown. Encapsulator-boundary wording remains unresolved in both requirements and NET-008.

- **REQ-I01**: Standalone encapsulator boundary and force conflict.
- **REQ-I02**: Same-level filtering sentence conflicts with the permitted peers.
- **REQ-I03**: Management encryption and local exceptions.
- **REQ-I04**: TRANSEC force and applicability differ.
- **REQ-I05**: New-version compliance deadline conflict.
- **REQ-I06**: AW physical-host exclusivity versus separate-VM wording.
- **REQ-I07**: Physical/cryptographic separation and minimum logical separation.
- **REQ-I08**: AS connection scope wording.
- **REQ-I09**: Gray address-only restrictions and explicit non-tunnel exceptions.
- **REQ-I10**: Objective table row has no Alternative marker.
- **REQ-I11**: MACsec provisioning paragraph uses VPN terminology.
- **REQ-I12**: External annex dependencies are not supplied.
- **REQ-I13**: Legal-domain interpretation remains unreviewed.
- **REQ-I14**: Figures and protocol examples do not prove compliance.
- **REQ-I15**: EAP-TLS CAK derivation and blanket KGS generation wording.

The background review found no additional active obligation stranded in background. Each active numbered row is grouped, and non-numbered prose obligations are retained across the groups. The result is a reviewed representation of the supplied PDF. External annex contents, implementation compliance, legal applicability, and theorem proofs remain outside the completed review.

The final reviewed content is bound by `reviewed_artifact_hashes.json`. Later content changes require renewed checks before the review can be treated as current.
