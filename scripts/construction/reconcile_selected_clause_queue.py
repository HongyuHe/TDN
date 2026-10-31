"""Replace inherited generic work entries with source-specific remaining tasks."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

run = Path(os.environ["TDN_OUTPUT_DIR"])
path = run / "theorem_register.json"
old = path.read_bytes()
directory = run / "register-revisions"
directory.mkdir(exist_ok=True)
saved = directory / (hashlib.sha256(old).hexdigest() + ".json")
if not saved.exists():
    saved.write_bytes(old)
register = json.loads(old)
tasks = {
    "RG-010": [
        "p14 local administration: bind each encryption component to its local administrator/site inventory and prove that every allowed management path remains off Black. The current independent-site specification has no concrete application; data-path isolation alone does not establish the management path clause.",
        "p14 certificate peers: reuse native-public-auth-bindings and retained CA/revocation bundles to bind every intended communicating peer to its actual loaded signing chain, revocation source and trusted authority. Existing cross-level trust results do not yet assemble the complete independent-site peer/material inventory.",
        "p14 MACsec alternatives: apply final EAP and PSK case records to the selected peer relationships. Redacted CKN lengths alone do not establish equal CAK material; use source/runtime key-derivation or authenticated MKA assumptions with their actual bindings.",
        "p14 AS attachment restriction: check the complete EAP server interface/namespace inventory against Red and Gray attachments, rather than assuming a single realm from its process role.",
        "p14 interoperability: connect intended peer pairs to retained useful forward/reverse executions for each selected mechanism. Site-count and local-versus-enterprise-CA alternatives are context and applicability choices, not missing independent proofs."
    ],
    "RG-017": [
        "p20 mutual device authentication: construct a method-specific bridge from complete loaded local/remote authentication settings and accepted IKE/EAP/MKA events to both directions of each actual Inner/Outer peer relationship.",
        "p20 NPE certificates: bind device credential subjects/SANs and loaded DER fingerprints to component identities, then distinguish the observed device credential inventory from the source's complete issued-certificate inventory. A hostname string or successful traffic probe alone does not supply issuance coverage.",
        "p23/p25 authentication/confidentiality/integrity context: cross-account packet and key-separation results with the peer-authentication clause. Preserve the declared implementation/cryptographic contracts and do not replace missing authentication settings with a tunnel-state flag.",
        "Apply the bridge to retained native public-key, final forward/reverse EAP and relevant PSK alternatives. Key-management annex technical duties and external issuing-authority records remain separately accounted."
    ],
    "RG-035": [
        "PF3/PF4/PF5/PF22: construct interface-and-direction policy projections from complete raw INPUT/OUTPUT/FORWARD and L2/MACsec hook inventories, then apply boundary_filtering_from_rule_checks. Current packet stack proofs do not by themselves establish each complete protocol allowlist.",
        "PF4 control exceptions: preserve the reviewed interpretation that MKA is allowed through the explicitly approved-control predicate on Outer MACsec interfaces. Do not infer organizational approval from an observed working MKA session.",
        "p23 Outer Firewall orientation: bind external incoming destination and internal incoming source to the actual local Outer endpoint addresses; check both firewall directions and all applicable interfaces.",
        "OR10: bind outgoing Outer peers and other intended devices to independent configured peer/service records. A broad route or the current allowlist cannot itself define intended destinations.",
        "Inner Red service restrictions: identify actual required Red service address/port classes from selected functions, then prove accepted traffic belongs to those classes. Missing organization-defined control approvals are external; extracting and checking raw rules remains actionable."
    ],
    "RG-041": [
        "p13/p21 unapproved control traffic: inventory enabled programs, sockets and all raw hooks in each selected backend, classify the supported control protocols and prove blocking/disablement for unapproved classes. The configuration normalizer theorem alone is not an installed-state application.",
        "p21 Layer 3 default: distinguish explicit configured enabling from the documented default-disabled state, and bind each enabled ICMP/routing/multicast class to the applicable local AO policy. Captured ordinary ping/FRR behavior supplies operational facts but not that approval.",
        "SR1 service placement: use retained Red/Gray clock and certificate-status service attachment records to prove that services used by Inner clients are on Red and services used by Outer clients are on Gray. Gray data placement may satisfy SR1 while a separate Gray Management requirement remains unproved.",
        "p21 Layer 2 necessity and public-standard conformance: connect actual ARP/MKA or other selected control mechanisms to their operational function and explicit implementation contract. Preserve owner/AO necessity decisions as external evidence where required.",
        "p21 independent IPv4/IPv6 choices and existing routing protocols: cross-account all eight family and retained native FRR alternatives as permitted choices; do not turn those permissive passages into independent unproved obligations. Outer routing restrictions belong to their separate source group and interpretation."
    ],
    "RG-073": [
        "Inventory software, firmware and verification paths for every actual Solution Component. The checked ML-DSA-87 deployment utility is outside that complete component inventory.",
        "Bind each applicable signed artifact to its installed consumer, trusted publisher key and signature-verification outcome. Retained utility observations and the coordinator's read-only saved-manifest verification are partial evidence.",
        "Supply authorized publisher/trust-anchor provisioning and update/boot/dependency coverage for the selected component inventory. No loader execution, injection probe or remote collection is authorized during this continuation."
    ],
}
for group in register["groups"]:
    gid = group["group_id"]
    if gid in tasks:
        group["remaining_construction_work"] = tasks[gid]
        group["status"] = "construction_in_progress"
        group["canonical_review_at"] = datetime.now(timezone.utc).isoformat()
        group["precise_queue_basis"] = {
            "source": "Original source passages already retained in this group's source_passages and source_clause_records",
            "assessment": "These items are actionable implementation/application work or explicitly named external records, not stopping justifications.",
        }
path.write_text(json.dumps(register, indent=2) + "\n")
(run / "clause-work-20261024T1848.json").write_text(json.dumps(tasks, indent=2) + "\n")
print(json.dumps({"updated_groups": list(tasks)}))
