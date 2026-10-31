# RG-027: CKN length and configured key-server selection

The retained forward and reverse EAP arrangements each have two MACsec peers. The source declares the authenticator site central and the other site remote. The importer checks those declarations against the pinned collector, the two complete peer logs and existing final MACsec runtime checks.

Each peer log reports a CKN length of 16 bytes. The actual bytes are redacted in the public artifacts. The importer therefore records the reported lengths and does not invent a CKN fingerprint or claim byte equality between peers. The imported pair length is the smaller reported length, so checking the minimum covers both peers.

The logs bind each local initialization to priority 0 or 1. The central peer has priority 0 in both arrangements, although the device names swap. A general theorem proves that the central site has the unique lower configured priority. The same proof applies to both imported arrangements. The result concerns configured selection; it does not prove all distributed protocol schedules converge to that choice.

The top-level RG-027 specification still includes approved key generation and disabled fallback CAKs. A new general theorem composes the technical checks with those separate premises. Neither missing premise is silently assigned true or false in the evidence. The current contribution covers the minimum-length portion of MD-5 and the configured priority/central-site clauses of MD-6.

MD-15 fallback/rollover behavior remains actionable. Successful EAP authentication and one reported CKN do not establish that no fallback can occur. The exact source/configuration branches need a separate review or additional retained records. NSA-approved KGS provenance remains an external requirement. PSK provisioning retains its separate evidence obligation.

The coordinator reviewed the full extracted source rows MD-5, MD-6 and MD-15 and their source-linked surrounding passages. No new interpretation of the requirement strength was needed. General proofs use existing natural-number comparison and checked finite records; no new execution framework was added.

Seven importer mutations pass. They cover short CKNs, changed priorities, wrong site assignments, missing CKN records, repeated arrangements and missing peers. The general and concrete Lean builds pass. The first data import rejected redacted CKN bytes, so the parser was corrected to preserve the actual available evidence: reported lengths only. The first finite Lean check exposed an equality-transport issue in the decision instance; an equivalent option-based check now reduces in the kernel. Both failed attempts remain recorded.

Files: TDN/Targets/MACsecKeyServer.lean, TDN/Evidence/FinalMACsecKeyServers.lean, scripts/construction/import_macsec_key_servers.py, tests/test_macsec_key_servers.py, and final-macsec-key-servers.json. Independent Construction review is required before mapping the contribution.
