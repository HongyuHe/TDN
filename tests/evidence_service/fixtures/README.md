# Selected public regression captures

These captures are retained inputs for parser tests. Their manifests preserve the original bytes and hashes. The tests also alter selected records and recompute the manifest to check that semantic inconsistencies are rejected even when file hashes agree.

`eap-public/` contains the two complete public authentication captures from `2026-11-01T015525Z`. They exercise reversed endpoint roles, compressed TLS certificate messages, authenticated RADIUS records, key references, and installed MACsec associations. Secret key values were excluded by the collector. The incomplete-transcript regression removes the compressed-certificate records from a copy of a complete capture.

`management-session/` contains `management-session-002` from the v3.1 isolated HTTPS experiment. It records an AW-initiated connection, its Outer replies, conntrack original and reverse tuples, and two rejected Outer-side attempts. Its 36 packet observations and eight replies bind the session interpretation to real packet bytes. The temporary TLS private key was deleted after collection.

The fixtures preserve the collectors and their original commands so that the interpretation can be inspected. They establish the behavior observed in these experiments. They do not certify products, prove the collectors correct, or establish behavior for every future exchange.

`native-ipsec/` contains the first fresh v3.1 native baseline key-correlation capture. Eight encryptors report sixteen local ESP associations across two observation phases. The collector compared private kernel key material in memory and retained public equality references. The parser binds those records to active IKE/CHILD associations, public peer certificates, daemon authentication logs, and reported kernel installation times. The fixture contains no private keys.

`native-sizing/` preserves five source-size probes and 152 captured packets. It includes the local DF size error and the large input that fragments on both encrypted interfaces. The negative outcome is retained as a regression case so that future projections cannot silently report universal fragmentation avoidance.

`eap-mka/` contains fresh forward and reverse EAP-TLS arrangements with exact public MKA messages. Instrumented send calls, receive callbacks, and successful integrity checks match independently captured packet bytes. The parser derives ordering from each process's log and matching messages. Private CAK, SAK, and MSK values remain excluded.

`administration-retained/` keeps public role/API/runtime records, including a failed historical deployment attempt. `admin-lifecycle/` contains a successful isolated capture with separate Unix identities, certificate ownership, authenticated channels, denied requests and revocation. Both exclude private keys.

`cover-sender/` selects retained command/settings/attempt records and the first five frames from two header observations. Its fixture note records that selection. It preserves failed sends and is used only for parser regression tests.

`native-component-audit/` preserves282 public command results for the repaired baseline. It includes23 account inventories and8 VPN credential-access records. It contains no password database or private-key bytes.

`mixed-sizing-frames.json` selects three public frames from the 1,360-byte Red boundary probe. They exercise SCI-bearing MACsec, a UDP/L2TPv3 carrier, and outer ESP at the 1,500-byte limit. The complete three-phase experiment remains in timestamped snapshots.
