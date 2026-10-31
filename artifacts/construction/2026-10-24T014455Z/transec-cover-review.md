# INT032-COVER: fixed-size scheduled records as the selected TRANSEC control

The coordinator and Evidence Agent use a size-masking interpretation of RG-032. The original CP page 23 requires TRANSEC for a Public Internet Black network. Table 15 on page 44 marks MSC-OR-9 as an Objective for external MACsec interfaces connected to an Outer Firewall. The definition on page 61 includes controls against intelligence derived from transmission characteristics. The retained laboratory configuration selects the OR-9 objective and declares its local Black bridge separately from the Public Internet.

The review used the full surrounding page 23 paragraph, the original table header and OR-9 row on page 44, and the definition on page 61. Those source captures and hashes are in references/transec/metadata.json. The CP PDF hash is 4e40e3d83708f33a033808d8362f78127973f53239dc03b72163fa6cfa5925c4. The extracted row's empty Alternatives cell does not change the selected objective into a mandatory universal rule. Both original triggers remain in msc_transec_conditions.

The selected mechanism runs a fixed-record sender before each Outer MACsec port. Each send attempt chooses the oldest queued packet or an empty payload. A 24-byte header and padding make the body exactly 512 bytes. The queue holds at most 64 packets. Arrivals exceeding 488 bytes or arriving at a full queue are dropped. The source schedules nominal 20 ms intervals, skips missed slots after delays, and consumes the selected payload even if sending fails.

The general proof establishes two facts for every finite execution of that sender model. Every queue stays within capacity, and every attempted record has the configured length. CSLib's mtrInv_of_trInv lifts the local arrival/send proofs to executions of arbitrary finite length. A second theorem says that equal send times and outcomes give equal observed record sizes for different queues. Equal schedules remain an explicit premise. Actual operating-system scheduling may depend on load.

The implementation contract is precise and limited. The retained Python sender must execute the reviewed queue and padding operations; its 64-bit sequence field must remain encodable; the MACsec port must continue protecting the resulting records; the collector must report the executed source and command results faithfully. Python floating-point monotonic clock arithmetic is approximated with integer nanoseconds in the scheduling definition. The fixed-size and queue invariant does not depend on a hard timing bound. Exact real-time equivalence is unproved.

The importer binds the two complete Outer inventories, runtime MACsec commands, exact source hash, sender invocations, default parameters, ready files, final statistics and every exported attempt. The finite Lean checks retain all 2,827 send attempts. The first endpoint reports 155 send errors. Attempt records contain no per-attempt success flag, so the importer does not invent one. Six positive/loss/restoration controls are compared with their raw command outcomes. Useful delivery is demonstrated for those finite probes; arbitrary-load losslessness is not claimed.

The enabled configuration theorem uses the selected size-masking interpretation of TRANSEC. The theorem does not establish general traffic-analysis resistance, independence of the real send schedule from data, prevention of interception or jamming, approved hardware, or authority acceptance. MACsec ciphertext confidentiality remains its existing cryptographic implementation assumption. Approval requirements remain in their applicable groups. The absence of those stronger claims must not erase the proved bounded-queue and fixed-record contributions.

## Library decision

The review inspected Cslib/Foundations/Semantics/LTS/Basic.lean, including LTS.TrInv, LTS.MTr and mtrInv_of_trInv. The sender uses those declarations directly. Mathlib List membership, append and map results support local queue and observation proofs. No new general reachability or execution framework was introduced.

## Files and interpretation decision

- General operations and proofs: TDN/Semantics/CoverTraffic.lean.
- CSfC conditions and selected mechanism theorem: TDN/Targets/Transec.lean.
- Imported parameters and every finite attempt: TDN/Evidence/FreshTransecCover.lean.
- Evidence parser: scripts/construction/import_transec_cover.py.
- Model regressions: tests/CoverTraffic.lean.
- Importer mutations: tests/test_transec_cover.py.
- Detailed data binding: fresh-transec-cover.json.

The independent Construction Agent must review the new contribution before marking any source clause complete. The Public Internet deployment alternative and stronger implementation correspondence remain separately assessed. No whole RG-032 or workflow completion is asserted here.

Recorded 2026-10-24T17:24:04.546906+00:00.

Pinned libraries: {"cslib": "990e65a685bed413f43b139db900a36ad5322a10", "mathlib": "d13f23b723b8a846827a245b89c10fc7d3f11612"}.

## Independent review and attachment correction

The Construction Agent identified two missing evidence connections. The importer now checks both phases of the complete raw veth inventory, namespace IDs, reciprocal peer indices and BF bridge membership before deriving firewall attachment. Four new mutation tests reject swapped peers, omitted links, incorrect namespace mappings and hardware offload. The importer also requires the observed MACsec software path with full protection and encryption. Zero confidentiality offset is inferred from the pinned upstream Linux v6.8 macsec_encrypt path, which encrypts every byte after macsec_hdr_len. Correspondence to the deployed kernel remains an explicit implementation assumption. The observed record-size theorem does not depend on that assumption. All13 importer tests pass.
