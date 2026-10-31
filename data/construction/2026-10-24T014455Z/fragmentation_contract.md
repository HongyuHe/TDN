# Fragmentation and logical packet execution

Updated 2026-10-24 05:17 UTC. The selected Linux ESP model treats fragmentation as a change in packet representation between cryptographic operations. The contract below is an implementation assumption supported by retained source review and actual stage observations. A finite experiment does not verify every kernel execution.

## Checked mathematical construction

Fragmentation.ValidPieces requires a nonempty finite list, common projected header, contiguous nonoverlapping offsets and exact reconstruction of the datagram bytes. The general partition theorem constructs such a list from any nonempty byte partition. SegmentedStep permits splitting, forwarding without changing the encoded datagram and valid reassembly. Its local projection to the packet model is proved. The trace transfer directly uses CSLib LTS.IsSimulation.sim_trace.

DistributedFragments additionally permits each piece to occupy its own forwarding state and take independent permitted route choices. A reassembly step requires every piece at the same assembly state and a valid complete assembly. CSLib invariant preservation proves the property for every piece across arbitrary interleavings. The result does not require fragments to travel together.

Targets.every_distributed_black_piece_is_double_protected proves that each modeled piece transmitted at Black has both actual protection layers. It also retains the initial payload and origin identity. The header descriptor is semantic provenance for the bytes; it is not an additional authenticated field transmitted by the implementation. The same local checks apply to shared native, baseline native and eight family configurations.

## Implementation contract

1. A logical datagram has an unambiguous projected source, destination and protocol. IPv4 identification, offsets, MF flags, length and checksums describe its pieces; they do not change the protected payload, tunnel endpoints or protection history. TTL changes are outside the modeled security-relevant header.
2. Fragmentation partitions the current datagram bytes. Forwarding may select any route permitted by the imported route model. Pieces can take different paths. Each piece retains its projected outer endpoint and protection provenance until reassembly.
3. Reassembly before a cryptographic operation accepts only a complete, consistent assembly. Incomplete queues, invalid lengths, conflicting fragment identities and malformed overlaps cannot produce an accepted logical datagram under this contract. Queue drops remove behavior from the safety model.
4. Reassembly of an outer ESP datagram occurs before ESP authentication and decryption. A successful decrypt still requires the configured receiving policy, matching wire SA, endpoint/protocol checks and cryptographic validation. Reassembly does not grant an authenticated-policy marker.
5. The selected Linux IPv4 outbound path gathers plaintext fragments before the forwarding policy and ESP operation. The policy sees the reconstructed datagram. The selected security policies use source/destination selectors. The route/filter checks do not infer port fields from noninitial fragments.
6. Additional size, checksum, replay, timeout and malformed-input checks may drop packets. Their omission in the safety model cannot permit an implementation to bypass the modeled policy or cryptographic operation. Positive acceptance is established separately by concrete modeled executions and operational controls.
7. The final family IPv6 configuration rejects immediate headers outside 6, 17, 50 and 58 at nft hook priority -450. Netfilter defragmentation occurs at -400 under the recorded hook-order contract. Immediate NH44 fragments are rejected before they can become reconstructed UDP datagrams. The older raw -300 rule alone does not satisfy that wire-header property.

The model assumes that cryptographic integrity prevents modified encrypted assemblies from producing an authenticated plaintext. The model also trusts the collector, the selected implementation semantics and the binding from observations to that implementation. Those assumptions are the same kind of implementation and cryptographic assumptions already used for unfragmented ESP. They are distinct from unchecked CSfC configuration or authority requirements.

## Source and actual stage evidence

RFC 4301 sections 5.2 and 7 describe inbound reassembly before IPsec processing and distinguish plaintext-side and ciphertext-side fragmentation. Section 7 and Appendix D explain why fragment handling depends on selectors and implementation context. The model does not assume that every RFC-permitted implementation performs the selected Linux stages.

The retained official Linux v6.8 files are in references/netfilter-fragment-order/. The netfilter_ipv6.h file at lines 35–38 gives the relevant hook priorities. The nf_defrag_ipv4.c and nf_defrag_ipv6_hooks.c files identify fragment-gathering hooks. The ip_fragment.c, inet_fragment.c, xfrm4_output.c and xfrm_input.c files support the implementation-family review. Their hashes and official URLs are recorded in metadata.json.

The actual stage experiment is artifacts/snapshots/2026-10-24T014455Z/data-fragments-v5. Raw commands cmd-0085 and cmd-0086 identify Ubuntu kernel 6.8.0-138-generic on node-0.twinet-msc.netsyn-pg0.clemson.cloudlab.us. The native shared manifest records that same host/kernel. Upstream v6.8 source is a family reference; no byte identity with the distribution build is claimed. A supplemental family host/kernel binding was requested because the family manifests omit those fields.

The experiment records a 4096-byte UDP payload as one 4124-byte IPv4 datagram, then one 4180-byte ESP datagram. The Black router produces four fragments at byte offsets 0, 1256, 2512 and 3768. The receiving gateway reassembles before ESP processing, and the destination reports the original payload digest. A second case starts with plaintext-side fragments, records reassembly before encryption, and again verifies the final digest. The malformed overlap case increments both the reassembly-failure and overlap counters, emits no ESP datagram and delivers no payload. A valid restoration control succeeds.

The same retained bundle preserves the IPv6 counterexample and repair. Two NH44 fragments pass the older raw gate after defragmentation. The early -450 gate drops both fragments, with the corresponding packet/byte counter increase. A valid below-MTU UDP control succeeds before and after. The eight families-v9 bundles independently bind all 32 gateway installations through exact nft JSON. The importer checks both hooks, priority, literal payload field, alternatives and terminal drop. Sixteen family mutation tests include wrong priority, upper-layer protocol substitution, missing drop and missing gateway.

## Scope and remaining applications

The stage experiment is one manually provisioned Linux ESP path. Its purpose is to support the backend contract. The network's double-layer property comes from checked routing, filtering, policy, SA and link conditions plus the general fragment theorem.

Native FreeBSD and MACsec/encapsulation pipelines require their own applicable implementation connections. The contract does not silently transfer Linux fragment stages to those mechanisms. Path MTU and the optional size-setting requirements remain separate from protection safety. IPv6-PMTU-v4 supplies an actual PTB and socket-PMTU transition for its supplemental ESP path; its numerical sizing application is still being constructed.
