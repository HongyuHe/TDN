# Reusable network theory

The modules in this directory import `Std` and have no dependency on `MSC.Deployment`.

`Graph.lean` accepts any vertex type and directed transition relation. `Reach.preserves` lifts a local label invariant to every finite walk. `Route.must_visit_of_labels` identifies a required waypoint in an explicit route. `Reach.map` states the simulation premise needed to transfer a reachability argument between two models.

`Filter.lean` accepts arbitrary packet and rule types. It models ACCEPT-only tables with a default policy. Rule guarantees lift to all accepted packets, and rule rejection lifts to default-deny tables. Tables containing mixed actions need an ordered first-match model.

`IPv4.lean` defines address prefixes and strict parsing. `Operational.lean` stores sampled interface, route, policy, SA, and switch records. Missing observations remain distinct from observed empty lists. `Routing.lean` selects policy-routing tables by rule priority and selects routes by destination-prefix length and metric. Its evidence lemmas show that a successful lookup uses an observed row and a matching source rule. The execution model must still connect that result to interfaces, filtering, and XFRM processing.

`Encapsulation.lean` calculates IPv4 ESP/AES-GCM packet sizes. Its bounds cover alignment padding and optional UDP encapsulation for one or two layers. Concrete clients supply their MTU and encoding premises.

`Packet.lean` distinguishes clear messages, control traffic, and ideal authenticated cipher wrappers. `Execution.lean` applies observed route lookup, INPUT/FORWARD callbacks, XFRM policy and SA selection, interface state, and MTUs to individual forwarding operations. A local protection budget lifts through arbitrary finite wire, switch, and forwarding executions. Message preservation keeps the protected-payload condition stable along the trace. The current encoding supports IPv4 ESP/AES-GCM; fragmentation and time-dependent SA or credential behavior need explicit extensions.

The MSC topology, filter, and MTU modules instantiate the relevant generic proofs. `tests/NetworkReuse.lean` provides a separate three-group, multiple-host example with renamed interfaces and no MSC import. Routing cases cover source-specific policy tables, an empty-table fallback, longest-prefix selection, metric preference, and missing routes. Deployment-specific observations, fixed counts, and device names belong to the instantiation layer.

`tests/ExecutionReuse.lean` exercises the same XFRM selection and layer-accounting code with a separate three-site, two-peer fixture. `TDN.MSC.Execution` binds the execution model to the deployed snapshot, and `TDN.MSC.ExecutionTrace` proves positive host-delivery and IKE-control witnesses.
