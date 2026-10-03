import TDN.MSC.Flow
import TDN.MSC.Configuration
import TDN.MSC.Credentials
import TDN.Network.Encapsulation
import TDN.MSC.Operational
import TDN.MSC.LocalPolicy
import TDN.MSC.MTU
import TDN.Network.Routing
import TDN.MSC.Execution
import TDN.MSC.ExecutionTrace
import TDN.MSC.Isolation
import TDN.MSC.Authentication
import TDN.MSC.Protection
import TDN.MSC.Hardening
import TDN.MSC.Lifecycle
import TDN.MSC.FirewallControl
import TDN.MSC.SourceReachability
import TDN.MSC.ControlServices
import TDN.MSC.Multicast

/-!
# MSC public entry point

Import `TDN` or `TDN.MSC` to use the required MSC example. The dependency order is
Types → Deployment → Topology → Policy, followed by Flow and Contracts.
`TDN.Network` contains reusable graph, filter, IPv4, route, runtime-record, and
encapsulation theory with no dependency on MSC declarations. Topology, Policy,
and MTU instantiate the relevant modules. LocalPolicy checks INPUT/OUTPUT
contracts, while Operational checks declared/runtime correspondence.
Execution connects those observations to packet-processing steps. Isolation
lifts checked source constraints to all finite executions and proves
same-level host delivery for correctly addressed originating packets.
Authentication checks public credentials, loaded peer policy, sampled sessions,
and their binding to kernel SAs. The generic admission theory handles validity,
revocation, explicit peer rules, and supplied cryptographic verification results.
Configuration imports Contracts. Deployment contains generated records;
Topology, Policy, Contracts, and Configuration prove snapshot facts and their
general consequences. Credentials checks sampled public certificate metadata.
Flow proves conditional properties of idealized protected-data processing.
Hardening checks configured startup, resolver choices, interface uses, process
inventory, and clock observations. Lifecycle checks both peers' loaded renewal
policies and lifts those finite checks to authentication-before-activation in
automatic renewal traces. Its input authentication results are bound to the
current exchange and modeled clock. Operator-forced and unconstrained external
renewal requests are separate from that automatic-peer model.

The administration plane is optional. Full-export totals, management lemmas,
and the full historical probe report live in `TDN.MSC.SnapshotDiagnostics`.
That module requires an explicit import and supplies no premise to the required
MSC proofs. Required regeneration projects out management before validating
semantic evidence. Regression tests rebuild the required library with management
removed, unavailable, misconfigured, or absent from observations. Optional probe
reports also supply no premise to required regeneration.

The two CSfC property documents under `docs/` explain the exact claims and their
limits. No theorem establishes full CSfC compliance or proves that Linux
implements the Lean transition semantics.
-/
