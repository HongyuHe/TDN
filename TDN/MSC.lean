import TDN.MSC.Flow
import TDN.MSC.Configuration
import TDN.MSC.Credentials

/-!
# MSC public entry point

Import `TDN` or `TDN.MSC` to use the required MSC example. The dependency order is
Types → Deployment → Topology → Policy, followed by Flow and Contracts.
Configuration imports Contracts. Deployment contains generated records;
Topology, Policy, Contracts, and Configuration prove snapshot facts and their
general consequences. Credentials checks sampled public certificate metadata.
Flow proves conditional properties of idealized protected-data processing.

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
