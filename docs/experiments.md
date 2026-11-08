# Experiments and results

The status below reflects the retained TDN v3.1 records as of November 8, 2026. The [review register](../data/publication/v3.1/register.json) records the status of each requirement group.

## CSfC Multi-Site Connectivity

The current case study formalizes the CSfC Multi-Site Connectivity specification against Twinet emulations. The models cover topology, packet filtering and routing, IPsec and MACsec layers, authentication, generated replies, and fragmentation. The theory separates reusable networking arguments from CSfC requirements and concrete evidence checks.

The requirements catalog contains **76 groups**. The [scope assessment](../specs/proof_scope.json) recommends general proofs for **24 groups** and direct checks for **29 current contributions**. The active Lean theory now follows that scope. The remaining **22 groups** need external assurance or unsupported capabilities; **one group** states an optional permission. These decisions concern the assessed clauses, and full CSfC compliance remains unproved.

Of the 24 selected groups, **14 have reviewed proofs of every clause of their instantiated specifications**. The remaining **10 are deferred** and retain supporting results. The [theory hierarchy](https://hongyu.nl/tdn/hierarchy/) connects each specification to its general proofs and concrete checks; the [role ontology](https://hongyu.nl/tdn/ontology/) explains how device roles map to the model. The [scope guide](theory_scope.md) records the accepted scopes, assumptions and validation commands. The earlier [construction record](../data/construction/current.json) preserves its original 53-group partial-contribution count.

Each proof establishes a claim about its stated model and assumptions. Applying the claim to a deployment requires faithful collection, correct translation, and a justified connection between actual processing and the modeled operations. Continuous proof maintenance remains a research goal.

## Evidence and reproduction

The [emulation profiles](../data/extraction/networks/profiles/README.md) describe the network configurations and topology diagrams. [Timestamped snapshots](../data/snapshots/) retain observations, and [imported evidence](../data/evidence/) supplies the records used by Lean. New observations require a new snapshot; changing a live network does not change previously saved evidence.

The [scope guide](theory_scope.md) explains the accepted results, their assumptions, and the validation commands. The [developer guide](development.md) covers the repository structure and build process.
