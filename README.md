# Theory-defined Networking (TDN)

Theory-defined Networking (TDN) explores **networks that carry and maintain their own correctness arguments**. Network requirements span specifications, device configurations, and changing runtime state. TDN connects those sources through formal models and reusable proofs, with the aim of making network behavior easier to explain, debug, and trust.

**AI agents construct the models and proofs; Lean checks the proofs.** A model describes the network behavior relevant to a requirement. A proof establishes that the modeled behavior satisfies that requirement under explicit assumptions. TDN aims to reuse those arguments across network designs and deployments, concentrating network-specific work on collecting evidence and checking the required conditions.

## Approach

TDN combines **top-down reasoning from requirements** with **bottom-up evidence from networks**:

- **Start with the requirements.** Extract requirements from documents, retain their source context, and translate them into precise statements. Identify the conditions needed to prove each statement.
- **Connect the statements to observations.** Collect device configurations and runtime state through an extensible evidence service. Translate relevant observations into data that the proofs can use, while preserving their sources.
- **Build and reuse the proofs.** Develop general arguments about network behavior, then check their conditions for each network. Proof construction and evidence collection inform one another: missing evidence or a failed condition can prompt a better model, additional observations, or a network repair.

For example, a requirement may demand that every path between two networks crosses a firewall. A general proof can establish that property from conditions on individual connections. Different deployments supply their own connections and checks while reusing the same argument.

A checked proof establishes a claim about its model and assumptions. Applying that claim to a running network requires reliable observations and a justified connection between the model and actual packet processing. Maintaining that connection as networks change is a central research goal.
