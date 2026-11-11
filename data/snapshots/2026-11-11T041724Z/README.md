# Peer-bound MKA parameter capture

The `mka-parameters` collection records two Linux MACsec peers running the identified instrumented wpa_supplicant binary. The collection checks configured and observed MKA settings together with peer identities, MACsec state, and successful traffic. The observed settings include a 2,000 ms normal hello interval, a 500 ms active interval, a 6,000 ms lifetime, replay window 2, and confidentiality offset 0. All three test ping packets were delivered.

The [collector](../../../scripts/construction/evidence/collect_mka_parameters.py) accepts `--binary` and a fresh `--output` directory. It creates isolated namespaces, generates temporary test keys, collects records, and cleans up its processes and namespaces. The saved public files redact secret CAK material. The MCP parser `mka-parameters-v1` exports the `mka_parameters` view after validating the capture's records and peer bindings.

The `mka-source-reference` directory records a source excerpt and the inspected source/binary identities. The excerpt explains how `macsec_policy=1` and `macsec_integ_only=0` select encryption. Source presence in the binary's build directory supports that interpretation but does not establish a reproducible build. Timer settings describe the captured instrumented build; the capture does not prove universal timer execution or conformance of an unmodified hostap release.

The proof applications combine these captured settings with separately identified model topologies and packet representations. Reduced-protection and nonzero-offset examples test the model's distinction between MACsec framing and full confidentiality. The installed iproute2 tool rejected nonzero confidentiality offsets, so those offset examples have no corresponding live capture.
