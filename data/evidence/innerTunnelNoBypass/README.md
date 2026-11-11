# Inner tunnel no-bypass application inputs

The IPsec application retains the complete baseline device, interface, route, firewall, tunnel, directional SA and link records from `data/evidence/continuation/MtuSizing_Baseline.json`. That accepted input is unchanged. The new application admits every Red-source request allowed by the same source processing on all four declared Red networks. Its `origin` and `domainName` functions identify those Red networks. The broader MtuSizing prototype also admits device management and control origins; RG029 does not claim that broader prototype satisfies no-bypass. The packet model describes a fixed installed-SA epoch. It does not generate IKE, routing-protocol, or rekey traffic. Essential protocol observations remain in the retained same-cohort key/execution exports; device-generated control traffic is not collectively classified as optional administration.

`IPsecDelivery.json` contains a generated 44-step TCP sample with a nonempty HTTP request. It crosses both Inner and Outer IPsec tunnel layers, decrypts at both receiving components, crosses the destination Red interface and reaches the destination host. The sample uses the captured FIBs, rules and November4 directional SAs. Its generated TCP bytes are model inputs. Captured sizing traffic is separate and exercises the L1 Inner and Outer pairs; no packet-identity or clock-based causal link between separate captures is asserted.

`IPsecTunnelBindings.json` maps all eight declared IPsec tunnels to same-cohort outbound installed SA records and their observed `mode=tunnel`, `protocol=esp`, endpoints, SPI and raw observation IDs. The original `associatedIPTunnel` flags are false. Interpretation I-RG029-IP-TUNNEL recognizes the IP tunnel encapsulation intrinsic to ESP tunnel mode. The isolated RG029 deployment view makes those flags true for IPsec records and leaves non-IPsec records unchanged. The source and receiver fields, keys, routes, firewall rules and packet processing remain unchanged. Lean proves coverage transfers to the view and binds outer-IP construction to the configured SA endpoints and ESP protocol. Components and tunnel records use the same interpretation within the new application.

The MACsec application uses the accepted `MacsecProtection.direct` profile, two MACsec peers with physical Gray links and logical Red interfaces. Its nonempty ten-step IPv4 delivery exercises encryption and decryption. The same final general RG029 theorem is applied to both mechanisms.

The IPsec key-material function is a deterministic model fixture indexed by retained public material references. The capture redacts the real key bytes. The fixture proves exact paired installation agreement and valid lengths; it does not recover or assert the captured secret bytes. The IPsec theorem accepts an `ESPWire.GCMPrimitive IPsecKeyMaterial` interface with its encrypt/decrypt laws. No concrete AES implementation or cryptographic security theorem is claimed. Sequence 1 and zero IV are serialization parameters for a single modeled sample; freshness and anti-replay across generated packets are outside the RG029 theorem.

Regenerate the two typed JSON inputs from the retained active inputs with:

```sh
python3 scripts/construction/build_inner_tunnel_no_bypass.py
```

The generator reads only repository-relative current evidence. Lean imports the JSON through `load_network_records`, including strict typed round-trip checks. Source hashes and exact MCP sessions are preserved in the RG029 submission.
