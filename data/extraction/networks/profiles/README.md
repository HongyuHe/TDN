# MSC network profiles

The five `native-` topology files define reusable FRR/OVS layouts for replay and further evidence collection. FRR supplies routing and router CLI access, OVS supplies switching, and strongSwan with Linux XFRM supplies encryption. Black routers and Outer Firewalls use OSPF. Gray routers and Gray Firewalls use static routes in FRR. All devices run in Linux containers.

| Configuration | Topology | Diagram | Devices / virtual links |
| --- | --- | --- | --- |
| Two-site baseline | [native-ipsec-baseline.json](native-ipsec-baseline.json) | [PNG](native-ipsec-baseline.png) / [SVG](native-ipsec-baseline.svg) | 23 / 24 |
| Two networks at one security level | [native-shared-same-level.json](native-shared-same-level.json) | [PNG](native-shared-same-level.png) / [SVG](native-shared-same-level.svg) | 19 / 20 |
| Four levels with shared Outer devices | [native-shared-four-levels.json](native-shared-four-levels.json) | [PNG](native-shared-four-levels.png) / [SVG](native-shared-four-levels.svg) | 31 / 36 |
| Four levels with redundant Outer paths | [native-redundant-four-levels.json](native-redundant-four-levels.json) | [PNG](native-redundant-four-levels.png) / [SVG](native-redundant-four-levels.svg) | 37 / 56 |
| Independent management at both sites | [native-management-independent.json](native-management-independent.json) | [PNG](native-management-independent.png) / [SVG](native-management-independent.svg) | 35 / 44 |

Each figure includes every device and virtual link from its JSON topology. Colors identify device roles and link zones. Names omit the shared prefix printed above each diagram. Hover over a link in the SVG to inspect its endpoint interfaces. IPsec tunnels run over the depicted links. FRR helper containers are additional runtime containers and are not separate topology devices.

The November 4 proof continuation uses the baseline and four-level shared layouts with additional firewall, service and packet-sizing configuration. Its exact observations and deployment changes are recorded under [the continuation run](../../../construction/v3.1-20261104-continuation/). The proof inputs are under [data/evidence/continuation](../../../evidence/continuation/). Reproducing a checked application requires the recorded configuration as well as its topology. The collection and configuration helpers are documented in [the evidence tools guide](../../../../scripts/construction/evidence/README.md).

## Supporting files

The directory contains the five native topology files above and five source profiles used by [make_native.py](../../../../scripts/construction/evidence/make_native.py). The source profiles are `ipsec-baseline.json`, `shared-same-level.json`, `shared-four-levels.json`, `redundant-four-levels.json`, and `management-independent.json`. The generator adds FRR/OVS image settings, device prefixes, and routing choices.

Five `native-*-mapping.json` files record original-to-native device names. `same-level-probe-policy.json` and `native-same-level-probe-policy.json` specify expected test outcomes. `visualization-manifest.json` records diagram source hashes, device IDs, and link endpoints.

Superseded three-level and router-placement profiles were removed from the active directory. Git revision `1a49bb76` preserves them under their former `scripts/construction/evidence/profiles/` path.

## Regenerate the figures

Run the following command from the TDN repository root with `rsvg-convert` installed:

```sh
python3 scripts/construction/evidence/draw_profiles.py
```

The generator reads the five native JSON files and writes matching PNGs, SVGs, and the visualization manifest in this folder. It checks that every declared device has a diagram position and renders each declared link once. The `.lavish/profile_visuals.py` helper inserts the figures into the existing report while preserving its other content.
