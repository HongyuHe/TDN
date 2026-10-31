# MSC network profiles

The five `native-` topology files define the final FRR/OVS configurations used in the construction run. FRR supplies routing and router CLI access, OVS supplies switching, and strongSwan with Linux XFRM supplies encryption. Black routers and Outer Firewalls use OSPF. Gray routers and Gray Firewalls use static routes in FRR. All devices run in Linux containers.

| Configuration | Topology | Diagram | Devices / virtual links |
| --- | --- | --- | --- |
| Two-site baseline | [native-ipsec-baseline.json](native-ipsec-baseline.json) | [PNG](native-ipsec-baseline.png) / [SVG](native-ipsec-baseline.svg) | 23 / 24 |
| Two networks at one security level | [native-shared-same-level.json](native-shared-same-level.json) | [PNG](native-shared-same-level.png) / [SVG](native-shared-same-level.svg) | 19 / 20 |
| Four levels with shared Outer devices | [native-shared-four-levels.json](native-shared-four-levels.json) | [PNG](native-shared-four-levels.png) / [SVG](native-shared-four-levels.svg) | 31 / 36 |
| Four levels with redundant Outer paths | [native-redundant-four-levels.json](native-redundant-four-levels.json) | [PNG](native-redundant-four-levels.png) / [SVG](native-redundant-four-levels.svg) | 37 / 56 |
| Independent management at both sites | [native-management-independent.json](native-management-independent.json) | [PNG](native-management-independent.png) / [SVG](native-management-independent.svg) | 35 / 44 |

Each figure includes every device and virtual link from its JSON topology. Colors identify device roles and link zones. Names omit the shared prefix printed above each diagram. Hover over a link in the SVG to inspect its endpoint interfaces. IPsec tunnels run over the depicted links. FRR helper containers are additional runtime containers and are not separate topology devices.

## Why the folder contains more than five profiles

The folder contains 15 topology JSON files and seven supporting JSON files from the construction work. The five native topology files above are the final configurations. Ten earlier topology files preserve generator inputs and intermediate experiments:

- `ipsec-baseline.json`, `shared-same-level.json`, `shared-four-levels.json`, `redundant-four-levels.json`, and `management-independent.json` are inputs to `../make_native.py`. The generator adds FRR/OVS image settings, distinct device prefixes, and the native routing choices.
- `shared-three-level.json`, `shared-three-level-inline.json`, `redundant-three-level.json`, `redundant-three-level-inline.json`, and `redundant-router.json` preserve earlier three-level and router-placement versions. The `inline` versions record the repair that inserted Gray Firewalls into paths from Inner encryptors. Earlier failed arrangements remain useful for tracing why the repair was needed.
- Five `native-*-mapping.json` files record original-to-native device names. They do not define networks.
- `same-level-probe-policy.json` and `native-same-level-probe-policy.json` specify which test flows should succeed or be blocked. They do not define networks.

The new `visualization-manifest.json` records diagram source hashes, device IDs, and link endpoints. The PNG and SVG files are generated figures.

## Regenerate the figures

Run the following command from the TDN repository root with `rsvg-convert` installed:

```sh
python3 scripts/construction/evidence/draw_profiles.py
```

The generator reads the five native JSON files and writes matching PNGs, SVGs, and the visualization manifest in this folder. It checks that every declared device has a diagram position and renders each declared link once. The `.lavish/profile_visuals.py` helper inserts the figures into the existing report while preserving its other content.
