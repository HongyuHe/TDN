# Experiment networks

The collection combines network inputs from the sibling `dna`, `sre`, and `expresso` projects.
It contains **312 datasets**, with **15 duplicate entries merged** from 327 source datasets.
The 13,942 collected input and supporting files occupy 297,234,227 bytes, or about 283.5 MiB.
These totals exclude the four catalog files in this directory.

## Layout

Source namespaces preserve the original directory structure and distinguish different representations of the same topology.

| Directory | Datasets | Contents |
| --- | ---: | --- |
| `dna/config2spec-networks/` | 6 | BICS, Columbus, and USCarrier vendor configurations for BGP and OSPF |
| `dna/example-network/` | 2 | Base and updated example configurations, with the original diagram |
| `dna/fattree/` | 10 | BGP and OSPF fat trees, with available topology and differential inputs |
| `sre/c2s/` | 6 | Config2Spec networks in parsed JSON form |
| `sre/differential/` | 95 | BICS, fat-tree, and campus configuration/update snapshots |
| `sre/exp/` | 98 | Fat-tree, mrinfo, and Topology Zoo inputs |
| `sre/netdice/` | 82 | Remaining NetDice inputs and distinct variants |
| `sre/paper_example/` | 1 | Paper example with configurations, ACLs, and topology |
| `sre/parallel/` | 10 | Parallel-experiment configurations that differ from other inputs |
| `expresso/` | 2 | Example and Internet2 configurations, with routing/topology artifacts |

A dataset is a directory containing a router `configs/` tree or a topology/generator input such as `.in` or `AS-*.json`.
Nested campus snapshots are counted separately.
The count describes experimental datasets and representations, rather than distinct physical topologies.

## Deduplication

Datasets are merged only when their network-defining files match byte for byte and all shared relative file paths have identical SHA-256 hashes.
Unique, nonconflicting supporting files are retained in the canonical directory.
Router datasets are compared using their complete `configs/` and `acls/` trees; generator datasets are compared using their `.in` or `AS-*.json` inputs.

The removed duplicate entries comprise four `sre/parallel/` snapshots, ten `sre/netdice/mrinfo/` datasets, and `sre/netdice/zoo/Kdl`.
Their canonical destinations are recorded in `manifest.json`.
Each dataset's `sources` array lists every original directory represented by that destination.

Different vendor and parsed JSON representations remain available.
Different protocol configurations, ACL/VLAN updates, address-allocation files, and other conflicting inputs also remain separate.
Several Topology Zoo variants share a graph but have different `IpBank` files.
Identical component files within distinct datasets remain in place so that each dataset stays self-contained and can be edited independently.
No semantic equivalence across formats is claimed.

## Included and excluded files

The collection retains configurations, ACLs, topology files, edge ports, environment/probability/property inputs, address-allocation data, differential `dpv` changes, update descriptions, and supporting documentation.
Existing FIB snapshots outside generated-output directories are retained as supporting artifacts.

Generated directories named `out`, `out` followed by digits, `out_*`, `*_out`, `tmp`, and `stats` are excluded.
Cache directories and macOS metadata are also excluded.
The exclusions account for 40,412 files totaling 6,261,647,144 bytes, about 5.83 GiB.
The original source directories remain unchanged.

## Provenance and verification

- [`manifest.json`](manifest.json) records source roots, dataset paths, source aliases, dataset hashes, and collection totals.
- [`files.tsv`](files.tsv) records every collected file's destination, byte count, SHA-256 hash, and source paths.
  Source paths use `<project>/<path relative to that project's networks directory>`.
- [`excluded.tsv`](excluded.tsv) records excluded source directories or metadata files, reasons, file counts, and byte counts.

Every copied file was read back and checked against its recorded size and SHA-256 hash.
Every retained source file was checked against its destination.
Every source file is accounted for by the input manifest or the exclusion report.
Files are independent regular copies; the collection contains no symlinks back to the source repositories.

The original DNA provenance note identifies its Config2Spec inputs as coming from [Config2Spec](https://github.com/nsg-ethz/config2spec). The original note is preserved in [`dna/README.md`](dna/README.md).
The SRE README identifies its `c2s` and `netdice` collections as Config2Spec and NetDice inputs, respectively.
