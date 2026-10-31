# Exact csfc-evidence/v1 field conventions

The validator accepts the proposed schema with the following explicit spellings. These conventions resolve fields that the initial prose left unspecified.

- Every inventory entry is an object: `"devices": {"complete": true, "reason": "Enumerated all requested namespaces and reconciled expected IDs"}`. The same form applies to all nine inventory categories. A false value requires a reason too.
- Observation times are `started_at` and `ended_at`. Successful parsed observations use `parse_status: "parsed"`. Records marked observed must cite successful parsed observations. Raw files must be in manifest files with matching hashes.
- Scope contains `expected_device_ids` and `expected_interface_ids`. Complete inventories must equal those ID sets, with no duplicates. An empty inventory cannot support a data-path conclusion.
- Links use `endpoint_interface_ids: ["interface-a", "interface-b"]`. Foreign references are checked.
- IDs are globally unique across fact categories. Observation IDs have their own namespace.
- Filter rules use an object in `matches`, retain `raw_text`, and specify a unique ascending integer `ordinal`. Unsupported matches/actions are preserved and reported; they prevent whole-policy proofs. Initial semantic support is deliberately narrow and can be extended from actual records.
- `management` remains its own object. Missing management capability does not gate data-path import.

The validator checks representation integrity and reference closure. It does not certify raw observation truth, implementation semantics, physical independence, source applicability, or compliance. Unknown fields remain preserved in the original hashed bundle.
