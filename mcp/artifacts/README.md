# Selected MCP capture

Git retains the BIRD collection `20261031T165203Z-aa3dae3f2fdc` because it supplies the source observations for the [BIRD Lean import example](../../tests/evidence_service/BirdImport.lean). Its exported JSON is [data/evidence/20261031T165203Z-aa3dae3f2fdc.json](../../data/evidence/20261031T165203Z-aa3dae3f2fdc.json).

The [capture directory](live/20261031T165203Z-aa3dae3f2fdc/) contains the manifest, its hash, raw command responses, the prepared Lean JSON, and its hash. The manifest records two BIRD devices, collection times, commands, parser versions, and response hashes. Retaining those files lets us check the inputs and reproduce the JSON export without contacting the original workers.

Routine build logs, test reports, migration summaries, and other collections remain local and are ignored by Git. Future captures should be retained only when an identified proof, test, or reproducibility task needs them. Add each selected capture explicitly to `.gitignore` and document its consumer here.
