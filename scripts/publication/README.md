# TDN public explorers

The website serves the theory hierarchy at <https://hongyuhe.github.io/tdn/hierarchy/> and the role ontology at <https://hongyuhe.github.io/tdn/ontology/>. Both pages contain their own styles, scripts, data, and diagrams. They use no website theme assets and require no browser-side requests to load their content.

## Update the pages

Run from the TDN repository root with the project's Lean toolchain, Python 3, and Graphviz installed:

```sh
python3 scripts/publication/build.py
```

The command builds Lean, exports dependencies from compiled declarations, rebuilds the hierarchy and ontology, and refreshes their publication copies under `public/`. The hierarchy's interface files and generator are maintained in `scripts/publication/hierarchy/` and `scripts/publication/build_hierarchy.py`. Local review pages remain under `.lavish/`.

Each generator also refreshes its own public copy when run separately:

```sh
python3 scripts/publication/build_hierarchy.py --render-only
python3 scripts/preprocess/preprocess_csfc_ontology.py
python3 scripts/publication/export_pages.py --check
```

Use `--render-only` after interface-only changes with unchanged hierarchy data. Changes to Lean declarations require the complete build. Changes to the ontology's Lean mappings require reviewing the pinned source hashes in `data/extraction/roles/ontology_theory.json` before rebuilding.

Commit the changed source files and `public/`, then push TDN's `main` branch. The website's Pages workflow checks for a changed publication every 15 minutes. It also runs on website pushes and manual dispatch. Scheduled checks with unchanged publication files skip the Jekyll build and deployment. GitHub can delay scheduled runs; the website workflow can be run manually for an immediate deployment request. See [GitHub's schedule documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

The website checks out one exact TDN commit and validates the page and source hashes before installing either page. It replaces the revision placeholder in each GitHub link with that commit's full ID. The pages therefore link to the same code revision used to generate their line numbers. A failed validation leaves the previously deployed site in place.

## Retained publication inputs

`data/publication/v3.1/` retains the accepted requirement register, the reviewed proof mappings, application records, the final verdict, and selected interpretation decisions. These records are the small, reusable inputs required to explain the published theory. Historical agent logs and intermediate construction files remain outside the publication.

`public/manifest.json` records each HTML file's hash and the source hashes checked before deployment. The website writes `/tdn/source.json` with the installed TDN commit and the publication hash. Each page's code links point to GitHub; local review pages retain VS Code links.

For a local website preview, install the current publication into the website checkout:

```sh
python3 scripts/publication/export_pages.py --install /Users/hongyu/Projects/hongyuhe.github.io/tdn --revision FULL_TDN_COMMIT_ID
```

Pass the actual website path if it is elsewhere. The install command only writes `hierarchy/index.html`, `ontology/index.html`, and `source.json` inside the requested destination. The website stores initial standalone copies, and its deployment workflow replaces those copies with the latest verified publication. No additional GitHub credential or shared CSS is required.
