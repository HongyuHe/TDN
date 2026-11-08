# Explorer publication

- Keep the current Lean code, source templates, generated local explorers, public exports, and deployed website pages synchronized whenever changing the theory hierarchy or role ontology.
- Use **TDN v3.1** for the project version in both page titles and headers. Lean names the implementation language.
- Follow `scripts/publication/README.md`. Regenerate affected pages, validate them, commit their required code and data with the public exports, and push `main` to run the website publication workflow.
- Verify the publication workflow and website deployment before reporting that a public page is updated. Check `/tdn/source.json` and both live pages against the published revision.
- Keep unrelated work and temporary outputs out of publication commits. Preserve revision-specific GitHub file and line links.
- Use Hongyu Hè as the sole author of every commit.
