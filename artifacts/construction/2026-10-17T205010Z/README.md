# CSfC construction run 2026-10-17T205010Z

Status: converged. Both independent GPT-6 Astra agents used extra-high reasoning and fresh context. Every target and case has an explicit outcome; the run does not establish every requirement.

Start with the [run report](RUN_REPORT.md) for outcomes, network repairs, model changes, replay instructions and validation. The [integrated proof report](integration/CONSTRUCTION_REPORT.md) explains the final code and its assumptions.

- `session.json`: model configuration, source commit, workspace locations, and isolation limitations.
- `coordination/`: frozen inputs, archive inventory, and complete initial target register.
- `communications/`: requests, responses, and coordinator exchanges.
- `evolution/`: timestamped change reasons and outcomes.
- `checkpoints/`: intermediate proof and deployment sources copied from agent histories.
- `validation/`: archive, isolation, build, and evidence checks.

The archive is preserved under `archive/v1/` relative to the repository root. Agent workspaces contain specification-only inputs and no old proof history.
