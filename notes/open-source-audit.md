# Open Source Audit

## Repository Shape

- Root launcher scripts: `run.sh`, `bin/run.sh`, `install.sh`.
- Scanner implementation: `pipeline/`, `tools/`, `scripts/`.
- User docs: `README.md`, `docs/`, `prompts/`, `notes/`.
- Test coverage and fixtures: `tests/`.
- Runtime output directories: `runs/`, `runtime/`.

## Generated Artifacts Found

- Saved run bundles under `runs/`.
- HTML reports, Markdown summaries, JSON, JSONL, XML, GNMAP, and NMAP outputs inside run bundles.
- Screenshots inside run bundles.
- Command logs, route captures, tool-version snapshots, NXC artifacts, and performance summaries inside run bundles.
- Python bytecode caches under `__pycache__` and `.pytest_cache`.

## Files With Environment-Specific Content

- `README.md`
- `bin/run.sh`
- `docs/architecture.md`
- `docs/flow.md`
- `AGENTS.md`
- `pipeline/local_scanner.py`
- `tests/fixtures/*`
- `tests/test_local_scanner.py`
- `runs/20260702-143937/*`

## Sensitive Content Categories Observed

- Internal lab domain names and hostnames.
- Private IPv4 ranges and routed VPN examples.
- Domain-controller candidate names and NXC/Nmap output containing lab-specific naming.
- Route-validation output with development interface and gateway addresses.
- Example DNS SRV records and hostnames in fixtures.

## Runtime Artifacts Removed

- `.pytest_cache/`
- `pipeline/__pycache__/`
- `tests/__pycache__/`
- `tools/__pycache__/`
- `runs/20260702-133041/`
- `runs/20260702-141716/`
- `runs/20260702-142042/`

## Runtime Artifacts Preserved

- `runs/20260702-143937/` as the single sanitized example bundle.
- `runtime/cache/.gitkeep`
- `runtime/logs/.gitkeep`
- `runtime/output/.gitkeep`
- `runtime/reports/.gitkeep`
- `runtime/screenshots/.gitkeep`

## Notes

- The preserved run bundle still demonstrates the full pipeline, but all lab-specific names were normalized to demo values.
- Remaining review items are mainly stylistic, such as whether the preserved example bundle should stay versioned long-term.
