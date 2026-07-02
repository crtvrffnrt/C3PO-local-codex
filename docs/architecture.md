# C3PO Local Scanner Architecture

## Overview

C3PO Local Scanner is an interface-scoped internal attack-surface mapper. It replaces the previous external Shodan-oriented collection path with a local Linux network discovery and reporting pipeline.

## Layers

1. `run.sh`
   Thin root entrypoint that delegates to `bin/run.sh`.

2. `bin/run.sh`
   Parses `./run.sh -i <interface>`, performs basic dependency checks, prints startup status, handles Ctrl+C, and invokes the Python scanner core.

3. `pipeline/local_scanner.py`
   Owns scanner logic:
   - interface validation
   - local route and scope discovery
   - safety filtering
   - passive and active host discovery
   - quick nmap scanning
   - deterministic top-10 prioritization
   - deep safe scanning of top 10 hosts only
   - optional safe Nuclei checks
   - optional screenshots
   - HTML report generation

## Runtime Outputs

Each run writes to `reports/<timestamp>/`:

- `report.html`: primary HTML report
- `scan_data.json`: structured internal evidence
- `dependencies.json`: dependency and privilege snapshot
- `nmap_*.xml`: nmap artifacts when nmap is installed
- `nuclei_safe.jsonl`: Nuclei findings when nuclei is installed and web targets exist
- `screenshots/*.png`: optional local screenshots
- `*_command.txt`: reproducibility commands

## Design Principles

- Interface-derived scope only
- No public internet scanning
- Safe, bounded active discovery
- Top-10-only deep enumeration
- Evidence-based reporting without overclaiming
- Graceful degradation when optional tools are missing
- Single primary HTML report
