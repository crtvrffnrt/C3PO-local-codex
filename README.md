<div align="center">
 

  <h1>C3PO-local-codex<h1>
  <img src="logo.jpg" alt="C3PO-shodan logo" width="360">

  <p><strong>A nmap,nxc and nuclei driven scanning pipeline for mapping local infrastructure orchestrated by codex cli <p>

  <p>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"></a>
    <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/shell-bash-121011?style=flat-square&logo=gnu-bash&logoColor=white" alt="Bash"></a>
    <a href="https://github.com/projectdiscovery/nuclei"><img src="https://img.shields.io/badge/scanner-Nuclei-0F766E?style=flat-square" alt="Nuclei"></a>
    <a href="https://github.com/projectdiscovery/httpx"><img src="https://img.shields.io/badge/enrichment-httpx-2563EB?style=flat-square" alt="httpx"></a>
  </p>
</div>


# C3PO Local Network Scanner

C3PO Local is a self-contained scanner for authorized internal networks. It derives scope from a selected Linux interface, discovers reachable local hosts, ranks up to 10 high-priority systems, runs deeper safe enumeration only against those hosts, and writes a standalone HTML report.

It is aimed at pre-authentication and unauthenticated reconnaissance of internal infrastructure, including Windows-oriented environments such as domain-controller and common server networks where valid credentials may not be available.



## Usage

Before the first scan, run the preparation check:

```bash
./install.sh
```

It verifies the required runtime (`bash`, `python3`, `ip`) and reports which optional scanners are available.

Primary path:

```bash
./run.sh -i wlan0
```

The wrapper displays an authorization banner, requires explicit acknowledgement, and then asks for a Codex model/reasoning profile:

- GPT-5.5 High
- GPT-5.5 Medium
- GPT-5.5 Low
- GPT-5.4 Mini High
- GPT-5.4 Mini Medium
- GPT-5.4 Mini Low

For automation:

```bash
./run.sh -i wlan0 --authorized
./run.sh -i wlan0 --authorized --dry-run
```

This installed Codex CLI supports `--model` but does not expose a documented reasoning-effort flag. C3PO records the selected reasoning profile and includes it in Codex prompts; it does not guess unsupported flags.

## Dependencies

Required:

- Linux with `ip`
- `bash`
- `python3` 3.10+

Optional:

- `nmap` for host discovery and service enumeration
- `nuclei` for safe local web checks
- `nxc` for safe NetExec protocol reconnaissance
- `arp` and `arp-scan` for local discovery

No Shodan, Docker lab targets, public DNS APIs, Cloudflare services, external MCP servers, agent files, or skill files are required.

## Scan Flow

1. Validate the selected interface.
2. Require authorization acknowledgement.
3. Create `runs/YYYYmmdd-HHMMSS/`.
4. Capture tool versions.
5. Derive private local scope from `ip -4 addr show dev <interface>`, `ip -4 route show dev <interface>`, `ip -4 route show table main`, and `ip -4 route get <representative-ip>`.
6. Write `scope.json` and `scope.txt`.
7. Validate effective routed scope, record overlap warnings, and persist route evidence under `routes/`.
8. Discover live hosts through neighbor/ARP data, gateways, optional `arp-scan`, bounded per-subnet `nmap -sn`, and a small TCP fallback scan for ping-blocked hosts on small subnets.
9. Write `live-hosts.txt` and `live-hosts.json`.
10. Run fast bounded Nmap against live hosts in per-subnet batches using explicit infrastructure ports.
11. Discover and prioritize `example.internal` domain-controller candidates from DNS SRV, Nmap, and NXC evidence.
12. Ask Codex to interpret structured discovery evidence when available; fall back to deterministic scoring if Codex fails.
13. Run deep Nmap only against selected top hosts.
14. Run Nuclei only against HTTP/HTTPS services on selected top hosts and always write a Nuclei artifact, even when no web targets are selected.
15. Run NXC only against protocols indicated by open ports/services.
16. Capture browser screenshots for top-host web targets when a local browser is available.
17. Generate `report.html` and structured artifacts under the run directory.

## Safety Model

C3PO only scans normalized private scope derived from the selected interface. It excludes public internet ranges, default routes, loopback, link-local active sweeps, multicast, broadcast, documentation ranges, Docker bridge assumptions, unrelated interfaces or routes, and overlapping routes that are not effectively routed through the selected interface.

The scanner does not run brute force, password spraying, exploit modules, command execution, coercion attacks, ADCS abuse, password changes, file upload/download, credential dumping, hash dumping, LSASS/SAM/LSA/NTDS/DPAPI extraction, browser data collection, token theft, or destructive checks.

## Outputs

Each run creates:

```text
runs/YYYYmmdd-HHMMSS/
  scope.json
  scope.txt
  live-hosts.txt
  live-hosts.json
  service-map.json
  top-hosts.json
  top-hosts.md
  scan-data.json
  commands.jsonl
  events.jsonl
  routes/
  domain/
  performance/
  screenshots/
  nmap_*.xml
  nuclei_safe.jsonl
  nxc/
  report.html
```

NXC writes:

```text
nxc/jsonl/commands.jsonl
nxc/jsonl/events.jsonl
nxc/jsonl/findings.jsonl
nxc/json/summary.json
  nxc/meta/capabilities.json
```

The HTML report now includes:

- a management summary;
- a routing and scope section with overlap warnings and route-validation evidence;
- domain-controller candidate evidence;
- top-host cards with open ports, relevant CVEs, and screenshots when available;
- explicit top-host verification commands such as `curl` and `nc` for confirming reported findings;
- phase durations, timeout tracking, and partial-result notes.

## Architecture

See [docs/architecture.md](docs/architecture.md) and [docs/flow.md](docs/flow.md).

## Removal Notes

Shodan and Docker target-generation paths were removed from the normal scanner. Historical references should only appear in changelog or refactor notes documenting that removal.
