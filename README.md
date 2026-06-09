<div align="center">
  <img src="logo.jpg" alt="C3PO-shodan logo" width="360">

  <h1>C3PO-shodan</h1>

  <p><strong>A Shodan-driven EASM pipeline for mapping exposed infrastructure, enriching risky web targets, and rendering operator-friendly reports.</strong></p>

  <p>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"></a>
    <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/shell-bash-121011?style=flat-square&logo=gnu-bash&logoColor=white" alt="Bash"></a>
    <a href="https://www.shodan.io/"><img src="https://img.shields.io/badge/data-Shodan-EA4335?style=flat-square" alt="Shodan"></a>
    <a href="https://github.com/projectdiscovery/nuclei"><img src="https://img.shields.io/badge/scanner-Nuclei-0F766E?style=flat-square" alt="Nuclei"></a>
    <a href="https://github.com/projectdiscovery/httpx"><img src="https://img.shields.io/badge/enrichment-httpx-2563EB?style=flat-square" alt="httpx"></a>
    <a href="https://github.com/google-gemini/gemini-cli"><img src="https://img.shields.io/badge/workflow-Gemini_CLI-5B5BD6?style=flat-square" alt="Gemini CLI"></a>
  </p>

  <p>
    <a href="#quick-start"><strong>Quick Start</strong></a> •
    <a href="#pipeline"><strong>Pipeline</strong></a> •
    <a href="#configuration"><strong>Configuration</strong></a> •
    <a href="#outputs"><strong>Outputs</strong></a>
  </p>
</div>

---

## Report Preview

The HTML report is designed as a high-contrast attack-surface console with infrastructure summaries, risk scoring, screenshots, and findings in one place.

<div align="center">
  <img src="example.png" alt="Example report view" width="1000">
</div>

## Overview

`C3PO-shodan` is an External Attack Surface Management (EASM) framework that orchestrates **Codex prompts** (via AI agent workflows) and **bash commands / Python scripts** to discover and map exposed infrastructure. It takes a target root domain, fetches DNS/host metadata using Shodan, detects potential subdomain takeovers, performs targeted Nuclei vulnerability scans, captures web screenshots, and renders interactive reports.

The execution logic is structured to enable LLM-based security agents and human operators to safely direct, validate, and execute complex reconnaissance pipelines.

## What It Does

| Capability | Details |
| --- | --- |
| Discovery | Collects Shodan DNS records, hostname/IP enrichment, DNS resolution, and optional `crt.sh` expansion. |
| Risk Signal Collection | Extracts TXT verification signals, provider-linked CNAME patterns, and takeover-oriented indicators. |
| Web Enrichment | Probes reachable HTTP/S targets and adds tech-stack enrichment with `httpx` when available. |
| Vulnerability Triage | Runs Nuclei against the top 25 risky reachable web targets. |
| Visual Evidence | Captures screenshots for up to 16 reachable targets, preferring Cloudflare URL Scanner and falling back to local tooling. |
| Reporting | Renders a versioned Markdown report, self-contained HTML dashboard, and supporting JSON artifacts. |

## Quick Start

### 1. Install dependencies

Required:

- `python3` 3.10+
- `bash`
- `curl`
- `nuclei`
- `httpx`
- `gemini` CLI

Optional but useful:

- One local screenshot tool: `chromium`, `google-chrome`, `microsoft-edge`, or `wkhtmltoimage`
- Cloudflare API credentials for better screenshots and URL intelligence

Recommended installs:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
npm install -g @google/gemini-cli
nuclei -update-templates
```

### 2. Configure credentials

Copy the example env file and add your keys:

```bash
cp .env.example .env
```

Minimum required:

```bash
SHODANAPI=your_shodan_api_key
```

Optional Cloudflare token flow:

```bash
CF_ACCOUNT_ID=your_account_id
CF_API_TOKEN=your_api_token
```

Alternative Shodan key file:

```bash
mkdir -p ~/.shodan
printf '%s\n' "your_shodan_api_key" > ~/.shodan/api_key
chmod 600 ~/.shodan/api_key
```

### 3. Run the pipeline

```bash
chmod +x run.sh bin/run.sh scripts/*.sh install.sh
./install.sh
./run.sh example.com
```

## Pipeline & Execution Flow

The tool operates by orchestrating **Codex/Gemini prompts** (via developer-agent workspaces and the `gemini` CLI) alongside **native bash commands and Python helper scripts** to automate end-to-end attack-surface mapping. 

The execution runs through the following sequence of phases:

### Phase 1: Preflight & Validation
- **Commands**: [install.sh](file:///tmp/C3PO-Shodan-codex/install.sh) and [scripts/validate.sh](file:///tmp/C3PO-Shodan-codex/scripts/validate.sh)
- **Mechanism**: Verifies environment dependencies (`python3`, `curl`, `nuclei`, `httpx`, and the `gemini` CLI) and API keys (such as `SHODANAPI` and optionally Cloudflare details). 
- **Orchestration**: Ensures the workspace context and target inputs are formatted correctly before starting execution.

### Phase 2: Shodan-Driven Discovery
- **Commands**: [scripts/orchestrate.py](file:///tmp/C3PO-Shodan-codex/scripts/orchestrate.py) invoking [pipeline/shodan_adapter.py](file:///tmp/C3PO-Shodan-codex/pipeline/shodan_adapter.py)
- **Mechanism**: Interrogates Shodan's DNS API to fetch subdomains, maps hostnames to IP addresses, performs reverse lookups, and optionally queries certificate transparency logs via `crt.sh`.
- **Orchestration**: Resolves domain listings and catalogs active hostnames for targeting.

### Phase 3: TXT & Takeover Enrichment
- **Commands**: [scripts/txtfinder.py](file:///tmp/C3PO-Shodan-codex/scripts/txtfinder.py)
- **Mechanism**: Inspects TXT records, resolves CNAME paths, and parses provider-linked DNS strings to detect subdomains dangling on third-party service providers (like AWS, Azure, Shopify, GitHub Pages).
- **Orchestration**: Flags targets with high takeover risk by matching signature fragments.

### Phase 4: Targeted Vulnerability Scanning
- **Command**: `nuclei`
- **Mechanism**: Feeds the top 25 reachable, highest-risk web targets into `nuclei`. Scans run using specific templates (tags: `misconfig,exposure,takeover,cve,tech,default-login`) at `critical`, `high`, and `medium` severity.
- **Orchestration**: Automates active scanning selectively to keep network noise low while validating high-severity risks.

### Phase 5: Visual Evidence Capture
- **Commands**: [scripts/capture-screenshots.py](file:///tmp/C3PO-Shodan-codex/scripts/capture-screenshots.py) (or the Cloudflare Parallel Scanner script)
- **Mechanism**: Captures visual proof of reachable HTTP/S hosts. It prioritizes Cloudflare's URL Scanner API for headless capture and falls back to local web engines (Chrome, Edge, Chromium, or `wkhtmltoimage`).
- **Orchestration**: Creates a screenshot index of reachable interfaces to assist human review.

### Phase 6: Report Synthesis
- **Commands**: [scripts/render-report.py](file:///tmp/C3PO-Shodan-codex/scripts/render-report.py)
- **Mechanism**: Aggregates all JSON outputs, Nuclei scan records, CNAME findings, and screenshot paths.
- **Orchestration**: Generates an interactive, offline-ready HTML dashboard (`output/report.html`) and structured Markdown reports (`runtime/reports/`).

---

### Codex and Agent Integration
While the pipeline execution is structured and deterministic to guarantee reliability, the workflow is designed to be governed by **Codex Prompts** and **LLM Agents** (like the `C3PO-shodan` agent). 
1. **Agent Guidance**: The pipeline relies on agent instructions ([AGENTS.md](file:///tmp/C3PO-Shodan-codex/AGENTS.md) and workflow-specific `SKILL.md` files) to orchestrate and patch behavior safely.
2. **Context Enrichment**: Shell scripts (like [scripts/fetch-context.sh](file:///tmp/C3PO-Shodan-codex/scripts/fetch-context.sh)) keep track of active rules, making the entire workspace navigable and controllable by LLM operators using Codex-style commands.

## Configuration

### Common runtime knobs

Defaults come from [`config/config.yaml`](config/config.yaml).

| Key | Default | Purpose |
| --- | --- | --- |
| `domain_ct_enabled` | `true` | Enable `crt.sh` hostname expansion. |
| `shodan_dns_page_limit` | `4` | Limit Shodan DNS paging. |
| `shodan_host_enrichment_limit` | `20` | Cap Shodan host detail enrichment. |
| `max_hosts_for_http_probe` | `40` | Limit HTTP probing volume. |
| `max_screenshots` | `16` | Limit screenshot captures. |
| `screenshot_timeout_seconds` | `35` | Local screenshot timeout. |

### Detailed setup

<details>
<summary><strong>Cloudflare URL Scanner setup</strong></summary>

For better screenshots and URL intelligence, create an API token at `https://dash.cloudflare.com/profile/api-tokens` with:

- `Account -> Cloudflare Radar:Read`
- `Account -> URL Scanner:Read`
- `Account -> URL Scanner:Edit`

Then add:

```bash
CF_ACCOUNT_ID=your_account_id
CF_API_TOKEN=your_api_token
```

Legacy global-key auth is also supported:

```bash
CF_ACCOUNT_ID=your_account_id
CF_EMAIL=your_cloudflare_email
CF_API_KEY=your_global_api_key
```

</details>

<details>
<summary><strong>Gemini CLI authentication</strong></summary>

Authenticate once before using Gemini-driven repo workflow:

```bash
gemini login
```

The report pipeline remains deterministic; Gemini is not used to fabricate a separate executive summary.

</details>

<details>
<summary><strong>Python requirements</strong></summary>

The Python code uses the standard library. A minimal [`requirements.txt`](requirements.txt) is included for automation compatibility:

```bash
python3 -m pip install -r requirements.txt
```

</details>

## Outputs

After a run, expect these primary artifacts:

| Path | Description |
| --- | --- |
| `output/attack_surface_<target>_<date>.json` | Raw collected attack-surface payload. |
| `output/attack_surface_<target>_<date>.html` | Self-contained HTML dashboard. |
| `runtime/reports/attack_surface_<target>_<date>.md` | Markdown report. |
| `output/nuclei_<target>_<date>.jsonl` | Nuclei findings for scanned web targets. |
| `output/attack_surface_<target>_<date>_screenshots.json` | Screenshot manifest. |
| `attack_surface_latest.html` | Convenience copy of the latest HTML report. |

## Project Layout

| Path | Role |
| --- | --- |
| [`bin/run.sh`](bin/run.sh) | Main entrypoint and phase orchestration. |
| [`install.sh`](install.sh) | Preflight checks for tools and credentials. |
| [`scripts/collect-attack-surface.py`](scripts/collect-attack-surface.py) | Shodan/DNS collection and enrichment. |
| [`scripts/capture-screenshots.py`](scripts/capture-screenshots.py) | Screenshot capture with local tooling. |
| [`scripts/render-report.py`](scripts/render-report.py) | Markdown and HTML report rendering. |
| [`docs/architecture.md`](docs/architecture.md) | High-level architecture notes. |
| [`docs/flow.md`](docs/flow.md) | End-to-end execution flow. |

## Notes

- Screenshot capture is best-effort and is skipped automatically when tooling is unavailable.
- If Cloudflare rate-limits or credentials are missing, the pipeline falls back to local screenshot capture.
- If `nuclei` is unavailable or no reachable web targets exist, the rest of the collection and reporting pipeline can still complete.
- Output is generated locally for inspection; the repo does not create a separate CISO-summary text artifact.
