# Project Ingestion

## Main Entry Points

- `run.sh` is the root launcher and delegates to `bin/run.sh`.
- `bin/run.sh` handles the authorization banner, Codex model selection, and passes arguments into the Python scanner.
- `pipeline/local_scanner.py` contains the scan pipeline, artifact writing, ranking, and HTML report generation.
- `tools/nxc_phase.py` is the safe NetExec/NXC wrapper used by the scanner.
- `scripts/validate.sh` and `install.sh` provide dependency checks and local validation.

## Scan Phases

Current scan flow in `pipeline/local_scanner.py`:

1. Capture tool versions.
2. Derive scope from the selected interface.
3. Write `scope.json` and `scope.txt`.
4. Discover live hosts using neighbor cache, ARP cache, optional `arp-scan`, and bounded `nmap -sn`.
5. Run a bounded fast Nmap service scan on discovered live hosts.
6. Rank hosts and optionally ask Codex to reorder the top 10.
7. Run deep Nmap only on the selected top hosts.
8. Run Nuclei only against HTTP/HTTPS services on top hosts.
9. Run NXC only for protocols implied by observed ports.
10. Generate `scan-data.json` and `report.html`.

## Scope Derivation Logic

- Scope currently comes from `ip -j addr show dev <iface>` and `ip route show dev <iface>`.
- Private IPv4 ranges are accepted; public, loopback, link-local, multicast, broadcast, and documentation ranges are excluded.
- Active sweeps are limited to networks with 4096 addresses or fewer.
- The current implementation does not yet validate effective routed scope with `ip route get`, and it does not yet model overlapping routes across interfaces.

## Route Parsing Logic

- The current code reads only interface-local routes from `ip route show dev <iface>`.
- Default routes are skipped.
- Safe IPv4 routes are added directly to the scope.
- The current route logic is too narrow for routed VPN environments because it does not confirm the effective egress interface for overlapping prefixes.

## Nmap Execution Logic

- Discovery uses `nmap -sn -T3 --max-retries 2 --host-timeout 30s` across the derived active networks.
- Fast service scanning uses `nmap -Pn -T4 --max-retries 2 --host-timeout 90s --open` on live hosts with a bounded port list.
- Deep scanning uses per-host `nmap -Pn -sV --version-light -T3 --max-retries 2 --host-timeout 8m --script-timeout 20s` with a safe NSE subset.
- This is already bounded, but large routed environments still need better batching, partial-result preservation, and per-phase timing visibility.

## Timeout and Retry Logic

- `run_command()` records per-command timeout, exit code, and duration.
- Nmap phases currently use fixed timeout ceilings derived from host count or host count times a constant.
- Nuclei uses a fixed 5 second per-request timeout and one retry.
- NXC uses the wrapper defaults from `tools/nxc_phase.py` and currently runs only in recon mode when no credentials are supplied.
- The current reporting does not expose a dedicated phase-duration summary or explicit partial-result ledger.

## NXC Integration

- NXC is executed through `tools/nxc_phase.py`.
- The wrapper derives protocol targets from `service-map.json`.
- The wrapper enforces `--authorized`, uses `--no-progress`, records raw logs, and blocks dangerous modules and behaviors unless explicit allow flags are supplied.
- In the current scanner, protocol selection is driven by open ports and observed services only.

## Nuclei Integration

- Nuclei currently runs only for URLs built from HTTP/HTTPS services on top hosts.
- Safe tags are limited to `exposure,misconfig,panel,tech,ssl,tls,http`.
- Intrusive tags are excluded.
- The current timeout is bounded, but the report should make partial or timed-out Nuclei runs more visible.

## Codex Model Selection

- `bin/run.sh` prompts for one of six model/reasoning profiles.
- The scanner records the selected model and reasoning profile in `scan-data.json`.
- If the installed Codex CLI is unavailable or fails, deterministic ranking is used as fallback.

## Top-Host Prioritization

- The current scorer boosts gateway-like hosts, `192.168.100.1`, identity services, storage, admin protocols, databases, web services, legacy services, and broad exposure.
- Codex is given structured host evidence and may reorder the deterministic top 10.
- The current code does not yet have explicit domain-controller discovery or forced DC inclusion.

## Report Generation

- `render_report()` currently writes a single HTML file with summary, scope, tool versions, top hosts, findings, inventory, Nmap/Nuclei/NXC summary, commands, and assumptions.
- The current layout is table-oriented.
- It does not yet provide a management-summary phase, card view for top hosts, host screenshots, or a finding-verification command section focused on top-host evidence.

## Existing Tests

- `tests/test_local_scanner.py` covers:
  - private/public IPv4 filtering;
  - neighbor parsing;
  - basic Nmap XML parsing;
  - FritzBox prioritization;
  - NXC protocol mapping;
  - top-host JSON schema;
  - NXC authorization safety;
  - a repository-wide string scan for removed attack-surface references.
- There are currently no tests for route overlap handling, effective route validation, DC discovery, timing summaries, or report rendering of the new requested sections.

## Known Risks In Larger Networks

- The current scope logic can miss VPN-routed networks or accept overlapping routes without checking the effective egress path.
- Long-running discovery or deep scans can still monopolize the run if a subnet is slow.
- Nuclei and NXC are bounded, but their results are not yet summarized as partial or timed-out per phase in the report.
- Domain controllers are not currently discovered as a first-class target class.
- The report does not yet include the requested one-page management summary or per-host card layout.

