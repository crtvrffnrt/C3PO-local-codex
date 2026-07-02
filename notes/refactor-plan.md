# C3PO Local Scanner Refactor Plan

## What Exists Today

- `run.sh` delegates to `bin/run.sh`, which invokes `pipeline/local_scanner.py`.
- `pipeline/local_scanner.py` already validates a selected interface, derives local scope, discovers hosts, runs Nmap/Nuclei, ranks hosts, and renders HTML.
- The current local scanner still contains Docker metadata discovery and writes reports under `reports/<timestamp>/`.
- Legacy external scanner files remain: Shodan adapters, domain collection scripts, old workflow `AGENTS.md`/`SKILL.md` files, Docker packaging, and Shodan-oriented config/install validation.
- Codex is not currently invoked by the scanner. Local `codex exec --help` supports `--model`, but this installed CLI does not expose a dedicated reasoning-effort flag.

## What Will Be Removed

- Active Docker target/lab generation and Docker metadata host discovery from the scanner flow.
- Docker compose packaging and Docker-focused usage instructions unless required solely for packaging. This refactor removes the Docker runtime path.
- Shodan modules, Shodan API key checks, Shodan config, Shodan report sections, and external domain attack-surface scripts from the default scanner path.
- Old workflow instruction files that describe Shodan, public web reconnaissance, external attack-surface collection, or extra agent/skill dependencies.

## What Will Be Replaced

- `reports/<timestamp>/` becomes `runs/YYYYmmdd-HHMMSS/` for the primary run directory.
- Ad hoc command recording becomes structured command/event/findings artifacts.
- Quick Nmap top-port scanning becomes a bounded explicit port scan of live hosts only.
- Deep Nmap scanning becomes per-host, top-10-only, version-oriented safe scanning with per-host timeouts.
- Deterministic host scoring is kept, with an added Codex interpretation pass where available. If Codex is unavailable or a selected model fails, the deterministic ranking remains the safe fallback and the failure is recorded.
- Shodan-derived scoring is replaced by local evidence from interface scope, neighbor/ARP/Nmap discovery, Nuclei, NXC, and local protocol observations.

## New Local Scan Flow

1. Operator runs `./run.sh -i wlan0`.
2. `bin/run.sh` validates `python3`, displays the authorization banner, requires acknowledgement, and prompts for a Codex model/reasoning profile.
3. The scanner creates `runs/YYYYmmdd-HHMMSS/` and captures tool versions.
4. Scope is derived from `ip addr show dev wlan0` and `ip route show dev wlan0`, then normalized into `scope.json` and `scope.txt`.
5. Unsafe routes and addresses are excluded by default: public internet, default routes, loopback, link-local active scans, multicast, broadcast, documentation ranges, Docker/bridge-style unrelated interfaces, and overly broad routes.
6. Host discovery uses neighbor/ARP data, gateway candidates, optional `arp-scan`, and bounded `nmap -sn`.
7. Fast Nmap scans only discovered live hosts using an explicit local infrastructure port set with bounded retries and host timeouts.
8. `192.168.100.1` is force-prioritized as a router/gateway/FritzBox candidate if reachable or discovered.
9. Codex is asked to interpret structured discovery evidence and select up to 10 hosts. The deterministic ranker validates and bounds this selection.
10. Deep Nmap, Nuclei, screenshots, and NXC run only against selected top hosts.
11. Nuclei runs only against relevant HTTP/HTTPS services with safe tags and excluded intrusive tags.
12. NXC runs only for protocols mapped from observed ports/services, with no-auth recon defaults and safety gates.
13. Final structured data and a standalone HTML report are written under the run directory. `reports/<timestamp>/report.html` may be created only as a compatibility copy/symlink if needed.

## `wlan0` Testing

- Run `./run.sh -i wlan0`.
- Confirm the authorization prompt appears and blocks scanning until acknowledged.
- Confirm selected Codex profile is recorded.
- Confirm `scope.json`, `scope.txt`, `live-hosts.txt`, `live-hosts.json`, Nmap artifacts, top-host files, NXC artifacts, and `report.html` are written under `runs/<id>/`.
- Confirm Docker commands are not executed and Shodan is not referenced or called.
- Confirm deep scan, Nuclei, and NXC only use `top-hosts.json`/observed service maps.

## `192.168.100.1` Prioritization

- If `192.168.100.1` appears in the interface scope and is discovered through gateway, neighbor, ping, ARP, or Nmap discovery, assign a high gateway/router/FritzBox ranking reason.
- If it is in scope but not reachable, record the router prioritization status as `unreachable_or_not_discovered` and do not force deep scans against it.
- If it is reachable, ensure it appears in `top-hosts.json` unless more than 10 safety-critical hosts outrank it; in normal home networks it should be selected.

## Remaining Risks or Blockers

- Codex model names are accepted by the local CLI through `--model`, but model availability is account/config dependent. The scanner records failures and continues with deterministic ranking.
- This Codex CLI build has no documented reasoning-effort flag, so the selected reasoning level is stored and included in prompts rather than passed as an unsupported option.
- Live network results depend on local privileges, host firewalls, Wi-Fi client isolation, and installed optional tools.
- NXC output formats vary. The wrapper parses defensively and always writes valid JSON/JSONL with parse-failure events when needed.
