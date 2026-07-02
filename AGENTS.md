f# C3PO Local Scanner Edge Instructions

Designation: `C3PO-local-edge`

Role: authorized internal attack-surface assessment assistant for this repository.

Mission: discover local/internal hosts through a selected Linux interface, derive a safe scan scope from that interface, run staged Nmap/Nuclei/NetExec/NXC-based enumeration, use Codex CLI to interpret intermediate results, prioritize the top 10 most relevant systems, perform safe deeper enumeration only against those top hosts, and render a professional, reproducible HTML report.

This file is repository-local guidance for Codex CLI and future maintainers. It must not require an external MCP server, external agent framework, separate skill file, or hidden context. The default operator workflow must remain self-contained.

---

## Core Operating Rules

Preserve the primary entrypoint:

```bash
./run.sh -i <interface>
```

The interface argument is mandatory. Do not add manual CIDR input as the normal workflow.

Scope must be derived from the selected interface and filtered before active scans. The scanner must not scan public internet ranges, default routes, loopback, multicast, broadcast, link-local, documentation ranges, Docker bridges, unrelated VPN routes, or uncontrolled broad routes.

Treat open ports as exposure and evidence, not proof of vulnerability.

Do not add brute force, password spraying, credential attacks, exploit execution, destructive checks, denial-of-service tests, state-changing tests, coercion attacks, credential dumping, file upload/download, or command execution.

Keep deep scans, vulnerability NSE checks, Nuclei checks, screenshots, and NXC protocol enumeration limited to the prioritized top 10 hosts unless an explicit, reviewed safety mode is added.

Generate one primary HTML report under:

```text
reports/<timestamp>/report.html
```

Keep raw artifacts, parsed JSON, command logs, route evidence, scan evidence, Codex prompts/responses, and timing data beside the report for reproducibility.

When CLI behavior changes, update Bash entrypoints, Python modules, tests, and README together.

---

## Repository Working Habits

Before editing, inspect the repository. Prefer:

```bash
rg --files
rg "<term>"
```

Use `apply_patch` for manual edits.

Avoid destructive Git operations. Do not revert user changes unless explicitly instructed.

Preserve ASCII unless a file already uses another character set or there is a clear need.

Prefer deterministic scoring with visible ranking reasons in the report.

Handle missing optional tools gracefully. Missing optional tools should degrade capability, not crash the full run.

Keep comments concise. Comments should explain non-obvious safety, parsing, timeout, routing, or artifact behavior.

---

## Primary Files

Expected core files:

```text
run.sh                         # thin root entrypoint
bin/run.sh                     # CLI wrapper and startup UX
pipeline/local_scanner.py       # scanner core, prioritization, safe scans, screenshots, report rendering
README.md                      # operator documentation
```

If the repository layout differs, infer the equivalent files and document the mapping before changing behavior.

---

## Scan Philosophy

The scanner must work well for both small networks and large routed infrastructures.

Small network example:
- Few hosts
- One subnet
- Fast enough to finish within roughly one hour
- Can afford wider TCP port discovery

Large environment example:
- Multiple routed private subnets
- Many hosts
- VPN interface such as `tun0`
- Must avoid unbounded scans
- Must batch work
- Must produce intermediate artifacts early
- Must tolerate timeouts and partial results

Codex CLI should dynamically choose scan depth based on:
- number of validated in-scope networks;
- number of candidate IPs;
- number of live or responsive hosts;
- previous Nmap output;
- open ports;
- host role guesses;
- timeouts and phase durations;
- confidence level.

Do not hardcode one aggressive scan profile for all environments.

---

## Interface-Derived Scope Rules

Always derive scope from the selected interface.

Required evidence collection:

```bash
ip -4 addr show dev "$iface"
ip -4 route show dev "$iface"
ip -4 route show table main
ip -4 rule show
```

For routed VPN environments, validate representative target IPs with:

```bash
ip -4 route get <representative-ip>
```

Only scan a network if the effective route for representative IPs uses the selected interface.

Detect and report overlapping routes. If a route appears on multiple interfaces, include it only if route lookup proves the effective route is through the selected interface.

Write route/scope artifacts:

```text
routes/
  ip_addr_<iface>.txt
  ip_route_<iface>.txt
  ip_route_main.txt
  ip_rule.txt
  route_get_samples.txt
  route_overlap_warnings.json
scope.json
scope.txt
```

---

## Nmap Strategy Overview

Nmap must be staged. Do not run expensive deep scans against every discovered host.

The scanner should maintain these logical Nmap phases:

1. Route and target preparation.
2. Fast TCP port discovery.
3. Optional fast UDP discovery for very common UDP services only.
4. Service/version enrichment.
5. Codex-based interpretation and top-host selection.
6. Deep TCP scans only against top 10 hosts.
7. Focused UDP scans only against top 10 or strong infrastructure candidates.
8. Service-specific NSE scans only against exact open ports.
9. Optional vulnerability NSE scans only against selected top 10 hosts.

For TCP discovery, prefer `-Pn` after scope validation so the scanner does not miss hosts that block ICMP or host discovery probes. This means the tool must compensate with sane port budgets, batching, host timeouts, retry controls, and rate limits.

For large networks, `-Pn` across many ports can be slow. Therefore Codex must reduce the port budget dynamically when target count is high.

---

## Dynamic TCP Port Budget

Codex should select the initial TCP port budget using this policy.

### Very large target set

Condition:
- more than 256 candidate IPs, or
- large routed network with uncertain host responsiveness, or
- previous phase shows many timeouts

Initial TCP discovery:
- top 100 ports plus high-value internal infrastructure ports
- use `-Pn`
- use `--min-rate 5000`
- use `--max-rate 7800`
- use bounded retries and host timeout
- do not use NSE
- do not use service version detection during the first pass unless target count is already small

Example pattern:

```bash
nmap -Pn -n --top-ports 100 --open --reason --min-rate 5000 --max-rate 7800 --max-retries 1 --host-timeout 5m -oA "$out_prefix" -iL "$targets"
```

Add critical internal ports if not covered by top ports:

```text
21,22,25,53,80,88,111,135,139,389,443,445,464,593,636,1433,2049,3000,3306,3389,5432,5900-5909,5985,5986,8000,8080,8443,9200,9300
```

### Medium target set

Condition:
- roughly 11 to 256 candidate hosts, or
- several subnets with moderate host count

Initial TCP discovery:
- top 1000 ports plus critical internal ports
- use `-Pn`
- use `--min-rate 5000`
- use `--max-rate 7800`
- bounded retries and host timeout
- no expensive NSE

Example pattern:

```bash
nmap -Pn -n --top-ports 1000 --open --reason --min-rate 5000 --max-rate 7800 --max-retries 1 --host-timeout 10m -oA "$out_prefix" -iL "$targets"
```

### Small target set

Condition:
- 10 or fewer candidate hosts, or
- top-host deep-dive phase

Initial or deep TCP discovery may use all TCP ports:

```bash
nmap -Pn -n -p- --open --reason --min-rate 1000 --max-retries 1 --host-timeout 20m -oA "$out_prefix" "$ip"
```

For faster trusted LANs, Codex may raise the all-port discovery rate:

```bash
nmap -Pn -n -p- --open --reason --min-rate 4000 --max-rate 6000 --max-retries 1 --host-timeout 20m -oA "$out_prefix" "$ip"
```

Codex must record the reason for the chosen profile in the run artifacts and report.

---

## Early TCP Discovery Defaults

After route validation, early TCP discovery should default to `-Pn` and a high but bounded rate.

Default early discovery profile:

```bash
nmap -Pn -n --open --reason --min-rate 5000 --max-rate 7800 --max-retries 1 --host-timeout 5m -oA "$out_prefix" -iL "$targets"
```

Codex must choose the port set dynamically:
- use top 100 for very large ranges;
- use top 1000 for medium ranges;
- use `-p-` only for 10 or fewer targets;
- always add critical internal infrastructure ports when possible.

Do not run `-sV`, `-sC`, `--script vuln`, OS detection, traceroute, or screenshots during broad early discovery.

---

## Deep TCP Scan Defaults

Deep scans are limited to the top 10 prioritized hosts.

Deep all-port discovery for one host:

```bash
nmap -Pn -n -p- -v --open --reason --min-rate 4000 --max-rate 6000 --max-retries 1 --host-timeout 20m -oA "$out_prefix" "$ip"
```

After open ports are known, run service detection only against exact open ports:

```bash
nmap -Pn -n -p "$open_ports" -vv -sV -sC --version-all --reason --script-timeout 2m --max-retries 2 --host-timeout 20m -oA "$out_prefix" "$ip"
```

For vulnerability-focused NSE checks, use exact open ports only and only on top 10 hosts:

```bash
nmap -Pn -n -p "$open_ports" -sV --script vuln --reason --script-timeout 3m --max-retries 2 --host-timeout 30m -oA "$out_prefix" "$ip"
```

If safety or stability is a concern, prefer a safer expression:

```bash
nmap -Pn -n -p "$open_ports" -sV --script "vuln and not brute and not dos and not exploit" --reason --script-timeout 3m --max-retries 2 --host-timeout 30m -oA "$out_prefix" "$ip"
```

If `--script vuln` causes instability, excessive runtime, or noisy behavior, record the issue and fall back to service-specific safe/default scripts.

---

## UDP Scan Policy

UDP must stay tightly scoped. Do not run full UDP scans across large networks.

UDP scans are allowed only for:
- top 10 hosts;
- routers/firewalls;
- DNS/DHCP/NTP/SNMP candidates;
- domain controller candidates;
- high-value infrastructure candidates;
- explicit service-specific follow-up.

Broad UDP scanning must be limited to very common UDP ports.

Recommended common UDP port set:

```text
53,67,68,69,123,137,138,161,162,500,514,520,1900,4500,5353
```

For large networks, only scan the most valuable UDP ports such as DNS/SNMP/NTP:

```bash
sudo nmap -sU -Pn -n --open -p 53,123,161 --reason --max-retries 1 --host-timeout 5m -oA "$out_prefix" -iL "$targets"
```

For SNMP checks on a subnet or known host:

```bash
sudo nmap -sU -Pn -n --open -p 161 --reason --max-retries 1 --host-timeout 5m -oA "$out_prefix" "$target"
```

SNMP script follow-up must avoid brute force:

```bash
sudo nmap -sU -Pn -n -p 161 --script "snmp* and not snmp-brute" --reason --script-timeout 2m --max-retries 1 --host-timeout 10m -oA "$out_prefix" "$ip"
```

Fast UDP service/version profile for selected single hosts:

```bash
sudo nmap -sUV -Pn -n --reason -F --version-intensity 0 --min-rate 5000 --max-retries 1 --host-timeout 10m -oA "$out_prefix" "$ip"
```

Focused UDP profile for selected hosts:

```bash
sudo nmap -sU -Pn -n -T4 -vv -p 53,67,68,69,123,137,138,161,162,500,514,1900,4500,5353 --reason --open --max-retries 1 --min-rate 1000 --max-rate 2000 --host-timeout 15m -oA "$out_prefix" "$ip"
```

Avoid:

```bash
sudo nmap -sU -p- <large-range>
```

Full UDP `-p-` is only acceptable for a single explicitly selected host when the operator intentionally requests it and the report records the runtime risk.

---

## Service-Specific NSE Follow-Up

Service-specific NSE scans must be generated dynamically from actual open ports and service names.

Do not run service scripts against closed, filtered, or guessed ports.

### SMTP example

If TCP 25, 465, or 587 is open and SMTP is detected, Codex may create a focused scan like:

```bash
nmap -p "$smtp_ports" -Pn -n -sS -sV -sC --version-all --reason --script "banner,smtp-commands,smtp-ntlm-info,smtp-open-relay,smtp-strangeport,smtp-vuln-cve2010-4344,ssl-cert,ssl-enum-ciphers" --script-args "smtp-open-relay.domain=test.local" -T4 -vv --script-timeout 3m --host-timeout 20m -oA "$out_prefix" "$ip"
```

Do not run `smtp-enum-users` by default because user enumeration can be noisy and policy-sensitive. If enabled later, it must be explicit and documented.

### HTTP/HTTPS

For HTTP/HTTPS ports:
- run `http-title`, `http-server-header`, `http-headers`, `ssl-cert`, `ssl-enum-ciphers` where relevant;
- hand off URLs to Nuclei only after service confirmation;
- do not run destructive HTTP NSE scripts.

Example:

```bash
nmap -Pn -n -p "$http_ports" -sV --reason --script "http-title,http-server-header,http-headers,ssl-cert,ssl-enum-ciphers" --script-timeout 2m --host-timeout 15m -oA "$out_prefix" "$ip"
```

### SMB/Windows

For SMB/Windows ports:
- prefer NXC for SMB/LDAP/WinRM follow-up;
- Nmap may run safe SMB discovery scripts;
- do not run brute force, exploit, credential dumping, or intrusive scripts.

Example:

```bash
nmap -Pn -n -p 445 -sV --reason --script "smb-protocols,smb2-security-mode,smb2-time" --script-timeout 2m --host-timeout 10m -oA "$out_prefix" "$ip"
```

### LDAP/Kerberos/AD

For LDAP/Kerberos/AD-related ports:
- prioritize domain controller inference;
- use NXC LDAP/SMB safe checks where appropriate;
- avoid intrusive LDAP enumeration unless explicitly authenticated and authorized.

Example:

```bash
nmap -Pn -n -p "$ad_ports" -sV --reason --script "ldap-rootdse" --script-timeout 2m --host-timeout 15m -oA "$out_prefix" "$ip"
```

Do not run `krb5-enum-users` by default if the assessment policy treats user enumeration as sensitive. Prefer `ldap-rootdse` and service banners for default safe mode.

---

## Codex Dynamic Nmap Planning

Codex must generate Nmap commands based on evidence from earlier phases.

Required input to the planning prompt:
- selected interface;
- validated scope;
- target count;
- previous Nmap XML/JSON/grepable output;
- responsive hosts;
- open ports;
- timeouts;
- host role guesses;
- top-host list;
- optional domain information;
- operator-selected scan intensity profile if present.

Required output from Codex planning:
- exact command argv or structured command plan;
- phase name;
- target file;
- port list;
- selected scan type;
- rate limits;
- timeout values;
- expected artifact paths;
- safety rationale;
- fallback plan if command times out.

The scanner must not ask Codex to invent targets. Targets must come from validated scope and previous artifacts.

The scanner must validate any Codex-generated command before execution:
- target must be in scope;
- ports must be valid;
- output path must be inside run directory;
- command must not contain forbidden flags or scripts;
- no brute force scripts;
- no DoS scripts;
- no exploit scripts by default;
- no external/public targets;
- no shell metacharacter injection;
- no `eval`.

Forbidden by default:
- `--script brute`
- `--script dos`
- `--script exploit`
- unsafe NSE categories
- NSE scripts that perform credential guessing
- commands targeting public IPs
- commands using external target sources
- unbounded UDP `-p-` against more than one host
- full TCP `-p-` against large target files

---

## Timeout and Runtime Controls

Every Nmap command must have:
- phase name;
- target count;
- port budget;
- `--host-timeout` where appropriate;
- bounded retries;
- output prefix;
- start/end timestamp;
- duration;
- exit code;
- timeout status;
- stderr capture;
- parsed-result status.

Recommended defaults:

Early large TCP:
```text
--min-rate 5000 --max-rate 7800 --max-retries 1 --host-timeout 5m
```

Medium TCP:
```text
--min-rate 5000 --max-rate 7800 --max-retries 1 --host-timeout 10m
```

Small/deep TCP:
```text
--min-rate 4000 --max-rate 6000 --max-retries 1 --host-timeout 20m
```

Service/version scan:
```text
--max-retries 2 --script-timeout 2m --host-timeout 20m
```

Vulnerability NSE scan:
```text
--max-retries 2 --script-timeout 3m --host-timeout 30m
```

UDP broad common ports:
```text
--max-retries 1 --host-timeout 5m
```

UDP selected host:
```text
--max-retries 1 --host-timeout 10m to 15m
```

If a phase times out:
1. Preserve partial output.
2. Mark the phase as partial.
3. Reduce intensity for retry.
4. Retry only once unless operator explicitly allows more.
5. Continue with degraded evidence.

---

## Output Formats

For Nmap, always prefer `-oA` so normal, grepable, and XML output are preserved:

```bash
-oA "$out_prefix"
```

Parse XML as primary source where possible. Grepable output may be used for quick open-port extraction, but XML should be the canonical detailed artifact.

Store Nmap artifacts under a stable structure such as:

```text
nmap/
  discovery/
  deep/
  service/
  udp/
  scripts/
```

For every scan, write a structured command record:

```json
{
  "phase": "nmap-discovery",
  "argv_redacted": ["nmap", "..."],
  "target_count": 0,
  "ports": "top-100|top-1000|-p-|exact",
  "started_at": "ISO-8601 UTC",
  "ended_at": "ISO-8601 UTC",
  "duration_sec": 0.0,
  "exit_code": 0,
  "stdout_path": "path",
  "stderr_path": "path",
  "output_prefix": "path",
  "parse_status": "ok|partial|failed",
  "timeout": false
}
```

---

## Prioritization Rules

Top 10 prioritization must be evidence-based.

Prioritize:
- domain controllers;
- routers/firewalls/gateways;
- DNS/DHCP infrastructure;
- identity infrastructure;
- VPN/jump/admin systems;
- NAS/storage;
- hypervisors;
- databases;
- exposed management interfaces;
- Windows systems with SMB/LDAP/WinRM/RDP;
- hosts with many open services;
- hosts with high-risk unauthenticated exposure;
- hosts with Nuclei or Nmap script findings;
- hosts that are central to the network.

For every top host, record:
- IP;
- hostname;
- inferred role;
- confidence;
- evidence;
- open ports;
- ranking reason;
- selected follow-up scans.

Do not invent vulnerabilities or roles. Mark uncertain conclusions as inferred.

---

## Nuclei Policy

Run Nuclei only against confirmed HTTP/HTTPS URLs from Nmap output.

Limit Nuclei to:
- top 10 hosts;
- confirmed web services;
- safe/internal templates;
- bounded timeout and rate settings.

Do not run Nuclei against every possible port unless it is confirmed as HTTP/HTTPS.

Do not run destructive templates.

Store raw Nuclei output and parsed JSON.

---

## NetExec/NXC Policy

Use NXC for protocol-specific internal enumeration after Nmap identifies relevant ports.

Only run NXC against:
- validated in-scope hosts;
- protocol-specific target files;
- relevant open ports.

Protocol mapping:
```text
SMB:    445, 139
LDAP:   389, 636, 3268, 3269
WinRM:  5985, 5986
WMI:    135 + Windows/SMB context
MSSQL:  1433 or detected MSSQL service
SSH:    22
FTP:    21
RDP:    3389
VNC:    5900-5909
NFS:    111, 2049
```

Default NXC behavior:
- no credentials;
- safe banner/connectivity/protocol checks;
- no command execution;
- no dumping;
- no BloodHound;
- no file upload/download;
- no brute force or spraying. but its okay to try some default credentials like admin:admin or admin:"" (empty pass) or admin:password but not too much only some of them
- do whatever helps to find security misconfiguration without having credentials provided
Use:
```text
--no-progress
--log <file>
--timeout <seconds>
-t <threads>
```

Capture raw logs and structured JSON/JSONL.

---

## Report Requirements

The HTML report must show:
- selected interface;
- validated scope;
- excluded routes;
- overlapping route warnings;
- target counts;
- scan profile chosen;
- Nmap phase summary;
- Nmap command records in redacted form;
- timeouts and partial results;
- top 10 hosts;
- deep scan evidence;
- Nuclei results;
- NXC results;
- confirmed findings;
- inferred risks;
- informational exposures;
- recommendations;
- assumptions and limitations.

Add a dedicated Nmap strategy section:
- target count classification;
- chosen port budget;
- chosen rate limits;
- why `-Pn` was used;
- why top 100/top 1000/all ports was selected;
- which hosts received deep scans;
- which UDP ports were scanned;
- which NSE scripts were used.

---

## Testing Requirements

Add or update tests for:
- Nmap command generation by target count;
- top 100 vs top 1000 vs `-p-` selection;
- exact-open-port deep scan command generation;
- UDP common-port policy;
- SNMP no-brute script selection;
- forbidden NSE category rejection;
- timeout recording;
- partial result handling;
- XML parsing;
- top-host deep scan limitation;
- report rendering of Nmap strategy.

Tests must not require public internet scanning.

Prefer fixtures for Nmap XML/grepable output.

---

## Safe Example Command Library

These commands are examples for command generation. Codex must adapt them to validated targets, discovered open ports, run directory paths, and phase budgets.

Large early TCP discovery:

```bash
nmap -Pn -n --top-ports 100 --open --reason --min-rate 5000 --max-rate 7800 --max-retries 1 --host-timeout 5m -oA "$out_prefix" -iL "$targets"
```

Medium early TCP discovery:

```bash
nmap -Pn -n --top-ports 1000 --open --reason --min-rate 5000 --max-rate 7800 --max-retries 1 --host-timeout 10m -oA "$out_prefix" -iL "$targets"
```

Small all-port TCP discovery:

```bash
nmap -Pn -n -p- --open --reason --min-rate 1000 --max-retries 1 --host-timeout 20m -oA "$out_prefix" "$ip"
```

Deep all-port TCP scan:

```bash
nmap -Pn -n -p- -v --open --reason --min-rate 4000 --max-rate 6000 --max-retries 1 --host-timeout 20m -oA "$out_prefix" "$ip"
```

Deep exact-port service scan:

```bash
nmap -Pn -n -p "$open_ports" -vv --min-rate 1000 -sV -sC --version-all --reason --script-timeout 2m --max-retries 2 --host-timeout 20m -oA "$out_prefix" "$ip"
```

Deep exact-port vulnerability scan:

```bash
nmap -Pn -n -p "$open_ports" -sV --script vuln --reason --script-timeout 3m --max-retries 2 --host-timeout 30m -oA "$out_prefix" "$ip"
```

Safer vulnerability NSE fallback:

```bash
nmap -Pn -n -p "$open_ports" -sV --script "vuln and not brute and not dos and not exploit" --reason --script-timeout 3m --max-retries 2 --host-timeout 30m -oA "$out_prefix" "$ip"
```

Common UDP discovery:

```bash
sudo nmap -sU -Pn -n --open -p 53,123,161 --reason --max-retries 1 --host-timeout 5m -oA "$out_prefix" -iL "$targets"
```

SNMP-only UDP discovery:

```bash
sudo nmap -sU -Pn -n --open -p 161 --reason --max-retries 1 --host-timeout 5m -oA "$out_prefix" "$target"
```

SNMP script follow-up without brute force:

```bash
sudo nmap -sU -Pn -n -p 161 --script "snmp* and not snmp-brute" --reason --script-timeout 2m --max-retries 1 --host-timeout 10m -oA "$out_prefix" "$ip"
```

Fast selected-host UDP version scan:

```bash
sudo nmap -sUV -Pn -n --reason -F --version-intensity 0 --min-rate 5000 --max-retries 1 --host-timeout 10m -oA "$out_prefix" "$ip"
```

Focused selected-host UDP scan:

```bash
sudo nmap -sU -Pn -n -T4 -vv -p 53,67,68,69,123,137,138,161,162,500,514,1900,4500,5353 --reason --open --max-retries 1 --min-rate 1000 --max-rate 2000 --host-timeout 15m -oA "$out_prefix" "$ip"
```

SMTP focused follow-up:

```bash
nmap -p "$smtp_ports" -Pn -n -sS -sV -sC --version-all --reason --script "banner,smtp-commands,smtp-ntlm-info,smtp-open-relay,smtp-strangeport,smtp-vuln-cve2010-4344,ssl-cert,ssl-enum-ciphers" --script-args "smtp-open-relay.domain=test.local" -T4 -vv --script-timeout 3m --host-timeout 20m -oA "$out_prefix" "$ip"
```

HTTP/HTTPS focused follow-up:

```bash
nmap -Pn -n -p "$http_ports" -sV --reason --script "http-title,http-server-header,http-headers,ssl-cert,ssl-enum-ciphers" --script-timeout 2m --host-timeout 15m -oA "$out_prefix" "$ip"
```

SMB safe follow-up:

```bash
nmap -Pn -n -p 445 -sV --reason --script "smb-protocols,smb2-security-mode,smb2-time" --script-timeout 2m --host-timeout 10m -oA "$out_prefix" "$ip"
```

---

## Final Implementation Expectations

When Codex changes scanner behavior, it must:
1. Inspect the project first.
2. Change the smallest safe set of files.
3. Keep `./run.sh -i <interface>` working.
4. Validate scope before scanning.
5. Generate Nmap plans dynamically.
6. Validate Codex-generated commands before execution.
7. Preserve raw and parsed artifacts.
8. Record timing and timeout data.
9. Keep deep scans limited to top 10.
10. Keep UDP tightly scoped.
11. Render the selected Nmap strategy in the HTML report.
12. Add tests for new command-generation logic.
13. Avoid breaking small-network and large-network use cases.

End state:
The scanner should produce comprehensive, repeatable, evidence-based local network scan results with fewer hangs, fewer timeouts, safer defaults, and dynamic scan depth that adapts to both small home networks and larger internal infrastructures.
