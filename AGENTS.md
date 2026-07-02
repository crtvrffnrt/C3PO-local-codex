# C3PO Local Scanner Production Instructions

Designation: `C3PO-local-edge`

Role: authorized internal attack-surface assessment assistant for this repository.

Mission: run a safe, reproducible, interface-scoped local network assessment that finds meaningful internal exposure, prioritizes the most relevant systems, performs bounded follow-up only where evidence supports it, and produces an operator-ready HTML report with raw artifacts beside it.

Primary entrypoint:

```bash
./run.sh -i <interface>
```

The optional `--cidr` flag may only narrow scope to a private network that is already proven to route through the selected interface.

## Production Priorities

1. Keep the run safe: no public internet scanning, brute force, password spraying, credential dumping, exploit execution, destructive checks, coercion, command execution, or state-changing tests.
2. Keep the run scoped: derive candidate networks from the selected interface, validate effective routes with `ip route get`, and scan only validated private IPv4 scope.
3. Keep the run useful: prioritize hosts with real evidence such as identity ports, management exposure, databases, storage protocols, web surfaces, NXC banners, Nuclei findings, and confirmed hostnames.
4. Keep the run bounded: broad discovery must be fast and shallow; expensive service detection, Nuclei, screenshots, UDP, NXC, and NSE follow-up stay limited to the selected top 10 hosts.
5. Keep the run reproducible: write every command, timeout, stdout/stderr path, parsed artifact, selected target list, scope decision, and report input beside the report.

## Scope Rules

Collect and persist:

```bash
ip -4 addr show dev "$iface"
ip -4 route show dev "$iface"
ip -4 route show table main
ip -4 rule show
ip -4 route get <representative-ip>
```

Exclude public internet ranges, default routes, loopback, multicast, broadcast, link-local, documentation ranges, Docker bridges, unrelated VPN routes, and routes whose effective device is not the selected interface.

If routes overlap, include only the network whose representative IP effectively routes through the selected interface. Report the competing route and selected effective route.

Persist at least:

```text
routes/
scope.json
scope.txt
commands.jsonl
tool-versions.json
live-hosts.json
service-map.json
top-hosts.json
scan-data.json
report.html
```

All persisted JSON must be JSON-serializable. Convert `IPv4Network`, `IPv4Address`, `Path`, sets, and dataclass-like objects to strings, lists, or dictionaries before writing.

## Scan Strategy

Use staged Nmap. Do not run expensive scans against every discovered host.

Required phases:

1. Route and scope validation.
2. Fast host discovery.
3. TCP discovery with `-Pn` after scope validation.
4. Fast service exposure scan for responsive/candidate hosts.
5. Deterministic top-host ranking, optionally refined by Codex.
6. Deep exact-port service scans for top 10 hosts only.
7. Nuclei only for confirmed HTTP/HTTPS URLs on top hosts.
8. NXC only for protocols with observed open ports on top hosts.
9. Report rendering from final, internally consistent artifacts.

Dynamic TCP discovery:

```text
>256 candidate IPs: top 100 ports plus critical internal ports, bounded rates and host timeouts.
11-256 candidate IPs: top 1000 or curated critical internal ports, bounded rates and host timeouts.
<=10 candidate IPs: all TCP ports may be used when runtime is acceptable.
```

Preferred broad TCP controls:

```bash
nmap -Pn -n --open --reason --min-rate 5000 --max-rate 7800 --max-retries 1 --host-timeout 5m -oA "$out_prefix" -iL "$targets"
```

Do not use `-sV`, `-sC`, vulnerability scripts, OS detection, traceroute, screenshots, or Nuclei during broad discovery.

Deep scan only exact open ports from earlier phases:

```bash
nmap -Pn -n -p "$open_ports" -sV --version-light --reason --script-timeout 20s --max-retries 2 --host-timeout 8m -oA "$out_prefix" "$ip"
```

If a phase times out, preserve partial output, mark the phase partial, reduce intensity once, and continue with degraded evidence.

## Top-Host Ranking

Top 10 selection must be evidence-based and stable.

Prioritize:

- Confirmed or high-confidence domain controllers and identity infrastructure.
- Routers, gateways, VPN, jump, and admin systems.
- DNS, DHCP, LDAP, Kerberos, SMB, WinRM, RDP, SSH, database, NAS, hypervisor, and web management exposure.
- Hosts with many high-impact open ports.
- Hosts with Nuclei or NXC findings.
- Hosts central to multiple observed protocols.

Do not promote hosts based on global evidence alone. For example, NXC evidence mentioning `domain:bhl.local` or LDAP somewhere in the run must not mark every host as a domain-controller candidate. NXC-derived role evidence must be host-scoped: the host IP or hostname must appear in the relevant NXC event or finding.

After enrichment phases, preserve consistency:

- Final `top-hosts.json`, `scan-data.json`, and `report.html` must describe the same top hosts.
- Hosts shown as deep-scanned must actually have corresponding deep scan artifacts.
- Domain-controller candidates must include concrete evidence and source artifact paths.
- Empty-service live hosts must not outrank hosts with identity, management, database, or web exposure.

## Codex Planning

Codex may refine top-host selection, but deterministic ranking must remain safe and useful without Codex.

When using Codex:

- Provide only validated in-scope hosts and observed evidence.
- Do not ask Codex to invent targets, roles, or vulnerabilities.
- Use a valid strict JSON schema. Every object schema with `properties` must include a `required` array for those properties when the output API requires it.
- If Codex fails, record stderr/stdout and use deterministic ranking without aborting the run.

## Nuclei Policy

Run Nuclei only against confirmed HTTP/HTTPS URLs from top 10 hosts.

Use safe tags and exclude brute force, fuzzing, DoS, intrusive, exploit, and destructive templates. Keep rate, concurrency, per-request timeout, and whole-phase timeout bounded.

If Nuclei times out:

- Preserve partial JSONL output.
- Mark the phase partial in performance artifacts.
- Include the target count and timeout in the report.
- Do not block report generation.

## NXC Policy

Run NXC only against validated in-scope top hosts and only for protocols with observed open ports.

Default behavior:

- No credentials.
- No brute force, spraying, dumping, file transfer, BloodHound collection, command execution, coercion, or exploit modules.
- Banner/connectivity/protocol checks only.
- Use `--no-progress`, `--log`, `--timeout`, and bounded threads.

Allowed protocol mapping:

```text
SMB:    445, 139
LDAP:   389, 636, 3268, 3269
WinRM:  5985, 5986
WMI:    135 plus Windows/SMB context
MSSQL:  1433 or detected MSSQL service
SSH:    22
FTP:    21
RDP:    3389
VNC:    5900-5909
NFS:    111, 2049
```

Parse NXC output into host-scoped events and findings. Never convert global text, module listings, help output, or summary text into host-specific findings unless the host IP or hostname appears in the event.

## Report Quality Gates

The report must show:

- Selected interface and validated scope.
- Excluded routes and overlap warnings.
- Target counts and scan profile.
- Nmap command records with timing and timeout status.
- Top 10 hosts with role, confidence, open ports, evidence, and ranking reason.
- Deep scan evidence only for hosts actually deep-scanned.
- Nuclei and NXC results with partial/timeout status when applicable.
- Confirmed findings, inferred risks, informational exposure, recommendations, assumptions, and limitations.
- A performance section showing slow phases and timeouts.

Before calling a run production-ready, verify:

```bash
python3 -m unittest tests/test_local_scanner.py
./run.sh -i <interface> --cidr <validated-private-cidr>
```

Then inspect:

```text
scope.json
commands.jsonl
performance/*.json
top-hosts.json
scan-data.json
report.html
```

Production failure conditions:

- The scanner crashes before writing a report.
- Final top hosts differ unexpectedly between `top-hosts.json`, `scan-data.json`, and `report.html`.
- NXC or Codex promotes hosts without host-specific evidence.
- Public or unrelated routes enter `scope.txt`.
- Deep/Nuclei/NXC phases run outside the top 10.
- A timeout hides partial output or prevents report generation.
