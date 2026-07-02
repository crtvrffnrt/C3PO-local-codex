# C3PO Local Attack Surface Scanner

Professional local-network attack-surface scanner for authorized internal security assessments.

The tool discovers local/internal hosts through a selected Linux network interface, performs a bounded quick scan, prioritizes the top 10 most relevant or risky hosts, runs deeper safe enumeration only on those hosts, and generates a single HTML report.

## Authorization

Use this only on networks where you have explicit authorization. The scanner is intentionally scoped to local/internal ranges reachable through the selected interface and avoids public internet scanning, exploit execution, brute force, denial-of-service checks, and state-changing tests.

## Usage

The interface argument is mandatory:

```bash
./run.sh -i eth0
./run.sh -i wlan0
```

Useful validation mode:

```bash
./run.sh -i eth0 --dry-run
```

`--dry-run` validates the interface and detected local scope, then renders a scope report without active nmap scans.

## Docker

Build and run the scanner in a container with host networking so it can read the selected interface:

```bash
docker build -t c3po-local .
docker run --rm --network host --privileged -v "$PWD:/app" c3po-local -i wlan0 --dry-run
```

For Compose:

```bash
docker compose run --rm c3po-local -i wlan0 --dry-run
```

## Dependencies

Required:

- Linux with `ip`
- `bash`
- `python3` 3.10+

Optional but recommended:

- `nmap` for host discovery, quick scans, and deep safe service enumeration
- `arp` and `arp-scan` for passive and ARP-based discovery
- `nuclei` for safe local web exposure, panel, technology, TLS, and misconfiguration checks
- Chromium, Google Chrome, or Microsoft Edge for optional local screenshots
- `resolvectl` for resolver context

The scanner does not require Shodan, Cloudflare, public DNS APIs, API keys, or target ranges supplied by the user.

## Scan Phases

1. **Interface and scope discovery**
   Reads `ip addr show dev <interface>`, `ip route show dev <interface>`, `ip -6 route show dev <interface>`, `ip neigh show dev <interface>`, and `resolvectl status` when available.

2. **Safety filtering**
   Keeps only private, link-local, ULA, or directly connected internal scope. Default routes, public ranges, loopback, multicast, broadcast, documentation ranges, and overly broad routes are skipped.

3. **Host discovery**
   Combines neighbor table entries, ARP cache data, gateways, optional `arp-scan`, reverse DNS, and bounded `nmap -sn` discovery.

4. **Quick scan**
   Runs a safe top-port scan against discovered hosts when `nmap` is available:

   ```bash
   nmap -Pn -T3 --top-ports 100 --open
   ```

5. **Prioritization**
   Scores hosts deterministically using role and exposure indicators such as gateways, DNS, Kerberos, LDAP, SMB, RDP, WinRM, SSH, SNMP, web admin ports, databases, virtualization ports, storage ports, vendor hints, and number of open services.

6. **Deep scan of top 10 only**
   Runs safe nmap service/version and default scripts only on the top 10 prioritized hosts:

   ```bash
   nmap -Pn -sV -sC -T3 --open
   ```

7. **Safe Nuclei checks**
   If installed, runs only safe local web checks with allowlisted tags:

   ```bash
   nuclei -tags exposure,misconfig,panel,tech,ssl,tls,http \
     -severity info,low,medium,high \
     -exclude-tags bruteforce,fuzz,dos,intrusive,exploit
   ```

8. **Optional screenshots**
   Captures unauthenticated HTTP/HTTPS page loads for top-10 web services only when a local headless browser is available.

9. **HTML report**
   Writes one primary report to:

   ```text
   reports/<timestamp>/report.html
   ```

## Report Contents

The HTML report includes:

- Executive summary
- Scan metadata and selected interface
- Detected local scope
- Safety and scope notes
- Discovery summary
- Total live hosts and services
- Top 10 prioritized hosts
- Transparent ranking rationale
- Detailed technical host inventory
- Optional screenshots
- Findings and exposure records
- Evidence, confidence, assumptions, and limitations
- Safe manual verification commands
- Remediation recommendations
- Raw artifact references and recorded scan commands

The report avoids unverified vulnerability claims. Open ports are treated as exposure unless version, script, or Nuclei evidence supports a stronger conclusion.

## Safety Model

The scanner:

- Requires `./run.sh -i <interface>`
- Derives scope from the selected interface; users do not provide CIDRs
- Refuses interfaces without safe local/internal scope
- Does not scan `0.0.0.0/0`, `::/0`, public internet ranges, loopback, multicast, broadcast, or documentation ranges
- Avoids uncontrolled broad active scans
- Limits deeper enumeration to the top 10 hosts
- Avoids brute force, credential attacks, exploit execution, destructive checks, denial-of-service tests, and state-changing tests

## Output Files

Each run creates a timestamped directory:

```text
reports/YYYY-MM-DD_HHMMSS/
```

Common artifacts:

- `report.html` - primary self-contained report
- `scan_data.json` - structured internal data for audit/debugging
- `nmap_discovery.xml`
- `nmap_quick.xml`
- `nmap_deep_<host>.xml`
- `nuclei_safe.jsonl`
- `screenshots/*.png`
- `*_command.txt` files with reproducibility commands

Some artifacts are present only when the relevant optional tool is installed and the phase runs.

## Troubleshooting

Invalid interface:

```text
[!] Interface does not exist or cannot be read: eth9
```

No safe local scope:

```text
[!] Interface eth0 has no safe local/internal scope to scan.
```

Limited results:

- Run with sufficient local privileges if ARP discovery is important.
- Install `nmap` for active host discovery and service enumeration.
- Host firewalls and network segmentation can hide live systems from unauthenticated scans.

## Limitations

This is an unauthenticated local-network assessment. It cannot prove that hosts are secure, cannot inspect configuration that requires credentials, and may miss systems that block ARP/ICMP/TCP probes. Treat findings as evidence-backed leads for manual verification and remediation planning.
