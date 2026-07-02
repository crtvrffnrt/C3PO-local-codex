# C3PO Local Scanner Flow

1. Operator runs `./run.sh -i <interface>` from the project root.
2. `bin/run.sh` validates that an interface was supplied and that `python3` is available.
3. `pipeline/local_scanner.py` reads local interface context:
   - `ip -j link show dev <interface>`
   - `ip -j addr show dev <interface>`
   - `ip route show dev <interface>`
   - `ip -6 route show dev <interface>`
   - `ip neigh show dev <interface>`
   - `resolvectl status` when available
4. The scanner derives local/internal candidate scope and rejects unsafe ranges:
   - public internet ranges
   - default routes
   - loopback
   - multicast
   - broadcast
   - documentation ranges
   - overly broad IPv4 routes
5. Host discovery combines:
   - neighbor table entries
   - gateway candidates
   - ARP cache
   - optional `arp-scan`
   - optional `nmap -sn`
   - reverse DNS
6. Quick scan runs against discovered hosts when `nmap` is installed:
   - `nmap -Pn -T3 --top-ports 100 --open`
7. The prioritization engine ranks hosts and records visible reasons.
8. Deep scan runs only against the top 10 hosts:
   - `nmap -Pn -sV -sC -T3 --open`
9. Optional Nuclei checks run only against top-10 local web URLs with safe allowlisted tags.
10. Optional browser screenshots capture top-10 local HTTP/HTTPS services.
11. The scanner writes `reports/<timestamp>/report.html` plus raw artifacts.

Use `./run.sh -i <interface> --dry-run` to validate interface scope and render a report without active scans.
