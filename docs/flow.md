# C3PO Local Scanner Flow

1. Operator runs `./run.sh -i wlan0`.
2. `bin/run.sh` displays the authorization banner and requires acknowledgement unless `--authorized` is supplied.
3. The wrapper loads `codex debug models` once, offers separate model and model-specific effort menus, and passes the selected values to the scanner. Missing or broken catalogs use deterministic prioritization.
4. `pipeline/local_scanner.py` creates `runs/YYYYmmdd-HHMMSS/`.
5. The scanner captures tool versions and derives safe local scope from the selected interface.
6. The scanner writes `scope.json` and `scope.txt`.
7. Host discovery uses neighbor cache, gateways, ARP cache, optional `arp-scan`, and optional bounded `nmap -sn`.
8. Live hosts are written to `live-hosts.txt` and `live-hosts.json`.
9. Fast Nmap scans live hosts only using an explicit bounded port set and timeout controls.
10. `service-map.json` is written from parsed Nmap output.
11. The deterministic scorer ranks hosts. Reachable `192.168.100.1` receives router/FritzBox priority.
12. Codex receives structured host evidence and may select up to 10 top hosts. If Codex fails, deterministic ranking is used.
13. Deep Nmap runs only on `top-hosts.json` hosts.
14. Nuclei runs only on top-host HTTP/HTTPS URLs.
15. NXC runs only on top-host protocols mapped from observed ports/services.
16. The scanner writes `scan-data.json`, NXC structured artifacts, and `report.html`.

Dry-run mode:

```bash
./run.sh -i wlan0 --authorized --dry-run
```

Dry-run validates scope and writes report artifacts without active Nmap/Nuclei/NXC scans.
