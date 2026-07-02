# Open Source Readiness

## Files Sanitized

- `README.md`
- `AGENTS.md`
- `bin/run.sh`
- `docs/architecture.md`
- `docs/flow.md`
- `pipeline/local_scanner.py`
- `tests/test_local_scanner.py`
- `tests/fixtures/dns_srv_ldap.txt`
- `tests/fixtures/dns_srv_kerberos.txt`
- `tests/fixtures/nmap_dc.xml`
- `tests/fixtures/tun0_route_main.txt`
- `tests/fixtures/tun0_route_legacy.txt`
- `runs/20260702-143937/`

## Files Removed

- `.pytest_cache/`
- `pipeline/__pycache__/`
- `tests/__pycache__/`
- `tools/__pycache__/`
- `runs/20260702-133041/`
- `runs/20260702-141716/`
- `runs/20260702-142042/`

## Files Preserved

- Source code and tests.
- Sanitized example run bundle: `runs/20260702-143937/`.
- Runtime placeholders in `runtime/`.
- Documentation and prompts.

## Placeholders Introduced

- `example.local`
- `router.example.local`
- `dc01.example.local`
- `dc02.example.local`
- `srv-id01.example.local`
- `srv-legacy01.example.local`
- `client03.example.local`
- `client04.example.local`
- `client77.example.local`
- `client99.example.local`
- `10.20.30.0/24`
- `10.20.30.1`
- `10.20.30.2`
- `10.20.0.0/16`
- `192.168.100.0/24`
- `192.168.100.1`

## Searches Performed

- Recursive repository scans for internal domains, private ranges, hostnames, VPN/router names, usernames, and lab identifiers.
- Targeted searches for `example.internal`, `bhl.local`, `192.168.178`, `172.16.16`, and `10.81.0`.
- Verification of the preserved run bundle and test fixtures after replacement.

## Potential Remaining Manual Review Items

- Decide whether the preserved example run should remain tracked long-term or be moved to release assets.
- Review image assets manually if future screenshots or logos are added.
- Keep an eye on generated output directories if new artifact types are introduced.
