# tun0 Lab Test Plan

## Expected `tun0` Route Behavior

- The scanner must derive scope from the real Linux routing table and not from legacy `route -n` assumptions.
- For the lab VPN example, the effective routed scope should include:
  - `10.20.0.0/16` via `10.20.30.1` on `tun0`
  - `10.20.30.0/24` directly on `tun0`
  - `10.20.30.0/24` via `10.20.30.1` on `tun0`
  - `192.168.100.0/24` via `10.20.30.1` on `tun0`, but only if `ip route get` confirms the effective route really uses `tun0`
- The overlapping `192.168.100.0/24` local `eth1` route must be treated as a warning, not as an automatic inclusion.

## Expected Networks

- Primary VPN scope candidates:
  - `10.20.0.0/16`
  - `10.20.30.0/24`
  - `10.20.30.0/24`
  - `192.168.100.0/24` only after effective-route validation
- Exclusions:
  - default route via `eth1`
  - public internet ranges
  - loopback
  - link-local
  - multicast
  - broadcast
  - unrelated local interfaces
  - Docker bridges
  - any route not effectively using `tun0`

## Overlap Handling For `192.168.100.0/24`

- Parse the route table and note the competing `eth1` and `tun0` routes.
- Validate representative targets with `ip -4 route get 192.168.100.1`.
- Keep the network only if the kernel-selected route uses `tun0`.
- Record the overlap as a warning in the run artifacts and report regardless of inclusion outcome.

## Verifying Effective Route Selection

Use commands like:

```bash
ip -4 addr show dev tun0
ip -4 route show dev tun0
ip -4 route show table main
ip -4 rule show
ip -4 route get 10.1.0.1
ip -4 route get 10.81.0.1
ip -4 route get 10.20.30.1
ip -4 route get 192.168.100.1
```

- The scanner should persist these facts under `routes/`.
- If a candidate network is ambiguous, the kernel route lookup decides.

## `example.local` Domain Controller Discovery

- Hint DC IPs from the operator context are `10.20.30.10` and `10.20.30.11`.
- Discover DCs safely by combining:
  - DNS SRV queries for `_ldap._tcp.dc._msdcs.example.local`
  - DNS SRV queries for `_kerberos._tcp.example.local`
  - DNS A/AAAA resolution for returned hostnames
  - Nmap service evidence on `53`, `88`, `135`, `389`, `445`, `464`, `593`, `636`, `3268`, `3269`, `5985`
  - NXC SMB/LDAP no-auth recon evidence
  - reverse DNS hostnames and domain/workgroup hints
- Only include DC candidates that are inside validated `tun0` scope.

## Ensuring Domain Controllers Appear In Top 10

- Treat DC candidates as high-priority infrastructure assets.
- Give them strong ranking weight when any of the following is observed:
  - LDAP/Kerberos/SMB/DNS combination
  - Active Directory-style service set
  - DNS SRV evidence for the domain
  - Nmap service detection indicating Microsoft DNS, LDAP, Kerberos, or domain controller behavior
  - NXC SMB/LDAP output showing domain `example.local`
- If both hinted DC IPs are discovered or strongly inferred, force both into the top 10 unless the evidence is contradictory or outside validated scope.

## Timeout And Runtime Tuning Strategy

- Expect multi-hour runs in large routed environments.
- Keep small phases quick and write intermediate artifacts early.
- Use bounded discovery, bounded host timeouts, and bounded retries.
- Prevent one slow host from blocking the whole run.
- Keep subnet batches independent so one network does not starve the others.
- Preserve partial results and record all command timeouts.

## Test Execution Steps

1. Run validation:

```bash
./scripts/validate.sh
```

2. Run the scanner in dry-run mode for routing/scope checks:

```bash
./run.sh -i tun0 --authorized --dry-run
```

3. Run the real lab path:

```bash
./run.sh -i tun0
```

4. Inspect:
  - `routes/`
  - `scope.json`
  - `scope.txt`
  - `domain/`
  - `performance/`
  - `top-hosts.json`
  - `top-hosts.md`
  - `report.html`

## Rollback And Safety Notes

- Do not scan routes that are not effectively on `tun0`.
- Do not scan public ranges, default routes, or unrelated interfaces.
- Keep Nuclei restricted to HTTP/HTTPS only.
- Keep NXC restricted to ports and protocols implied by observed services.
- No brute force, spraying, coercion, destructive actions, or credential dumping.
- If route validation is ambiguous, preserve the warning and exclude the network until the kernel route lookup confirms `tun0`.

