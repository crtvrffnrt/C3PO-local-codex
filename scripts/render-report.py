#!/usr/bin/env python3
import argparse
import base64
import json
import os
import sys
from datetime import datetime
from html import escape
from typing import Optional
from urllib.parse import urlparse

RISKY_PORTS = {
    21: "FTP: Cleartext authentication and data transfer. High risk of credential sniffing and unauthorized file access.",
    22: "SSH: Secure Shell. Public exposure invites brute-force attacks and makes a management path externally reachable.",
    23: "Telnet: Cleartext protocol. Extremely vulnerable to sniffing and should never be public-facing.",
    25: "SMTP: Mail transfer. Can expose mail infrastructure and relay abuse opportunities.",
    53: "DNS: Potential for amplification, recursion abuse, or zone disclosure if misconfigured.",
    80: "HTTP: Unencrypted web traffic. Susceptible to interception and session abuse.",
    110: "POP3: Cleartext mail retrieval. Credentials and content may be intercepted.",
    111: "RPCBind: Often used for port mapping in older Unix services. High risk of information disclosure.",
    135: "RPC: Windows RPC. Frequently targeted for remote code execution and service discovery.",
    137: "NetBIOS: Windows naming service. Discloses internal network information and hostnames.",
    139: "NetBIOS: Windows file sharing. High risk of unauthorized data access.",
    143: "IMAP: Cleartext mail access. Sensitive communications and credentials at risk.",
    161: "SNMP: Network management. Weak community strings can expose deep infrastructure data.",
    389: "LDAP: Directory access. May disclose sensitive organizational metadata.",
    445: "SMB: Windows file sharing. Commonly targeted and rarely appropriate on the public internet.",
    548: "AFP: Apple Filing Protocol. Potential for unauthorized file access.",
    1433: "MSSQL: Database access. High impact if exposed with weak authentication.",
    1521: "Oracle: Database access. Similar exposure concerns to MSSQL.",
    2049: "NFS: Network File System. Risk of unauthorized filesystem mounting.",
    3306: "MySQL: Database access. High risk of credential theft and data exposure.",
    3389: "RDP: Remote Desktop. Critical entry point and brute-force target.",
    5432: "PostgreSQL: Database access. Similar exposure concerns to MySQL and MSSQL.",
    5900: "VNC: Remote desktop. Often weakly protected when exposed externally.",
    6379: "Redis: In-memory store. Frequently left without strong authentication.",
    8080: "HTTP-Alt: Often used for management interfaces and application consoles.",
    9200: "Elasticsearch: High risk of data exposure if unauthenticated.",
    27017: "MongoDB: Historically targeted due to missing default authentication.",
}


def inline_image(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, "rb") as handle:
            encoded = base64.b64encode(handle.read()).decode("utf-8")
        ext = os.path.splitext(path)[1].lower().strip(".") or "png"
        return f"data:image/{ext};base64,{encoded}"
    except Exception:
        return ""


def screenshot_map(manifest: dict) -> dict:
    mapping = {}
    for entry in manifest.get("entries") or []:
        host = entry.get("hostname")
        if host:
            mapping[host] = entry
    return mapping


def join_list(items: list, empty: str = "none") -> str:
    valid = [str(i) for i in items if i]
    return ", ".join(valid) if valid else empty


def human_date(iso_value: str) -> str:
    if not iso_value:
        return "unknown"
    try:
        dt = datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y %H:%M UTC")
    except Exception:
        return iso_value


def severity_rank(level: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get((level or "").lower(), 0)


def severity_class(level: str) -> str:
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }.get((level or "").lower(), "low")


def target_host(value: str) -> str:
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.hostname:
        return parsed.hostname.lower().rstrip(".")
    return value.split("/", 1)[0].split(":", 1)[0].lower().rstrip(".")


def attach_nuclei_findings(hosts: list[dict], nuclei_results: list[dict]) -> list[dict]:
    by_name = {}
    by_ip = {}
    for host in hosts:
        host_copy = dict(host)
        host_copy["nuclei_findings"] = []
        hostname = str(host_copy.get("hostname", "")).lower().rstrip(".")
        if hostname:
            by_name[hostname] = host_copy
        for ip in host_copy.get("current_ips", []) or []:
            by_ip[str(ip)] = host_copy

    for result in nuclei_results:
        matched = target_host(result.get("matched-at", "") or result.get("host", ""))
        host = by_name.get(matched) or by_ip.get(matched)
        if not host:
            for candidate_name, candidate in by_name.items():
                if matched == candidate_name or matched.endswith(f".{candidate_name}"):
                    host = candidate
                    break
        if host is not None:
            host["nuclei_findings"].append(result)

    return list(by_name.values())


def risk_label(score: int, level: str) -> str:
    level_text = (level or "low").upper()
    return f"{level_text} {score}"


def risk_tone(level: str) -> str:
    normalized = (level or "").lower()
    if normalized in {"critical", "high"}:
        return "risk"
    if normalized == "medium":
        return "medium"
    return "neutral"


def summary_tone(critical: int = 0, high: int = 0, medium: int = 0) -> str:
    if critical or high:
        return "risk"
    if medium:
        return "medium"
    return "neutral"


def split_metric_html(items: list[tuple[str, str, str]]) -> str:
    return "".join(
        f'<span class="metric-chip chip-{escape(tone)}"><span>{escape(label)}</span><strong>{escape(value)}</strong></span>'
        for label, value, tone in items
    )


def render_metric_card(label: str, value: str, tone: str = "neutral", detail_html: str = "") -> str:
    detail_block = f'<div class="metric-detail">{detail_html}</div>' if detail_html else ""
    return (
        f'<section class="metric-card metric-{escape(tone)}">'
        f'<span class="meta-label">{escape(label)}</span>'
        f'<div class="metric-main"><strong>{escape(value)}</strong></div>'
        f"{detail_block}"
        "</section>"
    )


def vulnerability_summary_rows(hosts: list[dict]) -> str:
    all_vulns = []
    for host in hosts:
        details = host.get("vuln_details", {})
        for cve_id, info in details.items():
            all_vulns.append({
                "cve": cve_id,
                "cvss": float(info.get("cvss", 0.0) or 0.0),
                "summary": info.get("summary", "No details available."),
                "host": host.get("hostname", "n/a"),
                "severity": host.get("risk_level", "low"),
            })

    all_vulns.sort(key=lambda x: x["cvss"], reverse=True)

    rows = ""
    for v in all_vulns[:20]:
        badge_class = severity_class(
            "critical" if v["cvss"] >= 9.0 else "high" if v["cvss"] >= 7.0 else "medium" if v["cvss"] >= 4.0 else "low"
        )
        rows += f"""
        <tr>
          <td class="mono small"><strong>{escape(v['cve'])}</strong></td>
          <td><span class="badge badge-{badge_class}">{escape(f"{v['cvss']:.1f}")}</span></td>
          <td class="mono small">{escape(v['host'])}</td>
          <td class="small">{escape(v['summary'])}</td>
          <td><span class="badge badge-neutral">{escape(v['severity'].upper())}</span></td>
        </tr>
        """
    return rows or '<tr><td colspan="5" class="muted">No infrastructure vulnerabilities identified.</td></tr>'


def html_id(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value))
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    cleaned = cleaned.strip("-")
    return cleaned or "item"


def render_intel_fact(label: str, value: str, mono: bool = False, full: bool = False) -> str:
    classes = "intel-fact full" if full else "intel-fact"
    strong_class = ' class="mono"' if mono else ""
    safe_value = escape(str(value or "n/a"))
    return (
        f'<div class="{classes}">'
        f'<span class="meta-label">{escape(label)}</span>'
        f'<strong{strong_class}>{safe_value}</strong>'
        "</div>"
    )


def render_web_intel_modal(host: dict, modal_id: str) -> str:
    web_intel = host.get("web_intel") or {}
    intel_status = web_intel.get("status", "skipped")
    intel_reason = web_intel.get("reason", "")
    intel_target = web_intel.get("target") or host.get("http", {}).get("url") or host.get("hostname", "")
    intel_result = web_intel.get("result") or {}

    if intel_status == "ok" and intel_result:
        asn_info = intel_result.get("asn") or {}
        tech_stack = "".join(
            f'<span class="pill">{escape(str(tech))}</span>'
            for tech in intel_result.get("tech", [])[:20]
            if tech
        ) or '<span class="muted small">No technologies fingerprinted.</span>'
        dns_facts = "".join(
            [
                render_intel_fact("A Records", join_list(intel_result.get("a", [])), mono=True, full=True),
                render_intel_fact("AAAA Records", join_list(intel_result.get("aaaa", [])), mono=True, full=True),
                render_intel_fact("Resolvers", join_list(intel_result.get("resolvers", [])), mono=True, full=True),
                render_intel_fact("ASN Range", join_list(asn_info.get("as_range", [])), mono=True, full=True),
            ]
        )
        body_html = f"""
          <div class="intel-fact-grid">
            {render_intel_fact("Title", intel_result.get("title", "n/a"), full=True)}
            {render_intel_fact("HTTP Status", str(intel_result.get("status_code", "n/a")), mono=True)}
            {render_intel_fact("Web Server", intel_result.get("webserver", "n/a"), mono=True)}
            {render_intel_fact("CDN", intel_result.get("cdn_name", "n/a"))}
            {render_intel_fact("CDN Type", intel_result.get("cdn_type", "n/a"))}
            {render_intel_fact("Resolved Host IP", intel_result.get("host_ip", "n/a"), mono=True)}
            {render_intel_fact("Primary Host", intel_result.get("host", "n/a"), mono=True)}
            {render_intel_fact("Scheme / Port", f"{intel_result.get('scheme', 'n/a')} / {intel_result.get('port', 'n/a')}", mono=True)}
            {render_intel_fact("Content Type", intel_result.get("content_type", "n/a"), mono=True)}
            {render_intel_fact("Response Time", intel_result.get("time", "n/a"), mono=True)}
            {render_intel_fact("Words / Lines", f"{intel_result.get('words', 'n/a')} / {intel_result.get('lines', 'n/a')}", mono=True)}
            {render_intel_fact("Content Length", str(intel_result.get("content_length", "n/a")), mono=True)}
            {render_intel_fact("ASN", asn_info.get("as_number", "n/a"), mono=True)}
            {render_intel_fact("ASN Name", asn_info.get("as_name", "n/a"))}
            {render_intel_fact("ASN Country", asn_info.get("as_country", "n/a"), mono=True)}
            {render_intel_fact("Input Target", intel_result.get("input", intel_target), mono=True, full=True)}
          </div>
          <div class="intel-section">
            <span class="section-label">Detected Tech Stack</span>
            <div class="intel-pills">{tech_stack}</div>
          </div>
          <div class="intel-section">
            <span class="section-label">DNS / Network Evidence</span>
            <div class="intel-fact-grid">
              {dns_facts}
            </div>
          </div>
        """
    else:
        reason_text = intel_reason or "Website enrichment did not return structured data for this host."
        body_html = f"""
          <div class="callout compact-callout">
            <h3>Website Intel Unavailable</h3>
            <p class="small muted">{escape(reason_text)}</p>
          </div>
        """

    return f"""
      <div class="intel-modal" id="{escape(modal_id)}" aria-hidden="true">
        <div class="intel-modal-backdrop" data-modal-close></div>
        <div class="intel-panel" role="dialog" aria-modal="true" aria-labelledby="{escape(modal_id)}-title">
          <div class="intel-panel-head">
            <div>
              <span class="eyebrow">Website Intel</span>
              <h3 id="{escape(modal_id)}-title">{escape(host.get("hostname", ""))}</h3>
              <div class="host-subline mono">{escape(intel_target or "n/a")}</div>
            </div>
            <button type="button" class="intel-close" data-modal-close aria-label="Close website intelligence">x</button>
          </div>
          {body_html}
        </div>
      </div>
    """


def render_host_card(host: dict, screenshot_entry: Optional[dict], card_index: int) -> str:
    screenshot_html = ""
    cf_intel_html = ""

    if screenshot_entry and screenshot_entry.get("status") == "captured":
        image = inline_image(screenshot_entry.get("path", ""))
        if image:
            screenshot_html = (
                '<figure class="shot-frame">'
                f'<img class="shot" src="{image}" alt="Screenshot of {escape(host.get("hostname", ""))}">'
                f'<figcaption class="shot-caption mono">Screenshot evidence | {escape(host.get("hostname", ""))}</figcaption>'
                "</figure>"
            )

        cf_info = screenshot_entry.get("cloudflare_info", {})
        if cf_info:
            tech_stack = ", ".join(cf_info.get("tech_stack", [])) or "n/a"
            cf_intel_html = f"""
            <div class="evidence-strip">
              <div class="kv"><span class="meta-label">Cloudflare Server</span><strong class="mono small">{escape(cf_info.get("server", "n/a"))}</strong></div>
              <div class="kv"><span class="meta-label">TLS / Security</span><strong class="mono small">{escape(cf_info.get("tls_protocol", "n/a"))} / {escape(cf_info.get("security_state", "n/a"))}</strong></div>
              <div class="kv full"><span class="meta-label">Tech Stack</span><strong class="small">{escape(tech_stack)}</strong></div>
            </div>
            """

    services_list = []
    for port in host.get("ports", []):
        try:
            port_int = int(port)
        except Exception:
            continue
        if port_int in RISKY_PORTS:
            risk_text = RISKY_PORTS[port_int]
            color_class = "danger" if port_int in (21, 23, 135, 139, 445, 3389, 6379, 9200) else "warn"
            services_list.append(f'<span class="pill port {color_class}" title="{escape(risk_text)}">{escape(str(port))}</span>')
        else:
            services_list.append(f'<span class="pill port">{escape(str(port))}</span>')
    services = "".join(services_list[:12])

    vulns = "".join(
        f'<span class="pill vuln" title="{escape(host.get("vuln_details", {}).get(v, {}).get("summary", "No details available."))}\nCVSS: {host.get("vuln_details", {}).get(v, {}).get("cvss", "n/a")}">{escape(str(v))}</span>'
        for v in host.get("vulns", [])[:12]
    )
    nuclei_findings = host.get("nuclei_findings", []) or []
    nuclei_pills = "".join(
        f'<span class="pill vuln" title="{escape(item.get("info", {}).get("name", ""))}">{escape(item.get("template-id", "nuclei"))}</span>'
        for item in nuclei_findings[:12]
    )

    factors = "".join(f"<li>{escape(factor)}</li>" for factor in host.get("risk_factors", [])[:5])
    ips = host.get("current_ips", [])
    primary_ip = ips[0] if ips else "n/a"
    sh_hostnames = ", ".join(host.get("shodan_hostnames", [])) or "n/a"
    sh_domains = ", ".join(host.get("shodan_domains", [])) or "n/a"
    url = host.get("http", {}).get("url", "n/a")
    source_list = join_list(host.get("sources", []), empty="unspecified")
    risk_class = severity_class(host.get("risk_level", "low"))
    modal_id = f"web-intel-{card_index}-{html_id(host.get('hostname', 'host'))}"

    return f"""
      <article class="host-card">
        <div class="host-head">
          <div class="host-title-group">
            <span class="eyebrow">Top Exposure Target</span>
            <h3>{escape(host.get("hostname", ""))}</h3>
            <div class="host-subline mono">{escape(source_list)}</div>
          </div>
          <div class="host-actions">
            <button type="button" class="intel-trigger" data-modal-target="{escape(modal_id)}" aria-expanded="false" aria-label="Open website intelligence for {escape(host.get('hostname', ''))}">i</button>
            <div class="risk-badge badge-{risk_class}">
              {escape(risk_label(host.get('risk_score', 0), host.get('risk_level', 'low')))}
            </div>
          </div>
        </div>

        <div class="host-metrics">
          <div class="kv"><span class="meta-label">Primary IP</span><strong class="mono">{escape(primary_ip)}</strong></div>
          <div class="kv"><span class="meta-label">City</span><strong>{escape(host.get("city", "n/a"))}</strong></div>
          <div class="kv"><span class="meta-label">HTTP URL</span><strong class="mono truncate" title="{escape(url)}">{escape(url)}</strong></div>
          <div class="kv"><span class="meta-label">Shodan Hostnames</span><strong class="mono truncate" title="{escape(sh_hostnames)}">{escape(sh_hostnames)}</strong></div>
          <div class="kv full"><span class="meta-label">Associated Domains</span><strong class="mono truncate" title="{escape(sh_domains)}">{escape(sh_domains)}</strong></div>
        </div>

        <div class="section-label">Open Ports</div>
        <div class="pill-group">{services or '<span class="muted small">No port data recorded.</span>'}</div>

        <div class="section-label">Known Vulnerabilities</div>
        <div class="vuln-grid">{vulns or '<span class="muted small">No CVEs recorded for this host.</span>'}</div>

        <div class="section-label">Nuclei Detections</div>
        <div class="vuln-grid">{nuclei_pills or '<span class="muted small">No template matches recorded for this host.</span>'}</div>

        <div class="risk-factors">
          <span class="section-label">Risk Factors</span>
          <ul>{factors or '<li>Baseline exposure observed.</li>'}</ul>
        </div>

        {cf_intel_html}
        {screenshot_html}

        <div class="asset-footer mono">
          <span>Sources: {escape(source_list)}</span>
          <span>Recorded IPs: {escape(join_list(ips))}</span>
        </div>
        {render_web_intel_modal(host, modal_id)}
      </article>
    """


def html_report(payload: dict, manifest: dict, nuclei_results: list[dict]) -> str:
    target = payload.get("target", {})
    summary = payload.get("summary", {})
    hosts = attach_nuclei_findings(payload.get("hosts", []), nuclei_results)
    ip_assets = payload.get("ips", [])
    discoveries = payload.get("discoveries", {})
    screenshots = screenshot_map(manifest)

    cf_entries = [e for e in manifest.get("entries", []) if e.get("cloudflare_info")]
    if cf_entries:
        cf_intel_rows = ""
        for e in cf_entries:
            info = e["cloudflare_info"]
            techs = ", ".join(info.get("tech_stack", [])) or "n/a"
            cf_intel_rows += f"""
            <tr>
              <td class="mono small">{escape(e.get('hostname', ''))}</td>
              <td class="small">{escape(info.get('server', 'n/a'))}</td>
              <td class="mono small">{escape(info.get('tls_protocol', 'n/a'))}</td>
              <td><span class="badge badge-neutral">{escape(info.get('security_state', 'n/a'))}</span></td>
              <td class="small">{escape(techs)}</td>
              <td class="mono small">{escape(info.get('ip', 'n/a'))} ({escape(info.get('country', 'n/a'))})</td>
            </tr>
            """
    else:
        cf_intel_rows = """
        <tr>
          <td colspan="6" class="muted">
            <strong>No Cloudflare intelligence available.</strong><br>
            Cloudflare API credentials were not provided during this session. Refer to the collection documentation to enable enriched edge metadata.
          </td>
        </tr>
        """

    nuclei_critical = sum(1 for r in nuclei_results if r.get("info", {}).get("severity") == "critical")
    nuclei_high = sum(1 for r in nuclei_results if r.get("info", {}).get("severity") == "high")
    nuclei_med = sum(1 for r in nuclei_results if r.get("info", {}).get("severity") == "medium")
    nuclei_low = sum(1 for r in nuclei_results if r.get("info", {}).get("severity") == "low")
    nuclei_total = len(nuclei_results)

    critical_count = int(summary.get("critical_count", 0) or 0)
    high_count = int(summary.get("high_count", 0) or 0)
    medium_count = int(summary.get("medium_count", 0) or 0)
    web_count = int(summary.get("web_host_count", 0) or 0)
    asset_total = int(summary.get("original_total_hosts", 0) or 0)

    priority_hosts = sorted(hosts, key=lambda h: (severity_rank(h.get("risk_level")), h.get("risk_score", 0)), reverse=True)
    top_hosts = priority_hosts[:6]
    supporting_hosts = priority_hosts[6:12]

    summary_card_html = "".join(
        [
            render_metric_card("Discovered Assets", str(asset_total)),
            render_metric_card("Priority Targets", str(len(hosts))),
            render_metric_card("Web Exposures", str(web_count)),
            render_metric_card(
                "Critical / High / Medium",
                str(critical_count + high_count + medium_count),
                summary_tone(critical_count, high_count, medium_count),
                split_metric_html(
                    [
                        ("Critical", str(critical_count), "risk" if critical_count else "neutral"),
                        ("High", str(high_count), "risk" if high_count else "neutral"),
                        ("Medium", str(medium_count), "medium" if medium_count else "neutral"),
                    ]
                ),
            ),
            render_metric_card(
                "Nuclei Findings",
                str(nuclei_total),
                summary_tone(nuclei_critical, nuclei_high, nuclei_med),
                split_metric_html(
                    [
                        ("Critical", str(nuclei_critical), "risk" if nuclei_critical else "neutral"),
                        ("High", str(nuclei_high), "risk" if nuclei_high else "neutral"),
                        ("Medium", str(nuclei_med), "medium" if nuclei_med else "neutral"),
                        ("Low", str(nuclei_low), "neutral"),
                    ]
                ) if nuclei_total else "",
            ),
            render_metric_card(
                "Critical / High Nuclei",
                str(nuclei_critical + nuclei_high),
                summary_tone(nuclei_critical, nuclei_high, 0),
                split_metric_html(
                    [
                        ("Critical", str(nuclei_critical), "risk" if nuclei_critical else "neutral"),
                        ("High", str(nuclei_high), "risk" if nuclei_high else "neutral"),
                    ]
                ),
            ),
        ]
    )

    nuclei_breakdown_html = (
        '<div class="metric-grid">'
        + "".join(
            [
                render_metric_card("Critical", str(nuclei_critical), "risk" if nuclei_critical else "neutral"),
                render_metric_card("High", str(nuclei_high), "risk" if nuclei_high else "neutral"),
                render_metric_card("Medium", str(nuclei_med), "medium" if nuclei_med else "neutral"),
                render_metric_card("Low", str(nuclei_low), "neutral"),
                render_metric_card("Total", str(nuclei_total), summary_tone(nuclei_critical, nuclei_high, nuclei_med)),
            ]
        )
        + "</div>"
    ) if nuclei_total else '<div class="callout compact-callout"><h3>No Nuclei Detections</h3><p class="small">No templates matched during this session, so the finding breakdown stays neutral.</p></div>'

    nuclei_rows = "".join(
        f"""
        <tr>
          <td><span class="badge badge-{severity_class(r.get('info', {}).get('severity', 'low'))}">{escape(r.get('info', {}).get('severity', '').upper())}</span></td>
          <td class="mono small">{escape(r.get('template-id', ''))}</td>
          <td class="small">{escape(r.get('info', {}).get('name', ''))}</td>
          <td class="mono small">{escape(r.get('matched-at', ''))}</td>
        </tr>
        """
        for r in nuclei_results[:50]
    ) or '<tr><td colspan="4" class="muted">No nuclei findings recorded for this session.</td></tr>'

    takeover_html = "".join(
        f"""
        <article class="callout">
          <div class="pill-group"><span class="badge badge-neutral">Takeover Target</span></div>
          <h3>{escape(item.get('hostname', ''))}</h3>
          <p class="small">{escape(join_list(item.get('reasons', []), empty='No reason recorded'))}</p>
        </article>
        """
        for item in discoveries.get("takeover_candidates", [])[:12]
    ) or '<article class="callout"><h3>No Takeover Signals</h3><p class="small">Current heuristics indicate stable infrastructure.</p></article>'

    txt_html = "".join(
        f"""
        <article class="callout">
          <div class="pill-group"><span class="badge badge-neutral">DNS Intelligence</span></div>
          <h3>{escape(item.get('hostname', ''))}</h3>
          <p class="meta-label" style="margin-top:8px;">{escape(item.get('label', ''))}</p>
          <code class="mono dns-value">{escape(item.get('value', ''))}</code>
        </article>
        """
        for item in discoveries.get("interesting_txt", [])[:12]
    ) or '<article class="callout"><h3>No TXT Signals</h3><p class="small">No interesting DNS evidence collected.</p></article>'

    ip_rows = "".join(
        f"""
        <tr>
          <td class="mono small">{escape(item.get('ip', ''))}</td>
          <td class="mono small">{escape(item.get('network_hint', ''))}</td>
          <td class="small">{escape(join_list(item.get('hostnames', [])))}</td>
          <td class="mono small">{escape(join_list([str(port) for port in item.get('ports', [])]))}</td>
          <td class="small">{escape(join_list(sorted((item.get('port_sources') or {}).keys())))}</td>
          <td class="small">{escape(join_list(item.get('products', [])))}</td>
          <td class="muted small">{escape(item.get('org', '') or 'n/a')}</td>
        </tr>
        """
        for item in ip_assets[:80]
    )

    host_cards = "".join(
        render_host_card(host, screenshots.get(host.get("hostname", "")), card_index)
        for card_index, host in enumerate(top_hosts, start=1)
    )
    supporting_cards = "".join(
        render_host_card(host, screenshots.get(host.get("hostname", "")), card_index)
        for card_index, host in enumerate(supporting_hosts, start=len(top_hosts) + 1)
    )

    overall_state = "CRITICAL" if critical_count else "HIGH" if high_count else "MEDIUM" if medium_count else "BASELINE"
    overall_badge_class = "critical" if critical_count else "high" if high_count else "medium" if medium_count else "low"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EASM | {escape(target.get('core_domain', ''))}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Manrope:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      color-scheme: dark;
      --bg: #050816;
      --bg-2: #070d1f;
      --surface: rgba(10, 15, 33, 0.88);
      --surface-2: rgba(14, 20, 41, 0.94);
      --surface-3: rgba(255, 255, 255, 0.03);
      --text: #f5f7fb;
      --text-soft: #c7d1e0;
      --text-muted: #7f8aa0;
      --line: rgba(255, 255, 255, 0.09);
      --line-strong: rgba(76, 246, 255, 0.24);
      --shadow: 0 24px 70px rgba(0, 0, 0, 0.42);
      --radius-lg: 28px;
      --radius-md: 18px;
      --radius-sm: 12px;
      --cyan: #4cf6ff;
      --magenta: #ff4ff8;
      --green: #5cff8d;
      --amber: #e8d66c;
      --risk-red-text: #ff6b7a;
      --risk-red-line: rgba(255, 107, 122, 0.28);
      --risk-red-bg: rgba(255, 107, 122, 0.12);
      --risk-orange-text: #f4c15f;
      --risk-orange-line: rgba(244, 193, 95, 0.24);
      --risk-orange-bg: rgba(244, 193, 95, 0.12);
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at top left, rgba(255, 79, 248, 0.14), transparent 32%),
        radial-gradient(circle at top right, rgba(76, 246, 255, 0.12), transparent 28%),
        linear-gradient(180deg, #050816 0%, #070b18 50%, #050816 100%);
      color: var(--text);
      font: 400 15px/1.65 "Manrope", sans-serif;
    }}
    a {{ color: inherit; }}
    .viewer-shell {{
      width: min(1520px, calc(100% - 28px));
      margin: 0 auto;
      padding: 28px 0 52px;
      display: grid;
      grid-template-columns: 340px minmax(0, 1fr);
      gap: 28px;
    }}
    .sidebar {{
      position: sticky;
      top: 18px;
      align-self: start;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }}
    .panel {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow);
      backdrop-filter: blur(18px);
      padding: 22px 22px 20px;
    }}
    .eyebrow, .meta-label, .terminal-title, .badge, .pill, .toc a, .footer-meta, .section-label, .host-subline {{
      font-family: "IBM Plex Mono", monospace;
      letter-spacing: 0.03em;
      text-transform: uppercase;
    }}
    .eyebrow {{ margin: 0 0 12px; font-size: 0.7rem; color: var(--cyan); }}
    .sidebar h1, .paper h1, .paper h2, .paper h3 {{
      font-family: "Space Grotesk", sans-serif;
      line-height: 1.08;
      letter-spacing: -0.03em;
      color: var(--text);
    }}
    .sidebar h1 {{ margin: 0 0 14px; font-size: 1.5rem; }}
    .sidebar p {{ margin: 0; color: var(--text-soft); font-size: 0.9rem; }}
    .sidebar .muted {{ color: var(--text-muted); }}
    .quick-facts {{ margin-top: 16px; display: grid; gap: 8px; }}
    .fact-row {{
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 0;
      border-bottom: 1px solid var(--line);
    }}
    .fact-row:last-child {{ border-bottom: 0; padding-bottom: 0; }}
    .fact-row .meta-label {{ margin-bottom: 0; }}
    .fact-row .meta-value {{
      font-size: 0.88rem;
      font-weight: 700;
      color: var(--text);
      text-align: right;
    }}
    .meta-label {{ display: block; font-size: 0.65rem; color: var(--text-muted); margin-bottom: 4px; }}
    .meta-value {{ font-size: 0.9rem; font-weight: 700; color: var(--text); }}
    .toc h2, .info-card h2, .researcher-card h2 {{ margin: 0 0 14px; font-size: 0.9rem; }}
    .toc nav {{ display: grid; gap: 8px; }}
    .toc a {{
      display: block;
      font-size: 0.72rem;
      text-decoration: none;
      color: var(--text-soft);
      padding: 8px 10px;
      border-radius: 10px;
      border: 1px solid transparent;
      transition: all 140ms ease;
    }}
    .toc a:hover {{ background: rgba(255,255,255,0.04); border-color: var(--line-strong); transform: translateX(2px); }}
    .paper-wrap {{ min-width: 0; }}
    .paper {{
      background: linear-gradient(180deg, rgba(13, 18, 35, 0.96) 0%, rgba(7, 11, 24, 0.98) 100%);
      border: 1px solid var(--line);
      border-radius: 34px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }}
    .paper-inner {{ padding: 44px 52px 54px; }}
    .cover {{
      padding-bottom: 28px;
      border-bottom: 1px solid var(--line);
      position: relative;
      overflow: hidden;
    }}
    .cover::before {{
      content: "";
      position: absolute;
      inset: auto -8% -38% auto;
      width: 360px;
      height: 360px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(76, 246, 255, 0.11), transparent 68%);
      pointer-events: none;
    }}
    .cover-kicker {{ margin: 0 0 14px; font: 600 0.72rem/1 "IBM Plex Mono", monospace; text-transform: uppercase; letter-spacing: 0.06em; color: var(--magenta); }}
    .paper h1 {{ margin: 0 0 16px; font-size: clamp(1.8rem, 4vw, 2.8rem); }}
    .lede {{ margin: 0; max-width: 860px; font-size: 1.05rem; color: var(--text-soft); }}
    .hero-meta {{
      margin-top: 18px;
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }}
    .hero-pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.03);
      color: var(--text-soft);
      font: 600 0.72rem/1 "IBM Plex Mono", monospace;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .hero-pill strong {{ color: var(--text); }}
    .metric-grid {{ margin-top: 24px; display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }}
    .metric-card {{
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--surface-3);
      padding: 12px 14px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .metric-main {{
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px;
    }}
    .metric-main strong {{
      display: block;
      font-size: 1rem;
      line-height: 1.2;
      font-family: "IBM Plex Mono", monospace;
      color: var(--text);
    }}
    .metric-detail {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .metric-chip {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: #fff;
      color: var(--text-muted);
      font-size: 0.62rem;
      line-height: 1;
      font-family: "IBM Plex Mono", monospace;
      text-transform: uppercase;
    }}
    .metric-chip strong {{ font-size: 0.72rem; color: inherit; }}
    .metric-risk {{ border-color: var(--risk-red-line); background: var(--risk-red-bg); }}
    .metric-medium {{ border-color: var(--risk-orange-line); background: var(--risk-orange-bg); }}
    .chip-risk {{ border-color: var(--risk-red-line); background: var(--risk-red-bg); color: var(--risk-red-text); }}
    .chip-medium {{ border-color: var(--risk-orange-line); background: var(--risk-orange-bg); color: var(--risk-orange-text); }}
    .compact-callout {{ margin-top: 16px; }}
    .paper-section {{ padding-top: 30px; border-top: 1px solid var(--line); margin-top: 30px; }}
    .paper-section:first-of-type {{ border-top: 0; margin-top: 0; padding-top: 0; }}
    .paper h2 {{ margin: 0 0 16px; font-size: 1.4rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .paper h3 {{ margin: 24px 0 12px; font-size: 1.05rem; }}
    .paper p, .paper li {{ color: var(--text-soft); }}
    .paper p {{ margin: 0 0 14px; }}
    .grid-two {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }}
    .section-template {{
      display: grid;
      grid-template-columns: 1.1fr 0.9fr;
      gap: 16px;
      margin-bottom: 16px;
    }}
    .template-card {{
      border: 1px solid var(--line);
      border-radius: 20px;
      background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02));
      padding: 18px;
    }}
    .template-card h3 {{ margin-top: 0; }}
    .template-card .template-stat {{
      display: flex;
      justify-content: space-between;
      gap: 10px;
      padding: 10px 0;
      border-bottom: 1px solid var(--line);
      color: var(--text-soft);
    }}
    .template-card .template-stat:last-child {{ border-bottom: 0; padding-bottom: 0; }}
    .template-card .template-stat strong {{ color: var(--text); font-family: "IBM Plex Mono", monospace; font-size: 0.82rem; }}
    .callout {{
      border: 1px solid var(--line);
      border-radius: 16px;
      background: linear-gradient(180deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.03) 100%);
      padding: 18px 18px 16px;
    }}
    .callout h3 {{ margin-top: 0; font-size: 1rem; color: var(--text); }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 0.65rem;
      line-height: 1;
      background: rgba(255,255,255,0.04);
      color: var(--text-soft);
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.68rem;
      font-family: "IBM Plex Mono", monospace;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.04);
      color: var(--text-soft);
    }}
    .pill.port {{ color: var(--text-soft); border-color: var(--line); background: rgba(255,255,255,0.03); }}
    .pill.port.danger {{ color: var(--risk-red-text); border-color: var(--risk-red-line); background: var(--risk-red-bg); }}
    .pill.port.warn {{ color: var(--risk-orange-text); border-color: var(--risk-orange-line); background: var(--risk-orange-bg); }}
    .pill.vuln {{ color: var(--risk-red-text); border-color: var(--risk-red-line); background: var(--risk-red-bg); }}
    .pill-group {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }}
    .badge-neutral {{ background: rgba(255,255,255,0.05) !important; color: var(--text-soft) !important; border-color: var(--line) !important; }}
    .evidence-table {{ width: 100%; border-collapse: separate; border-spacing: 0; border: 1px solid var(--line); border-radius: 16px; overflow: hidden; font-size: 0.86rem; background: rgba(255,255,255,0.03); }}
    .evidence-table th, .evidence-table td {{ text-align: left; vertical-align: top; padding: 11px 14px; border-bottom: 1px solid var(--line); }}
    .evidence-table th {{ background: rgba(255,255,255,0.05); color: var(--text-muted); font-size: 0.65rem; text-transform: uppercase; font-family: "IBM Plex Mono", monospace; }}
    .evidence-table tr:last-child td {{ border-bottom: 0; }}
    .badge-critical {{ background: var(--risk-red-bg) !important; color: var(--risk-red-text) !important; border-color: var(--risk-red-line) !important; }}
    .badge-high {{ background: var(--risk-red-bg) !important; color: var(--risk-red-text) !important; border-color: var(--risk-red-line) !important; }}
    .badge-medium {{ background: var(--risk-orange-bg) !important; color: var(--risk-orange-text) !important; border-color: var(--risk-orange-line) !important; }}
    .badge-low {{ background: rgba(255,255,255,0.05) !important; color: var(--text-soft) !important; border-color: var(--line) !important; }}
    .host-card {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius-md);
      padding: 22px;
      position: relative;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }}
    .host-card:hover {{ border-color: var(--line-strong); box-shadow: 0 12px 24px rgba(16,18,20,0.04); }}
    .host-head {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }}
    .host-actions {{ display: flex; align-items: center; gap: 10px; }}
    .host-title-group h3 {{ margin: 0; font-size: 1.15rem; letter-spacing: -0.01em; }}
    .host-subline {{ margin-top: 6px; color: var(--text-muted); font-size: 0.68rem; word-break: break-all; }}
    .intel-trigger {{
      width: 34px;
      height: 34px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.05);
      color: var(--text-soft);
      font: 700 0.82rem/1 "IBM Plex Mono", monospace;
      cursor: pointer;
      transition: all 140ms ease;
    }}
    .intel-trigger:hover {{
      border-color: var(--line-strong);
      background: rgba(76,246,255,0.10);
      transform: translateY(-1px);
    }}
    .risk-badge {{
      padding: 6px 10px;
      border-radius: 8px;
      font-size: 0.68rem;
      font-weight: 700;
      font-family: "IBM Plex Mono", monospace;
      border: 1px solid var(--line);
      white-space: nowrap;
    }}
    .host-metrics {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 14px; }}
    .host-metrics .full {{ grid-column: 1 / -1; }}
    .kv strong {{ font-size: 0.84rem; word-break: break-word; color: var(--text-soft); }}
    .truncate {{ display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .section-label {{ margin-top: 2px; font: 600 0.68rem/1 "IBM Plex Mono", monospace; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; }}
    .risk-factors ul {{ margin: 0; padding-left: 18px; font-size: 0.85rem; color: var(--text-muted); }}
    .risk-factors li + li {{ margin-top: 4px; }}
    .shot-frame {{ margin: 0; border: 1px solid var(--line); border-radius: 14px; overflow: hidden; background: rgba(255,255,255,0.03); }}
    .shot {{ width: 100%; display: block; }}
    .shot-caption {{ padding: 10px 12px; border-top: 1px solid var(--line); background: rgba(255,255,255,0.05); font-size: 0.62rem; color: var(--text-muted); }}
    .evidence-strip {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 14px; padding: 14px; border: 1px solid var(--line); border-radius: 14px; background: rgba(255,255,255,0.03); }}
    .evidence-strip .full {{ grid-column: 1 / -1; }}
    .dns-value {{
      display: block;
      margin-top: 8px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: rgba(255,255,255,0.05);
      font-size: 0.76rem;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    body.modal-open {{ overflow: hidden; }}
    .intel-modal {{
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 24px;
      z-index: 1200;
    }}
    .intel-modal.is-open {{ display: flex; }}
    .intel-modal-backdrop {{
      position: absolute;
      inset: 0;
      background: rgba(1, 4, 10, 0.72);
      backdrop-filter: blur(4px);
    }}
    .intel-panel {{
      position: relative;
      width: min(920px, 100%);
      max-height: min(82vh, 920px);
      overflow: auto;
      background: var(--surface-2);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: 0 24px 70px rgba(16, 18, 20, 0.18);
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }}
    .intel-panel-head {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 14px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--line);
    }}
    .intel-close {{
      min-width: 36px;
      height: 36px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.05);
      color: var(--text-soft);
      font: 700 0.78rem/1 "IBM Plex Mono", monospace;
      cursor: pointer;
    }}
    .intel-fact-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    .intel-fact {{
      padding: 12px 14px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(255,255,255,0.04);
    }}
    .intel-fact.full {{ grid-column: 1 / -1; }}
    .intel-fact strong {{
      display: block;
      font-size: 0.88rem;
      color: var(--text-soft);
      word-break: break-word;
    }}
    .intel-section {{
      display: flex;
      flex-direction: column;
      gap: 10px;
    }}
    .intel-pills {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .asset-footer {{ display: flex; flex-wrap: wrap; justify-content: space-between; gap: 10px; padding-top: 6px; border-top: 1px solid var(--line); color: var(--text-muted); font-size: 0.62rem; }}
    .mono {{ font-family: "IBM Plex Mono", monospace; }}
    .small {{ font-size: 0.8rem; }}
    .muted {{ color: var(--text-muted); }}
    @media (max-width: 1180px) {{
      .viewer-shell {{ grid-template-columns: 1fr; }}
      .sidebar {{ position: static; }}
    }}
    @media (max-width: 760px) {{
      .paper-inner {{ padding: 28px 18px 34px; }}
      .viewer-shell {{ width: min(100% - 16px, 1460px); padding-top: 16px; }}
      .grid-two, .metric-grid, .host-metrics, .evidence-strip, .intel-fact-grid {{ grid-template-columns: 1fr; }}
      .host-head, .asset-footer {{ flex-direction: column; }}
      .intel-modal {{ padding: 12px; }}
      .intel-panel {{ padding: 18px; }}
      .intel-panel-head {{ flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <div class="viewer-shell">
    <aside class="sidebar">
      <section class="panel toc">
        <h2>Contents</h2>
        <nav>
          <a href="#summary">1. Executive Summary</a>
          <a href="#metrics">2. Key Metrics</a>
          <a href="#priority">3. Priority Findings</a>
          <a href="#targets">4. Top Exposed Assets</a>
          <a href="#supporting">5. Supporting Intelligence</a>
          <a href="#inventory">6. Infrastructure Inventory</a>
        </nav>
      </section>

      <section class="panel info-card">
        <p class="eyebrow">EASM Session</p>
        <h1>{escape(target.get('core_domain', ''))}</h1>
        <p>Attack surface analysis report for the specified domain and its sub-infrastructure.</p>
        <div class="quick-facts">
          <div class="fact-row">
            <span class="meta-label">Total Assets</span>
            <div class="meta-value mono">{escape(str(asset_total))}</div>
          </div>
          <div class="fact-row">
            <span class="meta-label">Web Targets</span>
            <div class="meta-value mono">{escape(str(web_count))}</div>
          </div>
          <div class="fact-row">
            <span class="meta-label">Exposure State</span>
            <div class="meta-value"><span class="badge badge-{overall_badge_class}">{escape(overall_state)}</span></div>
          </div>
          <div class="fact-row">
            <span class="meta-label">Generated At</span>
            <div class="meta-value">{escape(human_date(target.get('generated_at', '')))}</div>
          </div>
        </div>
      </section>

      <section class="panel researcher-card">
        <h2>Researcher</h2>
        <p><strong>Patrick Binder</strong></p>
        <p class="small muted">Offensive Cybersecurity Expert specializing in Microsoft Cloud pentesting and adversarial research.</p>
        <div style="margin-top: 12px;">
          <a href="https://www.patrick-binder.de/" class="badge" style="text-decoration: none;">[ Portfolio ]</a>
        </div>
      </section>
    </aside>

    <main class="paper-wrap">
      <article class="paper">
        <div class="paper-inner">
          <header class="cover">
            <p class="cover-kicker">External Attack Surface Management Report</p>
            <h1>{escape(target.get('core_domain', ''))}</h1>
            <p class="lede">Comprehensive analysis of the external attack surface, structured to highlight priority exposure, supporting evidence, and the assets that merit the earliest analyst review.</p>
            <div class="hero-meta">
              <span class="hero-pill">Report Mode <strong>Executive Brief</strong></span>
              <span class="hero-pill">Scope <strong>{escape(target.get('interface', 'Selected Interface'))}</strong></span>
              <span class="hero-pill">Status <strong class="badge badge-{overall_badge_class}">{escape(overall_state)}</strong></span>
            </div>
            <div class="metric-grid">
              {summary_card_html}
            </div>
          </header>

          <section id="summary" class="paper-section">
            <h2>1. Executive Summary</h2>
            <p>The external reconnaissance scope for <strong>{escape(target.get('core_domain', ''))}</strong> identified {asset_total} discovered assets, of which {len(hosts)} were prioritized for deeper analysis based on exposure, service composition, and observed risk indicators.</p>
            <p>Overall exposure is assessed as <strong>{overall_state}</strong>. The most relevant findings are concentrated in exposed web services, vulnerable internet-facing hosts, and a small set of infrastructure entries requiring analyst review first.</p>
            <div class="section-template">
              <article class="template-card">
                <h3>Assessment Framing</h3>
                <p class="small muted">This report is optimized for triage, evidence review, and prioritization. It distinguishes observed exposure from confirmed vulnerability so analysts can move quickly without over-claiming.</p>
                <div class="template-stat"><span>Primary signal</span><strong>Exposure + evidence</strong></div>
                <div class="template-stat"><span>Validation model</span><strong>Deterministic, offline readable</strong></div>
                <div class="template-stat"><span>Action level</span><strong>Top 10 first</strong></div>
              </article>
              <article class="template-card">
                <h3>At-a-Glance State</h3>
                <div class="template-stat"><span>Assets discovered</span><strong>{escape(str(asset_total))}</strong></div>
                <div class="template-stat"><span>Priority targets</span><strong>{escape(str(len(hosts)))}</strong></div>
                <div class="template-stat"><span>Web exposures</span><strong>{escape(str(web_count))}</strong></div>
              </article>
            </div>
            <div class="callout" style="margin-top: 20px;">
              <h3>Observed Infrastructure Vulnerabilities</h3>
              <p class="small muted">Key vulnerabilities identified via host intelligence across the discovered infrastructure.</p>
              <table class="evidence-table">
                <thead>
                  <tr>
                    <th>CVE ID</th>
                    <th>Score</th>
                    <th>Affected Host</th>
                    <th>Vulnerability Summary</th>
                    <th>Host Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerability_summary_rows(hosts)}
                </tbody>
              </table>
            </div>
          </section>

          <section id="metrics" class="paper-section">
            <h2>2. Key Metrics</h2>
            <p>High-level summary for quick triage and prioritization.</p>
            <div class="metric-grid">
              {summary_card_html}
            </div>
          </section>

          <section id="priority" class="paper-section">
            <h2>3. Priority Findings</h2>
            <p>Automated templates matched against discovered web entrypoints. Findings are ordered by severity to highlight items that deserve immediate validation.</p>
            <table class="evidence-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Template</th>
                  <th>Finding Name</th>
                  <th>Matched Target</th>
                </tr>
              </thead>
              <tbody>
                {nuclei_rows}
              </tbody>
            </table>
            <h3 style="margin-top: 24px;">Nuclei Severity Breakdown</h3>
            {nuclei_breakdown_html}
          </section>

          <section id="targets" class="paper-section">
            <h2>4. Top Exposed Assets</h2>
            <p>The most relevant hosts are presented first based on risk score, severity, and exposure characteristics.</p>
            <div class="grid-two">
              {host_cards}
            </div>
            {f'<h3 style="margin-top:24px;">Additional Priority Assets</h3><div class="grid-two">{supporting_cards}</div>' if supporting_cards else ''}
          </section>

          <section id="supporting" class="paper-section">
            <h2>5. Supporting Intelligence</h2>
            <p>Edge metadata, takeover candidates, and DNS observations used to support triage and deeper validation.</p>
            <h3>Cloudflare Intelligence</h3>
            <div style="overflow-x: auto;">
              <table class="evidence-table">
                <thead>
                  <tr>
                    <th>Target Host</th>
                    <th>Server</th>
                    <th>TLS</th>
                    <th>Security</th>
                    <th>Tech Stack</th>
                    <th>Edge IP</th>
                  </tr>
                </thead>
                <tbody>
                  {cf_intel_rows}
                </tbody>
              </table>
            </div>
            <h3 style="margin-top: 24px;">DNS / Takeover Intelligence</h3>
            <div class="grid-two">
              {takeover_html}
              {txt_html}
            </div>
          </section>

          <section id="inventory" class="paper-section">
            <h2>6. Infrastructure Inventory</h2>
            <p>Condensed view of discovered IP infrastructure and network groupings.</p>
            <div style="overflow-x: auto;">
              <table class="evidence-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Network</th>
                    <th>Hostnames</th>
                    <th>Ports</th>
                    <th>Port Sources</th>
                    <th>Products</th>
                    <th>Organization</th>
                  </tr>
                </thead>
                <tbody>
                  {ip_rows}
                </tbody>
              </table>
            </div>
          </section>

          <footer style="margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--line); display: flex; justify-content: space-between; gap: 12px;">
            <div class="footer-meta">C3PO-LOCAL // EASM ENGINE</div>
            <div class="footer-meta">CONFIDENTIAL RECONNAISSANCE DATA</div>
          </footer>
        </div>
      </article>
    </main>
  </div>
  <script>
    (() => {{
      const body = document.body;
      let activeModal = null;
      let activeTrigger = null;

      const closeModal = () => {{
        if (!activeModal) return;
        activeModal.classList.remove("is-open");
        activeModal.setAttribute("aria-hidden", "true");
        body.classList.remove("modal-open");
        if (activeTrigger) {{
          activeTrigger.setAttribute("aria-expanded", "false");
          activeTrigger.focus();
        }}
        activeModal = null;
        activeTrigger = null;
      }};

      document.querySelectorAll("[data-modal-target]").forEach((trigger) => {{
        trigger.addEventListener("click", () => {{
          const modal = document.getElementById(trigger.dataset.modalTarget);
          if (!modal) return;
          if (activeModal && activeModal !== modal) {{
            closeModal();
          }}
          activeModal = modal;
          activeTrigger = trigger;
          modal.classList.add("is-open");
          modal.setAttribute("aria-hidden", "false");
          trigger.setAttribute("aria-expanded", "true");
          body.classList.add("modal-open");
        }});
      }});

      document.querySelectorAll("[data-modal-close]").forEach((node) => {{
        node.addEventListener("click", (event) => {{
          event.preventDefault();
          closeModal();
        }});
      }});

      document.addEventListener("keydown", (event) => {{
        if (event.key === "Escape") {{
          closeModal();
        }}
      }});
    }})();
  </script>
</body>
</html>
"""


def markdown_report(payload: dict, manifest: dict, nuclei_results: list[dict]) -> str:
    target = payload.get("target", {})
    hosts = attach_nuclei_findings(payload.get("hosts", []), nuclei_results)

    lines = [
        f"# EASM Report: {target.get('core_domain', 'unknown')}",
        "",
        f"- Generated: {target.get('generated_at', '')}",
        f"- Target Focus: {len(hosts)} top targets analyzed.",
        f"- Nuclei Hits: {len(nuclei_results)} total vulnerabilities.",
        "",
        "## Top Vulnerability Targets",
        "",
    ]

    for host in hosts:
        lines.append(f"### {host.get('hostname', 'unknown')} (Risk: {host.get('risk_score', 0)})")
        lines.append(f"- IPs: {', '.join(host.get('current_ips', []))}")
        lines.append(f"- HTTP: {host.get('http', {}).get('url', 'n/a')}")
        lines.append(f"- Ports: {', '.join([str(p) for p in host.get('ports', [])])}")
        if host.get("nuclei_findings"):
            lines.append("- Nuclei Detections:")
            for finding in host["nuclei_findings"][:5]:
                sev = finding.get("info", {}).get("severity", "unknown")
                name = finding.get("info", {}).get("name", finding.get("template-id", "nuclei"))
                lines.append(f"  - {sev.upper()}: {name} ({finding.get('matched-at', '')})")
        if host.get("risk_factors"):
            lines.append("- Risk Factors:")
            for f in host["risk_factors"][:5]:
                lines.append(f"  - {f}")
        lines.append("")

    if nuclei_results:
        lines.append("## Nuclei Scan Findings")
        lines.append("")
        lines.append("| Severity | Template | Name | Target |")
        lines.append("|----------|----------|------|--------|")
        for r in nuclei_results[:20]:
            sev = r.get("info", {}).get("severity", "").upper()
            tid = r.get("template-id", "")
            name = r.get("info", {}).get("name", "")
            target_url = r.get("matched-at", "")
            lines.append(f"| {sev} | {tid} | {name} | {target_url} |")
        lines.append("")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render markdown and HTML reports from raw attack-surface JSON.")
    parser.add_argument("--input", required=True, help="Raw attack-surface JSON file")
    parser.add_argument("--screenshots", required=True, help="Screenshot manifest JSON path")
    parser.add_argument("--nuclei", help="Nuclei JSONL output path")
    parser.add_argument("--markdown-output", required=True, help="Markdown report path")
    parser.add_argument("--html-output", required=True, help="HTML output path")
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    with open(args.input, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    with open(args.screenshots, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    nuclei_results = []
    if args.nuclei and os.path.isfile(args.nuclei):
        with open(args.nuclei, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    try:
                        nuclei_results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    markdown = markdown_report(payload, manifest, nuclei_results)
    html = html_report(payload, manifest, nuclei_results)

    os.makedirs(os.path.dirname(args.markdown_output), exist_ok=True)
    os.makedirs(os.path.dirname(args.html_output), exist_ok=True)

    with open(args.markdown_output, "w", encoding="utf-8") as handle:
        handle.write(markdown)
    with open(args.html_output, "w", encoding="utf-8") as handle:
        handle.write(html)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
