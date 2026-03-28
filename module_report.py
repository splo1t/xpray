import json
import os
import re
from datetime import datetime
from pathlib import Path

from common import (
    CREDENTIALS,
    CVES,
    FOUND_FLAGS,
    HASHES,
    MISSING_TOOLS,
    OPEN_PORTS,
    PORT_SERVICE_MAP,
    SESSION_DATA_FILE,
    SESSION_DIR,
    SESSION_TARGET,
    SESSION_TIMESTAMP,
    TOOLNAME,
    flag_scan,
    print_status,
    toolname,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _divider(char="═", width=52):
    return char * width


def _section(title):
    return f"\n  [{title}]\n"


def _load_session_data():
    """
    Load the live session_data.json if it exists.
    Falls back gracefully to the in-memory globals if the file
    is missing or unreadable.
    """
    if SESSION_DATA_FILE and Path(SESSION_DATA_FILE).exists():
        try:
            with open(SESSION_DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    # Build a minimal dict from in-memory globals
    return {
        "tool": TOOLNAME,
        "target": SESSION_TARGET,
        "timestamp": SESSION_TIMESTAMP,
        "flags": FOUND_FLAGS,
        "credentials": CREDENTIALS,
        "hashes": HASHES,
        "cves": CVES,
        "missing_tools": MISSING_TOOLS,
        "open_ports": OPEN_PORTS,
        "port_service_map": PORT_SERVICE_MAP,
        "local_ip": None,
    }


def _fmt_port_service_map(psm):
    """
    Normalise PORT_SERVICE_MAP regardless of whether values are
    plain strings or {service, version} dicts.
    Returns list of (port, service, version) tuples sorted by port.
    """
    rows = []
    for port, info in psm.items():
        if isinstance(info, dict):
            service = info.get("service", "unknown")
            version = info.get("version", "")
        else:
            service = str(info)
            version = ""
        rows.append((int(port), service, version))
    rows.sort(key=lambda r: r[0])
    return rows


# ---------------------------------------------------------------------------
# Section builders — each returns a list of lines
# ---------------------------------------------------------------------------

def _build_header(data, category, attack_mode):
    mode_name = {"1": "Stealth", "2": "Normal", "3": "Aggressive"}.get(
        str(attack_mode), attack_mode
    )
    target = data.get("target", "unknown")
    timestamp = data.get("timestamp", SESSION_TIMESTAMP)
    local_ip = data.get("local_ip") or "N/A"

    lines = [
        "",
        f"  {_divider()}",
        f"  {TOOLNAME.upper()} — CTF AUTOMATION REPORT",
        f"  {_divider()}",
        f"  Target         : {target}",
        f"  Category       : {category}",
        f"  Attack Mode    : {mode_name}",
        f"  Date / Time    : {timestamp}",
        f"  Local IP       : {local_ip}",
        f"  {_divider()}",
    ]
    return lines


def _build_host_summary(data, os_guess, hostname):
    lines = [_section("HOST SUMMARY")]
    open_ports = data.get("open_ports", [])
    status = "Alive" if open_ports else "Unknown / Unreachable"
    lines.append(f"  Status    : {status}")
    lines.append(f"  OS Guess  : {os_guess or 'Unknown'}")
    lines.append(f"  Hostname  : {hostname or 'Unknown'}")
    return lines


def _build_ports_and_services(data):
    lines = [_section("OPEN PORTS AND SERVICES")]
    psm = data.get("port_service_map", {})
    if not psm:
        lines.append("  No services detected.")
        return lines
    rows = _fmt_port_service_map(psm)
    for port, service, version in rows:
        ver_str = f"  {version}" if version else ""
        lines.append(f"  {port:<7}/tcp   {service:<20}{ver_str}")
    return lines


def _build_cve_matches(findings):
    lines = [_section("CVE MATCHES")]
    cve_map = findings.get("cve_map", {})
    exploit_suggestions = findings.get("exploit_suggestions", [])

    if not cve_map and not exploit_suggestions:
        lines.append("  No CVE matches found.")
        return lines

    for port, cves in cve_map.items():
        for cve in cves:
            cve_id = cve.get("id", "UNKNOWN")
            score = cve.get("score", "N/A")
            desc = cve.get("description", "")
            short_desc = (desc[:100] + "...") if len(desc) > 100 else desc
            msf = cve.get("msf_module", "")

            lines.append(f"  Port {port} — {cve_id}")
            lines.append(f"    CVSS    : {score}")
            lines.append(f"    Detail  : {short_desc}")
            if msf:
                lines.append(f"    MSF     : {msf}")

    if exploit_suggestions:
        lines.append("")
        lines.append("  Searchsploit Matches:")
        for ex in exploit_suggestions:
            title = ex.get("title", "")
            path = ex.get("path", "")
            lines.append(f"    {title}")
            lines.append(f"      -> {path}")

    return lines


def _build_directories(findings):
    lines = [_section("DIRECTORIES AND ENDPOINTS FOUND")]
    found_paths = findings.get("found_paths", {})
    if not found_paths:
        lines.append("  No directories or endpoints discovered.")
        return lines
    # Sort by status code then path
    for path, code in sorted(found_paths.items(), key=lambda x: (x[1], x[0])):
        lines.append(f"  {path:<45}  (Status: {code})")
    return lines


def _build_vuln_findings(findings):
    lines = [_section("VULNERABILITY FINDINGS")]
    vuln_findings = findings.get("vuln_findings", [])
    sqli_findings = findings.get("sqli_findings", [])

    if not vuln_findings and not sqli_findings:
        lines.append("  No vulnerability findings.")
        return lines

    # Group by source
    by_source = {}
    for item in vuln_findings:
        src = item.get("source", "unknown").upper()
        by_source.setdefault(src, []).append(item)

    for source, items in by_source.items():
        lines.append(f"\n  [{source}]")
        for item in items:
            if source == "NIKTO":
                lines.append(f"    {item.get('detail', '')}")
            elif source == "NUCLEI":
                sev = item.get("severity", "").upper()
                tmpl = item.get("template", "")
                url = item.get("url", "")
                lines.append(f"    [{sev}] {tmpl} -> {url}")
            elif source == "DALFOX":
                param = item.get("parameter", "unknown")
                path = item.get("path", "")
                lines.append(f"    XSS on parameter '{param}' at {path}")
            else:
                lines.append(f"    {json.dumps(item)}")

    if sqli_findings:
        lines.append("\n  [SQLMAP]")
        for s in sqli_findings:
            param = s.get("parameter", "unknown")
            db_type = s.get("db_type", "unknown")
            db_names = s.get("db_names", [])
            lines.append(f"    Parameter : {param}")
            lines.append(f"    DB Type   : {db_type}")
            if db_names:
                lines.append(f"    Databases : {', '.join(db_names)}")

    return lines


def _build_credentials(data):
    lines = [_section("CREDENTIALS FOUND")]
    creds = data.get("credentials", [])
    if not creds:
        lines.append("  No credentials found.")
        return lines
    for c in creds:
        user = c.get("user", "")
        pw = c.get("pass", "")
        source = c.get("source", "")
        lines.append(f"  {user}:{pw}   (Source: {source})")
    return lines


def _build_hashes(data):
    lines = [_section("HASHES")]
    hashes = data.get("hashes", [])
    if not hashes:
        lines.append("  No hashes found.")
        return lines
    for h in hashes:
        val = h.get("value", "")
        htype = h.get("type", "Unknown")
        cracked = h.get("cracked") or "UNCRACKED"
        lines.append(f"  {val}")
        lines.append(f"    Type    : {htype}")
        lines.append(f"    Cracked : {cracked}")
    return lines


def _build_shell_access(findings):
    lines = [_section("SHELL ACCESS")]
    shell_access = findings.get("shell_access", False)
    shell_type = findings.get("shell_type") or "None"
    shell_user = findings.get("shell_user") or "Unknown"
    shell_priv = findings.get("shell_privilege") or "Unknown"

    if not shell_access:
        lines.append("  No shell access obtained.")
        return lines

    lines.append(f"  Type      : {shell_type}")
    lines.append(f"  User      : {shell_user}")
    lines.append(f"  Privilege : {shell_priv}")
    return lines


def _build_post_exploit(findings):
    lines = [_section("POST-EXPLOITATION FINDINGS")]
    post = findings.get("post_exploit", {})
    if not post:
        lines.append("  No post-exploitation data collected.")
        return lines

    linpeas_hits = post.get("linpeas", [])
    pspy_hits = post.get("pspy", [])
    flag_files = post.get("flag_files", [])
    interesting = post.get("interesting_files", [])

    if linpeas_hits:
        lines.append("\n  [LinPEAS]")
        for item in linpeas_hits:
            lines.append(f"    {item}")

    if pspy_hits:
        lines.append("\n  [pspy]")
        for item in pspy_hits:
            lines.append(f"    {item}")

    if flag_files:
        lines.append("\n  [Flag Files Found]")
        for f in flag_files:
            lines.append(f"    {f}")

    if interesting:
        lines.append("\n  [Interesting Files]")
        for f in interesting:
            lines.append(f"    {f}")

    if not any([linpeas_hits, pspy_hits, flag_files, interesting]):
        lines.append("  No post-exploitation data collected.")

    return lines


def _build_flags(data):
    lines = [_section("FLAGS FOUND")]
    flags = data.get("flags", [])
    if not flags:
        lines.append("  No flags found.")
        return lines
    for f in flags:
        lines.append(f"  {f}")
    return lines


def _build_metadata_osint(findings):
    lines = [_section("METADATA AND OSINT FINDINGS")]
    osint = findings.get("osint", {})
    metadata = findings.get("metadata", {})

    has_content = False

    if metadata:
        for key, value in metadata.items():
            lines.append(f"  {key}: {value}")
            has_content = True

    if osint:
        whois = osint.get("whois", {})
        for key, value in whois.items():
            lines.append(f"  {key}: {value}")
            has_content = True

        emails = osint.get("emails", [])
        if emails:
            lines.append(f"  Emails     : {', '.join(emails)}")
            has_content = True

        subdomains = osint.get("subdomains", [])
        if subdomains:
            lines.append(f"  Subdomains : {', '.join(subdomains)}")
            has_content = True

        discovered_ips = osint.get("discovered_ips", [])
        if discovered_ips:
            lines.append(f"  IPs        : {', '.join(discovered_ips)}")
            has_content = True

    if not has_content:
        lines.append("  No metadata or OSINT findings.")

    return lines


def _build_missing_tools(data):
    lines = [_section("MISSING TOOLS")]
    missing = data.get("missing_tools", [])
    if not missing:
        lines.append("  None — all tools present.")
        return lines
    lines.append(f"  {', '.join(missing)}")
    return lines


def _build_next_steps(data, findings):
    """
    Build actionable next steps from everything collected.
    Rules are purely conditional — no guessing.
    """
    lines = [_section("SUGGESTED NEXT STEPS")]
    steps = []

    cve_map = findings.get("cve_map", {})
    exploit_suggestions = findings.get("exploit_suggestions", [])
    creds = data.get("credentials", [])
    hashes = data.get("hashes", [])
    flags = data.get("flags", [])
    found_paths = findings.get("found_paths", {})
    sqli = findings.get("sqli_findings", [])
    vuln_findings = findings.get("vuln_findings", [])
    shell_access = findings.get("shell_access", False)
    post = findings.get("post_exploit", {})
    open_ports = data.get("open_ports", [])

    # Flags found
    if flags:
        steps.append(f"Flag(s) captured: {', '.join(flags)}")

    # CVE with MSF module
    for port, cves in cve_map.items():
        for cve in cves:
            msf = cve.get("msf_module", "")
            cve_id = cve.get("id", "")
            score = cve.get("score", "")
            if msf:
                steps.append(
                    f"{cve_id} (CVSS {score}) on port {port} — "
                    f"run Metasploit module: {msf}"
                )

    # Searchsploit exploits
    for ex in exploit_suggestions[:3]:
        steps.append(
            f"Local exploit available: {ex.get('title', '')} "
            f"-> {ex.get('path', '')}"
        )

    # Credentials found
    for c in creds:
        steps.append(
            f"Credential found ({c.get('source','')}) — try "
            f"{c.get('user','')}:{c.get('pass','')} on all open services"
        )

    # Cracked hashes
    for h in hashes:
        if h.get("cracked"):
            steps.append(
                f"Hash cracked: {h['cracked']} — try as password on all login surfaces"
            )

    # SQLi confirmed
    for s in sqli:
        steps.append(
            f"SQLi confirmed on parameter '{s.get('parameter','')}' "
            f"({s.get('db_type','')}) — dump credentials with: "
            f"sqlmap --dump --output-dir=/tmp/sqlmap_out"
        )

    # XSS found
    xss_hits = [v for v in vuln_findings if v.get("type") == "xss"]
    for x in xss_hits:
        steps.append(
            f"XSS on '{x.get('parameter','')}' at {x.get('path','')} — "
            f"consider cookie stealing or phishing"
        )

    # Login panel found but no creds yet
    login_paths = [
        p for p in found_paths
        if any(k in p.lower() for k in ("login", "admin", "signin"))
    ]
    if login_paths and not creds:
        for p in login_paths[:2]:
            steps.append(
                f"Login panel found at {p} — "
                f"try default credentials: admin:admin, admin:password"
            )

    # Shell obtained — check privilege
    if shell_access:
        priv = findings.get("shell_privilege", "")
        if priv and priv.lower() != "root":
            steps.append(
                "Shell obtained as non-root user — "
                "check sudo -l, SUID binaries, and cron jobs for privesc"
            )
        linpeas_hits = post.get("linpeas", [])
        for hit in linpeas_hits[:3]:
            steps.append(f"LinPEAS finding — investigate: {hit}")

    # No shell yet — suggest manual exploitation
    if not shell_access and (cve_map or exploit_suggestions):
        steps.append(
            "No shell obtained automatically — "
            "review CVE and searchsploit results above for manual exploitation"
        )

    # Open SMB with no creds
    if any(int(p) in (139, 445) for p in open_ports) and not creds:
        steps.append(
            "SMB detected — try null session: "
            "smbclient -L //<target> -N"
        )

    # No findings at all
    if not steps:
        steps.append("No actionable findings. Review raw logs in session directory.")

    for i, step in enumerate(steps, start=1):
        lines.append(f"  {i}. {step}")

    return lines


def _build_footer():
    return [
        "",
        f"  {_divider()}",
        f"  END OF REPORT",
        f"  {_divider()}",
        "",
    ]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_report(
    category="Unknown",
    attack_mode="2",
    findings=None,
    os_guess="",
    hostname="",
    output_dir=None,
):
    """
    Build and save the full xpray session report.

    Parameters
    ----------
    category    : human-readable category name string
    attack_mode : "1", "2", or "3"
    findings    : dict returned by the active module (web/pwn/reverse/etc.)
                  All keys are optional — missing keys produce graceful
                  "nothing found" lines rather than errors.
    os_guess    : OS string from nmap or empty string
    hostname    : hostname string or empty string
    output_dir  : directory to write the report file into.
                  Defaults to the current working directory.

    Returns
    -------
    str  — absolute path of the saved report file.
    """
    if findings is None:
        findings = {}

    data = _load_session_data()

    # Determine output path
    target_slug = re.sub(r"[^a-zA-Z0-9._-]", "_", str(data.get("target", "unknown")))
    timestamp = data.get("timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
    filename = f"{toolname}_report_{target_slug}_{timestamp}.txt"

    if output_dir:
        report_path = Path(output_dir) / filename
    else:
        report_path = Path.cwd() / filename

    # Assemble all sections
    all_lines = []
    all_lines += _build_header(data, category, attack_mode)
    all_lines += _build_host_summary(data, os_guess, hostname)
    all_lines += _build_ports_and_services(data)
    all_lines += _build_cve_matches(findings)
    all_lines += _build_directories(findings)
    all_lines += _build_vuln_findings(findings)
    all_lines += _build_credentials(data)
    all_lines += _build_hashes(data)
    all_lines += _build_shell_access(findings)
    all_lines += _build_post_exploit(findings)
    all_lines += _build_flags(data)
    all_lines += _build_metadata_osint(findings)
    all_lines += _build_missing_tools(data)
    all_lines += _build_next_steps(data, findings)
    all_lines += _build_footer()

    # Scan every line of the report for flags one final time
    full_text = "\n".join(all_lines)
    flag_scan(full_text)

    # Write to file
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(full_text, encoding="utf-8")
    except OSError as e:
        print_status("error", f"Failed to write report: {e}")
        return ""

    print_status("success", f"Report saved: {report_path}")
    return str(report_path)


def print_compact_summary(data=None, findings=None):
    """
    Print a short terminal summary after saving the report.
    Shows only: open ports, credentials, and flags.
    """
    if data is None:
        data = _load_session_data()
    if findings is None:
        findings = {}

    print_status("info", _divider("─", 47))
    print_status("info", "SESSION SUMMARY")
    print_status("info", _divider("─", 47))

    # Open ports
    psm = data.get("port_service_map", {})
    if psm:
        rows = _fmt_port_service_map(psm)
        ports_str = ", ".join(
            f"{p}/{s}" for p, s, _ in rows
        )
        print_status("success", f"Open ports  : {ports_str}")
    else:
        print_status("negative", "Open ports  : none detected")

    # Credentials
    creds = data.get("credentials", [])
    if creds:
        for c in creds:
            print_status("success", f"Credential  : {c.get('user','')}:{c.get('pass','')} ({c.get('source','')})")
    else:
        print_status("negative", "Credentials : none found")

    # Flags
    flags = data.get("flags", [])
    if flags:
        for f in flags:
            print_status("warning", f"Flag        : {f}")
    else:
        print_status("negative", "Flags       : none found")

    print_status("info", _divider("─", 47))