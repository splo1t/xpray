import re
import shlex

from common import (
    MISSING_TOOLS,
    flag_scan,
    print_status,
    run_tool,
    store_cred,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_whois(output):
    """Extract key registrant fields from whois output."""
    fields = {}
    wanted = {
        "registrant",
        "registrar",
        "admin",
        "tech",
        "name server",
        "nameserver",
        "nserver",
        "creation date",
        "updated date",
        "expiry date",
        "expiration date",
        "registrant email",
        "admin email",
        "org",
        "organisation",
        "organization",
        "country",
        "phone",
    }
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key_clean = key.strip().lower()
        value_clean = value.strip()
        if not value_clean:
            continue
        for w in wanted:
            if w in key_clean:
                # Keep first occurrence per key to avoid duplicate spam
                if key_clean not in fields:
                    fields[key_clean] = value_clean
                break
    return fields


def _parse_dns_records(output):
    """Pull A, MX, NS, TXT records and subdomains from dnsenum output."""
    records = []
    patterns = [
        # A record:  hostname  TTL  IN  A  ip
        (r"(\S+)\s+\d+\s+IN\s+A\s+(\S+)", "A"),
        # MX
        (r"(\S+)\s+\d+\s+IN\s+MX\s+\d+\s+(\S+)", "MX"),
        # NS
        (r"(\S+)\s+\d+\s+IN\s+NS\s+(\S+)", "NS"),
        # TXT (grab the whole quoted block)
        (r"(\S+)\s+\d+\s+IN\s+TXT\s+(.+)", "TXT"),
    ]
    for line in output.splitlines():
        for pat, rtype in patterns:
            m = re.search(pat, line, re.I)
            if m:
                records.append({"type": rtype, "name": m.group(1), "value": m.group(2).strip()})
                break
    return records


def _parse_harvester(output):
    """Extract emails, subdomains, IPs from theHarvester output."""
    emails = []
    subdomains = []
    ips = []

    email_pat = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    ip_pat = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    # Subdomain lines typically start with a hostname token
    sub_pat = re.compile(r"^\s*([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\s*$")

    for line in output.splitlines():
        line_stripped = line.strip()

        # Emails take priority
        found_emails = email_pat.findall(line_stripped)
        for e in found_emails:
            if e not in emails:
                emails.append(e)
            continue

        # IPs
        found_ips = ip_pat.findall(line_stripped)
        for ip in found_ips:
            if ip not in ips:
                ips.append(ip)

        # Subdomains
        if sub_pat.match(line_stripped) and line_stripped not in subdomains:
            subdomains.append(line_stripped)

    return emails, subdomains, ips


def _parse_gobuster_dns(output):
    """Extract valid subdomains from gobuster dns output."""
    subdomains = []
    for line in output.splitlines():
        # gobuster dns lines: Found: subdomain.domain.tld
        m = re.search(r"Found:\s*(\S+)", line, re.I)
        if m:
            sub = m.group(1).strip()
            if sub not in subdomains:
                subdomains.append(sub)
    return subdomains


# ---------------------------------------------------------------------------
# Step functions
# ---------------------------------------------------------------------------

def _step_1_whois(target):
    print_status("info", f"Running whois on {target}")
    out = run_tool(f"whois {shlex.quote(target)} 2>/dev/null", 60)
    flag_scan(out)
    fields = _parse_whois(out)
    for key, value in fields.items():
        print_status("success", f"Whois: {key} = {value}")
    return fields


def _step_2_dns_enum(target):
    print_status("info", f"Running dnsenum on {target}")
    out = run_tool(f"dnsenum {shlex.quote(target)} 2>/dev/null", 120)
    flag_scan(out)
    records = _parse_dns_records(out)
    discovered_ips = []
    for rec in records:
        print_status("success", f"DNS {rec['type']}: {rec['name']} -> {rec['value']}")
        # Collect A record IPs for pivot
        if rec["type"] == "A":
            ip = rec["value"].strip().rstrip(".")
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip) and ip not in discovered_ips:
                discovered_ips.append(ip)
    return records, discovered_ips


def _step_3_harvester(target):
    print_status("info", f"Running theHarvester on {target}")
    out = run_tool(
        f"theHarvester -d {shlex.quote(target)} -b all -l 200 2>/dev/null",
        120,
    )
    flag_scan(out)
    emails, subdomains, ips = _parse_harvester(out)

    if emails:
        print_status("success", f"Emails found: {', '.join(emails)}")
    if subdomains:
        print_status("success", f"Subdomains found: {', '.join(subdomains)}")
    if ips:
        print_status("success", f"IPs found: {', '.join(ips)}")

    return emails, subdomains, ips


def _step_4_subdomain_brute(target):
    """Brute-force subdomains with gobuster dns."""
    print_status("info", f"Running gobuster DNS brute-force on {target}")
    out = run_tool(
        f"gobuster dns -d {shlex.quote(target)} "
        "-w /usr/share/wordlists/dirb/common.txt -q 2>/dev/null",
        180,
    )
    flag_scan(out)
    subdomains = _parse_gobuster_dns(out)
    for sub in subdomains:
        print_status("success", f"Subdomain: {sub}")
    return subdomains


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_osint_module(target):
    """
    Full OSINT pipeline.
    Returns a findings dict with all collected data.
    Discovered IPs are returned so the caller (pivot/main) can
    route them into the PWN module automatically.
    """
    print_status("info", "─" * 47)
    print_status("info", "Starting OSINT module")
    print_status("info", "─" * 47)

    findings = {
        "whois": {},
        "dns_records": [],
        "emails": [],
        "subdomains": [],
        "ips": [],
        "discovered_ips": [],   # IPs to pivot into PWN module
    }

    # Step 1 — whois
    whois_fields = _step_1_whois(target)
    findings["whois"] = whois_fields

    # Step 2 — dnsenum
    if "dnsenum" not in MISSING_TOOLS:
        dns_records, dns_ips = _step_2_dns_enum(target)
        findings["dns_records"] = dns_records
        for ip in dns_ips:
            if ip not in findings["discovered_ips"]:
                findings["discovered_ips"].append(ip)
    else:
        print_status("negative", "dnsenum not available — skipping DNS enumeration")

    # Step 3 — theHarvester
    if "theHarvester" not in MISSING_TOOLS:
        emails, subdomains, harvester_ips = _step_3_harvester(target)
        # Merge, deduplicate
        for e in emails:
            if e not in findings["emails"]:
                findings["emails"].append(e)
        for s in subdomains:
            if s not in findings["subdomains"]:
                findings["subdomains"].append(s)
        for ip in harvester_ips:
            if ip not in findings["ips"]:
                findings["ips"].append(ip)
            if ip not in findings["discovered_ips"]:
                findings["discovered_ips"].append(ip)
    else:
        print_status("negative", "theHarvester not available — skipping asset harvesting")

    # Step 4 — gobuster DNS brute-force
    if "gobuster" not in MISSING_TOOLS:
        brute_subs = _step_4_subdomain_brute(target)
        for s in brute_subs:
            if s not in findings["subdomains"]:
                findings["subdomains"].append(s)
    else:
        print_status("negative", "gobuster not available — skipping subdomain brute-force")

    # Step 5 — pivot notice
    if findings["discovered_ips"]:
        print_status("info", "─" * 47)
        print_status(
            "warning",
            f"PIVOT: {len(findings['discovered_ips'])} IP(s) discovered — "
            "route to PWN module for full enumeration",
        )
        for ip in findings["discovered_ips"]:
            print_status("info", f"  -> {ip}")

    # Final summary
    print_status("info", "─" * 47)
    print_status("info", "OSINT module complete")
    print_status("success", f"Emails     : {len(findings['emails'])}")
    print_status("success", f"Subdomains : {len(findings['subdomains'])}")
    print_status("success", f"IPs        : {len(findings['discovered_ips'])}")

    return findings