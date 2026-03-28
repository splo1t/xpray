#!/usr/bin/env python3
"""
xpray — Full-Cycle CTF Automation Framework
Entry point: banner, dependency check, input flow, module dispatch.
"""

import re
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap: rich must exist before anything else prints
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.text import Text
except ImportError:
    print("[ERROR] 'rich' is not installed. Run: pip3 install rich --break-system-packages")
    sys.exit(1)

console = Console()

# ---------------------------------------------------------------------------
# Common imports (after rich check)
# ---------------------------------------------------------------------------
from common import (
    AVAILABLE_TOOLS,
    FLAG_PATTERNS,
    MISSING_TOOLS,
    TOOLNAME,
    dependency_check,
    detect_local_ip,
    init_session,
    print_status,
    toolname,
)

# ---------------------------------------------------------------------------
# Module imports
# ---------------------------------------------------------------------------
from module_web         import run_web_module
from module_pwn         import run_pwn_module
from module_reverse     import run_reverse_module
from module_forensics   import run_forensics_module
from module_crypto      import run_crypto_module
from module_osint       import run_osint_module
from module_pivot       import run_pivot_engine, label_for
from module_report      import generate_report, print_compact_summary

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BANNER = r"""
  ██╗  ██╗██████╗ ██████╗  █████╗ ██╗   ██╗
  ╚██╗██╔╝██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
   ╚███╔╝ ██████╔╝██████╔╝███████║ ╚████╔╝
   ██╔██╗ ██╔═══╝ ██╔══██╗██╔══██║  ╚██╔╝
  ██╔╝ ██╗██║     ██║  ██║██║  ██║   ██║
  ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
"""

TAGLINE  = "  [ Full-Cycle CTF Automation Framework ]"
VERSION  = "  [ Version 1.0  |  Kali Linux Native   ]"

DEFAULT_FLAG_PATTERNS = [
    r"HTB\{[^}]+\}",
    r"THM\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
]

CATEGORY_NAMES = {
    "1": "Web Exploitation",
    "2": "Network / Boot2Root (Full PWN)",
    "3": "Reverse Engineering",
    "4": "Digital Forensics",
    "5": "OSINT",
    "6": "Cryptography",
    "7": "Auto-Detect (Pivot Engine)",
}

# Full tool list for dependency check
ALL_TOOLS = [
    # recon
    "nmap", "ping", "curl", "wget",
    # web
    "ffuf", "gobuster", "dirsearch", "feroxbuster", "dirb",
    "sqlmap", "dalfox", "nuclei", "wfuzz", "nikto", "whatweb", "wafw00f",
    # pwn
    "msfconsole", "msfvenom", "searchsploit", "hydra",
    "nc", "ssh", "ftp", "smbclient", "enum4linux", "rpcclient",
    "linpeas", "pspy",
    # reverse
    "strings", "file", "ltrace", "strace", "gdb",
    "radare2", "ghidra", "objdump", "readelf",
    # forensics
    "binwalk", "exiftool", "foremost", "bulk_extractor",
    "volatility3", "stegseek", "zsteg", "steghide", "xxd",
    # crypto
    "base64", "xortool", "john", "hashcat", "hashid", "openssl",
    # osint
    "whois", "dnsenum", "theHarvester",
    # utils
    "python3", "pip3", "sshpass", "zip2john", "redis-cli",
    "showmount", "mongo", "psql", "mysql",
]


# ---------------------------------------------------------------------------
# Startup display
# ---------------------------------------------------------------------------

def _spinner(label, duration=1.2):
    """Animate a loading line with a spinner for `duration` seconds."""
    frames = ["|", "/", "-", "\\"]
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        frame = frames[i % len(frames)]
        console.print(
            f"  [cyan][*][/cyan] {label} [cyan]{frame}[/cyan]",
            end="\r",
            highlight=False,
        )
        time.sleep(0.08)
        i += 1
    # Print final done line
    console.print(f"  [cyan][*][/cyan] {label} [green]done[/green]   ", highlight=False)


def show_banner():
    console.print(BANNER, style="bold cyan")
    console.print(TAGLINE, style="bold white")
    console.print(VERSION, style="bold white")
    console.print()


def run_loading_sequence():
    """Metasploit-style animated loading sequence."""
    console.print()
    _spinner("Booting core engine        ", 0.6)
    _spinner("Loading category modules   ", 0.5)

    # Dependency check happens here — real work during the spinner
    dependency_check(ALL_TOOLS)
    _spinner("Verifying installed tools  ", 0.4)

    _spinner("Mounting wordlists         ", 0.4)
    _spinner("Initializing pivot engine  ", 0.4)
    _spinner("CVE database connector     ", 0.4)
    _spinner("Shell manager online       ", 0.3)

    console.print()

    # Report tool availability
    available_count = len(AVAILABLE_TOOLS)
    missing_count   = len(MISSING_TOOLS)

    print_status("success", f"{available_count} tools verified")
    if MISSING_TOOLS:
        print_status("warning", f"Missing tools (will be skipped): {', '.join(MISSING_TOOLS)}")

    console.print()
    console.print(
        f"  [bold green][+][/bold green] All systems ready. Welcome to "
        f"[bold cyan]{TOOLNAME.upper()}[/bold cyan].",
        highlight=False,
    )
    console.print()


# ---------------------------------------------------------------------------
# Input flow
# ---------------------------------------------------------------------------

def show_category_menu():
    print(
        "  ╔══════════════════════════════════════╗\n"
        "  ║   SELECT CATEGORY                    ║\n"
        "  ╠══════════════════════════════════════╣\n"
        "  ║  1. Web Exploitation                 ║\n"
        "  ║  2. Network / Boot2Root (Full PWN)   ║\n"
        "  ║  3. Reverse Engineering              ║\n"
        "  ║  4. Digital Forensics                ║\n"
        "  ║  5. OSINT                            ║\n"
        "  ║  6. Cryptography                     ║\n"
        "  ║  7. Auto-Detect (Pivot Engine)       ║\n"
        "  ╚══════════════════════════════════════╝"
    )


def input_category():
    while True:
        show_category_menu()
        choice = input("  Select category [1-7]: ").strip()
        if choice in CATEGORY_NAMES:
            return choice
        print_status("warning", "Invalid option. Try again.")


def input_target_for_category(category):
    if category in {"1", "2"}:
        while True:
            target = input("  Enter target IP address: ").strip()
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", target):
                break
            print_status("warning", "Invalid IP format. Try again.")

        while True:
            port_raw = input(
                "  Enter specific port to focus on (or press Enter to scan all ports): "
            ).strip()
            if not port_raw:
                port = None
                break
            if port_raw.isdigit():
                port = int(port_raw)
                break
            print_status("warning", "Invalid port. Enter a number or press Enter.")

        return target, port

    if category in {"3", "4", "6"}:
        while True:
            target = input("  Enter full path to target file: ").strip()
            if target and Path(target).exists() and Path(target).is_file():
                return target, None
            print_status("warning", "File not found. Try again.")

    if category == "5":
        while True:
            target = input("  Enter target domain, username, or organization: ").strip()
            if target:
                return target, None
            print_status("warning", "Input cannot be empty.")

    # category == "7"
    while True:
        target = input("  Enter IP address or file path: ").strip()
        if target:
            return target, None
        print_status("warning", "Input cannot be empty.")


def input_flag_patterns():
    raw = input(
        "  Enter flag prefix (e.g. THM{ or HTB{ or just THM).\n"
        "  Press Enter to scan for all common formats: "
    ).strip()

    FLAG_PATTERNS.clear()

    if not raw:
        FLAG_PATTERNS.extend(DEFAULT_FLAG_PATTERNS)
        return FLAG_PATTERNS.copy()

    prefix = "".join(raw.split())
    if not prefix.endswith("{"):
        prefix += "{"
    escaped = re.escape(prefix)
    pattern = rf"{escaped}[^}}]+\}}"
    FLAG_PATTERNS.append(pattern)
    return FLAG_PATTERNS.copy()


def input_attack_mode():
    while True:
        mode = input(
            "  Select attack mode:\n"
            "   1. Stealth    (slower, fewer requests)\n"
            "   2. Normal     (balanced — recommended)\n"
            "   3. Aggressive (fast, maximum coverage)\n"
            "  Enter choice [default: 2]: "
        ).strip()
        if not mode:
            return "2"
        if mode in {"1", "2", "3"}:
            return mode
        print_status("warning", "Invalid option. Try again.")


def confirm_launch(target, category, patterns, attack_mode, port):
    mode_name = {"1": "Stealth", "2": "Normal", "3": "Aggressive"}[attack_mode]
    console.print()
    print_status("info", f"Target      : {target}")
    if port is not None:
        print_status("info", f"Port focus  : {port}")
    print_status("info", f"Category    : {CATEGORY_NAMES[category]}")
    print_status("info", f"Flag format : {', '.join(patterns)}")
    print_status("info", f"Mode        : {mode_name}")
    console.print()

    answer = input("  Launch? [Y/n]: ").strip().lower()
    if answer in {"", "y", "yes"}:
        return True
    print_status("negative", "Aborted.")
    return False


# ---------------------------------------------------------------------------
# Module dispatcher
# ---------------------------------------------------------------------------

def _dispatch(category, target, port, attack_mode, pivot_module=None):
    """
    Route to the correct module based on category (or pivot_module override).
    Returns (findings_dict, category_name_str, os_guess_str, hostname_str).
    """
    # Pivot engine overrides category when category == "7"
    route = pivot_module or category

    findings  = {}
    os_guess  = ""
    hostname  = ""

    # ── 1. Web Exploitation ────────────────────────────────────────────────
    if route in ("1", "web"):
        print_status("info", "─" * 47)
        print_status("info", "Module: Web Exploitation")
        print_status("info", "─" * 47)

        # Nmap runs inside module_pwn — import whichever helper name exists.
        try:
            from module_pwn import _run_nmap_scans as _nmap_fn
        except ImportError:
            try:
                from module_pwn import _run_nmap_phases as _nmap_fn
            except ImportError:
                print_status("error", "module_pwn has no nmap helper (_run_nmap_scans / _run_nmap_phases). Aborting.")
                return {}, CATEGORY_NAMES["1"], "", ""

        # Call without full_portscan — web mode uses fast+deep scans only
        import inspect as _inspect
        _nmap_sig = _inspect.signature(_nmap_fn).parameters
        if "full_portscan" in _nmap_sig:
            open_ports, port_service_map, os_guess, hostname = _nmap_fn(
                target, attack_mode, port, full_portscan=False
            )
        else:
            open_ports, port_service_map, os_guess, hostname = _nmap_fn(
                target, attack_mode, port
            )
        findings = run_web_module(
            target=target,
            open_ports=open_ports,
            port_service_map=port_service_map,
            attack_mode=attack_mode,
            os_guess=os_guess,
        )
        _handle_shell(findings, target, attack_mode, os_guess)
        return findings, CATEGORY_NAMES["1"], os_guess, hostname

    # ── 2. Network / Full PWN ──────────────────────────────────────────────
    if route in ("2", "pwn"):
        print_status("info", "─" * 47)
        print_status("info", "Module: Network / Boot2Root (Full PWN)")
        print_status("info", "─" * 47)

        findings, os_guess, hostname = run_pwn_module(
            target=target,
            attack_mode=attack_mode,
            focus_port=port,
        )
        _handle_shell(findings, target, attack_mode, os_guess)
        return findings, CATEGORY_NAMES["2"], os_guess, hostname

    # ── 3. Reverse Engineering ─────────────────────────────────────────────
    if route in ("3", "reverse"):
        print_status("info", "─" * 47)
        print_status("info", "Module: Reverse Engineering")
        print_status("info", "─" * 47)

        findings = run_reverse_module(file_path=target)
        return findings, CATEGORY_NAMES["3"], "", ""

    # ── 4. Digital Forensics ───────────────────────────────────────────────
    if route in ("4", "forensics"):
        print_status("info", "─" * 47)
        print_status("info", "Module: Digital Forensics")
        print_status("info", "─" * 47)

        findings = run_forensics_module(file_path=target)
        return findings, CATEGORY_NAMES["4"], "", ""

    # ── 5. OSINT ───────────────────────────────────────────────────────────
    if route in ("5", "osint"):
        print_status("info", "─" * 47)
        print_status("info", "Module: OSINT")
        print_status("info", "─" * 47)

        findings = run_osint_module(target=target)

        # Auto-pivot: any IPs discovered → run PWN module on each
        discovered_ips = findings.get("discovered_ips", [])
        if discovered_ips:
            print_status("info", "─" * 47)
            print_status("warning", f"Pivoting to PWN module for {len(discovered_ips)} discovered IP(s)")
            for ip in discovered_ips:
                print_status("info", f"Pivoting to PWN on {ip}")
                pwn_findings, pwn_os, pwn_host = run_pwn_module(
                    target=ip,
                    attack_mode=attack_mode,
                    focus_port=None,
                )
                # Merge any flags / creds found into main findings
                findings.setdefault("pwn_pivot", {})[ip] = pwn_findings

        return findings, CATEGORY_NAMES["5"], "", ""

    # ── 6. Cryptography ────────────────────────────────────────────────────
    if route in ("6", "crypto"):
        print_status("info", "─" * 47)
        print_status("info", "Module: Cryptography")
        print_status("info", "─" * 47)

        findings = run_crypto_module(file_path=target)
        return findings, CATEGORY_NAMES["6"], "", ""

    # ── 7. Auto-Detect (Pivot Engine) ─────────────────────────────────────
    if route == "7":
        print_status("info", "─" * 47)
        print_status("info", "Module: Auto-Detect (Pivot Engine)")
        print_status("info", "─" * 47)

        detected_module = run_pivot_engine(target)
        if not detected_module:
            print_status("error", "Pivot engine could not determine input type. Aborting.")
            return {}, "Unknown", "", ""

        print_status("success", f"Routing to: {label_for(detected_module)}")
        # Re-dispatch using the detected module name as override
        return _dispatch(
            category=category,
            target=target,
            port=port,
            attack_mode=attack_mode,
            pivot_module=detected_module,
        )

    # Fallback — should never reach here
    print_status("error", f"Unknown route: {route!r}")
    return {}, "Unknown", "", ""


def _handle_shell(findings, target, attack_mode, os_guess):
    """
    If a module obtained a shell, automatically trigger post-exploitation.
    Writes post-exploit results back into the findings dict in-place.
    """
    if not findings.get("shell_access"):
        return

    shell_type = findings.get("shell_type", "")
    ssh_creds  = findings.get("ssh_creds")

    print_status("info", "─" * 47)
    print_status("warning", "Shell access confirmed — launching post-exploitation module")
    print_status("info", "─" * 47)

    from module_postexploit import run_postexploit_module

    post_findings = run_postexploit_module(
        target=target,
        shell_type=shell_type,
        ssh_creds=ssh_creds,
        os_guess=os_guess,
    )
    findings["post_exploit"] = post_findings

    # Bubble privilege info up into findings for the report
    findings["shell_user"]      = post_findings.get("whoami", "unknown")
    findings["shell_privilege"] = post_findings.get("privilege", "unknown")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    show_banner()
    run_loading_sequence()

    # Detect local IP early — needed for reverse shells / MSF payloads
    detect_local_ip()

    # ── Input flow ──────────────────────────────────────────────────────────
    category = input_category()
    console.print()

    target, port = input_target_for_category(category)
    console.print()

    patterns = input_flag_patterns()
    console.print()

    attack_mode = input_attack_mode()
    console.print()

    # Initialise session directory now that we have a target
    init_session(target)

    if not confirm_launch(target, category, patterns, attack_mode, port):
        sys.exit(0)

    console.print()
    print_status("info", "=" * 47)
    print_status("success", f"Launching {TOOLNAME.upper()} — target: {target}")
    print_status("info", "=" * 47)
    console.print()

    # ── Dispatch ────────────────────────────────────────────────────────────
    findings, category_name, os_guess, hostname = _dispatch(
        category=category,
        target=target,
        port=port,
        attack_mode=attack_mode,
    )

    # ── Report ──────────────────────────────────────────────────────────────
    console.print()
    print_status("info", "=" * 47)
    print_status("info", "Generating report...")
    print_status("info", "=" * 47)

    report_path = generate_report(
        category=category_name,
        attack_mode=attack_mode,
        findings=findings,
        os_guess=os_guess,
        hostname=hostname,
    )

    print_compact_summary(findings=findings)

    if report_path:
        print_status("success", f"Report saved: {report_path}")

    console.print()
    print_status("success", f"{TOOLNAME.upper()} session complete.")
    console.print()


if __name__ == "__main__":
    main()