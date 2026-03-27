import json
import os
import re
import shlex
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import requests
from rich.console import Console

TOOLNAME = "xpray"
toolname = "xpray"

console = Console()

MISSING_TOOLS = []
AVAILABLE_TOOLS = []
FLAG_PATTERNS = []
FOUND_FLAGS = []
CREDENTIALS = []
HASHES = []
CVES = []

OPEN_PORTS = []
PORT_SERVICE_MAP = {}

SESSION_TARGET = "unknown"
SESSION_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
SESSION_DIR = ""
SESSION_OUT_FILE = ""
SESSION_DATA_FILE = ""
LOCAL_IP = None


def _session_target_slug(target):
    cleaned = str(target).strip().replace(" ", "_")
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "_", cleaned)
    return cleaned or "unknown"


def init_session(target):
    global SESSION_TARGET, SESSION_TIMESTAMP, SESSION_DIR, SESSION_OUT_FILE, SESSION_DATA_FILE
    SESSION_TARGET = _session_target_slug(target)
    SESSION_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
    SESSION_DIR = f"/tmp/{toolname}_{SESSION_TARGET}_{SESSION_TIMESTAMP}"
    SESSION_OUT_FILE = f"{SESSION_DIR}/{toolname}_out.txt"
    SESSION_DATA_FILE = f"{SESSION_DIR}/session_data.json"
    Path(SESSION_DIR).mkdir(parents=True, exist_ok=True)
    Path(SESSION_OUT_FILE).touch(exist_ok=True)
    _write_session_data()
    return SESSION_DIR


def _ensure_session():
    if not SESSION_DIR:
        init_session("unknown")


def _write_session_data():
    _ensure_session()
    data = {
        "tool": TOOLNAME,
        "target": SESSION_TARGET,
        "timestamp": SESSION_TIMESTAMP,
        "flags": FOUND_FLAGS,
        "credentials": CREDENTIALS,
        "hashes": HASHES,
        "cves": CVES,
        "missing_tools": MISSING_TOOLS,
        "available_tools": AVAILABLE_TOOLS,
        "open_ports": OPEN_PORTS,
        "port_service_map": PORT_SERVICE_MAP,
        "local_ip": LOCAL_IP,
    }
    with open(SESSION_DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _append_session_output(text):
    _ensure_session()
    with open(SESSION_OUT_FILE, "a", encoding="utf-8", errors="replace") as f:
        f.write(text)
        if not text.endswith("\n"):
            f.write("\n")


def print_status(status_type, message):
    if status_type == "success":
        console.print(f"[+] {message}", style="green")
    elif status_type == "info":
        console.print(f"[*] {message}", style="cyan")
    elif status_type == "warning":
        console.print(f"[!] {message}", style="red")
    elif status_type == "negative":
        console.print(f"[-] {message}", style="yellow")
    elif status_type == "error":
        console.print(f"[ERROR] {message}", style="red bold")
        raise SystemExit(1)
    else:
        console.print(f"[*] {message}", style="cyan")


def run_tool(command, timeout_seconds):
    _ensure_session()
    tool = shlex.split(command)[0] if command.strip() else "unknown"
    if tool and shutil.which(tool) is None:
        _append_session_output(f"SKIPPED: {tool}\n")
        return ""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=True,
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        _append_session_output(f"$ {command}\n{stdout}{stderr}")
        if result.returncode != 0 and not stdout.strip():
            return ""
        return stdout
    except FileNotFoundError:
        _append_session_output(f"SKIPPED: {tool}\n")
        return ""
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        _append_session_output(f"$ {command}\n{stdout}{stderr}\n[timeout]")
        print_status("info", f"{tool} timed out")
        return stdout


def flag_scan(text):
    if not text:
        return []
    new_matches = []
    for pattern in FLAG_PATTERNS:
        matches = re.findall(pattern, text)
        for match in matches:
            if match not in FOUND_FLAGS:
                FOUND_FLAGS.append(match)
                new_matches.append(match)
                print_status("warning", "FLAG FOUND: " + match)
    if new_matches:
        _write_session_data()
    return new_matches


def store_cred(username, password, source_tool):
    cred = {"user": username, "pass": password, "source": source_tool}
    if cred not in CREDENTIALS:
        CREDENTIALS.append(cred)
        print_status(
            "success",
            "Credential found: " + username + ":" + password + " via " + source_tool,
        )
        # Modules can consume this state for immediate credential reuse.
        _write_session_data()


def _detect_hash_type(hash_value):
    output = run_tool(f"hashid {shlex.quote(hash_value)}", 60)
    if not output:
        return "Unknown"
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("[+]"):
            return line.replace("[+]", "", 1).strip()
    return "Unknown"


def _try_crack_with_john(hash_value):
    tmp_hash_file = f"/tmp/{toolname}_hash_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(tmp_hash_file, "w", encoding="utf-8") as f:
        f.write(hash_value + "\n")
    run_tool(f"john --wordlist=/usr/share/wordlists/rockyou.txt {shlex.quote(tmp_hash_file)}", 120)
    john_show = run_tool(f"john --show {shlex.quote(tmp_hash_file)}", 60)
    try:
        os.remove(tmp_hash_file)
    except OSError:
        pass
    if not john_show:
        return None
    for line in john_show.splitlines():
        if ":" in line and "password hash cracked" not in line.lower():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1].strip():
                return parts[1].strip()
    return None


def _try_crack_with_hashcat(hash_value):
    # Generic fallback mode; modules can later supply exact mode when known.
    tmp_hash_file = f"/tmp/{toolname}_hashcat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    pot_file = f"/tmp/{toolname}_hashcat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pot"
    with open(tmp_hash_file, "w", encoding="utf-8") as f:
        f.write(hash_value + "\n")
    run_tool(
        f"hashcat -m 0 -a 0 {shlex.quote(tmp_hash_file)} /usr/share/wordlists/rockyou.txt --potfile-path {shlex.quote(pot_file)} --force",
        180,
    )
    show = run_tool(
        f"hashcat -m 0 --show {shlex.quote(tmp_hash_file)} --potfile-path {shlex.quote(pot_file)}",
        60,
    )
    for p in (tmp_hash_file, pot_file):
        try:
            os.remove(p)
        except OSError:
            pass
    if not show:
        return None
    for line in show.splitlines():
        if ":" in line:
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[1].strip():
                return parts[1].strip()
    return None


def store_hash(hash_value):
    hash_type = _detect_hash_type(hash_value)
    entry = {"value": hash_value, "type": hash_type, "cracked": None}
    HASHES.append(entry)

    plaintext = _try_crack_with_john(hash_value)
    if not plaintext:
        plaintext = _try_crack_with_hashcat(hash_value)

    if plaintext:
        entry["cracked"] = plaintext
        print_status("success", "Hash cracked: " + plaintext)

    _write_session_data()
    return entry


def detect_local_ip():
    global LOCAL_IP
    output = run_tool("ip route get 1 2>/dev/null | awk '{print $7; exit}'", 10).strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", output):
        LOCAL_IP = output
        _write_session_data()
        return LOCAL_IP
    LOCAL_IP = input("Enter your local IP (for reverse shells): ").strip()
    _write_session_data()
    return LOCAL_IP


def dependency_check(tool_list):
    availability = {}
    for tool in tool_list:
        exists = shutil.which(tool) is not None
        availability[tool] = exists
        if exists:
            if tool not in AVAILABLE_TOOLS:
                AVAILABLE_TOOLS.append(tool)
        else:
            if tool not in MISSING_TOOLS:
                MISSING_TOOLS.append(tool)
    _write_session_data()
    return availability


def fetch_cve(service, version):
    query = f"{service} {version}".strip()
    cve_results = []
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": query, "resultsPerPage": 10},
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json()
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            description = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            score = None
            metrics = cve.get("metrics", {})
            if metrics.get("cvssMetricV31"):
                score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore")
            elif metrics.get("cvssMetricV30"):
                score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore")
            elif metrics.get("cvssMetricV2"):
                score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore")
            cve_results.append({"id": cve_id, "score": score, "description": description})
    except Exception:
        ss_output = run_tool(f"searchsploit {shlex.quote(query)}", 60)
        for line in ss_output.splitlines():
            if "|" in line and "----" not in line:
                cve_results.append({"id": "SEARCHSPLOIT", "score": None, "description": line.strip()})

    CVES.extend(cve_results)
    _write_session_data()
    return cve_results
