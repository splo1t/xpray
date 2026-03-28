<div align="center">

```
  ██╗  ██╗██████╗ ██████╗  █████╗ ██╗   ██╗
  ╚██╗██╔╝██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
   ╚███╔╝ ██████╔╝██████╔╝███████║ ╚████╔╝
   ██╔██╗ ██╔═══╝ ██╔══██╗██╔══██║  ╚██╔╝
  ██╔╝ ██╗██║     ██║  ██║██║  ██║   ██║
  ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
```

**Full-Cycle CTF Automation Framework for Kali Linux**

![Platform](https://img.shields.io/badge/platform-Kali%20Linux-blue?style=flat-square)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/version-1.0-cyan?style=flat-square)

</div>

---

xpray is a logic-driven CLI tool that automates the entire recon-to-report pipeline for CTF competitions. It chains pre-installed Kali Linux tools together based on discovered results — no AI, no guessing, pure conditional logic. Give it a target, it does the rest.

---

## Features

- Automated recon, enumeration, and exploitation chaining
- Seven modes: Web, PWN, Reverse Engineering, Forensics, OSINT, Cryptography, and Auto-Detect
- Auto-pivot engine — detects input type and routes to the correct module automatically
- CVE lookup against the NVD database for every discovered service version
- Metasploit automation with dynamically generated resource scripts
- Post-exploitation with LinPEAS and pspy integration
- Flag detection with regex scanning after every single tool execution
- Structured report generated at the end of every session
- Runs like a native Kali Linux tool after one-command installation

---

## Requirements

- Kali Linux 2023 or later
- Python 3.10 or later
- Root or sudo access for installation
- Internet connection for CVE lookup (optional — tool works fully offline)

---

## Installation

```bash
git clone https://github.com/splo1t/xpray.git
cd xpray
sudo bash install.sh
```

After installation, run from anywhere:

```bash
xpray
```

---

## Uninstall

```bash
sudo bash uninstall.sh
```

---

## Usage

```bash
xpray
```

Follow the interactive prompts:

```
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

[?] Enter target IP address:
[?] Enter flag prefix (e.g. THM{ or HTB{):
[?] Select attack mode (1-3):
```

xpray runs automatically from there. Every finding is printed live. A full report is saved when the session ends.

---

## Categories

| # | Category | Input |
|---|----------|-------|
| 1 | Web Exploitation | IP address |
| 2 | Network / Boot2Root (Full PWN) | IP address |
| 3 | Reverse Engineering | File path |
| 4 | Digital Forensics | File path |
| 5 | OSINT | Domain / username / org |
| 6 | Cryptography | File path |
| 7 | Auto-Detect (Pivot Engine) | IP or file path |

---

## Flag Format Input

xpray accepts partial flag prefixes — you only need to type the opening part:

```
THM{    →  scans for  THM{...}
HTB{    →  scans for  HTB{...}
THM     →  automatically becomes  THM{...}
(Enter) →  scans for all common formats simultaneously
```

Supported default formats: `HTB{}`, `THM{}`, `CTF{}`, `FLAG{}`, `flag{}`, `picoCTF{}`

Flag detection runs after every single tool execution — not at the end of a phase.

---

## Attack Modes

| Mode | Description |
|------|-------------|
| 1 — Stealth | Slower scans, fewer threads, less noise on the network |
| 2 — Normal | Balanced speed and coverage (recommended default) |
| 3 — Aggressive | Maximum threads, fastest scans, full coverage |

---

## Pivot Engine

Category 7 (Auto-Detect) analyses your input and routes automatically:

| Input type | Routed to |
|------------|-----------|
| IPv4 address | PWN module (web sub-module if HTTP found) |
| ELF / PE binary | Reverse Engineering |
| Image (JPEG, PNG, BMP) | Digital Forensics |
| Archive (ZIP, gzip, tar) | Digital Forensics |
| PCAP file | Digital Forensics |
| Base64 / hex / encoded text | Cryptography |
| Domain / hostname | OSINT → discovered IPs pivot to PWN |

The pivot engine also activates mid-session — if binwalk extracts an ELF during forensics, xpray automatically hands it to the reverse engineering module.

---

## Output

All findings are printed live in the terminal during execution:

```
[+]  success / confirmed finding          (green)
[*]  informational / in progress          (cyan)
[!]  vulnerability / flag / alert         (red)
[-]  confirmed negative                   (yellow)
```

A full structured report is saved at the end of every session:

```
xpray_report_<target>_<timestamp>.txt
```

Raw tool logs saved to:

```
/tmp/xpray_<target>_<timestamp>/
```

---

## Report Contents

Every session report includes:

- Target summary and OS detection result
- All open ports with service names and versions
- CVE matches with CVSS scores and short descriptions
- Discovered web directories and endpoints with status codes
- Vulnerability findings from Nikto, Nuclei, sqlmap, and dalfox
- All credentials found across all tools and services
- Hashes found and cracked plaintext values
- Shell access details — type, user, privilege level
- Post-exploitation findings from LinPEAS and pspy
- Every flag matched during the session
- Actionable next steps based on what was found

---

## Tools Used

xpray orchestrates the following pre-installed Kali Linux tools. Missing tools are detected at startup and skipped automatically — the session continues without them.

**Recon**
`nmap` `ping` `curl` `wget`

**Web**
`ffuf` `gobuster` `feroxbuster` `dirsearch` `dirb` `nikto` `nuclei` `whatweb` `wafw00f` `sqlmap` `dalfox` `wfuzz`

**PWN**
`nmap` `msfconsole` `msfvenom` `searchsploit` `hydra` `netcat` `ssh` `ftp` `smbclient` `enum4linux` `rpcclient` `linpeas` `pspy`

**Reverse Engineering**
`strings` `file` `ltrace` `strace` `gdb` `radare2` `ghidra` `objdump` `readelf`

**Digital Forensics**
`binwalk` `exiftool` `foremost` `bulk_extractor` `volatility3` `stegseek` `zsteg` `steghide`

**Cryptography**
`base64` `xortool` `john` `hashcat` `hashid` `openssl` `python3`

**OSINT**
`whois` `dnsenum` `theHarvester` `gobuster`

---

## Project Structure

```
xpray/
├── main.py               ← entry point, banner, input flow, module dispatch
├── common.py             ← all shared functions and global session state
├── module_web.py         ← web exploitation pipeline
├── module_pwn.py         ← network / boot2root full PWN pipeline
├── module_postexploit.py ← post-shell enumeration (SSH + Meterpreter)
├── module_reverse.py     ← reverse engineering pipeline
├── module_forensics.py   ← digital forensics pipeline
├── module_crypto.py      ← cryptography and encoding pipeline
├── module_osint.py       ← OSINT pipeline
├── module_pivot.py       ← auto-detect and mid-session routing
├── module_report.py      ← structured report generation
├── install.sh            ← system-wide installation
├── uninstall.sh          ← clean removal
└── README.md
```

---

## Disclaimer

xpray is intended for use in **legal CTF competitions and authorized penetration testing environments only**.

Appropriate use includes: HackTheBox, TryHackMe, PicoCTF, CTFtime.org events, and lab environments you own or have explicit written permission to test.

**Do not use this tool against systems you do not own or have explicit written permission to test. The author is not responsible for any misuse.**

---

## License

MIT License — see [LICENSE](LICENSE) for details.