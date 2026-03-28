# xpray — Pre-Installation Checklist

Everything that must be done before running `sudo bash install.sh`
and before the tool will work correctly on Kali Linux.

---

## 1. Code — Things to finish in your modules first

These are wiring points that main.py expects to exist.
If any of these are missing, the tool will crash on import.

### module_pwn.py must export two things:

```python
# 1. The main entry point
def run_pwn_module(target, attack_mode, focus_port):
    # Must return: (findings_dict, os_guess_str, hostname_str)
    ...

# 2. The nmap helper — called by web-only dispatch too
def _run_nmap_phases(target, attack_mode, focus_port, full_portscan=False):
    # Must return: (open_ports_list, port_service_map_dict, os_guess_str, hostname_str)
    ...
```

### module_postexploit.py must export:

```python
def run_postexploit_module(target, shell_type, ssh_creds, os_guess):
    # Must return a dict with at least these keys:
    # {
    #   "whoami": str,
    #   "privilege": str,       # "root" or "user"
    #   "linpeas": [],          # list of interesting finding strings
    #   "pspy": [],             # list of root process strings
    #   "flag_files": [],       # paths to flag files found
    #   "interesting_files": [] # other interesting paths
    # }
    ...
```

### module_reverse.py must export:

```python
def run_reverse_module(file_path):
    # Must return a findings dict
    ...
```

### module_forensics.py must export:

```python
def run_forensics_module(file_path):
    # Must return a findings dict
    ...
```

### module_crypto.py must export:

```python
def run_crypto_module(file_path):
    # Must return a findings dict
    ...
```

---

## 2. Files — Make sure all these exist in the project root

Run this from your project directory to check:

```bash
ls -1
```

Required files:
```
main.py
common.py
module_web.py
module_pwn.py
module_postexploit.py
module_reverse.py
module_forensics.py
module_crypto.py
module_osint.py
module_pivot.py
module_report.py
install.sh
uninstall.sh
README.md
```

---

## 3. Python — Check your version

```bash
python3 --version
```

Must be 3.10 or later. If not:

```bash
sudo apt update && sudo apt install python3 python3-pip -y
```

---

## 4. Python dependencies — Install manually first to test

```bash
pip3 install rich requests --break-system-packages
```

Verify:

```bash
python3 -c "import rich, requests; print('OK')"
```

---

## 5. Wordlists — rockyou.txt must be unzipped

xpray uses rockyou.txt for hydra and john. On Kali it ships compressed.

Check if it exists already:

```bash
ls -lh /usr/share/wordlists/rockyou.txt
```

If it shows `.gz` or is missing:

```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

Also verify dirb wordlist exists (used by all directory fuzzers):

```bash
ls /usr/share/wordlists/dirb/common.txt
```

If missing:

```bash
sudo apt install dirb -y
```

---

## 6. Quick import test — run before installing

From the project root, test that all modules import cleanly:

```bash
python3 -c "
import common
import module_web
import module_pwn
import module_postexploit
import module_reverse
import module_forensics
import module_crypto
import module_osint
import module_pivot
import module_report
print('All imports OK')
"
```

If any module fails to import, fix the error before installing.
The error message will tell you exactly which file and which line.

---

## 7. Permissions — make scripts executable

```bash
chmod +x install.sh uninstall.sh
```

---

## 8. Install

```bash
sudo bash install.sh
```

---

## 9. Verify it works after install

```bash
which xpray
# Expected: /usr/local/bin/xpray

xpray --help 2>/dev/null || xpray
# Should show the banner and loading sequence
```

---

## 10. Optional but recommended — install missing key tools

xpray skips missing tools automatically, but these are the most
important ones to have for CTF work. Install any that are missing:

```bash
# Web
sudo apt install ffuf gobuster feroxbuster dirsearch nikto nuclei dalfox wfuzz -y

# Metasploit (usually pre-installed on Kali)
sudo apt install metasploit-framework -y

# Enumeration
sudo apt install enum4linux smbclient hydra -y

# Forensics
sudo apt install binwalk exiftool foremost bulk-extractor steghide -y
pip3 install stegseek --break-system-packages 2>/dev/null || true
sudo apt install zsteg -y 2>/dev/null || gem install zsteg

# Reverse
sudo apt install gdb radare2 ltrace strace -y

# Crypto
sudo apt install hashid john hashcat xortool -y

# OSINT
sudo apt install whois dnsenum theharvester -y

# Misc
sudo apt install sshpass redis-tools mongodb-clients -y
```

---

## Summary — minimum to get it running

| Step | Command |
|------|---------|
| Unzip rockyou | `sudo gunzip /usr/share/wordlists/rockyou.txt.gz` |
| Install Python deps | `pip3 install rich requests --break-system-packages` |
| Test imports | `python3 -c "import main"` |
| Install | `sudo bash install.sh` |
| Run | `xpray` |