import re
import shlex
from pathlib import Path

from common import (
    MISSING_TOOLS,
    flag_scan,
    print_status,
    run_tool,
)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Patterns used to classify raw text content
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{20,}$")
_HEX_RE    = re.compile(r"^[0-9a-fA-F\s]{20,}$")
_BINARY_RE = re.compile(r"^[01\s]{20,}$")

# Hash-like: 32+ hex chars with no spaces (MD5 / SHA family)
_HASH_RE   = re.compile(r"^[0-9a-fA-F]{32,}$")


def _is_ip(value):
    return bool(_IP_RE.fullmatch(value.strip()))


def _is_file(value):
    p = Path(value.strip())
    return p.exists() and p.is_file()


def _file_type_string(file_path):
    """Return the output of `file <path>` as a lowercase string."""
    out = run_tool(f"file {shlex.quote(str(file_path))} 2>/dev/null", 15)
    return out.lower()


def _strings_head(file_path, lines=20):
    """Return first N lines of strings output for content sniffing."""
    out = run_tool(
        f"strings {shlex.quote(str(file_path))} 2>/dev/null | head -{lines}",
        15,
    )
    return out


def _classify_text_content(content):
    """
    Given a block of text, return the most likely encoding type.
    Returns one of: 'base64', 'hex', 'binary', 'hash', or None.
    """
    stripped = content.strip().replace("\n", "").replace(" ", "")
    if not stripped:
        return None
    if _HASH_RE.fullmatch(stripped):
        return "hash"
    if _BASE64_RE.fullmatch(stripped):
        return "base64"
    if _HEX_RE.fullmatch(stripped.replace(" ", "")):
        return "hex"
    if _BINARY_RE.fullmatch(content.strip()):
        return "binary"
    return None


# ---------------------------------------------------------------------------
# Route decision functions — each returns a module name string or None
# ---------------------------------------------------------------------------

def _route_ip(value):
    """An IP address routes to the PWN module."""
    ping = run_tool(f"ping -c 1 -W 2 {shlex.quote(value)} 2>/dev/null", 10)
    if "1 received" in ping or "1 packets transmitted, 1 received" in ping:
        print_status("success", f"Host {value} is alive")
    else:
        print_status("warning", f"Host {value} did not respond to ping — continuing anyway")
    return "pwn"


def _route_file(file_path):
    """
    Inspect a file and return the correct module name.
    Falls through in priority order defined in the blueprint.
    """
    ft = _file_type_string(file_path)
    flag_scan(ft)

    # ELF / PE executable → reverse engineering
    if "elf" in ft or "pe32" in ft or "executable" in ft:
        return "reverse"

    # Image formats → forensics
    if any(k in ft for k in ("image", "jpeg", "png", "gif", "bitmap", "tiff", "webp")):
        return "forensics"

    # Archive / compressed → forensics
    if any(k in ft for k in ("zip", "archive", "gzip", "bzip2", "xz", "7-zip", "rar", "tar")):
        return "forensics"

    # Packet capture → forensics
    if "pcap" in ft or "tcpdump" in ft or "capture" in ft:
        return "forensics"

    # Audio / video → forensics (may have steg data)
    if any(k in ft for k in ("audio", "video", "mp3", "mp4", "wav", "ogg")):
        return "forensics"

    # PDF → forensics
    if "pdf" in ft:
        return "forensics"

    # ASCII / text — sniff content for encoding
    if "ascii" in ft or "text" in ft or "data" in ft or "unicode" in ft:
        content = _strings_head(file_path, 20)
        flag_scan(content)
        enc = _classify_text_content(content)
        if enc == "hash":
            return "crypto"
        if enc in ("base64", "hex", "binary"):
            return "crypto"
        # Generic text — route to forensics for metadata and string extraction
        return "forensics"

    # Unknown / binary blob — default to forensics
    return "forensics"


# ---------------------------------------------------------------------------
# Mid-session pivot triggers
# ---------------------------------------------------------------------------

def pivot_on_extracted_file(file_path, depth=0):
    """
    Called by the forensics module when binwalk or foremost
    extracts a file mid-session. Recursively routes the
    extracted file into the appropriate module.

    depth caps recursion at 5 levels to prevent infinite loops.
    """
    if depth > 5:
        print_status("warning", "PIVOT: max recursion depth reached — stopping auto-pivot")
        return None

    file_path = str(file_path)
    if not _is_file(file_path):
        return None

    module = _route_file(file_path)
    print_status(
        "info",
        f"PIVOT: extracted file detected → routing to {module.upper()} module",
    )
    return module


def pivot_on_shell_access():
    """
    Called by PWN / web modules when a shell is confirmed.
    Always routes to post-exploitation.
    """
    print_status(
        "warning",
        "PIVOT: shell access detected → switching to POST-EXPLOITATION module",
    )
    return "postexploit"


def pivot_on_encoded_string(text):
    """
    Called whenever any module detects a long string in tool output.
    Auto-decodes and runs flag_scan on the result.
    Returns the decoded string if successful, else None.
    """
    if not text or len(text.strip()) < 20:
        return None

    stripped = text.strip()

    # Try base64
    if _BASE64_RE.fullmatch(stripped.replace("\n", "").replace(" ", "")):
        decoded = run_tool(
            f"echo {shlex.quote(stripped)} | base64 -d 2>/dev/null",
            15,
        )
        if decoded and decoded.isprintable():
            print_status("success", f"Auto-decoded (base64): {decoded.strip()}")
            flag_scan(decoded)
            return decoded

    # Try hex
    clean_hex = stripped.replace(" ", "").replace("\n", "")
    if _HEX_RE.fullmatch(clean_hex) and len(clean_hex) % 2 == 0:
        decoded = run_tool(
            f"echo {shlex.quote(clean_hex)} | xxd -r -p 2>/dev/null",
            15,
        )
        if decoded and decoded.isprintable():
            print_status("success", f"Auto-decoded (hex): {decoded.strip()}")
            flag_scan(decoded)
            return decoded

    # Try binary
    bin_clean = stripped.replace(" ", "").replace("\n", "")
    if _BINARY_RE.fullmatch(stripped) and len(bin_clean) % 8 == 0:
        decoded = run_tool(
            f"python3 -c \""
            f"b='{bin_clean}';"
            f"print(''.join(chr(int(b[i:i+8],2)) for i in range(0,len(b),8)))"
            f"\" 2>/dev/null",
            15,
        )
        if decoded and decoded.strip().isprintable():
            print_status("success", f"Auto-decoded (binary): {decoded.strip()}")
            flag_scan(decoded)
            return decoded

    return None


# ---------------------------------------------------------------------------
# Main pivot engine — entry point
# ---------------------------------------------------------------------------

def run_pivot_engine(user_input):
    """
    Auto-detect the type of user_input and return the module name
    that should handle it.

    Detection order (matches blueprint Section 11 exactly):
      RULE 1 — IPv4 address       → pwn
      RULE 2 — File path          → file type detection
      RULE 3 — Extracted file     → handled by pivot_on_extracted_file()
      RULE 4 — Shell access       → handled by pivot_on_shell_access()
      RULE 5 — Encoded string     → handled by pivot_on_encoded_string()

    This function handles Rules 1 and 2.
    Rules 3–5 are called directly by other modules mid-session.

    Returns a module name string:
      "web", "pwn", "reverse", "forensics", "crypto", "osint",
      "postexploit", or None if undetermined.
    """
    value = str(user_input).strip()

    if not value:
        print_status("warning", "PIVOT: empty input — cannot route")
        return None

    # ── RULE 1 — IP address ──────────────────────────────────────────────
    if _is_ip(value):
        module = _route_ip(value)
        print_status("info", f"PIVOT: IP address detected → routing to {module.upper()} module")
        return module

    # ── RULE 2 — File path ───────────────────────────────────────────────
    if _is_file(value):
        module = _route_file(value)
        print_status("info", f"PIVOT: file detected → routing to {module.upper()} module")
        return module

    # ── RULE 5 inline — bare encoded string (not a file path) ───────────
    enc = _classify_text_content(value)
    if enc:
        print_status("info", f"PIVOT: encoded string ({enc}) detected → routing to CRYPTO module")
        # Attempt immediate decode and flag scan
        pivot_on_encoded_string(value)
        return "crypto"

    # ── Fallback — treat as domain / hostname → OSINT ────────────────────
    if re.search(r"[a-zA-Z]", value):
        print_status("info", "PIVOT: hostname / domain detected → routing to OSINT module")
        return "osint"

    print_status("warning", f"PIVOT: could not determine type of input: {value!r}")
    return None


# ---------------------------------------------------------------------------
# Routing table — maps module names to human labels for display
# ---------------------------------------------------------------------------

MODULE_LABELS = {
    "web":         "Web Exploitation",
    "pwn":         "Network / Boot2Root (Full PWN)",
    "reverse":     "Reverse Engineering",
    "forensics":   "Digital Forensics",
    "osint":       "OSINT",
    "crypto":      "Cryptography",
    "postexploit": "Post-Exploitation",
}


def label_for(module_name):
    """Return the human-readable label for a module name string."""
    return MODULE_LABELS.get(module_name, module_name.upper() if module_name else "Unknown")