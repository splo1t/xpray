import base64
import codecs
import re
import shlex
import socket
import string
from pathlib import Path

from common import FLAG_PATTERNS, flag_scan, print_status, run_tool, store_hash, toolname


HASH_MODE_MAP = {
    "md5": 0,
    "sha1": 100,
    "sha256": 1400,
    "sha512": 1700,
    "bcrypt": 3200,
    "ntlm": 1000,
    "mysql4": 300,
}


def _is_printable_text(value):
    if not value:
        return False
    printable = sum(1 for c in value if c in string.printable)
    return printable / max(len(value), 1) > 0.9


def _read_raw_content(file_path=None, raw_content=None):
    if raw_content is not None:
        return raw_content
    if not file_path:
        return ""
    out = run_tool(f"cat {shlex.quote(file_path)}", 60)
    return out


def _detect_hash_types(raw_content):
    out = run_tool(f"hashid {shlex.quote(raw_content)} 2>/dev/null", 60)
    detected = []
    for line in out.splitlines():
        line_s = line.strip()
        if line_s.startswith("[+]"):
            t = line_s.replace("[+]", "", 1).strip()
            detected.append(t)
            print_status("success", f"Hash type detected: {t}")
    return detected


def _try_base64(text):
    if re.fullmatch(r"[A-Za-z0-9+/=]+", text or "") and len(text.strip()) > 8:
        try:
            decoded = base64.b64decode(text.strip(), validate=False).decode(errors="ignore")
            if _is_printable_text(decoded):
                print_status("success", f"Base64 decoded: {decoded[:220]}")
                flag_scan(decoded)
                return decoded
        except Exception:
            return None
    return None


def _try_hex(text):
    if not re.fullmatch(r"[0-9a-fA-F\s]+", text or ""):
        return None
    compact = re.sub(r"\s+", "", text)
    if len(compact) % 2 != 0:
        return None
    try:
        decoded = bytes.fromhex(compact).decode(errors="ignore")
        if _is_printable_text(decoded):
            print_status("success", f"Hex decoded: {decoded[:220]}")
            flag_scan(decoded)
            return decoded
    except Exception:
        return None
    return None


def _try_binary(text):
    if not re.fullmatch(r"[01\s]+", text or ""):
        return None
    bits = re.sub(r"\s+", "", text)
    if len(bits) < 8 or len(bits) % 8 != 0:
        return None
    try:
        decoded = "".join(chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8))
        if _is_printable_text(decoded):
            print_status("success", f"Binary decoded: {decoded[:220]}")
            flag_scan(decoded)
            return decoded
    except Exception:
        return None
    return None


def _try_rot13(text):
    if not _is_printable_text(text):
        return None
    result = codecs.decode(text, "rot_13")
    print_status("success", f"ROT13: {result[:220]}")
    flag_scan(result)
    return result


def _score_english(text):
    dictionary = {
        "the",
        "and",
        "flag",
        "password",
        "secret",
        "is",
        "you",
        "ctf",
        "this",
        "that",
        "for",
        "with",
        "from",
        "hello",
    }
    words = re.findall(r"[A-Za-z]{2,}", text.lower())
    return sum(1 for w in words if w in dictionary)


def _caesar_shift(text, shift):
    result = []
    for c in text:
        if "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") - shift) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") - shift) % 26 + ord("A")))
        else:
            result.append(c)
    return "".join(result)


def _try_caesar(text):
    if not _is_printable_text(text):
        return None
    best_shift = None
    best_out = None
    best_score = -1
    for s in range(1, 26):
        candidate = _caesar_shift(text, s)
        score = _score_english(candidate)
        if score > best_score:
            best_score = score
            best_shift = s
            best_out = candidate
    if best_out is not None:
        print_status("success", f"Caesar shift {best_shift}: {best_out[:220]}")
        flag_scan(best_out)
    return best_out


def _decode_recursive(raw_content, file_path=None, max_depth=5):
    current = raw_content
    history = []
    for _ in range(max_depth):
        changed = False
        for decoder in (_try_base64, _try_hex, _try_binary):
            out = decoder(current)
            if out and out != current:
                history.append(out)
                current = out
                changed = True
                break
        if changed:
            continue

        # ROT13 and Caesar still run in order in Step 2.
        rot = _try_rot13(current)
        if rot and rot != current:
            history.append(rot)
        cae = _try_caesar(current)
        if cae and cae != current:
            history.append(cae)

        # XOR only if FILE_PATH is available.
        if file_path:
            out_xor = _try_xor(file_path)
            if out_xor:
                history.append(out_xor)
                current = out_xor
                changed = True

        if not changed:
            break
    return current, history


def _select_hash_mode(hash_types):
    lowered = " ".join(hash_types).lower()
    for key, mode in HASH_MODE_MAP.items():
        if key in lowered:
            return mode, key
    return None, None


def _step_3_hash_crack(file_path, raw_content, hash_types):
    if not hash_types:
        return None
    if not file_path:
        # If no file path is provided, use store_hash fallback.
        store_hash(raw_content.strip())
        return {"method": "store_hash", "plaintext": None}

    run_tool(
        f"john {shlex.quote(file_path)} --wordlist=/usr/share/wordlists/rockyou.txt",
        120,
    )
    show = run_tool(f"john --show {shlex.quote(file_path)}", 60)
    for line in show.splitlines():
        if ":" in line and "password hash cracked" not in line.lower():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1].strip():
                plaintext = parts[1].strip()
                print_status("success", f"John cracked: {plaintext}")
                return {"method": "john", "plaintext": plaintext}

    mode, mode_name = _select_hash_mode(hash_types)
    if mode is not None:
        out = run_tool(
            f"hashcat -a 0 -m {mode} {shlex.quote(file_path)} /usr/share/wordlists/rockyou.txt --quiet",
            180,
        )
        for line in out.splitlines():
            if ":" in line:
                plaintext = line.split(":", 1)[1].strip()
                if plaintext:
                    print_status("success", f"Hashcat cracked: {plaintext}")
                    return {"method": f"hashcat-{mode_name}", "plaintext": plaintext}

    print_status("negative", "Hash not cracked with rockyou.txt")
    return {"method": None, "plaintext": None}


def _step_4_openssl(file_path, raw_content):
    if not file_path:
        return None
    if _is_printable_text(raw_content):
        return None

    for password in ["", "password", "admin", "secret", "ctf", "flag", "key"]:
        out = run_tool(
            f"openssl enc -d -aes-256-cbc -in {shlex.quote(file_path)} -pass pass:{shlex.quote(password)} 2>/dev/null",
            60,
        )
        if out and _is_printable_text(out):
            print_status("success", f'OpenSSL decrypted with: "{password}"')
            flag_scan(out)
            return {"password": password, "output": out}
    return None


def _try_xor(file_path):
    out = run_tool(f"xortool {shlex.quote(file_path)} 2>/dev/null", 60)
    key = None
    for line in out.splitlines():
        m = re.search(r"Key:\s*([0-9A-Fa-fx]+)", line)
        if m:
            key = m.group(1).strip()
            break
    if not key:
        return None

    run_tool(
        f"xortool-xor -r {shlex.quote(key)} -f {shlex.quote(file_path)} > /tmp/xor_out.bin 2>/dev/null",
        60,
    )
    strings_out = run_tool("strings /tmp/xor_out.bin", 60)
    flag_scan(strings_out)
    return strings_out


def _step_5_network_crypto():
    choice = input("Is this a network crypto challenge? [y/N]: ").strip().lower()
    if choice not in {"y", "yes"}:
        return None

    server_ip = input("Enter server IP: ").strip()
    server_port = int(input("Enter server port: ").strip())

    received = run_tool(f"nc {shlex.quote(server_ip)} {server_port}", 60)
    Path("/tmp/crypto_challenge.txt").write_text(received, encoding="utf-8", errors="replace")
    print_status("info", f"Connected to {server_ip}:{server_port}")
    flag_scan(received)

    decoded_preview, _ = _decode_recursive(received, max_depth=2)
    flag_scan(decoded_preview)

    solver_path = f"/tmp/{toolname}_crypto_solver.py"
    script = f'''import socket, base64, re

FLAG_PATTERNS = {FLAG_PATTERNS!r}
s = socket.socket()
s.connect(("{server_ip}", {server_port}))
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

        stripped = data.strip()
        try:
            decoded = base64.b64decode(stripped).decode()
            print("[+] Decoded:", decoded)
            s.send((decoded + "\\n").encode())
        except Exception:
            pass

    except socket.timeout:
        break

print("[*] Full output saved.")
with open("/tmp/crypto_challenge.txt","w") as f:
    f.write(full_output)
'''
    Path(solver_path).write_text(script, encoding="utf-8")

    solver_out = run_tool(f"python3 {shlex.quote(solver_path)}", 120)
    flag_scan(solver_out)
    found = []
    for pat in FLAG_PATTERNS:
        found.extend(re.findall(pat, solver_out))
    for f in sorted(set(found)):
        print_status("success", f"FLAG RECEIVED FROM SERVER: {f}")

    return {
        "server_ip": server_ip,
        "server_port": server_port,
        "solver_path": solver_path,
        "solver_output": solver_out,
    }


def run_crypto_module(file_path=None, raw_content=None):
    results = {
        "raw_content": "",
        "hash_types": [],
        "decoded_content": "",
        "decode_history": [],
        "hash_crack": None,
        "openssl_result": None,
        "network_result": None,
    }

    raw = _read_raw_content(file_path=file_path, raw_content=raw_content)
    results["raw_content"] = raw
    flag_scan(raw)

    # Step 1
    hash_types = _detect_hash_types(raw)
    results["hash_types"] = hash_types

    # Step 2
    decoded, history = _decode_recursive(raw, file_path=file_path, max_depth=5)
    results["decoded_content"] = decoded
    results["decode_history"] = history

    # Step 3
    results["hash_crack"] = _step_3_hash_crack(file_path, raw, hash_types)

    # Step 4
    results["openssl_result"] = _step_4_openssl(file_path, raw)

    # Step 5
    results["network_result"] = _step_5_network_crypto()

    # Final module-level scan.
    aggregate = "\n".join(
        [
            raw or "",
            decoded or "",
            "\n".join(history),
            str(results["hash_crack"]),
            str(results["openssl_result"]),
            str(results["network_result"]),
        ]
    )
    flag_scan(aggregate)
    return results
