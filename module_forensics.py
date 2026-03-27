import re
import shlex
import zipfile
from pathlib import Path

from common import flag_scan, print_status, run_tool, store_hash


def _safe_read(path):
    p = Path(path)
    if not p.exists() or not p.is_file():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _extract_hash_like_values(text):
    hashes = set()
    for line in text.splitlines():
        token = line.strip()
        if re.fullmatch(r"[a-fA-F0-9]{32,128}", token):
            hashes.add(token)
    return sorted(hashes)


def _list_files_recursive(base_dir):
    p = Path(base_dir)
    if not p.exists():
        return []
    return [str(x) for x in p.rglob("*") if x.is_file()]


def _step_1_metadata(file_path):
    findings = {"file_output": "", "metadata": {}}
    out_file = run_tool(f"file {shlex.quote(file_path)}", 60)
    out_exif = run_tool(f"exiftool {shlex.quote(file_path)}", 60)
    findings["file_output"] = out_file.strip()
    flag_scan(out_file)
    flag_scan(out_exif)

    for line in out_exif.splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        findings["metadata"][key] = val
        flag_scan(val)
        print_status("success", f"Metadata: {key} = {val}")

    return findings


def _step_2_embedded_extraction(file_path, pivot_callback=None):
    extracted = {"binwalk": [], "foremost": [], "bulk_hits": []}

    out_binwalk = run_tool(f"binwalk {shlex.quote(file_path)}", 60)
    flag_scan(out_binwalk)
    has_embedded = any(
        k in out_binwalk.lower() for k in ("squashfs", "gzip", "zip archive", "elf", "filesystem", "uimage", "lzma")
    )
    if has_embedded:
        run_tool(f"binwalk -e {shlex.quote(file_path)} --directory=/tmp/binwalk_out/ -q", 120)
        binwalk_files = _list_files_recursive("/tmp/binwalk_out")
        extracted["binwalk"] = binwalk_files
        for f in binwalk_files:
            print_status("success", f"Binwalk extracted: {f}")
            if pivot_callback:
                pivot_callback(f)

    run_tool(f"foremost -i {shlex.quote(file_path)} -o /tmp/foremost_out/ -q", 120)
    foremost_files = _list_files_recursive("/tmp/foremost_out")
    extracted["foremost"] = foremost_files
    for f in foremost_files:
        print_status("success", f"Foremost recovered: {f}")
        if pivot_callback:
            pivot_callback(f)

    run_tool(f"bulk_extractor {shlex.quote(file_path)} -o /tmp/bulk_out/ -q 2>/dev/null", 120)
    bulk_text = ""
    for report in Path("/tmp/bulk_out").glob("*.txt") if Path("/tmp/bulk_out").exists() else []:
        bulk_text += _safe_read(str(report)) + "\n"
    flag_scan(bulk_text)
    for line in bulk_text.splitlines():
        low = line.lower()
        if "@" in line or "http" in low or re.search(r"\b\d{13,19}\b", line) or re.search(r"\+?\d[\d\s\-]{7,}\d", line):
            extracted["bulk_hits"].append(line.strip())

    return extracted


def _is_image_candidate(file_path, file_output):
    ext = Path(file_path).suffix.lower()
    return "image" in file_output.lower() or ext in {".jpg", ".jpeg", ".png", ".bmp", ".gif"}


def _step_3_stego(file_path):
    stego = {"stegseek_extracted": False, "steghide_password": None, "zsteg_hits": []}

    out_stegseek = run_tool(
        f"stegseek {shlex.quote(file_path)} /usr/share/wordlists/rockyou.txt --output /tmp/steg_out.txt 2>/dev/null",
        120,
    )
    flag_scan(out_stegseek)
    steg_content = _safe_read("/tmp/steg_out.txt")
    if steg_content.strip():
        stego["stegseek_extracted"] = True
        flag_scan(steg_content)
        print_status("success", "Stegseek extracted data")

    for pw in ["", "password", "steghide", "ctf", "flag", "secret"]:
        out = run_tool(
            f"steghide extract -sf {shlex.quote(file_path)} -p {shlex.quote(pw)} -f -q 2>/dev/null",
            30,
        )
        if out is not None:
            extracted_files = [f for f in Path(".").glob("*") if f.is_file() and f.name not in {Path(file_path).name}]
            if extracted_files:
                stego["steghide_password"] = pw
                print_status("success", f"Steghide extracted with password: {pw}")
                for ef in extracted_files:
                    flag_scan(_safe_read(str(ef)))
                break

    ext = Path(file_path).suffix.lower()
    if ext in {".png", ".bmp"}:
        out_zsteg = run_tool(f"zsteg {shlex.quote(file_path)} --all 2>/dev/null", 120)
        flag_scan(out_zsteg)
        for line in out_zsteg.splitlines():
            line = line.strip()
            if not line:
                continue
            stego["zsteg_hits"].append(line)
            if ":" in line:
                channel, value = line.split(":", 1)
                print_status("success", f"zsteg: {channel.strip()} -> {value.strip()[:180]}")

    return stego


def _is_archive_candidate(file_output):
    low = file_output.lower()
    return any(x in low for x in ("zip", "gzip", "bzip2", "rar", "7-zip", "7zip"))


def _step_4_archive_cracking(file_path):
    result = {"password": None, "extracted_files": []}

    # No-password extraction attempt for ZIP.
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            zf.extractall("/tmp/archive_out")
            result["extracted_files"] = _list_files_recursive("/tmp/archive_out")
            for ef in result["extracted_files"]:
                flag_scan(_safe_read(ef))
            return result
    except Exception:
        pass

    run_tool(f"zip2john {shlex.quote(file_path)} > /tmp/zip_hash.txt 2>/dev/null", 60)
    run_tool("john /tmp/zip_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt", 120)
    show = run_tool("john --show /tmp/zip_hash.txt", 60)
    flag_scan(show)

    cracked = None
    for line in show.splitlines():
        if ":" in line and "password hash cracked" not in line.lower():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1].strip():
                cracked = parts[1].strip()
                break

    if cracked:
        result["password"] = cracked
        print_status("success", f"Archive password: {cracked}")
        out = run_tool(f"7z x -y -p{shlex.quote(cracked)} {shlex.quote(file_path)} -o/tmp/archive_out", 120)
        flag_scan(out)
        result["extracted_files"] = _list_files_recursive("/tmp/archive_out")
        for ef in result["extracted_files"]:
            flag_scan(_safe_read(ef))

    return result


def _is_memory_candidate(file_path):
    return Path(file_path).suffix.lower() in {".vmem", ".mem", ".raw", ".dmp"}


def _step_5_memory_forensics(file_path):
    result = {"profile": "", "volatility_findings": []}
    all_text = []

    info_out = run_tool(f"volatility3 -f {shlex.quote(file_path)} windows.info 2>/dev/null", 60)
    if not info_out.strip():
        info_out = run_tool(f"volatility3 -f {shlex.quote(file_path)} linux.info 2>/dev/null", 60)
    flag_scan(info_out)
    all_text.append(info_out)
    result["profile"] = "windows" if "windows" in info_out.lower() else "linux"

    commands = [
        f"volatility3 -f {shlex.quote(file_path)} windows.pslist",
        f"volatility3 -f {shlex.quote(file_path)} windows.cmdline",
        f"volatility3 -f {shlex.quote(file_path)} windows.filescan | grep -i \"flag\\|secret\\|pass\"",
        f"volatility3 -f {shlex.quote(file_path)} windows.hashdump",
    ]
    for cmd in commands:
        out = run_tool(cmd, 120)
        flag_scan(out)
        all_text.append(out)
        for line in out.splitlines():
            s = line.strip()
            if s:
                result["volatility_findings"].append(s)
                print_status("success", f"Volatility finding: {s[:220]}")
        for h in _extract_hash_like_values(out):
            store_hash(h)

    flag_scan("\n".join(all_text))
    return result


def run_forensics_module(file_path, pivot_callback=None):
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        print_status("error", f"File not found: {file_path}")

    results = {
        "file_path": file_path,
        "metadata": {},
        "embedded": {},
        "stego": {},
        "archive": {},
        "memory": {},
    }
    all_output = []

    # STEP 1
    step1 = _step_1_metadata(file_path)
    results["metadata"] = step1["metadata"]
    all_output.append(step1["file_output"])
    all_output.append("\n".join(f"{k}: {v}" for k, v in step1["metadata"].items()))

    # STEP 2
    step2 = _step_2_embedded_extraction(file_path, pivot_callback=pivot_callback)
    results["embedded"] = step2
    all_output.append("\n".join(step2.get("bulk_hits", [])))

    # STEP 3
    if _is_image_candidate(file_path, step1["file_output"]):
        step3 = _step_3_stego(file_path)
        results["stego"] = step3
        all_output.append("\n".join(step3.get("zsteg_hits", [])))

    # STEP 4
    if _is_archive_candidate(step1["file_output"]):
        step4 = _step_4_archive_cracking(file_path)
        results["archive"] = step4
        if step4.get("password"):
            all_output.append(step4["password"])

    # STEP 5
    if _is_memory_candidate(file_path):
        step5 = _step_5_memory_forensics(file_path)
        results["memory"] = step5
        all_output.append("\n".join(step5.get("volatility_findings", [])))

    # Final global scan over all collected module output.
    flag_scan("\n".join(all_output))
    return results
