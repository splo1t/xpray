import re
import shlex
import shutil
from pathlib import Path

from common import flag_scan, print_status, run_tool, toolname


def _extract_architecture(file_out, readelf_out):
    text = f"{file_out}\n{readelf_out}".lower()
    if "x86-64" in text or "x86_64" in text or "amd64" in text:
        return "x64"
    if "80386" in text or "i386" in text or "intel 80386" in text:
        return "x86"
    if "arm" in text or "aarch64" in text:
        return "ARM"
    return "unknown"


def _extract_stripped(file_out):
    low = file_out.lower()
    if "not stripped" in low:
        return "no"
    if "stripped" in low:
        return "yes"
    return "unknown"


def _extract_linked_libraries(readelf_out):
    libs = []
    for line in readelf_out.splitlines():
        m = re.search(r"Shared library: \[(.+?)\]", line)
        if m:
            libs.append(m.group(1))
    return sorted(set(libs))


def _parse_ltrace_strcmp(ltrace_out):
    for line in ltrace_out.splitlines():
        m = re.search(r"(str(?:n)?cmp)\((.+)\)\s*=", line)
        if not m:
            continue
        args_blob = m.group(2)
        args = [x.strip() for x in re.split(r",(?![^\"]*\"(?:,|\))", args_blob)]
        if len(args) >= 2:
            arg1 = args[0].strip().strip('"')
            arg2 = args[1].strip().strip('"')
            print_status("success", f'strcmp: comparing "{arg1}" with "{arg2}"')


def _parse_strace_calls(strace_out):
    for line in strace_out.splitlines():
        stripped = line.strip()
        if stripped.startswith("open(") or stripped.startswith("openat("):
            m = re.search(r"\"([^\"]+)\"", stripped)
            if m:
                print_status("info", f"File access: {m.group(1)}")
        elif stripped.startswith("connect("):
            ip = re.search(r"inet_addr\(\"([^\"]+)\"\)", stripped)
            port = re.search(r"htons\((\d+)\)", stripped)
            if ip:
                dest = ip.group(1)
                if port:
                    dest = f"{dest}:{port.group(1)}"
                print_status("info", f"Network destination: {dest}")
        elif stripped.startswith("read(") or stripped.startswith("write("):
            print_status("info", f"Syscall observed: {stripped[:160]}")


def _parse_objdump_functions(objdump_out):
    funcs = []
    for line in objdump_out.splitlines():
        m = re.search(r"<([A-Za-z0-9_.$@]+)>:", line)
        if m:
            funcs.append(m.group(1))
    unique = sorted(set(funcs))
    if unique:
        preview = ", ".join(unique[:25])
        print_status("success", f"Functions found: {preview}")
    print_status("info", "Full disassembly: /tmp/objdump_out.txt")
    return unique


def _extract_main_disassembly(objdump_out, max_lines=50):
    lines = objdump_out.splitlines()
    start = None
    for i, line in enumerate(lines):
        if "<main>:" in line:
            start = i
            break
    if start is None:
        return ""
    return "\n".join(lines[start : start + max_lines])


def _parse_radare2(radare_out):
    # afl output usually appears before main disassembly in this command output.
    afl_funcs = []
    for line in radare_out.splitlines():
        if re.search(r"\bsym\.", line):
            afl_funcs.append(line.strip())
    if afl_funcs:
        print_status("success", f"radare2 functions: {len(afl_funcs)} entries")


def _write_gdb_script():
    path = f"/tmp/{toolname}_gdb.script"
    script = (
        "set pagination off\n"
        "break main\n"
        "run\n"
        "info registers\n"
        "x/50i $pc\n"
        "continue\n"
        "quit\n"
    )
    Path(path).write_text(script, encoding="utf-8")
    return path


def _parse_gdb_registers(gdb_out):
    reg_lines = []
    for line in gdb_out.splitlines():
        if re.match(r"^(e?[abcds]x|e?ip|e?bp|e?sp|r\d+|rip|rbp|rsp)\s+", line.strip()):
            reg_lines.append(line.strip())
    for line in reg_lines[:20]:
        print_status("success", f"Register: {line}")


def run_reverse_module(file_path):
    results = {
        "file_path": file_path,
        "file_type": "",
        "architecture": "unknown",
        "stripped": "unknown",
        "linked_libraries": [],
        "interesting_strings": [],
        "functions": [],
        "main_disassembly": "",
        "ghidra_output_path": None,
    }

    all_output = []
    fp = Path(file_path)
    if not fp.exists() or not fp.is_file():
        print_status("error", f"File not found: {file_path}")

    # STEP 1 — FILE IDENTIFICATION
    out_file = run_tool(f"file {shlex.quote(file_path)}", 60)
    out_readelf = run_tool(f"readelf -h {shlex.quote(file_path)} 2>/dev/null", 60)
    flag_scan(out_file)
    flag_scan(out_readelf)
    all_output.extend([out_file, out_readelf])

    results["file_type"] = out_file.strip()
    results["architecture"] = _extract_architecture(out_file, out_readelf)
    results["stripped"] = _extract_stripped(out_file)
    results["linked_libraries"] = _extract_linked_libraries(out_readelf)

    print_status("success", f"File type: {results['file_type']}")
    print_status("success", f"Architecture: {results['architecture']}")
    print_status("success", f"Stripped: {results['stripped']}")

    # STEP 2 — STRING EXTRACTION
    run_tool(f"strings {shlex.quote(file_path)} > /tmp/strings_out.txt", 60)
    strings_out = Path("/tmp/strings_out.txt").read_text(encoding="utf-8", errors="replace") if Path("/tmp/strings_out.txt").exists() else ""
    flag_scan(strings_out)
    all_output.append(strings_out)

    interesting_keys = ("http", "ftp", "password", "pass", "key", "secret", "/etc/", "/home/", "strcmp", "flag")
    for line in strings_out.splitlines():
        low = line.lower()
        if any(k in low for k in interesting_keys):
            trimmed = line.strip()
            results["interesting_strings"].append(trimmed)
            print_status("success", f"Interesting string: {trimmed[:220]}")

    # STEP 3 — DYNAMIC ANALYSIS
    out_ltrace = run_tool(
        f"ltrace ./{shlex.quote(file_path)} 2>&1 | tee /tmp/ltrace_out.txt",
        60,
    )
    flag_scan(out_ltrace)
    all_output.append(out_ltrace)
    _parse_ltrace_strcmp(out_ltrace)

    out_strace = run_tool(
        f"strace ./{shlex.quote(file_path)} 2>&1 | tee /tmp/strace_out.txt",
        60,
    )
    flag_scan(out_strace)
    all_output.append(out_strace)
    _parse_strace_calls(out_strace)

    # STEP 4 — STATIC DISASSEMBLY
    run_tool(f"objdump -d {shlex.quote(file_path)} > /tmp/objdump_out.txt 2>/dev/null", 60)
    objdump_out = Path("/tmp/objdump_out.txt").read_text(encoding="utf-8", errors="replace") if Path("/tmp/objdump_out.txt").exists() else ""
    all_output.append(objdump_out)
    results["functions"] = _parse_objdump_functions(objdump_out)
    results["main_disassembly"] = _extract_main_disassembly(objdump_out)
    flag_scan(objdump_out)

    out_radare = run_tool(
        f"radare2 -A -q -c \"afl; pdf @ main\" {shlex.quote(file_path)} 2>/dev/null",
        60,
    )
    all_output.append(out_radare)
    flag_scan(out_radare)
    _parse_radare2(out_radare)

    # STEP 5 — GDB AUTOMATED SESSION
    gdb_script = _write_gdb_script()
    out_gdb = run_tool(
        f"gdb -batch -x {shlex.quote(gdb_script)} ./{shlex.quote(file_path)} 2>/dev/null",
        60,
    )
    all_output.append(out_gdb)
    flag_scan(out_gdb)
    _parse_gdb_registers(out_gdb)

    # STEP 6 — GHIDRA HEADLESS (if available)
    if shutil.which("analyzeHeadless"):
        ghidra_out_path = "/tmp/ghidra_out.txt"
        run_tool(
            "analyzeHeadless /tmp/ghidra_proj TEMP "
            f"-import {shlex.quote(file_path)} "
            "-postScript DecompileAllFunctions.java "
            f"> {shlex.quote(ghidra_out_path)} "
            "-deleteProject 2>/dev/null",
            120,
        )
        ghidra_text = Path(ghidra_out_path).read_text(encoding="utf-8", errors="replace") if Path(ghidra_out_path).exists() else ""
        flag_scan(ghidra_text)
        all_output.append(ghidra_text)
        results["ghidra_output_path"] = ghidra_out_path
        print_status("info", f"Ghidra output: {ghidra_out_path}")

    # Final rule: scan all collected output.
    flag_scan("\n".join(all_output))
    return results
