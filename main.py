import re
import sys
from pathlib import Path

from common import FLAG_PATTERNS, TOOLNAME, init_session, print_status


DEFAULT_FLAG_PATTERNS = [
    r"HTB\{[^}]+\}",
    r"THM\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
]

CATEGORY_NAMES = {
    "1": "Web Exploitation",
    "2": "Network / Boot2Root (Full PWN)",
    "3": "Reverse Engineering",
    "4": "Digital Forensics",
    "5": "OSINT",
    "6": "Cryptography",
    "7": "Auto-Detect (Pivot Engine)",
}


def show_category_menu():
    print(
        "  ╔══════════════════════════════════════╗\n"
        "  ║   SELECT CATEGORY                    ║\n"
        "  ╠══════════════════════════════════════╣\n"
        "  ║  1. Web Exploitation                 ║\n"
        "  ║  2. Network / Boot2Root (Full PWN)   ║\n"
        "  ║  3. Reverse Engineering              ║\n"
        "  ║  4. Digital Forensics                ║\n"
        "  ║  5. OSINT                            ║\n"
        "  ║  6. Cryptography                     ║\n"
        "  ║  7. Auto-Detect (Pivot Engine)       ║\n"
        "  ╚══════════════════════════════════════╝"
    )


def input_category():
    while True:
        show_category_menu()
        choice = input("Select category [1-7]: ").strip()
        if choice in CATEGORY_NAMES:
            return choice
        print_status("warning", "Invalid option. Try again.")


def input_target_for_category(category):
    if category in {"1", "2"}:
        while True:
            target = input("Enter target IP address: ").strip()
            if re.fullmatch(r"^\d{1,3}(\.\d{1,3}){3}$", target):
                break
            print_status("warning", "Invalid IP format.")

        while True:
            port_input = input(
                "Enter specific port to focus on (or press Enter to scan all ports): "
            ).strip()
            if not port_input:
                port = None
                break
            if port_input.isdigit():
                port = int(port_input)
                break
            print_status("warning", "Invalid port. Enter a numeric value or press Enter.")

        return target, port

    if category in {"3", "4", "6"}:
        while True:
            target = input("Enter full path to target file: ").strip()
            if target and Path(target).exists() and Path(target).is_file():
                return target, None
            print_status("warning", "File not found. Re-prompt.")

    if category == "5":
        while True:
            target = input("Enter target domain, username, or organization: ").strip()
            if target:
                return target, None
            print_status("warning", "Input cannot be empty.")

    # category == "7"
    while True:
        target = input("Enter IP address or file path: ").strip()
        if target:
            return target, None
        print_status("warning", "Input cannot be empty.")


def input_flag_patterns():
    raw = input(
        "Enter flag prefix (e.g. THM{ or HTB{ or just THM).\n"
        "Press Enter to scan for all common formats: "
    )
    raw = raw.strip()

    FLAG_PATTERNS.clear()
    if not raw:
        FLAG_PATTERNS.extend(DEFAULT_FLAG_PATTERNS)
        return FLAG_PATTERNS.copy()

    prefix = "".join(raw.split())
    if not prefix.endswith("{"):
        prefix += "{"
    escaped = re.escape(prefix)
    pattern = rf"{escaped}[^}}]+\}}"
    FLAG_PATTERNS.append(pattern)
    return FLAG_PATTERNS.copy()


def input_attack_mode():
    while True:
        mode = input(
            "Select attack mode:\n"
            " 1. Stealth    (slower, fewer requests)\n"
            " 2. Normal     (balanced — recommended)\n"
            " 3. Aggressive (fast, maximum coverage)\n"
            "Enter choice [default: 2]: "
        ).strip()
        if not mode:
            return "2"
        if mode in {"1", "2", "3"}:
            return mode
        print_status("warning", "Invalid option. Try again.")


def confirm_launch(target, category, patterns, attack_mode, port):
    attack_mode_name = {"1": "Stealth", "2": "Normal", "3": "Aggressive"}[attack_mode]

    print_status("info", f"Target      : {target}")
    if port is not None:
        print_status("info", f"Port focus  : {port}")
    print_status("info", f"Category    : {CATEGORY_NAMES[category]}")
    print_status("info", f"Flag format : {', '.join(patterns)}")
    print_status("info", f"Mode        : {attack_mode_name}")

    launch = input("Launch? [Y/n]: ").strip().lower()
    if launch in {"", "y", "yes"}:
        return True
    if launch == "n":
        print_status("negative", "Aborted.")
        return False
    print_status("negative", "Aborted.")
    return False


def main():
    print_status("info", f"{TOOLNAME} input flow initialized.")

    category = input_category()
    target, port = input_target_for_category(category)
    patterns = input_flag_patterns()
    attack_mode = input_attack_mode()

    init_session(target)

    if not confirm_launch(target, category, patterns, attack_mode, port):
        sys.exit(0)

    print_status("success", "Launch confirmed. Module execution wiring comes next.")


if __name__ == "__main__":
    main()
