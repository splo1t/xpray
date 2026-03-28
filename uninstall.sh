#!/bin/bash
# =============================================================
# xpray — uninstall.sh
# =============================================================

TOOL_NAME="xpray"
INSTALL_DIR="/opt/$TOOL_NAME"
BIN_PATH="/usr/local/bin/$TOOL_NAME"

# -------------------------------------------------------------
# Colours
# -------------------------------------------------------------
GREEN="\033[1;32m"
CYAN="\033[1;36m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
RESET="\033[0m"

ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
info() { echo -e "${CYAN}[*]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

# -------------------------------------------------------------
# STEP 1 — Must be run as root
# -------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    err "Please run as root:  sudo bash uninstall.sh"
fi

echo ""
info "Uninstalling $TOOL_NAME..."
echo ""

# -------------------------------------------------------------
# STEP 2 — Remove launcher
# -------------------------------------------------------------
if [ -f "$BIN_PATH" ]; then
    info "Removing launcher: $BIN_PATH"
    rm -f "$BIN_PATH"
    ok "Launcher removed."
else
    warn "Launcher not found at $BIN_PATH — skipping."
fi

# -------------------------------------------------------------
# STEP 3 — Remove install directory
# -------------------------------------------------------------
if [ -d "$INSTALL_DIR" ]; then
    info "Removing install directory: $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
    ok "Install directory removed."
else
    warn "Install directory not found at $INSTALL_DIR — skipping."
fi

# -------------------------------------------------------------
# STEP 4 — Confirm clean
# -------------------------------------------------------------
LEFTOVER=0
[ -f "$BIN_PATH" ]   && warn "Warning: $BIN_PATH still exists." && LEFTOVER=1
[ -d "$INSTALL_DIR" ] && warn "Warning: $INSTALL_DIR still exists." && LEFTOVER=1

echo ""
if [ $LEFTOVER -eq 0 ]; then
    ok "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    ok "$TOOL_NAME has been removed from this system."
    ok "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    warn "Uninstall completed with warnings. Check above."
fi
echo ""