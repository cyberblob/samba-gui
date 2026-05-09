#!/usr/bin/env bash
#
# uninstall.sh — Uninstall samba-gui
#
# Usage:
#   ./uninstall.sh          # remove the package and user-local files
#   ./uninstall.sh --purge  # also remove backups and user config
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

PURGE=false
if [ "${1:-}" = "--purge" ]; then
    PURGE=true
fi

# ── Remove the .deb package ──────────────────────────────────────────

if dpkg -s samba-gui >/dev/null 2>&1; then
    info "Removing samba-gui package..."
    sudo apt remove -y samba-gui
    info "Package removed."
else
    warn "samba-gui package is not installed (skipping apt remove)."
fi

# ── Remove user-local icons ──────────────────────────────────────────

info "Removing user-local icons..."
ICON_DIRS=(
    "$HOME/.local/share/icons/hicolor/48x48/apps"
    "$HOME/.local/share/icons/hicolor/64x64/apps"
    "$HOME/.local/share/icons/hicolor/128x128/apps"
    "$HOME/.local/share/icons/hicolor/256x256/apps"
)

for dir in "${ICON_DIRS[@]}"; do
    if [ -f "$dir/com.example.samba-gui.png" ]; then
        rm -f "$dir/com.example.samba-gui.png"
    fi
done

# Rebuild icon cache if the directory exists
if [ -d "$HOME/.local/share/icons/hicolor" ]; then
    gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor/" 2>/dev/null || true
fi

info "User-local icons removed."

# ── Remove system icon cache (handled by apt, but refresh just in case) ──

if [ -d /usr/share/icons/hicolor ]; then
    sudo gtk-update-icon-cache -f -t /usr/share/icons/hicolor/ 2>/dev/null || true
fi

# ── Purge optional data ──────────────────────────────────────────────

if [ "$PURGE" = true ]; then
    info "Purging backups and user configuration..."

    # System backups
    if [ -d /var/backups/samba ]; then
        sudo rm -rf /var/backups/samba
        info "Removed /var/backups/samba"
    fi

    # User-local backups
    LOCAL_BACKUP="$HOME/.local/share/samba-gui/backups"
    if [ -d "$LOCAL_BACKUP" ]; then
        rm -rf "$LOCAL_BACKUP"
        info "Removed $LOCAL_BACKUP"
    fi

    # User config (templates override, etc.)
    USER_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/samba-gui"
    if [ -d "$USER_CONFIG" ]; then
        rm -rf "$USER_CONFIG"
        info "Removed $USER_CONFIG"
    fi

    # Remove the parent directory if empty
    rmdir "$HOME/.local/share/samba-gui" 2>/dev/null || true

    info "Purge complete."
else
    echo ""
    info "Backups and user config were preserved."
    info "To remove everything: ./uninstall.sh --purge"
fi

echo ""
info "samba-gui has been uninstalled."
