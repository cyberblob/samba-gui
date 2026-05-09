#!/usr/bin/env bash
#
# install-deb.sh — Install the most recent samba-gui .deb package
#
# Usage:
#   ./install-deb.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Find the latest .deb ─────────────────────────────────────────────

DEB_FILE=$(ls -t target/debian/*.deb 2>/dev/null | head -1)

if [ -z "$DEB_FILE" ]; then
    error "No .deb file found in target/debian/. Run ./build-deb.sh first."
fi

info "Found package: $DEB_FILE"
echo ""
dpkg-deb --info "$DEB_FILE"
echo ""

# ── Install ───────────────────────────────────────────────────────────

info "Installing..."
sudo dpkg -i "$DEB_FILE"
sudo apt-get install -f -y

# ── Refresh icon cache ────────────────────────────────────────────────

if [ -d /usr/share/icons/hicolor ]; then
    sudo gtk-update-icon-cache -f -t /usr/share/icons/hicolor/ 2>/dev/null || true
fi

echo ""
info "Installed successfully. Run 'samba-gui' to launch."
