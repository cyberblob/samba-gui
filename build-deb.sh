#!/usr/bin/env bash
#
# build-deb.sh — Build a .deb package for samba-gui
#
# Usage:
#   ./build-deb.sh          # build the .deb
#   ./build-deb.sh install  # build and install locally
#
# Prerequisites:
#   cargo install cargo-deb
#   sudo apt install libgtk-4-dev libadwaita-1-dev
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Check prerequisites ──────────────────────────────────────────────

info "Checking prerequisites..."

command -v cargo   >/dev/null 2>&1 || error "cargo not found. Install Rust: https://rustup.rs"
command -v cargo-deb >/dev/null 2>&1 || {
    warn "cargo-deb not found. Installing..."
    cargo install cargo-deb
}

# Check build dependencies
if ! dpkg -s libgtk-4-dev >/dev/null 2>&1; then
    error "libgtk-4-dev not installed. Run: sudo apt install libgtk-4-dev"
fi
if ! dpkg -s libadwaita-1-dev >/dev/null 2>&1; then
    error "libadwaita-1-dev not installed. Run: sudo apt install libadwaita-1-dev"
fi

# ── Bump version (once per build) ─────────────────────────────────────

VERSION=$(cat VERSION | tr -d '[:space:]')
IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"
PATCH=$((PATCH + 1))
NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
echo "$NEW_VERSION" > VERSION
info "Version bumped: $VERSION → $NEW_VERSION"

# ── Run tests ─────────────────────────────────────────────────────────

info "Running tests..."
cargo test || error "Tests failed. Fix them before packaging."

# ── Sync version into Cargo.toml ──────────────────────────────────────

info "Syncing version $NEW_VERSION into Cargo.toml..."
sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml

# ── Build the .deb ────────────────────────────────────────────────────

info "Building .deb package..."
cargo deb

DEB_FILE=$(ls -t target/debian/*.deb 2>/dev/null | head -1)

if [ -z "$DEB_FILE" ]; then
    error "No .deb file found in target/debian/"
fi

info "Package built: $DEB_FILE"

# Show package info
echo ""
dpkg-deb --info "$DEB_FILE"
echo ""
info "Contents:"
dpkg-deb --contents "$DEB_FILE"

# ── Optional install ──────────────────────────────────────────────────

if [ "${1:-}" = "install" ]; then
    info "Installing package..."
    sudo dpkg -i "$DEB_FILE"
    sudo apt-get install -f -y
    info "Installed successfully. Run 'samba-gui' to launch."
else
    echo ""
    info "To install: sudo dpkg -i $DEB_FILE"
    info "Or re-run:  ./build-deb.sh install"
fi
