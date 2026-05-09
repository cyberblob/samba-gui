#!/usr/bin/env bash
#
# build.sh — Unified build script for samba-gui
#
# Usage:
#   ./build.sh dev          # Debug build with GUI (default)
#   ./build.sh release      # Optimized release build with GUI
#   ./build.sh deb          # Build .deb package (release + packaging)
#   ./build.sh deb install  # Build and install .deb locally
#   ./build.sh check        # Type-check only (fast)
#   ./build.sh test         # Run all tests
#   ./build.sh clean        # Remove build artifacts
#
# Prerequisites:
#   - Rust toolchain (rustup.rs)
#   - sudo apt install libgtk-4-dev libadwaita-1-dev
#   - cargo install cargo-deb  (for deb target only)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colors ────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
header() { echo -e "\n${BLUE}${BOLD}── $* ──${NC}\n"; }

# ── Helpers ───────────────────────────────────────────────────────────

check_rust() {
    command -v cargo >/dev/null 2>&1 || error "cargo not found. Install Rust: https://rustup.rs"
}

check_gtk_deps() {
    if ! dpkg -s libgtk-4-dev >/dev/null 2>&1; then
        error "libgtk-4-dev not installed. Run: sudo apt install libgtk-4-dev"
    fi
    if ! dpkg -s libadwaita-1-dev >/dev/null 2>&1; then
        error "libadwaita-1-dev not installed. Run: sudo apt install libadwaita-1-dev"
    fi
}

# Increment the patch version in VERSION file (call once per build session)
bump_version() {
    local version
    version=$(tr -d '[:space:]' < VERSION)
    local major minor patch
    IFS='.' read -r major minor patch <<< "$version"
    patch=$((patch + 1))
    local new_version="${major}.${minor}.${patch}"
    echo "$new_version" > VERSION
    info "Version bumped: $version → $new_version"
}

# Sync VERSION into Cargo.toml so cargo-deb picks it up
sync_version_to_cargo_toml() {
    local version
    version=$(tr -d '[:space:]' < VERSION)
    sed -i "s/^version = \".*\"/version = \"$version\"/" Cargo.toml
}

print_binary_info() {
    local bin="$1"
    if [ -f "$bin" ]; then
        local size
        size=$(du -h "$bin" | cut -f1)
        info "Binary: $bin ($size)"
    fi
}

show_usage() {
    echo -e "${BOLD}Usage:${NC} ./build.sh <target> [options]"
    echo ""
    echo "Targets:"
    echo "  dev          Debug build with GUI (default)"
    echo "  release      Optimized release build with GUI"
    echo "  deb          Build .deb package"
    echo "  deb install  Build and install .deb locally"
    echo "  all          Build everything (dev + release + deb)"
    echo "  check        Type-check only (fastest)"
    echo "  test         Run all tests"
    echo "  clean        Remove build artifacts"
    echo ""
    echo "Examples:"
    echo "  ./build.sh              # same as ./build.sh dev"
    echo "  ./build.sh release      # optimized build"
    echo "  ./build.sh deb install  # package and install"
}

# ── Targets ───────────────────────────────────────────────────────────

do_check() {
    header "Check (type-check only)"
    check_rust
    info "Running cargo check..."
    cargo check --features gui
    info "Check passed."
}

do_test() {
    header "Test"
    check_rust
    info "Running cargo test..."
    cargo test
    info "All tests passed."
}

do_dev() {
    header "Development Build (debug + GUI)"
    check_rust
    check_gtk_deps
    bump_version

    info "Building debug binary with GUI..."
    cargo build --features gui

    local bin="target/debug/samba-gui"
    print_binary_info "$bin"
    info "Done. Run with: RUST_LOG=debug cargo run --features gui"
}

do_release() {
    header "Release Build (optimized + GUI)"
    check_rust
    check_gtk_deps
    bump_version

    info "Running tests first..."
    cargo test || error "Tests failed. Fix them before building release."

    info "Building release binary with GUI..."
    cargo build --release --features gui

    local bin="target/release/samba-gui"
    print_binary_info "$bin"

    # Strip debug symbols for smaller binary
    if command -v strip >/dev/null 2>&1; then
        strip "$bin"
        info "Stripped debug symbols."
        print_binary_info "$bin"
    fi

    info "Done. Binary at: $bin"
    info "Run with: ./target/release/samba-gui"
}

do_deb() {
    header "Debian Package Build"
    check_rust
    check_gtk_deps

    # Check cargo-deb
    command -v cargo-deb >/dev/null 2>&1 || {
        warn "cargo-deb not found. Installing..."
        cargo install cargo-deb
    }

    bump_version

    info "Running tests..."
    cargo test || error "Tests failed. Fix them before packaging."

    # Sync version into Cargo.toml so cargo-deb picks it up
    sync_version_to_cargo_toml

    info "Building .deb package..."
    cargo deb

    local deb_file
    deb_file=$(ls -t target/debian/*.deb 2>/dev/null | head -1)

    if [ -z "$deb_file" ]; then
        error "No .deb file found in target/debian/"
    fi

    info "Package built: $deb_file"
    echo ""
    dpkg-deb --info "$deb_file"
    echo ""
    info "Contents:"
    dpkg-deb --contents "$deb_file"

    # Optional install
    if [ "${1:-}" = "install" ]; then
        echo ""
        info "Installing package..."
        sudo dpkg -i "$deb_file"
        sudo apt-get install -f -y
        info "Installed successfully. Run 'samba-gui' to launch."
    else
        echo ""
        info "To install: sudo dpkg -i $deb_file"
        info "Or re-run:  ./build.sh deb install"
    fi
}

do_clean() {
    header "Clean"
    info "Removing build artifacts..."
    cargo clean
    info "Done."
}

do_all() {
    header "Build All (dev + release + deb)"
    check_rust
    check_gtk_deps
    bump_version

    info "Running tests..."
    cargo test || error "Tests failed."

    info "Building debug binary with GUI..."
    cargo build --features gui
    print_binary_info "target/debug/samba-gui"

    info "Building release binary with GUI..."
    cargo build --release --features gui
    local bin="target/release/samba-gui"
    if command -v strip >/dev/null 2>&1; then
        strip "$bin"
    fi
    print_binary_info "$bin"

    # Build .deb if cargo-deb is available
    if command -v cargo-deb >/dev/null 2>&1; then
        sync_version_to_cargo_toml
        info "Building .deb package..."
        cargo deb
        local deb_file
        deb_file=$(ls -t target/debian/*.deb 2>/dev/null | head -1)
        if [ -n "$deb_file" ]; then
            info "Package: $deb_file"
        fi
    else
        warn "cargo-deb not installed, skipping .deb. Install with: cargo install cargo-deb"
    fi

    echo ""
    info "All builds complete:"
    info "  Debug:   target/debug/samba-gui"
    info "  Release: target/release/samba-gui"
    if [ -n "${deb_file:-}" ]; then
        info "  Deb:     $deb_file"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────

TARGET="${1:-dev}"

case "$TARGET" in
    dev|debug)
        do_dev
        ;;
    release|rel)
        do_release
        ;;
    deb|package|pkg)
        do_deb "${2:-}"
        ;;
    all)
        do_all
        ;;
    check)
        do_check
        ;;
    test|tests)
        do_test
        ;;
    clean)
        do_clean
        ;;
    help|-h|--help)
        show_usage
        ;;
    *)
        error "Unknown target: $TARGET\n\nRun './build.sh help' for usage."
        ;;
esac
