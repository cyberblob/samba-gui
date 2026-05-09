# Samba GUI

A GTK4/libadwaita-based desktop application for managing SAMBA server and client configurations on Linux.

## Features

- **Server Configuration** — Manage global settings and shares in `/etc/samba/smb.conf`
  - Security hardening: `restrict anonymous`, `ntlm auth`, SMB encryption, protocol versions, signing
  - Quick-start templates with diff preview before applying
- **Client Configuration** — Configure SMB/CIFS mounts via systemd .mount/.automount units
  - Multi-step Mount Wizard with auth method selection (Guest, Credentials File, Kerberos)
  - Pre-flight validation: share connectivity, FQDN checks, Kerberos ticket/DNS SRV verification
  - Boot-time Kerberos ticket acquisition via krb5-kinit systemd service
  - Edit mode for existing mounts with guided re-configuration
- **Service Management** — Start/stop/restart SAMBA services (smbd, nmbd, winbind)
- **User Management** — Manage SAMBA users with auto-detection of server mode:
  - Standalone: uses `pdbedit` / `smbpasswd` (local passdb)
  - AD Domain Controller: uses `samba-tool user` (AD/LDAP backend)
- **Backup/Restore** — Timestamped configuration backups
- **Firewall Integration** — Detect ufw/firewalld, show SMB port status, open ports with one click
- **Network Discovery** — Scan the local network for SMB hosts and browse their shares
- **Config Export/Import** — Export and import server config and mount entries as JSON
- **Share Preview** — Generate and validate share config via `testparm`
- **Share Templates** — Quick-add common share types (Public, Home, Team, Media, Drop Box, Time Machine, Printers)
- **Single Instance** — Only one copy runs at a time; launching again raises the existing window

## Privilege Handling

The app requires root for operations like managing users and controlling services. On first use it shows a single GTK password dialog, then caches the sudo session for the remainder of the run. No repeated prompts.

## Requirements

- Rust (2021 edition)
- Linux with GTK4 (>= 4.14) and libadwaita (>= 1.4) for GUI mode
- Samba installed (`smbd`, `testparm`, `pdbedit` or `samba-tool`)

### Build Dependencies

**Debian/Ubuntu/Linux Mint:**
```bash
sudo apt install libgtk-4-dev libadwaita-1-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install gtk4-devel libadwaita-devel
```

**Arch Linux:**
```bash
sudo pacman -S gtk4 libadwaita
```

### Runtime Dependencies

`samba`, `samba-common-bin` (these are declared in the `.deb` package and resolved automatically by `apt` when installing from the package).

## Building

```bash
# Build CLI only (no GUI)
cargo build

# Build with GUI support (Linux only)
cargo build --features gui

# Release build
cargo build --release --features gui
```

## Running

```bash
# Run with GUI
cargo run --features gui

# Run in CLI mode
cargo run

# Run with debug logging
RUST_LOG=debug cargo run --features gui
```

## Testing

```bash
cargo test
```

The project uses property-based testing with `proptest` and `quickcheck` for configuration parsing, systemd mount unit operations, mount wizard state logic, and data model validation.

## Versioning

The version is managed via the `VERSION` file in the project root. The `build.rs` script reads it, auto-increments the patch number on each build, and exposes it to the binary as the `SAMBA_GUI_VERSION` environment variable at compile time. The build script only re-runs when files in `src/` change, preventing infinite rebuild loops.

## Configuration Templates

Server configuration templates are loaded from JSON in this priority order:

1. `$XDG_CONFIG_HOME/samba-gui/templates.json` (user customizations)
2. `/usr/share/samba-gui/templates.json` (system-installed via .deb)
3. Bundled fallback compiled into the binary

Templates provide pre-configured global settings (e.g., "Default (Secure)", "Simple File Server") that can be applied with a diff preview showing what will change.

## Mount Wizard

The client configuration uses a guided 5-step wizard for creating and editing CIFS mounts:

1. **Auth Selection** — Choose Guest, Credentials File, or Kerberos
2. **Connection Details** — Share address, mount point, plus auth-specific fields
3. **Mount Options** — Protocol version, permissions, automount, timeout, extra options
4. **Validation** — Background pre-flight checks (file existence, DNS, Kerberos tickets, share connectivity)
5. **Summary & Confirm** — Review all systemd units to be created, confirm or go back

Mounts are managed as systemd `.mount` and `.automount` unit files rather than raw `/etc/fstab` entries, providing better integration with the system boot process and on-demand mounting.

## Packaging (.deb)

Build a `.deb` package for Debian, Ubuntu, and Linux Mint:

```bash
# One-time setup
cargo install cargo-deb

# Build the .deb
./build-deb.sh

# Build and install in one step
./build-deb.sh install
```

The `build-deb.sh` script:
1. Checks prerequisites (cargo, cargo-deb, libgtk-4-dev, libadwaita-1-dev)
2. Runs the test suite
3. Builds the `.deb` via `cargo deb`
4. Prints package info and contents
5. Optionally installs with `./build-deb.sh install`

The package installs:
- `/usr/bin/samba-gui` — the application binary (built with `--features gui`)
- `/usr/share/applications/samba-gui.desktop` — desktop launcher entry
- `/usr/share/samba-gui/templates.json` — server configuration templates
- `/usr/share/doc/samba-gui/README.md` — documentation
- `/usr/share/icons/hicolor/*/apps/com.example.samba-gui.png` — app icons

Runtime dependencies (`libgtk-4-1`, `libadwaita-1-0`, `samba`, `samba-common-bin`) are declared in the package and resolved automatically by `apt`.

### Uninstalling

```bash
sudo apt remove samba-gui
```

## Development

```bash
# Check code without building
cargo check

# Format code
cargo fmt

# Run with verbose logging
RUST_LOG=trace cargo run --features gui
```

## Project Structure

```
samba-gui/
├── src/
│   ├── main.rs                    # Entry point, single-instance, feature-gated GUI/CLI
│   ├── config/
│   │   ├── mod.rs                 # Module exports
│   │   ├── models.rs              # Data structures (SambaConfig, GlobalSettings, Share, SystemdMountEntry, AuthMethod, etc.)
│   │   ├── parser.rs              # smb.conf parsing, serialization, validation
│   │   ├── share_templates.rs     # Share-level templates (hardcoded presets for common share types)
│   │   └── templates.rs           # Server config templates (JSON-based, bundled + user-overridable)
│   ├── services/
│   │   ├── mod.rs                 # Module exports
│   │   ├── privileged_executor.rs # Single-auth sudo session (password cached per session)
│   │   ├── user_manager.rs        # User management (auto-detects standalone vs AD DC)
│   │   ├── service_controller.rs  # systemd service management
│   │   ├── systemd_mount.rs       # systemd .mount/.automount unit CRUD
│   │   ├── backup_manager.rs      # Configuration backup/restore
│   │   ├── share_preview.rs       # testparm integration and share preview
│   │   ├── validation_engine.rs   # Mount wizard pre-flight validation
│   │   ├── kerberos_checker.rs    # Kerberos environment checks (klist, kinit, FQDN, DNS SRV)
│   │   ├── kinit_service_manager.rs # Boot-time krb5-kinit systemd service
│   │   ├── firewall_checker.rs    # Firewall detection and port management (ufw/firewalld)
│   │   ├── network_scanner.rs     # Network discovery (Avahi mDNS, nmblookup, smbclient)
│   │   └── config_export.rs       # JSON export/import for config and mounts
│   ├── ui/
│   │   ├── mod.rs                 # Main window, navigation, toast system, systemd unit helpers
│   │   ├── server_config.rs       # Server settings view (global settings + template selector)
│   │   ├── client_config.rs       # Client mounts view (systemd mounts list)
│   │   ├── mount_wizard.rs        # Multi-step mount wizard dialog
│   │   ├── service_management.rs  # Service control view
│   │   ├── user_management.rs     # User management view
│   │   ├── backup_view.rs         # Backup/restore view
│   │   ├── firewall_view.rs       # Firewall status and port management view
│   │   └── network_discovery.rs   # Network host/share discovery view
│   └── vm/
│       ├── mod.rs                 # View model layer exports
│       └── wizard_state.rs        # Mount wizard state machine
├── assets/
│   ├── samba-gui.desktop          # Desktop launcher entry
│   └── com.example.samba-gui-*.png # App icons (various sizes)
├── templates.json                 # Bundled server config templates
├── build.rs                       # Build script (auto-increment version)
├── build-deb.sh                   # Debian package build script
├── VERSION                        # Semver version file (read/written by build.rs)
├── LICENSE                        # GPL-3.0
├── Cargo.toml
└── Cargo.lock
```

## Architecture

```
UI Layer (GTK4/libadwaita)
    ↓
VM Layer (reactive state — WizardState)
    ↓
Services Layer (privileged_executor → sudo, user_manager, service_controller, systemd_mount, backup, share_preview, validation_engine, kerberos_checker, kinit_service_manager, firewall_checker, network_scanner, config_export)
    ↓
Config Layer (parser, models, templates, share_templates)
```

All privileged commands flow through `privileged_executor`, which authenticates once via a GTK password dialog and caches the sudo session.

`UserManager` auto-detects whether Samba is running as a standalone server or an AD Domain Controller (via `testparm`) and dispatches to the correct tooling.

Client mounts use `SystemdMountManager` for systemd unit file CRUD, with the `MountWizard` providing a guided UI flow and `ValidationEngine` performing pre-flight checks.

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.
