#![allow(dead_code)]
//! SystemdMountManager for managing SMB/CIFS mounts as systemd .mount / .automount units
//!
//! Replaces the old fstab-based approach with native systemd mount units under
//! `/etc/systemd/system/`. Each CIFS mount gets a `.mount` unit and optionally
//! a companion `.automount` unit for on-demand mounting.

use crate::config::models::SystemdMountEntry;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur during systemd mount operations
#[derive(Error, Debug)]
pub enum SystemdMountError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Unit not found: {0}")]
    NotFound(String),

    #[error("Invalid mount point: {0}")]
    InvalidMountPoint(String),

    #[error("Command failed: {0}")]
    CommandFailed(String),

    #[error("Unit already exists: {0}")]
    AlreadyExists(String),
}

/// Result type for systemd mount operations
pub type SystemdMountResult<T> = Result<T, SystemdMountError>;

/// Base directory for systemd unit files
const SYSTEMD_UNIT_DIR: &str = "/etc/systemd/system";

/// Manager for SMB/CIFS mount entries as systemd units
pub struct SystemdMountManager {
    unit_dir: String,
}

impl SystemdMountManager {
    /// Create a new SystemdMountManager with the default unit directory
    pub fn new() -> Self {
        Self {
            unit_dir: SYSTEMD_UNIT_DIR.to_string(),
        }
    }

    /// Create a new SystemdMountManager with a custom unit directory (useful for testing)
    pub fn with_dir(dir: impl Into<String>) -> Self {
        Self {
            unit_dir: dir.into(),
        }
    }

    // ------------------------------------------------------------------
    // Unit name helpers
    // ------------------------------------------------------------------

    /// Convert a mount point path to a systemd unit name.
    ///
    /// `/mnt/share` → `mnt-share`  (caller appends `.mount` or `.automount`)
    ///
    /// This replicates the logic of `systemd-escape --path`.
    pub fn mount_point_to_unit_base(mount_point: &str) -> String {
        let trimmed = mount_point.trim_matches('/');
        if trimmed.is_empty() {
            return "-".to_string();
        }
        trimmed
            .split('/')
            .map(|seg| {
                seg.chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == ':' || c == '.' || c == '_' {
                            c.to_string()
                        } else {
                            // Escape as \xHH
                            format!("\\x{:02x}", c as u32)
                        }
                    })
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Get the .mount unit name for a mount point
    pub fn mount_unit_name(mount_point: &str) -> String {
        format!("{}.mount", Self::mount_point_to_unit_base(mount_point))
    }

    /// Get the .automount unit name for a mount point
    pub fn automount_unit_name(mount_point: &str) -> String {
        format!("{}.automount", Self::mount_point_to_unit_base(mount_point))
    }

    // ------------------------------------------------------------------
    // Unit file paths
    // ------------------------------------------------------------------

    fn mount_unit_path(&self, mount_point: &str) -> PathBuf {
        Path::new(&self.unit_dir).join(Self::mount_unit_name(mount_point))
    }

    fn automount_unit_path(&self, mount_point: &str) -> PathBuf {
        Path::new(&self.unit_dir).join(Self::automount_unit_name(mount_point))
    }

    // ------------------------------------------------------------------
    // Listing
    // ------------------------------------------------------------------

    /// List all CIFS/SMB systemd mount units.
    ///
    /// Scans the unit directory for `.mount` files whose `Type=` is `cifs` or
    /// `smbfs`, then queries systemd for enabled/active state.
    pub fn list_mounts(&self) -> SystemdMountResult<Vec<SystemdMountEntry>> {
        let dir = Path::new(&self.unit_dir);
        if !dir.is_dir() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();

        let dir_entries = fs::read_dir(dir)?;
        for de in dir_entries {
            let de = de?;
            let name = de.file_name().to_string_lossy().to_string();
            if !name.ends_with(".mount") {
                continue;
            }

            let content = fs::read_to_string(de.path())?;
            if let Some(entry) = self.parse_mount_unit(&name, &content) {
                // Only include CIFS/SMB mounts
                if entry.fs_type.eq_ignore_ascii_case("cifs")
                    || entry.fs_type.eq_ignore_ascii_case("smbfs")
                {
                    entries.push(entry);
                }
            }
        }

        // Query systemd for enabled/active state
        for entry in &mut entries {
            let mount_name = Self::mount_unit_name(&entry.mount_point);

            // Check for companion automount unit
            let automount_path = self.automount_unit_path(&entry.mount_point);
            entry.automount = automount_path.exists();

            // When an automount unit exists, it controls the lifecycle —
            // the .mount unit will show as "disabled" because systemd
            // activates it on-demand via the .automount. Check the
            // automount unit's state instead.
            if entry.automount {
                let automount_name = Self::automount_unit_name(&entry.mount_point);
                entry.enabled = self.is_unit_enabled(&automount_name);
                // Active if either the automount is listening or the mount is up
                entry.active = self.is_unit_active(&automount_name)
                    || self.is_unit_active(&mount_name);
            } else {
                entry.enabled = self.is_unit_enabled(&mount_name);
                entry.active = self.is_unit_active(&mount_name);
            }
        }

        entries.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));
        Ok(entries)
    }

    /// Parse a .mount unit file into a SystemdMountEntry
    fn parse_mount_unit(&self, unit_name: &str, content: &str) -> Option<SystemdMountEntry> {
        let mut description = String::new();
        let mut what = String::new();
        let mut where_ = String::new();
        let mut type_ = String::new();
        let mut options = Vec::new();
        let mut timeout_sec = None;

        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(val) = trimmed.strip_prefix("Description=") {
                description = val.to_string();
            } else if let Some(val) = trimmed.strip_prefix("What=") {
                what = val.to_string();
            } else if let Some(val) = trimmed.strip_prefix("Where=") {
                where_ = val.to_string();
            } else if let Some(val) = trimmed.strip_prefix("Type=") {
                type_ = val.to_string();
            } else if let Some(val) = trimmed.strip_prefix("Options=") {
                options = val.split(',').map(|s| s.trim().to_string()).collect();
            } else if let Some(val) = trimmed.strip_prefix("TimeoutSec=") {
                timeout_sec = val.parse().ok();
            }
        }

        if what.is_empty() || where_.is_empty() {
            return None;
        }

        Some(SystemdMountEntry {
            unit_name: unit_name.to_string(),
            description,
            device: what,
            mount_point: where_,
            fs_type: if type_.is_empty() { "cifs".to_string() } else { type_ },
            options,
            automount: false, // caller fills this in
            timeout_sec,
            enabled: false,   // caller fills this in
            active: false,    // caller fills this in
        })
    }

    // ------------------------------------------------------------------
    // Unit file generation
    // ------------------------------------------------------------------

    /// Generate the content of a .mount unit file
    pub fn generate_mount_unit(entry: &SystemdMountEntry) -> String {
        let mut unit = String::new();

        unit.push_str("[Unit]\n");
        let desc = if entry.description.is_empty() {
            format!("CIFS mount for {}", entry.device)
        } else {
            entry.description.clone()
        };
        unit.push_str(&format!("Description={}\n", desc));
        unit.push_str("After=network-online.target\n");
        unit.push_str("Requires=network-online.target\n");

        unit.push_str("\n[Mount]\n");
        unit.push_str(&format!("What={}\n", entry.device));
        unit.push_str(&format!("Where={}\n", entry.mount_point));
        unit.push_str(&format!("Type={}\n", entry.fs_type));

        if !entry.options.is_empty() {
            unit.push_str(&format!("Options={}\n", entry.options.join(",")));
        }

        if let Some(timeout) = entry.timeout_sec {
            unit.push_str(&format!("TimeoutSec={}\n", timeout));
        }

        unit.push_str("\n[Install]\n");
        unit.push_str("WantedBy=multi-user.target\n");

        unit
    }

    /// Generate the content of a .automount unit file
    pub fn generate_automount_unit(entry: &SystemdMountEntry) -> String {
        let mut unit = String::new();

        unit.push_str("[Unit]\n");
        let desc = if entry.description.is_empty() {
            format!("Automount for {}", entry.device)
        } else {
            format!("Automount: {}", entry.description)
        };
        unit.push_str(&format!("Description={}\n", desc));

        unit.push_str("\n[Automount]\n");
        unit.push_str(&format!("Where={}\n", entry.mount_point));
        if let Some(timeout) = entry.timeout_sec {
            unit.push_str(&format!("TimeoutIdleSec={}\n", timeout));
        }

        unit.push_str("\n[Install]\n");
        unit.push_str("WantedBy=multi-user.target\n");

        unit
    }

    // ------------------------------------------------------------------
    // CRUD operations (non-privileged — for testing with custom dirs)
    // ------------------------------------------------------------------

    /// Add a new mount (writes unit files directly — use add_mount_privileged
    /// for production where root is needed).
    pub fn add_mount(&self, entry: &SystemdMountEntry) -> SystemdMountResult<()> {
        if entry.mount_point.is_empty() {
            return Err(SystemdMountError::InvalidMountPoint(
                "Mount point cannot be empty".to_string(),
            ));
        }
        if entry.device.is_empty() {
            return Err(SystemdMountError::InvalidMountPoint(
                "Device cannot be empty".to_string(),
            ));
        }

        let mount_path = self.mount_unit_path(&entry.mount_point);
        if mount_path.exists() {
            return Err(SystemdMountError::AlreadyExists(format!(
                "Unit file already exists: {}",
                mount_path.display()
            )));
        }

        // Write .mount unit
        let mount_content = Self::generate_mount_unit(entry);
        fs::write(&mount_path, &mount_content)?;

        // Write .automount unit if requested
        if entry.automount {
            let automount_path = self.automount_unit_path(&entry.mount_point);
            let automount_content = Self::generate_automount_unit(entry);
            fs::write(&automount_path, &automount_content)?;
        }

        Ok(())
    }

    /// Remove a mount (deletes unit files directly — use remove_mount_privileged
    /// for production).
    pub fn remove_mount(&self, mount_point: &str) -> SystemdMountResult<()> {
        let mount_path = self.mount_unit_path(mount_point);
        if !mount_path.exists() {
            return Err(SystemdMountError::NotFound(format!(
                "No mount unit found for '{}'",
                mount_point
            )));
        }

        fs::remove_file(&mount_path)?;

        // Also remove automount unit if it exists
        let automount_path = self.automount_unit_path(mount_point);
        if automount_path.exists() {
            fs::remove_file(&automount_path)?;
        }

        Ok(())
    }

    /// Read the raw content of a mount unit file
    pub fn read_unit(&self, mount_point: &str) -> SystemdMountResult<String> {
        let mount_path = self.mount_unit_path(mount_point);
        if !mount_path.exists() {
            return Err(SystemdMountError::NotFound(format!(
                "No mount unit found for '{}'",
                mount_point
            )));
        }
        Ok(fs::read_to_string(&mount_path)?)
    }

    // ------------------------------------------------------------------
    // systemctl queries (used by list_mounts)
    // ------------------------------------------------------------------

    fn is_unit_enabled(&self, unit_name: &str) -> bool {
        std::process::Command::new("systemctl")
            .args(["is-enabled", unit_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn is_unit_active(&self, unit_name: &str) -> bool {
        std::process::Command::new("systemctl")
            .args(["is-active", unit_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    /// Validate a mount point path
    pub fn validate_mount_point(path: &str) -> SystemdMountResult<()> {
        if path.is_empty() {
            return Err(SystemdMountError::InvalidMountPoint(
                "Mount point cannot be empty".to_string(),
            ));
        }
        if !path.starts_with('/') {
            return Err(SystemdMountError::InvalidMountPoint(
                "Mount point must be an absolute path".to_string(),
            ));
        }
        let path_obj = Path::new(path);
        if let Some(parent) = path_obj.parent() {
            if !parent.exists() {
                return Err(SystemdMountError::InvalidMountPoint(format!(
                    "Parent directory '{}' does not exist",
                    parent.display()
                )));
            }
        }
        Ok(())
    }
}

impl Default for SystemdMountManager {
    fn default() -> Self {
        Self::new()
    }
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_manager() -> (SystemdMountManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let mgr = SystemdMountManager::with_dir(dir.path().to_string_lossy().as_ref());
        (mgr, dir)
    }

    fn sample_entry(mount_point: &str) -> SystemdMountEntry {
        SystemdMountEntry {
            unit_name: String::new(),
            description: format!("Test mount for {}", mount_point),
            device: "//server/share".to_string(),
            mount_point: mount_point.to_string(),
            fs_type: "cifs".to_string(),
            options: vec!["credentials=/root/.smbcred".to_string(), "uid=1000".to_string()],
            automount: true,
            timeout_sec: Some(30),
            enabled: true,
            active: false,
        }
    }

    #[test]
    fn test_mount_point_to_unit_base() {
        assert_eq!(SystemdMountManager::mount_point_to_unit_base("/mnt/share"), "mnt-share");
        assert_eq!(SystemdMountManager::mount_point_to_unit_base("/media/cifs/data"), "media-cifs-data");
        assert_eq!(SystemdMountManager::mount_point_to_unit_base("/"), "-");
        assert_eq!(SystemdMountManager::mount_point_to_unit_base("/mnt"), "mnt");
    }

    #[test]
    fn test_mount_unit_name() {
        assert_eq!(SystemdMountManager::mount_unit_name("/mnt/share"), "mnt-share.mount");
        assert_eq!(SystemdMountManager::mount_unit_name("/media/data"), "media-data.mount");
    }

    #[test]
    fn test_automount_unit_name() {
        assert_eq!(SystemdMountManager::automount_unit_name("/mnt/share"), "mnt-share.automount");
    }

    #[test]
    fn test_generate_mount_unit() {
        let entry = sample_entry("/mnt/share");
        let content = SystemdMountManager::generate_mount_unit(&entry);

        assert!(content.contains("[Unit]"));
        assert!(content.contains("Description=Test mount for /mnt/share"));
        assert!(content.contains("After=network-online.target"));
        assert!(content.contains("[Mount]"));
        assert!(content.contains("What=//server/share"));
        assert!(content.contains("Where=/mnt/share"));
        assert!(content.contains("Type=cifs"));
        assert!(content.contains("Options=credentials=/root/.smbcred,uid=1000"));
        assert!(content.contains("TimeoutSec=30"));
        assert!(content.contains("[Install]"));
        assert!(content.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn test_generate_automount_unit() {
        let entry = sample_entry("/mnt/share");
        let content = SystemdMountManager::generate_automount_unit(&entry);

        assert!(content.contains("[Unit]"));
        assert!(content.contains("[Automount]"));
        assert!(content.contains("Where=/mnt/share"));
        assert!(content.contains("TimeoutIdleSec=30"));
        assert!(content.contains("[Install]"));
    }

    #[test]
    fn test_add_mount_creates_files() {
        let (mgr, dir) = test_manager();
        let entry = sample_entry("/mnt/share");

        mgr.add_mount(&entry).unwrap();

        // .mount file should exist
        let mount_path = dir.path().join("mnt-share.mount");
        assert!(mount_path.exists());

        // .automount file should exist (automount=true)
        let automount_path = dir.path().join("mnt-share.automount");
        assert!(automount_path.exists());
    }

    #[test]
    fn test_add_mount_no_automount() {
        let (mgr, dir) = test_manager();
        let mut entry = sample_entry("/mnt/share");
        entry.automount = false;

        mgr.add_mount(&entry).unwrap();

        let mount_path = dir.path().join("mnt-share.mount");
        assert!(mount_path.exists());

        let automount_path = dir.path().join("mnt-share.automount");
        assert!(!automount_path.exists());
    }

    #[test]
    fn test_add_mount_duplicate_fails() {
        let (mgr, _dir) = test_manager();
        let entry = sample_entry("/mnt/share");

        mgr.add_mount(&entry).unwrap();
        let result = mgr.add_mount(&entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_mount_empty_device_fails() {
        let (mgr, _dir) = test_manager();
        let mut entry = sample_entry("/mnt/share");
        entry.device = String::new();

        let result = mgr.add_mount(&entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_mount_empty_mount_point_fails() {
        let (mgr, _dir) = test_manager();
        let mut entry = sample_entry("/mnt/share");
        entry.mount_point = String::new();

        let result = mgr.add_mount(&entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_mount() {
        let (mgr, dir) = test_manager();
        let entry = sample_entry("/mnt/share");
        mgr.add_mount(&entry).unwrap();

        mgr.remove_mount("/mnt/share").unwrap();

        assert!(!dir.path().join("mnt-share.mount").exists());
        assert!(!dir.path().join("mnt-share.automount").exists());
    }

    #[test]
    fn test_remove_mount_not_found() {
        let (mgr, _dir) = test_manager();
        let result = mgr.remove_mount("/nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_list_mounts() {
        let (mgr, _dir) = test_manager();

        let entry1 = sample_entry("/mnt/share1");
        let entry2 = sample_entry("/mnt/share2");
        mgr.add_mount(&entry1).unwrap();
        mgr.add_mount(&entry2).unwrap();

        let mounts = mgr.list_mounts().unwrap();
        assert_eq!(mounts.len(), 2);

        let mount_points: Vec<&str> = mounts.iter().map(|e| e.mount_point.as_str()).collect();
        assert!(mount_points.contains(&"/mnt/share1"));
        assert!(mount_points.contains(&"/mnt/share2"));
    }

    #[test]
    fn test_list_mounts_ignores_non_cifs() {
        let (mgr, dir) = test_manager();

        // Write a non-CIFS mount unit
        let ext4_unit = "[Unit]\nDescription=Root\n\n[Mount]\nWhat=/dev/sda1\nWhere=/\nType=ext4\n";
        fs::write(dir.path().join("-.mount"), ext4_unit).unwrap();

        // Write a CIFS mount unit
        let entry = sample_entry("/mnt/share");
        mgr.add_mount(&entry).unwrap();

        let mounts = mgr.list_mounts().unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mount_point, "/mnt/share");
    }

    #[test]
    fn test_read_unit() {
        let (mgr, _dir) = test_manager();
        let entry = sample_entry("/mnt/share");
        mgr.add_mount(&entry).unwrap();

        let content = mgr.read_unit("/mnt/share").unwrap();
        assert!(content.contains("What=//server/share"));
    }

    #[test]
    fn test_read_unit_not_found() {
        let (mgr, _dir) = test_manager();
        let result = mgr.read_unit("/nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_roundtrip() {
        let (mgr, _dir) = test_manager();
        let entry = sample_entry("/mnt/share");

        mgr.add_mount(&entry).unwrap();
        let mounts = mgr.list_mounts().unwrap();

        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].device, "//server/share");
        assert_eq!(mounts[0].mount_point, "/mnt/share");
        assert_eq!(mounts[0].fs_type, "cifs");
        assert_eq!(mounts[0].options, vec!["credentials=/root/.smbcred", "uid=1000"]);
        assert_eq!(mounts[0].timeout_sec, Some(30));
        assert!(mounts[0].automount); // automount file exists
    }

    #[test]
    fn test_validate_mount_point_empty() {
        let result = SystemdMountManager::validate_mount_point("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mount_point_relative() {
        let result = SystemdMountManager::validate_mount_point("mnt/share");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mount_point_absolute() {
        let result = SystemdMountManager::validate_mount_point("/tmp");
        if result.is_ok() {
            assert!(true);
        } else {
            let err = result.unwrap_err();
            assert!(!err.to_string().contains("absolute path"));
        }
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::TempDir;

    fn arb_smb_device() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "//server/share".to_string(),
            "//nas/documents".to_string(),
            "//fileserver/media".to_string(),
            "//192.168.1.100/backup".to_string(),
            "//smb.example.com/data".to_string(),
        ])
    }

    fn arb_mount_point() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "/mnt/share".to_string(),
            "/mnt/cifs".to_string(),
            "/media/share".to_string(),
            "/media/smb".to_string(),
            "/media/data".to_string(),
            "/home/user/share".to_string(),
        ])
    }

    fn arb_mount_options() -> impl Strategy<Value = Vec<String>> {
        prop::sample::select(vec![
            vec!["_netdev".to_string(), "nofail".to_string()],
            vec!["credentials=/root/.smbcred".to_string(), "uid=1000".to_string()],
            vec!["_netdev".to_string(), "nofail".to_string(), "noperm".to_string()],
            vec!["credentials=/root/.smbcred".to_string(), "uid=1000".to_string(), "gid=1000".to_string()],
        ])
    }

    fn arb_systemd_mount_entry() -> impl Strategy<Value = SystemdMountEntry> {
        (arb_smb_device(), arb_mount_point(), arb_mount_options(), proptest::bool::ANY)
            .prop_map(|(device, mount_point, options, automount)| {
                SystemdMountEntry {
                    unit_name: String::new(),
                    description: format!("CIFS mount for {}", device),
                    device,
                    mount_point,
                    fs_type: "cifs".to_string(),
                    options,
                    automount,
                    timeout_sec: Some(30),
                    enabled: true,
                    active: false,
                }
            })
    }

    /// For any valid SystemdMountEntry, adding it and re-listing SHALL contain the new entry
    #[test]
    fn test_property_add_then_list_contains_entry() {
        proptest!(|(entry in arb_systemd_mount_entry())| {
            let dir = TempDir::new().unwrap();
            let mgr = SystemdMountManager::with_dir(dir.path().to_string_lossy().as_ref());

            let result = mgr.add_mount(&entry);
            prop_assert!(result.is_ok(), "add_mount should succeed for valid entry");

            let mounts = mgr.list_mounts().unwrap();
            let found = mounts.iter().any(|e| e.mount_point == entry.mount_point);
            prop_assert!(found, "Added entry should be present after re-listing");
        });
    }

    /// For any valid entry, the device is preserved through add + list
    #[test]
    fn test_property_device_preserved() {
        proptest!(|(entry in arb_systemd_mount_entry())| {
            let dir = TempDir::new().unwrap();
            let mgr = SystemdMountManager::with_dir(dir.path().to_string_lossy().as_ref());

            mgr.add_mount(&entry).unwrap();
            let mounts = mgr.list_mounts().unwrap();
            let found = mounts.iter().find(|e| e.mount_point == entry.mount_point);
            prop_assert!(found.is_some());
            prop_assert_eq!(&found.unwrap().device, &entry.device);
        });
    }

    /// For any valid entry, options are preserved through add + list
    #[test]
    fn test_property_options_preserved() {
        proptest!(|(entry in arb_systemd_mount_entry())| {
            let dir = TempDir::new().unwrap();
            let mgr = SystemdMountManager::with_dir(dir.path().to_string_lossy().as_ref());

            mgr.add_mount(&entry).unwrap();
            let mounts = mgr.list_mounts().unwrap();
            let found = mounts.iter().find(|e| e.mount_point == entry.mount_point);
            prop_assert!(found.is_some());
            prop_assert_eq!(&found.unwrap().options, &entry.options);
        });
    }

    /// Adding then removing leaves no trace
    #[test]
    fn test_property_add_remove_roundtrip() {
        proptest!(|(entry in arb_systemd_mount_entry())| {
            let dir = TempDir::new().unwrap();
            let mgr = SystemdMountManager::with_dir(dir.path().to_string_lossy().as_ref());

            mgr.add_mount(&entry).unwrap();
            mgr.remove_mount(&entry.mount_point).unwrap();

            let mounts = mgr.list_mounts().unwrap();
            let found = mounts.iter().any(|e| e.mount_point == entry.mount_point);
            prop_assert!(!found, "Entry should be gone after removal");
        });
    }
}
