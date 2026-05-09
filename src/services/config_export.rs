#![allow(dead_code)]
//! Configuration export/import service.
//!
//! Allows exporting the current SambaConfig (global settings + shares) to a
//! portable JSON file, and importing it back on another machine.

use crate::config::{SambaConfig, ConfigParser};
use std::path::Path;
use thiserror::Error;

/// Errors from export/import operations.
#[derive(Error, Debug)]
pub enum ExportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Validation error: {0}")]
    Validation(String),
}

pub type ExportResult<T> = Result<T, ExportError>;

/// Export the given SambaConfig to a JSON file at the specified path.
pub fn export_config_json(config: &SambaConfig, destination: &Path) -> ExportResult<()> {
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(destination, &json)?;
    Ok(())
}

/// Export the given SambaConfig to a JSON string (for clipboard or display).
pub fn export_config_json_string(config: &SambaConfig) -> ExportResult<String> {
    let json = serde_json::to_string_pretty(config)?;
    Ok(json)
}

/// Import a SambaConfig from a JSON file.
/// Validates the imported config before returning.
pub fn import_config_json(source: &Path) -> ExportResult<SambaConfig> {
    let content = std::fs::read_to_string(source)?;
    import_config_from_string(&content)
}

/// Import a SambaConfig from a JSON string.
/// Validates the imported config before returning.
pub fn import_config_from_string(json: &str) -> ExportResult<SambaConfig> {
    let config: SambaConfig = serde_json::from_str(json)?;

    // Validate the imported config
    ConfigParser::validate(&config)
        .map_err(|e| ExportError::Validation(e.to_string()))?;

    Ok(config)
}

/// Export the current smb.conf as a JSON file.
/// Reads from the given smb.conf path, parses it, and writes JSON to destination.
pub fn export_smb_conf_as_json(smb_conf_path: &Path, destination: &Path) -> ExportResult<SambaConfig> {
    let content = std::fs::read_to_string(smb_conf_path)
        .map_err(|e| ExportError::Io(e))?;

    let config = ConfigParser::parse(&content)
        .map_err(|e| ExportError::Parse(e.to_string()))?;

    export_config_json(&config, destination)?;
    Ok(config)
}

/// Import a JSON config and convert it to smb.conf format string.
/// Does NOT write to disk — returns the serialized smb.conf content.
pub fn import_json_to_smb_conf_string(source: &Path) -> ExportResult<String> {
    let config = import_config_json(source)?;
    let smb_conf = ConfigParser::serialize(&config)
        .map_err(|e| ExportError::Parse(e.to_string()))?;
    Ok(smb_conf)
}

// ---------------------------------------------------------------------------
// Client mount entry export/import
// ---------------------------------------------------------------------------

use crate::config::SystemdMountEntry;

/// Export a list of SystemdMountEntry objects to a JSON file.
pub fn export_mounts_json(mounts: &[SystemdMountEntry], destination: &Path) -> ExportResult<()> {
    let json = serde_json::to_string_pretty(mounts)?;
    std::fs::write(destination, &json)?;
    Ok(())
}

/// Export a list of SystemdMountEntry objects to a JSON string.
pub fn export_mounts_json_string(mounts: &[SystemdMountEntry]) -> ExportResult<String> {
    let json = serde_json::to_string_pretty(mounts)?;
    Ok(json)
}

/// Import SystemdMountEntry objects from a JSON file.
pub fn import_mounts_json(source: &Path) -> ExportResult<Vec<SystemdMountEntry>> {
    let content = std::fs::read_to_string(source)?;
    import_mounts_from_string(&content)
}

/// Import SystemdMountEntry objects from a JSON string.
pub fn import_mounts_from_string(json: &str) -> ExportResult<Vec<SystemdMountEntry>> {
    let mounts: Vec<SystemdMountEntry> = serde_json::from_str(json)?;

    // Basic validation
    for mount in &mounts {
        if mount.mount_point.is_empty() {
            return Err(ExportError::Validation("Mount entry has empty mount_point".into()));
        }
        if mount.device.is_empty() {
            return Err(ExportError::Validation(
                format!("Mount entry for '{}' has empty device", mount.mount_point),
            ));
        }
        if !mount.mount_point.starts_with('/') {
            return Err(ExportError::Validation(
                format!("Mount point '{}' is not an absolute path", mount.mount_point),
            ));
        }
    }

    Ok(mounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GlobalSettings, Share};
    use tempfile::TempDir;

    #[test]
    fn test_export_import_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let export_path = temp_dir.path().join("config.json");

        let config = SambaConfig {
            global: GlobalSettings::default(),
            shares: vec![Share {
                name: "test".to_string(),
                path: "/srv/test".to_string(),
                ..Share::default()
            }],
        };

        // Export
        export_config_json(&config, &export_path).unwrap();
        assert!(export_path.exists());

        // Import
        let imported = import_config_json(&export_path).unwrap();
        assert_eq!(imported.global.workgroup, config.global.workgroup);
        assert_eq!(imported.shares.len(), 1);
        assert_eq!(imported.shares[0].name, "test");
    }

    #[test]
    fn test_export_json_string() {
        let config = SambaConfig::default();
        let json = export_config_json_string(&config).unwrap();
        assert!(json.contains("WORKGROUP"));
        assert!(json.contains("global"));
    }

    #[test]
    fn test_import_invalid_json() {
        let result = import_config_from_string("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_import_validates_config() {
        // Config with empty workgroup should fail validation
        let json = r#"{
            "global": {
                "workgroup": "",
                "server_string": "%h",
                "netbios_name": "",
                "security": "User",
                "guest_account": "nobody",
                "map_to_guest": "Never",
                "dns_proxy": false,
                "socket_options": "TCP_NODELAY",
                "winbind_nss_info": "template",
                "passdb_backend": "tdbsam",
                "smb_encrypt": "required",
                "server_min_protocol": "SMB3_11",
                "server_max_protocol": "SMB3_11",
                "client_min_protocol": "SMB3_11",
                "client_max_protocol": "SMB3_11",
                "server_signing": "mandatory",
                "client_signing": "mandatory",
                "interfaces": "",
                "bind_interfaces_only": false,
                "hosts_allow": "",
                "hosts_deny": "",
                "wins_support": false,
                "wins_server": "",
                "name_resolve_order": "lmhosts host wins bcast",
                "realm": "",
                "password_server": "",
                "unix_password_sync": false,
                "domain_master": false,
                "local_master": true,
                "preferred_master": false,
                "os_level": 20,
                "logon_drive": "",
                "logon_home": "",
                "logon_path": "",
                "logon_script": "",
                "username_map": "",
                "smb_passwd_file": "",
                "wins_proxy": false,
                "restrict_anonymous": 1,
                "ntlm_auth": "ntlmv2-only",
                "client_ntlmv2_auth": true,
                "wide_links": false,
                "unix_extensions": false,
                "case_sensitive": false,
                "load_printers": false,
                "disable_spoolss": true,
                "log_file": "/var/log/samba/log.%m",
                "log_level": "1",
                "max_log_size": 5000,
                "read_raw": true,
                "write_raw": true,
                "max_xmit": 65535,
                "deadtime": 15,
                "keepalive": 60
            },
            "shares": []
        }"#;
        let result = import_config_from_string(json);
        assert!(result.is_err());
        if let Err(ExportError::Validation(msg)) = result {
            assert!(msg.to_lowercase().contains("workgroup"));
        }
    }

    #[test]
    fn test_import_file_not_found() {
        let result = import_config_json(Path::new("/nonexistent/path.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_export_import_mounts_roundtrip() {
        use crate::config::SystemdMountEntry;
        let temp_dir = TempDir::new().unwrap();
        let export_path = temp_dir.path().join("mounts.json");

        let mounts = vec![
            SystemdMountEntry {
                unit_name: "mnt-share.mount".to_string(),
                description: "Test mount".to_string(),
                device: "//server/share".to_string(),
                mount_point: "/mnt/share".to_string(),
                fs_type: "cifs".to_string(),
                options: vec!["_netdev".to_string(), "nofail".to_string()],
                automount: true,
                timeout_sec: Some(30),
                enabled: true,
                active: false,
            },
        ];

        export_mounts_json(&mounts, &export_path).unwrap();
        assert!(export_path.exists());

        let imported = import_mounts_json(&export_path).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].device, "//server/share");
        assert_eq!(imported[0].mount_point, "/mnt/share");
        assert!(imported[0].automount);
    }

    #[test]
    fn test_import_mounts_validates_empty_mount_point() {
        let json = r#"[{"unit_name":"","description":"","device":"//s/s","mount_point":"","fs_type":"cifs","options":[],"automount":false,"timeout_sec":null,"enabled":true,"active":false}]"#;
        let result = import_mounts_from_string(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_import_mounts_validates_relative_path() {
        let json = r#"[{"unit_name":"","description":"","device":"//s/s","mount_point":"relative/path","fs_type":"cifs","options":[],"automount":false,"timeout_sec":null,"enabled":true,"active":false}]"#;
        let result = import_mounts_from_string(json);
        assert!(result.is_err());
    }
}
