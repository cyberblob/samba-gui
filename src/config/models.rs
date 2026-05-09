use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Security mode for SAMBA configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityMode {
    User,
    Share,
    Server,
    Domain,
    ADS,
}

impl Default for SecurityMode {
    fn default() -> Self {
        SecurityMode::User
    }
}

impl std::fmt::Display for SecurityMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityMode::User => write!(f, "user"),
            SecurityMode::Share => write!(f, "share"),
            SecurityMode::Server => write!(f, "server"),
            SecurityMode::Domain => write!(f, "domain"),
            SecurityMode::ADS => write!(f, "ads"),
        }
    }
}

/// Authentication method for a CIFS mount
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    Guest,
    CredentialsFile,
    Kerberos,
}

impl Default for AuthMethod {
    fn default() -> Self {
        AuthMethod::Guest
    }
}

/// Global settings for SAMBA server configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlobalSettings {
    pub workgroup: String,
    pub server_string: String,
    pub netbios_name: String,
    pub security: SecurityMode,
    pub guest_account: String,
    pub map_to_guest: String,
    pub dns_proxy: bool,
    pub socket_options: String,
    pub winbind_nss_info: String,
    // Security / protocol settings
    pub passdb_backend: String,
    pub smb_encrypt: String,
    pub server_min_protocol: String,
    pub server_max_protocol: String,
    pub client_min_protocol: String,
    pub client_max_protocol: String,
    pub server_signing: String,
    pub client_signing: String,
    // Networking
    pub interfaces: String,
    pub bind_interfaces_only: bool,
    pub hosts_allow: String,
    pub hosts_deny: String,
    // WINS / Name Resolution
    pub wins_support: bool,
    pub wins_server: String,
    pub name_resolve_order: String,
    // Domain / Authentication
    pub realm: String,
    pub password_server: String,
    pub unix_password_sync: bool,
    pub domain_master: bool,
    pub local_master: bool,
    pub preferred_master: bool,
    pub os_level: u32,
    // Domain logon settings
    pub logon_drive: String,
    pub logon_home: String,
    pub logon_path: String,
    pub logon_script: String,
    // Additional auth/security
    pub username_map: String,
    pub smb_passwd_file: String,
    pub wins_proxy: bool,
    pub restrict_anonymous: u32,
    pub ntlm_auth: String,
    // Client authentication (controls how this machine authenticates to remote servers)
    pub client_ntlmv2_auth: bool,
    // Filesystem / symlinks
    pub wide_links: bool,
    pub unix_extensions: bool,
    pub case_sensitive: bool,
    // Printing
    pub load_printers: bool,
    pub disable_spoolss: bool,
    // Logging
    pub log_file: String,
    pub log_level: String,
    pub max_log_size: u32,
    // Performance
    pub read_raw: bool,
    pub write_raw: bool,
    pub max_xmit: u32,
    pub deadtime: u32,
    pub keepalive: u32,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        GlobalSettings {
            workgroup: "WORKGROUP".to_string(),
            server_string: "%h".to_string(),
            netbios_name: String::new(),
            security: SecurityMode::User,
            guest_account: "nobody".to_string(),
            map_to_guest: "Never".to_string(),
            dns_proxy: false,
            socket_options: "TCP_NODELAY".to_string(),
            winbind_nss_info: "template".to_string(),
            passdb_backend: "tdbsam".to_string(),
            smb_encrypt: "required".to_string(),
            server_min_protocol: "SMB3_11".to_string(),
            server_max_protocol: "SMB3_11".to_string(),
            client_min_protocol: "SMB3_11".to_string(),
            client_max_protocol: "SMB3_11".to_string(),
            server_signing: "mandatory".to_string(),
            client_signing: "mandatory".to_string(),
            interfaces: String::new(),
            bind_interfaces_only: false,
            hosts_allow: String::new(),
            hosts_deny: String::new(),
            wins_support: false,
            wins_server: String::new(),
            name_resolve_order: "lmhosts host wins bcast".to_string(),
            realm: String::new(),
            password_server: String::new(),
            unix_password_sync: false,
            domain_master: false,
            local_master: true,
            preferred_master: false,
            os_level: 20,
            logon_drive: String::new(),
            logon_home: String::new(),
            logon_path: String::new(),
            logon_script: String::new(),
            username_map: String::new(),
            smb_passwd_file: String::new(),
            wins_proxy: false,
            restrict_anonymous: 1,
            ntlm_auth: "ntlmv2-only".to_string(),
            client_ntlmv2_auth: true,
            wide_links: false,
            unix_extensions: false,
            case_sensitive: false,
            load_printers: false,
            disable_spoolss: true,
            log_file: "/var/log/samba/log.%m".to_string(),
            log_level: "1".to_string(),
            max_log_size: 5000,
            read_raw: true,
            write_raw: true,
            max_xmit: 65535,
            deadtime: 15,
            keepalive: 60,
        }
    }
}

/// Template names for quick configuration — now loaded from templates.json.
/// Use `crate::config::template_names()` which returns the dynamically loaded list.

impl GlobalSettings {
    /// Get a pre-configured template by name.
    /// Delegates to the template loader (reads from templates.json).
    pub fn from_template(name: &str) -> Self {
        super::templates::settings_for_template(name)
    }
}

/// A SAMBA share configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Share {
    pub name: String,
    pub path: String,
    pub comment: String,
    pub browsable: bool,
    pub writable: bool,
    pub guest_ok: bool,
    pub read_only: bool,
    pub create_mask: String,
    pub directory_mask: String,
    pub force_create_mode: String,
    pub force_directory_mode: String,
    pub valid_users: Vec<String>,
    pub invalid_users: Vec<String>,
    pub read_list: Vec<String>,
    pub write_list: Vec<String>,
    pub hosts_allow: Vec<String>,
    pub hosts_deny: Vec<String>,
    pub force_user: String,
    pub force_group: String,
    pub inherit_acls: bool,
    pub inherit_permissions: bool,
    pub vfs_objects: Vec<String>,
    pub available: bool,
}

impl Default for Share {
    fn default() -> Self {
        Share {
            name: String::new(),
            path: String::new(),
            comment: String::new(),
            browsable: true,
            writable: false,
            guest_ok: false,
            read_only: true,
            create_mask: "0744".to_string(),
            directory_mask: "0755".to_string(),
            force_create_mode: String::new(),
            force_directory_mode: String::new(),
            valid_users: Vec::new(),
            invalid_users: Vec::new(),
            read_list: Vec::new(),
            write_list: Vec::new(),
            hosts_allow: Vec::new(),
            hosts_deny: Vec::new(),
            force_user: String::new(),
            force_group: String::new(),
            inherit_acls: false,
            inherit_permissions: false,
            vfs_objects: Vec::new(),
            available: true,
        }
    }
}

/// Complete SAMBA configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SambaConfig {
    pub global: GlobalSettings,
    pub shares: Vec<Share>,
}

impl Default for SambaConfig {
    fn default() -> Self {
        SambaConfig {
            global: GlobalSettings::default(),
            shares: Vec::new(),
        }
    }
}

/// A systemd .mount / .automount unit for SMB/CIFS mounts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemdMountEntry {
    /// Derived unit name, e.g. "mnt-share.mount"
    pub unit_name: String,
    /// Human-readable description for the [Unit] section
    pub description: String,
    /// What= field — the remote share (e.g. //server/share)
    pub device: String,
    /// Where= field — local mount point (e.g. /mnt/share)
    pub mount_point: String,
    /// Type= field — filesystem type (normally "cifs")
    pub fs_type: String,
    /// Options= field — comma-separated mount options
    pub options: Vec<String>,
    /// Whether a companion .automount unit should be created
    pub automount: bool,
    /// Optional TimeoutSec= value
    pub timeout_sec: Option<u32>,
    /// Whether the unit is enabled (systemctl is-enabled)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether the unit is currently active (systemctl is-active)
    #[serde(default)]
    pub active: bool,
}

fn default_true() -> bool { true }

impl Default for SystemdMountEntry {
    fn default() -> Self {
        SystemdMountEntry {
            unit_name: String::new(),
            description: String::new(),
            device: String::new(),
            mount_point: String::new(),
            fs_type: "cifs".to_string(),
            options: vec!["_netdev".to_string(), "nofail".to_string()],
            automount: true,
            timeout_sec: Some(30),
            enabled: true,
            active: false,
        }
    }
}

/// Status information for a systemd service
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceStatus {
    pub name: String,
    pub active: bool,
    pub enabled: bool,
    pub substate: String,
    pub state: String,
}

impl Default for ServiceStatus {
    fn default() -> Self {
        ServiceStatus {
            name: String::new(),
            active: false,
            enabled: false,
            substate: "unknown".to_string(),
            state: "unknown".to_string(),
        }
    }
}

/// A SAMBA user account
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SambaUser {
    pub username: String,
    pub enabled: bool,
}

impl Default for SambaUser {
    fn default() -> Self {
        SambaUser {
            username: String::new(),
            enabled: true,
        }
    }
}

/// Information about a configuration backup
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupInfo {
    pub path: String,
    pub timestamp: DateTime<Utc>,
    pub size_bytes: u64,
}

impl Default for BackupInfo {
    fn default() -> Self {
        BackupInfo {
            path: String::new(),
            timestamp: Utc::now(),
            size_bytes: 0,
        }
    }
}