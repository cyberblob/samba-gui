//! WizardState — pure data model for the Mount Wizard.
//!
//! Holds all user-entered data across wizard steps and provides methods for
//! building mount options, converting to/from `SystemdMountEntry`, and
//! validating each step. No GTK dependencies — fully testable.

use crate::config::models::{AuthMethod, SystemdMountEntry};
use crate::services::systemd_mount::SystemdMountManager;

/// The five steps of the Mount Wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    AuthSelection,
    ConnectionDetails,
    MountOptions,
    Validation,
    Summary,
}

/// Holds all user-entered data across wizard steps.
#[derive(Debug, Clone)]
pub struct WizardState {
    // Step 1 — authentication
    pub auth_method: AuthMethod,

    // Step 2 — connection details
    pub share_address: String,
    pub mount_point: String,
    pub credentials_file_path: String,
    pub domain: String,

    // Step 3 — mount options
    pub automount: bool,
    pub nofail: bool,
    pub netdev: bool,
    pub read_only: bool,
    pub timeout_sec: Option<u32>,
    pub uid: String,
    pub gid: String,
    pub file_mode: String,
    pub dir_mode: String,
    pub smb_version: String,
    pub security_mode: String,
    pub client_smb_encrypt: String,
    pub extra_options: String,

    // Step 4 — validation results (populated by ValidationEngine later)
    pub validation_results: Vec<String>,

    // Edit mode — the original entry being edited, if any
    pub editing: Option<SystemdMountEntry>,
}

impl WizardState {
    /// Create a new `WizardState` with sensible defaults for adding a mount.
    pub fn new() -> Self {
        Self {
            auth_method: AuthMethod::Guest,
            share_address: String::new(),
            mount_point: String::new(),
            credentials_file_path: String::new(),
            domain: String::new(),
            automount: true,
            nofail: true,
            netdev: true,
            read_only: false,
            timeout_sec: None,
            uid: String::new(),
            gid: String::new(),
            file_mode: String::new(),
            dir_mode: String::new(),
            smb_version: "auto".to_string(),
            security_mode: String::new(),
            client_smb_encrypt: "default".to_string(),
            extra_options: String::new(),
            validation_results: Vec::new(),
            editing: None,
        }
    }

    /// Detect the authentication method from a list of mount options.
    ///
    /// Checks for `"guest"`, any option starting with `"credentials="`, and
    /// `"sec=krb5"`. Falls back to `CredentialsFile` when no marker is found.
    pub fn detect_auth_method(options: &[String]) -> AuthMethod {
        for opt in options {
            let lower = opt.to_lowercase();
            if lower == "guest" {
                return AuthMethod::Guest;
            }
            if lower.starts_with("credentials=") {
                return AuthMethod::CredentialsFile;
            }
            if lower == "sec=krb5" {
                return AuthMethod::Kerberos;
            }
        }
        AuthMethod::CredentialsFile
    }

    /// Pre-populate a `WizardState` from an existing `SystemdMountEntry` (edit mode).
    pub fn from_entry(entry: &SystemdMountEntry) -> Self {
        let auth_method = Self::detect_auth_method(&entry.options);

        let mut credentials_file_path = String::new();
        let mut domain = String::new();
        let mut uid = String::new();
        let mut gid = String::new();
        let mut file_mode = String::new();
        let mut dir_mode = String::new();
        let mut smb_version = "auto".to_string();
        let mut security_mode = String::new();
        let mut client_smb_encrypt = "default".to_string();
        let mut nofail = false;
        let mut netdev = false;
        let mut read_only = false;
        let mut extra = Vec::new();

        for opt in &entry.options {
            let lower = opt.to_lowercase();
            if lower.starts_with("credentials=") {
                credentials_file_path = opt.splitn(2, '=').nth(1).unwrap_or("").to_string();
            } else if lower.starts_with("domain=") {
                domain = opt.splitn(2, '=').nth(1).unwrap_or("").to_string();
            } else if lower.starts_with("uid=") {
                uid = opt.splitn(2, '=').nth(1).unwrap_or("").to_string();
            } else if lower.starts_with("gid=") {
                gid = opt.splitn(2, '=').nth(1).unwrap_or("").to_string();
            } else if lower.starts_with("file_mode=") {
                file_mode = opt.splitn(2, '=').nth(1).unwrap_or("").to_string();
            } else if lower.starts_with("dir_mode=") {
                dir_mode = opt.splitn(2, '=').nth(1).unwrap_or("").to_string();
            } else if lower.starts_with("vers=") {
                smb_version = opt.splitn(2, '=').nth(1).unwrap_or("auto").to_string();
            } else if lower.starts_with("sec=") {
                security_mode = opt.splitn(2, '=').nth(1).unwrap_or("").to_string();
            } else if lower == "nofail" {
                nofail = true;
            } else if lower == "_netdev" {
                netdev = true;
            } else if lower == "ro" {
                read_only = true;
            } else if lower == "rw" {
                read_only = false;
            } else if lower == "seal" {
                client_smb_encrypt = "required".to_string();
            } else if lower == "guest" {
                // handled by detect_auth_method
            } else {
                extra.push(opt.clone());
            }
        }

        Self {
            auth_method,
            share_address: entry.device.clone(),
            mount_point: entry.mount_point.clone(),
            credentials_file_path,
            domain,
            automount: entry.automount,
            nofail,
            netdev,
            read_only,
            timeout_sec: entry.timeout_sec,
            uid,
            gid,
            file_mode,
            dir_mode,
            smb_version,
            security_mode,
            client_smb_encrypt,
            extra_options: extra.join(","),
            validation_results: Vec::new(),
            editing: Some(entry.clone()),
        }
    }

    /// Assemble the mount options vector from the current state.
    ///
    /// Assembly order (per design):
    /// 1. Auth-specific (`guest` / `credentials=<path>` / `sec=krb5`)
    /// 2. `_netdev` if enabled
    /// 3. `nofail` if enabled
    /// 4. `ro` or `rw`
    /// 5. `uid=<uid>` if non-empty
    /// 6. `gid=<gid>` if non-empty
    /// 7. `file_mode=<mode>` if non-empty
    /// 8. `dir_mode=<mode>` if non-empty
    /// 9. `vers=<version>` if not "auto"
    /// 10. `sec=<mode>` if not Kerberos and non-empty
    /// 11. `domain=<domain>` if non-empty
    /// 12. Extra options split by comma
    pub fn build_mount_options(&self) -> Vec<String> {
        let mut opts = Vec::new();

        // 1. Auth-specific options
        match self.auth_method {
            AuthMethod::Guest => {
                opts.push("guest".to_string());
            }
            AuthMethod::CredentialsFile => {
                opts.push(format!("credentials={}", self.credentials_file_path));
            }
            AuthMethod::Kerberos => {
                opts.push("sec=krb5".to_string());
            }
        }

        // 2. _netdev
        if self.netdev {
            opts.push("_netdev".to_string());
        }

        // 3. nofail
        if self.nofail {
            opts.push("nofail".to_string());
        }

        // 4. ro / rw
        if self.read_only {
            opts.push("ro".to_string());
        } else {
            opts.push("rw".to_string());
        }

        // 5. uid
        if !self.uid.is_empty() {
            opts.push(format!("uid={}", self.uid));
        }

        // 6. gid
        if !self.gid.is_empty() {
            opts.push(format!("gid={}", self.gid));
        }

        // 7. file_mode
        if !self.file_mode.is_empty() {
            opts.push(format!("file_mode={}", self.file_mode));
        }

        // 8. dir_mode
        if !self.dir_mode.is_empty() {
            opts.push(format!("dir_mode={}", self.dir_mode));
        }

        // 9. vers (only if not "auto")
        if !self.smb_version.is_empty() && self.smb_version != "auto" {
            opts.push(format!("vers={}", self.smb_version));
        }

        // 10. sec — only for non-Kerberos (Kerberos already emitted sec=krb5 above)
        if self.auth_method != AuthMethod::Kerberos && !self.security_mode.is_empty() {
            opts.push(format!("sec={}", self.security_mode));
        }

        // 11. seal — client SMB encryption (only when "required" or "desired")
        if self.client_smb_encrypt == "required" || self.client_smb_encrypt == "desired" {
            opts.push("seal".to_string());
        }

        // 12. domain
        if !self.domain.is_empty() {
            opts.push(format!("domain={}", self.domain));
        }

        // 13. Extra options
        for extra in self.extra_options.split(',') {
            let trimmed = extra.trim();
            if !trimmed.is_empty() {
                opts.push(trimmed.to_string());
            }
        }

        opts
    }

    /// Convert the current wizard state into a `SystemdMountEntry`.
    pub fn to_mount_entry(&self) -> SystemdMountEntry {
        let unit_name = SystemdMountManager::mount_unit_name(&self.mount_point);
        SystemdMountEntry {
            unit_name,
            description: format!("CIFS mount for {}", self.share_address),
            device: self.share_address.clone(),
            mount_point: self.mount_point.clone(),
            fs_type: "cifs".to_string(),
            options: self.build_mount_options(),
            automount: self.automount,
            timeout_sec: self.timeout_sec,
            enabled: true,
            active: false,
        }
    }

    /// Validate the inputs for a given wizard step.
    ///
    /// Returns a list of error messages. An empty list means the step is valid.
    pub fn validate_step(&self, step: WizardStep) -> Vec<String> {
        match step {
            WizardStep::AuthSelection => {
                // Auth selection is always valid — the user picks one of three options.
                Vec::new()
            }
            WizardStep::ConnectionDetails => {
                let mut errors = Vec::new();

                // Share address validation
                if self.share_address.is_empty() {
                    errors.push("Share address is required.".to_string());
                } else if !self.share_address.starts_with("//") {
                    errors.push("Share address must start with //.".to_string());
                } else {
                    let without_prefix = &self.share_address[2..];
                    let parts: Vec<&str> = without_prefix.splitn(2, '/').collect();
                    if parts.is_empty() || parts[0].is_empty() {
                        errors.push("Share address is missing a hostname.".to_string());
                    } else if parts.len() < 2 || parts[1].is_empty() {
                        errors.push("Share address is missing a share name.".to_string());
                    }
                }

                // Mount point validation
                if self.mount_point.is_empty() {
                    errors.push("Mount point is required.".to_string());
                } else if !self.mount_point.starts_with('/') {
                    errors.push("Mount point must be an absolute path.".to_string());
                } else if self.mount_point.contains("..") {
                    errors.push("Mount point must not contain '..'.".to_string());
                }

                // Kerberos requires an FQDN — reject short/NetBIOS hostnames
                if self.auth_method == AuthMethod::Kerberos && errors.is_empty() {
                    let without_prefix = &self.share_address[2..];
                    if let Some(host) = without_prefix.split('/').next() {
                        if !host.is_empty() && !host.contains('.') {
                            errors.push(format!(
                                "Kerberos requires a fully qualified domain name (FQDN). \
                                 '{}' looks like a NetBIOS/short name — use something like \
                                 '{}.yourdomain.local' instead.",
                                host, host
                            ));
                        }
                    }
                }

                // Credentials file path (only for CredentialsFile auth)
                if self.auth_method == AuthMethod::CredentialsFile {
                    if self.credentials_file_path.is_empty() {
                        errors.push("Credentials file path is required.".to_string());
                    } else if !self.credentials_file_path.starts_with('/') {
                        errors.push("Credentials file path must be an absolute path.".to_string());
                    } else if self.credentials_file_path.contains("..") {
                        errors.push("Credentials file path must not contain '..'.".to_string());
                    } else if Self::has_dangerous_chars(&self.credentials_file_path) {
                        errors.push("Credentials file path contains forbidden characters.".to_string());
                    }
                }

                // Domain validation (if provided)
                if !self.domain.is_empty() && Self::has_dangerous_chars(&self.domain) {
                    errors.push("Domain contains forbidden characters.".to_string());
                }

                errors
            }
            WizardStep::MountOptions => {
                let mut errors = Vec::new();

                // UID validation — must be numeric if provided
                if !self.uid.is_empty() && !self.uid.chars().all(|c| c.is_ascii_digit()) {
                    errors.push("UID must be a numeric value.".to_string());
                }

                // GID validation — must be numeric if provided
                if !self.gid.is_empty() && !self.gid.chars().all(|c| c.is_ascii_digit()) {
                    errors.push("GID must be a numeric value.".to_string());
                }

                // file_mode validation — must be valid octal
                if !self.file_mode.is_empty() {
                    if let Err(e) = Self::validate_octal(&self.file_mode, "File mode") {
                        errors.push(e);
                    }
                }

                // dir_mode validation — must be valid octal
                if !self.dir_mode.is_empty() {
                    if let Err(e) = Self::validate_octal(&self.dir_mode, "Directory mode") {
                        errors.push(e);
                    }
                }

                // extra_options — reject dangerous characters
                if !self.extra_options.is_empty() && Self::has_dangerous_chars(&self.extra_options) {
                    errors.push("Extra options contain forbidden characters.".to_string());
                }

                errors
            }
            WizardStep::Validation => {
                // Validation step errors come from the ValidationEngine (task 4).
                // This method only does local/synchronous checks.
                Vec::new()
            }
            WizardStep::Summary => {
                // Summary step has no additional validation.
                Vec::new()
            }
        }
    }

    /// Characters that are dangerous in shell contexts or systemd unit fields.
    const DANGEROUS_CHARS: &'static [char] = &[
        '\'', '"', '`', '$', '\\', '!', '|', '&', ';', '\n', '\r', '\t',
        '(', ')', '{', '}', '<', '>', '~', '#', '\0',
    ];

    /// Check if a string contains any dangerous/shell-injection characters.
    fn has_dangerous_chars(value: &str) -> bool {
        value.chars().any(|c| Self::DANGEROUS_CHARS.contains(&c) || c.is_control())
    }

    /// Validate an octal mode string (e.g. "0644", "0755").
    fn validate_octal(value: &str, field_name: &str) -> Result<(), String> {
        if value.len() > 4 {
            return Err(format!("{} is too long (max 4 digits).", field_name));
        }
        if !value.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("{} must contain only digits.", field_name));
        }
        if value.chars().any(|c| c > '7') {
            return Err(format!("{} must be octal (digits 0-7 only).", field_name));
        }
        Ok(())
    }

    /// Return the list of systemd unit filenames that will be created.
    ///
    /// Always includes the `.mount` unit. Includes the `.automount` unit if
    /// `automount` is true. Includes `krb5-kinit.service` if the auth method
    /// is Kerberos (the kinit service may already exist — the UI layer checks
    /// that separately).
    pub fn summary_unit_filenames(&self) -> Vec<String> {
        let mut filenames = Vec::new();

        // .mount unit is always created
        filenames.push(SystemdMountManager::mount_unit_name(&self.mount_point));

        // .automount unit if automount is enabled
        if self.automount {
            filenames.push(SystemdMountManager::automount_unit_name(&self.mount_point));
        }

        // krb5-kinit.service if Kerberos auth
        if self.auth_method == AuthMethod::Kerberos {
            filenames.push("krb5-kinit.service".to_string());
        }

        filenames
    }
}

impl Default for WizardState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_new_defaults() {
        let state = WizardState::new();
        assert_eq!(state.auth_method, AuthMethod::Guest);
        assert!(state.share_address.is_empty());
        assert!(state.mount_point.is_empty());
        assert!(state.automount);
        assert!(state.nofail);
        assert!(state.netdev);
        assert!(!state.read_only);
        assert_eq!(state.smb_version, "auto");
        assert!(state.security_mode.is_empty());
        assert!(state.editing.is_none());
    }

    #[test]
    fn test_detect_auth_method_guest() {
        let opts = vec!["guest".to_string(), "_netdev".to_string()];
        assert_eq!(WizardState::detect_auth_method(&opts), AuthMethod::Guest);
    }

    #[test]
    fn test_detect_auth_method_credentials() {
        let opts = vec!["credentials=/root/.smbcred".to_string(), "_netdev".to_string()];
        assert_eq!(
            WizardState::detect_auth_method(&opts),
            AuthMethod::CredentialsFile
        );
    }

    #[test]
    fn test_detect_auth_method_kerberos() {
        let opts = vec!["sec=krb5".to_string(), "_netdev".to_string()];
        assert_eq!(WizardState::detect_auth_method(&opts), AuthMethod::Kerberos);
    }

    #[test]
    fn test_detect_auth_method_fallback() {
        let opts = vec!["_netdev".to_string(), "nofail".to_string()];
        assert_eq!(
            WizardState::detect_auth_method(&opts),
            AuthMethod::CredentialsFile
        );
    }

    #[test]
    fn test_build_mount_options_guest() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::Guest;
        state.share_address = "//server/share".to_string();
        state.mount_point = "/mnt/share".to_string();

        let opts = state.build_mount_options();
        assert!(opts.contains(&"guest".to_string()));
        assert!(opts.contains(&"_netdev".to_string()));
        assert!(opts.contains(&"nofail".to_string()));
        assert!(opts.contains(&"rw".to_string()));
    }

    #[test]
    fn test_build_mount_options_credentials() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::CredentialsFile;
        state.credentials_file_path = "/root/.smbcred".to_string();

        let opts = state.build_mount_options();
        assert!(opts.contains(&"credentials=/root/.smbcred".to_string()));
        assert!(!opts.iter().any(|o| o == "guest"));
    }

    #[test]
    fn test_build_mount_options_kerberos() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::Kerberos;
        state.security_mode = "ntlm".to_string(); // should be ignored

        let opts = state.build_mount_options();
        assert!(opts.contains(&"sec=krb5".to_string()));
        // Should NOT contain sec=ntlm — Kerberos locks to krb5
        assert!(!opts.iter().any(|o| o == "sec=ntlm"));
    }

    #[test]
    fn test_build_mount_options_non_kerberos_security_mode() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::Guest;
        state.security_mode = "ntlm".to_string();

        let opts = state.build_mount_options();
        assert!(opts.contains(&"sec=ntlm".to_string()));
    }

    #[test]
    fn test_build_mount_options_smb_version() {
        let mut state = WizardState::new();
        state.smb_version = "3.0".to_string();

        let opts = state.build_mount_options();
        assert!(opts.contains(&"vers=3.0".to_string()));
    }

    #[test]
    fn test_build_mount_options_smb_version_auto_omitted() {
        let state = WizardState::new();
        let opts = state.build_mount_options();
        assert!(!opts.iter().any(|o| o.starts_with("vers=")));
    }

    #[test]
    fn test_build_mount_options_extra() {
        let mut state = WizardState::new();
        state.extra_options = "noperm, seal".to_string();

        let opts = state.build_mount_options();
        assert!(opts.contains(&"noperm".to_string()));
        assert!(opts.contains(&"seal".to_string()));
    }

    #[test]
    fn test_build_mount_options_uid_gid_modes() {
        let mut state = WizardState::new();
        state.uid = "1000".to_string();
        state.gid = "1000".to_string();
        state.file_mode = "0644".to_string();
        state.dir_mode = "0755".to_string();

        let opts = state.build_mount_options();
        assert!(opts.contains(&"uid=1000".to_string()));
        assert!(opts.contains(&"gid=1000".to_string()));
        assert!(opts.contains(&"file_mode=0644".to_string()));
        assert!(opts.contains(&"dir_mode=0755".to_string()));
    }

    #[test]
    fn test_build_mount_options_read_only() {
        let mut state = WizardState::new();
        state.read_only = true;

        let opts = state.build_mount_options();
        assert!(opts.contains(&"ro".to_string()));
        assert!(!opts.contains(&"rw".to_string()));
    }

    #[test]
    fn test_to_mount_entry() {
        let mut state = WizardState::new();
        state.share_address = "//nas/data".to_string();
        state.mount_point = "/mnt/data".to_string();
        state.automount = true;
        state.timeout_sec = Some(30);

        let entry = state.to_mount_entry();
        assert_eq!(entry.device, "//nas/data");
        assert_eq!(entry.mount_point, "/mnt/data");
        assert_eq!(entry.fs_type, "cifs");
        assert!(entry.automount);
        assert_eq!(entry.timeout_sec, Some(30));
        assert_eq!(entry.unit_name, "mnt-data.mount");
        assert_eq!(entry.description, "CIFS mount for //nas/data");
    }

    #[test]
    fn test_from_entry_guest() {
        let entry = SystemdMountEntry {
            unit_name: "mnt-share.mount".to_string(),
            description: "Test".to_string(),
            device: "//server/share".to_string(),
            mount_point: "/mnt/share".to_string(),
            fs_type: "cifs".to_string(),
            options: vec![
                "guest".to_string(),
                "_netdev".to_string(),
                "nofail".to_string(),
                "rw".to_string(),
            ],
            automount: true,
            timeout_sec: Some(30),
            enabled: true,
            active: false,
        };

        let state = WizardState::from_entry(&entry);
        assert_eq!(state.auth_method, AuthMethod::Guest);
        assert_eq!(state.share_address, "//server/share");
        assert_eq!(state.mount_point, "/mnt/share");
        assert!(state.nofail);
        assert!(state.netdev);
        assert!(!state.read_only);
        assert!(state.automount);
        assert_eq!(state.timeout_sec, Some(30));
        assert!(state.editing.is_some());
    }

    #[test]
    fn test_from_entry_credentials() {
        let entry = SystemdMountEntry {
            unit_name: "mnt-share.mount".to_string(),
            description: "Test".to_string(),
            device: "//server/share".to_string(),
            mount_point: "/mnt/share".to_string(),
            fs_type: "cifs".to_string(),
            options: vec![
                "credentials=/root/.smbcred".to_string(),
                "_netdev".to_string(),
                "nofail".to_string(),
                "domain=EXAMPLE".to_string(),
                "uid=1000".to_string(),
                "vers=3.0".to_string(),
            ],
            automount: false,
            timeout_sec: None,
            enabled: true,
            active: false,
        };

        let state = WizardState::from_entry(&entry);
        assert_eq!(state.auth_method, AuthMethod::CredentialsFile);
        assert_eq!(state.credentials_file_path, "/root/.smbcred");
        assert_eq!(state.domain, "EXAMPLE");
        assert_eq!(state.uid, "1000");
        assert_eq!(state.smb_version, "3.0");
        assert!(!state.automount);
    }

    #[test]
    fn test_from_entry_kerberos() {
        let entry = SystemdMountEntry {
            unit_name: "mnt-share.mount".to_string(),
            description: "Test".to_string(),
            device: "//nas.example.com/share".to_string(),
            mount_point: "/mnt/share".to_string(),
            fs_type: "cifs".to_string(),
            options: vec![
                "sec=krb5".to_string(),
                "_netdev".to_string(),
                "nofail".to_string(),
            ],
            automount: true,
            timeout_sec: Some(60),
            enabled: true,
            active: false,
        };

        let state = WizardState::from_entry(&entry);
        assert_eq!(state.auth_method, AuthMethod::Kerberos);
        assert_eq!(state.security_mode, "krb5");
        assert_eq!(state.share_address, "//nas.example.com/share");
    }

    #[test]
    fn test_validate_step_auth_always_valid() {
        let state = WizardState::new();
        assert!(state.validate_step(WizardStep::AuthSelection).is_empty());
    }

    #[test]
    fn test_validate_step_connection_empty() {
        let state = WizardState::new();
        let errors = state.validate_step(WizardStep::ConnectionDetails);
        assert!(errors.iter().any(|e| e.contains("Share address")));
        assert!(errors.iter().any(|e| e.contains("Mount point")));
    }

    #[test]
    fn test_validate_step_connection_invalid_share() {
        let mut state = WizardState::new();
        state.share_address = "server/share".to_string();
        state.mount_point = "/mnt/share".to_string();

        let errors = state.validate_step(WizardStep::ConnectionDetails);
        assert!(errors.iter().any(|e| e.contains("must start with //")));
    }

    #[test]
    fn test_validate_step_connection_missing_hostname() {
        let mut state = WizardState::new();
        state.share_address = "///share".to_string();
        state.mount_point = "/mnt/share".to_string();

        let errors = state.validate_step(WizardStep::ConnectionDetails);
        assert!(errors.iter().any(|e| e.contains("hostname")));
    }

    #[test]
    fn test_validate_step_connection_missing_share_name() {
        let mut state = WizardState::new();
        state.share_address = "//server".to_string();
        state.mount_point = "/mnt/share".to_string();

        let errors = state.validate_step(WizardStep::ConnectionDetails);
        assert!(errors.iter().any(|e| e.contains("share name")));
    }

    #[test]
    fn test_validate_step_connection_relative_mount() {
        let mut state = WizardState::new();
        state.share_address = "//server/share".to_string();
        state.mount_point = "mnt/share".to_string();

        let errors = state.validate_step(WizardStep::ConnectionDetails);
        assert!(errors.iter().any(|e| e.contains("absolute path")));
    }

    #[test]
    fn test_validate_step_connection_credentials_missing_path() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::CredentialsFile;
        state.share_address = "//server/share".to_string();
        state.mount_point = "/mnt/share".to_string();

        let errors = state.validate_step(WizardStep::ConnectionDetails);
        assert!(errors.iter().any(|e| e.contains("Credentials file")));
    }

    #[test]
    fn test_validate_step_connection_valid() {
        let mut state = WizardState::new();
        state.share_address = "//server/share".to_string();
        state.mount_point = "/mnt/share".to_string();

        let errors = state.validate_step(WizardStep::ConnectionDetails);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_step_mount_options_always_valid() {
        let state = WizardState::new();
        assert!(state.validate_step(WizardStep::MountOptions).is_empty());
    }

    #[test]
    fn test_summary_unit_filenames_guest_with_automount() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::Guest;
        state.mount_point = "/mnt/share".to_string();
        state.automount = true;

        let filenames = state.summary_unit_filenames();
        assert_eq!(filenames.len(), 2);
        assert!(filenames.contains(&"mnt-share.mount".to_string()));
        assert!(filenames.contains(&"mnt-share.automount".to_string()));
    }

    #[test]
    fn test_summary_unit_filenames_guest_no_automount() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::Guest;
        state.mount_point = "/mnt/share".to_string();
        state.automount = false;

        let filenames = state.summary_unit_filenames();
        assert_eq!(filenames.len(), 1);
        assert!(filenames.contains(&"mnt-share.mount".to_string()));
    }

    #[test]
    fn test_summary_unit_filenames_kerberos_with_automount() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::Kerberos;
        state.mount_point = "/mnt/share".to_string();
        state.automount = true;

        let filenames = state.summary_unit_filenames();
        assert_eq!(filenames.len(), 3);
        assert!(filenames.contains(&"mnt-share.mount".to_string()));
        assert!(filenames.contains(&"mnt-share.automount".to_string()));
        assert!(filenames.contains(&"krb5-kinit.service".to_string()));
    }

    #[test]
    fn test_summary_unit_filenames_kerberos_no_automount() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::Kerberos;
        state.mount_point = "/mnt/share".to_string();
        state.automount = false;

        let filenames = state.summary_unit_filenames();
        assert_eq!(filenames.len(), 2);
        assert!(filenames.contains(&"mnt-share.mount".to_string()));
        assert!(filenames.contains(&"krb5-kinit.service".to_string()));
    }

    #[test]
    fn test_build_mount_options_domain() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::CredentialsFile;
        state.credentials_file_path = "/root/.smbcred".to_string();
        state.domain = "EXAMPLE".to_string();

        let opts = state.build_mount_options();
        assert!(opts.contains(&"domain=EXAMPLE".to_string()));
    }

    #[test]
    fn test_build_mount_options_netdev_disabled() {
        let mut state = WizardState::new();
        state.netdev = false;

        let opts = state.build_mount_options();
        assert!(!opts.contains(&"_netdev".to_string()));
    }

    #[test]
    fn test_build_mount_options_nofail_disabled() {
        let mut state = WizardState::new();
        state.nofail = false;

        let opts = state.build_mount_options();
        assert!(!opts.contains(&"nofail".to_string()));
    }

    // ---------------------------------------------------------------
    // Property-based tests (proptest)
    // ---------------------------------------------------------------

    /// Generator for arbitrary security mode strings, including empty,
    /// well-known CIFS modes, and random alphanumeric values.
    fn arb_security_mode() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::new()),
            Just("none".to_string()),
            Just("ntlm".to_string()),
            Just("ntlmi".to_string()),
            Just("ntlmv2".to_string()),
            Just("ntlmv2i".to_string()),
            Just("ntlmssp".to_string()),
            Just("ntlmsspi".to_string()),
            Just("krb5".to_string()),
            Just("krb5i".to_string()),
            "[a-zA-Z0-9]{1,12}".prop_map(|s| s),
        ]
    }

    /// Generator for an arbitrary WizardState with auth_method = Kerberos
    /// and a random security_mode value.
    fn arb_kerberos_wizard_state() -> impl Strategy<Value = WizardState> {
        (
            arb_security_mode(),
            proptest::bool::ANY,   // nofail
            proptest::bool::ANY,   // netdev
            proptest::bool::ANY,   // read_only
            proptest::bool::ANY,   // automount
            "[a-zA-Z0-9]{0,6}",   // uid
            "[a-zA-Z0-9]{0,6}",   // gid
            "[0-7]{0,4}",         // file_mode
            "[0-7]{0,4}",         // dir_mode
            prop::sample::select(vec![
                "auto".to_string(),
                "1.0".to_string(),
                "2.0".to_string(),
                "2.1".to_string(),
                "3.0".to_string(),
                "3.0.2".to_string(),
                "3.1.1".to_string(),
            ]),
            "[a-zA-Z0-9, ]{0,20}", // extra_options
        )
            .prop_map(
                |(
                    security_mode,
                    nofail,
                    netdev,
                    read_only,
                    automount,
                    uid,
                    gid,
                    file_mode,
                    dir_mode,
                    smb_version,
                    extra_options,
                )| {
                    WizardState {
                        auth_method: AuthMethod::Kerberos,
                        share_address: "//nas.example.com/share".to_string(),
                        mount_point: "/mnt/share".to_string(),
                        credentials_file_path: String::new(),
                        domain: String::new(),
                        automount,
                        nofail,
                        netdev,
                        read_only,
                        timeout_sec: None,
                        uid,
                        gid,
                        file_mode,
                        dir_mode,
                        smb_version,
                        security_mode,
                        client_smb_encrypt: "default".to_string(),
                        extra_options,
                        validation_results: Vec::new(),
                        editing: None,
                    }
                },
            )
    }

    /// Generator for valid share addresses in the form `//host.domain/share`.
    fn arb_share_address() -> impl Strategy<Value = String> {
        (
            "[a-zA-Z][a-zA-Z0-9]{0,10}",   // hostname part
            "[a-zA-Z]{2,6}",                // domain part
            "[a-zA-Z][a-zA-Z0-9_]{0,10}",  // share name
        )
            .prop_map(|(host, domain, share)| format!("//{}.{}/{}", host, domain, share))
    }

    /// Generator for valid absolute mount point paths.
    fn arb_mount_point() -> impl Strategy<Value = String> {
        (
            "[a-zA-Z][a-zA-Z0-9]{0,8}",  // first path component
            "[a-zA-Z][a-zA-Z0-9]{0,8}",  // second path component
        )
            .prop_map(|(a, b)| format!("/{}/{}", a, b))
    }

    /// Generator for an arbitrary WizardState with auth_method = Guest,
    /// arbitrary share address and mount point, and randomised option fields.
    ///
    /// Per Requirements 2.1 and 2.2, Guest mounts always include `_netdev`
    /// and `nofail`, so those toggles are fixed to `true`. All other option
    /// fields are randomised to exercise the full option-assembly path.
    fn arb_guest_wizard_state() -> impl Strategy<Value = WizardState> {
        (
            arb_share_address(),
            arb_mount_point(),
            proptest::bool::ANY,   // read_only
            proptest::bool::ANY,   // automount
            "[a-zA-Z0-9]{0,6}",   // uid
            "[a-zA-Z0-9]{0,6}",   // gid
            "[0-7]{0,4}",         // file_mode
            "[0-7]{0,4}",         // dir_mode
            (
                prop::sample::select(vec![
                    "auto".to_string(),
                    "1.0".to_string(),
                    "2.0".to_string(),
                    "2.1".to_string(),
                    "3.0".to_string(),
                    "3.0.2".to_string(),
                    "3.1.1".to_string(),
                ]),
                arb_security_mode(),
                "[a-zA-Z0-9, ]{0,20}", // extra_options
            ),
        )
            .prop_map(
                |(
                    share_address,
                    mount_point,
                    read_only,
                    automount,
                    uid,
                    gid,
                    file_mode,
                    dir_mode,
                    (smb_version, security_mode, extra_options),
                )| {
                    WizardState {
                        auth_method: AuthMethod::Guest,
                        share_address,
                        mount_point,
                        credentials_file_path: String::new(),
                        domain: String::new(),
                        automount,
                        nofail: true,
                        netdev: true,
                        read_only,
                        timeout_sec: None,
                        uid,
                        gid,
                        file_mode,
                        dir_mode,
                        smb_version,
                        security_mode,
                        client_smb_encrypt: "default".to_string(),
                        extra_options,
                        validation_results: Vec::new(),
                        editing: None,
                    }
                },
            )
    }

    /// Generator for valid credentials file paths.
    fn arb_credentials_file_path() -> impl Strategy<Value = String> {
        prop_oneof![
            // Typical home-directory paths
            (
                "[a-zA-Z][a-zA-Z0-9]{0,8}",  // username
                "[a-zA-Z][a-zA-Z0-9._-]{0,12}", // filename
            )
                .prop_map(|(user, file)| format!("/home/{}/.{}", user, file)),
            // Root-owned paths
            "[a-zA-Z][a-zA-Z0-9._-]{0,12}"
                .prop_map(|file| format!("/root/.{}", file)),
            // Paths under /etc
            "[a-zA-Z][a-zA-Z0-9._-]{0,12}"
                .prop_map(|file| format!("/etc/samba/{}", file)),
        ]
    }

    /// Generator for an arbitrary WizardState with auth_method = CredentialsFile,
    /// a random credentials file path, and randomised option fields.
    fn arb_credentials_wizard_state() -> impl Strategy<Value = WizardState> {
        (
            arb_share_address(),
            arb_mount_point(),
            arb_credentials_file_path(),
            proptest::bool::ANY,   // read_only
            proptest::bool::ANY,   // automount
            proptest::bool::ANY,   // nofail
            proptest::bool::ANY,   // netdev
            "[a-zA-Z0-9]{0,6}",   // uid
            "[a-zA-Z0-9]{0,6}",   // gid
            (
                "[0-7]{0,4}",         // file_mode
                "[0-7]{0,4}",         // dir_mode
                prop::sample::select(vec![
                    "auto".to_string(),
                    "1.0".to_string(),
                    "2.0".to_string(),
                    "2.1".to_string(),
                    "3.0".to_string(),
                    "3.0.2".to_string(),
                    "3.1.1".to_string(),
                ]),
                arb_security_mode(),
                "[a-zA-Z0-9, ]{0,20}", // extra_options
                "[a-zA-Z]{0,10}",      // domain
            ),
        )
            .prop_map(
                |(
                    share_address,
                    mount_point,
                    credentials_file_path,
                    read_only,
                    automount,
                    nofail,
                    netdev,
                    uid,
                    gid,
                    (file_mode, dir_mode, smb_version, security_mode, extra_options, domain),
                )| {
                    WizardState {
                        auth_method: AuthMethod::CredentialsFile,
                        share_address,
                        mount_point,
                        credentials_file_path,
                        domain,
                        automount,
                        nofail,
                        netdev,
                        read_only,
                        timeout_sec: None,
                        uid,
                        gid,
                        file_mode,
                        dir_mode,
                        smb_version,
                        security_mode,
                        client_smb_encrypt: "default".to_string(),
                        extra_options,
                        validation_results: Vec::new(),
                        editing: None,
                    }
                },
            )
    }

    // Feature: mount-wizard, Property 5: CredentialsFile auth option invariants
    //
    // For any valid credentials file path, build_mount_options() with
    // auth_method = CredentialsFile SHALL contain credentials=<path> matching
    // the configured path.
    // Validates: Requirements 3.5
    proptest! {
        #[test]
        fn test_property_credentials_file_auth_option_invariants(
            state in arb_credentials_wizard_state()
        ) {
            let opts = state.build_mount_options();
            let expected = format!("credentials={}", state.credentials_file_path);

            prop_assert!(
                opts.contains(&expected),
                "CredentialsFile build_mount_options() must contain \"{}\", got: {:?}",
                expected,
                opts
            );

            // Must not contain "guest" option
            prop_assert!(
                !opts.contains(&"guest".to_string()),
                "CredentialsFile build_mount_options() must not contain \"guest\", got: {:?}",
                opts
            );

            // Must not contain "sec=krb5" as the auth-specific option
            // (it may appear if security_mode happens to be "krb5", but that
            // would be at position 10 in assembly order, not position 1)
            let first_opt = &opts[0];
            prop_assert!(
                first_opt == &expected,
                "First option must be credentials=<path>, got: {:?}",
                first_opt
            );
        }
    }

    // Feature: mount-wizard, Property 1: Guest auth option invariants
    //
    // For any valid share address and mount point, build_mount_options() with
    // auth_method = Guest SHALL contain "guest", "_netdev", and "nofail".
    // Validates: Requirements 2.1, 2.2
    proptest! {
        #[test]
        fn test_property_guest_auth_option_invariants(
            state in arb_guest_wizard_state()
        ) {
            let opts = state.build_mount_options();

            prop_assert!(
                opts.contains(&"guest".to_string()),
                "Guest build_mount_options() must contain \"guest\", got: {:?}",
                opts
            );
            prop_assert!(
                opts.contains(&"_netdev".to_string()),
                "Guest build_mount_options() must contain \"_netdev\", got: {:?}",
                opts
            );
            prop_assert!(
                opts.contains(&"nofail".to_string()),
                "Guest build_mount_options() must contain \"nofail\", got: {:?}",
                opts
            );
        }
    }

    // Feature: mount-wizard, Property 9: Kerberos auth locks security mode to krb5
    //
    // For any WizardState with auth_method = Kerberos and any security_mode
    // value, build_mount_options() SHALL contain "sec=krb5" and no other
    // sec= option.
    // Validates: Requirements 11.5
    proptest! {
        #[test]
        fn test_property_kerberos_locks_security_mode_to_krb5(
            state in arb_kerberos_wizard_state()
        ) {
            let opts = state.build_mount_options();

            // Must contain exactly "sec=krb5"
            prop_assert!(
                opts.contains(&"sec=krb5".to_string()),
                "Kerberos build_mount_options() must contain \"sec=krb5\", got: {:?}",
                opts
            );

            // Must not contain any other sec= option
            let sec_options: Vec<&String> = opts
                .iter()
                .filter(|o| o.starts_with("sec=") && *o != "sec=krb5")
                .collect();
            prop_assert!(
                sec_options.is_empty(),
                "Kerberos build_mount_options() must not contain sec= options other than \
                 \"sec=krb5\", but found: {:?}",
                sec_options
            );
        }
    }

    /// Generator for a non-empty security mode string (excludes empty strings).
    fn arb_non_empty_security_mode() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("none".to_string()),
            Just("ntlm".to_string()),
            Just("ntlmi".to_string()),
            Just("ntlmv2".to_string()),
            Just("ntlmv2i".to_string()),
            Just("ntlmssp".to_string()),
            Just("ntlmsspi".to_string()),
            Just("krb5".to_string()),
            Just("krb5i".to_string()),
            "[a-zA-Z][a-zA-Z0-9]{0,11}".prop_map(|s| s),
        ]
    }

    /// Generator for an arbitrary WizardState with auth_method = Guest or
    /// CredentialsFile and a guaranteed non-empty security_mode.
    fn arb_non_kerberos_wizard_state_with_security_mode() -> impl Strategy<Value = WizardState> {
        (
            // Pick either Guest or CredentialsFile
            prop::sample::select(vec![AuthMethod::Guest, AuthMethod::CredentialsFile]),
            arb_share_address(),
            arb_mount_point(),
            arb_credentials_file_path(),
            arb_non_empty_security_mode(),
            proptest::bool::ANY, // nofail
            proptest::bool::ANY, // netdev
            proptest::bool::ANY, // read_only
            proptest::bool::ANY, // automount
            "[a-zA-Z0-9]{0,6}", // uid
            (
                "[a-zA-Z0-9]{0,6}", // gid
                "[0-7]{0,4}",       // file_mode
                "[0-7]{0,4}",       // dir_mode
                prop::sample::select(vec![
                    "auto".to_string(),
                    "1.0".to_string(),
                    "2.0".to_string(),
                    "2.1".to_string(),
                    "3.0".to_string(),
                    "3.0.2".to_string(),
                    "3.1.1".to_string(),
                ]),
                "[a-zA-Z0-9, ]{0,20}", // extra_options
                "[a-zA-Z]{0,10}",       // domain
            ),
        )
            .prop_map(
                |(
                    auth_method,
                    share_address,
                    mount_point,
                    credentials_file_path,
                    security_mode,
                    nofail,
                    netdev,
                    read_only,
                    automount,
                    uid,
                    (gid, file_mode, dir_mode, smb_version, extra_options, domain),
                )| {
                    WizardState {
                        auth_method,
                        share_address,
                        mount_point,
                        credentials_file_path,
                        domain,
                        automount,
                        nofail,
                        netdev,
                        read_only,
                        timeout_sec: None,
                        uid,
                        gid,
                        file_mode,
                        dir_mode,
                        smb_version,
                        security_mode,
                        client_smb_encrypt: "default".to_string(),
                        extra_options,
                        validation_results: Vec::new(),
                        editing: None,
                    }
                },
            )
    }

    // Feature: mount-wizard, Property 10: Non-Kerberos auth uses chosen security mode
    //
    // For any WizardState with auth_method = Guest or CredentialsFile and a
    // non-empty security_mode, build_mount_options() SHALL contain
    // sec=<chosen_mode> matching the configured security mode.
    // Validates: Requirements 11.6
    proptest! {
        #[test]
        fn test_property_non_kerberos_auth_uses_chosen_security_mode(
            state in arb_non_kerberos_wizard_state_with_security_mode()
        ) {
            let opts = state.build_mount_options();
            let expected_sec = format!("sec={}", state.security_mode);

            // The options must contain sec=<chosen_mode>
            prop_assert!(
                opts.contains(&expected_sec),
                "Non-Kerberos ({:?}) build_mount_options() with security_mode=\"{}\" \
                 must contain \"{}\", got: {:?}",
                state.auth_method,
                state.security_mode,
                expected_sec,
                opts
            );

            // The sec= option must appear exactly once
            let sec_count = opts.iter().filter(|o| o.starts_with("sec=")).count();
            prop_assert!(
                sec_count == 1,
                "Non-Kerberos build_mount_options() should contain exactly one sec= option, \
                 found {}: {:?}",
                sec_count,
                opts.iter().filter(|o| o.starts_with("sec=")).collect::<Vec<_>>()
            );
        }
    }

    // ---------------------------------------------------------------
    // Property 11 generators and test
    // ---------------------------------------------------------------

    /// Generator for a `SystemdMountEntry` with `guest` auth marker.
    fn arb_guest_mount_entry() -> impl Strategy<Value = SystemdMountEntry> {
        (
            arb_share_address(),
            arb_mount_point(),
            proptest::bool::ANY,                          // automount
            proptest::option::of(0u32..3600),             // timeout_sec
            proptest::bool::ANY,                          // nofail
            proptest::bool::ANY,                          // netdev
            proptest::bool::ANY,                          // read_only
            "[a-zA-Z0-9]{0,6}",                          // uid
            "[a-zA-Z0-9]{0,6}",                          // gid
            "[0-7]{0,4}",                                 // file_mode
            (
                "[0-7]{0,4}",                             // dir_mode
                prop::sample::select(vec![
                    "auto".to_string(),
                    "1.0".to_string(),
                    "2.0".to_string(),
                    "3.0".to_string(),
                    "3.1.1".to_string(),
                ]),
                "[a-zA-Z]{0,10}",                         // domain
            ),
        )
            .prop_map(
                |(
                    device,
                    mount_point,
                    automount,
                    timeout_sec,
                    nofail,
                    netdev,
                    read_only,
                    uid,
                    gid,
                    file_mode,
                    (dir_mode, smb_version, domain),
                )| {
                    let mut options = vec!["guest".to_string()];
                    if netdev { options.push("_netdev".to_string()); }
                    if nofail { options.push("nofail".to_string()); }
                    if read_only { options.push("ro".to_string()); } else { options.push("rw".to_string()); }
                    if !uid.is_empty() { options.push(format!("uid={}", uid)); }
                    if !gid.is_empty() { options.push(format!("gid={}", gid)); }
                    if !file_mode.is_empty() { options.push(format!("file_mode={}", file_mode)); }
                    if !dir_mode.is_empty() { options.push(format!("dir_mode={}", dir_mode)); }
                    if smb_version != "auto" { options.push(format!("vers={}", smb_version)); }
                    if !domain.is_empty() { options.push(format!("domain={}", domain)); }

                    let unit_name = SystemdMountManager::mount_unit_name(&mount_point);
                    SystemdMountEntry {
                        unit_name,
                        description: format!("CIFS mount for {}", device),
                        device,
                        mount_point,
                        fs_type: "cifs".to_string(),
                        options,
                        automount,
                        timeout_sec,
                        enabled: true,
                        active: false,
                    }
                },
            )
    }

    /// Generator for a `SystemdMountEntry` with `credentials=<path>` auth marker.
    fn arb_credentials_mount_entry() -> impl Strategy<Value = SystemdMountEntry> {
        (
            arb_share_address(),
            arb_mount_point(),
            arb_credentials_file_path(),
            proptest::bool::ANY,                          // automount
            proptest::option::of(0u32..3600),             // timeout_sec
            proptest::bool::ANY,                          // nofail
            proptest::bool::ANY,                          // netdev
            proptest::bool::ANY,                          // read_only
            "[a-zA-Z0-9]{0,6}",                          // uid
            "[a-zA-Z0-9]{0,6}",                          // gid
            (
                "[0-7]{0,4}",                             // file_mode
                "[0-7]{0,4}",                             // dir_mode
                prop::sample::select(vec![
                    "auto".to_string(),
                    "1.0".to_string(),
                    "2.0".to_string(),
                    "3.0".to_string(),
                    "3.1.1".to_string(),
                ]),
                "[a-zA-Z]{0,10}",                         // domain
            ),
        )
            .prop_map(
                |(
                    device,
                    mount_point,
                    creds_path,
                    automount,
                    timeout_sec,
                    nofail,
                    netdev,
                    read_only,
                    uid,
                    gid,
                    (file_mode, dir_mode, smb_version, domain),
                )| {
                    let mut options = vec![format!("credentials={}", creds_path)];
                    if netdev { options.push("_netdev".to_string()); }
                    if nofail { options.push("nofail".to_string()); }
                    if read_only { options.push("ro".to_string()); } else { options.push("rw".to_string()); }
                    if !uid.is_empty() { options.push(format!("uid={}", uid)); }
                    if !gid.is_empty() { options.push(format!("gid={}", gid)); }
                    if !file_mode.is_empty() { options.push(format!("file_mode={}", file_mode)); }
                    if !dir_mode.is_empty() { options.push(format!("dir_mode={}", dir_mode)); }
                    if smb_version != "auto" { options.push(format!("vers={}", smb_version)); }
                    if !domain.is_empty() { options.push(format!("domain={}", domain)); }

                    let unit_name = SystemdMountManager::mount_unit_name(&mount_point);
                    SystemdMountEntry {
                        unit_name,
                        description: format!("CIFS mount for {}", device),
                        device,
                        mount_point,
                        fs_type: "cifs".to_string(),
                        options,
                        automount,
                        timeout_sec,
                        enabled: true,
                        active: false,
                    }
                },
            )
    }

    /// Generator for a `SystemdMountEntry` with `sec=krb5` auth marker.
    fn arb_kerberos_mount_entry() -> impl Strategy<Value = SystemdMountEntry> {
        (
            arb_share_address(),
            arb_mount_point(),
            proptest::bool::ANY,                          // automount
            proptest::option::of(0u32..3600),             // timeout_sec
            proptest::bool::ANY,                          // nofail
            proptest::bool::ANY,                          // netdev
            proptest::bool::ANY,                          // read_only
            "[a-zA-Z0-9]{0,6}",                          // uid
            "[a-zA-Z0-9]{0,6}",                          // gid
            "[0-7]{0,4}",                                 // file_mode
            (
                "[0-7]{0,4}",                             // dir_mode
                "[a-zA-Z]{0,10}",                         // domain
            ),
        )
            .prop_map(
                |(
                    device,
                    mount_point,
                    automount,
                    timeout_sec,
                    nofail,
                    netdev,
                    read_only,
                    uid,
                    gid,
                    file_mode,
                    (dir_mode, domain),
                )| {
                    let mut options = vec!["sec=krb5".to_string()];
                    if netdev { options.push("_netdev".to_string()); }
                    if nofail { options.push("nofail".to_string()); }
                    if read_only { options.push("ro".to_string()); } else { options.push("rw".to_string()); }
                    if !uid.is_empty() { options.push(format!("uid={}", uid)); }
                    if !gid.is_empty() { options.push(format!("gid={}", gid)); }
                    if !file_mode.is_empty() { options.push(format!("file_mode={}", file_mode)); }
                    if !dir_mode.is_empty() { options.push(format!("dir_mode={}", dir_mode)); }
                    if !domain.is_empty() { options.push(format!("domain={}", domain)); }

                    let unit_name = SystemdMountManager::mount_unit_name(&mount_point);
                    SystemdMountEntry {
                        unit_name,
                        description: format!("CIFS mount for {}", device),
                        device,
                        mount_point,
                        fs_type: "cifs".to_string(),
                        options,
                        automount,
                        timeout_sec,
                        enabled: true,
                        active: false,
                    }
                },
            )
    }

    /// Generator for a `SystemdMountEntry` with one of the three known auth
    /// markers, chosen uniformly at random.
    fn arb_auth_mount_entry() -> impl Strategy<Value = SystemdMountEntry> {
        prop_oneof![
            arb_guest_mount_entry(),
            arb_credentials_mount_entry(),
            arb_kerberos_mount_entry(),
        ]
    }

    // ---------------------------------------------------------------
    // Property 12 generators and test
    // ---------------------------------------------------------------

    /// Generator for an arbitrary WizardState with any auth method and
    /// randomised automount flag, used for testing summary_unit_filenames().
    fn arb_wizard_state_any_auth() -> impl Strategy<Value = WizardState> {
        (
            prop::sample::select(vec![
                AuthMethod::Guest,
                AuthMethod::CredentialsFile,
                AuthMethod::Kerberos,
            ]),
            arb_share_address(),
            arb_mount_point(),
            arb_credentials_file_path(),
            proptest::bool::ANY, // automount
            proptest::bool::ANY, // nofail
            proptest::bool::ANY, // netdev
            proptest::bool::ANY, // read_only
            "[a-zA-Z0-9]{0,6}", // uid
            "[a-zA-Z0-9]{0,6}", // gid
            (
                "[0-7]{0,4}",       // file_mode
                "[0-7]{0,4}",       // dir_mode
                prop::sample::select(vec![
                    "auto".to_string(),
                    "1.0".to_string(),
                    "2.0".to_string(),
                    "2.1".to_string(),
                    "3.0".to_string(),
                    "3.0.2".to_string(),
                    "3.1.1".to_string(),
                ]),
                arb_security_mode(),
                "[a-zA-Z0-9, ]{0,20}", // extra_options
                "[a-zA-Z]{0,10}",       // domain
            ),
        )
            .prop_map(
                |(
                    auth_method,
                    share_address,
                    mount_point,
                    credentials_file_path,
                    automount,
                    nofail,
                    netdev,
                    read_only,
                    uid,
                    gid,
                    (file_mode, dir_mode, smb_version, security_mode, extra_options, domain),
                )| {
                    WizardState {
                        auth_method,
                        share_address,
                        mount_point,
                        credentials_file_path,
                        domain,
                        automount,
                        nofail,
                        netdev,
                        read_only,
                        timeout_sec: None,
                        uid,
                        gid,
                        file_mode,
                        dir_mode,
                        smb_version,
                        security_mode,
                        client_smb_encrypt: "default".to_string(),
                        extra_options,
                        validation_results: Vec::new(),
                        editing: None,
                    }
                },
            )
    }

    // Feature: mount-wizard, Property 12: Summary lists correct unit filenames
    //
    // For any WizardState, summary_unit_filenames() SHALL return the .mount
    // name always, .automount name if automount is true, and
    // krb5-kinit.service if auth_method is Kerberos.
    // Validates: Requirements 9.1
    proptest! {
        #[test]
        fn test_property_summary_lists_correct_unit_filenames(
            state in arb_wizard_state_any_auth()
        ) {
            let filenames = state.summary_unit_filenames();

            let expected_mount = SystemdMountManager::mount_unit_name(&state.mount_point);
            let expected_automount = SystemdMountManager::automount_unit_name(&state.mount_point);

            // 1. .mount unit is always present
            prop_assert!(
                filenames.contains(&expected_mount),
                "summary_unit_filenames() must always contain the .mount unit \"{}\", got: {:?}",
                expected_mount,
                filenames
            );

            // 2. .automount unit is present iff automount is true
            if state.automount {
                prop_assert!(
                    filenames.contains(&expected_automount),
                    "summary_unit_filenames() must contain .automount unit \"{}\" when automount \
                     is true, got: {:?}",
                    expected_automount,
                    filenames
                );
            } else {
                prop_assert!(
                    !filenames.contains(&expected_automount),
                    "summary_unit_filenames() must NOT contain .automount unit \"{}\" when \
                     automount is false, got: {:?}",
                    expected_automount,
                    filenames
                );
            }

            // 3. krb5-kinit.service is present iff auth_method is Kerberos
            let kinit_service = "krb5-kinit.service".to_string();
            if state.auth_method == AuthMethod::Kerberos {
                prop_assert!(
                    filenames.contains(&kinit_service),
                    "summary_unit_filenames() must contain \"krb5-kinit.service\" when auth is \
                     Kerberos, got: {:?}",
                    filenames
                );
            } else {
                prop_assert!(
                    !filenames.contains(&kinit_service),
                    "summary_unit_filenames() must NOT contain \"krb5-kinit.service\" when auth \
                     is {:?}, got: {:?}",
                    state.auth_method,
                    filenames
                );
            }

            // 4. Verify the total count matches expectations
            let mut expected_count = 1; // .mount always
            if state.automount { expected_count += 1; }
            if state.auth_method == AuthMethod::Kerberos { expected_count += 1; }
            prop_assert_eq!(
                filenames.len(),
                expected_count,
                "summary_unit_filenames() should return exactly {} filenames for automount={}, \
                 auth={:?}, got: {:?}",
                expected_count,
                state.automount,
                state.auth_method,
                filenames
            );
        }
    }

    // Feature: mount-wizard, Property 11: SystemdMountEntry round-trip via WizardState
    //
    // For any valid SystemdMountEntry with a known auth marker in its options
    // (guest, credentials=..., or sec=krb5), creating a WizardState via
    // from_entry() and then converting back via to_mount_entry() SHALL
    // preserve device, mount_point, fs_type, automount, and timeout_sec.
    // The options vector SHALL contain the same auth-specific option.
    // Additionally, detect_auth_method() SHALL return the correct AuthMethod
    // variant for the original options.
    // Validates: Requirements 12.1, 12.2
    proptest! {
        #[test]
        fn test_property_systemd_mount_entry_round_trip(
            entry in arb_auth_mount_entry()
        ) {
            // Determine the expected auth method from the original options
            let expected_auth = WizardState::detect_auth_method(&entry.options);

            // Round-trip: from_entry -> to_mount_entry
            let state = WizardState::from_entry(&entry);
            let result = state.to_mount_entry();

            // 1. device is preserved
            prop_assert_eq!(
                &result.device, &entry.device,
                "device must be preserved through round-trip"
            );

            // 2. mount_point is preserved
            prop_assert_eq!(
                &result.mount_point, &entry.mount_point,
                "mount_point must be preserved through round-trip"
            );

            // 3. fs_type is preserved (always "cifs")
            prop_assert_eq!(
                &result.fs_type, &entry.fs_type,
                "fs_type must be preserved through round-trip"
            );

            // 4. automount is preserved
            prop_assert_eq!(
                result.automount, entry.automount,
                "automount must be preserved through round-trip"
            );

            // 5. timeout_sec is preserved
            prop_assert_eq!(
                result.timeout_sec, entry.timeout_sec,
                "timeout_sec must be preserved through round-trip"
            );

            // 6. The auth-specific option is preserved in the result options
            match expected_auth {
                AuthMethod::Guest => {
                    prop_assert!(
                        result.options.contains(&"guest".to_string()),
                        "Round-trip options must contain \"guest\" for Guest auth, got: {:?}",
                        result.options
                    );
                }
                AuthMethod::CredentialsFile => {
                    // Find the original credentials= option
                    let orig_creds = entry.options.iter()
                        .find(|o| o.to_lowercase().starts_with("credentials="))
                        .expect("CredentialsFile entry must have credentials= option");
                    prop_assert!(
                        result.options.contains(orig_creds),
                        "Round-trip options must contain \"{}\" for CredentialsFile auth, got: {:?}",
                        orig_creds,
                        result.options
                    );
                }
                AuthMethod::Kerberos => {
                    prop_assert!(
                        result.options.contains(&"sec=krb5".to_string()),
                        "Round-trip options must contain \"sec=krb5\" for Kerberos auth, got: {:?}",
                        result.options
                    );
                }
            }

            // 7. detect_auth_method returns the correct variant
            prop_assert_eq!(
                WizardState::detect_auth_method(&entry.options),
                expected_auth,
                "detect_auth_method must return {:?} for options: {:?}",
                expected_auth,
                entry.options
            );

            // Also verify detect_auth_method on the round-tripped options
            // returns the same variant
            prop_assert_eq!(
                WizardState::detect_auth_method(&result.options),
                expected_auth,
                "detect_auth_method on round-tripped options must return {:?}, got options: {:?}",
                expected_auth,
                result.options
            );
        }
    }
}
