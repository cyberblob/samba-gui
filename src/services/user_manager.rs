#![allow(dead_code)]
//! UserManager for managing SAMBA users via smbpasswd/passdb or samba-tool (AD DC mode)
//!
//! Automatically detects whether Samba is running as an Active Directory Domain Controller
//! and uses the appropriate tooling:
//! - Standalone mode: pdbedit + smbpasswd (local passdb.tdb)
//! - AD DC mode: samba-tool user (AD/LDAP backend)
//!
//! All privileged commands go through `privileged_executor` so the user only
//! authenticates once per session.

use std::process::Command;
use thiserror::Error;
use crate::config::SambaUser;
use super::privileged_executor::{run_privileged, run_privileged_with_stdin};

/// The detected Samba server role
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SambaMode {
    /// Standalone file server using local passdb (tdbsam/ldapsam)
    Standalone,
    /// Active Directory Domain Controller using samba-tool
    AdDc,
}

/// Errors that can occur during user operations
#[derive(Error, Debug)]
pub enum UserError {
    #[error("Command execution failed: {0}")]
    CommandExecution(String),

    #[error("Failed to parse user list: {0}")]
    ParseError(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Password mismatch: passwords do not match")]
    PasswordMismatch,

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Authentication cancelled")]
    AuthCancelled,
}

/// Result type for user operations
pub type UserResult<T> = Result<T, UserError>;

/// Convert a privileged_executor error into a UserError
fn map_priv_err(e: super::privileged_executor::PrivilegedError) -> UserError {
    use super::privileged_executor::PrivilegedError;
    match e {
        PrivilegedError::AuthCancelled => UserError::AuthCancelled,
        PrivilegedError::PermissionDenied(msg) => UserError::PermissionDenied(msg),
        PrivilegedError::CommandExecution(msg) => UserError::CommandExecution(msg),
    }
}

/// Manager for SAMBA users
///
/// Detects whether Samba runs as an AD DC or standalone server and
/// dispatches to the correct backend (samba-tool vs pdbedit/smbpasswd).
/// All privileged commands use a single-auth executor so the user only
/// sees one password prompt per session.
pub struct UserManager {
    mode: SambaMode,
}

impl UserManager {
    /// Create a new UserManager, auto-detecting the Samba mode
    pub fn new() -> Self {
        Self {
            mode: Self::detect_mode(),
        }
    }

    /// Detect whether Samba is running as an AD DC or standalone server.
    fn detect_mode() -> SambaMode {
        let output = Command::new("testparm")
            .args(["-s", "--parameter-name=server role"])
            .stderr(std::process::Stdio::null())
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.to_lowercase().contains("active directory domain controller") {
                return SambaMode::AdDc;
            }
        }

        SambaMode::Standalone
    }

    /// Returns the detected Samba mode
    pub fn mode(&self) -> SambaMode {
        self.mode
    }

    // ── List users ──────────────────────────────────────────────────

    pub fn list_users(&self) -> UserResult<Vec<SambaUser>> {
        match self.mode {
            SambaMode::Standalone => self.list_users_standalone(),
            SambaMode::AdDc => self.list_users_ad(),
        }
    }

    fn list_users_standalone(&self) -> UserResult<Vec<SambaUser>> {
        let (stdout, stderr, _ok) = run_privileged("pdbedit", &["-L", "-v"])
            .map_err(map_priv_err)?;

        if stderr.contains("Permission denied") || stderr.contains("NT_STATUS_ACCESS_DENIED") {
            return Err(UserError::PermissionDenied(stderr));
        }

        Ok(Self::parse_pdbedit_list(&stdout))
    }

    fn list_users_ad(&self) -> UserResult<Vec<SambaUser>> {
        let (stdout, stderr, _ok) = run_privileged("samba-tool", &["user", "list"])
            .map_err(map_priv_err)?;

        if stderr.contains("Permission denied") || stderr.contains("NT_STATUS_ACCESS_DENIED") {
            return Err(UserError::PermissionDenied(stderr));
        }

        Ok(Self::parse_samba_tool_list(&stdout))
    }

    // ── Create user ─────────────────────────────────────────────────

    pub fn create_user(&self, username: &str, password: &str) -> UserResult<()> {
        match self.mode {
            SambaMode::Standalone => self.create_user_standalone(username, password),
            SambaMode::AdDc => self.create_user_ad(username, password),
        }
    }

    fn create_user_standalone(&self, username: &str, password: &str) -> UserResult<()> {
        // Standalone requires a pre-existing Linux user
        let check_output = Command::new("id")
            .arg(username)
            .output()
            .map_err(|e| UserError::CommandExecution(e.to_string()))?;

        if !check_output.status.success() {
            return Err(UserError::UserNotFound(
                format!("Linux user '{}' does not exist. Create the Linux user first.", username)
            ));
        }

        let stdin_data = format!("{}\n{}\n", password, password);
        let (_stdout, stderr, _ok) = run_privileged_with_stdin(
            "smbpasswd", &["-a", username], &stdin_data
        ).map_err(map_priv_err)?;

        if stderr.contains("Permission denied") {
            return Err(UserError::PermissionDenied(
                "Need elevated privileges to create SAMBA users.".to_string()
            ));
        }

        Ok(())
    }

    fn create_user_ad(&self, username: &str, password: &str) -> UserResult<()> {
        let (_stdout, stderr, _ok) = run_privileged(
            "samba-tool", &["user", "create", username, password]
        ).map_err(map_priv_err)?;

        if stderr.contains("Permission denied") {
            return Err(UserError::PermissionDenied(
                "Need elevated privileges to create AD users.".to_string()
            ));
        }

        Ok(())
    }

    // ── Enable user ─────────────────────────────────────────────────

    pub fn enable_user(&self, username: &str) -> UserResult<()> {
        match self.mode {
            SambaMode::Standalone => self.enable_user_standalone(username),
            SambaMode::AdDc => self.enable_user_ad(username),
        }
    }

    fn enable_user_standalone(&self, username: &str) -> UserResult<()> {
        let (_stdout, stderr, _ok) = run_privileged("smbpasswd", &["-e", username])
            .map_err(map_priv_err)?;

        if stderr.contains("Permission denied") {
            return Err(UserError::PermissionDenied(
                "Need elevated privileges to enable SAMBA users.".to_string()
            ));
        }
        if stderr.contains("does not exist") {
            return Err(UserError::UserNotFound(
                format!("SAMBA user '{}' does not exist", username)
            ));
        }
        Ok(())
    }

    fn enable_user_ad(&self, username: &str) -> UserResult<()> {
        let (_stdout, stderr, _ok) = run_privileged("samba-tool", &["user", "enable", username])
            .map_err(map_priv_err)?;

        if stderr.contains("Permission denied") {
            return Err(UserError::PermissionDenied(
                "Need elevated privileges to enable AD users.".to_string()
            ));
        }
        Ok(())
    }

    // ── Disable user ────────────────────────────────────────────────

    pub fn disable_user(&self, username: &str) -> UserResult<()> {
        match self.mode {
            SambaMode::Standalone => self.disable_user_standalone(username),
            SambaMode::AdDc => self.disable_user_ad(username),
        }
    }

    fn disable_user_standalone(&self, username: &str) -> UserResult<()> {
        let (_stdout, stderr, _ok) = run_privileged("smbpasswd", &["-d", username])
            .map_err(map_priv_err)?;

        if stderr.contains("Permission denied") {
            return Err(UserError::PermissionDenied(
                "Need elevated privileges to disable SAMBA users.".to_string()
            ));
        }
        if stderr.contains("does not exist") {
            return Err(UserError::UserNotFound(
                format!("SAMBA user '{}' does not exist", username)
            ));
        }
        Ok(())
    }

    fn disable_user_ad(&self, username: &str) -> UserResult<()> {
        let (_stdout, stderr, _ok) = run_privileged("samba-tool", &["user", "disable", username])
            .map_err(map_priv_err)?;

        if stderr.contains("Permission denied") {
            return Err(UserError::PermissionDenied(
                "Need elevated privileges to disable AD users.".to_string()
            ));
        }
        Ok(())
    }

    // ── Password validation ─────────────────────────────────────────

    pub fn validate_password_confirmation(password: &str, confirmation: &str) -> UserResult<()> {
        if password != confirmation {
            return Err(UserError::PasswordMismatch);
        }
        Ok(())
    }

    // ── Parsers ─────────────────────────────────────────────────────

    /// Parse `pdbedit -L -v` output (standalone mode)
    pub fn parse_pdbedit_list(output: &str) -> Vec<SambaUser> {
        let mut users = Vec::new();
        let mut current_user: Option<String> = None;
        let mut enabled = true;

        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("---") {
                continue;
            }

            // Verbose format: "Unix username:        cyberblob"
            if let Some(val) = trimmed.strip_prefix("Unix username:") {
                // Push the previous user before starting a new one
                if let Some(username) = current_user.take() {
                    users.push(SambaUser { username, enabled });
                }
                current_user = Some(val.trim().to_string());
                enabled = true;
                continue;
            }

            // Verbose format: "Account Flags:        [U          ]"
            if trimmed.contains("Account Flags:") {
                if trimmed.contains("[D") {
                    enabled = false;
                } else {
                    enabled = true;
                }
                continue;
            }

            // Non-verbose format: "cyberblob:1000:Doug"
            if !trimmed.contains(' ') && trimmed.contains(':') {
                let parts: Vec<&str> = trimmed.split(':').collect();
                if parts.len() >= 2 && parts[1].parse::<u32>().is_ok() {
                    // Push the previous user before starting a new one
                    if let Some(username) = current_user.take() {
                        users.push(SambaUser { username, enabled });
                    }
                    current_user = Some(parts[0].to_string());
                    enabled = true;
                }
            }
        }

        if let Some(username) = current_user {
            users.push(SambaUser { username, enabled });
        }

        users
    }

    /// Parse `samba-tool user list` output (AD DC mode)
    pub fn parse_samba_tool_list(output: &str) -> Vec<SambaUser> {
        output
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(|username| SambaUser {
                username: username.to_string(),
                enabled: true,
            })
            .collect()
    }
}

impl Default for UserManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_password_confirmation_matching() {
        let result = UserManager::validate_password_confirmation("password123", "password123");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_password_confirmation_mismatching() {
        let result = UserManager::validate_password_confirmation("password123", "different");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), UserError::PasswordMismatch));
    }

    #[test]
    fn test_parse_user_list_simple() {
        let output = r#"testuser:1000:
admin:1001:"#;
        let users = UserManager::parse_pdbedit_list(output);
        assert_eq!(users.len(), 2);
        assert!(users.iter().any(|u| u.username == "testuser"));
        assert!(users.iter().any(|u| u.username == "admin"));
    }

    #[test]
    fn test_parse_user_list_with_disabled() {
        let output = r#"testuser:1000:
Account Flags:        [U          ]
admin:1001:
Account Flags:        [D         ]"#;
        let users = UserManager::parse_pdbedit_list(output);
        assert_eq!(users.len(), 2);
        let testuser = users.iter().find(|u| u.username == "testuser").unwrap();
        let admin = users.iter().find(|u| u.username == "admin").unwrap();
        assert!(testuser.enabled);
        assert!(!admin.enabled);
    }

    #[test]
    fn test_parse_user_list_verbose_output() {
        // Real pdbedit -L -v output (no non-verbose lines)
        let output = r#"---------------
Unix username:        testuser
NT username:          testuser
Account Flags:        [U          ]
User SID:             S-1-5-21-123456789-123456789-123456789-1000
Primary Group SID:    S-1-5-21-123456789-123456789-123456789-513
Full Name:            Test User
Home Directory:       \\localhost\testuser
HomeDir Drive:        H:
Logon Script:         
Profile Path:         \\localhost\profiles\testuser
Domain:               WORKGROUP
Account desc:         
Workstations:         
Munged dial:          
Logon time:           0
Logoff time:          Tue, 01 Jan 2035 00:00:00 UTC
Kickoff time:         Tue, 01 Jan 2035 00:00:00 UTC
Password last set:    0
Password can change:  0
Password must change: 0
Last bad password   : 0
Bad password count  : 0
Logon hours       : FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
---------------
Unix username:        admin
NT username:          admin
Account Flags:        [D         ]
User SID:             S-1-5-21-123456789-123456789-123456789-1001
Primary Group SID:    S-1-5-21-123456789-123456789-123456789-513
Full Name:            Administrator"#;
        let users = UserManager::parse_pdbedit_list(output);
        assert_eq!(users.len(), 2);
        let testuser = users.iter().find(|u| u.username == "testuser").unwrap();
        let admin = users.iter().find(|u| u.username == "admin").unwrap();
        assert!(testuser.enabled, "testuser should be enabled");
        assert!(!admin.enabled, "admin should be disabled");
    }

    #[test]
    fn test_parse_samba_tool_list() {
        let output = "Administrator\nkrbtgt\njdoe\njsmith\n";
        let users = UserManager::parse_samba_tool_list(output);
        assert_eq!(users.len(), 4);
        assert!(users.iter().all(|u| u.enabled));
        assert!(users.iter().any(|u| u.username == "Administrator"));
        assert!(users.iter().any(|u| u.username == "jdoe"));
    }

    #[test]
    fn test_parse_samba_tool_list_empty() {
        let output = "";
        let users = UserManager::parse_samba_tool_list(output);
        assert!(users.is_empty());
    }

    #[test]
    fn test_parse_samba_tool_list_whitespace() {
        let output = "  admin  \n  user1  \n\n";
        let users = UserManager::parse_samba_tool_list(output);
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].username, "admin");
        assert_eq!(users[1].username, "user1");
    }
}
