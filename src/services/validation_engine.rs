//! ValidationEngine — orchestrates all pre-flight checks for the Mount Wizard.
//!
//! Each check returns a [`ValidationResult`] with a severity level. The UI
//! layer calls [`ValidationEngine::run_all`] from a background thread (it
//! performs blocking I/O) and displays the results with appropriate icons.

use std::path::Path;
use std::process::Command;

use crate::config::models::AuthMethod;
use crate::vm::wizard_state::WizardState;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Severity of a single validation check.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationSeverity {
    /// Check passed — no issues.
    Ok,
    /// Non-blocking issue — user can proceed but should be aware.
    Warning,
    /// Blocking issue — user cannot advance until resolved.
    Error,
}

/// Result of a single validation check.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Short identifier for the check (e.g. "share_address", "credentials_file").
    pub check_name: String,
    /// How severe the finding is.
    pub severity: ValidationSeverity,
    /// Human-readable message describing the outcome.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Dangerous-character validation (mirrors ui/mod.rs logic)
// ---------------------------------------------------------------------------

/// Characters that are dangerous in shell contexts or systemd unit fields.
const DANGEROUS_CHARS: &[char] = &[
    '\'', '"', '`', '$', '\\', '!', '|', '&', ';', '\n', '\r', '\t',
    '(', ')', '{', '}', '<', '>', '~', '#', '\0',
];

/// Reject strings containing shell-dangerous or control characters.
fn reject_dangerous_chars(value: &str, field_name: &str) -> Result<(), String> {
    for ch in DANGEROUS_CHARS {
        if value.contains(*ch) {
            let ch_name = match *ch {
                '\n' => "newline".to_string(),
                '\r' => "carriage-return".to_string(),
                '\t' => "tab".to_string(),
                '\0' => "null".to_string(),
                other => format!("'{}'", other),
            };
            return Err(format!("{} contains forbidden character {}", field_name, ch_name));
        }
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(format!("{} contains control characters", field_name));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ValidationEngine
// ---------------------------------------------------------------------------

/// Stateless engine that runs pre-flight validation checks for the wizard.
///
/// All methods are static — no instance state is needed. Blocking methods
/// (file I/O, subprocess execution) must be called from a background thread.
pub struct ValidationEngine;

impl ValidationEngine {
    // ----- Share address ---------------------------------------------------

    /// Validate a CIFS share address (`//host/share`).
    ///
    /// Reuses the same rules as `ui/mod.rs::validate_share_address`:
    /// - Must start with `//`
    /// - Must contain a hostname and a share name separated by `/`
    /// - No dangerous characters
    pub fn validate_share_address(addr: &str) -> ValidationResult {
        if addr.is_empty() {
            return ValidationResult {
                check_name: "share_address".into(),
                severity: ValidationSeverity::Error,
                message: "Share address is required".into(),
            };
        }

        if let Err(msg) = reject_dangerous_chars(addr, "Share address") {
            return ValidationResult {
                check_name: "share_address".into(),
                severity: ValidationSeverity::Error,
                message: msg,
            };
        }

        if !addr.starts_with("//") {
            return ValidationResult {
                check_name: "share_address".into(),
                severity: ValidationSeverity::Error,
                message: "Share address must start with // (e.g. //server/share)".into(),
            };
        }

        let body = &addr[2..];
        if body.is_empty() {
            return ValidationResult {
                check_name: "share_address".into(),
                severity: ValidationSeverity::Error,
                message: "Share address must include a hostname and share name".into(),
            };
        }

        let slash_pos = match body.find('/') {
            Some(pos) => pos,
            None => {
                return ValidationResult {
                    check_name: "share_address".into(),
                    severity: ValidationSeverity::Error,
                    message: "Share address must be //hostname/sharename".into(),
                };
            }
        };

        let host = &body[..slash_pos];
        let share = &body[slash_pos + 1..];

        if host.is_empty() {
            return ValidationResult {
                check_name: "share_address".into(),
                severity: ValidationSeverity::Error,
                message: "Share address is missing the hostname".into(),
            };
        }

        if share.is_empty() || share == "/" {
            return ValidationResult {
                check_name: "share_address".into(),
                severity: ValidationSeverity::Error,
                message: "Share address is missing the share name".into(),
            };
        }

        if !host.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '[' || c == ']') {
            return ValidationResult {
                check_name: "share_address".into(),
                severity: ValidationSeverity::Error,
                message: "Hostname contains invalid characters".into(),
            };
        }

        if !share.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ' ' || c == '/') {
            return ValidationResult {
                check_name: "share_address".into(),
                severity: ValidationSeverity::Error,
                message: "Share name contains invalid characters".into(),
            };
        }

        ValidationResult {
            check_name: "share_address".into(),
            severity: ValidationSeverity::Ok,
            message: "Share address is valid".into(),
        }
    }

    // ----- Mount point -----------------------------------------------------

    /// Validate a mount point path.
    ///
    /// Must be an absolute path with no dangerous characters or `..` segments.
    pub fn validate_mount_point(path: &str) -> ValidationResult {
        if path.is_empty() {
            return ValidationResult {
                check_name: "mount_point".into(),
                severity: ValidationSeverity::Error,
                message: "Mount point is required".into(),
            };
        }

        if let Err(msg) = reject_dangerous_chars(path, "Mount point") {
            return ValidationResult {
                check_name: "mount_point".into(),
                severity: ValidationSeverity::Error,
                message: msg,
            };
        }

        if !path.starts_with('/') {
            return ValidationResult {
                check_name: "mount_point".into(),
                severity: ValidationSeverity::Error,
                message: "Mount point must be an absolute path".into(),
            };
        }

        if path.contains("..") {
            return ValidationResult {
                check_name: "mount_point".into(),
                severity: ValidationSeverity::Error,
                message: "Mount point must not contain '..'".into(),
            };
        }

        if !path.chars().all(|c| c.is_alphanumeric() || c == '/' || c == '-' || c == '_' || c == '.') {
            return ValidationResult {
                check_name: "mount_point".into(),
                severity: ValidationSeverity::Error,
                message: "Mount point contains invalid characters".into(),
            };
        }

        ValidationResult {
            check_name: "mount_point".into(),
            severity: ValidationSeverity::Ok,
            message: "Mount point is valid".into(),
        }
    }

    // ----- Credentials file ------------------------------------------------

    /// Check that a credentials file exists on disk.
    pub fn validate_credentials_file(path: &str) -> ValidationResult {
        if path.is_empty() {
            return ValidationResult {
                check_name: "credentials_file".into(),
                severity: ValidationSeverity::Error,
                message: "Credentials file path is required".into(),
            };
        }

        if Path::new(path).exists() {
            ValidationResult {
                check_name: "credentials_file".into(),
                severity: ValidationSeverity::Ok,
                message: format!("Credentials file found at {}", path),
            }
        } else {
            ValidationResult {
                check_name: "credentials_file".into(),
                severity: ValidationSeverity::Error,
                message: format!("Credentials file not found at {}", path),
            }
        }
    }

    /// Validate the content of a credentials file.
    ///
    /// The file must contain at least one line starting with `username=` and
    /// at least one line starting with `password=`.
    pub fn validate_credentials_file_content(content: &str) -> ValidationResult {
        let has_username = content.lines().any(|line| line.trim_start().starts_with("username="));
        let has_password = content.lines().any(|line| line.trim_start().starts_with("password="));

        match (has_username, has_password) {
            (true, true) => ValidationResult {
                check_name: "credentials_content".into(),
                severity: ValidationSeverity::Ok,
                message: "Credentials file contains username and password".into(),
            },
            (false, false) => ValidationResult {
                check_name: "credentials_content".into(),
                severity: ValidationSeverity::Error,
                message: "Credentials file is missing both username= and password= lines".into(),
            },
            (false, true) => ValidationResult {
                check_name: "credentials_content".into(),
                severity: ValidationSeverity::Error,
                message: "Credentials file is missing a username= line".into(),
            },
            (true, false) => ValidationResult {
                check_name: "credentials_content".into(),
                severity: ValidationSeverity::Error,
                message: "Credentials file is missing a password= line".into(),
            },
        }
    }

    // ----- Share connectivity ----------------------------------------------

    /// Test connectivity to an SMB share using `smbclient -L`.
    ///
    /// This is a blocking call — run from a background thread.
    pub fn check_share_connectivity(
        addr: &str,
        auth: &AuthMethod,
        creds_path: Option<&str>,
    ) -> ValidationResult {
        // Extract the hostname from //host/share
        let host = addr
            .strip_prefix("//")
            .and_then(|body| body.split('/').next())
            .unwrap_or("");

        if host.is_empty() {
            return ValidationResult {
                check_name: "share_connectivity".into(),
                severity: ValidationSeverity::Error,
                message: "Cannot test connectivity: invalid share address".into(),
            };
        }

        let mut cmd = Command::new("smbclient");
        cmd.arg("-L").arg(host);

        match auth {
            AuthMethod::Guest => {
                cmd.arg("-N"); // no password
                // Relax client-side restrictions that block NTLM for
                // anonymous/guest sessions.
                cmd.arg("--option=reject md5 servers=no");
            }
            AuthMethod::CredentialsFile => {
                if let Some(path) = creds_path {
                    cmd.arg("-A").arg(path);
                } else {
                    cmd.arg("-N");
                }
                cmd.arg("--option=reject md5 servers=no");
            }
            AuthMethod::Kerberos => {
                cmd.arg("--use-kerberos=required");
            }
        }

        // Suppress interactive prompts
        cmd.stdin(std::process::Stdio::null());

        match cmd.output() {
            Ok(output) => {
                if output.status.success() {
                    return ValidationResult {
                        check_name: "share_connectivity".into(),
                        severity: ValidationSeverity::Ok,
                        message: format!("Successfully connected to {}", host),
                    };
                }

                let stderr = String::from_utf8_lossy(&output.stderr);
                let stderr_trimmed = stderr.trim();

                // If smbclient fails due to auth policy (NTLM blocked,
                // access denied), fall back to a TCP port check. The
                // mount.cifs kernel module uses a different auth path and
                // may succeed where smbclient cannot.
                if stderr_trimmed.contains("NT_STATUS_NTLM_BLOCKED")
                    || stderr_trimmed.contains("NT_STATUS_ACCESS_DENIED")
                {
                    return Self::check_tcp_reachability(host);
                }

                ValidationResult {
                    check_name: "share_connectivity".into(),
                    severity: ValidationSeverity::Warning,
                    message: format!(
                        "Could not connect to {}: {}",
                        host,
                        stderr_trimmed
                    ),
                }
            }
            Err(_) => {
                // smbclient not installed — fall back to TCP check
                Self::check_tcp_reachability(host)
            }
        }
    }

    /// Fall back to a simple TCP port 445 reachability check when smbclient
    /// cannot authenticate (e.g. NTLM blocked by local or server policy).
    ///
    /// This confirms the host is listening on SMB but cannot verify share
    /// existence or authentication.
    fn check_tcp_reachability(host: &str) -> ValidationResult {
        use std::net::{TcpStream, ToSocketAddrs};
        use std::time::Duration;

        let addr_str = format!("{}:445", host);
        let addrs: Vec<_> = match addr_str.to_socket_addrs() {
            Ok(a) => a.collect(),
            Err(e) => {
                return ValidationResult {
                    check_name: "share_connectivity".into(),
                    severity: ValidationSeverity::Warning,
                    message: format!("Could not resolve {}: {}", host, e),
                };
            }
        };

        for addr in addrs {
            if TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok() {
                return ValidationResult {
                    check_name: "share_connectivity".into(),
                    severity: ValidationSeverity::Ok,
                    message: format!(
                        "Host {} is reachable on port 445 (SMB). \
                         Share-level auth could not be verified via smbclient \
                         due to local security policy, but mount.cifs may succeed.",
                        host
                    ),
                };
            }
        }

        ValidationResult {
            check_name: "share_connectivity".into(),
            severity: ValidationSeverity::Warning,
            message: format!(
                "Could not connect to {} on port 445. \
                 The host may be unreachable or not running an SMB service.",
                host
            ),
        }
    }

    // ----- Orchestrator ----------------------------------------------------

    /// Run all validations appropriate for the current wizard state.
    ///
    /// This is a **blocking** call — the UI layer must invoke it from a
    /// background thread via `spawn_blocking_then`.
    pub fn run_all(state: &WizardState) -> Vec<ValidationResult> {
        let mut results = Vec::new();

        // Common checks for every auth method
        results.push(Self::validate_share_address(&state.share_address));
        results.push(Self::validate_mount_point(&state.mount_point));

        // Auth-specific checks
        match state.auth_method {
            AuthMethod::Guest => {
                // Guest: only share connectivity
            }
            AuthMethod::CredentialsFile => {
                let file_result = Self::validate_credentials_file(&state.credentials_file_path);
                let file_ok = file_result.severity == ValidationSeverity::Ok;
                results.push(file_result);

                // Only check content if the file exists
                if file_ok {
                    if let Ok(content) = std::fs::read_to_string(&state.credentials_file_path) {
                        results.push(Self::validate_credentials_file_content(&content));
                    } else {
                        results.push(ValidationResult {
                            check_name: "credentials_content".into(),
                            severity: ValidationSeverity::Error,
                            message: "Failed to read credentials file".into(),
                        });
                    }
                }
            }
            AuthMethod::Kerberos => {
                // Kerberos-specific checks are handled by KerberosChecker
                // (task 5). The ValidationEngine delegates to it when
                // available. For now, we note that Kerberos checks will be
                // added in a later task.
            }
        }

        // Share connectivity (all auth methods)
        let creds_path = if state.auth_method == AuthMethod::CredentialsFile {
            Some(state.credentials_file_path.as_str())
        } else {
            None
        };
        results.push(Self::check_share_connectivity(
            &state.share_address,
            &state.auth_method,
            creds_path,
        ));

        results
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ---------------------------------------------------------------
    // validate_share_address
    // ---------------------------------------------------------------

    #[test]
    fn test_share_address_valid() {
        let r = ValidationEngine::validate_share_address("//server/share");
        assert_eq!(r.severity, ValidationSeverity::Ok);
    }

    #[test]
    fn test_share_address_empty() {
        let r = ValidationEngine::validate_share_address("");
        assert_eq!(r.severity, ValidationSeverity::Error);
    }

    #[test]
    fn test_share_address_no_prefix() {
        let r = ValidationEngine::validate_share_address("server/share");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("must start with //"));
    }

    #[test]
    fn test_share_address_missing_share() {
        let r = ValidationEngine::validate_share_address("//server");
        assert_eq!(r.severity, ValidationSeverity::Error);
    }

    #[test]
    fn test_share_address_missing_host() {
        let r = ValidationEngine::validate_share_address("///share");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("hostname"));
    }

    #[test]
    fn test_share_address_empty_share_name() {
        let r = ValidationEngine::validate_share_address("//server/");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("share name"));
    }

    #[test]
    fn test_share_address_with_fqdn() {
        let r = ValidationEngine::validate_share_address("//nas.example.com/data");
        assert_eq!(r.severity, ValidationSeverity::Ok);
    }

    #[test]
    fn test_share_address_with_ipv4() {
        let r = ValidationEngine::validate_share_address("//192.168.1.1/share");
        assert_eq!(r.severity, ValidationSeverity::Ok);
    }

    #[test]
    fn test_share_address_dangerous_chars() {
        let r = ValidationEngine::validate_share_address("//server/share;rm -rf /");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("forbidden character"));
    }

    // ---------------------------------------------------------------
    // validate_mount_point
    // ---------------------------------------------------------------

    #[test]
    fn test_mount_point_valid() {
        let r = ValidationEngine::validate_mount_point("/mnt/share");
        assert_eq!(r.severity, ValidationSeverity::Ok);
    }

    #[test]
    fn test_mount_point_empty() {
        let r = ValidationEngine::validate_mount_point("");
        assert_eq!(r.severity, ValidationSeverity::Error);
    }

    #[test]
    fn test_mount_point_relative() {
        let r = ValidationEngine::validate_mount_point("mnt/share");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("absolute path"));
    }

    #[test]
    fn test_mount_point_dotdot() {
        let r = ValidationEngine::validate_mount_point("/mnt/../etc");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains(".."));
    }

    #[test]
    fn test_mount_point_dangerous_chars() {
        let r = ValidationEngine::validate_mount_point("/mnt/share$(whoami)");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("forbidden character"));
    }

    #[test]
    fn test_mount_point_invalid_chars() {
        let r = ValidationEngine::validate_mount_point("/mnt/my share");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("invalid characters"));
    }

    // ---------------------------------------------------------------
    // validate_credentials_file_content
    // ---------------------------------------------------------------

    #[test]
    fn test_credentials_content_valid() {
        let content = "username=admin\npassword=secret\n";
        let r = ValidationEngine::validate_credentials_file_content(content);
        assert_eq!(r.severity, ValidationSeverity::Ok);
    }

    #[test]
    fn test_credentials_content_missing_both() {
        let content = "some random content\n";
        let r = ValidationEngine::validate_credentials_file_content(content);
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("username="));
        assert!(r.message.contains("password="));
    }

    #[test]
    fn test_credentials_content_missing_username() {
        let content = "password=secret\n";
        let r = ValidationEngine::validate_credentials_file_content(content);
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("username="));
    }

    #[test]
    fn test_credentials_content_missing_password() {
        let content = "username=admin\n";
        let r = ValidationEngine::validate_credentials_file_content(content);
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("password="));
    }

    #[test]
    fn test_credentials_content_with_extra_lines() {
        let content = "# comment\nusername=admin\ndomain=EXAMPLE\npassword=secret\n";
        let r = ValidationEngine::validate_credentials_file_content(content);
        assert_eq!(r.severity, ValidationSeverity::Ok);
    }

    #[test]
    fn test_credentials_content_with_leading_whitespace() {
        let content = "  username=admin\n  password=secret\n";
        let r = ValidationEngine::validate_credentials_file_content(content);
        assert_eq!(r.severity, ValidationSeverity::Ok);
    }

    // ---------------------------------------------------------------
    // validate_credentials_file (file existence)
    // ---------------------------------------------------------------

    #[test]
    fn test_credentials_file_empty_path() {
        let r = ValidationEngine::validate_credentials_file("");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("required"));
    }

    #[test]
    fn test_credentials_file_nonexistent() {
        let r = ValidationEngine::validate_credentials_file("/tmp/nonexistent_creds_file_xyz");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("not found"));
    }

    #[test]
    fn test_credentials_file_exists() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        write!(tmp, "username=test\npassword=test\n").unwrap();
        let path = tmp.path().to_str().unwrap();

        let r = ValidationEngine::validate_credentials_file(path);
        assert_eq!(r.severity, ValidationSeverity::Ok);
        assert!(r.message.contains("found"));
    }

    // ---------------------------------------------------------------
    // check_share_connectivity — basic argument validation
    // ---------------------------------------------------------------

    #[test]
    fn test_connectivity_invalid_address() {
        let r = ValidationEngine::check_share_connectivity("bad", &AuthMethod::Guest, None);
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("invalid share address"));
    }

    // ---------------------------------------------------------------
    // run_all — orchestration
    // ---------------------------------------------------------------

    #[test]
    fn test_run_all_guest_includes_common_checks() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::Guest;
        state.share_address = "//server/share".to_string();
        state.mount_point = "/mnt/share".to_string();

        let results = ValidationEngine::run_all(&state);

        // Should have at least: share_address, mount_point, share_connectivity
        let check_names: Vec<&str> = results.iter().map(|r| r.check_name.as_str()).collect();
        assert!(check_names.contains(&"share_address"));
        assert!(check_names.contains(&"mount_point"));
        assert!(check_names.contains(&"share_connectivity"));
    }

    #[test]
    fn test_run_all_credentials_includes_file_checks() {
        let mut state = WizardState::new();
        state.auth_method = AuthMethod::CredentialsFile;
        state.share_address = "//server/share".to_string();
        state.mount_point = "/mnt/share".to_string();
        state.credentials_file_path = "/tmp/nonexistent_creds_xyz".to_string();

        let results = ValidationEngine::run_all(&state);

        let check_names: Vec<&str> = results.iter().map(|r| r.check_name.as_str()).collect();
        assert!(check_names.contains(&"credentials_file"));
        // Content check should NOT run because the file doesn't exist
        assert!(!check_names.contains(&"credentials_content"));
    }

    #[test]
    fn test_run_all_credentials_with_existing_file() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        write!(tmp, "username=test\npassword=test\n").unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        let mut state = WizardState::new();
        state.auth_method = AuthMethod::CredentialsFile;
        state.share_address = "//server/share".to_string();
        state.mount_point = "/mnt/share".to_string();
        state.credentials_file_path = path;

        let results = ValidationEngine::run_all(&state);

        let check_names: Vec<&str> = results.iter().map(|r| r.check_name.as_str()).collect();
        assert!(check_names.contains(&"credentials_file"));
        assert!(check_names.contains(&"credentials_content"));
    }

    #[test]
    fn test_run_all_invalid_inputs_produce_errors() {
        let state = WizardState::new(); // empty share_address and mount_point

        let results = ValidationEngine::run_all(&state);

        let errors: Vec<&ValidationResult> = results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Error)
            .collect();
        assert!(errors.len() >= 2, "Expected at least 2 errors for empty inputs");
    }

    // ---------------------------------------------------------------
    // Property-based tests
    // ---------------------------------------------------------------

    /// Generator for invalid share addresses: empty strings.
    fn arb_empty_share_address() -> impl Strategy<Value = String> {
        Just(String::new())
    }

    /// Generator for invalid share addresses: strings that do not start
    /// with `//`. Produces non-empty strings with alphanumeric content
    /// that never begin with `//`.
    fn arb_no_prefix_share_address() -> impl Strategy<Value = String> {
        "[a-zA-Z][a-zA-Z0-9/]{0,20}".prop_filter(
            "must not start with //",
            |s| !s.starts_with("//"),
        )
    }

    /// Generator for invalid share addresses: `//` prefix but missing
    /// hostname (i.e. `///share` or `//` alone or `///`).
    fn arb_missing_hostname_share_address() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("//".to_string()),
            // ///sharename — empty hostname, non-empty share
            "[a-zA-Z][a-zA-Z0-9]{0,10}".prop_map(|share| format!("///{}", share)),
        ]
    }

    /// Generator for invalid share addresses: `//hostname` with no
    /// slash separator for the share name, or `//hostname/` with an
    /// empty share name.
    fn arb_missing_share_name_address() -> impl Strategy<Value = String> {
        let hostname = "[a-zA-Z][a-zA-Z0-9.\\-]{0,10}";
        prop_oneof![
            // //hostname — no trailing slash at all
            hostname.prop_map(|h| format!("//{}", h)),
            // //hostname/ — trailing slash but empty share name
            hostname.prop_map(|h| format!("//{}/", h)),
        ]
    }

    // Feature: mount-wizard, Property 2: Invalid share address rejection
    //
    // For any string that is empty, does not start with //, is missing a
    // hostname, or is missing a share name, validate_share_address() SHALL
    // return an error.
    // Validates: Requirements 2.3
    proptest! {
        #[test]
        fn test_property_empty_share_address_rejected(
            addr in arb_empty_share_address()
        ) {
            let result = ValidationEngine::validate_share_address(&addr);
            prop_assert!(
                result.severity == ValidationSeverity::Error,
                "validate_share_address('{}') should return Error for empty input, got: {:?} — {}",
                addr,
                result.severity,
                result.message
            );
        }

        #[test]
        fn test_property_no_prefix_share_address_rejected(
            addr in arb_no_prefix_share_address()
        ) {
            let result = ValidationEngine::validate_share_address(&addr);
            prop_assert!(
                result.severity == ValidationSeverity::Error,
                "validate_share_address('{}') should return Error for missing // prefix, got: {:?} — {}",
                addr,
                result.severity,
                result.message
            );
        }

        #[test]
        fn test_property_missing_hostname_share_address_rejected(
            addr in arb_missing_hostname_share_address()
        ) {
            let result = ValidationEngine::validate_share_address(&addr);
            prop_assert!(
                result.severity == ValidationSeverity::Error,
                "validate_share_address('{}') should return Error for missing hostname, got: {:?} — {}",
                addr,
                result.severity,
                result.message
            );
        }

        #[test]
        fn test_property_missing_share_name_address_rejected(
            addr in arb_missing_share_name_address()
        ) {
            let result = ValidationEngine::validate_share_address(&addr);
            prop_assert!(
                result.severity == ValidationSeverity::Error,
                "validate_share_address('{}') should return Error for missing share name, got: {:?} — {}",
                addr,
                result.severity,
                result.message
            );
        }

        // Feature: mount-wizard, Property 3: Invalid mount point rejection
        //
        // For any string that is empty or does not start with `/`,
        // validate_mount_point() SHALL return an error.
        // Validates: Requirements 2.4

        #[test]
        fn test_property_empty_mount_point_rejected(
            _dummy in Just(())
        ) {
            let result = ValidationEngine::validate_mount_point("");
            prop_assert!(
                result.severity == ValidationSeverity::Error,
                "validate_mount_point('') should return Error for empty input, got: {:?} — {}",
                result.severity,
                result.message
            );
        }

        #[test]
        fn test_property_relative_mount_point_rejected(
            path in "[a-zA-Z][a-zA-Z0-9/_\\-]{0,30}"
                .prop_filter("must not start with /", |s| !s.starts_with('/'))
        ) {
            let result = ValidationEngine::validate_mount_point(&path);
            prop_assert!(
                result.severity == ValidationSeverity::Error,
                "validate_mount_point('{}') should return Error for relative path, got: {:?} — {}",
                path,
                result.severity,
                result.message
            );
        }
    }
}
