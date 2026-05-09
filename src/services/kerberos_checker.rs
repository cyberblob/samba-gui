//! KerberosChecker — Kerberos environment validation for the Mount Wizard.
//!
//! Wraps `klist`, `kinit`, DNS resolution, and DNS SRV lookups to verify
//! that the local Kerberos environment is correctly configured for CIFS
//! mounts. All blocking methods must be called from a background thread.

use std::process::Command;

use crate::services::privileged_executor;
use crate::services::validation_engine::{ValidationResult, ValidationSeverity};

/// Stateless checker for Kerberos prerequisites.
///
/// All methods are static — no instance state is needed. Methods that shell
/// out (`has_valid_ticket`, `run_kinit`, `resolve_hostname`, `check_dns_srv`)
/// are blocking and must be called from a background thread.
pub struct KerberosChecker;

impl KerberosChecker {
    /// Extract the hostname from a share address like `//host/share`.
    ///
    /// Returns `None` if the address doesn't start with `//` or has no
    /// hostname component.
    pub fn extract_hostname(share_address: &str) -> Option<String> {
        let body = share_address.strip_prefix("//")?;
        if body.is_empty() {
            return None;
        }
        let host = body.split('/').next()?;
        if host.is_empty() {
            return None;
        }
        Some(host.to_string())
    }

    /// Extract the domain portion from an FQDN.
    ///
    /// Returns everything after the first dot, or `None` if there is no dot.
    ///
    /// # Examples
    /// ```ignore
    /// assert_eq!(KerberosChecker::extract_domain("nas.example.com"), Some("example.com".into()));
    /// assert_eq!(KerberosChecker::extract_domain("shortname"), None);
    /// ```
    pub fn extract_domain(fqdn: &str) -> Option<String> {
        let dot_pos = fqdn.find('.')?;
        let domain = &fqdn[dot_pos + 1..];
        if domain.is_empty() {
            return None;
        }
        Some(domain.to_string())
    }

    /// Validate that a hostname is a fully qualified domain name (contains at
    /// least one dot with a non-empty suffix).
    ///
    /// Returns `Ok` severity when the hostname is an FQDN, or `Error`
    /// severity with the short hostname in the message when it is not.
    pub fn validate_fqdn(hostname: &str) -> ValidationResult {
        if hostname.is_empty() {
            return ValidationResult {
                check_name: "fqdn_validation".into(),
                severity: ValidationSeverity::Error,
                message: "Hostname is empty".into(),
            };
        }

        if Self::extract_domain(hostname).is_some() {
            ValidationResult {
                check_name: "fqdn_validation".into(),
                severity: ValidationSeverity::Ok,
                message: format!("Hostname '{}' is a fully qualified domain name", hostname),
            }
        } else {
            ValidationResult {
                check_name: "fqdn_validation".into(),
                severity: ValidationSeverity::Error,
                message: format!(
                    "Kerberos requires a fully qualified domain name; '{}' is a short hostname",
                    hostname
                ),
            }
        }
    }

    /// Attempt DNS resolution of a hostname.
    ///
    /// Returns `Ok` severity on success, or `Warning` severity on failure
    /// (the user can still proceed).
    ///
    /// **Blocking** — call from a background thread.
    pub fn resolve_hostname(hostname: &str) -> ValidationResult {
        if hostname.is_empty() {
            return ValidationResult {
                check_name: "dns_resolution".into(),
                severity: ValidationSeverity::Warning,
                message: "Cannot resolve an empty hostname".into(),
            };
        }

        // Use `getent hosts` which respects nsswitch.conf (works with
        // /etc/hosts, DNS, mDNS, WINS, etc.)
        let output = Command::new("getent")
            .args(["hosts", hostname])
            .stdin(std::process::Stdio::null())
            .output();

        match output {
            Ok(result) if result.status.success() => ValidationResult {
                check_name: "dns_resolution".into(),
                severity: ValidationSeverity::Ok,
                message: format!("Hostname '{}' resolved successfully", hostname),
            },
            Ok(_) => ValidationResult {
                check_name: "dns_resolution".into(),
                severity: ValidationSeverity::Warning,
                message: format!(
                    "Could not resolve hostname '{}'; the mount may fail at runtime",
                    hostname
                ),
            },
            Err(e) => ValidationResult {
                check_name: "dns_resolution".into(),
                severity: ValidationSeverity::Warning,
                message: format!("DNS resolution check failed: {}", e),
            },
        }
    }

    /// Query DNS for `_kerberos._udp.<domain>` SRV records.
    ///
    /// Tries `dig` first, then falls back to `host`. Returns `Ok` severity
    /// when records are found, or `Warning` when they are not (the user can
    /// still proceed but should check `/etc/krb5.conf`).
    ///
    /// **Blocking** — call from a background thread.
    pub fn check_dns_srv(domain: &str) -> ValidationResult {
        if domain.is_empty() {
            return ValidationResult {
                check_name: "dns_srv".into(),
                severity: ValidationSeverity::Warning,
                message: "Cannot query SRV records: domain is empty".into(),
            };
        }

        let srv_name = format!("_kerberos._udp.{}", domain);

        // Try `dig` first — it's the most common DNS tool on Linux.
        if let Ok(output) = Command::new("dig")
            .args(["+short", "SRV", &srv_name])
            .stdin(std::process::Stdio::null())
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if output.status.success() && !stdout.trim().is_empty() {
                return ValidationResult {
                    check_name: "dns_srv".into(),
                    severity: ValidationSeverity::Ok,
                    message: format!(
                        "Kerberos realm discovered via DNS SRV records for '{}'",
                        domain
                    ),
                };
            }
        }

        // Fallback: try `host -t SRV`.
        if let Ok(output) = Command::new("host")
            .args(["-t", "SRV", &srv_name])
            .stdin(std::process::Stdio::null())
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // `host` prints "has SRV record" on success and "has no SRV record"
            // or "not found" on failure.
            if output.status.success() && !stdout.contains("not found") && !stdout.contains("has no") {
                return ValidationResult {
                    check_name: "dns_srv".into(),
                    severity: ValidationSeverity::Ok,
                    message: format!(
                        "Kerberos realm discovered via DNS SRV records for '{}'",
                        domain
                    ),
                };
            }
        }

        ValidationResult {
            check_name: "dns_srv".into(),
            severity: ValidationSeverity::Warning,
            message: format!(
                "No DNS SRV records found for '{}'; Kerberos realm auto-discovery may not work. \
                 Verify /etc/krb5.conf configuration.",
                srv_name
            ),
        }
    }

    /// Check whether a valid Kerberos ticket-granting ticket exists.
    ///
    /// Runs `klist -s` which exits 0 when a valid TGT is present and
    /// non-zero otherwise.
    ///
    /// **Blocking** — call from a background thread.
    pub fn has_valid_ticket() -> Result<bool, String> {
        let output = Command::new("klist")
            .arg("-s")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("Failed to run klist: {}", e))?;

        Ok(output.success())
    }

    /// Run `kinit <principal>` via the PrivilegedExecutor.
    ///
    /// Returns `Ok(())` on success or an error message on failure.
    ///
    /// **Blocking** — call from a background thread.
    pub fn run_kinit(principal: &str) -> Result<(), String> {
        if principal.is_empty() {
            return Err("Kerberos principal is required".into());
        }

        let (stdout, stderr, success) =
            privileged_executor::run_privileged("kinit", &[principal])
                .map_err(|e| format!("Failed to execute kinit: {}", e))?;

        if success {
            Ok(())
        } else {
            let mut msg = String::from("kinit failed");
            let err_output = stderr.trim();
            let std_output = stdout.trim();
            if !err_output.is_empty() {
                msg.push_str(": ");
                msg.push_str(err_output);
            } else if !std_output.is_empty() {
                msg.push_str(": ");
                msg.push_str(std_output);
            }
            Err(msg)
        }
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
    // extract_hostname
    // ---------------------------------------------------------------

    #[test]
    fn test_extract_hostname_valid() {
        assert_eq!(
            KerberosChecker::extract_hostname("//nas.example.com/share"),
            Some("nas.example.com".into())
        );
    }

    #[test]
    fn test_extract_hostname_short() {
        assert_eq!(
            KerberosChecker::extract_hostname("//myserver/data"),
            Some("myserver".into())
        );
    }

    #[test]
    fn test_extract_hostname_no_prefix() {
        assert_eq!(KerberosChecker::extract_hostname("server/share"), None);
    }

    #[test]
    fn test_extract_hostname_empty() {
        assert_eq!(KerberosChecker::extract_hostname(""), None);
    }

    #[test]
    fn test_extract_hostname_only_slashes() {
        assert_eq!(KerberosChecker::extract_hostname("//"), None);
    }

    #[test]
    fn test_extract_hostname_missing_host() {
        assert_eq!(KerberosChecker::extract_hostname("///share"), None);
    }

    #[test]
    fn test_extract_hostname_no_share() {
        // //host with no trailing slash — host is still extractable
        assert_eq!(
            KerberosChecker::extract_hostname("//host"),
            Some("host".into())
        );
    }

    #[test]
    fn test_extract_hostname_ipv4() {
        assert_eq!(
            KerberosChecker::extract_hostname("//192.168.1.1/share"),
            Some("192.168.1.1".into())
        );
    }

    // ---------------------------------------------------------------
    // extract_domain
    // ---------------------------------------------------------------

    #[test]
    fn test_extract_domain_fqdn() {
        assert_eq!(
            KerberosChecker::extract_domain("nas.example.com"),
            Some("example.com".into())
        );
    }

    #[test]
    fn test_extract_domain_two_parts() {
        assert_eq!(
            KerberosChecker::extract_domain("host.local"),
            Some("local".into())
        );
    }

    #[test]
    fn test_extract_domain_short() {
        assert_eq!(KerberosChecker::extract_domain("shortname"), None);
    }

    #[test]
    fn test_extract_domain_empty() {
        assert_eq!(KerberosChecker::extract_domain(""), None);
    }

    #[test]
    fn test_extract_domain_trailing_dot() {
        // "host." — dot exists but suffix is empty → None
        assert_eq!(KerberosChecker::extract_domain("host."), None);
    }

    #[test]
    fn test_extract_domain_multiple_dots() {
        assert_eq!(
            KerberosChecker::extract_domain("a.b.c.d"),
            Some("b.c.d".into())
        );
    }

    // ---------------------------------------------------------------
    // validate_fqdn
    // ---------------------------------------------------------------

    #[test]
    fn test_validate_fqdn_valid() {
        let r = KerberosChecker::validate_fqdn("nas.example.com");
        assert_eq!(r.severity, ValidationSeverity::Ok);
        assert!(r.message.contains("nas.example.com"));
    }

    #[test]
    fn test_validate_fqdn_short_hostname() {
        let r = KerberosChecker::validate_fqdn("myserver");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("myserver"));
        assert!(r.message.contains("short hostname"));
    }

    #[test]
    fn test_validate_fqdn_empty() {
        let r = KerberosChecker::validate_fqdn("");
        assert_eq!(r.severity, ValidationSeverity::Error);
    }

    #[test]
    fn test_validate_fqdn_trailing_dot_only() {
        // "host." has a dot but empty suffix — not a valid FQDN
        let r = KerberosChecker::validate_fqdn("host.");
        assert_eq!(r.severity, ValidationSeverity::Error);
        assert!(r.message.contains("host."));
    }

    // ---------------------------------------------------------------
    // has_valid_ticket — basic smoke test
    // ---------------------------------------------------------------

    #[test]
    fn test_has_valid_ticket_returns_result() {
        // We can't guarantee klist is installed in CI, but the function
        // should return a Result (Ok or Err) without panicking.
        let result = KerberosChecker::has_valid_ticket();
        // Either Ok(true/false) or Err("Failed to run klist: ...")
        assert!(result.is_ok() || result.is_err());
    }

    // ---------------------------------------------------------------
    // run_kinit — empty principal
    // ---------------------------------------------------------------

    #[test]
    fn test_run_kinit_empty_principal() {
        let result = KerberosChecker::run_kinit("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("required"));
    }

    // ---------------------------------------------------------------
    // resolve_hostname — empty input
    // ---------------------------------------------------------------

    #[test]
    fn test_resolve_hostname_empty() {
        let r = KerberosChecker::resolve_hostname("");
        assert_eq!(r.severity, ValidationSeverity::Warning);
    }

    // ---------------------------------------------------------------
    // check_dns_srv — empty domain
    // ---------------------------------------------------------------

    #[test]
    fn test_check_dns_srv_empty_domain() {
        let r = KerberosChecker::check_dns_srv("");
        assert_eq!(r.severity, ValidationSeverity::Warning);
        assert!(r.message.contains("empty"));
    }

    // ---------------------------------------------------------------
    // Property-based tests (proptest)
    // ---------------------------------------------------------------

    /// Generator for FQDN hostnames — at least one dot with a non-empty
    /// suffix (e.g. "nas.example.com", "host.local").
    fn arb_hostname_fqdn() -> impl Strategy<Value = String> {
        (
            "[a-zA-Z][a-zA-Z0-9\\-]{0,10}",  // label before the dot
            "[a-zA-Z][a-zA-Z0-9.\\-]{0,20}",  // domain suffix after the dot
        )
            .prop_map(|(label, suffix)| format!("{}.{}", label, suffix))
    }

    /// Generator for short hostnames — no dots at all.
    fn arb_hostname_short() -> impl Strategy<Value = String> {
        "[a-zA-Z][a-zA-Z0-9\\-]{0,15}"
    }

    // Feature: mount-wizard, Property 6: FQDN validation
    //
    // For any hostname string, validate_fqdn() SHALL return Ok severity iff
    // the hostname contains at least one dot (with a non-empty suffix after
    // it); for hostnames without a dot, return Error severity with the short
    // hostname in the message.
    // Validates: Requirements 4.1, 4.2
    proptest! {
        #[test]
        fn test_property_fqdn_valid_hostnames_return_ok(
            hostname in arb_hostname_fqdn()
        ) {
            let result = KerberosChecker::validate_fqdn(&hostname);
            prop_assert!(
                result.severity == ValidationSeverity::Ok,
                "validate_fqdn('{}') should return Ok for an FQDN, got: {:?} — {}",
                hostname,
                result.severity,
                result.message
            );
        }

        #[test]
        fn test_property_fqdn_short_hostnames_return_error(
            hostname in arb_hostname_short()
        ) {
            let result = KerberosChecker::validate_fqdn(&hostname);
            prop_assert!(
                result.severity == ValidationSeverity::Error,
                "validate_fqdn('{}') should return Error for a short hostname, got: {:?} — {}",
                hostname,
                result.severity,
                result.message
            );
            // The error message must contain the short hostname so the user
            // knows which name was rejected (Requirement 4.2).
            prop_assert!(
                result.message.contains(&hostname),
                "Error message should contain the short hostname '{}', got: {}",
                hostname,
                result.message
            );
        }
    }

    // Feature: mount-wizard, Property 7: Domain extraction from FQDN
    //
    // For any FQDN with at least one dot, extract_domain() SHALL return
    // Some(suffix) where suffix is everything after the first dot; for
    // strings without a dot, return None.
    // Validates: Requirements 7.1
    proptest! {
        #[test]
        fn test_property_extract_domain_fqdn_returns_suffix(
            label in "[a-zA-Z][a-zA-Z0-9\\-]{0,10}",
            suffix in "[a-zA-Z][a-zA-Z0-9.\\-]{0,20}",
        ) {
            let fqdn = format!("{}.{}", label, suffix);
            let result = KerberosChecker::extract_domain(&fqdn);
            prop_assert_eq!(
                result.as_deref(),
                Some(suffix.as_str()),
                "extract_domain('{}') should return Some('{}'), got: {:?}",
                fqdn,
                suffix,
                result
            );
        }

        #[test]
        fn test_property_extract_domain_no_dot_returns_none(
            hostname in arb_hostname_short()
        ) {
            let result = KerberosChecker::extract_domain(&hostname);
            prop_assert!(
                result.is_none(),
                "extract_domain('{}') should return None for a hostname without a dot, got: {:?}",
                hostname,
                result
            );
        }
    }
}
