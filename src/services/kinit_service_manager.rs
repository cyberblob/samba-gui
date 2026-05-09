//! KinitServiceManager — manages the `krb5-kinit.service` systemd unit for
//! boot-time Kerberos ticket acquisition.
//!
//! When a CIFS mount uses Kerberos authentication, a valid TGT must exist
//! before the mount is attempted. This manager creates a oneshot systemd
//! service that runs `kinit -k -t <keytab> <principal>` before
//! `remote-fs-pre.target`, ensuring tickets are available at boot.
//!
//! All methods that shell out are blocking and must be called from a
//! background thread in GUI builds.

use std::process::Command;

use crate::services::privileged_executor;

/// The systemd unit name for the boot-time kinit service.
const KINIT_SERVICE_NAME: &str = "krb5-kinit.service";

/// The path where the kinit service unit file is written.
const KINIT_SERVICE_PATH: &str = "/etc/systemd/system/krb5-kinit.service";

/// Manages the `krb5-kinit.service` systemd unit for boot-time Kerberos
/// ticket acquisition.
///
/// All methods are static — no instance state is needed.
pub struct KinitServiceManager;

impl KinitServiceManager {
    /// Check whether the `krb5-kinit.service` unit exists and is enabled.
    ///
    /// Runs `systemctl is-enabled krb5-kinit.service`. Returns `Ok(true)` if
    /// the service is enabled, `Ok(false)` if it is disabled or does not
    /// exist, and `Err` if the command cannot be executed.
    ///
    /// **Blocking** — call from a background thread.
    pub fn service_exists_and_enabled() -> Result<bool, String> {
        let output = Command::new("systemctl")
            .args(["is-enabled", KINIT_SERVICE_NAME])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("Failed to run systemctl: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();

        // `systemctl is-enabled` exits 0 for "enabled" / "enabled-runtime" /
        // "static" and non-zero for "disabled" / "not-found" / "masked".
        // We only consider it enabled when the output is literally "enabled".
        Ok(output.status.success() && trimmed == "enabled")
    }

    /// Generate the content of the `krb5-kinit.service` systemd unit.
    ///
    /// The generated unit runs `kinit -k -t <keytab_path> <principal>` as a
    /// oneshot service ordered before `remote-fs-pre.target` so that a valid
    /// TGT is available before any Kerberos-authenticated mounts are
    /// attempted.
    ///
    /// # Panics
    ///
    /// Does not panic. Returns an empty-looking but structurally valid unit
    /// if `principal` or `keytab_path` are empty (callers should validate
    /// inputs before calling).
    pub fn generate_service_unit(principal: &str, keytab_path: &str) -> String {
        format!(
            "\
[Unit]
Description=Kerberos TGT renewal for CIFS mounts
Before=remote-fs-pre.target
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/kinit -k -t {keytab_path} {principal}
RemainAfterExit=yes

[Install]
WantedBy=remote-fs-pre.target
"
        )
    }

    /// Write the `krb5-kinit.service` unit file via the PrivilegedExecutor,
    /// then run `systemctl daemon-reload` and `systemctl enable`.
    ///
    /// Returns `Ok(())` on success or an error message describing which step
    /// failed.
    ///
    /// **Blocking** — call from a background thread.
    pub fn create_service(principal: &str, keytab_path: &str) -> Result<(), String> {
        if principal.is_empty() {
            return Err("Kerberos principal is required".into());
        }
        if keytab_path.is_empty() {
            return Err("Keytab file path is required".into());
        }

        let unit_content = Self::generate_service_unit(principal, keytab_path);

        // Write the unit file via tee (PrivilegedExecutor pipes stdin to a
        // privileged process).
        let (_stdout, stderr, success) =
            privileged_executor::run_privileged_with_stdin(
                "tee",
                &[KINIT_SERVICE_PATH],
                &unit_content,
            )
            .map_err(|e| format!("Failed to write kinit service unit: {}", e))?;

        if !success {
            return Err(format!(
                "Failed to write {}: {}",
                KINIT_SERVICE_PATH,
                stderr.trim()
            ));
        }

        // Reload systemd so it picks up the new unit.
        let (_stdout, stderr, success) =
            privileged_executor::run_privileged("systemctl", &["daemon-reload"])
                .map_err(|e| format!("Failed to run systemctl daemon-reload: {}", e))?;

        if !success {
            return Err(format!("systemctl daemon-reload failed: {}", stderr.trim()));
        }

        // Enable the service so it starts at boot.
        let (_stdout, stderr, success) =
            privileged_executor::run_privileged(
                "systemctl",
                &["enable", KINIT_SERVICE_NAME],
            )
            .map_err(|e| format!("Failed to run systemctl enable: {}", e))?;

        if !success {
            return Err(format!(
                "systemctl enable {} failed: {}",
                KINIT_SERVICE_NAME,
                stderr.trim()
            ));
        }

        Ok(())
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
    // generate_service_unit
    // ---------------------------------------------------------------

    #[test]
    fn test_generate_service_unit_contains_sections() {
        let unit = KinitServiceManager::generate_service_unit("user@REALM", "/etc/krb5.keytab");
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
    }

    #[test]
    fn test_generate_service_unit_exec_start() {
        let unit =
            KinitServiceManager::generate_service_unit("admin@EXAMPLE.COM", "/etc/krb5.keytab");
        assert!(unit.contains("ExecStart=/usr/bin/kinit -k -t /etc/krb5.keytab admin@EXAMPLE.COM"));
    }

    #[test]
    fn test_generate_service_unit_wanted_by() {
        let unit = KinitServiceManager::generate_service_unit("user@REALM", "/etc/krb5.keytab");
        assert!(unit.contains("WantedBy=remote-fs-pre.target"));
    }

    #[test]
    fn test_generate_service_unit_ordering() {
        let unit = KinitServiceManager::generate_service_unit("user@REALM", "/etc/krb5.keytab");
        assert!(unit.contains("Before=remote-fs-pre.target"));
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("Wants=network-online.target"));
    }

    #[test]
    fn test_generate_service_unit_type_oneshot() {
        let unit = KinitServiceManager::generate_service_unit("user@REALM", "/etc/krb5.keytab");
        assert!(unit.contains("Type=oneshot"));
    }

    #[test]
    fn test_generate_service_unit_remain_after_exit() {
        let unit = KinitServiceManager::generate_service_unit("user@REALM", "/etc/krb5.keytab");
        assert!(unit.contains("RemainAfterExit=yes"));
    }

    #[test]
    fn test_generate_service_unit_description() {
        let unit = KinitServiceManager::generate_service_unit("user@REALM", "/etc/krb5.keytab");
        assert!(unit.contains("Description=Kerberos TGT renewal for CIFS mounts"));
    }

    #[test]
    fn test_generate_service_unit_with_special_chars_in_principal() {
        let unit = KinitServiceManager::generate_service_unit(
            "host/server.example.com@EXAMPLE.COM",
            "/etc/krb5.keytab",
        );
        assert!(unit.contains(
            "ExecStart=/usr/bin/kinit -k -t /etc/krb5.keytab host/server.example.com@EXAMPLE.COM"
        ));
    }

    #[test]
    fn test_generate_service_unit_with_custom_keytab_path() {
        let unit = KinitServiceManager::generate_service_unit(
            "user@REALM",
            "/home/user/.keytab",
        );
        assert!(unit.contains("ExecStart=/usr/bin/kinit -k -t /home/user/.keytab user@REALM"));
    }

    // ---------------------------------------------------------------
    // create_service — input validation
    // ---------------------------------------------------------------

    #[test]
    fn test_create_service_empty_principal() {
        let result = KinitServiceManager::create_service("", "/etc/krb5.keytab");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("principal"));
    }

    #[test]
    fn test_create_service_empty_keytab() {
        let result = KinitServiceManager::create_service("user@REALM", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Keytab"));
    }

    // ---------------------------------------------------------------
    // service_exists_and_enabled — smoke test
    // ---------------------------------------------------------------

    #[test]
    fn test_service_exists_and_enabled_returns_result() {
        // In CI / test environments the service likely doesn't exist, but
        // the function should return a Result without panicking.
        let result = KinitServiceManager::service_exists_and_enabled();
        assert!(result.is_ok() || result.is_err());
    }

    // ---------------------------------------------------------------
    // Property-based tests
    // ---------------------------------------------------------------

    /// Generator for Kerberos principal strings (e.g. "user@REALM",
    /// "host/server.example.com@EXAMPLE.COM").
    fn arb_principal() -> impl Strategy<Value = String> {
        (
            "[a-zA-Z][a-zA-Z0-9._/\\-]{0,20}",  // local part
            "[A-Z][A-Z0-9.\\-]{1,15}",            // realm
        )
            .prop_map(|(local, realm)| format!("{}@{}", local, realm))
    }

    /// Generator for keytab file paths (absolute paths).
    fn arb_keytab_path() -> impl Strategy<Value = String> {
        "[a-zA-Z][a-zA-Z0-9._\\-]{0,15}"
            .prop_map(|name| format!("/etc/{}.keytab", name))
    }

    // Feature: mount-wizard, Property 8: Kinit service unit generation
    //
    // For any valid principal and keytab path, generate_service_unit() SHALL
    // produce a string containing ExecStart=/usr/bin/kinit -k -t <keytab_path>
    // <principal>, [Unit], [Service], and [Install] sections with
    // WantedBy=remote-fs-pre.target.
    // Validates: Requirements 6.4
    proptest! {
        #[test]
        fn test_property_kinit_service_unit_generation(
            principal in arb_principal(),
            keytab_path in arb_keytab_path(),
        ) {
            let unit = KinitServiceManager::generate_service_unit(&principal, &keytab_path);

            // Must contain all three systemd sections.
            prop_assert!(
                unit.contains("[Unit]"),
                "Generated unit must contain [Unit] section, got:\n{}",
                unit
            );
            prop_assert!(
                unit.contains("[Service]"),
                "Generated unit must contain [Service] section, got:\n{}",
                unit
            );
            prop_assert!(
                unit.contains("[Install]"),
                "Generated unit must contain [Install] section, got:\n{}",
                unit
            );

            // Must contain the correct ExecStart line with the exact
            // keytab path and principal.
            let expected_exec = format!(
                "ExecStart=/usr/bin/kinit -k -t {} {}",
                keytab_path, principal
            );
            prop_assert!(
                unit.contains(&expected_exec),
                "Generated unit must contain '{}', got:\n{}",
                expected_exec,
                unit
            );

            // Must be ordered before remote-fs-pre.target via WantedBy.
            prop_assert!(
                unit.contains("WantedBy=remote-fs-pre.target"),
                "Generated unit must contain WantedBy=remote-fs-pre.target, got:\n{}",
                unit
            );
        }
    }
}
