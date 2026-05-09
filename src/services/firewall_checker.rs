#![allow(dead_code)]
//! Firewall detection and management for Samba GUI.
//!
//! Detects whether `ufw` or `firewalld` is active, checks if SMB ports
//! (445/tcp, 137-138/udp, 139/tcp) are open, and provides actions to
//! open them.

use std::process::Command;
use thiserror::Error;

/// Errors from firewall operations.
#[derive(Error, Debug)]
pub enum FirewallError {
    #[error("Command execution failed: {0}")]
    CommandExecution(String),

    #[error("No supported firewall detected")]
    NoFirewall,

    #[error("Firewall operation failed: {0}")]
    OperationFailed(String),
}

pub type FirewallResult<T> = Result<T, FirewallError>;

/// Which firewall backend is active on this system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Ufw,
    Firewalld,
}

impl std::fmt::Display for FirewallBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallBackend::Ufw => write!(f, "ufw"),
            FirewallBackend::Firewalld => write!(f, "firewalld"),
        }
    }
}

/// Status of a single firewall port/rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortStatus {
    pub port: String,
    pub allowed: bool,
}

/// Overall firewall status for SMB.
#[derive(Debug, Clone)]
pub struct FirewallStatus {
    pub backend: FirewallBackend,
    pub active: bool,
    pub ports: Vec<PortStatus>,
}

impl FirewallStatus {
    /// Returns true if all required SMB ports are open.
    pub fn all_ports_open(&self) -> bool {
        self.ports.iter().all(|p| p.allowed)
    }

    /// Returns the list of ports that are NOT open.
    pub fn blocked_ports(&self) -> Vec<&PortStatus> {
        self.ports.iter().filter(|p| !p.allowed).collect()
    }
}

/// The ports Samba needs.
const SMB_PORTS: &[&str] = &["445/tcp", "139/tcp", "137/udp", "138/udp"];

/// Firewall checker and manager.
pub struct FirewallChecker;

impl FirewallChecker {
    /// Detect which firewall is active on the system.
    /// Returns None if no supported firewall is found or none is active.
    pub fn detect_backend() -> Option<FirewallBackend> {
        // Check ufw first (common on Ubuntu/Mint/Debian)
        if let Ok(output) = Command::new("ufw").arg("status").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("Status: active") {
                return Some(FirewallBackend::Ufw);
            }
        }

        // Check firewalld (common on Fedora/RHEL)
        if let Ok(output) = Command::new("firewall-cmd").arg("--state").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim() == "running" || output.status.success() {
                return Some(FirewallBackend::Firewalld);
            }
        }

        None
    }

    /// Get the full firewall status including per-port checks.
    pub fn get_status() -> FirewallResult<FirewallStatus> {
        let backend = Self::detect_backend()
            .ok_or(FirewallError::NoFirewall)?;

        let ports = match backend {
            FirewallBackend::Ufw => Self::check_ufw_ports()?,
            FirewallBackend::Firewalld => Self::check_firewalld_ports()?,
        };

        Ok(FirewallStatus {
            backend,
            active: true,
            ports,
        })
    }

    /// Check which SMB ports are allowed in ufw.
    fn check_ufw_ports() -> FirewallResult<Vec<PortStatus>> {
        let output = Command::new("ufw")
            .args(["status", "verbose"])
            .output()
            .map_err(|e| FirewallError::CommandExecution(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        let mut ports = Vec::new();
        for port_spec in SMB_PORTS {
            let allowed = Self::ufw_port_allowed(&stdout, port_spec);
            ports.push(PortStatus {
                port: port_spec.to_string(),
                allowed,
            });
        }

        Ok(ports)
    }

    /// Parse ufw status output to determine if a port is allowed.
    fn ufw_port_allowed(ufw_output: &str, port_spec: &str) -> bool {
        // ufw output looks like:
        // 445/tcp                    ALLOW IN    Anywhere
        // Samba                      ALLOW IN    Anywhere
        // We also check for the "Samba" application profile which covers all ports.
        let parts: Vec<&str> = port_spec.split('/').collect();
        let port_num = parts[0];
        let proto = parts.get(1).unwrap_or(&"tcp");

        for line in ufw_output.lines() {
            let line_lower = line.to_lowercase();
            // Direct port match: "445/tcp" or "445" (any protocol)
            if line_lower.contains(&format!("{}/{}", port_num, proto))
                && (line_lower.contains("allow"))
            {
                return true;
            }
            // Check for just the port number with ALLOW (ufw sometimes shows "445" without proto)
            if line_lower.contains(port_num) && line_lower.contains("allow") {
                return true;
            }
            // Check for Samba application profile
            if line_lower.contains("samba") && line_lower.contains("allow") {
                return true;
            }
        }

        false
    }

    /// Check which SMB ports are allowed in firewalld.
    fn check_firewalld_ports() -> FirewallResult<Vec<PortStatus>> {
        // Get list of allowed ports in the default zone
        let output = Command::new("firewall-cmd")
            .args(["--list-ports"])
            .output()
            .map_err(|e| FirewallError::CommandExecution(e.to_string()))?;

        let ports_output = String::from_utf8_lossy(&output.stdout).to_string();

        // Also check services (samba service covers the standard ports)
        let svc_output = Command::new("firewall-cmd")
            .args(["--list-services"])
            .output()
            .map_err(|e| FirewallError::CommandExecution(e.to_string()))?;

        let services_output = String::from_utf8_lossy(&svc_output.stdout).to_string();
        let has_samba_service = services_output.contains("samba");

        let mut ports = Vec::new();
        for port_spec in SMB_PORTS {
            let allowed = has_samba_service || ports_output.contains(port_spec);
            ports.push(PortStatus {
                port: port_spec.to_string(),
                allowed,
            });
        }

        Ok(ports)
    }

    /// Open all required SMB ports using the detected firewall.
    /// Requires root privileges — caller should use privileged_executor.
    pub fn open_smb_ports() -> FirewallResult<Vec<String>> {
        let backend = Self::detect_backend()
            .ok_or(FirewallError::NoFirewall)?;

        match backend {
            FirewallBackend::Ufw => Self::open_ports_ufw(),
            FirewallBackend::Firewalld => Self::open_ports_firewalld(),
        }
    }

    /// Open SMB ports via ufw (privileged).
    fn open_ports_ufw() -> FirewallResult<Vec<String>> {
        use super::privileged_executor::run_privileged;

        let mut results = Vec::new();

        for port_spec in SMB_PORTS {
            let (stdout, stderr, ok) = run_privileged("ufw", &["allow", port_spec])
                .map_err(|e| FirewallError::CommandExecution(e.to_string()))?;

            if ok {
                results.push(format!("Allowed {}", port_spec));
            } else {
                let msg = if !stderr.is_empty() { stderr } else { stdout };
                results.push(format!("Failed to allow {}: {}", port_spec, msg.trim()));
            }
        }

        Ok(results)
    }

    /// Open SMB ports via firewalld (privileged).
    fn open_ports_firewalld() -> FirewallResult<Vec<String>> {
        use super::privileged_executor::run_privileged;

        let mut results = Vec::new();

        // Try adding the samba service first (covers all ports)
        let (stdout, stderr, ok) = run_privileged(
            "firewall-cmd",
            &["--permanent", "--add-service=samba"],
        )
        .map_err(|e| FirewallError::CommandExecution(e.to_string()))?;

        if ok {
            results.push("Added samba service to firewall".to_string());
        } else {
            // Fall back to adding individual ports
            let msg = if !stderr.is_empty() { &stderr } else { &stdout };
            results.push(format!("samba service not available ({}), adding ports individually", msg.trim()));

            for port_spec in SMB_PORTS {
                let (stdout, stderr, ok) = run_privileged(
                    "firewall-cmd",
                    &["--permanent", &format!("--add-port={}", port_spec)],
                )
                .map_err(|e| FirewallError::CommandExecution(e.to_string()))?;

                if ok {
                    results.push(format!("Allowed {}", port_spec));
                } else {
                    let msg = if !stderr.is_empty() { stderr } else { stdout };
                    results.push(format!("Failed to allow {}: {}", port_spec, msg.trim()));
                }
            }
        }

        // Reload firewalld to apply permanent changes
        let (_, _, _) = run_privileged("firewall-cmd", &["--reload"])
            .map_err(|e| FirewallError::CommandExecution(e.to_string()))?;
        results.push("Firewall reloaded".to_string());

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ufw_port_allowed_direct_match() {
        let output = "445/tcp                    ALLOW IN    Anywhere\n";
        assert!(FirewallChecker::ufw_port_allowed(output, "445/tcp"));
    }

    #[test]
    fn test_ufw_port_allowed_samba_profile() {
        let output = "Samba                      ALLOW IN    Anywhere\n";
        assert!(FirewallChecker::ufw_port_allowed(output, "445/tcp"));
        assert!(FirewallChecker::ufw_port_allowed(output, "139/tcp"));
    }

    #[test]
    fn test_ufw_port_not_allowed() {
        let output = "22/tcp                     ALLOW IN    Anywhere\n";
        assert!(!FirewallChecker::ufw_port_allowed(output, "445/tcp"));
    }

    #[test]
    fn test_firewall_status_all_open() {
        let status = FirewallStatus {
            backend: FirewallBackend::Ufw,
            active: true,
            ports: vec![
                PortStatus { port: "445/tcp".into(), allowed: true },
                PortStatus { port: "139/tcp".into(), allowed: true },
            ],
        };
        assert!(status.all_ports_open());
        assert!(status.blocked_ports().is_empty());
    }

    #[test]
    fn test_firewall_status_some_blocked() {
        let status = FirewallStatus {
            backend: FirewallBackend::Ufw,
            active: true,
            ports: vec![
                PortStatus { port: "445/tcp".into(), allowed: true },
                PortStatus { port: "139/tcp".into(), allowed: false },
            ],
        };
        assert!(!status.all_ports_open());
        assert_eq!(status.blocked_ports().len(), 1);
    }
}
