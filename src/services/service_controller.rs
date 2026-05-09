#![allow(dead_code)]
//! ServiceController for managing systemd services (smbd, nmbd, winbind)
//!
//! Provides functionality to get status, start, stop, and restart SAMBA services.

use std::process::Command;
use thiserror::Error;
use super::privileged_executor::run_privileged;

/// Errors that can occur during service operations
#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Command execution failed: {0}")]
    CommandExecution(String),
    
    #[error("Failed to parse systemctl output: {0}")]
    ParseError(String),
    
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
}

/// Result type for service operations
pub type ServiceResult<T> = Result<T, ServiceError>;

/// Service status information
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceStatus {
    pub name: String,
    pub active: bool,
    pub enabled: bool,
    pub substate: String,
}

/// Manager for systemd services
pub struct ServiceController;

impl ServiceController {
    /// Create a new ServiceController
    pub fn new() -> Self {
        Self
    }
    
    /// Get the status of a service
    /// 
    /// Executes `systemctl status <service>` and parses the output
    pub fn get_status(&self, service_name: &str) -> ServiceResult<ServiceStatus> {
        let full_service_name = Self::ensure_service_suffix(service_name);
        
        let output = Command::new("systemctl")
            .args(["status", &full_service_name])
            .output()
            .map_err(|e| ServiceError::CommandExecution(e.to_string()))?;
        
        // Check if service not found (exit code 4)
        if output.status.code() == Some(4) {
            return Err(ServiceError::ServiceNotFound(
                format!("Service '{}' not found", full_service_name)
            ));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        // If both stdout and stderr are empty, something went wrong
        if stdout.is_empty() && stderr.is_empty() {
            return Err(ServiceError::CommandExecution(
                "No output from systemctl".to_string()
            ));
        }
        
        // Use stdout, fall back to stderr if stdout is empty
        let output_text = if stdout.is_empty() { stderr.as_ref() } else { stdout.as_ref() };
        
        Self::parse_status(&full_service_name, output_text)
    }
    
    /// Start a service
    /// 
    /// Executes `systemctl start <service>`
    pub fn start(&self, service_name: &str) -> ServiceResult<()> {
        Self::execute_systemctl_command("start", service_name)
    }
    
    /// Stop a service
    /// 
    /// Executes `systemctl stop <service>`
    pub fn stop(&self, service_name: &str) -> ServiceResult<()> {
        Self::execute_systemctl_command("stop", service_name)
    }
    
    /// Restart a service
    /// 
    /// Executes `systemctl restart <service>`
    pub fn restart(&self, service_name: &str) -> ServiceResult<()> {
        Self::execute_systemctl_command("restart", service_name)
    }
    
    /// Execute a systemctl command (start, stop, restart)
    fn execute_systemctl_command(action: &str, service_name: &str) -> ServiceResult<()> {
        let full_service_name = Self::ensure_service_suffix(service_name);

        let (_stdout, stderr, _ok) = run_privileged("systemctl", &[action, &full_service_name])
            .map_err(|e| ServiceError::CommandExecution(e.to_string()))?;

        if !stderr.is_empty() && stderr.contains("Failed") {
            return Err(ServiceError::CommandExecution(
                format!("Failed to {} service '{}': {}", action, full_service_name, stderr)
            ));
        }

        Ok(())
    }
    
    /// Parse systemctl status output into ServiceStatus
    fn parse_status(service_name: &str, output: &str) -> ServiceResult<ServiceStatus> {
        let mut active = false;
        let mut enabled = false;
        let mut substate = String::new();
        
        for line in output.lines() {
            let line = line.trim();
            
            // Parse "Active: active (running)" or "Active: inactive (dead)"
            if line.starts_with("Active:") {
                let active_part = line.strip_prefix("Active:").unwrap_or("").trim();
                // Check if active (running, exited, etc.) vs inactive
                active = !active_part.starts_with("inactive") 
                    && !active_part.starts_with("failed")
                    && !active_part.starts_with("activating")
                    && !active_part.starts_with("deactivating");
                
                // Extract substate from parentheses if present
                if let Some(start) = active_part.find('(') {
                    if let Some(end) = active_part.find(')') {
                        substate = active_part[start+1..end].to_string();
                    }
                } else {
                    // No parentheses, use the first word as substate
                    substate = active_part.split_whitespace().next().unwrap_or("").to_string();
                }
            }
            
            // Parse "Loaded: loaded (/lib/systemd/system/smbd.service; enabled; vendor preset: enabled)"
            // or "Loaded: loaded (/lib/systemd/system/smbd.service; disabled; ...)"
            if line.starts_with("Loaded:") {
                let loaded_part = line.strip_prefix("Loaded:").unwrap_or("").trim();
                // Check for "; enabled;" specifically (not just "enabled" anywhere)
                // The format is: "; enabled;" or "; disabled;"
                enabled = loaded_part.contains("; enabled;") || loaded_part.ends_with("; enabled");
            }
        }
        
        // If we couldn't parse anything, return an error
        if substate.is_empty() && !active {
            // Try to detect if it's just not running vs parse error
            if output.contains("inactive (dead)") || output.contains("inactive") {
                substate = "dead".to_string();
                active = false;
            } else if output.contains("running") {
                substate = "running".to_string();
                active = true;
            } else {
                return Err(ServiceError::ParseError(
                    format!("Could not parse status output for {}", service_name)
                ));
            }
        }
        
        Ok(ServiceStatus {
            name: service_name.to_string(),
            active,
            enabled,
            substate,
        })
    }
    
    /// Ensure the service name has .service suffix
    fn ensure_service_suffix(service_name: &str) -> String {
        if service_name.ends_with(".service") {
            service_name.to_string()
        } else {
            format!("{}.service", service_name)
        }
    }
    
    /// Get list of managed services
    pub fn managed_services() -> Vec<&'static str> {
        vec!["smbd", "nmbd", "winbind"]
    }
}

impl Default for ServiceController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ensure_service_suffix_with_suffix() {
        let result = ServiceController::ensure_service_suffix("smbd.service");
        assert_eq!(result, "smbd.service");
    }
    
    #[test]
    fn test_ensure_service_suffix_without_suffix() {
        let result = ServiceController::ensure_service_suffix("smbd");
        assert_eq!(result, "smbd.service");
    }
    
    #[test]
    fn test_parse_status_active_running() {
        let output = r#"● smbd.service - Samba SMB Daemon
     Loaded: loaded (/lib/systemd/system/smbd.service; enabled; vendor preset: enabled)
     Active: active (running) since Mon 2024-01-01 12:00:00 UTC; 1h ago
   Main PID: 1234 (smbd)
     CGroup: /system.slice/smbd.service
             └─1234 /usr/sbin/smbd --foreground --no-process-group"#;
        
        let status = ServiceController::parse_status("smbd.service", output).unwrap();
        
        assert_eq!(status.name, "smbd.service");
        assert!(status.active);
        assert!(status.enabled);
        assert_eq!(status.substate, "running");
    }
    
    #[test]
    fn test_parse_status_inactive() {
        let output = r#"● smbd.service - Samba SMB Daemon
     Loaded: loaded (/lib/systemd/system/smbd.service; disabled; vendor preset: enabled)
     Active: inactive (dead)
   Main PID: 1234 (exited)"#;
        
        let status = ServiceController::parse_status("smbd.service", output).unwrap();
        
        assert_eq!(status.name, "smbd.service");
        assert!(!status.active);
        assert!(!status.enabled);
        assert_eq!(status.substate, "dead");
    }
    
    #[test]
    fn test_parse_status_failed() {
        let output = r#"● smbd.service - Samba SMB Daemon
     Loaded: loaded (/lib/systemd/system/smbd.service; enabled; vendor preset: enabled)
     Active: failed
   Main PID: 1234 (code=exited, status=1/FAILURE)"#;
        
        let status = ServiceController::parse_status("smbd.service", output).unwrap();
        
        assert_eq!(status.name, "smbd.service");
        assert!(!status.active);
        assert!(status.enabled);
    }
    
    #[test]
    fn test_parse_status_exited() {
        let output = r#"● nmbd.service - Samba NMB Daemon
     Loaded: loaded (/lib/systemd/system/nmbd.service; enabled; vendor preset: enabled)
     Active: active (exited) since Mon 2024-01-01 12:00:00 UTC; 1h ago
   Main PID: 1234 (nmbd)"#;
        
        let status = ServiceController::parse_status("nmbd.service", output).unwrap();
        
        assert!(status.active);
        assert!(status.enabled);
        assert_eq!(status.substate, "exited");
    }
    
    #[test]
    fn test_parse_status_activating() {
        let output = r#"● winbind.service - Samba Winbind Daemon
     Loaded: loaded (/lib/systemd/system/winbind.service; enabled; vendor preset: enabled)
     Active: activating (auto-restart) since Mon 2024-01-01 12:00:00 UTC; 2s ago"#;
        
        let status = ServiceController::parse_status("winbind.service", output).unwrap();
        
        // activating is not considered active
        assert!(!status.active);
        assert!(status.enabled);
    }
    
    #[test]
    fn test_managed_services() {
        let services = ServiceController::managed_services();
        
        assert_eq!(services.len(), 3);
        assert!(services.contains(&"smbd"));
        assert!(services.contains(&"nmbd"));
        assert!(services.contains(&"winbind"));
    }
}