#![allow(dead_code)]
// Share preview service - generates smb.conf sections and runs testparm

use crate::config::{ConfigParser, Share, SambaConfig, GlobalSettings};
use std::process::Command;
use thiserror::Error;

/// Errors that can occur during share preview or testparm execution
#[derive(Debug, Error)]
pub enum PreviewError {
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("IO error: {0}")]
    IoError(String),
    
    #[error("testparm execution error: {0}")]
    TestparmError(String),
}

/// Result type for preview operations
pub type PreviewResult<T> = Result<T, PreviewError>;

/// Share preview and validation service
pub struct SharePreview;

impl SharePreview {
    /// Generate a preview of the smb.conf section for a single share
    /// This includes the global section followed by the share section
    pub fn preview_share(share: &Share, global: &GlobalSettings) -> PreviewResult<String> {
        // Create a minimal config with just this share
        let config = SambaConfig {
            global: global.clone(),
            shares: vec![share.clone()],
        };
        
        ConfigParser::serialize(&config)
            .map_err(|e| PreviewError::SerializationError(e.to_string()))
    }
    
    /// Generate just the share section (without global) for preview
    pub fn preview_share_section(share: &Share) -> PreviewResult<String> {
        let mut output = String::new();
        
        output.push_str(&format!("[{}]\n", share.name));
        output.push_str(&format!("   path = {}\n", share.path));
        
        if !share.comment.is_empty() {
            output.push_str(&format!("   comment = {}\n", share.comment));
        }
        
        output.push_str(&format!("   browseable = {}\n", 
            if share.browsable { "yes" } else { "no" }));
        output.push_str(&format!("   writable = {}\n", 
            if share.writable { "yes" } else { "no" }));
        output.push_str(&format!("   guest ok = {}\n", 
            if share.guest_ok { "yes" } else { "no" }));
        output.push_str(&format!("   read only = {}\n", 
            if share.read_only { "yes" } else { "no" }));
        
        if !share.create_mask.is_empty() {
            output.push_str(&format!("   create mask = {}\n", share.create_mask));
        }
        if !share.directory_mask.is_empty() {
            output.push_str(&format!("   directory mask = {}\n", share.directory_mask));
        }
        
        if !share.valid_users.is_empty() {
            output.push_str(&format!("   valid users = {}\n", share.valid_users.join(" ")));
        }
        if !share.invalid_users.is_empty() {
            output.push_str(&format!("   invalid users = {}\n", share.invalid_users.join(" ")));
        }
        if !share.hosts_allow.is_empty() {
            output.push_str(&format!("   hosts allow = {}\n", share.hosts_allow.join(" ")));
        }
        if !share.hosts_deny.is_empty() {
            output.push_str(&format!("   hosts deny = {}\n", share.hosts_deny.join(" ")));
        }
        
        Ok(output)
    }
    
    /// Run testparm to validate the share configuration
    /// Returns the testparm output with error lines highlighted
    pub fn run_testparm(share: &Share, global: &GlobalSettings) -> PreviewResult<TestparmOutput> {
        // First generate the full config
        let config = SambaConfig {
            global: global.clone(),
            shares: vec![share.clone()],
        };
        
        let config_content = ConfigParser::serialize(&config)
            .map_err(|e| PreviewError::SerializationError(e.to_string()))?;
        
        // Write to a temporary file
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("smb_preview.conf");
        
        std::fs::write(&temp_path, &config_content)
            .map_err(|e| PreviewError::IoError(e.to_string()))?;
        
        // Run testparm on the temp file
        let output = Command::new("testparm")
            .args(["-s", "-l", temp_path.to_str().unwrap_or("/tmp/smb_preview.conf")])
            .output();
        
        // Clean up temp file
        let _ = std::fs::remove_file(&temp_path);
        
        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let exit_code = output.status.code().unwrap_or(-1);
                
                // Check for errors in output
                let has_errors = exit_code != 0 
                    || stderr.to_lowercase().contains("error")
                    || stdout.to_lowercase().contains("error");
                
                // Extract error lines for highlighting
                let error_lines = Self::extract_error_lines(&stdout, &stderr);
                
                Ok(TestparmOutput {
                    stdout,
                    stderr,
                    exit_code,
                    has_errors,
                    error_lines,
                })
            }
            Err(e) => {
                // testparm might not be installed
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(TestparmOutput {
                        stdout: String::new(),
                        stderr: "testparm not found. Install samba-common-bin package.".to_string(),
                        exit_code: -1,
                        has_errors: true,
                        error_lines: vec![0], // Line 0 indicates testparm not available
                    })
                } else {
                    Err(PreviewError::TestparmError(e.to_string()))
                }
            }
        }
    }
    
    /// Extract line numbers that contain errors
    fn extract_error_lines(stdout: &str, stderr: &str) -> Vec<usize> {
        let mut error_lines = Vec::new();
        
        // Check stderr for errors
        for (line_num, line) in stderr.lines().enumerate() {
            let lower = line.to_lowercase();
            if lower.contains("error") || lower.contains("warning") || lower.contains("failed") {
                error_lines.push(line_num);
            }
        }
        
        // Check stdout for errors
        for (line_num, line) in stdout.lines().enumerate() {
            let lower = line.to_lowercase();
            if lower.contains("error") || lower.contains("warning") || lower.contains("failed") {
                if !error_lines.contains(&line_num) {
                    error_lines.push(line_num);
                }
            }
        }
        
        error_lines
    }
}

/// Output from testparm execution
#[derive(Debug, Clone)]
pub struct TestparmOutput {
    /// Standard output from testparm
    pub stdout: String,
    /// Standard error from testparm
    pub stderr: String,
    /// Exit code from testparm
    pub exit_code: i32,
    /// Whether errors were detected
    pub has_errors: bool,
    /// Line numbers containing errors (for highlighting)
    pub error_lines: Vec<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    /// Test generating share preview section
    #[test]
    fn test_preview_share_section() {
        let share = Share {
            name: "testshare".to_string(),
            path: "/home/test".to_string(),
            comment: "Test share".to_string(),
            browsable: true,
            writable: true,
            guest_ok: false,
            read_only: false,
            create_mask: "0744".to_string(),
            directory_mask: "0755".to_string(),
            valid_users: vec!["user1".to_string()],
            ..Default::default()
        };
        
        let preview = SharePreview::preview_share_section(&share).unwrap();
        
        assert!(preview.contains("[testshare]"));
        assert!(preview.contains("path = /home/test"));
        assert!(preview.contains("comment = Test share"));
        assert!(preview.contains("writable = yes"));
        assert!(preview.contains("valid users = user1"));
    }
    
    /// Test generating full share preview with global
    #[test]
    fn test_preview_share_with_global() {
        let share = Share {
            name: "myshare".to_string(),
            path: "/srv/samba".to_string(),
            comment: "My share".to_string(),
            ..Default::default()
        };
        
        let global = GlobalSettings::default();
        
        let preview = SharePreview::preview_share(&share, &global).unwrap();
        
        assert!(preview.contains("[global]"));
        assert!(preview.contains("[myshare]"));
        assert!(preview.contains("path = /srv/samba"));
    }
    
    /// Test error line extraction
    #[test]
    fn test_extract_error_lines() {
        let stderr = "Error: invalid configuration\nWarning: deprecated option";
        let stdout = "Loaded services file OK.";
        
        let error_lines = SharePreview::extract_error_lines(stdout, stderr);
        
        assert!(error_lines.len() >= 2);
    }
    
    /// Test empty share section
    #[test]
    fn test_preview_minimal_share() {
        let share = Share {
            name: "minimal".to_string(),
            path: "/minimal".to_string(),
            ..Default::default()
        };
        
        let preview = SharePreview::preview_share_section(&share).unwrap();
        
        assert!(preview.contains("[minimal]"));
        assert!(preview.contains("path = /minimal"));
    }
}