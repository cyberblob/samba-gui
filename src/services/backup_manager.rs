#![allow(dead_code)]
//! BackupManager for managing SAMBA configuration backups
//!
//! Provides functionality to create, list, and restore configuration backups.

use crate::config::models::BackupInfo;
use chrono::{DateTime, Utc};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Determine the best backup directory, falling back to a user-writable location.
fn default_backup_dir() -> PathBuf {
    let system_dir = PathBuf::from("/var/backups/samba");

    // If the system dir already exists and is writable, use it.
    if system_dir.exists() {
        if let Ok(metadata) = fs::metadata(&system_dir) {
            if metadata.is_dir() {
                // Quick write-check: try creating a temp file
                let probe = system_dir.join(".write_probe");
                if fs::write(&probe, b"").is_ok() {
                    let _ = fs::remove_file(&probe);
                    return system_dir;
                }
            }
        }
    } else {
        // Try to create it – succeeds only with sufficient permissions.
        if fs::create_dir_all(&system_dir).is_ok() {
            return system_dir;
        }
    }

    // Fall back to ~/.local/share/samba-gui/backups
    if let Some(home) = std::env::var_os("HOME") {
        let user_dir = PathBuf::from(home)
            .join(".local/share/samba-gui/backups");
        // Ensure it exists (user home should be writable).
        let _ = fs::create_dir_all(&user_dir);
        return user_dir;
    }

    // Last resort – keep the original path and let callers handle errors.
    system_dir
}

/// Errors that can occur during backup operations
#[derive(Error, Debug)]
pub enum BackupError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Backup not found: {0}")]
    NotFound(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    
    #[error("No backups found")]
    NoBackups,
    
    #[error("Backup directory does not exist: {0}")]
    DirectoryNotFound(String),
}

/// Result type for backup operations
pub type BackupResult<T> = Result<T, BackupError>;

/// Manager for SAMBA configuration backups
pub struct BackupManager {
    backup_dir: PathBuf,
}

impl BackupManager {
    /// Create a new BackupManager with the default backup directory.
    /// Prefers `/var/backups/samba` when writable, otherwise falls back to
    /// `~/.local/share/samba-gui/backups`.
    pub fn new() -> Self {
        Self {
            backup_dir: default_backup_dir(),
        }
    }
    
    /// Create a new BackupManager with a custom backup directory
    pub fn with_path(path: impl Into<String>) -> Self {
        Self {
            backup_dir: PathBuf::from(path.into()),
        }
    }

    /// Return the backup directory path as a string (for UI display).
    pub fn backup_dir_display(&self) -> String {
        self.backup_dir.display().to_string()
    }
    
    /// Create a timestamped backup of the source file
    ///
    /// Copies the source file to the backup directory with a timestamped name.
    /// Returns BackupInfo with the backup path, timestamp, and size.
    /// Check if a source file exists and is accessible (directly or via sudo).
    /// Call this before backup() to give early feedback without needing auth.
    pub fn check_source(&self, source: &Path) -> BackupResult<()> {
        // Direct check — works if we have read perms on parent dir
        if source.exists() {
            if source.is_file() {
                return Ok(());
            } else {
                return Err(BackupError::InvalidPath(
                    format!("'{}' is not a file", source.display())
                ));
            }
        }

        // source.exists() can return false if we lack permission on the parent.
        // Try a non-interactive sudo test as a fallback.
        let status = std::process::Command::new("sudo")
            .args(["-n", "test", "-f", &source.display().to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        match status {
            Ok(s) if s.success() => Ok(()),
            _ => {
                // Can't confirm it exists even with sudo — check if the
                // parent directory at least exists (common case: /etc/samba/)
                if let Some(parent) = source.parent() {
                    if parent.exists() {
                        // Parent exists but file doesn't
                        return Err(BackupError::NotFound(source.display().to_string()));
                    }
                }
                // Parent doesn't exist either — file is definitely missing
                Err(BackupError::NotFound(source.display().to_string()))
            }
        }
    }

    pub fn backup(&self, source: &Path) -> BackupResult<BackupInfo> {
        // Basic existence check (caller should use check_source() for better UX)
        if !source.exists() && source.parent().map_or(true, |p| p.exists()) {
            eprintln!("[backup_mgr] Source not found: {}", source.display());
            return Err(BackupError::NotFound(source.display().to_string()));
        }
        
        // Create backup directory if it doesn't exist
        if !self.backup_dir.exists() {
            eprintln!("[backup_mgr] Creating backup dir: {}", self.backup_dir.display());
            fs::create_dir_all(&self.backup_dir).map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    BackupError::PermissionDenied(self.backup_dir.display().to_string())
                } else {
                    BackupError::Io(e)
                }
            })?;
        }
        
        // Generate timestamped backup filename
        let timestamp = Utc::now();
        let timestamp_str = timestamp.format("%Y%m%d_%H%M%S").to_string();
        let source_name = source.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config");
        let backup_filename = format!("{}_{}.bak", timestamp_str, source_name);
        let backup_path = self.backup_dir.join(&backup_filename);
        eprintln!("[backup_mgr] Copying {} -> {}", source.display(), backup_path.display());
        
        // Try direct copy first, fall back to privileged copy
        let copy_result = fs::copy(source, &backup_path);
        match &copy_result {
            Ok(bytes) => eprintln!("[backup_mgr] Direct copy OK: {} bytes", bytes),
            Err(e) => eprintln!("[backup_mgr] Direct copy failed: {} — trying sudo", e),
        }
        if copy_result.is_err() {
            // Use privileged copy via sudo cp
            let src_str = source.display().to_string();
            let dst_str = backup_path.display().to_string();
            let (_, stderr, _ok) = crate::services::privileged_executor::run_privileged(
                "cp", &[&src_str, &dst_str]
            ).map_err(|e| BackupError::PermissionDenied(e.to_string()))?;

            if !stderr.is_empty() && !backup_path.exists() {
                return Err(BackupError::PermissionDenied(stderr));
            }

            // Make the backup file owned by the current user so we can manage it
            if let Some(user) = std::env::var_os("USER") {
                let user_str = user.to_string_lossy().to_string();
                let _ = crate::services::privileged_executor::run_privileged(
                    "chown", &[&user_str, &dst_str]
                );
            }
        }
        
        // Get file size
        let metadata = fs::metadata(&backup_path).map_err(|e| {
            BackupError::Io(e)
        })?;
        let size_bytes = metadata.len();
        
        Ok(BackupInfo {
            path: backup_path.to_string_lossy().to_string(),
            timestamp,
            size_bytes,
        })
    }
    
    /// List all available backups in the backup directory
    ///
    /// Returns a vector of BackupInfo for each backup file.
    /// Returns an error if the backup directory doesn't exist.
    pub fn list_backups(&self) -> BackupResult<Vec<BackupInfo>> {
        // Create backup directory if it doesn't exist yet
        if !self.backup_dir.exists() {
            fs::create_dir_all(&self.backup_dir).map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    BackupError::PermissionDenied(self.backup_dir.display().to_string())
                } else {
                    BackupError::Io(e)
                }
            })?;
            // Directory was just created, so it's empty
            return Ok(Vec::new());
        }
        
        let mut backups = Vec::new();
        
        let entries = fs::read_dir(&self.backup_dir).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                BackupError::PermissionDenied(self.backup_dir.display().to_string())
            } else {
                BackupError::Io(e)
            }
        })?;
        
        for entry in entries.flatten() {
            let path = entry.path();
            
            // Only process files
            if !path.is_file() {
                continue;
            }
            
            // Get metadata for size and modification time
            if let Ok(metadata) = fs::metadata(&path) {
                let size_bytes = metadata.len();
                
                // Use modification time as timestamp
                let timestamp = metadata.modified()
                    .map(|t| DateTime::<Utc>::from(t))
                    .unwrap_or_else(|_| Utc::now());
                
                backups.push(BackupInfo {
                    path: path.to_string_lossy().to_string(),
                    timestamp,
                    size_bytes,
                });
            }
        }
        
        // Sort by timestamp, newest first
        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        Ok(backups)
    }
    
    /// Restore a backup to the specified destination
    ///
    /// Copies the backup file to the destination path.
    /// The destination must be a valid path.
    pub fn restore(&self, backup_path: &Path, destination: &Path) -> BackupResult<()> {
        // Validate backup path exists
        if !backup_path.exists() {
            return Err(BackupError::NotFound(backup_path.display().to_string()));
        }
        
        if !backup_path.is_file() {
            return Err(BackupError::InvalidPath(
                format!("Backup '{}' is not a file", backup_path.display())
            ));
        }
        
        // Validate destination path
        if let Some(parent) = destination.parent() {
            if !parent.exists() {
                return Err(BackupError::InvalidPath(
                    format!("Parent directory '{}' does not exist", parent.display())
                ));
            }
        }
        
        // Try direct copy first, fall back to privileged copy
        let copy_result = fs::copy(backup_path, destination);
        if copy_result.is_err() {
            let src_str = backup_path.display().to_string();
            let dst_str = destination.display().to_string();
            let (_, stderr, _ok) = crate::services::privileged_executor::run_privileged(
                "cp", &[&src_str, &dst_str]
            ).map_err(|e| BackupError::PermissionDenied(e.to_string()))?;

            if !stderr.is_empty() {
                // Check if the copy actually succeeded despite stderr output
                if let Ok(meta) = fs::metadata(destination) {
                    if meta.len() == 0 {
                        return Err(BackupError::PermissionDenied(stderr));
                    }
                } else {
                    return Err(BackupError::PermissionDenied(stderr));
                }
            }
        }
        
        Ok(())
    }

    /// Delete a backup file
    ///
    /// Removes the specified backup file from disk.
    pub fn delete(&self, backup_path: &Path) -> BackupResult<()> {
        if !backup_path.exists() {
            return Err(BackupError::NotFound(backup_path.display().to_string()));
        }

        if !backup_path.is_file() {
            return Err(BackupError::InvalidPath(
                format!("'{}' is not a file", backup_path.display())
            ));
        }

        // Verify the file is inside our backup directory
        if let Ok(canonical) = backup_path.canonicalize() {
            if let Ok(backup_dir) = self.backup_dir.canonicalize() {
                if !canonical.starts_with(&backup_dir) {
                    return Err(BackupError::InvalidPath(
                        format!("'{}' is not inside the backup directory", backup_path.display())
                    ));
                }
            }
        }

        fs::remove_file(backup_path).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                BackupError::PermissionDenied(backup_path.display().to_string())
            } else {
                BackupError::Io(e)
            }
        })?;

        Ok(())
    }
}

impl Default for BackupManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_backup_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        let manager = BackupManager::with_path(backup_dir.to_string_lossy().as_ref());
        
        let source = temp_dir.path().join("smb.conf");
        fs::write(&source, "test config").unwrap();
        
        let result = manager.backup(&source);
        assert!(result.is_ok());
        
        let info = result.unwrap();
        assert!(info.path.contains(".bak"));
        assert!(info.size_bytes > 0);
    }
    
    #[test]
    fn test_backup_source_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let manager = BackupManager::with_path(temp_dir.path().to_string_lossy().as_ref());
        
        let source = temp_dir.path().join("nonexistent.conf");
        let result = manager.backup(&source);
        
        assert!(result.is_err());
        matches!(result.unwrap_err(), BackupError::NotFound(_));
    }
    
    #[test]
    fn test_list_backups_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let manager = BackupManager::with_path(temp_dir.path().to_string_lossy().as_ref());
        
        let result = manager.list_backups();
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
    
    #[test]
    fn test_list_backups_directory_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let non_existent = temp_dir.path().join("does_not_exist");
        let manager = BackupManager::with_path(non_existent.to_string_lossy().as_ref());
        
        // Should auto-create the directory and return an empty list
        let result = manager.list_backups();
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
        assert!(non_existent.exists());
    }
    
    #[test]
    fn test_list_backups_returns_sorted() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        
        // Create files with different timestamps
        let file1 = backup_dir.join("old.bak");
        let file2 = backup_dir.join("new.bak");
        fs::write(&file1, "old content").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&file2, "new content").unwrap();
        
        let manager = BackupManager::with_path(backup_dir.to_string_lossy().as_ref());
        let backups = manager.list_backups().unwrap();
        
        assert_eq!(backups.len(), 2);
        // Newest first
        assert!(backups[0].timestamp >= backups[1].timestamp);
    }
    
    #[test]
    fn test_restore_success() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        
        let backup_file = backup_dir.join("test.bak");
        fs::write(&backup_file, "backup content").unwrap();
        
        let manager = BackupManager::with_path(backup_dir.to_string_lossy().as_ref());
        let destination = temp_dir.path().join("restored.conf");
        
        let result = manager.restore(&backup_file, &destination);
        assert!(result.is_ok());
        assert!(destination.exists());
        
        let content = fs::read_to_string(&destination).unwrap();
        assert_eq!(content, "backup content");
    }
    
    #[test]
    fn test_restore_backup_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let manager = BackupManager::new();
        
        let backup_path = temp_dir.path().join("nonexistent.bak");
        let destination = temp_dir.path().join("restored.conf");
        
        let result = manager.restore(&backup_path, &destination);
        assert!(result.is_err());
        matches!(result.unwrap_err(), BackupError::NotFound(_));
    }
}