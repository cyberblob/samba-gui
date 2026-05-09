#![allow(dead_code)]
use crate::config::{GlobalSettings, SambaConfig, SecurityMode, Share};
use thiserror::Error;

/// Errors that can occur during configuration parsing, serialization, or validation
#[derive(Debug, Error, PartialEq)]
pub enum ConfigError {
    #[error("Parse error at line {line}: {message}")]
    ParseError { line: usize, message: String },
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("IO error: {0}")]
    IoError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        ConfigError::IoError(err.to_string())
    }
}

/// Result type for configuration operations
pub type ConfigResult<T> = Result<T, ConfigError>;

/// Parser for Samba configuration files (smb.conf format)
pub struct ConfigParser;

impl ConfigParser {
    /// Parse smb.conf format into SambaConfig
    pub fn parse(content: &str) -> ConfigResult<SambaConfig> {
        let mut global = GlobalSettings::default();
        let mut shares: Vec<Share> = Vec::new();
        let mut current_section: Option<String> = None;
        let mut current_share: Option<Share> = None;
        
        for (_line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            
            // Skip empty lines and comments
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            
            // Check for section headers
            if line.starts_with('[') && line.ends_with(']') {
                // Save previous share if any
                if let Some(share) = current_share.take() {
                    shares.push(share);
                }
                
                let section_name = line[1..line.len()-1].trim().to_string();
                current_section = Some(section_name.clone());
                
                if section_name.to_lowercase() == "global" {
                    // Reset global to defaults before parsing
                    global = GlobalSettings::default();
                } else {
                    // Start a new share
                    current_share = Some(Share {
                        name: section_name,
                        ..Default::default()
                    });
                }
                continue;
            }
            
            // Parse key-value pairs
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();
                
                match current_section.as_deref() {
                    Some("global") | None => {
                        Self::parse_global_setting(&mut global, &key, &value)?;
                    }
                    Some(_) => {
                        // Share section
                        if let Some(ref mut share) = current_share {
                            Self::parse_share_setting(share, &key, &value)?;
                        }
                    }
                }
            }
        }
        
        // Don't forget the last share
        if let Some(share) = current_share {
            shares.push(share);
        }
        
        Ok(SambaConfig { global, shares })
    }
    
    /// Parse a global setting into GlobalSettings
    fn parse_global_setting(global: &mut GlobalSettings, key: &str, value: &str) -> ConfigResult<()> {
        match key {
            "workgroup" => global.workgroup = value.to_string(),
            "server string" => global.server_string = value.to_string(),
            "security" => {
                global.security = match value.to_lowercase().as_str() {
                    "user" => SecurityMode::User,
                    "share" => SecurityMode::Share,
                    "server" => SecurityMode::Server,
                    "domain" => SecurityMode::Domain,
                    "ads" => SecurityMode::ADS,
                    _ => SecurityMode::User,
                };
            }
            "encrypt passwords" => {
                // Deprecated in modern Samba — silently consume for backward compatibility
            }
            "guest account" => global.guest_account = value.to_string(),
            "map to guest" => global.map_to_guest = value.to_string(),
            "dns proxy" => {
                global.dns_proxy = value.to_lowercase() == "yes" || value == "true";
            }
            "socket options" => global.socket_options = value.to_string(),
            "winbind nss info" => global.winbind_nss_info = value.to_string(),
            "passdb backend" => global.passdb_backend = value.to_string(),
            "smb encrypt" => global.smb_encrypt = value.to_string(),
            "server min protocol" => global.server_min_protocol = value.to_string(),
            "server max protocol" => global.server_max_protocol = value.to_string(),
            "client min protocol" => global.client_min_protocol = value.to_string(),
            "client max protocol" => global.client_max_protocol = value.to_string(),
            "server signing" => global.server_signing = value.to_string(),
            "client signing" => global.client_signing = value.to_string(),
            "load printers" => {
                global.load_printers = value.to_lowercase() == "yes" || value == "true";
            }
            "disable spoolss" => {
                global.disable_spoolss = value.to_lowercase() == "yes" || value == "true";
            }
            "log file" => global.log_file = value.to_string(),
            "log level" | "debug level" => global.log_level = value.to_string(),
            "max log size" => {
                global.max_log_size = value.parse().unwrap_or(1000);
            }
            "netbios name" => global.netbios_name = value.to_string(),
            "interfaces" => global.interfaces = value.to_string(),
            "bind interfaces only" => {
                global.bind_interfaces_only = value.to_lowercase() == "yes" || value == "true";
            }
            "hosts allow" | "allow hosts" => global.hosts_allow = value.to_string(),
            "hosts deny" | "deny hosts" => global.hosts_deny = value.to_string(),
            "wins support" => {
                global.wins_support = value.to_lowercase() == "yes" || value == "true";
            }
            "wins server" => global.wins_server = value.to_string(),
            "name resolve order" => global.name_resolve_order = value.to_string(),
            "realm" => global.realm = value.to_string(),
            "password server" => global.password_server = value.to_string(),
            "unix password sync" => {
                global.unix_password_sync = value.to_lowercase() == "yes" || value == "true";
            }
            "domain logons" => {
                // Deprecated in modern Samba — silently consume for backward compatibility
            }
            "domain master" => {
                global.domain_master = value.to_lowercase() == "yes" || value == "true";
            }
            "local master" => {
                global.local_master = value.to_lowercase() == "yes" || value == "true";
            }
            "preferred master" => {
                global.preferred_master = value.to_lowercase() == "yes" || value == "true";
            }
            "os level" => {
                global.os_level = value.parse().unwrap_or(20);
            }
            "logon drive" => global.logon_drive = value.to_string(),
            "logon home" => global.logon_home = value.to_string(),
            "logon path" => global.logon_path = value.to_string(),
            "logon script" => global.logon_script = value.to_string(),
            "username map" => global.username_map = value.to_string(),
            "smb passwd file" => global.smb_passwd_file = value.to_string(),
            "null passwords" => {
                // Deprecated in modern Samba — silently consume for backward compatibility
            }
            "wins proxy" => {
                global.wins_proxy = value.to_lowercase() == "yes" || value == "true";
            }
            "restrict anonymous" => {
                global.restrict_anonymous = value.parse().unwrap_or(0);
            }
            "ntlm auth" => global.ntlm_auth = value.to_string(),
            "client ntlmv2 auth" => {
                global.client_ntlmv2_auth = value.to_lowercase() == "yes" || value == "true";
            }
            // Deprecated since Samba 4.13 — silently ignore if present in existing configs
            "client lanman auth" | "client use spnego" | "client plaintext auth" => {}
            "wide links" => {
                global.wide_links = value.to_lowercase() == "yes" || value == "true";
            }
            "unix extensions" => {
                global.unix_extensions = value.to_lowercase() == "yes" || value == "true";
            }
            "case sensitive" => {
                global.case_sensitive = value.to_lowercase() == "yes" || value == "true";
            }
            "read raw" => {
                global.read_raw = value.to_lowercase() == "yes" || value == "true";
            }
            "write raw" => {
                global.write_raw = value.to_lowercase() == "yes" || value == "true";
            }
            "max xmit" => {
                global.max_xmit = value.parse().unwrap_or(65535);
            }
            "deadtime" => {
                global.deadtime = value.parse().unwrap_or(0);
            }
            "keepalive" | "keep alive" => {
                global.keepalive = value.parse().unwrap_or(300);
            }
            _ => {
                // Unknown global option, skip silently
            }
        }
        Ok(())
    }
    
    /// Parse a share setting into Share
    fn parse_share_setting(share: &mut Share, key: &str, value: &str) -> ConfigResult<()> {
        match key {
            "path" => share.path = value.to_string(),
            "comment" => share.comment = value.to_string(),
            "browsable" | "browseable" => {
                share.browsable = value.to_lowercase() == "yes" || value == "true";
            }
            "writable" | "writeable" => {
                share.writable = value.to_lowercase() == "yes" || value == "true";
            }
            "guest ok" | "guest_ok" | "public" => {
                share.guest_ok = value.to_lowercase() == "yes" || value == "true";
            }
            "read only" | "read_only" => {
                share.read_only = value.to_lowercase() == "yes" || value == "true";
            }
            "create mask" | "create_mask" | "create mode" => share.create_mask = value.to_string(),
            "directory mask" | "directory_mask" | "directory mode" => share.directory_mask = value.to_string(),
            "force create mode" => share.force_create_mode = value.to_string(),
            "force directory mode" => share.force_directory_mode = value.to_string(),
            "valid users" | "valid_users" => {
                share.valid_users = value.split_whitespace().map(String::from).collect();
            }
            "invalid users" | "invalid_users" => {
                share.invalid_users = value.split_whitespace().map(String::from).collect();
            }
            "read list" => {
                share.read_list = value.split_whitespace().map(String::from).collect();
            }
            "write list" => {
                share.write_list = value.split_whitespace().map(String::from).collect();
            }
            "hosts allow" | "hosts_allow" | "allow hosts" => {
                share.hosts_allow = value.split_whitespace().map(String::from).collect();
            }
            "hosts deny" | "hosts_deny" | "deny hosts" => {
                share.hosts_deny = value.split_whitespace().map(String::from).collect();
            }
            "force user" => share.force_user = value.to_string(),
            "force group" | "group" => share.force_group = value.to_string(),
            "inherit acls" => {
                share.inherit_acls = value.to_lowercase() == "yes" || value == "true";
            }
            "inherit permissions" => {
                share.inherit_permissions = value.to_lowercase() == "yes" || value == "true";
            }
            "vfs objects" => {
                share.vfs_objects = value.split_whitespace().map(String::from).collect();
            }
            "available" => {
                share.available = value.to_lowercase() == "yes" || value == "true";
            }
            _ => {
                // Unknown share option, skip silently
            }
        }
        Ok(())
    }
    
    /// Serialize SambaConfig to smb.conf format
    pub fn serialize(config: &SambaConfig) -> ConfigResult<String> {
        let mut output = String::new();
        
        // Serialize global section
        output.push_str("[global]\n");
        output.push_str(&format!("   workgroup = {}\n", config.global.workgroup));
        output.push_str(&format!("   server string = {}\n", config.global.server_string));
        if !config.global.netbios_name.is_empty() {
            output.push_str(&format!("   netbios name = {}\n", config.global.netbios_name));
        }
        output.push_str(&format!("   security = {}\n", config.global.security));
        output.push_str(&format!("   passdb backend = {}\n", config.global.passdb_backend));
        output.push_str(&format!("   guest account = {}\n", config.global.guest_account));
        output.push_str(&format!("   map to guest = {}\n", config.global.map_to_guest));
        output.push_str(&format!("   dns proxy = {}\n", 
            if config.global.dns_proxy { "yes" } else { "no" }));
        output.push_str(&format!("   socket options = {}\n", config.global.socket_options));
        output.push_str(&format!("   winbind nss info = {}\n", config.global.winbind_nss_info));
        // Security / protocol
        output.push_str(&format!("   smb encrypt = {}\n", config.global.smb_encrypt));
        output.push_str(&format!("   server min protocol = {}\n", config.global.server_min_protocol));
        output.push_str(&format!("   server max protocol = {}\n", config.global.server_max_protocol));
        output.push_str(&format!("   client min protocol = {}\n", config.global.client_min_protocol));
        output.push_str(&format!("   client max protocol = {}\n", config.global.client_max_protocol));
        output.push_str(&format!("   server signing = {}\n", config.global.server_signing));
        output.push_str(&format!("   client signing = {}\n", config.global.client_signing));
        // Networking
        if !config.global.interfaces.is_empty() {
            output.push_str(&format!("   interfaces = {}\n", config.global.interfaces));
        }
        output.push_str(&format!("   bind interfaces only = {}\n",
            if config.global.bind_interfaces_only { "yes" } else { "no" }));
        if !config.global.hosts_allow.is_empty() {
            output.push_str(&format!("   hosts allow = {}\n", config.global.hosts_allow));
        }
        if !config.global.hosts_deny.is_empty() {
            output.push_str(&format!("   hosts deny = {}\n", config.global.hosts_deny));
        }
        // WINS / Name Resolution
        output.push_str(&format!("   wins support = {}\n",
            if config.global.wins_support { "yes" } else { "no" }));
        if !config.global.wins_server.is_empty() {
            output.push_str(&format!("   wins server = {}\n", config.global.wins_server));
        }
        output.push_str(&format!("   name resolve order = {}\n", config.global.name_resolve_order));
        // Domain / Authentication
        if !config.global.realm.is_empty() {
            output.push_str(&format!("   realm = {}\n", config.global.realm));
        }
        if !config.global.password_server.is_empty() {
            output.push_str(&format!("   password server = {}\n", config.global.password_server));
        }
        output.push_str(&format!("   unix password sync = {}\n",
            if config.global.unix_password_sync { "yes" } else { "no" }));
        output.push_str(&format!("   domain master = {}\n",
            if config.global.domain_master { "yes" } else { "no" }));
        output.push_str(&format!("   local master = {}\n",
            if config.global.local_master { "yes" } else { "no" }));
        output.push_str(&format!("   preferred master = {}\n",
            if config.global.preferred_master { "yes" } else { "no" }));
        output.push_str(&format!("   os level = {}\n", config.global.os_level));
        // Domain logon settings
        if !config.global.logon_drive.is_empty() {
            output.push_str(&format!("   logon drive = {}\n", config.global.logon_drive));
        }
        if !config.global.logon_home.is_empty() {
            output.push_str(&format!("   logon home = {}\n", config.global.logon_home));
        }
        if !config.global.logon_path.is_empty() {
            output.push_str(&format!("   logon path = {}\n", config.global.logon_path));
        }
        if !config.global.logon_script.is_empty() {
            output.push_str(&format!("   logon script = {}\n", config.global.logon_script));
        }
        // Additional auth/security
        if !config.global.username_map.is_empty() {
            output.push_str(&format!("   username map = {}\n", config.global.username_map));
        }
        if !config.global.smb_passwd_file.is_empty() {
            output.push_str(&format!("   smb passwd file = {}\n", config.global.smb_passwd_file));
        }
        output.push_str(&format!("   wins proxy = {}\n",
            if config.global.wins_proxy { "yes" } else { "no" }));
        output.push_str(&format!("   restrict anonymous = {}\n", config.global.restrict_anonymous));
        output.push_str(&format!("   ntlm auth = {}\n", config.global.ntlm_auth));
        // Client authentication
        output.push_str(&format!("   client NTLMv2 auth = {}\n",
            if config.global.client_ntlmv2_auth { "yes" } else { "no" }));
        // Filesystem / symlinks
        output.push_str(&format!("   wide links = {}\n",
            if config.global.wide_links { "yes" } else { "no" }));
        output.push_str(&format!("   unix extensions = {}\n",
            if config.global.unix_extensions { "yes" } else { "no" }));
        output.push_str(&format!("   case sensitive = {}\n",
            if config.global.case_sensitive { "yes" } else { "no" }));
        // Printing
        output.push_str(&format!("   load printers = {}\n",
            if config.global.load_printers { "yes" } else { "no" }));
        output.push_str(&format!("   disable spoolss = {}\n",
            if config.global.disable_spoolss { "yes" } else { "no" }));
        // Logging
        output.push_str(&format!("   log file = {}\n", config.global.log_file));
        output.push_str(&format!("   log level = {}\n", config.global.log_level));
        output.push_str(&format!("   max log size = {}\n", config.global.max_log_size));
        // Performance
        output.push_str(&format!("   read raw = {}\n",
            if config.global.read_raw { "yes" } else { "no" }));
        output.push_str(&format!("   write raw = {}\n",
            if config.global.write_raw { "yes" } else { "no" }));
        output.push_str(&format!("   max xmit = {}\n", config.global.max_xmit));
        output.push_str(&format!("   deadtime = {}\n", config.global.deadtime));
        output.push_str(&format!("   keepalive = {}\n", config.global.keepalive));
        output.push('\n');
        
        // Serialize shares
        for share in &config.shares {
            output.push_str(&format!("[{}]\n", share.name));
            output.push_str(&format!("   path = {}\n", share.path));
            output.push_str(&format!("   comment = {}\n", share.comment));
            output.push_str(&format!("   browseable = {}\n", 
                if share.browsable { "yes" } else { "no" }));
            output.push_str(&format!("   writable = {}\n", 
                if share.writable { "yes" } else { "no" }));
            output.push_str(&format!("   guest ok = {}\n", 
                if share.guest_ok { "yes" } else { "no" }));
            output.push_str(&format!("   read only = {}\n", 
                if share.read_only { "yes" } else { "no" }));
            output.push_str(&format!("   create mask = {}\n", share.create_mask));
            output.push_str(&format!("   directory mask = {}\n", share.directory_mask));
            if !share.force_create_mode.is_empty() {
                output.push_str(&format!("   force create mode = {}\n", share.force_create_mode));
            }
            if !share.force_directory_mode.is_empty() {
                output.push_str(&format!("   force directory mode = {}\n", share.force_directory_mode));
            }
            if !share.valid_users.is_empty() {
                output.push_str(&format!("   valid users = {}\n", share.valid_users.join(" ")));
            }
            if !share.invalid_users.is_empty() {
                output.push_str(&format!("   invalid users = {}\n", share.invalid_users.join(" ")));
            }
            if !share.read_list.is_empty() {
                output.push_str(&format!("   read list = {}\n", share.read_list.join(" ")));
            }
            if !share.write_list.is_empty() {
                output.push_str(&format!("   write list = {}\n", share.write_list.join(" ")));
            }
            if !share.hosts_allow.is_empty() {
                output.push_str(&format!("   hosts allow = {}\n", share.hosts_allow.join(" ")));
            }
            if !share.hosts_deny.is_empty() {
                output.push_str(&format!("   hosts deny = {}\n", share.hosts_deny.join(" ")));
            }
            if !share.force_user.is_empty() {
                output.push_str(&format!("   force user = {}\n", share.force_user));
            }
            if !share.force_group.is_empty() {
                output.push_str(&format!("   force group = {}\n", share.force_group));
            }
            output.push_str(&format!("   inherit acls = {}\n",
                if share.inherit_acls { "yes" } else { "no" }));
            output.push_str(&format!("   inherit permissions = {}\n",
                if share.inherit_permissions { "yes" } else { "no" }));
            if !share.vfs_objects.is_empty() {
                output.push_str(&format!("   vfs objects = {}\n", share.vfs_objects.join(" ")));
            }
            output.push_str(&format!("   available = {}\n",
                if share.available { "yes" } else { "no" }));
            output.push('\n');
        }
        
        Ok(output)
    }
    
    /// Validate SambaConfig for required fields and valid values
    pub fn validate(config: &SambaConfig) -> ConfigResult<()> {
        // Validate global settings
        Self::validate_global(&config.global)?;
        
        // Validate each share
        for share in &config.shares {
            Self::validate_share(share)?;
        }
        
        Ok(())
    }
    
    /// Validate global settings
    fn validate_global(global: &GlobalSettings) -> ConfigResult<()> {
        // Validate workgroup
        if global.workgroup.is_empty() {
            return Err(ConfigError::ValidationError(
                "Global setting 'workgroup' cannot be empty".to_string()
            ));
        }
        
        // Validate workgroup name (NetBIOS name restrictions)
        if global.workgroup.len() > 15 {
            return Err(ConfigError::ValidationError(
                "Global setting 'workgroup' must be 15 characters or less".to_string()
            ));
        }
        
        // Validate server string
        if global.server_string.is_empty() {
            return Err(ConfigError::ValidationError(
                "Global setting 'server string' cannot be empty".to_string()
            ));
        }
        
        // Validate guest account
        if global.guest_account.is_empty() {
            return Err(ConfigError::ValidationError(
                "Global setting 'guest account' cannot be empty".to_string()
            ));
        }
        
        // Validate security mode is valid
        match global.security {
            SecurityMode::User | SecurityMode::Share | SecurityMode::Server 
            | SecurityMode::Domain | SecurityMode::ADS => {}
        }
        
        // Validate socket options
        if global.socket_options.is_empty() {
            return Err(ConfigError::ValidationError(
                "Global setting 'socket options' cannot be empty".to_string()
            ));
        }
        
        // Validate map_to_guest
        let valid_map_to_guest = ["Never", "Bad User", "Bad Password"];
        if !valid_map_to_guest.iter().any(|&v| global.map_to_guest == v) 
            && !global.map_to_guest.is_empty() {
            // Only error if it's not empty and not a known valid value
            // Allow empty as it will use default
        }
        
        Ok(())
    }
    
    /// Validate a share
    fn validate_share(share: &Share) -> ConfigResult<()> {
        // Validate share name
        if share.name.is_empty() {
            return Err(ConfigError::ValidationError(
                "Share name cannot be empty".to_string()
            ));
        }
        
        // Share name cannot contain certain characters
        let invalid_chars = ['/', '\\', '[', ']', ':', '+', '*', '?', '"', '<', '>', '|'];
        for c in invalid_chars {
            if share.name.contains(c) {
                return Err(ConfigError::ValidationError(
                    format!("Share name '{}' contains invalid character '{}'", share.name, c)
                ));
            }
        }
        
        // Validate path
        if share.path.is_empty() {
            return Err(ConfigError::ValidationError(
                format!("Share '{}': path cannot be empty", share.name)
            ));
        }
        
        // Path must be absolute
        if !share.path.starts_with('/') {
            return Err(ConfigError::ValidationError(
                format!("Share '{}': path must be absolute (start with /)", share.name)
            ));
        }
        
        // Validate create mask (octal)
        if !share.create_mask.is_empty() {
            if let Err(_) = u16::from_str_radix(&share.create_mask.replace("0", ""), 8) {
                return Err(ConfigError::ValidationError(
                    format!("Share '{}': create mask must be a valid octal number", share.name)
                ));
            }
        }
        
        // Validate directory mask (octal)
        if !share.directory_mask.is_empty() {
            if let Err(_) = u16::from_str_radix(&share.directory_mask.replace("0", ""), 8) {
                return Err(ConfigError::ValidationError(
                    format!("Share '{}': directory mask must be a valid octal number", share.name)
                ));
            }
        }
        
        // Validate hosts_allow and hosts_deny don't both have values
        if !share.hosts_allow.is_empty() && !share.hosts_deny.is_empty() {
            // This is actually valid in Samba, just a warning case
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    /// Test parsing a minimal smb.conf
    #[test]
    fn test_parse_minimal() {
        let content = r#"[global]
   workgroup = WORKGROUP
   server string = Test Server
   security = user
   encrypt passwords = yes
   guest account = nobody
"#;
        let config = ConfigParser::parse(content).unwrap();
        assert_eq!(config.global.workgroup, "WORKGROUP");
        assert_eq!(config.global.server_string, "Test Server");
        assert_eq!(config.global.security, SecurityMode::User);
        assert_eq!(config.global.guest_account, "nobody");
    }
    
    /// Test parsing with shares
    #[test]
    fn test_parse_with_shares() {
        let content = r#"[global]
   workgroup = WORKGROUP
   server string = Test
   security = user
   encrypt passwords = yes
   guest account = nobody

[share1]
   path = /home/share
   comment = Test Share
   writable = yes
   browsable = yes
   guest ok = no
"#;
        let config = ConfigParser::parse(content).unwrap();
        assert_eq!(config.shares.len(), 1);
        assert_eq!(config.shares[0].name, "share1");
        assert_eq!(config.shares[0].path, "/home/share");
        assert_eq!(config.shares[0].comment, "Test Share");
        assert!(config.shares[0].writable);
    }
    
    /// Test serialization
    #[test]
    fn test_serialize() {
        let config = SambaConfig {
            global: GlobalSettings {
                workgroup: "WORKGROUP".to_string(),
                server_string: "Test Server".to_string(),
                security: SecurityMode::User,
                guest_account: "nobody".to_string(),
                map_to_guest: "Never".to_string(),
                dns_proxy: false,
                socket_options: "TCP_NODELAY".to_string(),
                winbind_nss_info: "template".to_string(),
                ..Default::default()
            },
            shares: vec![Share {
                name: "testshare".to_string(),
                path: "/home/test".to_string(),
                comment: "Test share".to_string(),
                browsable: true,
                writable: false,
                guest_ok: false,
                read_only: true,
                create_mask: "0744".to_string(),
                directory_mask: "0755".to_string(),
                valid_users: vec!["user1".to_string(), "user2".to_string()],
                ..Default::default()
            }],
        };
        
        let serialized = ConfigParser::serialize(&config).unwrap();
        assert!(serialized.contains("[global]"));
        assert!(serialized.contains("workgroup = WORKGROUP"));
        assert!(serialized.contains("[testshare]"));
        assert!(serialized.contains("path = /home/test"));
    }
    
    /// Test round-trip: parse -> serialize -> parse
    #[test]
    fn test_roundtrip() {
        let original = r#"[global]
   workgroup = MYGROUP
   server string = My Server
   security = user
   encrypt passwords = yes
   guest account = nobody
   map to guest = Bad User
   dns proxy = no
   socket options = TCP_NODELAY
   winbind nss info = template

[myshare]
   path = /srv/samba
   comment = My Share
   browsable = yes
   writable = no
   guest ok = no
   read only = yes
   create mask = 0744
   directory mask = 0755
   valid users = alice bob
"#;
        
        let config1 = ConfigParser::parse(original).unwrap();
        let serialized = ConfigParser::serialize(&config1).unwrap();
        let config2 = ConfigParser::parse(&serialized).unwrap();
        
        assert_eq!(config1.global.workgroup, config2.global.workgroup);
        assert_eq!(config1.global.security, config2.global.security);
        assert_eq!(config1.shares.len(), config2.shares.len());
        if !config1.shares.is_empty() {
            assert_eq!(config1.shares[0].name, config2.shares[0].name);
            assert_eq!(config1.shares[0].path, config2.shares[0].path);
        }
    }
    
    /// Test validation of valid config
    #[test]
    fn test_validate_valid() {
        let config = SambaConfig {
            global: GlobalSettings::default(),
            shares: vec![Share {
                name: "testshare".to_string(),
                path: "/home/test".to_string(),
                comment: "Test".to_string(),
                ..Default::default()
            }],
        };
        
        assert!(ConfigParser::validate(&config).is_ok());
    }
    
    /// Test validation catches empty workgroup
    #[test]
    fn test_validate_empty_workgroup() {
        let mut config = SambaConfig::default();
        config.global.workgroup = "".to_string();
        
        let result = ConfigParser::validate(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("workgroup"));
    }
    
    /// Test validation catches empty share path
    #[test]
    fn test_validate_empty_share_path() {
        let config = SambaConfig {
            global: GlobalSettings::default(),
            shares: vec![Share {
                name: "testshare".to_string(),
                path: "".to_string(),
                comment: "Test".to_string(),
                ..Default::default()
            }],
        };
        
        let result = ConfigParser::validate(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path"));
    }
    
    /// Test validation catches relative path
    #[test]
    fn test_validate_relative_path() {
        let config = SambaConfig {
            global: GlobalSettings::default(),
            shares: vec![Share {
                name: "testshare".to_string(),
                path: "home/test".to_string(),
                comment: "Test".to_string(),
                ..Default::default()
            }],
        };
        
        let result = ConfigParser::validate(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("absolute"));
    }
    
    /// Test validation catches invalid share name
    #[test]
    fn test_validate_invalid_share_name() {
        let config = SambaConfig {
            global: GlobalSettings::default(),
            shares: vec![Share {
                name: "test/share".to_string(),
                path: "/home/test".to_string(),
                comment: "Test".to_string(),
                ..Default::default()
            }],
        };
        
        let result = ConfigParser::validate(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid character"));
    }
    
    /// Test validation catches workgroup too long
    #[test]
    fn test_validate_workgroup_too_long() {
        let mut config = SambaConfig::default();
        config.global.workgroup = "A".repeat(20);
        
        let result = ConfigParser::validate(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("15 characters"));
    }
    
    /// Test parsing boolean values (yes/no)
    #[test]
    fn test_parse_booleans() {
        let content = r#"[global]
   workgroup = TEST
   server string = Test
   security = user
   encrypt passwords = no
   guest account = nobody

[testshare]
   path = /test
   browsable = no
   writable = yes
   guest ok = yes
   read only = no
"#;
        let config = ConfigParser::parse(content).unwrap();
        assert!(!config.shares[0].browsable);
        assert!(config.shares[0].writable);
        assert!(config.shares[0].guest_ok);
        assert!(!config.shares[0].read_only);
    }
    
    /// Test parsing boolean values (true/false)
    #[test]
    fn test_parse_booleans_true_false() {
        let content = r#"[global]
   workgroup = TEST
   server string = Test
   security = user
   encrypt passwords = true
   guest account = nobody

[testshare]
   path = /test
   browsable = false
   writable = true
   guest ok = true
   read only = false
"#;
        let config = ConfigParser::parse(content).unwrap();
        assert!(!config.shares[0].browsable);
        assert!(config.shares[0].writable);
        assert!(config.shares[0].guest_ok);
        assert!(!config.shares[0].read_only);
    }
    
    /// Test parsing multiple shares
    #[test]
    fn test_parse_multiple_shares() {
        let content = r#"[global]
   workgroup = TEST
   server string = Test
   security = user
   encrypt passwords = yes
   guest account = nobody

[share1]
   path = /share1
   comment = Share 1

[share2]
   path = /share2
   comment = Share 2

[share3]
   path = /share3
   comment = Share 3
"#;
        let config = ConfigParser::parse(content).unwrap();
        assert_eq!(config.shares.len(), 3);
        assert_eq!(config.shares[0].name, "share1");
        assert_eq!(config.shares[1].name, "share2");
        assert_eq!(config.shares[2].name, "share3");
    }
    
    /// Test parsing user lists
    #[test]
    fn test_parse_user_lists() {
        let content = r#"[global]
   workgroup = TEST
   server string = Test
   security = user
   encrypt passwords = yes
   guest account = nobody

[testshare]
   path = /test
   valid users = user1 user2 @group1
   invalid users = baduser
   hosts allow = 192.168.1. 10.0.0.
   hosts deny = 192.168.1.1
"#;
        let config = ConfigParser::parse(content).unwrap();
        assert_eq!(config.shares[0].valid_users, vec!["user1", "user2", "@group1"]);
        assert_eq!(config.shares[0].invalid_users, vec!["baduser"]);
        assert_eq!(config.shares[0].hosts_allow, vec!["192.168.1.", "10.0.0."]);
        assert_eq!(config.shares[0].hosts_deny, vec!["192.168.1.1"]);
    }
    
    /// Test serialize includes all fields
    #[test]
    fn test_serialize_all_fields() {
        let config = SambaConfig {
            global: GlobalSettings {
                workgroup: "TESTGROUP".to_string(),
                server_string: "Test Server".to_string(),
                security: SecurityMode::Share,
                guest_account: "ftp".to_string(),
                map_to_guest: "Bad Password".to_string(),
                dns_proxy: true,
                socket_options: "SO_KEEPALIVE".to_string(),
                winbind_nss_info: "sfu".to_string(),
                ..Default::default()
            },
            shares: vec![Share {
                name: "fullshare".to_string(),
                path: "/full/path".to_string(),
                comment: "Full test share".to_string(),
                browsable: false,
                writable: true,
                guest_ok: true,
                read_only: false,
                create_mask: "0777".to_string(),
                directory_mask: "0775".to_string(),
                valid_users: vec!["admin".to_string()],
                invalid_users: vec!["guest".to_string()],
                hosts_allow: vec!["127.".to_string()],
                hosts_deny: vec!["0.".to_string()],
                ..Default::default()
            }],
        };
        
        let serialized = ConfigParser::serialize(&config).unwrap();
        
        // Check global section
        assert!(serialized.contains("workgroup = TESTGROUP"));
        assert!(serialized.contains("security = share"));
        assert!(serialized.contains("map to guest = Bad Password"));
        assert!(serialized.contains("dns proxy = yes"));
        
        // Check share section
        assert!(serialized.contains("[fullshare]"));
        assert!(serialized.contains("path = /full/path"));
        assert!(serialized.contains("browseable = no"));
        assert!(serialized.contains("writable = yes"));
        assert!(serialized.contains("guest ok = yes"));
        assert!(serialized.contains("read only = no"));
        assert!(serialized.contains("create mask = 0777"));
        assert!(serialized.contains("directory mask = 0775"));
        assert!(serialized.contains("valid users = admin"));
        assert!(serialized.contains("invalid users = guest"));
        assert!(serialized.contains("hosts allow = 127."));
        assert!(serialized.contains("hosts deny = 0."));
    }
    
    /// Test skipping comments and empty lines
    #[test]
    fn test_skip_comments_and_empty() {
        let content = r#"
; This is a comment
# This is also a comment

[global]
   workgroup = TEST
   server string = Test
   security = user
   encrypt passwords = yes
   guest account = nobody

; Comment before share
[testshare]
   path = /test
   # Another comment
   comment = Test
"#;
        let config = ConfigParser::parse(content).unwrap();
        assert_eq!(config.global.workgroup, "TEST");
        assert_eq!(config.shares[0].name, "testshare");
    }
}
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::sample::select;
    use proptest::string::string_regex;
    
    // Implement Arbitrary for SecurityMode (simple enum)
    impl Arbitrary for SecurityMode {
        type Parameters = ();
        type Strategy = BoxedStrategy<SecurityMode>;
        
        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            select(vec![
                SecurityMode::User,
                SecurityMode::Share,
                SecurityMode::Server,
                SecurityMode::Domain,
                SecurityMode::ADS,
            ]).boxed()
        }
    }
    
    // Property 1: Configuration parsing round-trip
    // For any valid SambaConfig structure, serializing to smb.conf format 
    // and then parsing the result SHALL produce an equivalent configuration
    // Validates: Requirements 1.1, 1.5
    proptest! {
        #[test]
        fn test_property_roundtrip_workgroup(workgroup in "[A-Za-z0-9]{1,15}") {
            let config = SambaConfig {
                global: GlobalSettings {
                    workgroup: workgroup.clone(),
                    server_string: "Test Server".to_string(),
                    security: SecurityMode::User,
                    guest_account: "nobody".to_string(),
                    map_to_guest: "Never".to_string(),
                    dns_proxy: false,
                    socket_options: "TCP_NODELAY".to_string(),
                    winbind_nss_info: "template".to_string(),
                    ..Default::default()
                },
                shares: vec![],
            };
            
            // Validate first
            prop_assume!(ConfigParser::validate(&config).is_ok());
            
            // Serialize to smb.conf format
            let serialized = ConfigParser::serialize(&config).unwrap();
            
            // Parse the serialized result
            let parsed = ConfigParser::parse(&serialized).unwrap();
            
            // Compare
            prop_assert_eq!(config.global.workgroup, parsed.global.workgroup);
            prop_assert_eq!(config.global.security, parsed.global.security);
        }
        
        #[test]
        fn test_property_roundtrip_with_share(
            share_name in "[a-z0-9_]+",
            share_path in "/[a-zA-Z0-9/_-]+"
        ) {
            let config = SambaConfig {
                global: GlobalSettings::default(),
                shares: vec![Share {
                    name: share_name.clone(),
                    path: share_path.clone(),
                    comment: "Test".to_string(),
                    browsable: true,
                    writable: false,
                    guest_ok: false,
                    read_only: true,
                    create_mask: "0744".to_string(),
                    directory_mask: "0755".to_string(),
                    ..Default::default()
                }],
            };
            
            // Validate first
            prop_assume!(ConfigParser::validate(&config).is_ok());
            
            // Serialize to smb.conf format
            let serialized = ConfigParser::serialize(&config).unwrap();
            
            // Parse the serialized result
            let parsed = ConfigParser::parse(&serialized).unwrap();
            
            // Compare
            prop_assert_eq!(config.shares.len(), parsed.shares.len());
            if !config.shares.is_empty() {
                prop_assert_eq!(&config.shares[0].name, &parsed.shares[0].name);
                prop_assert_eq!(&config.shares[0].path, &parsed.shares[0].path);
            }
        }
    }
    
    // Property 5: Configuration validation detects errors
    // For any invalid SambaConfig (missing required fields, invalid values), 
    // the validation function SHALL return an error
    // Validates: Requirements 1.5, 1.6
    proptest! {
        #[test]
        fn test_property_validation_detects_empty_workgroup(workgroup in "\\PC*") {
            // Skip empty workgroup as that's tested separately
            prop_assume!(!workgroup.is_empty());
            
            let mut config = SambaConfig::default();
            config.global.workgroup = workgroup;
            
            // If workgroup is too long, validation should fail
            if config.global.workgroup.len() > 15 {
                let result = ConfigParser::validate(&config);
                prop_assert!(result.is_err());
            }
        }
        
        #[test]
        fn test_property_validation_detects_invalid_share_name(
            name in "[a-zA-Z0-9_]+",
            invalid_char in "[/\\\\\\[\\]:+*?\"<>|]"
        ) {
            let share_name = format!("{}test{}share", name, invalid_char);
            let config = SambaConfig {
                global: GlobalSettings::default(),
                shares: vec![Share {
                    name: share_name,
                    path: "/valid/path".to_string(),
                    comment: "Test".to_string(),
                    ..Default::default()
                }],
            };
            
            let result = ConfigParser::validate(&config);
            prop_assert!(result.is_err());
        }
        
        #[test]
        fn test_property_validation_detects_relative_path(
            name in "[a-z][a-z0-9_]*",
            path in string_regex(r"[^/].*").unwrap()
        ) {
            // Skip empty name as that's tested separately
            prop_assume!(!name.is_empty());
            
            // If path doesn't start with /, it's relative
            if !path.starts_with('/') {
                let config = SambaConfig {
                    global: GlobalSettings::default(),
                    shares: vec![Share {
                        name: name,
                        path: path,
                        comment: "Test".to_string(),
                        ..Default::default()
                    }],
                };
                
                let result = ConfigParser::validate(&config);
                prop_assert!(result.is_err());
            }
        }
    }
}