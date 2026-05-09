#![allow(dead_code)]
//! Network scanner for discovering SMB/CIFS shares on the local network.
//!
//! Uses multiple discovery methods:
//! 1. `avahi-browse` for mDNS/DNS-SD service discovery (_smb._tcp)
//! 2. `smbclient -L` to list shares on a discovered host
//! 3. `nmblookup` for NetBIOS name resolution
//!
//! All operations are designed to run in background threads.

use std::process::Command;
use thiserror::Error;

/// Errors from network scanning operations.
#[derive(Error, Debug, Clone)]
pub enum ScanError {
    #[error("Command execution failed: {0}")]
    CommandExecution(String),

    #[error("No discovery tools available (install avahi-utils or samba-common-bin)")]
    NoToolsAvailable,

    #[error("Scan timed out")]
    Timeout,

    #[error("Parse error: {0}")]
    ParseError(String),
}

pub type ScanResult<T> = Result<T, ScanError>;

/// A discovered SMB host on the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredHost {
    /// Hostname or IP address
    pub address: String,
    /// NetBIOS name (if available)
    pub netbios_name: String,
    /// How it was discovered
    pub source: DiscoverySource,
}

/// A discovered share on a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredShare {
    /// The host this share is on
    pub host: String,
    /// Share name
    pub name: String,
    /// Share type (Disk, Printer, IPC)
    pub share_type: String,
    /// Comment/description
    pub comment: String,
}

impl DiscoveredShare {
    /// Return the full UNC path for this share (e.g. //server/share)
    pub fn unc_path(&self) -> String {
        format!("//{}/{}", self.host, self.name)
    }
}

/// How a host was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    Avahi,
    Nmblookup,
    Manual,
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoverySource::Avahi => write!(f, "mDNS"),
            DiscoverySource::Nmblookup => write!(f, "NetBIOS"),
            DiscoverySource::Manual => write!(f, "manual"),
        }
    }
}

/// Network scanner for SMB shares.
pub struct NetworkScanner;

impl NetworkScanner {
    /// Discover SMB hosts on the local network.
    /// Tries avahi-browse first, falls back to nmblookup.
    /// Returns a list of discovered hosts.
    pub fn discover_hosts() -> ScanResult<Vec<DiscoveredHost>> {
        let mut hosts = Vec::new();

        // Try avahi-browse first (mDNS/DNS-SD)
        if let Ok(avahi_hosts) = Self::discover_via_avahi() {
            hosts.extend(avahi_hosts);
        }

        // Also try nmblookup for NetBIOS discovery
        if let Ok(nmb_hosts) = Self::discover_via_nmblookup() {
            // Merge, avoiding duplicates by address
            for host in nmb_hosts {
                if !hosts.iter().any(|h: &DiscoveredHost| h.address == host.address) {
                    hosts.push(host);
                }
            }
        }

        if hosts.is_empty() {
            // Check if any tools are available at all
            let has_avahi = Command::new("which").arg("avahi-browse")
                .output().map(|o| o.status.success()).unwrap_or(false);
            let has_nmblookup = Command::new("which").arg("nmblookup")
                .output().map(|o| o.status.success()).unwrap_or(false);
            let has_smbclient = Command::new("which").arg("smbclient")
                .output().map(|o| o.status.success()).unwrap_or(false);

            if !has_avahi && !has_nmblookup && !has_smbclient {
                return Err(ScanError::NoToolsAvailable);
            }
        }

        Ok(hosts)
    }

    /// List shares on a specific host using smbclient.
    /// Tries multiple authentication strategies:
    /// 1. Anonymous/no-password access
    /// 2. Kerberos ticket (if available)
    /// 3. Local config via testparm (if host is the local machine)
    pub fn list_shares(host: &str) -> ScanResult<Vec<DiscoveredShare>> {
        // Strategy 1: Try anonymous/guest access with machine-readable output
        let shares = Self::try_smbclient_list(host, &["-N", "--no-pass"]);
        if !shares.is_empty() {
            return Ok(shares);
        }

        // Strategy 2: Try with Kerberos authentication
        let shares = Self::try_smbclient_list(host, &["-k", "-N"]);
        if !shares.is_empty() {
            return Ok(shares);
        }

        // Strategy 3: Try with empty username/password (-U%)
        let shares = Self::try_smbclient_list(host, &["-U%"]);
        if !shares.is_empty() {
            return Ok(shares);
        }

        // Strategy 4: If the host is the local machine, read shares from testparm
        if Self::is_local_host(host) {
            log::debug!("Host {} appears to be local, trying testparm fallback", host);
            let shares = Self::list_shares_from_testparm(host);
            if !shares.is_empty() {
                return Ok(shares);
            }
        }

        // All strategies failed — return empty (not an error, host may just require auth)
        log::debug!("All share listing strategies failed for {}", host);
        Ok(Vec::new())
    }

    /// Attempt to list shares using smbclient with the given extra arguments.
    fn try_smbclient_list(host: &str, extra_args: &[&str]) -> Vec<DiscoveredShare> {
        let mut args = vec!["-L", host];
        args.extend_from_slice(extra_args);

        let output = match Command::new("smbclient").args(&args).output() {
            Ok(o) => o,
            Err(e) => {
                log::debug!("smbclient {:?} failed to execute: {}", args, e);
                return Vec::new();
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{}\n{}", stdout, stderr);

        let shares = Self::parse_smbclient_output(&combined, host);
        if shares.is_empty() && !output.status.success() {
            log::debug!("smbclient -L {} {:?} failed: {}", host, extra_args, stderr.trim());
        }
        shares
    }

    /// Check if a host refers to the local machine.
    fn is_local_host(host: &str) -> bool {
        let host_lower = host.to_lowercase();

        // Obvious localhost aliases
        if host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "::1" {
            return true;
        }

        // Check against local hostname
        if let Ok(output) = Command::new("hostname").output() {
            let hostname = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
            if host_lower == hostname || host_lower == format!("{}.local", hostname) {
                return true;
            }
        }

        // Check against local IP addresses
        if let Ok(output) = Command::new("hostname").arg("-I").output() {
            let ips = String::from_utf8_lossy(&output.stdout);
            for ip in ips.split_whitespace() {
                if host_lower == ip {
                    return true;
                }
            }
        }

        false
    }

    /// List shares from the local samba configuration using testparm.
    /// This works even when anonymous access is restricted because it reads
    /// the config file directly rather than connecting over the network.
    fn list_shares_from_testparm(host: &str) -> Vec<DiscoveredShare> {
        let output = match Command::new("testparm").args(["-s"]).output() {
            Ok(o) => o,
            Err(e) => {
                log::debug!("testparm failed: {}", e);
                return Vec::new();
            }
        };

        if !output.status.success() {
            return Vec::new();
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_testparm_shares(&stdout, host)
    }

    /// Parse testparm -s output to extract share definitions.
    /// Format:
    /// ```
    /// [ShareName]
    ///     comment = Some comment
    ///     path = /some/path
    ///     browseable = Yes
    ///     ...
    /// ```
    fn parse_testparm_shares(output: &str, host: &str) -> Vec<DiscoveredShare> {
        let mut shares = Vec::new();
        let mut current_name: Option<String> = None;
        let mut current_comment = String::new();
        let mut current_browseable = true;
        let mut current_printable = false;
        let mut current_available = true;

        for line in output.lines() {
            let trimmed = line.trim();

            // Detect section headers [name]
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                // Save previous share if any
                if let Some(name) = current_name.take() {
                    if name != "global" && current_browseable && current_available {
                        let share_type = if current_printable {
                            "Printer".to_string()
                        } else {
                            "Disk".to_string()
                        };
                        shares.push(DiscoveredShare {
                            host: host.to_string(),
                            name,
                            share_type,
                            comment: current_comment.clone(),
                        });
                    }
                }

                // Start new section
                let section_name = trimmed[1..trimmed.len() - 1].to_string();
                current_name = Some(section_name);
                current_comment = String::new();
                current_browseable = true;
                current_printable = false;
                current_available = true;
                continue;
            }

            // Parse key = value pairs within a section
            if current_name.is_some() {
                if let Some((key, value)) = trimmed.split_once('=') {
                    let key = key.trim().to_lowercase();
                    let value = value.trim();

                    match key.as_str() {
                        "comment" => current_comment = value.to_string(),
                        "browseable" | "browsable" => {
                            current_browseable = value.eq_ignore_ascii_case("yes")
                                || value.eq_ignore_ascii_case("true");
                        }
                        "printable" | "print ok" => {
                            current_printable = value.eq_ignore_ascii_case("yes")
                                || value.eq_ignore_ascii_case("true");
                        }
                        "available" => {
                            current_available = value.eq_ignore_ascii_case("yes")
                                || value.eq_ignore_ascii_case("true");
                        }
                        _ => {}
                    }
                }
            }
        }

        // Don't forget the last section
        if let Some(name) = current_name {
            if name != "global" && current_browseable && current_available {
                let share_type = if current_printable {
                    "Printer".to_string()
                } else {
                    "Disk".to_string()
                };
                shares.push(DiscoveredShare {
                    host: host.to_string(),
                    name,
                    share_type,
                    comment: current_comment,
                });
            }
        }

        // Filter out hidden shares (ending with $) and IPC$
        shares.retain(|s| !s.name.ends_with('$') && s.name != "IPC$");

        shares
    }

    /// Discover hosts via avahi-browse (mDNS/DNS-SD).
    /// Looks for _smb._tcp services.
    fn discover_via_avahi() -> ScanResult<Vec<DiscoveredHost>> {
        let output = Command::new("avahi-browse")
            .args(["-t", "-r", "-p", "_smb._tcp"])
            .output()
            .map_err(|e| ScanError::CommandExecution(format!("avahi-browse: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandExecution(
                "avahi-browse returned non-zero".into(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let hosts = Self::parse_avahi_output(&stdout);
        Ok(hosts)
    }

    /// Parse avahi-browse parseable output (-p flag).
    /// Format: =;interface;protocol;name;type;domain;hostname;address;port;txt
    fn parse_avahi_output(output: &str) -> Vec<DiscoveredHost> {
        let mut hosts = Vec::new();
        let mut seen_addresses = std::collections::HashSet::new();

        for line in output.lines() {
            // Only process resolved entries (start with '=')
            if !line.starts_with('=') {
                continue;
            }

            let fields: Vec<&str> = line.split(';').collect();
            if fields.len() < 8 {
                continue;
            }

            let name = fields[3];
            let hostname = fields[6].trim_end_matches('.');
            let address = fields[7];

            // Skip link-local IPv6 and empty addresses
            if address.is_empty() || address.starts_with("fe80") {
                continue;
            }

            // Prefer hostname over IP, but use IP if hostname is empty
            let addr = if !hostname.is_empty() {
                hostname.to_string()
            } else {
                address.to_string()
            };

            if seen_addresses.contains(&addr) {
                continue;
            }
            seen_addresses.insert(addr.clone());

            hosts.push(DiscoveredHost {
                address: addr,
                netbios_name: name.to_string(),
                source: DiscoverySource::Avahi,
            });
        }

        hosts
    }

    /// Discover hosts via nmblookup (NetBIOS broadcast).
    fn discover_via_nmblookup() -> ScanResult<Vec<DiscoveredHost>> {
        // Broadcast query for workgroup members
        let output = Command::new("nmblookup")
            .args(["-S", "__SAMBA__"])
            .output()
            .or_else(|_| {
                // Try a broader query
                Command::new("nmblookup")
                    .args(["-S", "*"])
                    .output()
            })
            .map_err(|e| ScanError::CommandExecution(format!("nmblookup: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let hosts = Self::parse_nmblookup_output(&stdout);
        Ok(hosts)
    }

    /// Parse nmblookup output.
    /// Format: "IP_ADDRESS HOSTNAME<XX>"
    fn parse_nmblookup_output(output: &str) -> Vec<DiscoveredHost> {
        let mut hosts = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for line in output.lines() {
            let line = line.trim();
            // Skip empty lines and error messages
            if line.is_empty() || line.starts_with("querying") || line.starts_with("name_query") {
                continue;
            }

            // Format: "192.168.1.10 SERVER<20>"
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() < 2 {
                continue;
            }

            let ip = parts[0].trim();
            let name_part = parts[1].trim();

            // Validate IP-like format
            if !ip.contains('.') && !ip.contains(':') {
                continue;
            }

            // Extract name before the <XX> suffix
            let netbios_name = if let Some(bracket_pos) = name_part.find('<') {
                name_part[..bracket_pos].trim().to_string()
            } else {
                name_part.to_string()
            };

            if seen.contains(ip) {
                continue;
            }
            seen.insert(ip.to_string());

            hosts.push(DiscoveredHost {
                address: ip.to_string(),
                netbios_name,
                source: DiscoverySource::Nmblookup,
            });
        }

        hosts
    }

    /// Parse smbclient -L output to extract share names.
    /// The output format varies but typically looks like:
    /// ```
    ///     Sharename       Type      Comment
    ///     ---------       ----      -------
    ///     public          Disk      Public share
    ///     IPC$            IPC       IPC Service
    /// ```
    fn parse_smbclient_output(output: &str, host: &str) -> Vec<DiscoveredShare> {
        let mut shares = Vec::new();
        let mut in_share_section = false;
        let mut past_header_line = false;

        for line in output.lines() {
            let trimmed = line.trim();

            // Detect the share list header
            if trimmed.starts_with("Sharename") && trimmed.contains("Type") {
                in_share_section = true;
                past_header_line = false;
                continue;
            }

            // Skip the separator line (------)
            if in_share_section && !past_header_line {
                if trimmed.starts_with('-') || trimmed.starts_with('—') {
                    past_header_line = true;
                    continue;
                }
            }

            // End of share section (empty line or new section header)
            if in_share_section && past_header_line {
                if trimmed.is_empty() || trimmed.starts_with("Server") || trimmed.starts_with("Workgroup") {
                    in_share_section = false;
                    continue;
                }

                // Parse share line — columns are roughly fixed-width
                // Try splitting by multiple spaces
                if let Some(share) = Self::parse_share_line(trimmed, host) {
                    // Skip IPC$ and hidden shares (ending with $) unless they're useful
                    if share.name != "IPC$" && !share.name.ends_with('$') {
                        shares.push(share);
                    }
                }
            }
        }

        shares
    }

    /// Parse a single share line from smbclient output.
    fn parse_share_line(line: &str, host: &str) -> Option<DiscoveredShare> {
        // The format is roughly: "name    Type    Comment"
        // Split by 2+ whitespace characters
        let parts: Vec<&str> = line.splitn(3, |c: char| c == '\t')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        if parts.len() >= 2 {
            return Some(DiscoveredShare {
                host: host.to_string(),
                name: parts[0].to_string(),
                share_type: parts[1].to_string(),
                comment: parts.get(2).unwrap_or(&"").to_string(),
            });
        }

        // Try splitting by multiple spaces
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0].to_string();
            let share_type = parts[1].to_string();
            let comment = if parts.len() > 2 {
                parts[2..].join(" ")
            } else {
                String::new()
            };

            return Some(DiscoveredShare {
                host: host.to_string(),
                name,
                share_type,
                comment,
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_avahi_output_basic() {
        let output = "=;eth0;IPv4;fileserver;_smb._tcp;local;fileserver.local;192.168.1.10;445;\n";
        let hosts = NetworkScanner::parse_avahi_output(output);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].address, "fileserver.local");
        assert_eq!(hosts[0].netbios_name, "fileserver");
        assert_eq!(hosts[0].source, DiscoverySource::Avahi);
    }

    #[test]
    fn test_parse_avahi_output_skips_ipv6_link_local() {
        let output = "=;eth0;IPv6;server;_smb._tcp;local;server.local;fe80::1;445;\n";
        let hosts = NetworkScanner::parse_avahi_output(output);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_parse_avahi_output_deduplicates() {
        let output = "=;eth0;IPv4;server;_smb._tcp;local;server.local;192.168.1.10;445;\n\
                      =;wlan0;IPv4;server;_smb._tcp;local;server.local;192.168.1.10;445;\n";
        let hosts = NetworkScanner::parse_avahi_output(output);
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn test_parse_avahi_output_ignores_non_resolved() {
        let output = "+;eth0;IPv4;server;_smb._tcp;local\n\
                      =;eth0;IPv4;server;_smb._tcp;local;server.local;192.168.1.10;445;\n";
        let hosts = NetworkScanner::parse_avahi_output(output);
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn test_parse_nmblookup_output() {
        let output = "querying __SAMBA__ on 192.168.1.255\n\
                      192.168.1.10 SERVER<20>\n\
                      192.168.1.11 NAS<20>\n";
        let hosts = NetworkScanner::parse_nmblookup_output(output);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].address, "192.168.1.10");
        assert_eq!(hosts[0].netbios_name, "SERVER");
        assert_eq!(hosts[1].address, "192.168.1.11");
        assert_eq!(hosts[1].netbios_name, "NAS");
    }

    #[test]
    fn test_parse_nmblookup_deduplicates() {
        let output = "192.168.1.10 SERVER<00>\n\
                      192.168.1.10 SERVER<20>\n";
        let hosts = NetworkScanner::parse_nmblookup_output(output);
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn test_parse_smbclient_output() {
        let output = "\tSharename       Type      Comment\n\
                      \t---------       ----      -------\n\
                      \tpublic          Disk      Public files\n\
                      \tprinters        Printer   All printers\n\
                      \tIPC$            IPC       IPC Service\n\
                      \n\
                      Server               Comment\n";
        let shares = NetworkScanner::parse_smbclient_output(output, "server");
        assert_eq!(shares.len(), 2); // IPC$ is filtered out
        assert_eq!(shares[0].name, "public");
        assert_eq!(shares[0].share_type, "Disk");
        assert_eq!(shares[0].comment, "Public files");
        assert_eq!(shares[0].host, "server");
        assert_eq!(shares[1].name, "printers");
    }

    #[test]
    fn test_parse_smbclient_output_empty() {
        let output = "Connection to server failed\n";
        let shares = NetworkScanner::parse_smbclient_output(output, "server");
        assert!(shares.is_empty());
    }

    #[test]
    fn test_discovered_share_unc_path() {
        let share = DiscoveredShare {
            host: "fileserver".to_string(),
            name: "documents".to_string(),
            share_type: "Disk".to_string(),
            comment: String::new(),
        };
        assert_eq!(share.unc_path(), "//fileserver/documents");
    }

    #[test]
    fn test_parse_smbclient_filters_hidden_shares() {
        let output = "\tSharename       Type      Comment\n\
                      \t---------       ----      -------\n\
                      \tpublic          Disk      Public\n\
                      \tADMIN$          Disk      Admin share\n\
                      \tC$              Disk      Default share\n";
        let shares = NetworkScanner::parse_smbclient_output(output, "server");
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "public");
    }

    #[test]
    fn test_parse_testparm_shares_basic() {
        let output = "[global]\n\
                      \tworkgroup = WORKGROUP\n\
                      \n\
                      [Test]\n\
                      \tcomment = Testing\n\
                      \tpath = /home/user\n\
                      \tguest ok = Yes\n\
                      \tread only = No\n";
        let shares = NetworkScanner::parse_testparm_shares(output, "localhost");
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "Test");
        assert_eq!(shares[0].comment, "Testing");
        assert_eq!(shares[0].share_type, "Disk");
        assert_eq!(shares[0].host, "localhost");
    }

    #[test]
    fn test_parse_testparm_shares_skips_non_browseable() {
        let output = "[global]\n\
                      \tworkgroup = WORKGROUP\n\
                      \n\
                      [visible]\n\
                      \tcomment = Visible share\n\
                      \tpath = /srv/visible\n\
                      \n\
                      [hidden]\n\
                      \tcomment = Hidden share\n\
                      \tpath = /srv/hidden\n\
                      \tbrowseable = No\n";
        let shares = NetworkScanner::parse_testparm_shares(output, "localhost");
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "visible");
    }

    #[test]
    fn test_parse_testparm_shares_detects_printers() {
        let output = "[printers]\n\
                      \tcomment = All Printers\n\
                      \tpath = /var/tmp\n\
                      \tprintable = Yes\n\
                      \tbrowseable = No\n\
                      \n\
                      [public]\n\
                      \tcomment = Public files\n\
                      \tpath = /srv/public\n";
        let shares = NetworkScanner::parse_testparm_shares(output, "localhost");
        // printers is not browseable, so only public shows
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "public");
        assert_eq!(shares[0].share_type, "Disk");
    }

    #[test]
    fn test_parse_testparm_shares_filters_dollar_shares() {
        let output = "[public]\n\
                      \tpath = /srv/public\n\
                      \n\
                      [print$]\n\
                      \tpath = /var/lib/samba/printers\n";
        let shares = NetworkScanner::parse_testparm_shares(output, "localhost");
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "public");
    }

    #[test]
    fn test_parse_testparm_shares_skips_unavailable() {
        let output = "[available_share]\n\
                      \tpath = /srv/available\n\
                      \tavailable = Yes\n\
                      \n\
                      [disabled_share]\n\
                      \tpath = /srv/disabled\n\
                      \tavailable = No\n";
        let shares = NetworkScanner::parse_testparm_shares(output, "localhost");
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "available_share");
    }

    #[test]
    fn test_is_local_host_obvious() {
        assert!(NetworkScanner::is_local_host("localhost"));
        assert!(NetworkScanner::is_local_host("127.0.0.1"));
        assert!(NetworkScanner::is_local_host("::1"));
        assert!(NetworkScanner::is_local_host("LOCALHOST"));
    }
}
