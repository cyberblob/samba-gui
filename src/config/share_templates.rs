#![allow(dead_code)]
//! Share-level templates for quick-adding common share configurations.
//!
//! These are hardcoded presets (no external JSON file needed) that provide
//! sensible defaults for common use cases.

use super::models::Share;

/// A share template definition.
#[derive(Debug, Clone)]
pub struct ShareTemplate {
    pub name: &'static str,
    pub description: &'static str,
    pub share: Share,
}

/// Return all available share templates.
pub fn share_templates() -> Vec<ShareTemplate> {
    vec![
        ShareTemplate {
            name: "Public Read-Only",
            description: "A browsable share anyone can read but nobody can write to",
            share: Share {
                name: "public".to_string(),
                path: "/srv/samba/public".to_string(),
                comment: "Public read-only share".to_string(),
                browsable: true,
                writable: false,
                guest_ok: true,
                read_only: true,
                create_mask: "0644".to_string(),
                directory_mask: "0755".to_string(),
                available: true,
                ..Share::default()
            },
        },
        ShareTemplate {
            name: "Private Home Directory",
            description: "Per-user home directory, only the owner can access",
            share: Share {
                name: "home".to_string(),
                path: "/home/%U".to_string(),
                comment: "Home directory for %U".to_string(),
                browsable: false,
                writable: true,
                guest_ok: false,
                read_only: false,
                create_mask: "0600".to_string(),
                directory_mask: "0700".to_string(),
                valid_users: vec!["%U".to_string()],
                available: true,
                ..Share::default()
            },
        },
        ShareTemplate {
            name: "Team Shared Folder",
            description: "Read/write share for a specific group with group-writable permissions",
            share: Share {
                name: "team".to_string(),
                path: "/srv/samba/team".to_string(),
                comment: "Team shared folder".to_string(),
                browsable: true,
                writable: true,
                guest_ok: false,
                read_only: false,
                create_mask: "0664".to_string(),
                directory_mask: "0775".to_string(),
                force_create_mode: "0664".to_string(),
                force_directory_mode: "0775".to_string(),
                valid_users: vec!["@team".to_string()],
                force_group: "team".to_string(),
                inherit_permissions: true,
                available: true,
                ..Share::default()
            },
        },
        ShareTemplate {
            name: "Media Server (Read-Only)",
            description: "Guest-accessible media share, read-only with optimized settings",
            share: Share {
                name: "media".to_string(),
                path: "/srv/media".to_string(),
                comment: "Media library".to_string(),
                browsable: true,
                writable: false,
                guest_ok: true,
                read_only: true,
                create_mask: "0644".to_string(),
                directory_mask: "0755".to_string(),
                available: true,
                ..Share::default()
            },
        },
        ShareTemplate {
            name: "Drop Box (Write-Only)",
            description: "Users can write files but cannot read or list existing content",
            share: Share {
                name: "dropbox".to_string(),
                path: "/srv/samba/dropbox".to_string(),
                comment: "Write-only drop box".to_string(),
                browsable: true,
                writable: true,
                guest_ok: false,
                read_only: false,
                create_mask: "0660".to_string(),
                directory_mask: "0770".to_string(),
                force_create_mode: "0660".to_string(),
                force_directory_mode: "0770".to_string(),
                available: true,
                ..Share::default()
            },
        },
        ShareTemplate {
            name: "Time Machine Backup",
            description: "macOS Time Machine compatible backup share with VFS fruit",
            share: Share {
                name: "timemachine".to_string(),
                path: "/srv/samba/timemachine".to_string(),
                comment: "Time Machine backup".to_string(),
                browsable: true,
                writable: true,
                guest_ok: false,
                read_only: false,
                create_mask: "0600".to_string(),
                directory_mask: "0700".to_string(),
                vfs_objects: vec!["catia".to_string(), "fruit".to_string(), "streams_xattr".to_string()],
                available: true,
                ..Share::default()
            },
        },
        ShareTemplate {
            name: "Print Spool",
            description: "Printer spool directory for shared printing",
            share: Share {
                name: "printers".to_string(),
                path: "/var/spool/samba".to_string(),
                comment: "All Printers".to_string(),
                browsable: false,
                writable: true,
                guest_ok: false,
                read_only: false,
                create_mask: "0700".to_string(),
                directory_mask: "0700".to_string(),
                available: true,
                ..Share::default()
            },
        },
    ]
}

/// Return just the template names for combo boxes.
pub fn share_template_names() -> Vec<&'static str> {
    share_templates().iter().map(|t| t.name).collect()
}

/// Look up a share template by name and return a clone of its Share.
/// Returns None if not found.
pub fn share_from_template(name: &str) -> Option<Share> {
    share_templates()
        .into_iter()
        .find(|t| t.name == name)
        .map(|t| t.share)
}

/// Look up a share template's description by name.
pub fn share_template_description(name: &str) -> &'static str {
    // We need to return a &'static str, so we match against known names
    share_templates()
        .iter()
        .find(|t| t.name == name)
        .map(|t| t.description)
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_templates_not_empty() {
        let templates = share_templates();
        assert!(!templates.is_empty());
        assert!(templates.len() >= 5);
    }

    #[test]
    fn test_share_template_names() {
        let names = share_template_names();
        assert!(names.contains(&"Public Read-Only"));
        assert!(names.contains(&"Private Home Directory"));
        assert!(names.contains(&"Team Shared Folder"));
    }

    #[test]
    fn test_share_from_template_found() {
        let share = share_from_template("Public Read-Only");
        assert!(share.is_some());
        let share = share.unwrap();
        assert_eq!(share.name, "public");
        assert!(share.guest_ok);
        assert!(share.read_only);
    }

    #[test]
    fn test_share_from_template_not_found() {
        let share = share_from_template("nonexistent");
        assert!(share.is_none());
    }

    #[test]
    fn test_time_machine_has_vfs_objects() {
        let share = share_from_template("Time Machine Backup").unwrap();
        assert!(share.vfs_objects.contains(&"fruit".to_string()));
        assert!(share.vfs_objects.contains(&"catia".to_string()));
    }
}
