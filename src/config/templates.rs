#![allow(dead_code)]
//! Template loader — reads server configuration templates from a JSON file.
//!
//! Search order:
//!   1. `$XDG_CONFIG_HOME/samba-gui/templates.json` (user customizations)
//!   2. `/usr/share/samba-gui/templates.json` (system-installed)
//!   3. Bundled fallback compiled into the binary via `include_str!`
//!
//! The JSON file is an array of `TemplateEntry` objects.

use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::models::GlobalSettings;

/// A single template entry as stored in the JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub settings: GlobalSettings,
}

/// Bundled fallback — compiled into the binary so the app always works
/// even if no external file is found.
const BUNDLED_TEMPLATES: &str = include_str!("../../templates.json");

/// Global cache of loaded templates (loaded once on first access).
static TEMPLATES: OnceLock<Vec<TemplateEntry>> = OnceLock::new();

/// Return the list of loaded templates (cached after first call).
pub fn templates() -> &'static [TemplateEntry] {
    TEMPLATES.get_or_init(load_templates)
}

/// Return just the template names (for combo boxes, etc.).
pub fn template_names() -> Vec<&'static str> {
    templates().iter().map(|t| t.name.as_str()).collect()
}

/// Look up a template by name and return a clone of its settings.
/// Falls back to `GlobalSettings::default()` if not found.
pub fn settings_for_template(name: &str) -> GlobalSettings {
    templates()
        .iter()
        .find(|t| t.name == name)
        .map(|t| t.settings.clone())
        .unwrap_or_default()
}

/// Look up a template's description by name.
pub fn description_for_template(name: &str) -> &'static str {
    templates()
        .iter()
        .find(|t| t.name == name)
        .map(|t| t.description.as_str())
        .unwrap_or("")
}

/// Load templates from disk or fall back to the bundled JSON.
fn load_templates() -> Vec<TemplateEntry> {
    // Try user config first, then system path
    let candidates = config_paths();
    for path in &candidates {
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(content) => match serde_json::from_str::<Vec<TemplateEntry>>(&content) {
                    Ok(entries) if !entries.is_empty() => {
                        log::info!("Loaded {} templates from {}", entries.len(), path.display());
                        return entries;
                    }
                    Ok(_) => {
                        log::warn!("Template file {} is empty, using bundled defaults", path.display());
                    }
                    Err(e) => {
                        log::warn!("Failed to parse {}: {}, using bundled defaults", path.display(), e);
                    }
                },
                Err(e) => {
                    log::warn!("Failed to read {}: {}", path.display(), e);
                }
            }
        }
    }

    // Fall back to bundled
    log::info!("Using bundled templates");
    serde_json::from_str(BUNDLED_TEMPLATES).expect("Bundled templates.json is invalid")
}

/// Return candidate paths in priority order.
fn config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // 1. User config: $XDG_CONFIG_HOME/samba-gui/templates.json
    if let Some(config_dir) = dirs_config_home() {
        paths.push(config_dir.join("samba-gui").join("templates.json"));
    }

    // 2. System-installed
    paths.push(PathBuf::from("/usr/share/samba-gui/templates.json"));

    paths
}

/// Get XDG_CONFIG_HOME or default to ~/.config
fn dirs_config_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_templates_parse() {
        let entries: Vec<TemplateEntry> =
            serde_json::from_str(BUNDLED_TEMPLATES).expect("bundled JSON must parse");
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|t| t.name == "Default (Secure)"));
    }

    #[test]
    fn template_names_not_empty() {
        let names = template_names();
        assert!(names.contains(&"Default (Secure)"));
        assert!(names.contains(&"Simple File Server"));
    }

    #[test]
    fn settings_for_unknown_returns_default() {
        let s = settings_for_template("nonexistent");
        assert_eq!(s, GlobalSettings::default());
    }
}
