#![allow(dead_code)]
// Server configuration view module
// Displays global settings and share management

use crate::config::{ConfigParser, SambaConfig};

/// Load configuration from smb.conf file
pub fn load_config(path: &str) -> Result<SambaConfig, String> {
    std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|content| {
            ConfigParser::parse(&content).map_err(|e| e.to_string())
        })
}

/// Save configuration to smb.conf file
pub fn save_config(path: &str, config: &SambaConfig) -> Result<(), String> {
    ConfigParser::validate(config).map_err(|e| e.to_string())?;
    
    let content = ConfigParser::serialize(config).map_err(|e| e.to_string())?;
    
    std::fs::write(path, content).map_err(|e| e.to_string())
}

#[cfg(feature = "gui")]
pub mod gui_impl {
    use super::*;
    use adw::{EntryRow, ActionRow, PreferencesGroup};
    use gtk::{Label, Button, Orientation, Align};
    use adw::prelude::*;

    /// Server configuration view widget
pub struct ServerConfigView {
        pub container: gtk::Box,
        config: SambaConfig,
    }

impl ServerConfigView {
        /// Create a new server configuration view
        pub fn new() -> Self {
            let container = gtk::Box::builder()
                .orientation(Orientation::Vertical)
                .margin_start(24)
                .margin_end(24)
                .margin_top(24)
                .margin_bottom(24)
                .spacing(16)
                .build();

            let config = load_config("/etc/samba/smb.conf")
                .or_else(|_| load_config("/etc/smb.conf"))
                .unwrap_or_default();

            Self { container, config }
        }

        /// Build the UI with global settings and shares
        pub fn build_ui(&mut self) {
            // Title
            let title = Label::builder()
                .label("Server Configuration")
                .css_classes(["title-1"])
                .halign(Align::Start)
                .build();
            self.container.append(&title);

            // Global settings group
            let global_group = PreferencesGroup::builder()
                .title("Global Settings")
                .build();

            // Workgroup
            let workgroup_row = EntryRow::builder()
                .title("Workgroup")
                .text(&self.config.global.workgroup)
                .tooltip_text("The Windows workgroup or domain this server belongs to. Clients must use the same workgroup to browse this server.")
                .build();
            global_group.add(&workgroup_row);

            // Server string
            let server_string_row = EntryRow::builder()
                .title("Server String")
                .text(&self.config.global.server_string)
                .tooltip_text("A descriptive string shown to clients when browsing the network. Use %h for hostname, %v for Samba version.")
                .build();
            global_group.add(&server_string_row);

            self.container.append(&global_group);

            // Shares group
            let shares_group = PreferencesGroup::builder()
                .title("Shares")
                .build();

            // Add share button
            let add_button = Button::builder()
                .label("Add Share")
                .css_classes(["flat", "suggested-action"])
                .build();
            
            add_button.connect_clicked(|_button| {
                println!("Add share clicked");
            });
            
            shares_group.add(&add_button);

            // List existing shares
            for share in &self.config.shares {
                let share_row = ActionRow::builder()
                    .title(&share.name)
                    .subtitle(&share.path)
                    .build();
                shares_group.add(&share_row);
            }

            self.container.append(&shares_group);
        }
    }

    impl Default for ServerConfigView {
        fn default() -> Self {
            Self::new()
        }
    }
}