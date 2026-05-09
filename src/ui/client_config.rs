#![allow(dead_code)]
// Client configuration view module
// Displays and manages SMB/CIFS mounts via systemd .mount / .automount units

use crate::config::SystemdMountEntry;
use crate::services::SystemdMountManager;

/// Load systemd CIFS mount entries
pub fn load_mounts() -> Result<Vec<SystemdMountEntry>, String> {
    SystemdMountManager::new().list_mounts().map_err(|e| e.to_string())
}

#[cfg(feature = "gui")]
pub mod gui_impl {
    use super::*;
    use adw::{ActionRow, PreferencesGroup, NavigationPage};
    use gtk::{Box, Label, Button, Orientation, Align};
    use adw::prelude::*;

    /// Client configuration view widget
    pub struct ClientConfigView {
        pub container: Box,
        mounts: Vec<SystemdMountEntry>,
        mount_manager: SystemdMountManager,
        mounts_wrapper: std::rc::Rc<Box>,
    }

    impl ClientConfigView {
        /// Create a new client configuration view
        pub fn new() -> Self {
            let container = Box::builder()
                .orientation(Orientation::Vertical)
                .margin_start(24)
                .margin_end(24)
                .margin_top(24)
                .margin_bottom(24)
                .spacing(16)
                .build();

            let mount_manager = SystemdMountManager::new();
            let mounts = mount_manager.list_mounts().unwrap_or_default();
            let mounts_wrapper = std::rc::Rc::new(Box::builder()
                .orientation(Orientation::Vertical)
                .build());

            Self {
                container,
                mounts,
                mount_manager,
                mounts_wrapper,
            }
        }

        /// Build the UI
        pub fn build_ui(&mut self) {
            let title = Label::builder()
                .label("Client Configuration")
                .css_classes(["title-1"])
                .halign(Align::Start)
                .build();
            self.container.append(&title);

            let desc = Label::builder()
                .label("Manage SMB/CIFS mounts (systemd mount units)")
                .css_classes(["body"])
                .halign(Align::Start)
                .build();
            self.container.append(&desc);

            let group = build_mounts_group(&self.mounts_wrapper);
            self.mounts_wrapper.append(&group);
            self.container.append(self.mounts_wrapper.as_ref());

            let add_button = Button::builder()
                .label("Add Mount")
                .css_classes(["flat", "suggested-action"])
                .build();

            let wrapper_ref = self.mounts_wrapper.clone();
            add_button.connect_clicked(move |btn| {
                use crate::ui::mount_wizard::wizard_ui::MountWizard;
                let wizard = MountWizard::new();
                if let Some(root) = btn.root() {
                    if let Ok(win) = root.downcast::<gtk::Window>() {
                        wizard.set_transient_for(&win);
                    }
                }
                let w = wrapper_ref.clone();
                wizard.set_on_complete(move || {
                    refresh_mounts(&w);
                });
                wizard.present();
            });

            self.container.append(&add_button);
        }
    }

    /// Build a fresh PreferencesGroup with the current CIFS mounts
    fn build_mounts_group(wrapper: &std::rc::Rc<Box>) -> PreferencesGroup {
        let group = PreferencesGroup::builder()
            .title("Mounted Shares")
            .build();

        let mount_manager = SystemdMountManager::new();
        let mounts = mount_manager.list_mounts().unwrap_or_default();

        if mounts.is_empty() {
            let empty_row = ActionRow::builder()
                .title("No SMB/CIFS mounts")
                .subtitle("Click 'Add Mount' to add a new mount")
                .build();
            group.add(&empty_row);
        } else {
            for mount in &mounts {
                let options_str = mount.options.join(",");
                let subtitle = format!("{} ({})", mount.device, options_str);
                let mount_row = ActionRow::builder()
                    .title(&mount.mount_point)
                    .subtitle(&subtitle)
                    .build();
                let _ = wrapper; // available for future edit/delete buttons
                group.add(&mount_row);
            }
        }
        group
    }

    /// Replace the PreferencesGroup inside the wrapper Box
    fn refresh_mounts(wrapper: &std::rc::Rc<Box>) {
        while let Some(child) = wrapper.first_child() {
            wrapper.remove(&child);
        }
        let group = build_mounts_group(wrapper);
        wrapper.append(&group);
    }

    impl Default for ClientConfigView {
        fn default() -> Self {
            Self::new()
        }
    }

    pub fn create_client_config_page() -> NavigationPage {
        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(24)
            .margin_end(24)
            .margin_top(24)
            .margin_bottom(24)
            .spacing(16)
            .build();

        let title = Label::builder()
            .label("Client Configuration")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        let desc = Label::builder()
            .label("Manage SMB/CIFS mounts (systemd mount units)")
            .css_classes(["body"])
            .halign(Align::Start)
            .build();
        content.append(&desc);

        let mounts_wrapper = std::rc::Rc::new(Box::builder()
            .orientation(Orientation::Vertical)
            .build());

        let group = build_mounts_group(&mounts_wrapper);
        mounts_wrapper.append(&group);
        content.append(mounts_wrapper.as_ref());

        let add_button = Button::builder()
            .label("Add Mount")
            .css_classes(["flat", "suggested-action"])
            .build();

        let wrapper_for_btn = mounts_wrapper.clone();
        add_button.connect_clicked(move |btn| {
            use crate::ui::mount_wizard::wizard_ui::MountWizard;
            let wizard = MountWizard::new();
            if let Some(root) = btn.root() {
                if let Ok(win) = root.downcast::<gtk::Window>() {
                    wizard.set_transient_for(&win);
                }
            }
            let w = wrapper_for_btn.clone();
            wizard.set_on_complete(move || {
                refresh_mounts(&w);
            });
            wizard.present();
        });
        content.append(&add_button);

        NavigationPage::builder()
            .title("Client")
            .name("client")
            .child(&content)
            .build()
    }
}
