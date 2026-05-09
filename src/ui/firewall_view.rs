#![allow(dead_code)]
// Firewall integration view for Samba GUI
//
// Detects ufw/firewalld, shows port status, and offers to open SMB ports.

#[cfg(feature = "gui")]
mod gui {
    use adw::PreferencesGroup;
    use gtk::{Box, Label, Button, Orientation, Align};
    use adw::prelude::*;
    use crate::services::firewall_checker::{FirewallChecker, FirewallStatus};
    use crate::ui::show_success_toast;
    use crate::ui::show_error_toast;

    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

    /// Creates the firewall page widget for the content stack.
    pub fn create_firewall_page_widget() -> gtk::ScrolledWindow {
        let scrolled = gtk::ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .build();

        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(24)
            .margin_end(24)
            .margin_top(24)
            .margin_bottom(24)
            .spacing(16)
            .build();

        let title = Label::builder()
            .label("Firewall Status")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        let desc = Label::builder()
            .label("Check and configure firewall rules for Samba (SMB) ports")
            .css_classes(["body"])
            .halign(Align::Start)
            .build();
        content.append(&desc);

        // Status container — replaced on refresh
        let status_container = std::rc::Rc::new(Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(8)
            .build());

        // Initial load
        refresh_firewall_status(&status_container);

        content.append(status_container.as_ref());

        // Action buttons
        let button_row = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .margin_top(8)
            .build();

        let refresh_button = Button::builder()
            .label("Refresh")
            .css_classes(["flat"])
            .build();

        let container_for_refresh = status_container.clone();
        refresh_button.connect_clicked(move |_| {
            refresh_firewall_status(&container_for_refresh);
        });
        button_row.append(&refresh_button);

        let open_ports_button = Button::builder()
            .label("Open SMB Ports")
            .css_classes(["suggested-action"])
            .tooltip_text("Allow ports 445/tcp, 139/tcp, 137/udp, 138/udp through the firewall")
            .build();

        let container_for_open = status_container.clone();
        open_ports_button.connect_clicked(move |button| {
            button.set_sensitive(false);
            let btn = button.clone();
            let container = container_for_open.clone();

            let (sender, receiver) = std::sync::mpsc::channel::<Result<Vec<String>, String>>();

            std::thread::spawn(move || {
                let res = FirewallChecker::open_smb_ports().map_err(|e| e.to_string());
                let _ = sender.send(res);
            });

            fn poll_open(
                receiver: std::sync::mpsc::Receiver<Result<Vec<String>, String>>,
                container: std::rc::Rc<Box>,
                btn: Button,
            ) {
                match receiver.try_recv() {
                    Ok(Ok(results)) => {
                        let summary = results.join("\n");
                        show_success_toast("Firewall ports opened");
                        log::info!("Firewall open results:\n{}", summary);
                        refresh_firewall_status(&container);
                        btn.set_sensitive(true);
                    }
                    Ok(Err(e)) => {
                        show_error_toast(&format!("Failed to open ports: {}", e));
                        btn.set_sensitive(true);
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        let poll_interval = std::time::Duration::from_millis(100);
                        glib::timeout_add_local_once(poll_interval, move || {
                            poll_open(receiver, container, btn);
                        });
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        show_error_toast("Firewall operation thread terminated");
                        btn.set_sensitive(true);
                    }
                }
            }
            poll_open(receiver, container, btn);
        });
        button_row.append(&open_ports_button);

        content.append(&button_row);

        scrolled.set_child(Some(&content));
        scrolled
    }

    /// Refresh the firewall status display.
    fn refresh_firewall_status(container: &std::rc::Rc<Box>) {
        // Clear existing content
        while let Some(child) = container.first_child() {
            container.remove(&child);
        }

        // Run detection (this is fast — just spawns a couple of processes)
        match FirewallChecker::get_status() {
            Ok(status) => {
                build_status_display(container, &status);
            }
            Err(crate::services::firewall_checker::FirewallError::NoFirewall) => {
                let info_group = PreferencesGroup::builder()
                    .title("Detection Result")
                    .build();

                let row = adw::ActionRow::builder()
                    .title("No active firewall detected")
                    .subtitle("Neither ufw nor firewalld is running. SMB ports should be accessible unless blocked by iptables/nftables rules directly.")
                    .build();

                let icon = Label::builder()
                    .label("✅")
                    .build();
                row.add_prefix(&icon);

                info_group.add(&row);
                container.append(&info_group);
            }
            Err(e) => {
                let error_group = PreferencesGroup::builder()
                    .title("Detection Error")
                    .build();

                let row = adw::ActionRow::builder()
                    .title("Could not check firewall status")
                    .subtitle(&format!("{}", e))
                    .build();

                let icon = Label::builder()
                    .label("⚠️")
                    .build();
                row.add_prefix(&icon);

                error_group.add(&row);
                container.append(&error_group);
            }
        }
    }

    /// Build the status display showing backend info and per-port status.
    fn build_status_display(container: &std::rc::Rc<Box>, status: &FirewallStatus) {
        // Backend info group
        let info_group = PreferencesGroup::builder()
            .title("Firewall Backend")
            .build();

        let backend_row = adw::ActionRow::builder()
            .title(&format!("{}", status.backend))
            .subtitle(if status.active { "Active" } else { "Inactive" })
            .build();

        let backend_icon = Label::builder()
            .label(if status.active { "🛡️" } else { "⚪" })
            .build();
        backend_row.add_prefix(&backend_icon);
        info_group.add(&backend_row);
        container.append(&info_group);

        // Ports group
        let ports_group = PreferencesGroup::builder()
            .title("SMB Port Status")
            .description("Samba requires these ports to be accessible")
            .build();

        for port_status in &status.ports {
            let (icon_text, subtitle) = if port_status.allowed {
                ("✅", "Allowed")
            } else {
                ("❌", "Blocked")
            };

            let row = adw::ActionRow::builder()
                .title(&port_status.port)
                .subtitle(subtitle)
                .build();

            let icon = Label::builder()
                .label(icon_text)
                .build();
            row.add_prefix(&icon);

            ports_group.add(&row);
        }

        // Summary row
        if status.all_ports_open() {
            let summary_row = adw::ActionRow::builder()
                .title("All SMB ports are open")
                .subtitle("Samba should be reachable from the network")
                .build();
            let icon = Label::builder()
                .label("👍")
                .build();
            summary_row.add_prefix(&icon);
            ports_group.add(&summary_row);
        } else {
            let blocked: Vec<&str> = status.blocked_ports()
                .iter()
                .map(|p| p.port.as_str())
                .collect();
            let summary_row = adw::ActionRow::builder()
                .title("Some ports are blocked")
                .subtitle(&format!("Blocked: {}. Click 'Open SMB Ports' to fix.", blocked.join(", ")))
                .build();
            let icon = Label::builder()
                .label("⚠️")
                .build();
            summary_row.add_prefix(&icon);
            ports_group.add(&summary_row);
        }

        container.append(&ports_group);
    }
}

#[cfg(feature = "gui")]
pub use gui::create_firewall_page_widget;

#[cfg(not(feature = "gui"))]
pub fn create_firewall_page_widget() {
    // No-op when GUI feature is not enabled
}
