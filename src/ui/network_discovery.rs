#![allow(dead_code)]
// Network Discovery view for Samba GUI
//
// Scans the local network for SMB hosts and shares, allowing users to
// browse and one-click mount discovered shares.

#[cfg(feature = "gui")]
mod gui {
    use adw::PreferencesGroup;
    use gtk::{Box, Label, Button, Orientation, Align, Spinner, ScrolledWindow, Entry};
    use adw::prelude::*;
    use std::cell::RefCell;
    use crate::services::network_scanner::{NetworkScanner, DiscoveredHost, DiscoveredShare};
    use crate::ui::show_success_toast;
    use crate::ui::show_error_toast;
    use crate::ui::show_toast;

    /// Creates the network discovery page widget for the content stack.
    pub fn create_network_discovery_page_widget() -> ScrolledWindow {
        let scrolled = ScrolledWindow::builder()
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
            .label("Network Discovery")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        let desc = Label::builder()
            .label("Scan the local network for SMB/CIFS shares. Discovered shares can be mounted with one click.")
            .css_classes(["body"])
            .halign(Align::Start)
            .wrap(true)
            .build();
        content.append(&desc);

        // Manual host entry
        let manual_group = PreferencesGroup::builder()
            .title("Browse a Specific Host")
            .description("Enter a hostname or IP address to list its shares")
            .build();

        let manual_row = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(8)
            .build();

        let host_entry = Entry::builder()
            .placeholder_text("hostname or IP (e.g. 192.168.1.10)")
            .hexpand(true)
            .build();
        manual_row.append(&host_entry);

        let browse_button = Button::builder()
            .label("Browse")
            .css_classes(["suggested-action"])
            .build();
        manual_row.append(&browse_button);

        manual_group.add(&manual_row);
        content.append(&manual_group);

        // Results container — replaced on each scan
        let results_container = std::rc::Rc::new(Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(8)
            .build());

        // Cached host list so "Back to Hosts" can restore without re-scanning
        let cached_hosts: std::rc::Rc<RefCell<Vec<DiscoveredHost>>> =
            std::rc::Rc::new(RefCell::new(Vec::new()));

        // Browse button handler — list shares on a specific host
        let container_for_browse = results_container.clone();
        let entry_for_browse = host_entry.clone();
        browse_button.connect_clicked(move |btn| {
            let host = entry_for_browse.text().to_string();
            let host = host.trim().to_string();
            if host.is_empty() {
                show_error_toast("Enter a hostname or IP address");
                return;
            }
            btn.set_sensitive(false);
            let b = btn.clone();
            let container = container_for_browse.clone();
            show_scanning_indicator(&container, &format!("Listing shares on {}...", host));

            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = NetworkScanner::list_shares(&host);
                let _ = sender.send((host, result));
            });

            poll_share_results(receiver, container, b, None);
        });

        // Enter key in the host entry triggers browse
        let browse_btn_for_enter = browse_button.clone();
        host_entry.connect_activate(move |_| {
            browse_btn_for_enter.emit_clicked();
        });

        // Scan network button
        let scan_group = PreferencesGroup::builder()
            .title("Network Scan")
            .description("Discover SMB hosts on the local network via mDNS and NetBIOS")
            .build();

        let scan_button = Button::builder()
            .label("Scan Network")
            .css_classes(["flat"])
            .tooltip_text("Discover SMB servers using avahi-browse and nmblookup")
            .build();

        let container_for_scan = results_container.clone();
        let cached_hosts_for_scan = cached_hosts.clone();
        scan_button.connect_clicked(move |btn| {
            btn.set_sensitive(false);
            let container = container_for_scan.clone();
            let hosts_cache = cached_hosts_for_scan.clone();
            show_scanning_indicator(&container, "Scanning network for SMB hosts...");

            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = NetworkScanner::discover_hosts();
                let _ = sender.send(result);
            });

            poll_host_results(receiver, container, btn.clone(), hosts_cache);
        });
        scan_group.add(&scan_button);
        content.append(&scan_group);

        content.append(results_container.as_ref());

        scrolled.set_child(Some(&content));
        scrolled
    }

    /// Show a spinner with a message while scanning.
    fn show_scanning_indicator(container: &std::rc::Rc<Box>, message: &str) {
        while let Some(child) = container.first_child() {
            container.remove(&child);
        }

        let loading_box = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .halign(Align::Center)
            .margin_top(16)
            .margin_bottom(16)
            .build();

        let spinner = Spinner::new();
        spinner.set_spinning(true);
        spinner.set_size_request(24, 24);
        loading_box.append(&spinner);

        let label = Label::builder()
            .label(message)
            .css_classes(["body"])
            .build();
        loading_box.append(&label);

        container.append(&loading_box);
    }

    /// Poll for host discovery results.
    fn poll_host_results(
        receiver: std::sync::mpsc::Receiver<Result<Vec<DiscoveredHost>, crate::services::network_scanner::ScanError>>,
        container: std::rc::Rc<Box>,
        btn: Button,
        cached_hosts: std::rc::Rc<RefCell<Vec<DiscoveredHost>>>,
    ) {
        match receiver.try_recv() {
            Ok(Ok(hosts)) => {
                // Cache the discovered hosts for the back button
                *cached_hosts.borrow_mut() = hosts.clone();
                display_hosts(&container, &hosts, &cached_hosts);
                btn.set_sensitive(true);
                if hosts.is_empty() {
                    show_toast("No SMB hosts found on the network");
                } else {
                    show_toast(&format!("Found {} host(s)", hosts.len()));
                }
            }
            Ok(Err(e)) => {
                display_error(&container, &format!("{}", e));
                btn.set_sensitive(true);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                let interval = std::time::Duration::from_millis(100);
                glib::timeout_add_local_once(interval, move || {
                    poll_host_results(receiver, container, btn, cached_hosts);
                });
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                display_error(&container, "Scan thread terminated unexpectedly");
                btn.set_sensitive(true);
            }
        }
    }

    /// Poll for share listing results.
    fn poll_share_results(
        receiver: std::sync::mpsc::Receiver<(String, Result<Vec<DiscoveredShare>, crate::services::network_scanner::ScanError>)>,
        container: std::rc::Rc<Box>,
        btn: Button,
        cached_hosts: Option<std::rc::Rc<RefCell<Vec<DiscoveredHost>>>>,
    ) {
        match receiver.try_recv() {
            Ok((host, Ok(shares))) => {
                display_shares(&container, &host, &shares, &cached_hosts);
                btn.set_sensitive(true);
                if shares.is_empty() {
                    show_toast(&format!("No accessible shares found on {}", host));
                } else {
                    show_toast(&format!("Found {} share(s) on {}", shares.len(), host));
                }
            }
            Ok((_host, Err(e))) => {
                display_error(&container, &format!("{}", e));
                btn.set_sensitive(true);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                let interval = std::time::Duration::from_millis(100);
                glib::timeout_add_local_once(interval, move || {
                    poll_share_results(receiver, container, btn, cached_hosts);
                });
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                display_error(&container, "Browse thread terminated unexpectedly");
                btn.set_sensitive(true);
            }
        }
    }

    /// Display discovered hosts with "Browse" buttons.
    fn display_hosts(
        container: &std::rc::Rc<Box>,
        hosts: &[DiscoveredHost],
        cached_hosts: &std::rc::Rc<RefCell<Vec<DiscoveredHost>>>,
    ) {
        while let Some(child) = container.first_child() {
            container.remove(&child);
        }

        if hosts.is_empty() {
            let empty_label = Label::builder()
                .label("No SMB hosts found. Try entering a hostname manually above.")
                .css_classes(["body", "dim-label"])
                .halign(Align::Start)
                .wrap(true)
                .build();
            container.append(&empty_label);
            return;
        }

        let group = PreferencesGroup::builder()
            .title("Discovered Hosts")
            .description("Click 'Browse' to list shares on a host")
            .build();

        for host in hosts {
            let subtitle = format!("{} (discovered via {})", host.address, host.source);
            let display_name = if host.netbios_name.is_empty() {
                host.address.clone()
            } else {
                host.netbios_name.clone()
            };

            let row = adw::ActionRow::builder()
                .title(&display_name)
                .subtitle(&subtitle)
                .build();

            let icon = Label::builder()
                .label("🖥️")
                .build();
            row.add_prefix(&icon);

            let browse_btn = Button::builder()
                .label("Browse")
                .css_classes(["flat", "suggested-action"])
                .valign(Align::Center)
                .build();

            let host_addr = host.address.clone();
            let container_for_host = container.clone();
            let cached_hosts_for_browse = cached_hosts.clone();
            browse_btn.connect_clicked(move |btn| {
                btn.set_sensitive(false);
                let b = btn.clone();
                let c = container_for_host.clone();
                let addr = host_addr.clone();
                let hosts_cache = cached_hosts_for_browse.clone();
                show_scanning_indicator(&c, &format!("Listing shares on {}...", addr));

                let (sender, receiver) = std::sync::mpsc::channel();
                let addr_thread = addr.clone();
                std::thread::spawn(move || {
                    let result = NetworkScanner::list_shares(&addr_thread);
                    let _ = sender.send((addr_thread, result));
                });

                poll_share_results(receiver, c, b, Some(hosts_cache));
            });

            row.add_suffix(&browse_btn);
            group.add(&row);
        }

        container.append(&group);
    }

    /// Display discovered shares with "Mount" buttons.
    fn display_shares(
        container: &std::rc::Rc<Box>,
        host: &str,
        shares: &[DiscoveredShare],
        cached_hosts: &Option<std::rc::Rc<RefCell<Vec<DiscoveredHost>>>>,
    ) {
        while let Some(child) = container.first_child() {
            container.remove(&child);
        }

        if shares.is_empty() {
            let empty_label = Label::builder()
                .label(&format!("No accessible shares found on {}. The host may require authentication.", host))
                .css_classes(["body", "dim-label"])
                .halign(Align::Start)
                .wrap(true)
                .build();
            container.append(&empty_label);
            // Still show back button even when no shares found
            if let Some(hosts_cache) = cached_hosts {
                if !hosts_cache.borrow().is_empty() {
                    let back_btn = Button::builder()
                        .label("← Back to Hosts")
                        .css_classes(["flat"])
                        .margin_top(8)
                        .build();

                    let container_for_back = container.clone();
                    let hosts_for_back = hosts_cache.clone();
                    back_btn.connect_clicked(move |_| {
                        let hosts = hosts_for_back.borrow().clone();
                        display_hosts(&container_for_back, &hosts, &hosts_for_back);
                    });
                    container.append(&back_btn);
                }
            }
            return;
        }

        let group = PreferencesGroup::builder()
            .title(&format!("Shares on {}", host))
            .description("Click 'Mount' to open the Mount Wizard with the share address pre-filled")
            .build();

        for share in shares {
            let subtitle = if share.comment.is_empty() {
                format!("{} — {}", share.unc_path(), share.share_type)
            } else {
                format!("{} — {} — {}", share.unc_path(), share.share_type, share.comment)
            };

            let row = adw::ActionRow::builder()
                .title(&share.name)
                .subtitle(&subtitle)
                .build();

            let icon_text = match share.share_type.as_str() {
                "Printer" => "🖨️",
                _ => "📁",
            };
            let icon = Label::builder()
                .label(icon_text)
                .build();
            row.add_prefix(&icon);

            // Only show Mount button for Disk shares
            if share.share_type == "Disk" || share.share_type.is_empty() {
                let mount_btn = Button::builder()
                    .label("Mount")
                    .css_classes(["flat", "suggested-action"])
                    .valign(Align::Center)
                    .tooltip_text("Open Mount Wizard with this share address")
                    .build();

                let unc = share.unc_path();
                mount_btn.connect_clicked(move |btn| {
                    use crate::ui::mount_wizard::wizard_ui::MountWizard;
                    let wizard = MountWizard::new_with_address(&unc);
                    if let Some(root) = btn.root() {
                        if let Ok(win) = root.downcast::<gtk::Window>() {
                            wizard.set_transient_for(&win);
                        }
                    }
                    wizard.present();
                    show_success_toast("Mount Wizard opened with share address pre-filled");
                });

                row.add_suffix(&mount_btn);
            }

            group.add(&row);
        }

        container.append(&group);

        // Back button to return to cached host list
        if let Some(hosts_cache) = cached_hosts {
            if !hosts_cache.borrow().is_empty() {
                let back_btn = Button::builder()
                    .label("← Back to Hosts")
                    .css_classes(["flat"])
                    .build();

                let container_for_back = container.clone();
                let hosts_for_back = hosts_cache.clone();
                back_btn.connect_clicked(move |_| {
                    let hosts = hosts_for_back.borrow().clone();
                    display_hosts(&container_for_back, &hosts, &hosts_for_back);
                });

                container.append(&back_btn);
            }
        }
    }

    /// Display an error message in the results container.
    fn display_error(container: &std::rc::Rc<Box>, message: &str) {
        while let Some(child) = container.first_child() {
            container.remove(&child);
        }

        let error_group = PreferencesGroup::builder()
            .title("Error")
            .build();

        let row = adw::ActionRow::builder()
            .title("Scan failed")
            .subtitle(message)
            .build();

        let icon = Label::builder()
            .label("⚠️")
            .build();
        row.add_prefix(&icon);

        error_group.add(&row);

        // Hint about required tools
        let hint_row = adw::ActionRow::builder()
            .title("Required tools")
            .subtitle("Install avahi-utils (for mDNS) and/or samba-common-bin (for smbclient/nmblookup)")
            .build();
        error_group.add(&hint_row);

        container.append(&error_group);
    }
}

#[cfg(feature = "gui")]
pub use gui::create_network_discovery_page_widget;

#[cfg(not(feature = "gui"))]
pub fn create_network_discovery_page_widget() {
    // No-op when GUI feature is not enabled
}
