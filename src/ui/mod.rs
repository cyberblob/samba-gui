// UI layer - GTK4/libadwaita components
// Main window with AdwNavigationSplitView for sidebar navigation

mod server_config;
mod client_config;
mod service_management;
mod user_management;
mod backup_view;
mod mount_wizard;
mod firewall_view;
mod network_discovery;

#[cfg(feature = "gui")]
#[allow(dead_code)]
mod gui {
    use adw::{Application, NavigationSplitView, NavigationPage, PreferencesGroup, EntryRow, ActionRow, ComboRow, ToastOverlay, StatusPage, Toast};
    use gtk::{Box, Label, Button, Orientation, Align, TextView, Spinner, ScrolledWindow, Stack, StackTransitionType, StringList};
    use adw::StyleManager;
    use crate::config::{SambaConfig, GlobalSettings, Share, SystemdMountEntry};
    use crate::ui::server_config::load_config;
    use crate::services::SharePreview;

    // Import all necessary traits
    use adw::prelude::*;

    /// Characters that are dangerous in shell contexts or systemd unit fields.
    /// Rejects anything that could be used for shell injection, escape sequences,
    /// or corrupt the unit file format.
    const DANGEROUS_CHARS: &[char] = &[
        '\'', '"', '`', '$', '\\', '!', '|', '&', ';', '\n', '\r', '\t',
        '(', ')', '{', '}', '<', '>', '~', '#', '\0',
    ];

    /// Validate that a string contains no dangerous / escape characters.
    fn reject_dangerous_chars(value: &str, field_name: &str) -> Result<(), String> {
        for ch in DANGEROUS_CHARS {
            if value.contains(*ch) {
                let ch_name = match *ch {
                    '\n' => "newline".to_string(),
                    '\r' => "carriage-return".to_string(),
                    '\t' => "tab".to_string(),
                    '\0' => "null".to_string(),
                    other => format!("'{}'", other),
                };
                return Err(format!("{} contains forbidden character {}", field_name, ch_name));
            }
        }
        // Also reject any non-ASCII control characters
        if value.chars().any(|c| c.is_control()) {
            return Err(format!("{} contains control characters", field_name));
        }
        Ok(())
    }

    /// Validate a CIFS share address: must be //host/share with no dangerous chars.
    pub(crate) fn validate_share_address(addr: &str) -> Result<(), String> {
        reject_dangerous_chars(addr, "Share address")?;

        if !addr.starts_with("//") {
            return Err("Share address must start with // (e.g. //server/share)".into());
        }

        let body = &addr[2..]; // strip leading //
        if body.is_empty() {
            return Err("Share address must include a hostname and share name".into());
        }

        // Must contain at least one / separating host from share
        let slash_pos = match body.find('/') {
            Some(pos) => pos,
            None => return Err("Share address must be //hostname/sharename".into()),
        };

        let host = &body[..slash_pos];
        let share = &body[slash_pos + 1..];

        if host.is_empty() {
            return Err("Share address is missing the hostname".into());
        }
        if share.is_empty() || share == "/" {
            return Err("Share address is missing the share name".into());
        }

        // Host: alphanumeric, dots, hyphens, or IPv4/IPv6
        if !host.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '[' || c == ']') {
            return Err("Hostname contains invalid characters".into());
        }

        // Share name: alphanumeric, hyphens, underscores, dots, spaces, and path separators
        if !share.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ' ' || c == '/') {
            return Err("Share name contains invalid characters".into());
        }

        Ok(())
    }

    /// Validate a mount point: absolute path, no dangerous chars, reasonable characters only.
    pub(crate) fn validate_mount_point(mp: &str) -> Result<(), String> {
        reject_dangerous_chars(mp, "Mount point")?;

        if !mp.starts_with('/') {
            return Err("Mount point must be an absolute path".into());
        }
        if mp.contains("..") {
            return Err("Mount point must not contain '..'".into());
        }
        // Only allow alphanumeric, /, -, _, .
        if !mp.chars().all(|c| c.is_alphanumeric() || c == '/' || c == '-' || c == '_' || c == '.') {
            return Err("Mount point contains invalid characters".into());
        }
        Ok(())
    }

    /// Validate a free-text mount option value (username, domain, path, etc.)
    pub(crate) fn validate_option_value(value: &str, field_name: &str) -> Result<(), String> {
        reject_dangerous_chars(value, field_name)?;
        if value.contains(char::is_whitespace) {
            return Err(format!("{} must not contain whitespace", field_name));
        }
        Ok(())
    }

    /// Validate an octal file mode string (e.g. "0644", "0755")
    fn validate_octal_mode(value: &str, field_name: &str) -> Result<(), String> {
        if !value.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("{} must be a numeric octal value (e.g. 0644)", field_name));
        }
        if value.len() > 4 {
            return Err(format!("{} is too long for an octal mode", field_name));
        }
        // Each digit must be 0-7
        if value.chars().any(|c| c > '7') {
            return Err(format!("{} contains non-octal digits (must be 0-7)", field_name));
        }
        Ok(())
    }

    /// Write a systemd .mount (and optionally .automount) unit via the privileged executor.
    pub(crate) fn write_systemd_mount_unit(entry: &SystemdMountEntry) -> Result<(), String> {
        use crate::services::privileged_executor;
        use crate::services::SystemdMountManager;

        let mount_unit_name = SystemdMountManager::mount_unit_name(&entry.mount_point);
        let mount_path = format!("/etc/systemd/system/{}", mount_unit_name);
        let mount_content = SystemdMountManager::generate_mount_unit(entry);

        // Write .mount unit file
        let (_stdout, stderr, ok) = privileged_executor::run_privileged_with_stdin(
            "tee", &[&mount_path], &mount_content,
        ).map_err(|e| format!("Failed to write mount unit: {}", e))?;

        if !ok && stderr.contains("Permission denied") {
            return Err(stderr.trim().to_string());
        }

        // Write .automount unit if requested
        if entry.automount {
            let automount_unit_name = SystemdMountManager::automount_unit_name(&entry.mount_point);
            let automount_path = format!("/etc/systemd/system/{}", automount_unit_name);
            let automount_content = SystemdMountManager::generate_automount_unit(entry);

            let (_stdout, stderr, ok) = privileged_executor::run_privileged_with_stdin(
                "tee", &[&automount_path], &automount_content,
            ).map_err(|e| format!("Failed to write automount unit: {}", e))?;

            if !ok && stderr.contains("Permission denied") {
                return Err(stderr.trim().to_string());
            }
        }

        // Reload systemd daemon
        let (_out, stderr, ok) = privileged_executor::run_privileged(
            "systemctl", &["daemon-reload"],
        ).map_err(|e| format!("daemon-reload failed: {}", e))?;
        if !ok {
            log::warn!("systemctl daemon-reload failed: {}", stderr.trim());
        }

        // Enable and start the unit
        if entry.automount {
            let automount_unit_name = SystemdMountManager::automount_unit_name(&entry.mount_point);
            let (_out, stderr, ok) = privileged_executor::run_privileged(
                "systemctl", &["enable", "--now", &automount_unit_name],
            ).map_err(|e| format!("Failed to enable automount unit: {}", e))?;
            if !ok {
                log::warn!("systemctl enable automount failed: {}", stderr.trim());
            }
        } else {
            let (_out, stderr, ok) = privileged_executor::run_privileged(
                "systemctl", &["enable", "--now", &mount_unit_name],
            ).map_err(|e| format!("Failed to enable mount unit: {}", e))?;
            if !ok {
                log::warn!("systemctl enable mount failed: {}", stderr.trim());
            }
        }

        // Verify the unit actually came up; surface journal output on failure
        std::thread::sleep(std::time::Duration::from_millis(500));

        let check_unit = if entry.automount {
            SystemdMountManager::automount_unit_name(&entry.mount_point)
        } else {
            mount_unit_name.clone()
        };
        let (status_out, _, _) = privileged_executor::run_privileged(
            "systemctl", &["is-active", &check_unit],
        ).map_err(|e| format!("Failed to check unit status: {}", e))?;

        let status = status_out.trim();
        if status != "active" {
            let (journal, _, _) = privileged_executor::run_privileged(
                "journalctl", &["-u", &mount_unit_name, "-n", "10", "--no-pager", "-o", "short"],
            ).unwrap_or_default();

            let detail = if journal.trim().is_empty() {
                "no journal output".to_string()
            } else {
                journal.trim().to_string()
            };

            log::error!("Mount unit {} is '{}' after enable. Journal:\n{}", check_unit, status, detail);
            return Err(format!(
                "Unit enabled but not active ({}). Journal:\n{}",
                status, detail
            ));
        }

        Ok(())
    }

    /// Remove a systemd .mount (and .automount) unit for a given mount point.
    /// Stops and disables the units, deletes the files, and reloads the daemon.
    fn remove_systemd_mount_unit(mount_point: &str) -> Result<(), String> {
        use crate::services::privileged_executor;
        use crate::services::SystemdMountManager;

        let mount_unit_name = SystemdMountManager::mount_unit_name(mount_point);
        let automount_unit_name = SystemdMountManager::automount_unit_name(mount_point);
        let mount_path = format!("/etc/systemd/system/{}", mount_unit_name);
        let automount_path = format!("/etc/systemd/system/{}", automount_unit_name);

        // Stop and disable automount unit first (if it exists)
        let _ = privileged_executor::run_privileged(
            "systemctl", &["disable", "--now", &automount_unit_name],
        );

        // Stop and disable mount unit
        let _ = privileged_executor::run_privileged(
            "systemctl", &["disable", "--now", &mount_unit_name],
        );

        // Remove unit files
        let (_out, _stderr, _ok) = privileged_executor::run_privileged(
            "rm", &["-f", &mount_path],
        ).map_err(|e| format!("Failed to remove mount unit: {}", e))?;

        let (_out, _stderr, _ok) = privileged_executor::run_privileged(
            "rm", &["-f", &automount_path],
        ).map_err(|e| format!("Failed to remove automount unit: {}", e))?;

        // Reload daemon
        let (_out, stderr, ok) = privileged_executor::run_privileged(
            "systemctl", &["daemon-reload"],
        ).map_err(|e| format!("daemon-reload failed: {}", e))?;
        if !ok {
            log::warn!("systemctl daemon-reload failed: {}", stderr.trim());
        }

        // Remove the mount point directory if it's empty
        let _ = privileged_executor::run_privileged(
            "rmdir", &[mount_point],
        );

        Ok(())
    }

    // Store window reference for toast notifications
    static mut TOAST_OVERLAY: Option<ToastOverlay> = None;

    /// Set the toast overlay reference for showing toasts
    pub fn set_toast_overlay(overlay: &ToastOverlay) {
        unsafe { TOAST_OVERLAY = Some(overlay.clone()); }
    }

    /// Shows a toast notification with the given message
    /// Requirement 5.4: Display toast notifications for operation results
    pub fn show_toast(message: &str) {
        unsafe {
            if let Some(ref overlay) = TOAST_OVERLAY {
                let toast = Toast::builder()
                    .title(message)
                    .timeout(3)
                    .build();
                overlay.add_toast(toast);
            }
        }
    }

    /// Shows a success toast notification
    pub fn show_success_toast(message: &str) {
        show_toast(&format!("✅ {}", message));
    }

    /// Shows an error toast notification
    pub fn show_error_toast(message: &str) {
        show_toast(&format!("❌ {}", message));
    }

    /// Write content to a file, using the privileged executor for system paths
    fn write_config_file(path: &str, content: &str) -> Result<(), String> {
        if path.starts_with("/etc/") {
            // Use the privileged executor so we reuse the cached sudo session
            // instead of spawning a separate pkexec prompt.
            let (_stdout, stderr, _ok) =
                crate::services::privileged_executor::run_privileged_with_stdin(
                    "tee", &[path], content,
                )
                .map_err(|e| format!("Privileged write failed: {}", e))?;
            if !stderr.is_empty() {
                log::warn!("write_config_file stderr: {}", stderr);
            }
            Ok(())
        } else {
            std::fs::write(path, content).map_err(|e| e.to_string())
        }
    }

    /// Creates the main window with sidebar navigation
    pub fn create_main_window(app: &Application) -> adw::Window {
        let window = adw::Window::builder()
            .application(app)
            .title("Samba GUI")
            .default_width(1000)
            .default_height(700)
            .build();

        // Set minimum size for responsive resizing (Requirement 5.5)
        window.set_size_request(800, 500);

        // Create toast overlay to wrap the content for toast notifications (Requirement 5.4)
        let toast_overlay = ToastOverlay::new();

        // Store reference for toast notifications
        set_toast_overlay(&toast_overlay);

        // Build the content stack with all pages
        let content_stack = Stack::builder()
            .transition_type(StackTransitionType::Crossfade)
            .transition_duration(200)
            .vexpand(true)
            .hexpand(true)
            .build();

        // Home page
        content_stack.add_named(&create_home_page(), Some("home"));
        // Shared config state for server + shares pages
        let server_config = load_config("/etc/samba/smb.conf").unwrap_or_else(|_| {
            load_config("/etc/smb.conf").unwrap_or_else(|_| {
                SambaConfig::default()
            })
        });
        let shared_config = std::rc::Rc::new(std::cell::RefCell::new(server_config));
        let shared_shares = std::rc::Rc::new(std::cell::RefCell::new(shared_config.borrow().shares.clone()));
        // Server config page (global settings)
        content_stack.add_named(&create_server_config_page_widget(&shared_config, &shared_shares), Some("server"));
        // Shares page (child of server)
        content_stack.add_named(&create_shares_page_widget(&shared_config, &shared_shares), Some("shares"));
        // Client config page
        content_stack.add_named(&create_client_config_page_widget(), Some("client"));
        // Network discovery page — placeholder, built lazily on first navigation
        let network_placeholder = Box::new(Orientation::Vertical, 0);
        content_stack.add_named(&network_placeholder, Some("network"));
        // Services page — placeholder, built lazily on first navigation
        let services_placeholder = Box::new(Orientation::Vertical, 0);
        content_stack.add_named(&services_placeholder, Some("services"));
        // Users page — placeholder, built lazily on first navigation
        let users_placeholder = Box::new(Orientation::Vertical, 0);
        content_stack.add_named(&users_placeholder, Some("users"));
        // Backup page
        content_stack.add_named(&create_backup_page_widget(), Some("backup"));
        // Firewall page — placeholder, built lazily on first navigation
        let firewall_placeholder = Box::new(Orientation::Vertical, 0);
        content_stack.add_named(&firewall_placeholder, Some("firewall"));
        // Logs page — placeholder, built lazily on first navigation
        let logs_placeholder = Box::new(Orientation::Vertical, 0);
        content_stack.add_named(&logs_placeholder, Some("logs"));

        // Track which lazy pages have been built
        let lazy_built: std::rc::Rc<std::cell::RefCell<std::collections::HashSet<String>>> =
            std::rc::Rc::new(std::cell::RefCell::new(std::collections::HashSet::new()));

        // Build lazy pages on first switch
        let lazy_built_signal = lazy_built.clone();
        content_stack.connect_visible_child_name_notify(move |stack| {
            if let Some(name) = stack.visible_child_name() {
                let name = name.to_string();
                let mut built = lazy_built_signal.borrow_mut();
                if built.contains(&name) {
                    return;
                }
                match name.as_str() {
                    "services" => {
                        let real = create_service_management_page_widget();
                        // Replace the placeholder in the stack
                        if let Some(child) = stack.child_by_name("services") {
                            stack.remove(&child);
                        }
                        stack.add_named(&real, Some("services"));
                        stack.set_visible_child_name("services");
                        built.insert(name);
                    }
                    "users" => {
                        let real = create_user_management_page_widget();
                        if let Some(child) = stack.child_by_name("users") {
                            stack.remove(&child);
                        }
                        stack.add_named(&real, Some("users"));
                        stack.set_visible_child_name("users");
                        built.insert(name);
                    }
                    "logs" => {
                        let real = create_logs_page_widget();
                        if let Some(child) = stack.child_by_name("logs") {
                            stack.remove(&child);
                        }
                        stack.add_named(&real, Some("logs"));
                        stack.set_visible_child_name("logs");
                        built.insert(name);
                    }
                    "firewall" => {
                        let real = crate::ui::firewall_view::create_firewall_page_widget();
                        if let Some(child) = stack.child_by_name("firewall") {
                            stack.remove(&child);
                        }
                        stack.add_named(&real, Some("firewall"));
                        stack.set_visible_child_name("firewall");
                        built.insert(name);
                    }
                    "network" => {
                        let real = crate::ui::network_discovery::create_network_discovery_page_widget();
                        if let Some(child) = stack.child_by_name("network") {
                            stack.remove(&child);
                        }
                        stack.add_named(&real, Some("network"));
                        stack.set_visible_child_name("network");
                        built.insert(name);
                    }
                    _ => {}
                }
            }
        });

        content_stack.set_visible_child_name("home");

        // Wrap the stack in a NavigationPage for the split view content
        let content_page = NavigationPage::builder()
            .title("Home")
            .name("content")
            .child(&content_stack)
            .build();

        // Create the sidebar, passing the stack so buttons can switch pages
        let sidebar_page = create_sidebar_page(&content_stack, &content_page);

        // Create the main split view with sidebar navigation
        let split_view = NavigationSplitView::builder()
            .sidebar(&sidebar_page)
            .content(&content_page)
            .build();

        // Wrap the split view in a ToolbarView with a HeaderBar for a draggable titlebar
        let header_bar = adw::HeaderBar::new();

        // About button in the header bar
        let about_button = Button::builder()
            .icon_name("help-about-symbolic")
            .tooltip_text("About Samba GUI")
            .build();
        about_button.connect_clicked(move |btn| {
            let about = adw::AboutWindow::builder()
                .application_name("Samba GUI")
                .version(format!("{}-Beta", env!("SAMBA_GUI_VERSION")))
                .copyright("© 2026 Douglas Farrell")
                .developer_name("Douglas Farrell")
                .website("https://github.com/cyberblob/samba-gui")
                .issue_url("https://github.com/cyberblob/samba-gui/issues")
                .license_type(gtk::License::Gpl30)
                .comments("A GTK4/libadwaita desktop application for managing Samba server and client configurations on Linux. Because Windows GUIs shouldn't be the only ones that don't suck.")
                .build();
            if let Some(root) = btn.root() {
                if let Ok(win) = root.downcast::<adw::Window>() {
                    about.set_transient_for(Some(&win));
                }
            }
            about.present();
        });
        header_bar.pack_end(&about_button);

        // Theme toggle button in the header bar
        let theme_button = Button::builder()
            .icon_name("weather-clear-night-symbolic")
            .tooltip_text("Toggle Dark/Light/System theme")
            .build();
        theme_button.connect_clicked(move |btn| {
            cycle_theme(btn);
        });
        header_bar.pack_end(&theme_button);

        let toolbar_view = adw::ToolbarView::new();
        toolbar_view.add_top_bar(&header_bar);
        toolbar_view.set_content(Some(&split_view));

        // Set the toolbar view as the toast overlay child
        toast_overlay.set_child(Some(&toolbar_view));

        // Set the toast overlay as the window content
        window.set_content(Some(&toast_overlay));

        // Apply saved theme preference (or default to dark)
        apply_saved_theme();

        window
    }

    /// Creates the home/welcome widget
    fn create_home_page() -> Box {
        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(24)
            .margin_end(24)
            .margin_top(24)
            .margin_bottom(24)
            .spacing(16)
            .build();

        let title = Label::builder()
            .label("Samba GUI")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        let desc = Label::builder()
            .label("Welcome to Samba GUI — Select a section from the sidebar")
            .css_classes(["body"])
            .halign(Align::Start)
            .build();
        content.append(&desc);

        content
    }

    /// Builds the server config content directly for the stack
    fn create_server_config_page_widget(shared_config: &std::rc::Rc<std::cell::RefCell<SambaConfig>>, shared_shares: &std::rc::Rc<std::cell::RefCell<Vec<Share>>>) -> ScrolledWindow {
        let scrolled = ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .build();

        let config = shared_config.clone();

        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(24)
            .margin_end(24)
            .margin_top(24)
            .margin_bottom(24)
            .spacing(16)
            .build();

        let title = Label::builder()
            .label("Server Configuration")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        // Template selector
        let template_group = PreferencesGroup::builder()
            .title("Quick Start Template")
            .description("Apply a preset configuration as a starting point")
            .build();

        let available_templates = crate::config::template_names();
        let template_combo = add_combo(&template_group, "Template", &available_templates, "Default (Secure)",
            "Select a template to pre-fill global settings. Your current values will be overwritten.");

        content.append(&template_group);

        let (global_group, global_rows) = create_global_settings_group(&config.borrow().global);
        let global_rows = std::rc::Rc::new(global_rows);
        content.append(&global_group);

        // Apply template button
        let apply_button = Button::builder()
            .label("Apply Template")
            .css_classes(["flat"])
            .build();

        let rows_for_template = global_rows.clone();
        apply_button.connect_clicked(move |button| {
            let name = combo_value(&template_combo);
            let template = GlobalSettings::from_template(&name);
            let current = rows_for_template.to_global_settings();
            let diffs = diff_global_settings(&current, &template);

            if diffs.is_empty() {
                show_success_toast("No changes — current settings already match this template");
                return;
            }

            // Build confirmation dialog
            let dialog = adw::Window::builder()
                .title(&format!("Apply '{}' Template?", name))
                .default_width(500)
                .default_height(400)
                .modal(true)
                .build();

            if let Some(root) = button.root() {
                if let Ok(win) = root.downcast::<adw::Window>() {
                    dialog.set_transient_for(Some(&win));
                }
            }

            let content = Box::builder()
                .orientation(Orientation::Vertical)
                .margin_start(24)
                .margin_end(24)
                .margin_top(24)
                .margin_bottom(24)
                .spacing(12)
                .build();

            let header = Label::builder()
                .label(&format!("{} setting(s) will change:", diffs.len()))
                .css_classes(["title-4"])
                .halign(Align::Start)
                .build();
            content.append(&header);

            // Scrollable diff list
            let scrolled = ScrolledWindow::builder()
                .vexpand(true)
                .min_content_height(200)
                .build();
            let diff_box = Box::builder()
                .orientation(Orientation::Vertical)
                .spacing(4)
                .build();
            for diff in &diffs {
                let row = Label::builder()
                    .label(diff)
                    .css_classes(["monospace", "caption"])
                    .halign(Align::Start)
                    .wrap(true)
                    .build();
                diff_box.append(&row);
            }
            scrolled.set_child(Some(&diff_box));
            content.append(&scrolled);

            // Buttons
            let button_box = Box::builder()
                .orientation(Orientation::Horizontal)
                .spacing(12)
                .halign(Align::End)
                .build();

            let cancel_button = Button::builder()
                .label("Cancel")
                .css_classes(["flat"])
                .build();
            let dialog_for_cancel = dialog.clone();
            cancel_button.connect_clicked(move |_| {
                dialog_for_cancel.close();
            });

            let confirm_button = Button::builder()
                .label("Apply")
                .css_classes(["suggested-action"])
                .build();
            let rows_for_apply = rows_for_template.clone();
            let template_name = name.clone();
            let dialog_for_apply = dialog.clone();
            confirm_button.connect_clicked(move |_| {
                let t = GlobalSettings::from_template(&template_name);
                rows_for_apply.apply_from(&t);
                show_success_toast(&format!("Applied '{}' template", template_name));
                dialog_for_apply.close();
            });

            button_box.append(&cancel_button);
            button_box.append(&confirm_button);
            content.append(&button_box);

            dialog.set_content(Some(&content));
            dialog.present();
        });
        template_group.add(&apply_button);

        let save_button = Button::builder()
            .label("Save Configuration")
            .css_classes(["suggested-action"])
            .build();

        let config_path = "/etc/samba/smb.conf".to_string();
        let shared_shares_clone = shared_shares.clone();
        let rows_for_save = global_rows.clone();
        save_button.connect_clicked(move |button| {
            let mut config = config.borrow_mut();
            rows_for_save.update_config(&mut config);
            config.shares = shared_shares_clone.borrow().clone();
            match crate::config::ConfigParser::validate(&config) {
                Ok(()) => {
                    match crate::config::ConfigParser::serialize(&config) {
                        Ok(content) => {
                            // Move the privileged write off the main thread to
                            // avoid deadlocking when sudo needs re-auth.
                            let path = config_path.clone();
                            button.set_sensitive(false);
                            let btn = button.clone();
                            spawn_blocking_then(
                                move || {
                                    // Auto-backup before overwriting the config
                                    let source = std::path::Path::new(&path);
                                    if source.exists() || {
                                        // Check via sudo if direct access fails
                                        std::process::Command::new("sudo")
                                            .args(["-n", "test", "-f", &path])
                                            .stdout(std::process::Stdio::null())
                                            .stderr(std::process::Stdio::null())
                                            .status()
                                            .map(|s| s.success())
                                            .unwrap_or(false)
                                    } {
                                        let backup_mgr = crate::services::backup_manager::BackupManager::new();
                                        match backup_mgr.backup(source) {
                                            Ok(info) => log::info!(
                                                "Auto-backup created before save: {}",
                                                info.path
                                            ),
                                            Err(e) => log::warn!(
                                                "Auto-backup failed (continuing with save): {}",
                                                e
                                            ),
                                        }
                                    }
                                    write_config_file(&path, &content)
                                },
                                move |result| {
                                    btn.set_sensitive(true);
                                    match result {
                                        Ok(()) => show_success_toast("Configuration saved (auto-backup created)"),
                                        Err(e) => show_error_toast(&format!("Failed to write config: {}", e)),
                                    }
                                },
                            );
                        }
                        Err(e) => show_error_toast(&format!("Failed to serialize config: {}", e)),
                    }
                }
                Err(e) => show_error_toast(&format!("Validation failed: {}", e)),
            }
        });
        content.append(&save_button);

        // Export/Import buttons
        let export_import_group = PreferencesGroup::builder()
            .title("Export / Import")
            .description("Export configuration as JSON for backup or transfer to another machine")
            .build();

        let export_button = Button::builder()
            .label("Export as JSON")
            .css_classes(["flat"])
            .tooltip_text("Save the current configuration as a portable JSON file")
            .build();

        let config_for_export = shared_config.clone();
        let shares_for_export = shared_shares.clone();
        let rows_for_export = global_rows.clone();
        export_button.connect_clicked(move |_btn| {
            let mut config = config_for_export.borrow_mut();
            rows_for_export.update_config(&mut config);
            config.shares = shares_for_export.borrow().clone();

            let file_dialog = gtk::FileDialog::builder()
                .title("Export Configuration")
                .initial_name("samba-config.json")
                .build();

            let config_clone = config.clone();
            file_dialog.save(
                None::<&adw::Window>,
                None::<&gtk::gio::Cancellable>,
                move |result| {
                    if let Ok(file) = result {
                        if let Some(path) = file.path() {
                            match crate::services::config_export::export_config_json(&config_clone, &path) {
                                Ok(()) => show_success_toast(&format!("Exported to {}", path.display())),
                                Err(e) => show_error_toast(&format!("Export failed: {}", e)),
                            }
                        }
                    }
                },
            );
        });
        export_import_group.add(&export_button);

        let import_button = Button::builder()
            .label("Import from JSON")
            .css_classes(["flat"])
            .tooltip_text("Load configuration from a previously exported JSON file")
            .build();

        let config_for_import = shared_config.clone();
        let shares_for_import = shared_shares.clone();
        let rows_for_import = global_rows.clone();
        import_button.connect_clicked(move |_btn| {
            let file_dialog = gtk::FileDialog::builder()
                .title("Import Configuration")
                .build();

            let config_ref = config_for_import.clone();
            let shares_ref = shares_for_import.clone();
            let rows_ref = rows_for_import.clone();
            file_dialog.open(
                None::<&adw::Window>,
                None::<&gtk::gio::Cancellable>,
                move |result| {
                    if let Ok(file) = result {
                        if let Some(path) = file.path() {
                            match crate::services::config_export::import_config_json(&path) {
                                Ok(imported) => {
                                    // Apply imported config to the UI
                                    rows_ref.apply_from(&imported.global);
                                    *shares_ref.borrow_mut() = imported.shares.clone();
                                    let mut config = config_ref.borrow_mut();
                                    config.global = imported.global;
                                    config.shares = imported.shares;
                                    show_success_toast("Configuration imported — click Save to apply");
                                }
                                Err(e) => show_error_toast(&format!("Import failed: {}", e)),
                            }
                        }
                    }
                },
            );
        });
        export_import_group.add(&import_button);

        content.append(&export_import_group);

        scrolled.set_child(Some(&content));
        scrolled
    }

    /// Builds the shares management page as a child of server config
    fn create_shares_page_widget(shared_config: &std::rc::Rc<std::cell::RefCell<SambaConfig>>, shared_shares: &std::rc::Rc<std::cell::RefCell<Vec<Share>>>) -> ScrolledWindow {
        let scrolled = ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .build();

        let config = shared_config.clone();

        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(24)
            .margin_end(24)
            .margin_top(24)
            .margin_bottom(24)
            .spacing(16)
            .build();

        let title = Label::builder()
            .label("Share Management")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        let shares_group = create_shares_group(shared_shares, &config.borrow().global);
        content.append(&shares_group);

        scrolled.set_child(Some(&content));
        scrolled
    }

    /// Builds the client config content directly for the stack
    /// Build a fresh PreferencesGroup with the current CIFS mounts from systemd units
    fn build_mounts_group(wrapper: &std::rc::Rc<Box>) -> adw::PreferencesGroup {
        let group = adw::PreferencesGroup::builder()
            .title("Mounted Shares")
            .build();

        let mount_manager = crate::services::SystemdMountManager::new();
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
                let status = if mount.active {
                    "active"
                } else if mount.enabled {
                    "enabled"
                } else {
                    "disabled"
                };
                let subtitle = format!("{} ({}) — {}", mount.device, options_str, status);
                let mount_row = ActionRow::builder()
                    .title(&mount.mount_point)
                    .subtitle(&subtitle)
                    .build();

                // Enable/disable switch — show as on if the unit is enabled or active
                let enable_sw = gtk::Switch::builder()
                    .active(mount.enabled || mount.active)
                    .valign(Align::Center)
                    .tooltip_text("Enable or disable this systemd mount unit")
                    .build();

                let wrapper_for_toggle = wrapper.clone();
                let mp_for_toggle = mount.mount_point.clone();
                let has_automount = mount.automount;
                enable_sw.connect_state_set(move |_, active| {
                    toggle_systemd_mount(&mp_for_toggle, active, has_automount, &wrapper_for_toggle);
                    gtk::glib::Propagation::Stop
                });

                let button_box = Box::builder()
                    .orientation(Orientation::Horizontal)
                    .spacing(8)
                    .valign(Align::Center)
                    .build();

                // Edit button
                let edit_btn = Button::builder()
                    .icon_name("document-edit-symbolic")
                    .css_classes(["flat"])
                    .tooltip_text("Edit mount")
                    .valign(Align::Center)
                    .build();

                let wrapper_for_edit = wrapper.clone();
                let mount_for_edit = mount.clone();
                edit_btn.connect_clicked(move |btn| {
                    use crate::ui::mount_wizard::wizard_ui::MountWizard;
                    let wizard = MountWizard::new_edit(&mount_for_edit);
                    if let Some(root) = btn.root() {
                        if let Ok(win) = root.downcast::<gtk::Window>() {
                            wizard.set_transient_for(&win);
                        }
                    }
                    let w = wrapper_for_edit.clone();
                    wizard.set_on_complete(move || {
                        refresh_mounts_group(&w);
                    });
                    wizard.present();
                });

                // Delete button
                let delete_btn = Button::builder()
                    .icon_name("user-trash-symbolic")
                    .css_classes(["flat", "error"])
                    .tooltip_text("Remove mount")
                    .valign(Align::Center)
                    .build();

                let wrapper_for_delete = wrapper.clone();
                let mp_for_delete = mount.mount_point.clone();
                delete_btn.connect_clicked(move |_| {
                    remove_systemd_mount_entry(&mp_for_delete, &wrapper_for_delete);
                });

                button_box.append(&enable_sw);
                button_box.append(&edit_btn);
                button_box.append(&delete_btn);
                mount_row.add_suffix(&button_box);

                group.add(&mount_row);
            }
        }
        group
    }

    /// Refresh the mounts group by replacing the entire PreferencesGroup inside the wrapper Box
    fn refresh_mounts_group(wrapper: &std::rc::Rc<Box>) {
        // Remove old group from wrapper
        while let Some(child) = wrapper.first_child() {
            wrapper.remove(&child);
        }
        // Build and append a fresh group
        let group = build_mounts_group(wrapper);
        wrapper.append(&group);
    }

    /// Remove a mount entry and refresh the UI
    /// Helper: spawn blocking work on a background thread and run a callback
    /// on the GTK main thread with the result. This avoids freezing the UI
    /// during sudo / mount / umount operations.
    fn spawn_blocking_then<T, F, C>(work: F, callback: C)
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
        C: FnOnce(T) + 'static,
    {
        let (tx, rx) = std::sync::mpsc::channel::<T>();
        std::thread::spawn(move || {
            let result = work();
            let _ = tx.send(result);
        });
        // Poll the channel on the main thread until the result arrives.
        let cb = std::cell::RefCell::new(Some(callback));
        glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
            match rx.try_recv() {
                Ok(val) => {
                    if let Some(f) = cb.borrow_mut().take() {
                        f(val);
                    }
                    glib::ControlFlow::Break
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => glib::ControlFlow::Break,
            }
        });
    }

    fn remove_systemd_mount_entry(mount_point: &str, wrapper: &std::rc::Rc<Box>) {
        let mp = mount_point.to_string();
        let w = wrapper.clone();
        spawn_blocking_then(
            move || remove_systemd_mount_unit(&mp),
            move |result| {
                match result {
                    Ok(()) => {
                        show_success_toast("Mount removed");
                        refresh_mounts_group(&w);
                    }
                    Err(e) => show_error_toast(&format!("Failed to remove mount: {}", e)),
                }
            },
        );
    }

    /// Toggle a systemd mount unit between enabled and disabled.
    /// When enabling, starts the unit. When disabling, stops it.
    fn toggle_systemd_mount(mount_point: &str, enable: bool, has_automount: bool, wrapper: &std::rc::Rc<Box>) {
        let mp = mount_point.to_string();
        let w = wrapper.clone();
        spawn_blocking_then(
            move || {
                use crate::services::privileged_executor;
                use crate::services::SystemdMountManager;

                let mount_unit = SystemdMountManager::mount_unit_name(&mp);
                let automount_unit = SystemdMountManager::automount_unit_name(&mp);

                if enable {
                    let target_unit = if has_automount {
                        &automount_unit
                    } else {
                        &mount_unit
                    };

                    let (_out, stderr, ok) = privileged_executor::run_privileged(
                        "systemctl", &["enable", "--now", target_unit],
                    ).map_err(|e| format!("Failed to enable {}: {}", target_unit, e))?;

                    if !ok {
                        return Err(format!("systemctl enable --now {} failed: {}", target_unit, stderr.trim()));
                    }

                    // systemctl enable --now can return 0 even when the mount
                    // fails asynchronously. Check the actual unit state and
                    // pull journal output when it didn't come up.
                    std::thread::sleep(std::time::Duration::from_millis(500));

                    let check_unit = if has_automount { &automount_unit } else { &mount_unit };
                    let (status_out, _, _) = privileged_executor::run_privileged(
                        "systemctl", &["is-active", check_unit],
                    ).map_err(|e| format!("Failed to check unit status: {}", e))?;

                    let status = status_out.trim();
                    if status != "active" {
                        // Grab the last few journal lines for the mount unit
                        // so the user sees *why* it failed.
                        let (journal, _, _) = privileged_executor::run_privileged(
                            "journalctl", &["-u", &mount_unit, "-n", "10", "--no-pager", "-o", "short"],
                        ).unwrap_or_default();

                        let detail = if journal.trim().is_empty() {
                            stderr.trim().to_string()
                        } else {
                            journal.trim().to_string()
                        };

                        return Err(format!(
                            "Unit {} is '{}' after enable. Journal:\n{}",
                            check_unit, status, detail
                        ));
                    }

                    Ok(())
                } else {
                    // Stop and disable
                    if has_automount {
                        let _ = privileged_executor::run_privileged(
                            "systemctl", &["disable", "--now", &automount_unit],
                        );
                    }
                    let (_out, stderr, ok) = privileged_executor::run_privileged(
                        "systemctl", &["disable", "--now", &mount_unit],
                    ).map_err(|e| format!("Failed to disable mount: {}", e))?;
                    if !ok {
                        return Err(format!("systemctl disable mount failed: {}", stderr.trim()));
                    }

                    // Remove the mount point directory if it's empty
                    let _ = privileged_executor::run_privileged(
                        "rmdir", &[&mp],
                    );

                    Ok(())
                }
            },
            move |result: Result<(), String>| {
                match result {
                    Ok(()) => {
                        if enable {
                            show_success_toast("Mount enabled and started");
                        } else {
                            show_success_toast("Mount disabled and stopped");
                        }
                        refresh_mounts_group(&w);
                    }
                    Err(e) => {
                        show_error_toast(&format!("Failed to toggle mount: {}", e));
                        log::error!("toggle_systemd_mount failed: {}", e);
                        refresh_mounts_group(&w);
                    }
                }
            },
        );
    }

    fn create_client_config_page_widget() -> ScrolledWindow {
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
                refresh_mounts_group(&w);
            });
            wizard.present();
        });

        let view_units_button = Button::builder()
            .label("View Unit Files")
            .css_classes(["flat"])
            .tooltip_text("Show the systemd mount unit files")
            .build();

        view_units_button.connect_clicked(|btn| {
            let parent = btn.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            show_unit_viewer(parent.as_ref());
        });

        let button_box = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .build();
        button_box.append(&add_button);
        button_box.append(&view_units_button);
        content.append(&button_box);

        // Export/Import section for client mounts
        let export_import_group = adw::PreferencesGroup::builder()
            .title("Export / Import")
            .description("Export mount configurations as JSON for transfer to another machine")
            .build();

        let export_mounts_button = Button::builder()
            .label("Export Mounts as JSON")
            .css_classes(["flat"])
            .tooltip_text("Save all client mount configurations to a portable JSON file")
            .build();

        export_mounts_button.connect_clicked(move |_btn| {
            let mount_manager = crate::services::SystemdMountManager::new();
            let mounts = mount_manager.list_mounts().unwrap_or_default();

            if mounts.is_empty() {
                show_error_toast("No mounts to export");
                return;
            }

            let file_dialog = gtk::FileDialog::builder()
                .title("Export Client Mounts")
                .initial_name("samba-mounts.json")
                .build();

            file_dialog.save(
                None::<&adw::Window>,
                None::<&gtk::gio::Cancellable>,
                move |result| {
                    if let Ok(file) = result {
                        if let Some(path) = file.path() {
                            match crate::services::config_export::export_mounts_json(&mounts, &path) {
                                Ok(()) => show_success_toast(&format!("Exported {} mount(s) to {}", mounts.len(), path.display())),
                                Err(e) => show_error_toast(&format!("Export failed: {}", e)),
                            }
                        }
                    }
                },
            );
        });
        export_import_group.add(&export_mounts_button);

        let import_mounts_button = Button::builder()
            .label("Import Mounts from JSON")
            .css_classes(["flat"])
            .tooltip_text("Load mount configurations from a previously exported JSON file and create systemd units")
            .build();

        let wrapper_for_import = mounts_wrapper.clone();
        import_mounts_button.connect_clicked(move |_btn| {
            let file_dialog = gtk::FileDialog::builder()
                .title("Import Client Mounts")
                .build();

            let wrapper = wrapper_for_import.clone();
            file_dialog.open(
                None::<&adw::Window>,
                None::<&gtk::gio::Cancellable>,
                move |result| {
                    if let Ok(file) = result {
                        if let Some(path) = file.path() {
                            match crate::services::config_export::import_mounts_json(&path) {
                                Ok(entries) => {
                                    let count = entries.len();
                                    let w = wrapper.clone();
                                    // Write each mount unit in the background
                                    spawn_blocking_then(
                                        move || {
                                            let mut errors = Vec::new();
                                            for entry in &entries {
                                                if let Err(e) = write_systemd_mount_unit(entry) {
                                                    errors.push(format!("{}: {}", entry.mount_point, e));
                                                }
                                            }
                                            (count, errors)
                                        },
                                        move |(total, errors)| {
                                            if errors.is_empty() {
                                                show_success_toast(&format!("Imported {} mount(s) successfully", total));
                                            } else {
                                                show_error_toast(&format!(
                                                    "Imported with {} error(s): {}",
                                                    errors.len(),
                                                    errors.first().unwrap_or(&String::new())
                                                ));
                                            }
                                            refresh_mounts_group(&w);
                                        },
                                    );
                                }
                                Err(e) => show_error_toast(&format!("Import failed: {}", e)),
                            }
                        }
                    }
                },
            );
        });
        export_import_group.add(&import_mounts_button);

        content.append(&export_import_group);

        scrolled.set_child(Some(&content));
        scrolled
    }

    /// Show a read-only dialog displaying the systemd mount unit files
    fn show_unit_viewer(parent: Option<&gtk::Window>) {
        let mount_manager = crate::services::SystemdMountManager::new();
        let mounts = mount_manager.list_mounts().unwrap_or_default();

        if mounts.is_empty() {
            show_toast("No CIFS mount units found");
            return;
        }

        // Collect all unit file contents
        let mut content_text = String::new();
        for mount in &mounts {
            let unit_name = crate::services::SystemdMountManager::mount_unit_name(&mount.mount_point);
            content_text.push_str(&format!("# {}\n", unit_name));
            match mount_manager.read_unit(&mount.mount_point) {
                Ok(c) => content_text.push_str(&c),
                Err(e) => content_text.push_str(&format!("# Error reading unit: {}\n", e)),
            }
            content_text.push_str("\n---\n\n");
        }

        let dialog = adw::Window::builder()
            .title("Systemd Mount Units")
            .default_width(900)
            .default_height(500)
            .modal(true)
            .build();

        if let Some(win) = parent {
            dialog.set_transient_for(Some(win));
        }

        let toolbar_view = adw::ToolbarView::new();
        toolbar_view.add_top_bar(&adw::HeaderBar::new());

        let scrolled = ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .build();

        let text_view = gtk::TextView::builder()
            .editable(false)
            .cursor_visible(false)
            .monospace(true)
            .left_margin(16)
            .right_margin(16)
            .top_margin(12)
            .bottom_margin(12)
            .build();

        text_view.buffer().set_text(&content_text);

        scrolled.set_child(Some(&text_view));
        toolbar_view.set_content(Some(&scrolled));
        dialog.set_content(Some(&toolbar_view));
        dialog.present();
    }

    /// Builds the service management content directly for the stack
    fn create_service_management_page_widget() -> ScrolledWindow {
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
            .label("Service Management")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        let desc = Label::builder()
            .label("Manage Samba daemon services (smbd, nmbd, winbind)")
            .css_classes(["body"])
            .halign(Align::Start)
            .build();
        content.append(&desc);

        let services_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(8)
            .build();

        // Populate service rows
        fn populate_services(services_box: &Box) {
            // Clear existing children
            while let Some(child) = services_box.first_child() {
                services_box.remove(&child);
            }

            let controller = crate::services::ServiceController::new();
            let services = crate::services::ServiceController::managed_services();
            for service_name in services {
                let row = Box::builder()
                    .orientation(Orientation::Horizontal)
                    .spacing(12)
                    .build();
                let name_label = Label::builder()
                    .label(service_name)
                    .halign(Align::Start)
                    .hexpand(true)
                    .css_classes(["heading"])
                    .build();
                row.append(&name_label);

                let status_text = match controller.get_status(service_name) {
                    Ok(s) => if s.active { format!("Active ({})", s.substate) } else { format!("Inactive ({})", s.substate) },
                    Err(_) => "Unknown".to_string(),
                };
                let status_label = Label::builder().label(&status_text).build();
                row.append(&status_label);

                // Start button
                let start_btn = Button::builder().label("Start").css_classes(["flat", "suggested-action"]).build();
                let svc = service_name.to_string();
                let sb = services_box.clone();
                start_btn.connect_clicked(move |_| {
                    let svc_clone = svc.clone();
                    let sb_clone = sb.clone();
                    spawn_blocking_then(
                        move || {
                            let ctrl = crate::services::ServiceController::new();
                            ctrl.start(&svc_clone).map(|()| svc_clone)
                        },
                        move |result| {
                            match result {
                                Ok(name) => show_success_toast(&format!("{} started", name)),
                                Err(e) => show_error_toast(&format!("Start failed: {}", e)),
                            }
                            populate_services(&sb_clone);
                        },
                    );
                });
                row.append(&start_btn);

                // Stop button
                let stop_btn = Button::builder().label("Stop").css_classes(["flat", "destructive-action"]).build();
                let svc = service_name.to_string();
                let sb = services_box.clone();
                stop_btn.connect_clicked(move |_| {
                    let svc_clone = svc.clone();
                    let sb_clone = sb.clone();
                    spawn_blocking_then(
                        move || {
                            let ctrl = crate::services::ServiceController::new();
                            ctrl.stop(&svc_clone).map(|()| svc_clone)
                        },
                        move |result| {
                            match result {
                                Ok(name) => show_success_toast(&format!("{} stopped", name)),
                                Err(e) => show_error_toast(&format!("Stop failed: {}", e)),
                            }
                            populate_services(&sb_clone);
                        },
                    );
                });
                row.append(&stop_btn);

                // Restart button
                let restart_btn = Button::builder().label("Restart").css_classes(["flat"]).build();
                let svc = service_name.to_string();
                let sb = services_box.clone();
                restart_btn.connect_clicked(move |_| {
                    let svc_clone = svc.clone();
                    let sb_clone = sb.clone();
                    spawn_blocking_then(
                        move || {
                            let ctrl = crate::services::ServiceController::new();
                            ctrl.restart(&svc_clone).map(|()| svc_clone)
                        },
                        move |result| {
                            match result {
                                Ok(name) => show_success_toast(&format!("{} restarted", name)),
                                Err(e) => show_error_toast(&format!("Restart failed: {}", e)),
                            }
                            populate_services(&sb_clone);
                        },
                    );
                });
                row.append(&restart_btn);

                services_box.append(&row);
            }
        }

        populate_services(&services_box);
        content.append(&services_box);

        // Refresh button
        let refresh_btn = Button::builder().label("Refresh Status").css_classes(["flat"]).build();
        let sb = services_box.clone();
        refresh_btn.connect_clicked(move |_| {
            populate_services(&sb);
        });
        content.append(&refresh_btn);

        scrolled.set_child(Some(&content));
        scrolled
    }

    /// Builds the user management content directly for the stack
    fn create_user_management_page_widget() -> ScrolledWindow {
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
            .label("User Management - This is still a work in progress")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        let desc = Label::builder()
            .label("Manage SAMBA user accounts")
            .css_classes(["body"])
            .halign(Align::Start)
            .build();
        content.append(&desc);

        // Placeholder while loading
        let spinner = Spinner::builder()
            .spinning(true)
            .width_request(32)
            .height_request(32)
            .halign(Align::Center)
            .valign(Align::Center)
            .build();
        content.append(&spinner);

        let loading_label = Label::builder()
            .label("Loading users…")
            .css_classes(["dimmed", "caption"])
            .halign(Align::Center)
            .build();
        content.append(&loading_label);

        scrolled.set_child(Some(&content));

        // Load users on a background thread to avoid blocking the GTK main loop.
        // UserManager::new() runs testparm and list_users() runs pdbedit via
        // the privileged executor, both of which can block or deadlock if run
        // on the main thread.
        let content_ref = content.clone();
        spawn_blocking_then(
            move || {
                let manager = crate::services::UserManager::new();
                manager.list_users()
            },
            move |result| {
                // Remove spinner and loading label
                content_ref.remove(&spinner);
                content_ref.remove(&loading_label);

                match result {
                    Ok(users) => {
                        if users.is_empty() {
                            let empty = Label::builder()
                                .label("No SAMBA users found.")
                                .css_classes(["dimmed", "caption"])
                                .halign(Align::Start)
                                .build();
                            content_ref.append(&empty);
                        } else {
                            for user in users {
                                let row = Box::builder()
                                    .orientation(Orientation::Horizontal)
                                    .spacing(12)
                                    .build();
                                let name_label = Label::builder()
                                    .label(&user.username)
                                    .halign(Align::Start)
                                    .hexpand(true)
                                    .build();
                                row.append(&name_label);
                                let status = Label::builder()
                                    .label(if user.enabled { "Enabled" } else { "Disabled" })
                                    .build();
                                row.append(&status);
                                content_ref.append(&row);
                            }
                        }
                    }
                    Err(e) => {
                        let err = Label::builder()
                            .label(&format!("Failed to load users: {}", e))
                            .css_classes(["error"])
                            .halign(Align::Start)
                            .build();
                        content_ref.append(&err);
                    }
                }
            },
        );

        scrolled
    }

    /// Builds the backup content directly for the stack
    fn create_backup_page_widget() -> ScrolledWindow {
        let scrolled = ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .build();

        let page = super::backup_view::create_backup_page();
        scrolled.set_child(Some(&page));
        scrolled
    }

    /// Fetch dmesg output, optionally filtered for SMB/CIFS messages.
    ///
    /// Tries unprivileged `dmesg` first; falls back to `sudo dmesg` via
    /// the privileged executor if permission is denied.
    fn fetch_dmesg(filter_smb: bool) -> Result<String, String> {
        use std::process::Command;

        // Try unprivileged first
        let output = Command::new("dmesg")
            .args(["--time-format", "reltime", "--nopager"])
            .output()
            .map_err(|e| format!("Failed to run dmesg: {}", e))?;

        let text = if output.status.success() {
            String::from_utf8_lossy(&output.stdout).into_owned()
        } else {
            // Permission denied — try with sudo
            let (stdout, stderr, ok) = crate::services::privileged_executor::run_privileged(
                "dmesg", &["--time-format", "reltime", "--nopager"],
            ).map_err(|e| format!("Failed to run dmesg: {}", e))?;

            if !ok {
                return Err(format!("dmesg failed: {}", stderr.trim()));
            }
            stdout
        };

        if filter_smb {
            let filtered: Vec<&str> = text
                .lines()
                .filter(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower.contains("cifs")
                        || lower.contains("smb")
                        || lower.contains("samba")
                        || lower.contains("mount")
                })
                .collect();

            if filtered.is_empty() {
                Ok("No SMB/CIFS/mount-related messages found in dmesg.".to_string())
            } else {
                Ok(filtered.join("\n"))
            }
        } else {
            Ok(text)
        }
    }

    /// Fetch journalctl output for Samba-related systemd units.
    ///
    /// When `filter_smb` is true, only shows logs from smbd, nmbd, winbind,
    /// and any CIFS .mount / .automount units. When false, shows the full
    /// system journal (last 500 lines).
    fn fetch_journalctl(filter_smb: bool) -> Result<String, String> {
        use std::process::Command;

        if filter_smb {
            // Collect output from multiple Samba-related units into one view.
            // journalctl supports multiple -u flags.
            let mut args: Vec<&str> = vec![
                "--no-pager", "-o", "short-iso", "-n", "500",
                "-u", "smbd",
                "-u", "nmbd",
                "-u", "winbind",
                "-u", "samba-ad-dc",
            ];

            // Also include any CIFS mount/automount units.
            // We discover them from /etc/systemd/system/*.mount files.
            let cifs_units = discover_cifs_unit_names();
            // journalctl args need to live long enough, so collect owned strings
            let extra_args: Vec<String> = cifs_units.iter()
                .flat_map(|u| vec!["-u".to_string(), u.clone()])
                .collect();
            let extra_refs: Vec<&str> = extra_args.iter().map(|s| s.as_str()).collect();
            args.extend(extra_refs);

            let output = Command::new("journalctl")
                .args(&args)
                .output()
                .map_err(|e| format!("Failed to run journalctl: {}", e))?;

            let text = if output.status.success() {
                String::from_utf8_lossy(&output.stdout).into_owned()
            } else {
                // journalctl may need privileges for some logs
                let priv_args = args.clone();
                let (stdout, stderr, ok) = crate::services::privileged_executor::run_privileged(
                    "journalctl", &priv_args,
                ).map_err(|e| format!("Failed to run journalctl: {}", e))?;

                if !ok {
                    return Err(format!("journalctl failed: {}", stderr.trim()));
                }
                stdout
            };

            if text.trim().is_empty() || text.trim() == "-- No entries --" {
                Ok("No Samba/CIFS-related journal entries found.\n\nChecked units: smbd, nmbd, winbind, samba-ad-dc, and CIFS mount units.".to_string())
            } else {
                Ok(text)
            }
        } else {
            // Full journal, last 500 lines
            let output = Command::new("journalctl")
                .args(["--no-pager", "-o", "short-iso", "-n", "500"])
                .output()
                .map_err(|e| format!("Failed to run journalctl: {}", e))?;

            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).into_owned())
            } else {
                let (stdout, stderr, ok) = crate::services::privileged_executor::run_privileged(
                    "journalctl", &["--no-pager", "-o", "short-iso", "-n", "500"],
                ).map_err(|e| format!("Failed to run journalctl: {}", e))?;

                if !ok {
                    return Err(format!("journalctl failed: {}", stderr.trim()));
                }
                Ok(stdout)
            }
        }
    }

    /// Discover CIFS .mount and .automount unit names from /etc/systemd/system.
    fn discover_cifs_unit_names() -> Vec<String> {
        let dir = std::path::Path::new("/etc/systemd/system");
        let mut units = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".mount") {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if content.contains("Type=cifs") || content.contains("Type=smbfs") {
                            units.push(name.clone());
                            // Also add the companion .automount if it exists
                            let automount = name.replace(".mount", ".automount");
                            if dir.join(&automount).exists() {
                                units.push(automount);
                            }
                        }
                    }
                }
            }
        }
        units
    }

    /// Builds the logs page with tabs for dmesg and journalctl
    fn create_logs_page_widget() -> ScrolledWindow {
        let outer_scrolled = ScrolledWindow::builder()
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
            .label("System Logs")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        let desc = Label::builder()
            .label("View kernel and systemd journal messages for diagnosing SMB/CIFS issues")
            .css_classes(["body"])
            .halign(Align::Start)
            .build();
        content.append(&desc);

        // Tab stack for dmesg vs journalctl
        let log_stack = Stack::builder()
            .transition_type(StackTransitionType::Crossfade)
            .transition_duration(150)
            .vexpand(true)
            .build();

        // ── dmesg tab ──
        let dmesg_box = build_dmesg_tab();
        log_stack.add_titled(&dmesg_box, Some("dmesg"), "Kernel (dmesg)");

        // ── journalctl tab ──
        let journal_box = build_journalctl_tab();
        log_stack.add_titled(&journal_box, Some("journal"), "Journal (journalctl)");

        // ── Samba log files tab ──
        let samba_log_box = build_samba_log_tab();
        log_stack.add_titled(&samba_log_box, Some("samba-log"), "Samba Logs");

        // Stack switcher (tab bar)
        let switcher = gtk::StackSwitcher::builder()
            .stack(&log_stack)
            .halign(Align::Center)
            .build();
        content.append(&switcher);
        content.append(&log_stack);

        outer_scrolled.set_child(Some(&content));
        outer_scrolled
    }

    /// Helper: scroll a ScrolledWindow to the bottom after the next layout pass
    fn scroll_to_bottom(scrolled: &ScrolledWindow) {
        let adj = scrolled.vadjustment();
        gtk::glib::idle_add_local_once(move || {
            adj.set_value(adj.upper() - adj.page_size());
        });
    }

    /// Build the dmesg tab content
    fn build_dmesg_tab() -> Box {
        let tab = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(12)
            .build();

        // Filter toggle
        let filter_group = adw::PreferencesGroup::builder()
            .title("Filter")
            .build();

        let filter_row = ActionRow::builder()
            .title("Show only SMB/CIFS messages")
            .subtitle("Filter for lines containing cifs, smb, samba, or mount")
            .build();

        let filter_switch = gtk::Switch::builder()
            .active(true)
            .valign(Align::Center)
            .tooltip_text("Toggle between filtered and full dmesg output")
            .build();
        filter_row.add_suffix(&filter_switch);
        filter_group.add(&filter_row);
        tab.append(&filter_group);

        // Log output area
        let log_scrolled = ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .min_content_height(300)
            .build();

        let text_view = gtk::TextView::builder()
            .editable(false)
            .cursor_visible(false)
            .monospace(true)
            .left_margin(12)
            .right_margin(12)
            .top_margin(8)
            .bottom_margin(8)
            .wrap_mode(gtk::WrapMode::WordChar)
            .build();

        log_scrolled.set_child(Some(&text_view));
        tab.append(&log_scrolled);

        // Load initial content (filtered) and scroll to bottom
        match fetch_dmesg(true) {
            Ok(text) => text_view.buffer().set_text(&text),
            Err(e) => text_view.buffer().set_text(&format!("Error: {}", e)),
        }
        scroll_to_bottom(&log_scrolled);

        // Refresh button
        let refresh_button = Button::builder()
            .label("Refresh")
            .css_classes(["flat", "suggested-action"])
            .tooltip_text("Reload dmesg output")
            .build();

        let tv_for_refresh = text_view.clone();
        let sw_for_refresh = filter_switch.clone();
        let scroll_for_refresh = log_scrolled.clone();
        refresh_button.connect_clicked(move |_| {
            let filtered = sw_for_refresh.is_active();
            match fetch_dmesg(filtered) {
                Ok(text) => {
                    tv_for_refresh.buffer().set_text(&text);
                    scroll_to_bottom(&scroll_for_refresh);
                    show_success_toast("dmesg refreshed");
                }
                Err(e) => {
                    tv_for_refresh.buffer().set_text(&format!("Error: {}", e));
                    show_error_toast(&format!("Failed to load dmesg: {}", e));
                }
            }
        });

        tab.append(&refresh_button);

        // Re-fetch when the filter toggle changes
        let tv_for_toggle = text_view;
        let scroll_for_toggle = log_scrolled;
        filter_switch.connect_state_set(move |_, active| {
            match fetch_dmesg(active) {
                Ok(text) => tv_for_toggle.buffer().set_text(&text),
                Err(e) => tv_for_toggle.buffer().set_text(&format!("Error: {}", e)),
            }
            scroll_to_bottom(&scroll_for_toggle);
            gtk::glib::Propagation::Proceed
        });

        tab
    }

    /// Build the journalctl tab content
    fn build_journalctl_tab() -> Box {
        let tab = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(12)
            .build();

        // Filter toggle
        let filter_group = adw::PreferencesGroup::builder()
            .title("Filter")
            .build();

        let filter_row = ActionRow::builder()
            .title("Show only Samba/CIFS units")
            .subtitle("Filter for smbd, nmbd, winbind, and CIFS mount units")
            .build();

        let filter_switch = gtk::Switch::builder()
            .active(true)
            .valign(Align::Center)
            .tooltip_text("Toggle between Samba-filtered and full journal output")
            .build();
        filter_row.add_suffix(&filter_switch);
        filter_group.add(&filter_row);
        tab.append(&filter_group);

        // Log output area
        let log_scrolled = ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .min_content_height(300)
            .build();

        let text_view = gtk::TextView::builder()
            .editable(false)
            .cursor_visible(false)
            .monospace(true)
            .left_margin(12)
            .right_margin(12)
            .top_margin(8)
            .bottom_margin(8)
            .wrap_mode(gtk::WrapMode::WordChar)
            .build();

        log_scrolled.set_child(Some(&text_view));
        tab.append(&log_scrolled);

        // Load initial content (filtered) and scroll to bottom
        match fetch_journalctl(true) {
            Ok(text) => text_view.buffer().set_text(&text),
            Err(e) => text_view.buffer().set_text(&format!("Error: {}", e)),
        }
        scroll_to_bottom(&log_scrolled);

        // Refresh button
        let refresh_button = Button::builder()
            .label("Refresh")
            .css_classes(["flat", "suggested-action"])
            .tooltip_text("Reload journal output")
            .build();

        let tv_for_refresh = text_view.clone();
        let sw_for_refresh = filter_switch.clone();
        let scroll_for_refresh = log_scrolled.clone();
        refresh_button.connect_clicked(move |_| {
            let filtered = sw_for_refresh.is_active();
            match fetch_journalctl(filtered) {
                Ok(text) => {
                    tv_for_refresh.buffer().set_text(&text);
                    scroll_to_bottom(&scroll_for_refresh);
                    show_success_toast("Journal refreshed");
                }
                Err(e) => {
                    tv_for_refresh.buffer().set_text(&format!("Error: {}", e));
                    show_error_toast(&format!("Failed to load journal: {}", e));
                }
            }
        });

        tab.append(&refresh_button);

        // Re-fetch when the filter toggle changes
        let tv_for_toggle = text_view;
        let scroll_for_toggle = log_scrolled;
        filter_switch.connect_state_set(move |_, active| {
            match fetch_journalctl(active) {
                Ok(text) => tv_for_toggle.buffer().set_text(&text),
                Err(e) => tv_for_toggle.buffer().set_text(&format!("Error: {}", e)),
            }
            scroll_to_bottom(&scroll_for_toggle);
            gtk::glib::Propagation::Proceed
        });

        tab
    }

    /// Build the Samba log files tab — reads from /var/log/samba/
    fn build_samba_log_tab() -> Box {
        let tab = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(12)
            .build();

        // File selector group
        let file_group = adw::PreferencesGroup::builder()
            .title("Log File")
            .description("Select a log file from /var/log/samba/")
            .build();

        // Discover available log files
        let log_files = discover_samba_log_files();
        let file_names: Vec<&str> = log_files.iter().map(|s| s.as_str()).collect();

        let default_file = if file_names.contains(&"log.smbd") {
            "log.smbd"
        } else if let Some(first) = file_names.first() {
            first
        } else {
            ""
        };

        let file_combo = if !file_names.is_empty() {
            let combo = add_combo(&file_group, "File", &file_names, default_file,
                "Choose which Samba log file to view");
            tab.append(&file_group);
            Some(combo)
        } else {
            tab.append(&file_group);
            None
        };

        // Tail lines selector
        let lines_group = adw::PreferencesGroup::builder()
            .title("Display")
            .build();
        let lines_choices = &["100", "250", "500", "1000", "All"];
        let lines_combo = add_combo(&lines_group, "Lines to show", lines_choices, "500",
            "Number of lines to display from the end of the file");
        tab.append(&lines_group);

        // Log output area
        let log_scrolled = ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .min_content_height(300)
            .build();

        let text_view = gtk::TextView::builder()
            .editable(false)
            .cursor_visible(false)
            .monospace(true)
            .left_margin(12)
            .right_margin(12)
            .top_margin(8)
            .bottom_margin(8)
            .wrap_mode(gtk::WrapMode::WordChar)
            .build();

        log_scrolled.set_child(Some(&text_view));
        tab.append(&log_scrolled);

        // Load initial content
        if !default_file.is_empty() {
            match fetch_samba_log_file(default_file, 500) {
                Ok(text) => text_view.buffer().set_text(&text),
                Err(e) => text_view.buffer().set_text(&format!("Error: {}", e)),
            }
            scroll_to_bottom(&log_scrolled);
        } else {
            text_view.buffer().set_text("No log files found in /var/log/samba/\n\nEnsure Samba is installed and has been started at least once.");
        }

        // Refresh button
        let refresh_button = Button::builder()
            .label("Refresh")
            .css_classes(["flat", "suggested-action"])
            .tooltip_text("Reload the selected log file")
            .build();

        let tv_for_refresh = text_view.clone();
        let scroll_for_refresh = log_scrolled.clone();
        let file_combo_for_refresh = file_combo.clone();
        let lines_combo_for_refresh = lines_combo.clone();
        refresh_button.connect_clicked(move |_| {
            let filename = file_combo_for_refresh.as_ref()
                .map(|c| combo_value(c))
                .unwrap_or_default();
            let lines = parse_lines_choice(&combo_value(&lines_combo_for_refresh));

            if filename.is_empty() {
                tv_for_refresh.buffer().set_text("No log file selected");
                return;
            }

            match fetch_samba_log_file(&filename, lines) {
                Ok(text) => {
                    tv_for_refresh.buffer().set_text(&text);
                    scroll_to_bottom(&scroll_for_refresh);
                    show_success_toast("Samba log refreshed");
                }
                Err(e) => {
                    tv_for_refresh.buffer().set_text(&format!("Error: {}", e));
                    show_error_toast(&format!("Failed to load log: {}", e));
                }
            }
        });

        tab.append(&refresh_button);

        // Auto-refresh when file selection changes
        if let Some(ref combo) = file_combo {
            let tv_for_combo = text_view.clone();
            let scroll_for_combo = log_scrolled.clone();
            let lines_combo_for_combo = lines_combo.clone();
            combo.connect_selected_notify(move |c| {
                let filename = combo_value(c);
                let lines = parse_lines_choice(&combo_value(&lines_combo_for_combo));
                match fetch_samba_log_file(&filename, lines) {
                    Ok(text) => {
                        tv_for_combo.buffer().set_text(&text);
                        scroll_to_bottom(&scroll_for_combo);
                    }
                    Err(e) => tv_for_combo.buffer().set_text(&format!("Error: {}", e)),
                }
            });
        }

        // Auto-refresh when lines selection changes
        {
            let tv_for_lines = text_view;
            let scroll_for_lines = log_scrolled;
            let file_combo_for_lines = file_combo;
            lines_combo.connect_selected_notify(move |c| {
                let lines = parse_lines_choice(&combo_value(c));
                let filename = file_combo_for_lines.as_ref()
                    .map(|fc| combo_value(fc))
                    .unwrap_or_default();
                if filename.is_empty() { return; }
                match fetch_samba_log_file(&filename, lines) {
                    Ok(text) => {
                        tv_for_lines.buffer().set_text(&text);
                        scroll_to_bottom(&scroll_for_lines);
                    }
                    Err(e) => tv_for_lines.buffer().set_text(&format!("Error: {}", e)),
                }
            });
        }

        tab
    }

    /// Parse the lines combo value into a number (0 = all)
    fn parse_lines_choice(value: &str) -> usize {
        match value {
            "All" => 0,
            s => s.parse().unwrap_or(500),
        }
    }

    /// Discover log files in /var/log/samba/, sorted by modification time (newest first)
    fn discover_samba_log_files() -> Vec<String> {
        let dir = std::path::Path::new("/var/log/samba");
        let mut files: Vec<(String, std::time::SystemTime)> = Vec::new();

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                // Only include regular files (skip directories like "cores")
                if path.is_file() {
                    if let Some(name) = path.file_name() {
                        let name = name.to_string_lossy().to_string();
                        let mtime = entry.metadata()
                            .and_then(|m| m.modified())
                            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                        files.push((name, mtime));
                    }
                }
            }
        }

        // Sort by modification time, newest first
        files.sort_by(|a, b| b.1.cmp(&a.1));
        files.into_iter().map(|(name, _)| name).collect()
    }

    /// Read a Samba log file from /var/log/samba/. Returns the last N lines
    /// (or all if lines == 0). Falls back to privileged read if permission denied.
    fn fetch_samba_log_file(filename: &str, lines: usize) -> Result<String, String> {
        // Sanitize filename — no path traversal
        if filename.contains('/') || filename.contains("..") {
            return Err("Invalid filename".to_string());
        }

        let path = format!("/var/log/samba/{}", filename);

        // Try reading directly first
        match std::fs::read_to_string(&path) {
            Ok(content) => Ok(tail_lines(&content, lines)),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // Fall back to privileged read
                let lines_str = lines.to_string();
                let args: Vec<&str> = if lines > 0 {
                    vec!["-n", &lines_str, &path]
                } else {
                    vec![path.as_str()]
                };
                let cmd = if lines > 0 { "tail" } else { "cat" };

                let (stdout, stderr, ok) = crate::services::privileged_executor::run_privileged(
                    cmd, &args,
                ).map_err(|e| format!("Failed to read log: {}", e))?;

                if !ok {
                    return Err(format!("Failed to read {}: {}", filename, stderr.trim()));
                }
                Ok(stdout)
            }
            Err(e) => Err(format!("Failed to read {}: {}", filename, e)),
        }
    }

    /// Return the last N lines of a string (or all if n == 0)
    fn tail_lines(content: &str, n: usize) -> String {
        if n == 0 {
            return content.to_string();
        }
        let lines: Vec<&str> = content.lines().collect();
        if lines.len() <= n {
            content.to_string()
        } else {
            lines[lines.len() - n..].join("\n")
        }
    }

    /// Creates a loading status page
    /// Requirement 5.3: Show loading indicators during long operations
    pub fn create_loading_page(message: &str) -> NavigationPage {
        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(16)
            .build();

        // Status page with spinner
        let status_page = StatusPage::builder()
            .title("Loading")
            .description(message)
            .build();

        // Create and start spinner
        let spinner = Spinner::new();
        spinner.set_spinning(true);
        spinner.set_size_request(48, 48);

        status_page.set_child(Some(&spinner));
        content.append(&status_page);

        NavigationPage::builder()
            .title("Loading")
            .name("loading")
            .child(&content)
            .build()
    }

    /// Creates an empty/error status page
    pub fn create_status_page(title: &str, description: &str, icon_name: Option<&str>) -> StatusPage {
        let mut builder = StatusPage::builder()
            .title(title)
            .description(description);

        if let Some(icon) = icon_name {
            builder = builder.icon_name(icon);
        }

        builder.build()
    }

    /// Creates the sidebar as a NavigationPage
    fn create_sidebar_page(content_stack: &Stack, content_page: &NavigationPage) -> NavigationPage {
        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(12)
            .margin_end(12)
            .margin_top(12)
            .margin_bottom(12)
            .spacing(8)
            .build();

        let sections: &[(&str, &str, bool)] = &[
            ("server", "Server", false),
            ("shares", "Shares", true),
            ("client", "Client", false),
            ("network", "Network", false),
            ("services", "Services", false),
            ("firewall", "Firewall", false),
            ("users", "Users", false),
            ("backup", "Backup", false),
            ("logs", "Logs", false),
        ];

        for &(id, label, is_child) in sections {
            let button = Button::builder()
                .label(label)
                .css_classes(["flat"])
                .hexpand(true)
                .build();

            if is_child {
                button.set_margin_start(16);
            }

            let stack = content_stack.clone();
            let page = content_page.clone();
            let section_id = id.to_string();
            let section_label = label.to_string();
            button.connect_clicked(move |_| {
                println!("Sidebar clicked: {} -> switching to {}", section_label, section_id);
                stack.set_visible_child_name(&section_id);
                page.set_title(&section_label);
            });

            content.append(&button);
        }

        // Spacer to push quit button to the bottom
        let spacer = Box::builder()
            .orientation(Orientation::Vertical)
            .vexpand(true)
            .build();
        content.append(&spacer);

        // Quit button
        let quit_button = Button::builder()
            .label("Quit")
            .css_classes(["flat", "destructive-action"])
            .hexpand(true)
            .build();
        quit_button.connect_clicked(|btn| {
            if let Some(root) = btn.root() {
                if let Ok(win) = root.downcast::<adw::Window>() {
                    win.close();
                }
            }
        });
        content.append(&quit_button);

        NavigationPage::builder()
            .title("Menu")
            .name("sidebar")
            .child(&content)
            .build()
    }

    /// Creates the server configuration page with global settings and shares
    fn create_server_config_page() -> NavigationPage {
        // Load configuration from default location or use defaults
        let config = load_config("/etc/samba/smb.conf").unwrap_or_else(|_| {
            // Try user config location
            load_config("/etc/smb.conf").unwrap_or_else(|_| {
                SambaConfig::default()
            })
        });

        // Use RefCell for interior mutability in closure
        let config = std::cell::RefCell::new(config);

        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(24)
            .margin_end(24)
            .margin_top(24)
            .margin_bottom(24)
            .spacing(16)
            .build();

        // Title
        let title = Label::builder()
            .label("Server Configuration")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        // Global Settings Section - get mutable references to rows
        let (global_group, global_rows) = create_global_settings_group(&config.borrow().global);
        content.append(&global_group);

        // Shares Section - pass global settings for testparm
        // Use a shared shares list so add/remove updates are visible to the save button
        let shared_shares = std::rc::Rc::new(std::cell::RefCell::new(config.borrow().shares.clone()));
        let shares_group = create_shares_group(&shared_shares, &config.borrow().global);
        content.append(&shares_group);

        // Save button
        let save_button = Button::builder()
            .label("Save Configuration")
            .css_classes(["suggested-action"])
            .build();
        
        // Clone config path for the closure
        let config_path = "/etc/samba/smb.conf".to_string();
        
        save_button.connect_clicked(move |button| {
            // Update config from UI values
            let mut config = config.borrow_mut();
            global_rows.update_config(&mut config);
            // Sync shares from the shared list
            config.shares = shared_shares.borrow().clone();
            
            // Validate and save
            match crate::config::ConfigParser::validate(&config) {
                Ok(()) => {
                    match crate::config::ConfigParser::serialize(&config) {
                        Ok(content) => {
                            // Move the privileged write off the main thread to
                            // avoid deadlocking when sudo needs re-auth.
                            let path = config_path.clone();
                            button.set_sensitive(false);
                            let btn = button.clone();
                            spawn_blocking_then(
                                move || {
                                    // Auto-backup before overwriting the config
                                    let source = std::path::Path::new(&path);
                                    if source.exists() || {
                                        std::process::Command::new("sudo")
                                            .args(["-n", "test", "-f", &path])
                                            .stdout(std::process::Stdio::null())
                                            .stderr(std::process::Stdio::null())
                                            .status()
                                            .map(|s| s.success())
                                            .unwrap_or(false)
                                    } {
                                        let backup_mgr = crate::services::backup_manager::BackupManager::new();
                                        match backup_mgr.backup(source) {
                                            Ok(info) => log::info!(
                                                "Auto-backup created before save: {}",
                                                info.path
                                            ),
                                            Err(e) => log::warn!(
                                                "Auto-backup failed (continuing with save): {}",
                                                e
                                            ),
                                        }
                                    }
                                    write_config_file(&path, &content)
                                },
                                move |result| {
                                    btn.set_sensitive(true);
                                    match result {
                                        Ok(()) => {
                                            show_success_toast("Configuration saved (auto-backup created)");
                                            println!("Configuration saved");
                                        }
                                        Err(e) => {
                                            show_error_toast(&format!("Failed to write config: {}", e));
                                            eprintln!("Failed to write config: {}", e);
                                        }
                                    }
                                },
                            );
                        }
                        Err(e) => {
                            show_error_toast(&format!("Failed to serialize config: {}", e));
                            eprintln!("Failed to serialize config: {}", e);
                        }
                    }
                }
                Err(e) => {
                    show_error_toast(&format!("Validation failed: {}", e));
                    eprintln!("Validation failed: {}", e);
                }
            }
        });
        
        content.append(&save_button);

        NavigationPage::builder()
            .title("Server")
            .name("server")
            .child(&content)
            .build()
    }

    /// Holds references to global settings rows for reading values
    struct GlobalSettingsRows {
        workgroup: EntryRow,
        server_string: EntryRow,
        netbios_name: EntryRow,
        security: ComboRow,
        guest_account: EntryRow,
        map_to_guest: ComboRow,
        socket_options: EntryRow,
        dns_proxy: gtk::Switch,
        passdb_backend: ComboRow,
        smb_encrypt: ComboRow,
        server_min_protocol: ComboRow,
        server_max_protocol: ComboRow,
        client_min_protocol: ComboRow,
        client_max_protocol: ComboRow,
        server_signing: ComboRow,
        client_signing: ComboRow,
        interfaces: EntryRow,
        bind_interfaces_only: gtk::Switch,
        hosts_allow: EntryRow,
        hosts_deny: EntryRow,
        wins_support: gtk::Switch,
        wins_server: EntryRow,
        name_resolve_order: EntryRow,
        realm: EntryRow,
        password_server: EntryRow,
        unix_password_sync: gtk::Switch,
        domain_master: gtk::Switch,
        local_master: gtk::Switch,
        preferred_master: gtk::Switch,
        os_level: EntryRow,
        logon_drive: EntryRow,
        logon_home: EntryRow,
        logon_path: EntryRow,
        logon_script: EntryRow,
        username_map: EntryRow,
        smb_passwd_file: EntryRow,
        wins_proxy: gtk::Switch,
        restrict_anonymous: ComboRow,
        ntlm_auth: ComboRow,
        client_ntlmv2_auth: gtk::Switch,
        wide_links: gtk::Switch,
        unix_extensions: gtk::Switch,
        case_sensitive: gtk::Switch,
        load_printers: gtk::Switch,
        disable_spoolss: gtk::Switch,
        log_file: EntryRow,
        log_level: EntryRow,
        max_log_size: EntryRow,
        read_raw: gtk::Switch,
        write_raw: gtk::Switch,
        max_xmit: EntryRow,
        deadtime: EntryRow,
        keepalive: EntryRow,
    }

    // Known SMB protocol versions
    const SMB_PROTOCOLS: &[&str] = &[
        "CORE", "COREPLUS", "LANMAN1", "LANMAN2", "NT1",
        "SMB2_02", "SMB2_10",
        "SMB3_00", "SMB3_02", "SMB3_11",
    ];
    const SECURITY_MODES: &[&str] = &["user", "share", "server", "domain", "ads"];
    const SMB_ENCRYPT_OPTS: &[&str] = &["off", "desired", "required", "if_required"];
    const SIGNING_OPTS: &[&str] = &["off", "auto", "mandatory", "desired", "required"];
    const MAP_TO_GUEST_OPTS: &[&str] = &["Never", "bad user", "Bad Password", "Bad Uid"];
    const PASSDB_BACKENDS: &[&str] = &["tdbsam", "ldapsam", "smbpasswd"];
    const RESTRICT_ANONYMOUS_OPTS: &[&str] = &["0", "1", "2"];
    const NTLM_AUTH_OPTS: &[&str] = &["ntlmv2-only", "yes", "no", "mschapv2-and-ntlmv2-only", "disabled"];

    impl GlobalSettingsRows {
        fn update_config(&self, config: &mut SambaConfig) {
            config.global.workgroup = self.workgroup.text().to_string();
            config.global.server_string = self.server_string.text().to_string();
            config.global.netbios_name = self.netbios_name.text().to_string();
            let sec = combo_value(&self.security);
            config.global.security = match sec.to_lowercase().as_str() {
                "user" => crate::config::SecurityMode::User,
                "share" => crate::config::SecurityMode::Share,
                "server" => crate::config::SecurityMode::Server,
                "domain" => crate::config::SecurityMode::Domain,
                "ads" => crate::config::SecurityMode::ADS,
                _ => crate::config::SecurityMode::User,
            };
            config.global.guest_account = self.guest_account.text().to_string();
            config.global.map_to_guest = combo_value(&self.map_to_guest);
            config.global.socket_options = self.socket_options.text().to_string();
            config.global.dns_proxy = self.dns_proxy.is_active();
            config.global.passdb_backend = combo_value(&self.passdb_backend);
            config.global.smb_encrypt = combo_value(&self.smb_encrypt);
            config.global.server_min_protocol = combo_value(&self.server_min_protocol);
            config.global.server_max_protocol = combo_value(&self.server_max_protocol);
            config.global.client_min_protocol = combo_value(&self.client_min_protocol);
            config.global.client_max_protocol = combo_value(&self.client_max_protocol);
            config.global.server_signing = combo_value(&self.server_signing);
            config.global.client_signing = combo_value(&self.client_signing);
            config.global.interfaces = self.interfaces.text().to_string();
            config.global.bind_interfaces_only = self.bind_interfaces_only.is_active();
            config.global.hosts_allow = self.hosts_allow.text().to_string();
            config.global.hosts_deny = self.hosts_deny.text().to_string();
            config.global.wins_support = self.wins_support.is_active();
            config.global.wins_server = self.wins_server.text().to_string();
            config.global.name_resolve_order = self.name_resolve_order.text().to_string();
            config.global.realm = self.realm.text().to_string();
            config.global.password_server = self.password_server.text().to_string();
            config.global.unix_password_sync = self.unix_password_sync.is_active();
            config.global.domain_master = self.domain_master.is_active();
            config.global.local_master = self.local_master.is_active();
            config.global.preferred_master = self.preferred_master.is_active();
            config.global.os_level = self.os_level.text().to_string().parse().unwrap_or(20);
            config.global.logon_drive = self.logon_drive.text().to_string();
            config.global.logon_home = self.logon_home.text().to_string();
            config.global.logon_path = self.logon_path.text().to_string();
            config.global.logon_script = self.logon_script.text().to_string();
            config.global.username_map = self.username_map.text().to_string();
            config.global.smb_passwd_file = self.smb_passwd_file.text().to_string();
            config.global.wins_proxy = self.wins_proxy.is_active();
            config.global.restrict_anonymous = combo_value(&self.restrict_anonymous).parse().unwrap_or(0);
            config.global.ntlm_auth = combo_value(&self.ntlm_auth);
            config.global.client_ntlmv2_auth = self.client_ntlmv2_auth.is_active();
            config.global.wide_links = self.wide_links.is_active();
            config.global.unix_extensions = self.unix_extensions.is_active();
            config.global.case_sensitive = self.case_sensitive.is_active();
            config.global.load_printers = self.load_printers.is_active();
            config.global.disable_spoolss = self.disable_spoolss.is_active();
            config.global.log_file = self.log_file.text().to_string();
            config.global.log_level = self.log_level.text().to_string();
            config.global.max_log_size = self.max_log_size.text().to_string().parse().unwrap_or(1000);
            config.global.read_raw = self.read_raw.is_active();
            config.global.write_raw = self.write_raw.is_active();
            config.global.max_xmit = self.max_xmit.text().to_string().parse().unwrap_or(65535);
            config.global.deadtime = self.deadtime.text().to_string().parse().unwrap_or(0);
            config.global.keepalive = self.keepalive.text().to_string().parse().unwrap_or(300);
        }

        /// Apply a GlobalSettings template to the UI rows
        fn apply_from(&self, g: &GlobalSettings) {
            self.workgroup.set_text(&g.workgroup);
            self.server_string.set_text(&g.server_string);
            self.netbios_name.set_text(&g.netbios_name);
            set_combo(&self.security, SECURITY_MODES, &g.security.to_string());
            set_combo(&self.passdb_backend, PASSDB_BACKENDS, &g.passdb_backend);
            self.guest_account.set_text(&g.guest_account);
            set_combo(&self.map_to_guest, MAP_TO_GUEST_OPTS, &g.map_to_guest);
            self.socket_options.set_text(&g.socket_options);
            self.dns_proxy.set_active(g.dns_proxy);
            set_combo(&self.smb_encrypt, SMB_ENCRYPT_OPTS, &g.smb_encrypt);
            set_combo(&self.server_min_protocol, SMB_PROTOCOLS, &g.server_min_protocol);
            set_combo(&self.server_max_protocol, SMB_PROTOCOLS, &g.server_max_protocol);
            set_combo(&self.client_min_protocol, SMB_PROTOCOLS, &g.client_min_protocol);
            set_combo(&self.client_max_protocol, SMB_PROTOCOLS, &g.client_max_protocol);
            set_combo(&self.server_signing, SIGNING_OPTS, &g.server_signing);
            set_combo(&self.client_signing, SIGNING_OPTS, &g.client_signing);
            self.interfaces.set_text(&g.interfaces);
            self.bind_interfaces_only.set_active(g.bind_interfaces_only);
            self.hosts_allow.set_text(&g.hosts_allow);
            self.hosts_deny.set_text(&g.hosts_deny);
            self.wins_support.set_active(g.wins_support);
            self.wins_server.set_text(&g.wins_server);
            self.name_resolve_order.set_text(&g.name_resolve_order);
            self.realm.set_text(&g.realm);
            self.password_server.set_text(&g.password_server);
            self.unix_password_sync.set_active(g.unix_password_sync);
            self.domain_master.set_active(g.domain_master);
            self.local_master.set_active(g.local_master);
            self.preferred_master.set_active(g.preferred_master);
            self.os_level.set_text(&g.os_level.to_string());
            self.logon_drive.set_text(&g.logon_drive);
            self.logon_home.set_text(&g.logon_home);
            self.logon_path.set_text(&g.logon_path);
            self.logon_script.set_text(&g.logon_script);
            self.username_map.set_text(&g.username_map);
            self.smb_passwd_file.set_text(&g.smb_passwd_file);
            self.wins_proxy.set_active(g.wins_proxy);
            set_combo(&self.restrict_anonymous, RESTRICT_ANONYMOUS_OPTS, &g.restrict_anonymous.to_string());
            set_combo(&self.ntlm_auth, NTLM_AUTH_OPTS, &g.ntlm_auth);
            self.client_ntlmv2_auth.set_active(g.client_ntlmv2_auth);
            self.wide_links.set_active(g.wide_links);
            self.unix_extensions.set_active(g.unix_extensions);
            self.case_sensitive.set_active(g.case_sensitive);
            self.load_printers.set_active(g.load_printers);
            self.disable_spoolss.set_active(g.disable_spoolss);
            self.log_file.set_text(&g.log_file);
            self.log_level.set_text(&g.log_level);
            self.max_log_size.set_text(&g.max_log_size.to_string());
            self.read_raw.set_active(g.read_raw);
            self.write_raw.set_active(g.write_raw);
            self.max_xmit.set_text(&g.max_xmit.to_string());
            self.deadtime.set_text(&g.deadtime.to_string());
            self.keepalive.set_text(&g.keepalive.to_string());
        }

        /// Read current UI values into a GlobalSettings (without needing SambaConfig)
        fn to_global_settings(&self) -> GlobalSettings {
            GlobalSettings {
                workgroup: self.workgroup.text().to_string(),
                server_string: self.server_string.text().to_string(),
                netbios_name: self.netbios_name.text().to_string(),
                security: match combo_value(&self.security).to_lowercase().as_str() {
                    "share" => crate::config::SecurityMode::Share,
                    "server" => crate::config::SecurityMode::Server,
                    "domain" => crate::config::SecurityMode::Domain,
                    "ads" => crate::config::SecurityMode::ADS,
                    _ => crate::config::SecurityMode::User,
                },
                guest_account: self.guest_account.text().to_string(),
                map_to_guest: combo_value(&self.map_to_guest),
                dns_proxy: self.dns_proxy.is_active(),
                socket_options: self.socket_options.text().to_string(),
                winbind_nss_info: String::new(),
                passdb_backend: combo_value(&self.passdb_backend),
                smb_encrypt: combo_value(&self.smb_encrypt),
                server_min_protocol: combo_value(&self.server_min_protocol),
                server_max_protocol: combo_value(&self.server_max_protocol),
                client_min_protocol: combo_value(&self.client_min_protocol),
                client_max_protocol: combo_value(&self.client_max_protocol),
                server_signing: combo_value(&self.server_signing),
                client_signing: combo_value(&self.client_signing),
                interfaces: self.interfaces.text().to_string(),
                bind_interfaces_only: self.bind_interfaces_only.is_active(),
                hosts_allow: self.hosts_allow.text().to_string(),
                hosts_deny: self.hosts_deny.text().to_string(),
                wins_support: self.wins_support.is_active(),
                wins_server: self.wins_server.text().to_string(),
                name_resolve_order: self.name_resolve_order.text().to_string(),
                realm: self.realm.text().to_string(),
                password_server: self.password_server.text().to_string(),
                unix_password_sync: self.unix_password_sync.is_active(),
                domain_master: self.domain_master.is_active(),
                local_master: self.local_master.is_active(),
                preferred_master: self.preferred_master.is_active(),
                os_level: self.os_level.text().to_string().parse().unwrap_or(20),
                logon_drive: self.logon_drive.text().to_string(),
                logon_home: self.logon_home.text().to_string(),
                logon_path: self.logon_path.text().to_string(),
                logon_script: self.logon_script.text().to_string(),
                username_map: self.username_map.text().to_string(),
                smb_passwd_file: self.smb_passwd_file.text().to_string(),
                wins_proxy: self.wins_proxy.is_active(),
                restrict_anonymous: combo_value(&self.restrict_anonymous).parse().unwrap_or(0),
                ntlm_auth: combo_value(&self.ntlm_auth),
                client_ntlmv2_auth: self.client_ntlmv2_auth.is_active(),
                wide_links: self.wide_links.is_active(),
                unix_extensions: self.unix_extensions.is_active(),
                case_sensitive: self.case_sensitive.is_active(),
                load_printers: self.load_printers.is_active(),
                disable_spoolss: self.disable_spoolss.is_active(),
                log_file: self.log_file.text().to_string(),
                log_level: self.log_level.text().to_string(),
                max_log_size: self.max_log_size.text().to_string().parse().unwrap_or(1000),
                read_raw: self.read_raw.is_active(),
                write_raw: self.write_raw.is_active(),
                max_xmit: self.max_xmit.text().to_string().parse().unwrap_or(65535),
                deadtime: self.deadtime.text().to_string().parse().unwrap_or(0),
                keepalive: self.keepalive.text().to_string().parse().unwrap_or(300),
            }
        }
    }

    /// Compare two GlobalSettings and return a list of human-readable differences
    fn diff_global_settings(current: &GlobalSettings, template: &GlobalSettings) -> Vec<String> {
        let mut diffs = Vec::new();
        macro_rules! cmp_str {
            ($field:ident, $label:expr) => {
                if current.$field != template.$field {
                    diffs.push(format!("{}: '{}' → '{}'", $label, current.$field, template.$field));
                }
            };
        }
        macro_rules! cmp_bool {
            ($field:ident, $label:expr) => {
                if current.$field != template.$field {
                    let yn = |b: bool| if b { "yes" } else { "no" };
                    diffs.push(format!("{}: {} → {}", $label, yn(current.$field), yn(template.$field)));
                }
            };
        }
        macro_rules! cmp_u32 {
            ($field:ident, $label:expr) => {
                if current.$field != template.$field {
                    diffs.push(format!("{}: {} → {}", $label, current.$field, template.$field));
                }
            };
        }
        // General
        cmp_str!(workgroup, "Workgroup");
        cmp_str!(server_string, "Server String");
        cmp_str!(netbios_name, "NetBIOS Name");
        if current.security != template.security {
            diffs.push(format!("Security Mode: '{}' → '{}'", current.security, template.security));
        }
        cmp_str!(passdb_backend, "Passdb Backend");
        cmp_str!(guest_account, "Guest Account");
        cmp_str!(map_to_guest, "Map to Guest");
        cmp_str!(socket_options, "Socket Options");
        cmp_bool!(dns_proxy, "DNS Proxy");
        // Security / Protocol
        cmp_str!(smb_encrypt, "SMB Encrypt");
        cmp_str!(server_min_protocol, "Server Min Protocol");
        cmp_str!(server_max_protocol, "Server Max Protocol");
        cmp_str!(client_min_protocol, "Client Min Protocol");
        cmp_str!(client_max_protocol, "Client Max Protocol");
        cmp_str!(server_signing, "Server Signing");
        cmp_str!(client_signing, "Client Signing");
        // Networking
        cmp_str!(interfaces, "Interfaces");
        cmp_bool!(bind_interfaces_only, "Bind Interfaces Only");
        cmp_str!(hosts_allow, "Hosts Allow");
        cmp_str!(hosts_deny, "Hosts Deny");
        // WINS
        cmp_bool!(wins_support, "WINS Support");
        cmp_str!(wins_server, "WINS Server");
        cmp_str!(name_resolve_order, "Name Resolve Order");
        // Domain / Auth
        cmp_str!(realm, "Realm");
        cmp_str!(password_server, "Password Server");
        cmp_bool!(unix_password_sync, "Unix Password Sync");
        cmp_bool!(domain_master, "Domain Master");
        cmp_bool!(local_master, "Local Master");
        cmp_bool!(preferred_master, "Preferred Master");
        cmp_u32!(os_level, "OS Level");
        // Domain Logon
        cmp_str!(logon_drive, "Logon Drive");
        cmp_str!(logon_home, "Logon Home");
        cmp_str!(logon_path, "Logon Path");
        cmp_str!(logon_script, "Logon Script");
        // Additional Auth
        cmp_str!(username_map, "Username Map");
        cmp_str!(smb_passwd_file, "SMB Passwd File");
        cmp_bool!(wins_proxy, "WINS Proxy");
        cmp_u32!(restrict_anonymous, "Restrict Anonymous");
        cmp_str!(ntlm_auth, "NTLM Auth");
        cmp_bool!(client_ntlmv2_auth, "Client NTLMv2 Auth");
        // Filesystem
        cmp_bool!(wide_links, "Wide Links");
        cmp_bool!(unix_extensions, "Unix Extensions");
        cmp_bool!(case_sensitive, "Case Sensitive");
        // Printing
        cmp_bool!(load_printers, "Load Printers");
        cmp_bool!(disable_spoolss, "Disable Spoolss");
        // Logging
        cmp_str!(log_file, "Log File");
        cmp_str!(log_level, "Log Level");
        cmp_u32!(max_log_size, "Max Log Size (KB)");
        // Performance
        cmp_bool!(read_raw, "Read Raw");
        cmp_bool!(write_raw, "Write Raw");
        cmp_u32!(max_xmit, "Max Xmit");
        cmp_u32!(deadtime, "Deadtime (min)");
        cmp_u32!(keepalive, "Keepalive (sec)");
        diffs
    }

    fn add_entry(group: &PreferencesGroup, title: &str, value: &str, tooltip: &str) -> EntryRow {
        let row = EntryRow::builder().title(title).text(value).build();
        if !tooltip.is_empty() {
            row.set_tooltip_text(Some(tooltip));
        }
        group.add(&row);
        row
    }

    fn add_switch(group: &PreferencesGroup, title: &str, subtitle: &str, active: bool, tooltip: &str) -> gtk::Switch {
        let sw = gtk::Switch::builder().valign(Align::Center).active(active).build();
        let row = ActionRow::builder().title(title).subtitle(subtitle).build();
        if !tooltip.is_empty() {
            row.set_tooltip_text(Some(tooltip));
        }
        row.add_suffix(&sw);
        row.set_activatable_widget(Some(&sw));
        group.add(&row);
        sw
    }

    /// Add a dropdown (ComboRow) with predefined choices. Returns the ComboRow.
    fn add_combo(group: &PreferencesGroup, title: &str, choices: &[&str], current: &str, tooltip: &str) -> ComboRow {
        let string_list = StringList::new(choices);
        let selected = choices.iter().position(|&c| c.eq_ignore_ascii_case(current)).unwrap_or(0) as u32;
        let row = ComboRow::builder()
            .title(title)
            .model(&string_list)
            .selected(selected)
            .build();
        if !tooltip.is_empty() {
            row.set_tooltip_text(Some(tooltip));
        }
        group.add(&row);
        row
    }

    /// Read the selected string from a ComboRow
    fn combo_value(combo: &ComboRow) -> String {
        let idx = combo.selected() as usize;
        if let Some(model) = combo.model() {
            if let Ok(sl) = model.downcast::<StringList>() {
                if let Some(val) = sl.string(idx as u32) {
                    return val.to_string();
                }
            }
        }
        String::new()
    }

    /// Set a ComboRow's selection by matching a value against its model
    fn set_combo(combo: &ComboRow, choices: &[&str], value: &str) {
        let idx = choices.iter().position(|&c| c.eq_ignore_ascii_case(value)).unwrap_or(0) as u32;
        combo.set_selected(idx);
    }

    /// Create global settings preferences group
    fn create_global_settings_group(global: &GlobalSettings) -> (PreferencesGroup, GlobalSettingsRows) {
        let group = PreferencesGroup::builder().title("Global Settings").build();

        // General
        let workgroup_row = add_entry(&group, "Workgroup", &global.workgroup,
            "The Windows workgroup or domain this server belongs to. Clients must use the same workgroup to browse this server.");
        let server_string_row = add_entry(&group, "Server String", &global.server_string,
            "A descriptive string shown to clients when browsing the network. Use %h for hostname, %v for Samba version.");
        let netbios_name_row = add_entry(&group, "NetBIOS Name", &global.netbios_name,
            "The NetBIOS name by which this server is known on the network. Defaults to the first component of the DNS hostname if empty.");
        let security_row = add_combo(&group, "Security Mode", SECURITY_MODES, &global.security.to_string(),
            "Controls how clients authenticate. 'user' requires a valid username/password. 'ads' joins an Active Directory domain. 'domain' joins an NT4-style domain.");
        let passdb_backend_row = add_combo(&group, "Passdb Backend", PASSDB_BACKENDS, &global.passdb_backend,
            "The password database backend. 'tdbsam' stores passwords locally (default). 'ldapsam' uses an LDAP directory. 'smbpasswd' uses the legacy flat file.");
        let guest_account_row = add_entry(&group, "Guest Account", &global.guest_account,
            "The Unix account used for guest access. This user must exist on the system. Typically 'nobody'.");
        let map_to_guest_row = add_combo(&group, "Map to Guest", MAP_TO_GUEST_OPTS, &global.map_to_guest,
            "When to map login attempts to the guest account. 'Never' disables guest mapping. 'Bad User' maps unknown usernames to guest. 'Bad Password' maps failed logins to guest.");
        let socket_options_row = add_entry(&group, "Socket Options", &global.socket_options,
            "TCP socket tuning options. 'TCP_NODELAY' disables Nagle's algorithm for lower latency. Modify only if you understand network tuning.");
        let dns_proxy_sw = add_switch(&group, "DNS Proxy", "Enable DNS proxy", global.dns_proxy,
            "When enabled, Samba will attempt to resolve NetBIOS names via DNS if WINS lookup fails. Usually not needed in modern networks.");

        // Security / Protocol
        let smb_encrypt_row = add_combo(&group, "SMB Encrypt", SMB_ENCRYPT_OPTS, &global.smb_encrypt,
            "Controls SMB transport encryption. 'off' disables encryption. 'desired' requests but doesn't require it. 'required' enforces encryption for all connections.");
        let server_min_protocol_row = add_combo(&group, "Server Min Protocol", SMB_PROTOCOLS, &global.server_min_protocol,
            "The minimum SMB protocol version the server will accept from clients. Set to SMB2_10 or higher to disable insecure SMBv1. Default: LANMAN1.");
        let server_max_protocol_row = add_combo(&group, "Server Max Protocol", SMB_PROTOCOLS, &global.server_max_protocol,
            "The maximum SMB protocol version the server will offer to clients. SMB3_11 is recommended for best security and performance. Default: SMB3.");
        let client_min_protocol_row = add_combo(&group, "Client Min Protocol", SMB_PROTOCOLS, &global.client_min_protocol,
            "The minimum SMB protocol version this machine will use when connecting to other servers as a client. Default: CORE.");
        let client_max_protocol_row = add_combo(&group, "Client Max Protocol", SMB_PROTOCOLS, &global.client_max_protocol,
            "The maximum SMB protocol version this machine will use when connecting to other servers as a client. Default: SMB3.");
        let server_signing_row = add_combo(&group, "Server Signing", SIGNING_OPTS, &global.server_signing,
            "Controls SMB packet signing for server connections. 'mandatory' requires signing (recommended for security). 'auto' signs if the client supports it. 'off' disables signing.");
        let client_signing_row = add_combo(&group, "Client Signing", SIGNING_OPTS, &global.client_signing,
            "Controls SMB packet signing when this machine acts as a client. 'mandatory' requires signing. 'auto' signs if the server supports it.");

        // Networking
        let interfaces_row = add_entry(&group, "Interfaces", &global.interfaces,
            "Network interfaces Samba should listen on. Use IP addresses, subnet/mask pairs, or interface names (e.g. 'eth0 192.168.1.0/24'). Empty means all interfaces.");
        let bind_interfaces_only_sw = add_switch(&group, "Bind Interfaces Only", "Restrict to listed interfaces", global.bind_interfaces_only,
            "When enabled, Samba only binds to the interfaces listed above. Useful for multi-homed servers to restrict which networks can access shares.");
        let hosts_allow_row = add_entry(&group, "Hosts Allow", &global.hosts_allow,
            "Comma-separated list of hosts/networks allowed to connect. Supports IP addresses, subnets (192.168.1.), and hostnames. Empty means all hosts allowed.");
        let hosts_deny_row = add_entry(&group, "Hosts Deny", &global.hosts_deny,
            "Comma-separated list of hosts/networks denied access. Checked after 'hosts allow'. Use 'ALL' to deny everyone not explicitly allowed.");

        // WINS / Name Resolution
        let wins_support_sw = add_switch(&group, "WINS Support", "Act as a WINS server", global.wins_support,
            "Enable this server to act as a WINS (Windows Internet Name Service) server. Only one WINS server should exist per network.");
        let wins_server_row = add_entry(&group, "WINS Server", &global.wins_server,
            "IP address of an external WINS server to register with. Do not set this if WINS Support is enabled on this server.");
        let name_resolve_order_row = add_entry(&group, "Name Resolve Order", &global.name_resolve_order,
            "Order of name resolution methods. Options: lmhosts, host, wins, bcast. Default: 'lmhosts host wins bcast'.");

        // Domain / Authentication
        let realm_row = add_entry(&group, "Realm", &global.realm,
            "The Kerberos realm for Active Directory authentication. Typically the uppercase DNS domain name (e.g. 'EXAMPLE.COM'). Required for ADS security mode.");
        let password_server_row = add_entry(&group, "Password Server", &global.password_server,
            "The server used to validate passwords in domain/ADS mode. Use '*' for automatic discovery, or specify IP/hostname of the domain controller.");
        let unix_password_sync_sw = add_switch(&group, "Unix Password Sync", "Sync Samba and Unix passwords", global.unix_password_sync,
            "When enabled, changing a Samba password also updates the Unix system password. Requires 'passwd program' and 'passwd chat' to be configured.");
        let domain_master_sw = add_switch(&group, "Domain Master", "Act as domain master browser", global.domain_master,
            "Enable this server to be the domain master browser, collecting browse lists from local master browsers across subnets.");
        let local_master_sw = add_switch(&group, "Local Master", "Participate in local master elections", global.local_master,
            "Allow this server to participate in local master browser elections on its subnet. The winner maintains the browse list.");
        let preferred_master_sw = add_switch(&group, "Preferred Master", "Force election on startup", global.preferred_master,
            "When enabled, Samba forces a browser election on startup and gives itself a slight advantage. Use with caution in multi-server environments.");
        let os_level_row = add_entry(&group, "OS Level", &global.os_level.to_string(),
            "Determines this server's priority in browser elections. Higher values win. Windows NT Server uses 32, Windows 2000/2003 uses 64. Default: 20.");

        // Domain Logon
        let logon_drive_row = add_entry(&group, "Logon Drive", &global.logon_drive,
            "The drive letter to map the user's home directory to on Windows clients (e.g. 'H:'). Only used when domain logons are enabled.");
        let logon_home_row = add_entry(&group, "Logon Home", &global.logon_home,
            "The UNC path to the user's home directory for domain logons (e.g. '\\\\%N\\%U'). %N = server name, %U = username.");
        let logon_path_row = add_entry(&group, "Logon Path", &global.logon_path,
            "The UNC path where roaming profiles are stored (e.g. '\\\\%N\\profiles\\%U'). Set empty to disable roaming profiles.");
        let logon_script_row = add_entry(&group, "Logon Script", &global.logon_script,
            "The relative path to a logon script executed on Windows client login (e.g. 'logon.bat'). Relative to the [netlogon] share.");

        // Additional Auth/Security
        let username_map_row = add_entry(&group, "Username Map", &global.username_map,
            "Path to a file that maps client-supplied usernames to local Unix usernames (e.g. '/etc/samba/smbusers'). Useful for aliasing.");
        let smb_passwd_file_row = add_entry(&group, "SMB Passwd File", &global.smb_passwd_file,
            "Path to the legacy smbpasswd file. Only relevant when using 'smbpasswd' as the passdb backend. Default: /etc/samba/smbpasswd.");
        let wins_proxy_sw = add_switch(&group, "WINS Proxy", "Proxy WINS requests for old broadcast clients", global.wins_proxy,
            "When enabled, Samba proxies WINS name resolution requests on behalf of older clients that only support broadcast name resolution.");
        let restrict_anonymous_row = add_combo(&group, "Restrict Anonymous", RESTRICT_ANONYMOUS_OPTS, &global.restrict_anonymous.to_string(),
            "Controls anonymous access to server information. 0 = no restrictions. 1 = disallow anonymous enumeration of SAM accounts. 2 = disallow anonymous access entirely.");
        let ntlm_auth_row = add_combo(&group, "NTLM Auth", NTLM_AUTH_OPTS, &global.ntlm_auth,
            "Controls NTLM authentication methods for this server. 'ntlmv2-only' is the most secure (recommended). 'yes' allows all NTLM versions. 'disabled' blocks NTLM entirely.");

        // Client Authentication (how this machine authenticates to remote servers)
        let client_ntlmv2_auth_sw = add_switch(&group, "Client NTLMv2 Auth",
            "Enforce NTLMv2 when connecting to remote servers", global.client_ntlmv2_auth,
            "When enabled (recommended), only NTLMv2 is used for outgoing connections. \
             Disables weaker NTLM and LanMan. Required by most modern servers.");

        // Filesystem / Symlinks
        let wide_links_sw = add_switch(&group, "Wide Links", "Follow symlinks outside the share path", global.wide_links,
            "When enabled, Samba follows symbolic links that point outside the shared directory. Disabled by default for security. Enabling requires 'unix extensions = no'.");
        let unix_extensions_sw = add_switch(&group, "Unix Extensions", "Enable CIFS Unix extensions", global.unix_extensions,
            "Enables CIFS Unix extensions for clients that support them (e.g. Linux). Provides Unix ownership and permission info. Must be disabled if 'wide links = yes'.");
        let case_sensitive_sw = add_switch(&group, "Case Sensitive", "Use case-sensitive filenames", global.case_sensitive,
            "When disabled (default), Samba ignores case in filenames to match Windows behavior. Enable only if all clients are Unix/Linux and you need case-sensitive file lookups.");

        // Printing
        let load_printers_sw = add_switch(&group, "Load Printers", "Auto-load printer shares", global.load_printers,
            "When enabled, Samba automatically creates shares for all printers found in the system's printcap file.");
        let disable_spoolss_sw = add_switch(&group, "Disable Spoolss", "Disable print spooler service", global.disable_spoolss,
            "When enabled, disables the Windows print spooler RPC service. Enable this if you don't need printer sharing to reduce attack surface.");

        // Logging
        let log_file_row = add_entry(&group, "Log File", &global.log_file,
            "Path to the Samba log file. Use %m for the client machine name to create per-client logs (e.g. '/var/log/samba/log.%m').");
        let log_level_row = add_entry(&group, "Log Level", &global.log_level,
            "Logging verbosity level. 0 = errors only, 1 = warnings (default), 2-3 = debug info, 10 = full debug. Higher values generate more output.");
        let max_log_size_row = add_entry(&group, "Max Log Size (KB)", &global.max_log_size.to_string(),
            "Maximum size of each log file in kilobytes before it is rotated. The old log is renamed with a .old extension. 0 = no limit.");

        // Performance
        let read_raw_sw = add_switch(&group, "Read Raw", "Enable raw read SMB requests", global.read_raw,
            "Enables large read requests for better throughput. Should be on unless you experience network issues with specific clients.");
        let write_raw_sw = add_switch(&group, "Write Raw", "Enable raw write SMB requests", global.write_raw,
            "Enables large write requests for better throughput. Should be on unless you experience network issues with specific clients.");
        let max_xmit_row = add_entry(&group, "Max Xmit", &global.max_xmit.to_string(),
            "Maximum packet size in bytes negotiated with clients. Default 65535 is optimal for most networks. Lower values may help on unreliable links.");
        let deadtime_row = add_entry(&group, "Deadtime (min)", &global.deadtime.to_string(),
            "Minutes of inactivity before an idle connection is closed. 0 = never disconnect. Useful for freeing resources on busy servers.");
        let keepalive_row = add_entry(&group, "Keepalive (sec)", &global.keepalive.to_string(),
            "Seconds between TCP keepalive probes to detect dead clients. 0 = disabled. Default: 300 (5 minutes).");

        let rows = GlobalSettingsRows {
            workgroup: workgroup_row, server_string: server_string_row, netbios_name: netbios_name_row,
            security: security_row, guest_account: guest_account_row, map_to_guest: map_to_guest_row,
            socket_options: socket_options_row, dns_proxy: dns_proxy_sw,
            passdb_backend: passdb_backend_row, smb_encrypt: smb_encrypt_row,
            server_min_protocol: server_min_protocol_row, server_max_protocol: server_max_protocol_row,
            client_min_protocol: client_min_protocol_row, client_max_protocol: client_max_protocol_row,
            server_signing: server_signing_row, client_signing: client_signing_row,
            interfaces: interfaces_row, bind_interfaces_only: bind_interfaces_only_sw,
            hosts_allow: hosts_allow_row, hosts_deny: hosts_deny_row,
            wins_support: wins_support_sw, wins_server: wins_server_row, name_resolve_order: name_resolve_order_row,
            realm: realm_row, password_server: password_server_row, unix_password_sync: unix_password_sync_sw,
            domain_master: domain_master_sw,
            local_master: local_master_sw, preferred_master: preferred_master_sw, os_level: os_level_row,
            logon_drive: logon_drive_row, logon_home: logon_home_row,
            logon_path: logon_path_row, logon_script: logon_script_row,
            username_map: username_map_row, smb_passwd_file: smb_passwd_file_row,
            wins_proxy: wins_proxy_sw,
            restrict_anonymous: restrict_anonymous_row, ntlm_auth: ntlm_auth_row,
            client_ntlmv2_auth: client_ntlmv2_auth_sw,
            wide_links: wide_links_sw, unix_extensions: unix_extensions_sw,
            case_sensitive: case_sensitive_sw,
            load_printers: load_printers_sw, disable_spoolss: disable_spoolss_sw,
            log_file: log_file_row, log_level: log_level_row, max_log_size: max_log_size_row,
            read_raw: read_raw_sw, write_raw: write_raw_sw, max_xmit: max_xmit_row,
            deadtime: deadtime_row, keepalive: keepalive_row,
        };

        (group, rows)
    }

    /// Helper: create a switch row and return the switch widget
    fn add_dialog_switch(group: &PreferencesGroup, title: &str, subtitle: &str, active: bool, tooltip: &str) -> gtk::Switch {
        let row = ActionRow::builder().title(title).subtitle(subtitle).build();
        row.set_tooltip_text(Some(tooltip));
        let sw = gtk::Switch::builder().valign(Align::Center).active(active).build();
        row.add_suffix(&sw);
        row.set_activatable_widget(Some(&sw));
        group.add(&row);
        sw
    }

    /// Shows a dialog to pick a share template and add it to the shares list.
    fn show_share_template_picker(
        shares_group: &PreferencesGroup,
        global: &GlobalSettings,
        shared_shares: &std::rc::Rc<std::cell::RefCell<Vec<Share>>>,
        parent: Option<&gtk::Window>,
    ) {
        let dialog = adw::Window::builder()
            .title("Add Share from Template")
            .default_width(500)
            .default_height(450)
            .modal(true)
            .build();

        if let Some(win) = parent {
            dialog.set_transient_for(Some(win));
        }

        let toolbar_view = adw::ToolbarView::new();
        toolbar_view.add_top_bar(&adw::HeaderBar::new());

        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(24)
            .margin_end(24)
            .margin_top(12)
            .margin_bottom(24)
            .spacing(12)
            .build();

        let desc = Label::builder()
            .label("Select a template to pre-fill a new share. You can edit the values before saving.")
            .css_classes(["body"])
            .halign(Align::Start)
            .wrap(true)
            .build();
        content.append(&desc);

        let templates_group = PreferencesGroup::builder()
            .title("Available Templates")
            .build();

        let templates = crate::config::share_templates::share_templates();
        for template in &templates {
            let row = ActionRow::builder()
                .title(template.name)
                .subtitle(template.description)
                .activatable(true)
                .build();

            let use_button = Button::builder()
                .label("Use")
                .css_classes(["flat", "suggested-action"])
                .valign(Align::Center)
                .build();

            let template_name = template.name.to_string();
            let group_for_use = shares_group.clone();
            let global_for_use = global.clone();
            let shares_for_use = shared_shares.clone();
            let dialog_for_use = dialog.clone();
            use_button.connect_clicked(move |btn| {
                if let Some(share) = crate::config::share_from_template(&template_name) {
                    // Open the share dialog pre-filled with the template values
                    let parent = btn.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                    show_share_dialog(&group_for_use, &global_for_use, &shares_for_use, Some(&share), None, parent.as_ref());
                    dialog_for_use.close();
                }
            });

            row.add_suffix(&use_button);
            templates_group.add(&row);
        }

        content.append(&templates_group);

        let scrolled = ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .build();
        scrolled.set_child(Some(&content));

        toolbar_view.set_content(Some(&scrolled));
        dialog.set_content(Some(&toolbar_view));
        dialog.present();
    }

    /// Shows a dialog to add or edit a share
    /// If `existing_share` is Some, pre-fills the dialog for editing.
    /// If `existing_row` is Some, updates that row's title/subtitle on save.
    fn show_share_dialog(
        shares_group: &PreferencesGroup,
        global: &GlobalSettings,
        shared_shares: &std::rc::Rc<std::cell::RefCell<Vec<Share>>>,
        existing_share: Option<&Share>,
        existing_row: Option<&ActionRow>,
        parent: Option<&gtk::Window>,
    ) {
        let is_edit = existing_share.is_some();
        let dialog_title = if is_edit { "Edit Share" } else { "Add Share" };
        let confirm_label = if is_edit { "Save" } else { "Add" };

        let dialog = adw::Window::builder()
            .title(dialog_title)
            .default_width(600)
            .default_height(700)
            .modal(true)
            .build();

        if let Some(win) = parent {
            dialog.set_transient_for(Some(win));
        }

        let toolbar_view = adw::ToolbarView::new();
        toolbar_view.add_top_bar(&adw::HeaderBar::new());

        let scrolled = ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .build();

        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(24)
            .margin_end(24)
            .margin_top(12)
            .margin_bottom(24)
            .spacing(16)
            .build();

        // ── Basic Settings ──
        let basic_group = PreferencesGroup::builder()
            .title("Basic Settings")
            .description("Share name, path, and description")
            .build();
        let name_row = EntryRow::builder().title("Name").build();
        name_row.set_tooltip_text(Some("The share name as it appears on the network (e.g. 'documents')"));
        let path_row = EntryRow::builder().title("Path").build();
        path_row.set_tooltip_text(Some("Absolute path to the directory to share (e.g. /srv/samba/share)"));

        // Browse button to pick a directory
        let browse_btn = Button::builder()
            .icon_name("folder-open-symbolic")
            .css_classes(["flat"])
            .valign(Align::Center)
            .tooltip_text("Browse for directory")
            .build();
        path_row.add_suffix(&browse_btn);

        let path_row_for_browse = path_row.clone();
        let dialog_weak_browse = dialog.downgrade();
        browse_btn.connect_clicked(move |_| {
            let file_dialog = gtk::FileDialog::builder()
                .title("Select Share Directory")
                .modal(true)
                .build();
            let pr = path_row_for_browse.clone();
            let parent = dialog_weak_browse.upgrade();
            file_dialog.select_folder(
                parent.as_ref(),
                None::<&gtk::gio::Cancellable>,
                move |result| {
                    if let Ok(folder) = result {
                        if let Some(path) = folder.path() {
                            pr.set_text(&path.to_string_lossy());
                        }
                    }
                },
            );
        });

        let comment_row = EntryRow::builder().title("Comment").build();
        comment_row.set_tooltip_text(Some("Description shown in network browse lists and 'net view' output"));
        basic_group.add(&name_row);
        basic_group.add(&path_row);
        basic_group.add(&comment_row);
        content.append(&basic_group);

        // ── Access Control ──
        let access_group = PreferencesGroup::builder()
            .title("Access Control")
            .description("Visibility, write access, and guest policy")
            .build();
        let available_sw   = add_dialog_switch(&access_group, "Available",   "Share is active and accessible",          true,  "If disabled, the share appears in browse lists but access attempts will fail");
        let browsable_sw   = add_dialog_switch(&access_group, "Browsable",   "Visible in network browse lists",         true,  "Controls whether this share shows up when clients browse the network");
        let writable_sw    = add_dialog_switch(&access_group, "Writable",    "Allow write access (overrides read only)", false, "Allow users to create, modify, and delete files in this share");
        let read_only_sw   = add_dialog_switch(&access_group, "Read Only",   "Restrict to read-only access",            true,  "Prevent all write operations; users can only read files");
        let guest_ok_sw    = add_dialog_switch(&access_group, "Guest OK",    "Allow access without authentication",     false, "Allow connections without a password, mapped to the guest account");
        content.append(&access_group);

        // Keep writable / read_only in sync
        let ro_for_wr = read_only_sw.clone();
        writable_sw.connect_state_set(move |_, active| {
            ro_for_wr.set_active(!active);
            gtk::glib::Propagation::Proceed
        });
        let wr_for_ro = writable_sw.clone();
        read_only_sw.connect_state_set(move |_, active| {
            wr_for_ro.set_active(!active);
            gtk::glib::Propagation::Proceed
        });

        // ── User & Group Restrictions ──
        let users_group = PreferencesGroup::builder()
            .title("User and Group Restrictions")
            .description("Comma-separated lists of users/groups (@group syntax)")
            .build();
        let valid_users_row   = EntryRow::builder().title("Valid Users").build();
        valid_users_row.set_tooltip_text(Some("Only these users/groups can access the share. Use @group for groups. Empty means everyone."));
        let invalid_users_row = EntryRow::builder().title("Invalid Users").build();
        invalid_users_row.set_tooltip_text(Some("These users/groups are denied access even if listed in valid users"));
        let read_list_row     = EntryRow::builder().title("Read List").build();
        read_list_row.set_tooltip_text(Some("Users/groups given read-only access to a writable share"));
        let write_list_row    = EntryRow::builder().title("Write List").build();
        write_list_row.set_tooltip_text(Some("Users/groups given read-write access to a read-only share"));
        let force_user_row    = EntryRow::builder().title("Force User").build();
        force_user_row.set_tooltip_text(Some("All file operations are performed as this Unix user, regardless of who connects"));
        let force_group_row   = EntryRow::builder().title("Force Group").build();
        force_group_row.set_tooltip_text(Some("All file operations use this Unix group, overriding the user's normal group"));
        users_group.add(&valid_users_row);
        users_group.add(&invalid_users_row);
        users_group.add(&read_list_row);
        users_group.add(&write_list_row);
        users_group.add(&force_user_row);
        users_group.add(&force_group_row);
        content.append(&users_group);

        // ── Host Restrictions ──
        let hosts_group = PreferencesGroup::builder()
            .title("Host Restrictions")
            .description("Comma-separated hosts/networks (e.g. 192.168.1.0/24)")
            .build();
        let hosts_allow_row = EntryRow::builder().title("Hosts Allow").build();
        hosts_allow_row.set_tooltip_text(Some("Only these hosts/networks can connect (e.g. 192.168.1. 10.0.0.0/24)"));
        let hosts_deny_row  = EntryRow::builder().title("Hosts Deny").build();
        hosts_deny_row.set_tooltip_text(Some("These hosts/networks are blocked from connecting"));
        hosts_group.add(&hosts_allow_row);
        hosts_group.add(&hosts_deny_row);
        content.append(&hosts_group);

        // ── File Permissions ──
        let perms_group = PreferencesGroup::builder()
            .title("File Permissions")
            .description("Octal masks for new files and directories")
            .build();
        let create_mask_row       = EntryRow::builder().title("Create Mask").text("0744").build();
        create_mask_row.set_tooltip_text(Some("Maximum permissions for new files (octal, e.g. 0644). Bits not set here are removed."));
        let directory_mask_row    = EntryRow::builder().title("Directory Mask").text("0755").build();
        directory_mask_row.set_tooltip_text(Some("Maximum permissions for new directories (octal, e.g. 0755)"));
        let force_create_row      = EntryRow::builder().title("Force Create Mode").build();
        force_create_row.set_tooltip_text(Some("Permission bits always set on new files (octal). Combined with create mask."));
        let force_directory_row   = EntryRow::builder().title("Force Directory Mode").build();
        force_directory_row.set_tooltip_text(Some("Permission bits always set on new directories (octal). Combined with directory mask."));
        let inherit_acls_sw       = add_dialog_switch(&perms_group, "Inherit ACLs",        "New files inherit parent ACLs",        false, "Files and subdirectories inherit the ACLs of their parent directory");
        let inherit_permissions_sw = add_dialog_switch(&perms_group, "Inherit Permissions", "New files inherit parent permissions", false, "Files and subdirectories inherit Unix permissions from their parent directory. Overrides create/directory masks.");
        // Insert entry rows before the switches (add to group in order)
        // We already added switches via helper; insert entries at the top by re-creating group
        // Actually, PreferencesGroup appends in order, so let's build a second group for masks
        perms_group.add(&create_mask_row);
        perms_group.add(&directory_mask_row);
        perms_group.add(&force_create_row);
        perms_group.add(&force_directory_row);
        content.append(&perms_group);

        // ── Advanced ──
        let advanced_group = PreferencesGroup::builder()
            .title("Advanced")
            .description("VFS objects and other options")
            .build();
        let vfs_objects_row = EntryRow::builder().title("VFS Objects").build();
        vfs_objects_row.set_tooltip_text(Some("Comma-separated VFS modules (e.g. recycle, full_audit, shadow_copy2)"));
        advanced_group.add(&vfs_objects_row);
        content.append(&advanced_group);

        // Pre-fill fields when editing an existing share
        if let Some(share) = existing_share {
            name_row.set_text(&share.name);
            path_row.set_text(&share.path);
            comment_row.set_text(&share.comment);
            available_sw.set_active(share.available);
            browsable_sw.set_active(share.browsable);
            writable_sw.set_active(share.writable);
            read_only_sw.set_active(share.read_only);
            guest_ok_sw.set_active(share.guest_ok);
            valid_users_row.set_text(&share.valid_users.join(", "));
            invalid_users_row.set_text(&share.invalid_users.join(", "));
            read_list_row.set_text(&share.read_list.join(", "));
            write_list_row.set_text(&share.write_list.join(", "));
            force_user_row.set_text(&share.force_user);
            force_group_row.set_text(&share.force_group);
            hosts_allow_row.set_text(&share.hosts_allow.join(", "));
            hosts_deny_row.set_text(&share.hosts_deny.join(", "));
            create_mask_row.set_text(&share.create_mask);
            directory_mask_row.set_text(&share.directory_mask);
            force_create_row.set_text(&share.force_create_mode);
            force_directory_row.set_text(&share.force_directory_mode);
            inherit_acls_sw.set_active(share.inherit_acls);
            inherit_permissions_sw.set_active(share.inherit_permissions);
            vfs_objects_row.set_text(&share.vfs_objects.join(", "));
        }

        // ── Buttons ──
        let button_box = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .halign(Align::End)
            .build();
        let cancel_button = Button::builder().label("Cancel").css_classes(["flat"]).build();
        let confirm_button = Button::builder().label(confirm_label).css_classes(["suggested-action"]).build();
        button_box.append(&cancel_button);
        button_box.append(&confirm_button);
        content.append(&button_box);

        scrolled.set_child(Some(&content));
        toolbar_view.set_content(Some(&scrolled));
        dialog.set_content(Some(&toolbar_view));

        // Cancel
        let dialog_weak = dialog.downgrade();
        cancel_button.connect_clicked(move |_| {
            if let Some(d) = dialog_weak.upgrade() { d.close(); }
        });

        // Helper: split comma-separated text into Vec<String>
        fn csv_to_vec(entry: &EntryRow) -> Vec<String> {
            entry.text().split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }

        // Confirm (Add or Save)
        let dialog_weak = dialog.downgrade();
        let group_clone = shares_group.clone();
        let global_clone = global.clone();
        let shares_for_confirm = shared_shares.clone();
        let old_name = existing_share.map(|s| s.name.clone());
        let existing_row_clone = existing_row.cloned();
        confirm_button.connect_clicked(move |_| {
            let name_val = name_row.text().to_string();
            let path_val = path_row.text().to_string();

            if name_val.is_empty() || path_val.is_empty() {
                show_error_toast("Share name and path are required");
                return;
            }

            // Validate share name — no dangerous characters
            if let Err(e) = reject_dangerous_chars(&name_val, "Share name") {
                show_error_toast(&e);
                return;
            }
            // Share name: only allow alphanumeric, hyphens, underscores, spaces, dots
            if !name_val.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.') {
                show_error_toast("Share name contains invalid characters");
                return;
            }

            // Validate path — must be absolute, no dangerous chars
            if let Err(e) = validate_mount_point(&path_val) {
                show_error_toast(&e);
                return;
            }

            // Validate comment
            let comment_val = comment_row.text().to_string();
            if !comment_val.is_empty() {
                if let Err(e) = reject_dangerous_chars(&comment_val, "Comment") {
                    show_error_toast(&e);
                    return;
                }
            }

            // Validate octal masks
            let create_mask_val = create_mask_row.text().to_string();
            let directory_mask_val = directory_mask_row.text().to_string();
            let force_create_val = force_create_row.text().to_string();
            let force_directory_val = force_directory_row.text().to_string();
            if !create_mask_val.is_empty() {
                if let Err(e) = validate_octal_mode(&create_mask_val, "Create mask") {
                    show_error_toast(&e);
                    return;
                }
            }
            if !directory_mask_val.is_empty() {
                if let Err(e) = validate_octal_mode(&directory_mask_val, "Directory mask") {
                    show_error_toast(&e);
                    return;
                }
            }
            if !force_create_val.is_empty() {
                if let Err(e) = validate_octal_mode(&force_create_val, "Force create mode") {
                    show_error_toast(&e);
                    return;
                }
            }
            if !force_directory_val.is_empty() {
                if let Err(e) = validate_octal_mode(&force_directory_val, "Force directory mode") {
                    show_error_toast(&e);
                    return;
                }
            }

            // Validate user/group fields
            let force_user_val = force_user_row.text().to_string();
            let force_group_val = force_group_row.text().to_string();
            if !force_user_val.is_empty() {
                if let Err(e) = validate_option_value(&force_user_val, "Force user") {
                    show_error_toast(&e);
                    return;
                }
            }
            if !force_group_val.is_empty() {
                if let Err(e) = validate_option_value(&force_group_val, "Force group") {
                    show_error_toast(&e);
                    return;
                }
            }

            let share = Share {
                name: name_val.clone(),
                path: path_val.clone(),
                comment: comment_row.text().to_string(),
                available: available_sw.is_active(),
                browsable: browsable_sw.is_active(),
                writable: writable_sw.is_active(),
                read_only: read_only_sw.is_active(),
                guest_ok: guest_ok_sw.is_active(),
                valid_users: csv_to_vec(&valid_users_row),
                invalid_users: csv_to_vec(&invalid_users_row),
                read_list: csv_to_vec(&read_list_row),
                write_list: csv_to_vec(&write_list_row),
                force_user: force_user_row.text().to_string(),
                force_group: force_group_row.text().to_string(),
                hosts_allow: csv_to_vec(&hosts_allow_row),
                hosts_deny: csv_to_vec(&hosts_deny_row),
                create_mask: create_mask_row.text().to_string(),
                directory_mask: directory_mask_row.text().to_string(),
                force_create_mode: force_create_row.text().to_string(),
                force_directory_mode: force_directory_row.text().to_string(),
                inherit_acls: inherit_acls_sw.is_active(),
                inherit_permissions: inherit_permissions_sw.is_active(),
                vfs_objects: csv_to_vec(&vfs_objects_row),
            };

            if let Some(ref old) = old_name {
                // Edit mode: update in-place
                let mut shares = shares_for_confirm.borrow_mut();
                if let Some(existing) = shares.iter_mut().find(|s| s.name == *old) {
                    *existing = share.clone();
                }
                // Update the existing row's title/subtitle
                if let Some(ref row) = existing_row_clone {
                    row.set_title(&share.name);
                    row.set_subtitle(&share.path);
                }
                show_success_toast(&format!("Share '{}' updated", name_val));
            } else {
                // Add mode: push new share and create a row
                shares_for_confirm.borrow_mut().push(share.clone());

                let share_row = ActionRow::builder()
                    .title(&share.name)
                    .subtitle(&share.path)
                    .build();

                // Edit button
                let edit_button = Button::builder()
                    .label("Edit")
                    .css_classes(["flat"])
                    .build();
                let share_for_edit = share.clone();
                let group_for_edit = group_clone.clone();
                let global_for_edit = global_clone.clone();
                let shares_for_edit = shares_for_confirm.clone();
                let row_for_edit = share_row.clone();
                edit_button.connect_clicked(move |btn| {
                    let parent = btn.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                    show_share_dialog(&group_for_edit, &global_for_edit, &shares_for_edit, Some(&share_for_edit), Some(&row_for_edit), parent.as_ref());
                });
                share_row.add_suffix(&edit_button);

                // Preview button
                let preview_button = Button::builder()
                    .label("Preview")
                    .css_classes(["flat"])
                    .build();
                let share_for_preview = share.clone();
                let global_for_preview = global_clone.clone();
                preview_button.connect_clicked(move |btn| {
                    let parent = btn.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                    show_share_preview_dialog(&share_for_preview, &global_for_preview, parent.as_ref());
                });
                share_row.add_suffix(&preview_button);

                // Remove button
                let remove_button = Button::builder()
                    .label("Remove")
                    .css_classes(["flat", "destructive-action"])
                    .build();
                let remove_name = share.name.clone();
                let group_for_remove = group_clone.clone();
                let row_for_remove = share_row.clone();
                let shares_for_remove = shares_for_confirm.clone();
                remove_button.connect_clicked(move |_| {
                    shares_for_remove.borrow_mut().retain(|s| s.name != remove_name);
                    group_for_remove.remove(&row_for_remove);
                    show_success_toast(&format!("Share '{}' removed", remove_name));
                });
                share_row.add_suffix(&remove_button);
                share_row.set_activatable(true);

                group_clone.add(&share_row);
                show_success_toast(&format!("Share '{}' added", name_val));
            }

            if let Some(d) = dialog_weak.upgrade() { d.close(); }
        });

        dialog.present();
    }

    /// Create shares preferences group with add/remove functionality
    fn create_shares_group(shared_shares: &std::rc::Rc<std::cell::RefCell<Vec<Share>>>, global: &GlobalSettings) -> PreferencesGroup {
        let group = PreferencesGroup::builder()
            .title("Shares")
            .build();

        // Button row for Add Share + From Template
        let button_row = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(8)
            .build();

        // Add share button
        let add_button = Button::builder()
            .label("Add Share")
            .css_classes(["flat", "suggested-action"])
            .build();

        let group_for_add = group.clone();
        let global_for_add = global.clone();
        let shares_for_add = shared_shares.clone();
        add_button.connect_clicked(move |btn| {
            let parent = btn.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            show_share_dialog(&group_for_add, &global_for_add, &shares_for_add, None, None, parent.as_ref());
        });
        button_row.append(&add_button);

        // From Template button
        let template_button = Button::builder()
            .label("From Template")
            .css_classes(["flat"])
            .tooltip_text("Add a share from a preset template")
            .build();

        let group_for_template = group.clone();
        let global_for_template = global.clone();
        let shares_for_template = shared_shares.clone();
        template_button.connect_clicked(move |btn| {
            let parent = btn.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            show_share_template_picker(&group_for_template, &global_for_template, &shares_for_template, parent.as_ref());
        });
        button_row.append(&template_button);

        group.add(&button_row);

        // List existing shares
        for share in shared_shares.borrow().iter() {
            let share_row = ActionRow::builder()
                .title(&share.name)
                .subtitle(&share.path)
                .build();

            // Edit button for each share
            let edit_button = Button::builder()
                .label("Edit")
                .css_classes(["flat"])
                .build();

            let share_for_edit = share.clone();
            let group_for_edit = group.clone();
            let global_for_edit = global.clone();
            let shares_for_edit = shared_shares.clone();
            let row_for_edit = share_row.clone();
            edit_button.connect_clicked(move |btn| {
                let parent = btn.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                show_share_dialog(&group_for_edit, &global_for_edit, &shares_for_edit, Some(&share_for_edit), Some(&row_for_edit), parent.as_ref());
            });

            share_row.add_suffix(&edit_button);

            // Preview button for each share
            let preview_button = Button::builder()
                .label("Preview")
                .css_classes(["flat"])
                .build();
            
            let share_clone = share.clone();
            let global_clone = global.clone();
            preview_button.connect_clicked(move |btn| {
                // Show preview dialog
                let parent = btn.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                show_share_preview_dialog(&share_clone, &global_clone, parent.as_ref());
            });
            
            share_row.add_suffix(&preview_button);

            // Remove button for each share
            let remove_button = Button::builder()
                .label("Remove")
                .css_classes(["flat", "destructive-action"])
                .build();
            
            let share_name = share.name.clone();
            let shares_for_remove = shared_shares.clone();
            let group_for_remove = group.clone();
            let row_for_remove = share_row.clone();
            remove_button.connect_clicked(move |_button| {
                shares_for_remove.borrow_mut().retain(|s| s.name != share_name);
                group_for_remove.remove(&row_for_remove);
                show_success_toast(&format!("Share '{}' removed", share_name));
            });
            
            share_row.add_suffix(&remove_button);
            share_row.set_activatable(true);
            
            group.add(&share_row);
        }

        group
    }

    /// Shows a dialog with share preview and testparm output
    fn show_share_preview_dialog(share: &Share, global: &GlobalSettings, parent: Option<&gtk::Window>) {
        // Create the dialog window
        let dialog = adw::Window::builder()
            .title(&format!("Preview: {}", share.name))
            .default_width(700)
            .default_height(500)
            .modal(true)
            .build();

        if let Some(win) = parent {
            dialog.set_transient_for(Some(win));
        }

        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(24)
            .margin_end(24)
            .margin_top(24)
            .margin_bottom(24)
            .spacing(16)
            .build();

        // Title
        let title_label = Label::builder()
            .label(&format!("Share Preview: {}", share.name))
            .css_classes(["title-2"])
            .halign(Align::Start)
            .build();
        content.append(&title_label);

        // Generate share preview
        let share_preview = SharePreview::preview_share_section(share)
            .unwrap_or_else(|e| format!("Error generating preview: {}", e));

        // Preview section
        let preview_label = Label::builder()
            .label("Generated smb.conf section:")
            .css_classes(["heading"])
            .halign(Align::Start)
            .build();
        content.append(&preview_label);

        let preview_scrolled = ScrolledWindow::builder()
            .min_content_height(120)
            .max_content_height(150)
            .build();
        
        let preview_text = TextView::builder()
            .editable(false)
            .monospace(true)
            .wrap_mode(gtk::WrapMode::WordChar)
            .build();
        
        let preview_buffer = preview_text.buffer();
        preview_buffer.set_text(&share_preview);
        preview_scrolled.set_child(Some(&preview_text));
        content.append(&preview_scrolled);

        // Run testparm button
        let testparm_button = Button::builder()
            .label("Run testparm")
            .css_classes(["suggested-action"])
            .build();
        
        let testparm_output_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(8)
            .build();
        
        let testparm_label = Label::builder()
            .label("testparm output:")
            .css_classes(["heading"])
            .halign(Align::Start)
            .build();
        testparm_output_box.append(&testparm_label);

        let testparm_scrolled = ScrolledWindow::builder()
            .min_content_height(150)
            .build();
        
        let testparm_text = TextView::builder()
            .editable(false)
            .monospace(true)
            .wrap_mode(gtk::WrapMode::WordChar)
            .build();
        
        let testparm_buffer = testparm_text.buffer();
        testparm_buffer.set_text("Click 'Run testparm' to validate the configuration...");
        
        testparm_scrolled.set_child(Some(&testparm_text));
        testparm_output_box.append(&testparm_scrolled);
        
        let share_for_testparm = share.clone();
        let global_for_testparm = global.clone();
        let testparm_buffer_clone = testparm_buffer.clone();
        
        testparm_button.connect_clicked(move |_button| {
            // Run testparm and update the text view
            match SharePreview::run_testparm(&share_for_testparm, &global_for_testparm) {
                Ok(output) => {
                    let mut display_text = String::new();
                    
                    if !output.stdout.is_empty() {
                        display_text.push_str("=== STDOUT ===\n");
                        display_text.push_str(&output.stdout);
                        display_text.push_str("\n");
                    }
                    
                    if !output.stderr.is_empty() {
                        display_text.push_str("=== STDERR ===\n");
                        display_text.push_str(&output.stderr);
                        display_text.push_str("\n");
                    }
                    
                    display_text.push_str(&format!("Exit code: {}\n", output.exit_code));
                    
                    if output.has_errors {
                        display_text.push_str("\n⚠️  ERRORS DETECTED - See above for details\n");
                    } else {
                        display_text.push_str("\n✅ Configuration is valid\n");
                    }
                    
                    // Highlight error lines by adding markers
                    if !output.error_lines.is_empty() && output.error_lines[0] != 0 {
                        display_text.push_str("\nError lines: ");
                        for line in &output.error_lines {
                            display_text.push_str(&format!("{} ", line + 1)); // 1-indexed for user
                        }
                    }
                    
                    testparm_buffer_clone.set_text(&display_text);
                }
                Err(e) => {
                    testparm_buffer_clone.set_text(&format!("Error running testparm: {}", e));
                }
            }
        });
        
        content.append(&testparm_button);
        content.append(&testparm_output_box);

        // Close button
        let close_button = Button::builder()
            .label("Close")
            .css_classes(["destructive-action"])
            .build();
        
        close_button.connect_clicked(move |button| {
            if let Some(window) = button.root() {
                if let Ok(win) = window.downcast::<adw::Window>() {
                    win.close();
                }
            }
        });
        
        content.append(&close_button);

        dialog.set_content(Some(&content));
        dialog.present();
    }

    /// Creates a single navigation page with title and description
    fn create_navigation_page(id: &str, title: &str, description: &str) -> NavigationPage {
        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(24)
            .margin_end(24)
            .margin_top(24)
            .margin_bottom(24)
            .spacing(16)
            .build();

        // Page title
        let title_label = Label::builder()
            .label(title)
            .css_classes(["title-1"])
            .build();
        content.append(&title_label);

        // Page description
        let desc_label = Label::builder()
            .label(description)
            .css_classes(["body"])
            .build();
        content.append(&desc_label);

        // Placeholder content - will be expanded in future tasks
        let placeholder = Label::builder()
            .label(&format!("{} section - To be implemented", title))
            .css_classes(["caption", "dimmed"])
            .halign(Align::Start)
            .build();
        content.append(&placeholder);

        NavigationPage::builder()
            .title(title)
            .name(id)
            .child(&content)
            .build()
    }

    /// Applies dark theme compatible with Linux Mint
    fn apply_dark_theme() {
        // Use AdwStyleManager to detect and follow system theme
        let style_manager = StyleManager::default();
        // Try to enable dark mode - this follows system preference on Linux Mint
        style_manager.set_color_scheme(adw::ColorScheme::PreferDark);
    }

    // --- Theme preference system ---

    /// Theme preference file path: ~/.config/samba-gui/theme.conf
    fn theme_pref_path() -> std::path::PathBuf {
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                std::path::PathBuf::from(home).join(".config")
            });
        config_dir.join("samba-gui").join("theme.conf")
    }

    /// Read the saved theme preference. Returns "dark", "light", or "system".
    fn read_theme_pref() -> String {
        let path = theme_pref_path();
        std::fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "dark".to_string())
    }

    /// Save the theme preference to disk.
    fn save_theme_pref(pref: &str) {
        let path = theme_pref_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, pref);
    }

    /// Apply the saved theme preference (called at startup).
    fn apply_saved_theme() {
        let pref = read_theme_pref();
        apply_theme_by_name(&pref);
    }

    /// Apply a theme by name: "dark", "light", or "system".
    fn apply_theme_by_name(name: &str) {
        let style_manager = StyleManager::default();
        match name {
            "light" => style_manager.set_color_scheme(adw::ColorScheme::ForceLight),
            "system" => style_manager.set_color_scheme(adw::ColorScheme::Default),
            _ => style_manager.set_color_scheme(adw::ColorScheme::PreferDark),
        }
    }

    /// Cycle through themes: dark → light → system → dark …
    /// Updates the button icon and shows a toast.
    fn cycle_theme(button: &Button) {
        let current = read_theme_pref();
        let (next, icon, label) = match current.as_str() {
            "dark" => ("light", "display-brightness-symbolic", "Light theme"),
            "light" => ("system", "preferences-desktop-appearance-symbolic", "System theme"),
            _ => ("dark", "weather-clear-night-symbolic", "Dark theme"),
        };
        save_theme_pref(next);
        apply_theme_by_name(next);
        button.set_icon_name(icon);
        button.set_tooltip_text(Some(&format!("Current: {} (click to cycle)", label)));
        show_toast(&format!("Switched to {} theme", label.to_lowercase()));
    }

    /// Activates the application and sets up the main window
    pub fn activate(app: &Application) {
        // Register the password callback for privileged operations.
        // This shows a GTK dialog when sudo needs a password, so the user
        // only enters it once per session.
        crate::services::privileged_executor::set_password_callback(prompt_password_dialog);

        // Set the application icon for the taskbar / window list.
        // Try to load from the assets directory next to the binary,
        // falling back to the source tree location for development.
        set_app_icon();

        let window = create_main_window(app);
        window.present();
    }

    /// Register the application icon so it appears in the taskbar and window list.
    fn set_app_icon() {
        // The window manager (Cinnamon/Mutter/KWin) looks up the taskbar icon
        // by matching the GApplication ID to a .desktop file, then using the
        // Icon= field from that file to find the icon in the icon theme.
        //
        // For development, we also add the assets directory to the search path
        // and copy icons to the user-local icon theme so they're always current.
        let display = gtk::gdk::Display::default().unwrap();
        let theme = gtk::IconTheme::for_display(&display);

        // Add the local assets directory so icons are found during development
        let assets_dirs: Vec<std::path::PathBuf> = vec![
            std::path::PathBuf::from("assets"),
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets"),
        ];
        for dir in &assets_dirs {
            if dir.exists() {
                theme.add_search_path(dir);
            }
        }

        // During development, sync icons to the user-local icon theme so the
        // taskbar/window list picks up the latest version without a .deb install.
        install_user_icons();

        gtk::Window::set_default_icon_name("com.example.samba-gui");
    }

    /// Copy the application icons from the assets directory into
    /// ~/.local/share/icons/hicolor/ and update the icon cache.
    /// This ensures the taskbar shows the current icon during development.
    fn install_user_icons() {
        let sizes = &[("48", "48x48"), ("64", "64x64"), ("128", "128x128"), ("256", "256x256")];
        let home = match std::env::var("HOME") {
            Ok(h) => h,
            Err(_) => return,
        };
        let icon_base = std::path::PathBuf::from(&home)
            .join(".local/share/icons/hicolor");

        // Find the assets directory
        let assets_dir = ["assets", &format!("{}/assets", env!("CARGO_MANIFEST_DIR"))]
            .iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.exists());

        let assets_dir = match assets_dir {
            Some(d) => d,
            None => return,
        };

        let mut any_updated = false;
        for (size_suffix, dir_name) in sizes {
            let src = assets_dir.join(format!("com.example.samba-gui-{}.png", size_suffix));
            let dst_dir = icon_base.join(dir_name).join("apps");
            let dst = dst_dir.join("com.example.samba-gui.png");

            if !src.exists() {
                continue;
            }

            // Only copy if source is newer or destination doesn't exist
            let needs_update = if dst.exists() {
                match (std::fs::metadata(&src), std::fs::metadata(&dst)) {
                    (Ok(src_meta), Ok(dst_meta)) => {
                        src_meta.modified().ok() > dst_meta.modified().ok()
                    }
                    _ => true,
                }
            } else {
                true
            };

            if needs_update {
                let _ = std::fs::create_dir_all(&dst_dir);
                if std::fs::copy(&src, &dst).is_ok() {
                    any_updated = true;
                }
            }
        }

        // Rebuild the icon cache if we updated anything
        if any_updated {
            let _ = std::process::Command::new("gtk-update-icon-cache")
                .args(["-f", "-t", &icon_base.to_string_lossy()])
                .output();
        }
    }

    /// Shows a modal password dialog and returns the entered password,
    /// or None if the user cancelled. Used by the privileged executor
    /// for the one-time sudo authentication.
    fn prompt_password_dialog() -> Option<String> {
        use std::cell::RefCell;
        use std::rc::Rc;

        // We need to run a nested main loop to make this synchronous
        let result: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
        let main_loop = gtk::glib::MainLoop::new(None, false);

        let dialog = adw::Window::builder()
            .title("Authentication Required")
            .default_width(380)
            .default_height(200)
            .modal(true)
            .build();

        let content = Box::builder()
            .orientation(Orientation::Vertical)
            .margin_start(24)
            .margin_end(24)
            .margin_top(24)
            .margin_bottom(24)
            .spacing(16)
            .build();

        let label = Label::builder()
            .label("Enter your password to manage Samba")
            .css_classes(["body"])
            .halign(Align::Start)
            .build();
        content.append(&label);

        let password_entry = gtk::PasswordEntry::builder()
            .placeholder_text("Password")
            .show_peek_icon(true)
            .build();
        content.append(&password_entry);

        let button_row = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .halign(Align::End)
            .build();

        let cancel_btn = Button::builder()
            .label("Cancel")
            .css_classes(["flat"])
            .build();

        let ok_btn = Button::builder()
            .label("Authenticate")
            .css_classes(["suggested-action"])
            .build();

        button_row.append(&cancel_btn);
        button_row.append(&ok_btn);
        content.append(&button_row);
        dialog.set_content(Some(&content));

        // Wire up OK
        let result_ok = result.clone();
        let loop_ok = main_loop.clone();
        let dialog_ok = dialog.clone();
        let entry_ok = password_entry.clone();
        ok_btn.connect_clicked(move |_| {
            let pw = entry_ok.text().to_string();
            if !pw.is_empty() {
                *result_ok.borrow_mut() = Some(pw);
            }
            dialog_ok.close();
            loop_ok.quit();
        });

        // Wire up Cancel
        let loop_cancel = main_loop.clone();
        let dialog_cancel = dialog.clone();
        cancel_btn.connect_clicked(move |_| {
            dialog_cancel.close();
            loop_cancel.quit();
        });

        // Wire up Enter key in password field
        let ok_btn_enter = ok_btn.clone();
        password_entry.connect_activate(move |_| {
            ok_btn_enter.emit_clicked();
        });

        // Handle window close (X button)
        let loop_close = main_loop.clone();
        dialog.connect_close_request(move |_| {
            loop_close.quit();
            gtk::glib::Propagation::Proceed
        });

        dialog.present();
        main_loop.run();

        let val = result.borrow().clone();
        val
    }
}

#[cfg(feature = "gui")]
pub use gui::activate;

#[cfg(feature = "gui")]
pub use gui::show_toast;

#[cfg(feature = "gui")]
pub use gui::show_error_toast;

#[cfg(feature = "gui")]
pub use gui::show_success_toast;

#[cfg(not(feature = "gui"))]
pub fn activate(_app: &impl std::any::Any) {
    // No-op when GUI feature is not enabled
}