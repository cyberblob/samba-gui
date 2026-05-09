#![allow(dead_code)]
// User management UI - displays and manages SAMBA users
// Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 5.3, 5.4, 5.5

#[cfg(feature = "gui")]
mod gui {
    use adw::NavigationPage;
    use gtk::{Box, Label, Button, Orientation, Align, Entry, PasswordEntry, Spinner};

    use crate::config::SambaUser;
    use crate::services::{UserManager, SambaMode};
    use adw::prelude::*;

    // Import toast functions from mod.rs
    use crate::ui::show_toast;

    /// Creates the user management page
pub fn create_user_management_page() -> adw::NavigationPage {
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
            .label("User Management")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        // Description (shows detected mode)
        let manager = UserManager::new();
        let mode_hint = match manager.mode() {
            SambaMode::AdDc => "Active Directory Domain Controller mode (samba-tool)",
            SambaMode::Standalone => "Standalone mode (passdb)",
        };
        let desc = Label::builder()
            .label(&format!("Manage SAMBA user accounts — {}", mode_hint))
            .css_classes(["body"])
            .halign(Align::Start)
            .build();
        content.append(&desc);

        // Users list container
        let users_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(8)
            .build();
        content.append(&users_box);

        // Error message label (hidden by default)
        let error_label = Label::builder()
            .label("")
            .css_classes(["error"])
            .halign(Align::Start)
            .visible(false)
            .build();
        content.append(&error_label);

        // Initial load of users
        load_users(&users_box, &error_label);

        // Button row
        let button_row = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .build();

        // Refresh button
        let refresh_button = Button::builder()
            .label("Refresh")
            .css_classes(["flat"])
            .build();
        
        let users_box_clone = users_box.clone();
        let error_label_clone = error_label.clone();
        refresh_button.connect_clicked(move |_button| {
            load_users(&users_box_clone, &error_label_clone);
        });
        button_row.append(&refresh_button);

        // Add user button
        let add_button = Button::builder()
            .label("Add User")
            .css_classes(["flat", "suggested-action"])
            .build();
        button_row.append(&add_button);

        content.append(&button_row);

        // Create dialog for adding users (will be shown when button clicked)
        let add_user_dialog = create_add_user_dialog(&users_box, &error_label);
        add_button.connect_clicked(move |btn| {
            if let Some(root) = btn.root() {
                if let Ok(win) = root.downcast::<gtk::Window>() {
                    add_user_dialog.set_transient_for(Some(&win));
                }
            }
            add_user_dialog.present();
        });

        NavigationPage::builder()
            .title("Users")
            .name("users")
            .child(&content)
            .build()
    }

    /// Shows loading indicator during user operations
    /// Requirement 5.3: Show loading indicators during long operations
fn show_loading_indicator(users_box: &gtk::Box) {
        // Clear existing content
        while let Some(child) = users_box.first_child() {
            users_box.remove(&child);
        }

        let loading_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(16)
            .halign(Align::Center)
            .valign(Align::Center)
            .build();

        let spinner = Spinner::new();
        spinner.set_spinning(true);
        spinner.set_size_request(48, 48);
        loading_box.append(&spinner);

        let loading_label = Label::builder()
            .label("Loading users...")
            .css_classes(["body"])
            .build();
        loading_box.append(&loading_label);

        users_box.append(&loading_box);
    }

    /// Loads all users and creates their rows
fn load_users(users_box: &gtk::Box, error_label: &gtk::Label) {
        // Show loading indicator (Requirement 5.3)
        show_loading_indicator(users_box);

        // Clear existing rows
        while let Some(child) = users_box.first_child() {
            users_box.remove(&child);
        }

        let manager = UserManager::new();
        
        match manager.list_users() {
            Ok(users) => {
                if users.is_empty() {
                    let empty_label = Label::builder()
                        .label("No SAMBA users found. Click 'Add User' to create one.")
                        .css_classes(["dimmed", "caption"])
                        .halign(Align::Start)
                        .build();
                    users_box.append(&empty_label);
                } else {
                    for user in users {
                        let user_row = create_user_row(user, users_box, error_label);
                        users_box.append(&user_row);
                    }
                }
                error_label.set_visible(false);
            }
            Err(e) => {
                error_label.set_label(&format!("Failed to load users: {}", e));
                error_label.set_visible(true);
                // Show error toast (Requirement 5.4)
                show_toast(&format!("Failed to load users: {}", e));
                
                // Add empty state
                let empty_label = Label::builder()
                    .label("Unable to load users. Make sure you have permission to run pdbedit.")
                    .css_classes(["dimmed", "caption"])
                    .halign(Align::Start)
                    .build();
                users_box.append(&empty_label);
            }
        }
    }

    /// Creates a row for a single user with status and control buttons
fn create_user_row(
        user: SambaUser,
        users_box: &gtk::Box,
        error_label: &gtk::Label
    ) -> gtk::Box {
        let row = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .build();

        // Username label
        let name_label = Label::builder()
            .label(&user.username)
            .halign(Align::Start)
            .hexpand(true)
            .build();
        row.append(&name_label);

        // Status indicator
        let status_text = if user.enabled { "Enabled" } else { "Disabled" };
        let status_indicator = Label::builder()
            .label(status_text)
            .halign(Align::Center)
            .build();
        row.append(&status_indicator);

        // Enable/Disable button
        let toggle_button = Button::builder()
            .label(if user.enabled { "Disable" } else { "Enable" })
            .css_classes(["flat"])
            .build();

        let user_clone = user.clone();
        let users_box_toggle = users_box.clone();
        let error_label_toggle = error_label.clone();
        
        toggle_button.connect_clicked(move |_button| {
            error_label_toggle.set_visible(false);
            
            // Show loading indicator (Requirement 5.3)
            show_loading_indicator(&users_box_toggle);
            
            let mgr = UserManager::new();
            
            let result = if user_clone.enabled {
                mgr.disable_user(&user_clone.username)
            } else {
                mgr.enable_user(&user_clone.username)
            };
            
            match result {
                Ok(()) => {
                    // Show success toast (Requirement 5.4)
                    show_toast(&format!("User {} {}", user_clone.username, 
                        if user_clone.enabled { "disabled" } else { "enabled" }));
                    // Refresh user list after toggle
                    load_users(&users_box_toggle, &error_label_toggle);
                }
                Err(e) => {
                    // Display error message and toast (Requirements 5.4, 3.6)
                    error_label_toggle.set_label(&format!("Failed to {} user: {}", 
                        if user_clone.enabled { "disable" } else { "enable" }, e));
                    error_label_toggle.set_visible(true);
                    show_toast(&format!("Failed to {} user: {}", 
                        if user_clone.enabled { "disable" } else { "enable" }, e));
                }
            }
        });

        row.append(&toggle_button);

        row
    }

    /// Creates the add user dialog with password confirmation
    fn create_add_user_dialog(users_box: &gtk::Box, error_label: &gtk::Label) -> adw::Window {
        let dialog = adw::Window::builder()
            .title("Add SAMBA User")
            .default_width(400)
            .default_height(300)
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

        // Dialog title
        let title = Label::builder()
            .label("Create New SAMBA User")
            .css_classes(["title-2"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        // Username input
        let username_entry = Entry::builder()
            .placeholder_text("Username")
            .build();
        content.append(&username_entry);

        // Password input
        let password_entry = PasswordEntry::builder()
            .placeholder_text("Password")
            .show_peek_icon(true)
            .build();
        content.append(&password_entry);

        // Confirm password input
        let confirm_entry = PasswordEntry::builder()
            .placeholder_text("Confirm Password")
            .show_peek_icon(true)
            .build();
        content.append(&confirm_entry);

        // Error label for dialog
        let dialog_error = Label::builder()
            .label("")
            .css_classes(["error"])
            .halign(Align::Start)
            .visible(false)
            .build();
        content.append(&dialog_error);

        // Button row
        let button_row = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .halign(Align::End)
            .build();

        // Cancel button
        let cancel_button = Button::builder()
            .label("Cancel")
            .css_classes(["flat"])
            .build();
        
        cancel_button.connect_clicked(move |button: &gtk::Button| {
            if let Some(window) = button.root() {
                window.downcast::<adw::Window>().unwrap().close();
            }
        });
        button_row.append(&cancel_button);

        // Create button
        let create_button = Button::builder()
            .label("Create")
            .css_classes(["suggested-action"])
            .build();
        
        // Get clones for the button handler
        let username_entry_clone = username_entry.clone();
        let password_entry_clone = password_entry.clone();
        let confirm_entry_clone = confirm_entry.clone();
        let users_box_create = users_box.clone();
        let error_label_create = error_label.clone();
        let dialog_error_create = dialog_error.clone();
        
        create_button.connect_clicked(move |_button: &gtk::Button| {
            dialog_error_create.set_visible(false);
            
            let username = username_entry_clone.text().to_string();
            let password = password_entry_clone.text().to_string();
            let confirmation = confirm_entry_clone.text().to_string();
            
            // Validate inputs
            if username.is_empty() {
                dialog_error_create.set_label("Username is required");
                dialog_error_create.set_visible(true);
                return;
            }

            // Validate username characters — only allow safe POSIX-style usernames
            if !username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
                dialog_error_create.set_label("Username may only contain letters, digits, hyphens, underscores, and dots");
                dialog_error_create.set_visible(true);
                return;
            }
            if username.starts_with('-') {
                dialog_error_create.set_label("Username must not start with a hyphen");
                dialog_error_create.set_visible(true);
                return;
            }
            if username.len() > 32 {
                dialog_error_create.set_label("Username must be 32 characters or fewer");
                dialog_error_create.set_visible(true);
                return;
            }
            
            if password.is_empty() {
                dialog_error_create.set_label("Password is required");
                dialog_error_create.set_visible(true);
                return;
            }
            
            // Validate password confirmation (Requirement 4.5)
            if UserManager::validate_password_confirmation(&password, &confirmation).is_err() {
                dialog_error_create.set_label("Passwords do not match");
                dialog_error_create.set_visible(true);
                return;
            }
            
            // Create the user (Requirement 4.2)
            let manager = UserManager::new();
            match manager.create_user(&username, &password) {
                Ok(()) => {
                    // Show success toast (Requirement 5.4)
                    show_toast(&format!("User {} created successfully", username));
                    
                    // Close dialog and refresh list
                    if let Some(window) = _button.root() {
                        window.downcast::<adw::Window>().unwrap().close();
                    }
                    load_users(&users_box_create, &error_label_create);
                }
                Err(e) => {
                    dialog_error_create.set_label(&format!("Failed to create user: {}", e));
                    dialog_error_create.set_visible(true);
                    // Show error toast (Requirement 5.4)
                    show_toast(&format!("Failed to create user: {}", e));
                }
            }
        });
        
        button_row.append(&create_button);
        content.append(&button_row);

        dialog.set_content(Some(&content));
        dialog
    }
}

#[cfg(feature = "gui")]
#[allow(unused_imports)]
pub use gui::create_user_management_page;

#[cfg(not(feature = "gui"))]
pub fn create_user_management_page() {
    // No-op when GUI feature is not enabled
}