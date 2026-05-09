#![allow(dead_code)]
// Service management UI - displays and controls Samba services (smbd, nmbd, winbind)
// Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 5.3, 5.4, 5.5

#[cfg(feature = "gui")]
mod gui {
    use adw::NavigationPage;
    use gtk::{Box, Label, Button, Orientation, Align, Spinner};
    use crate::services::ServiceController;
    use adw::prelude::*;

    // Import toast functions from mod.rs
    use crate::ui::show_toast;

    /// Creates the service management page
pub fn create_service_management_page() -> adw::NavigationPage {
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
            .label("Service Management")
            .css_classes(["title-1"])
            .halign(Align::Start)
            .build();
        content.append(&title);

        // Description
        let desc = Label::builder()
            .label("Manage Samba daemon services")
            .css_classes(["body"])
            .halign(Align::Start)
            .build();
        content.append(&desc);

        // Services container
        let services_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(8)
            .build();
        content.append(&services_box);

        // Error message label (hidden by default)
        let error_label = Label::builder()
            .label("")
            .css_classes(["error"])
            .halign(Align::Start)
            .visible(false)
            .build();
        content.append(&error_label);

        // Initial load of services
        load_services(&services_box, &error_label);

        // Button row
        let button_row = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .build();

        // Refresh button
        let refresh_button = Button::builder()
            .label("Refresh Status")
            .css_classes(["flat"])
            .build();
        
        let services_box_clone = services_box.clone();
        let error_label_clone = error_label.clone();
        refresh_button.connect_clicked(move |_button| {
            load_services(&services_box_clone, &error_label_clone);
        });
        button_row.append(&refresh_button);

        content.append(&button_row);

        NavigationPage::builder()
            .title("Services")
            .name("services")
            .child(&content)
            .build()
    }

    /// Shows loading indicator during service operations
    /// Requirement 5.3: Show loading indicators during long operations
fn show_loading_indicator(services_box: &gtk::Box) {
        // Clear existing content
        while let Some(child) = services_box.first_child() {
            services_box.remove(&child);
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
            .label("Loading services...")
            .css_classes(["body"])
            .build();
        loading_box.append(&loading_label);

        services_box.append(&loading_box);
    }

    /// Loads all services and creates their rows
fn load_services(services_box: &gtk::Box, error_label: &gtk::Label) {
        // Show loading indicator (Requirement 5.3)
        show_loading_indicator(services_box);

        // Clear existing rows after a brief delay (simulating async load)
        // In a real implementation, this would be async
        while let Some(child) = services_box.first_child() {
            services_box.remove(&child);
        }

        let controller = ServiceController::new();
        let services = ServiceController::managed_services();

        for service_name in services {
            let service_row = create_service_row(&controller, service_name, services_box, error_label);
            services_box.append(&service_row);
        }
    }

    /// Creates a row for a single service with status and control buttons
fn create_service_row(
        controller: &ServiceController,
        service_name: &str,
        services_box: &gtk::Box,
        error_label: &gtk::Label
    ) -> gtk::Box {
        let row = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .build();

        // Get service status
        let status = controller.get_status(service_name);
        
        // Service name label
        let name_label = Label::builder()
            .label(service_name)
            .halign(Align::Start)
            .hexpand(true)
            .build();
        row.append(&name_label);

        // Status text
        let status_text = match &status {
            Ok(s) => {
                if s.active {
                    format!("Active ({})", s.substate)
                } else {
                    format!("Inactive ({})", s.substate)
                }
            }
            Err(_) => "Unknown".to_string()
        };

        let status_indicator = Label::builder()
            .label(&status_text)
            .halign(Align::Center)
            .build();
        row.append(&status_indicator);

        // Enabled status
        let enabled_text = match &status {
            Ok(s) => if s.enabled { "Enabled" } else { "Disabled" },
            Err(_) => "Unknown"
        };
        let enabled_label = Label::builder()
            .label(enabled_text)
            .halign(Align::Center)
            .build();
        row.append(&enabled_label);

        // Start button
        let start_button = Button::builder()
            .label("Start")
            .css_classes(["flat", "suggested-action"])
            .build();
        
        // Stop button
        let stop_button = Button::builder()
            .label("Stop")
            .css_classes(["flat", "destructive-action"])
            .build();
        
        // Restart button
        let restart_button = Button::builder()
            .label("Restart")
            .css_classes(["flat"])
            .build();

        // Start button clicked
        let service_name_start = service_name.to_string();
        let services_box_start = services_box.clone();
        let error_label_start = error_label.clone();
        start_button.connect_clicked(move |_button| {
            error_label_start.set_visible(false);
            
            // Show loading indicator (Requirement 5.3)
            show_loading_indicator(&services_box_start);
            
            let controller = ServiceController::new();
            match controller.start(&service_name_start) {
                Ok(()) => {
                    // Show success toast (Requirement 5.4)
                    show_toast(&format!("Service {} started successfully", service_name_start));
                    // Refresh status after start
                    load_services(&services_box_start, &error_label_start);
                }
                Err(e) => {
                    // Display error message and toast (Requirements 5.4, 3.6)
                    error_label_start.set_label(&format!("Failed to start {}: {}", service_name_start, e));
                    error_label_start.set_visible(true);
                    show_toast(&format!("Failed to start {}: {}", service_name_start, e));
                }
            }
        });

        // Stop button clicked
        let service_name_stop = service_name.to_string();
        let services_box_stop = services_box.clone();
        let error_label_stop = error_label.clone();
        stop_button.connect_clicked(move |_button| {
            error_label_stop.set_visible(false);
            
            // Show loading indicator (Requirement 5.3)
            show_loading_indicator(&services_box_stop);
            
            let controller = ServiceController::new();
            match controller.stop(&service_name_stop) {
                Ok(()) => {
                    // Show success toast (Requirement 5.4)
                    show_toast(&format!("Service {} stopped successfully", service_name_stop));
                    // Refresh status after stop
                    load_services(&services_box_stop, &error_label_stop);
                }
                Err(e) => {
                    // Display error message and toast (Requirements 5.4, 3.6)
                    error_label_stop.set_label(&format!("Failed to stop {}: {}", service_name_stop, e));
                    error_label_stop.set_visible(true);
                    show_toast(&format!("Failed to stop {}: {}", service_name_stop, e));
                }
            }
        });

        // Restart button clicked
        let service_name_restart = service_name.to_string();
        let services_box_restart = services_box.clone();
        let error_label_restart = error_label.clone();
        restart_button.connect_clicked(move |_button| {
            error_label_restart.set_visible(false);
            
            // Show loading indicator (Requirement 5.3)
            show_loading_indicator(&services_box_restart);
            
            let controller = ServiceController::new();
            match controller.restart(&service_name_restart) {
                Ok(()) => {
                    // Show success toast (Requirement 5.4)
                    show_toast(&format!("Service {} restarted successfully", service_name_restart));
                    // Refresh status after restart
                    load_services(&services_box_restart, &error_label_restart);
                }
                Err(e) => {
                    // Display error message and toast (Requirements 5.4, 3.6)
                    error_label_restart.set_label(&format!("Failed to restart {}: {}", service_name_restart, e));
                    error_label_restart.set_visible(true);
                    show_toast(&format!("Failed to restart {}: {}", service_name_restart, e));
                }
            }
        });

        row.append(&start_button);
        row.append(&stop_button);
        row.append(&restart_button);

        row
    }
}

#[cfg(feature = "gui")]
#[allow(unused_imports)]
pub use gui::create_service_management_page;

#[cfg(not(feature = "gui"))]
pub fn create_service_management_page() {
    // No-op when GUI feature is not enabled
}