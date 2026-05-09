// Suppress dead_code warnings for the non-GUI build.
// All service/VM/config code is consumed by the GUI feature;
// without it the binary is just a smoke-test stub.
#![cfg_attr(not(feature = "gui"), allow(dead_code, unused_imports))]

mod config;
mod services;
mod ui;
mod vm;

use log::info;

#[cfg(feature = "gui")]
use adw::Application;

#[cfg(feature = "gui")]
use adw::prelude::*;

#[cfg(feature = "gui")]
use ui::activate;

#[cfg(feature = "gui")]
use adw::prelude::{ApplicationExt, ApplicationExtManual};

fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    info!("SAMBA GUI application starting...");

    // Verify data models are properly defined
    let _config = config::SambaConfig::default();
    let _global_settings = config::GlobalSettings::default();
    let _share = config::Share::default();
    let _systemd_mount_entry = config::SystemdMountEntry::default();
    let _service_status = config::ServiceStatus::default();
    let _samba_user = config::SambaUser::default();
    let _backup_info = config::BackupInfo::default();

    println!("SAMBA GUI - Configuration management for SAMBA server and client");
    println!("Data models initialized successfully.");
    
    #[cfg(feature = "gui")]
    {
        println!("GUI support enabled. Run on Linux with GTK4/libadwaita for full functionality.");

        let application = Application::builder()
            .application_id("com.example.samba-gui")
            .build();
        
        // Connect the activate signal to create the main window
        // GApplication ensures only one instance runs. If a second instance
        // is launched, it signals this one and activate fires again —
        // we just present the existing window instead of creating a new one.
        application.connect_activate(move |app| {
            if let Some(window) = app.active_window() {
                window.present();
            } else {
                activate(app);
            }
        });
        
        application.run();
    }
    
    #[cfg(not(feature = "gui"))]
    {
        println!("GUI support disabled. Enable 'gui' feature on Linux for GTK4/libadwaita.");
    }
}