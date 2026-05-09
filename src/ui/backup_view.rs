// Backup and restore view for Samba GUI

#[cfg(feature = "gui")]
use adw::{NavigationPage, PreferencesGroup, ActionRow, EntryRow};
#[cfg(feature = "gui")]
use gtk::{Box, Label, Button, Orientation, Align};
#[cfg(feature = "gui")]
use adw::prelude::*;
#[cfg(feature = "gui")]
use glib;
#[cfg(feature = "gui")]
use std::path::PathBuf;

#[cfg(feature = "gui")]
use crate::config::BackupInfo;
#[cfg(feature = "gui")]
use crate::services::backup_manager::BackupManager;

#[cfg(feature = "gui")]
use crate::ui::show_error_toast;
#[cfg(feature = "gui")]
use crate::ui::show_success_toast;

#[cfg(feature = "gui")]
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// The list container holds a single PreferencesGroup child.
/// On refresh we remove the old group and append a new one.
#[cfg(feature = "gui")]
fn refresh_backup_list(container: &std::rc::Rc<Box>) {
    // Remove the old group
    while let Some(child) = container.first_child() {
        container.remove(&child);
    }
    // Build and append a fresh group
    let group_rc = std::rc::Rc::new(build_backup_list_group());
    populate_backup_group(&group_rc, container);
    container.append(group_rc.as_ref());
}

/// Build an empty PreferencesGroup with the title
#[cfg(feature = "gui")]
fn build_backup_list_group() -> PreferencesGroup {
    PreferencesGroup::builder()
        .title("Available Backups")
        .build()
}

/// Populate a PreferencesGroup with backup rows
#[cfg(feature = "gui")]
fn populate_backup_group(group: &std::rc::Rc<PreferencesGroup>, container: &std::rc::Rc<Box>) {
    let manager = BackupManager::new();
    match manager.list_backups() {
        Ok(backup_list) => {
            if backup_list.is_empty() {
                let empty_row = ActionRow::builder()
                    .title("No backups found")
                    .subtitle("Create a backup to get started")
                    .build();
                group.add(&empty_row);
            } else {
                for backup in &backup_list {
                    let row = create_backup_row(backup, container);
                    group.add(&row);
                }
            }
        }
        Err(e) => {
            let error_row = ActionRow::builder()
                .title("Error loading backups")
                .subtitle(&format!("{}", e))
                .build();
            group.add(&error_row);
        }
    }
}

#[cfg(feature = "gui")]
pub fn create_backup_page() -> NavigationPage {
    let content = Box::builder()
        .orientation(Orientation::Vertical)
        .margin_start(24)
        .margin_end(24)
        .margin_top(24)
        .margin_bottom(24)
        .spacing(16)
        .build();

    let title = Label::builder()
        .label("Backup & Restore")
        .css_classes(["title-1"])
        .halign(Align::Start)
        .build();
    content.append(&title);

    let location_group = create_backup_location_group();
    content.append(&location_group);

    // Container box that holds the backup list group — replaced on refresh
    let list_container = std::rc::Rc::new(Box::builder()
        .orientation(Orientation::Vertical)
        .build());

    let actions_group = create_backup_actions_group(&list_container);
    content.append(&actions_group);

    // Initial population
    let group_rc = std::rc::Rc::new(build_backup_list_group());
    populate_backup_group(&group_rc, &list_container);
    list_container.append(group_rc.as_ref());

    content.append(list_container.as_ref());

    NavigationPage::builder()
        .title("Backup")
        .name("backup")
        .child(&content)
        .build()
}

#[cfg(feature = "gui")]
fn create_backup_location_group() -> PreferencesGroup {
    let group = PreferencesGroup::builder()
        .title("Backup Location")
        .build();
    let default_path = {
        let mgr = BackupManager::new();
        mgr.backup_dir_display()
    };
    let path_row = EntryRow::builder()
        .title("Backup Directory")
        .text(&default_path)
        .build();
    group.add(&path_row);
    let info_row = ActionRow::builder()
        .title("Location Info")
        .subtitle("Backups are stored with timestamps for easy restoration")
        .build();
    group.add(&info_row);
    group
}

#[cfg(feature = "gui")]
fn create_backup_actions_group(list_container: &std::rc::Rc<Box>) -> PreferencesGroup {
    let group = PreferencesGroup::builder()
        .title("Actions")
        .build();

    // Create backup button
    let backup_button = Button::builder()
        .label("Create Backup Now")
        .css_classes(["suggested-action"])
        .build();

    let container_for_backup = list_container.clone();
    backup_button.connect_clicked(move |button| {
        let source = PathBuf::from("/etc/samba/smb.conf");

        let manager = BackupManager::new();
        if let Err(e) = manager.check_source(&source) {
            show_error_toast(&format!("Cannot backup: {}", e));
            return;
        }

        let needs_sudo = std::fs::File::open(&source).is_err();
        let _ = needs_sudo; // run_privileged handles auth automatically

        button.set_sensitive(false);
        let btn = button.clone();
        let container = container_for_backup.clone();

        let (sender, receiver) = std::sync::mpsc::channel::<Result<BackupInfo, String>>();

        std::thread::spawn(move || {
            let manager = BackupManager::new();
            let source = PathBuf::from("/etc/samba/smb.conf");
            let res = manager.backup(&source).map_err(|e| e.to_string());
            let _ = sender.send(res);
        });

        fn poll_backup(
            receiver: std::sync::mpsc::Receiver<Result<BackupInfo, String>>,
            container: std::rc::Rc<Box>,
            btn: Button,
        ) {
            match receiver.try_recv() {
                Ok(Ok(backup_info)) => {
                    show_success_toast(&format!(
                        "Backup created: {}",
                        backup_info.timestamp.format("%Y-%m-%d %H:%M:%S")
                    ));
                    refresh_backup_list(&container);
                    btn.set_sensitive(true);
                }
                Ok(Err(e)) => {
                    show_error_toast(&format!("Backup failed: {}", e));
                    btn.set_sensitive(true);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    glib::timeout_add_local_once(POLL_INTERVAL, move || {
                        poll_backup(receiver, container, btn);
                    });
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    show_error_toast("Backup thread terminated unexpectedly");
                    btn.set_sensitive(true);
                }
            }
        }
        poll_backup(receiver, container, btn);
    });
    group.add(&backup_button);

    // Refresh button
    let refresh_button = Button::builder()
        .label("Refresh List")
        .css_classes(["flat"])
        .build();

    let container_for_refresh = list_container.clone();
    refresh_button.connect_clicked(move |_button| {
        refresh_backup_list(&container_for_refresh);
        crate::ui::show_toast("Backup list refreshed");
    });
    group.add(&refresh_button);

    group
}

#[cfg(feature = "gui")]
fn create_backup_row(backup: &BackupInfo, list_container: &std::rc::Rc<Box>) -> ActionRow {
    let timestamp_str = backup.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();

    let row = ActionRow::builder()
        .title(&timestamp_str)
        .subtitle(&backup.path)
        .build();

    // Restore button
    let restore_button = Button::builder()
        .label("Restore")
        .css_classes(["flat", "suggested-action"])
        .build();

    let backup_path = backup.path.clone();
    restore_button.connect_clicked(move |button| {
        let destination = PathBuf::from("/etc/samba/smb.conf");
        let needs_sudo = std::fs::OpenOptions::new().write(true).open(&destination).is_err();
        let _ = needs_sudo; // run_privileged handles auth automatically
        button.set_sensitive(false);
        let btn = button.clone();
        let path_str = backup_path.clone();

        let (sender, receiver) = std::sync::mpsc::channel::<Result<(), String>>();
        std::thread::spawn(move || {
            let manager = BackupManager::new();
            let source = PathBuf::from(&path_str);
            let destination = PathBuf::from("/etc/samba/smb.conf");
            let res = manager.restore(&source, &destination).map_err(|e| e.to_string());
            let _ = sender.send(res);
        });

        fn poll_restore(receiver: std::sync::mpsc::Receiver<Result<(), String>>, btn: Button) {
            match receiver.try_recv() {
                Ok(Ok(())) => { show_success_toast("Configuration restored successfully"); btn.set_sensitive(true); }
                Ok(Err(e)) => { show_error_toast(&format!("Restore failed: {}", e)); btn.set_sensitive(true); }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    glib::timeout_add_local_once(POLL_INTERVAL, move || poll_restore(receiver, btn));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => { show_error_toast("Restore thread terminated"); btn.set_sensitive(true); }
            }
        }
        poll_restore(receiver, btn);
    });
    row.add_suffix(&restore_button);

    // Delete button
    let delete_button = Button::builder()
        .label("Delete")
        .css_classes(["flat", "destructive-action"])
        .build();

    let backup_path_delete = backup.path.clone();
    let container_for_delete = list_container.clone();
    delete_button.connect_clicked(move |button| {
        button.set_sensitive(false);
        let btn = button.clone();
        let container = container_for_delete.clone();
        let path_str = backup_path_delete.clone();

        let (sender, receiver) = std::sync::mpsc::channel::<Result<(), String>>();
        std::thread::spawn(move || {
            let manager = BackupManager::new();
            let path = PathBuf::from(&path_str);
            let res = manager.delete(&path).map_err(|e| e.to_string());
            let _ = sender.send(res);
        });

        fn poll_delete(receiver: std::sync::mpsc::Receiver<Result<(), String>>, container: std::rc::Rc<Box>, btn: Button) {
            match receiver.try_recv() {
                Ok(Ok(())) => { show_success_toast("Backup deleted"); refresh_backup_list(&container); btn.set_sensitive(true); }
                Ok(Err(e)) => { show_error_toast(&format!("Delete failed: {}", e)); btn.set_sensitive(true); }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    glib::timeout_add_local_once(POLL_INTERVAL, move || poll_delete(receiver, container, btn));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => { show_error_toast("Delete thread terminated"); btn.set_sensitive(true); }
            }
        }
        poll_delete(receiver, container, btn);
    });
    row.add_suffix(&delete_button);

    row
}
