// Mount Wizard — guided multi-step dialog for creating or editing CIFS mounts.
//
// Replaces the flat show_mount_dialog() with a 5-step wizard:
//   1. Auth Selection
//   2. Connection Details
//   3. Mount Options
//   4. Validation
//   5. Summary & Confirm
//
// Gated behind the `gui` feature flag.

#[cfg(feature = "gui")]
pub mod wizard_ui {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use adw::prelude::*;
    use gtk::{Align, Box, Button, CheckButton, Label, Orientation, Separator, Stack, StackTransitionType, StringList, pango};

    use crate::config::models::{AuthMethod, SystemdMountEntry};
    use crate::services::validation_engine::{ValidationEngine, ValidationResult, ValidationSeverity};
    use crate::services::kerberos_checker::KerberosChecker;
    use crate::services::kinit_service_manager::KinitServiceManager;
    use crate::vm::wizard_state::{WizardState, WizardStep};

    /// Spawn blocking work on a background thread and run a callback on the
    /// GTK main thread with the result. Mirrors the pattern in `ui/mod.rs`.
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

    /// Widgets for Step 2 (Connection Details) that need to be accessed
    /// after construction — for syncing state ↔ UI and conditional visibility.
    struct ConnectionDetailsWidgets {
        domain_row: adw::EntryRow,
        credentials_group: adw::PreferencesGroup,
        domain_group_label: Label,
    }

    /// Widgets for Step 3 (Mount Options) that need to be accessed
    /// after construction — for syncing state ↔ UI and Kerberos security lock.
    struct MountOptionsWidgets {
        security_mode_row: adw::ComboRow,
    }

    /// Widgets for Step 5 (Summary & Confirm) that need to be accessed
    /// after construction — for connectivity check, error display, and confirm action.
    struct SummaryStepWidgets {
        /// Row showing the share address (value in subtitle).
        share_address_row: adw::ActionRow,
        /// Row showing the mount point (value in subtitle).
        mount_point_row: adw::ActionRow,
        /// Row showing the assembled mount options (value in subtitle).
        mount_options_row: adw::ActionRow,
        /// Container for the list of unit filenames.
        units_list_box: Box,
        /// Spinner for the connectivity check.
        connectivity_spinner: gtk::Spinner,
        /// Label for connectivity check status text.
        connectivity_label: Label,
        /// Label for displaying errors during write operations.
        write_error_label: Label,
    }

    /// Widgets for Step 4 (Validation) that need to be accessed after
    /// construction — for updating results, spinner, and action buttons.
    struct ValidationStepWidgets {
        /// Spinner shown while validations are running.
        spinner: gtk::Spinner,
        /// Label shown alongside the spinner.
        spinner_label: Label,
        /// Container for validation result rows.
        results_box: Box,
        /// Container for Kerberos action buttons (kinit, kinit service).
        kerberos_actions_box: Box,
        /// The "Run kinit" button (Kerberos only).
        kinit_button: Button,
        /// The "Create kinit service" button (Kerberos only).
        kinit_service_button: Button,
        /// Entry row for keytab path (used by kinit service creation).
        keytab_row: adw::EntryRow,
        /// Label for kinit action feedback.
        kinit_feedback_label: Label,
        /// Label for kinit service action feedback.
        kinit_service_feedback_label: Label,
    }

    /// The five wizard steps in display order.
    const STEPS: [WizardStep; 5] = [
        WizardStep::AuthSelection,
        WizardStep::ConnectionDetails,
        WizardStep::MountOptions,
        WizardStep::Validation,
        WizardStep::Summary,
    ];

    /// Map a `WizardStep` to the `gtk::Stack` child name.
    fn step_name(step: WizardStep) -> &'static str {
        match step {
            WizardStep::AuthSelection => "auth",
            WizardStep::ConnectionDetails => "connection",
            WizardStep::MountOptions => "options",
            WizardStep::Validation => "validation",
            WizardStep::Summary => "summary",
        }
    }

    /// Human-readable title for the header bar.
    fn step_title(step: WizardStep) -> &'static str {
        match step {
            WizardStep::AuthSelection => "Authentication Method",
            WizardStep::ConnectionDetails => "Connection Details",
            WizardStep::MountOptions => "Mount Options",
            WizardStep::Validation => "Validation",
            WizardStep::Summary => "Summary",
        }
    }

    /// Return the index of `step` in the ordered STEPS array.
    fn step_index(step: WizardStep) -> usize {
        STEPS.iter().position(|&s| s == step).unwrap_or(0)
    }

    /// The Mount Wizard dialog.
    pub struct MountWizard {
        dialog: adw::Window,
        stack: Stack,
        state: Rc<RefCell<WizardState>>,
        back_button: Button,
        next_button: Button,
        cancel_button: Button,
        confirm_button: Button,
        current_step: Rc<Cell<WizardStep>>,
        title_label: Label,
        step_indicator: Label,
        error_label: Label,
        connection_widgets: Rc<RefCell<Option<ConnectionDetailsWidgets>>>,
        mount_options_widgets: Rc<RefCell<Option<MountOptionsWidgets>>>,
        validation_widgets: Rc<RefCell<Option<ValidationStepWidgets>>>,
        summary_widgets: Rc<RefCell<Option<SummaryStepWidgets>>>,
        /// Optional callback invoked after a successful confirm (write).
        /// Used by the caller to refresh the mounts list.
        on_complete: Rc<RefCell<Option<std::boxed::Box<dyn Fn()>>>>,
    }

    impl MountWizard {
        /// Create a new wizard for adding a mount.
        pub fn new() -> Self {
            Self::build(WizardState::new(), false)
        }

        /// Create a new wizard with a pre-filled share address (from network discovery).
        pub fn new_with_address(address: &str) -> Self {
            let mut state = WizardState::new();
            state.share_address = address.to_string();
            Self::build(state, false)
        }

        /// Create a wizard pre-populated for editing an existing mount.
        pub fn new_edit(entry: &SystemdMountEntry) -> Self {
            Self::build(WizardState::from_entry(entry), true)
        }

        /// Register a callback that will be invoked after a successful write.
        /// Typically used to refresh the mounts list in the parent view.
        pub fn set_on_complete<F: Fn() + 'static>(&self, f: F) {
            *self.on_complete.borrow_mut() = Some(std::boxed::Box::new(f));
        }

        /// Set the transient parent window so the dialog stays on top.
        pub fn set_transient_for(&self, parent: &impl gtk::prelude::IsA<gtk::Window>) {
            self.dialog.set_transient_for(Some(parent));
        }

        /// Show the dialog.
        pub fn present(&self) {
            self.dialog.present();
        }

        // ── Private construction ──────────────────────────────────────

        fn build(state: WizardState, is_edit: bool) -> Self {
            let dialog_title = if is_edit { "Edit Mount" } else { "Add Mount" };

            let dialog = adw::Window::builder()
                .title(dialog_title)
                .default_width(560)
                .default_height(640)
                .modal(true)
                .build();

            // Header bar
            let header_bar = adw::HeaderBar::new();

            // Title label — updated on each step change
            let title_label = Label::builder()
                .label(step_title(WizardStep::AuthSelection))
                .css_classes(["title"])
                .build();
            header_bar.set_title_widget(Some(&title_label));

            // Navigation buttons in the header
            let cancel_button = Button::builder()
                .label("Cancel")
                .build();

            let back_button = Button::builder()
                .label("Back")
                .build();

            let next_button = Button::builder()
                .label("Next")
                .css_classes(["suggested-action"])
                .build();

            let confirm_button = Button::builder()
                .label(if is_edit { "Save" } else { "Confirm" })
                .css_classes(["suggested-action"])
                .visible(false)
                .build();

            header_bar.pack_start(&cancel_button);
            header_bar.pack_start(&back_button);
            header_bar.pack_end(&next_button);
            header_bar.pack_end(&confirm_button);

            // Step indicator (e.g. "Step 1 of 5")
            let step_indicator = Label::builder()
                .label("Step 1 of 5")
                .css_classes(["dim-label", "caption"])
                .halign(Align::Center)
                .margin_top(8)
                .build();

            // Error label — shown when validation fails on the current step
            let error_label = Label::builder()
                .label("")
                .css_classes(["error"])
                .halign(Align::Start)
                .margin_start(24)
                .margin_end(24)
                .wrap(true)
                .visible(false)
                .build();

            // Content stack — one child per wizard step
            let stack = Stack::builder()
                .transition_type(StackTransitionType::SlideLeftRight)
                .transition_duration(200)
                .vexpand(true)
                .hexpand(true)
                .build();

            // Add pages for each step.
            // Step 1 (Auth Selection) is fully built; remaining steps are
            // placeholders to be replaced by tasks 8.3–8.6.
            for &step in &STEPS {
                if step == WizardStep::AuthSelection {
                    // Placeholder — replaced after wizard construction below.
                    let placeholder = Self::build_step_placeholder(step);
                    stack.add_named(&placeholder, Some(step_name(step)));
                } else {
                    let placeholder = Self::build_step_placeholder(step);
                    stack.add_named(&placeholder, Some(step_name(step)));
                }
            }

            // Assemble the layout
            let content_box = Box::builder()
                .orientation(Orientation::Vertical)
                .build();
            content_box.append(&step_indicator);
            content_box.append(&Separator::new(Orientation::Horizontal));
            content_box.append(&error_label);
            content_box.append(&stack);

            let toolbar_view = adw::ToolbarView::new();
            toolbar_view.add_top_bar(&header_bar);
            toolbar_view.set_content(Some(&content_box));

            dialog.set_content(Some(&toolbar_view));

            let state = Rc::new(RefCell::new(state));
            let current_step = Rc::new(Cell::new(WizardStep::AuthSelection));
            let connection_widgets = Rc::new(RefCell::new(None));
            let mount_options_widgets = Rc::new(RefCell::new(None));
            let validation_widgets = Rc::new(RefCell::new(None));
            let summary_widgets = Rc::new(RefCell::new(None));

            let wizard = Self {
                dialog,
                stack,
                state,
                back_button,
                next_button,
                cancel_button,
                confirm_button,
                current_step,
                title_label,
                step_indicator,
                error_label,
                connection_widgets,
                mount_options_widgets,
                validation_widgets,
                summary_widgets,
                on_complete: Rc::new(RefCell::new(None)),
            };

            // Set initial button visibility for AuthSelection (step 0)
            wizard.back_button.set_visible(false);
            wizard.next_button.set_visible(true);
            wizard.confirm_button.set_visible(false);
            wizard.title_label.set_label(step_title(WizardStep::AuthSelection));
            wizard.step_indicator.set_label(&format!("Step 1 of {}", STEPS.len()));

            // Wire up signals
            wizard.connect_signals();

            // Build the real Auth Selection step and swap it in.
            wizard.install_auth_selection_step();

            // Build the real Connection Details step and swap it in.
            wizard.install_connection_details_step();

            // Build the real Mount Options step and swap it in.
            wizard.install_mount_options_step();

            // Build the real Validation step and swap it in.
            wizard.install_validation_step();

            // Build the real Summary step and swap it in.
            wizard.install_summary_step();

            wizard
        }

        /// Build a placeholder widget for a wizard step.
        /// Tasks 8.2–8.6 will replace these with real content.
        fn build_step_placeholder(step: WizardStep) -> Box {
            let container = Box::builder()
                .orientation(Orientation::Vertical)
                .margin_start(24)
                .margin_end(24)
                .margin_top(24)
                .margin_bottom(24)
                .spacing(12)
                .valign(Align::Center)
                .halign(Align::Center)
                .build();

            let label = Label::builder()
                .label(step_title(step))
                .css_classes(["title-2"])
                .build();
            container.append(&label);

            let desc = Label::builder()
                .label("This step will be implemented in a subsequent task.")
                .css_classes(["dim-label"])
                .build();
            container.append(&desc);

            container
        }

        // ── Step 1: Auth Selection ─────────────────────────────────

        /// Remove the Auth Selection placeholder and install the real widget.
        fn install_auth_selection_step(&self) {
            if let Some(old) = self.stack.child_by_name(step_name(WizardStep::AuthSelection)) {
                self.stack.remove(&old);
            }
            let page = self.build_auth_selection_step();
            self.stack.add_named(&page, Some(step_name(WizardStep::AuthSelection)));
            // Ensure the stack still shows the auth step (it's the initial step).
            self.stack.set_visible_child_name(step_name(WizardStep::AuthSelection));
        }

        /// Build the Auth Selection step content (Req 1.1, 1.2, 12.2).
        ///
        /// Displays three radio-style rows (Guest, Credentials File, Kerberos).
        /// Selecting a row updates `WizardState.auth_method` and advances to
        /// Step 2 (Connection Details). In edit mode the current auth method
        /// is pre-selected via `detect_auth_method()`.
        fn build_auth_selection_step(&self) -> Box {
            let container = Box::builder()
                .orientation(Orientation::Vertical)
                .margin_start(24)
                .margin_end(24)
                .margin_top(24)
                .margin_bottom(24)
                .spacing(16)
                .build();

            let heading = Label::builder()
                .label("How do you want to authenticate?")
                .css_classes(["title-3"])
                .halign(Align::Start)
                .build();
            container.append(&heading);

            let subtitle = Label::builder()
                .label("Choose the authentication method for this mount. The wizard will show only the fields relevant to your choice.")
                .css_classes(["dim-label"])
                .halign(Align::Start)
                .wrap(true)
                .build();
            container.append(&subtitle);

            // Preferences group holding the three auth rows
            let group = adw::PreferencesGroup::builder()
                .margin_top(8)
                .build();

            // Radio button group — first button is the group anchor.
            let radio_guest = CheckButton::new();
            let radio_credentials = CheckButton::builder()
                .group(&radio_guest)
                .build();
            let radio_kerberos = CheckButton::builder()
                .group(&radio_guest)
                .build();

            // Guest row
            let row_guest = adw::ActionRow::builder()
                .title("Guest")
                .subtitle("Anonymous access — no username or password required")
                .activatable_widget(&radio_guest)
                .build();
            row_guest.add_prefix(&radio_guest);
            group.add(&row_guest);

            // Credentials File row
            let row_credentials = adw::ActionRow::builder()
                .title("Credentials File")
                .subtitle("Authenticate with a username/password stored in a file on disk")
                .activatable_widget(&radio_credentials)
                .build();
            row_credentials.add_prefix(&radio_credentials);
            group.add(&row_credentials);

            // Kerberos row
            let row_kerberos = adw::ActionRow::builder()
                .title("Kerberos")
                .subtitle("Use Kerberos tickets for single sign-on (requires FQDN)")
                .activatable_widget(&radio_kerberos)
                .build();
            row_kerberos.add_prefix(&radio_kerberos);
            group.add(&row_kerberos);

            container.append(&group);

            // Pre-select the current auth method (edit mode: Req 12.2).
            let current_auth = self.state.borrow().auth_method;
            match current_auth {
                AuthMethod::Guest => radio_guest.set_active(true),
                AuthMethod::CredentialsFile => radio_credentials.set_active(true),
                AuthMethod::Kerberos => radio_kerberos.set_active(true),
            }

            // Connect toggled signals — each updates state and advances.
            // We use `toggled` and only act when the button becomes active to
            // avoid double-firing (the previously active button also emits
            // toggled when it becomes inactive).
            {
                let state = self.state.clone();
                let current_step = self.current_step.clone();
                let stack = self.stack.clone();
                let back_button = self.back_button.clone();
                let next_button = self.next_button.clone();
                let confirm_button = self.confirm_button.clone();
                let title_label = self.title_label.clone();
                let step_indicator = self.step_indicator.clone();
                let error_label = self.error_label.clone();
                let connection_widgets = self.connection_widgets.clone();
                let mount_options_widgets = self.mount_options_widgets.clone();
                let validation_widgets = self.validation_widgets.clone();
                let summary_widgets = self.summary_widgets.clone();

                radio_guest.connect_toggled(move |btn: &CheckButton| {
                    if !btn.is_active() {
                        return;
                    }
                    state.borrow_mut().auth_method = AuthMethod::Guest;
                    Self::navigate_to(
                        WizardStep::ConnectionDetails,
                        &current_step,
                        &stack,
                        &back_button,
                        &next_button,
                        &confirm_button,
                        &title_label,
                        &step_indicator,
                        &error_label,
                        &connection_widgets,
                        &mount_options_widgets,
                        &state,
                        &validation_widgets,
                        &summary_widgets,
                    );
                });
            }
            {
                let state = self.state.clone();
                let current_step = self.current_step.clone();
                let stack = self.stack.clone();
                let back_button = self.back_button.clone();
                let next_button = self.next_button.clone();
                let confirm_button = self.confirm_button.clone();
                let title_label = self.title_label.clone();
                let step_indicator = self.step_indicator.clone();
                let error_label = self.error_label.clone();
                let connection_widgets = self.connection_widgets.clone();
                let mount_options_widgets = self.mount_options_widgets.clone();
                let validation_widgets = self.validation_widgets.clone();
                let summary_widgets = self.summary_widgets.clone();

                radio_credentials.connect_toggled(move |btn: &CheckButton| {
                    if !btn.is_active() {
                        return;
                    }
                    state.borrow_mut().auth_method = AuthMethod::CredentialsFile;
                    Self::navigate_to(
                        WizardStep::ConnectionDetails,
                        &current_step,
                        &stack,
                        &back_button,
                        &next_button,
                        &confirm_button,
                        &title_label,
                        &step_indicator,
                        &error_label,
                        &connection_widgets,
                        &mount_options_widgets,
                        &state,
                        &validation_widgets,
                        &summary_widgets,
                    );
                });
            }
            {
                let state = self.state.clone();
                let current_step = self.current_step.clone();
                let stack = self.stack.clone();
                let back_button = self.back_button.clone();
                let next_button = self.next_button.clone();
                let confirm_button = self.confirm_button.clone();
                let title_label = self.title_label.clone();
                let step_indicator = self.step_indicator.clone();
                let error_label = self.error_label.clone();
                let connection_widgets = self.connection_widgets.clone();
                let mount_options_widgets = self.mount_options_widgets.clone();
                let validation_widgets = self.validation_widgets.clone();
                let summary_widgets = self.summary_widgets.clone();

                radio_kerberos.connect_toggled(move |btn: &CheckButton| {
                    if !btn.is_active() {
                        return;
                    }
                    state.borrow_mut().auth_method = AuthMethod::Kerberos;
                    Self::navigate_to(
                        WizardStep::ConnectionDetails,
                        &current_step,
                        &stack,
                        &back_button,
                        &next_button,
                        &confirm_button,
                        &title_label,
                        &step_indicator,
                        &error_label,
                        &connection_widgets,
                        &mount_options_widgets,
                        &state,
                        &validation_widgets,
                        &summary_widgets,
                    );
                });
            }

            container
        }

        // ── Step 2: Connection Details ─────────────────────────────

        /// Remove the Connection Details placeholder and install the real widget.
        fn install_connection_details_step(&self) {
            if let Some(old) = self.stack.child_by_name(step_name(WizardStep::ConnectionDetails)) {
                self.stack.remove(&old);
            }
            let page = self.build_connection_details_step();
            self.stack.add_named(&page, Some(step_name(WizardStep::ConnectionDetails)));
        }

        /// Build the Connection Details step content (Req 1.3, 1.4, 1.5, 2.3, 2.4).
        ///
        /// Always shows Share Address and Mount Point fields.
        /// Conditionally shows Credentials File path and Domain based on auth_method:
        ///   - Guest: Share Address + Mount Point only
        ///   - CredentialsFile: + Credentials File path + Domain
        ///   - Kerberos: + Domain
        fn build_connection_details_step(&self) -> Box {
            let container = Box::builder()
                .orientation(Orientation::Vertical)
                .margin_start(24)
                .margin_end(24)
                .margin_top(24)
                .margin_bottom(24)
                .spacing(16)
                .build();

            let heading = Label::builder()
                .label("Where is the share?")
                .css_classes(["title-3"])
                .halign(Align::Start)
                .build();
            container.append(&heading);

            let subtitle = Label::builder()
                .label("Enter the network share address and the local directory where it should be mounted.")
                .css_classes(["dim-label"])
                .halign(Align::Start)
                .wrap(true)
                .build();
            container.append(&subtitle);

            // ── Connection group (always visible) ──────────────────

            let conn_group = adw::PreferencesGroup::builder()
                .title("Connection")
                .margin_top(8)
                .build();

            let share_address_row = adw::EntryRow::builder()
                .title("Share Address")
                .build();
            share_address_row.set_tooltip_text(Some(
                "UNC path of the remote share (e.g. //server/share)",
            ));

            let mount_point_row = adw::EntryRow::builder()
                .title("Mount Point")
                .build();
            mount_point_row.set_tooltip_text(Some(
                "Absolute local path where the share will be mounted (e.g. /mnt/share)",
            ));

            // Browse button for mount point directory
            let mount_browse_btn = Button::builder()
                .icon_name("folder-open-symbolic")
                .css_classes(["flat"])
                .valign(Align::Center)
                .tooltip_text("Browse for mount directory")
                .build();
            mount_point_row.add_suffix(&mount_browse_btn);

            {
                let mp_row = mount_point_row.clone();
                let dialog_weak = self.dialog.downgrade();
                mount_browse_btn.connect_clicked(move |_| {
                    let file_dialog = gtk::FileDialog::builder()
                        .title("Select Mount Point Directory")
                        .modal(true)
                        .build();
                    let row = mp_row.clone();
                    let parent = dialog_weak.upgrade();
                    file_dialog.select_folder(
                        parent.as_ref(),
                        None::<&gtk::gio::Cancellable>,
                        move |result| {
                            if let Ok(folder) = result {
                                if let Some(path) = folder.path() {
                                    row.set_text(&path.to_string_lossy());
                                }
                            }
                        },
                    );
                });
            }

            conn_group.add(&share_address_row);
            conn_group.add(&mount_point_row);
            container.append(&conn_group);

            // ── Credentials group (CredentialsFile only) ───────────

            let credentials_group = adw::PreferencesGroup::builder()
                .title("Credentials")
                .build();

            let credentials_file_row = adw::EntryRow::builder()
                .title("Credentials File")
                .build();
            credentials_file_row.set_tooltip_text(Some(
                "Path to a file containing username= and password= lines (e.g. /root/.smbcredentials)",
            ));

            // Browse button for credentials file
            let cred_browse_btn = Button::builder()
                .icon_name("document-open-symbolic")
                .css_classes(["flat"])
                .valign(Align::Center)
                .tooltip_text("Browse for credentials file")
                .build();
            credentials_file_row.add_suffix(&cred_browse_btn);

            {
                let cred_row = credentials_file_row.clone();
                let dialog_weak = self.dialog.downgrade();
                cred_browse_btn.connect_clicked(move |_| {
                    let file_dialog = gtk::FileDialog::builder()
                        .title("Select Credentials File")
                        .modal(true)
                        .build();
                    let row = cred_row.clone();
                    let parent = dialog_weak.upgrade();
                    file_dialog.open(
                        parent.as_ref(),
                        None::<&gtk::gio::Cancellable>,
                        move |result| {
                            if let Ok(file) = result {
                                if let Some(path) = file.path() {
                                    row.set_text(&path.to_string_lossy());
                                }
                            }
                        },
                    );
                });
            }

            credentials_group.add(&credentials_file_row);
            container.append(&credentials_group);

            // ── Domain group (CredentialsFile + Kerberos) ──────────

            let domain_group = adw::PreferencesGroup::builder()
                .title("Domain")
                .build();

            // A label to provide context about why domain is needed
            let domain_group_label = Label::builder()
                .label("")
                .css_classes(["dim-label", "caption"])
                .halign(Align::Start)
                .margin_start(24)
                .wrap(true)
                .visible(false)
                .build();

            let domain_row = adw::EntryRow::builder()
                .title("Domain")
                .build();
            domain_row.set_tooltip_text(Some(
                "Windows domain or workgroup name",
            ));

            domain_group.add(&domain_row);
            container.append(&domain_group_label);
            container.append(&domain_group);

            // ── Pre-populate from state (edit mode or returning to step) ──

            {
                let state = self.state.borrow();
                share_address_row.set_text(&state.share_address);
                mount_point_row.set_text(&state.mount_point);
                credentials_file_row.set_text(&state.credentials_file_path);
                domain_row.set_text(&state.domain);
            }

            // ── Sync UI → state on text changes ───────────────────

            {
                let state = self.state.clone();
                share_address_row.connect_changed(move |row| {
                    state.borrow_mut().share_address = row.text().trim().to_string();
                });
            }
            {
                let state = self.state.clone();
                mount_point_row.connect_changed(move |row| {
                    state.borrow_mut().mount_point = row.text().trim().to_string();
                });
            }
            {
                let state = self.state.clone();
                credentials_file_row.connect_changed(move |row| {
                    state.borrow_mut().credentials_file_path = row.text().trim().to_string();
                });
            }
            {
                let state = self.state.clone();
                domain_row.connect_changed(move |row| {
                    state.borrow_mut().domain = row.text().trim().to_string();
                });
            }

            // ── Store widget references for visibility updates ─────

            *self.connection_widgets.borrow_mut() = Some(ConnectionDetailsWidgets {
                domain_row,
                credentials_group,
                domain_group_label,
            });

            // Set initial visibility based on current auth method
            self.update_connection_field_visibility();

            container
        }

        /// Update the visibility of Connection Details fields based on the
        /// current `auth_method` in `WizardState`.
        ///
        /// - Guest: only Share Address + Mount Point
        /// - CredentialsFile: + Credentials File + Domain
        /// - Kerberos: + Domain (no Credentials File)
        fn update_connection_field_visibility(&self) {
            Self::update_connection_visibility_static(&self.connection_widgets, &self.state);
        }

        /// Static helper to navigate to a step from within a signal closure.
        ///
        /// Handles step transition, button visibility, error clearing, and
        /// step-specific actions (field visibility, security lock, validations,
        /// summary population). Uses individual widget references rather than
        /// `&self` so it can be captured by GTK signal closures.
        fn navigate_to(
            step: WizardStep,
            current_step: &Rc<Cell<WizardStep>>,
            stack: &Stack,
            back_button: &Button,
            next_button: &Button,
            confirm_button: &Button,
            title_label: &Label,
            step_indicator: &Label,
            error_label: &Label,
            connection_widgets: &Rc<RefCell<Option<ConnectionDetailsWidgets>>>,
            mount_options_widgets: &Rc<RefCell<Option<MountOptionsWidgets>>>,
            state: &Rc<RefCell<WizardState>>,
            validation_widgets: &Rc<RefCell<Option<ValidationStepWidgets>>>,
            summary_widgets: &Rc<RefCell<Option<SummaryStepWidgets>>>,
        ) {
            current_step.set(step);
            stack.set_visible_child_name(step_name(step));

            // Clear errors
            error_label.set_label("");
            error_label.set_visible(false);

            // Update nav buttons
            let idx = step_index(step);
            back_button.set_visible(idx > 0);
            let is_summary = step == WizardStep::Summary;
            next_button.set_visible(!is_summary);
            confirm_button.set_visible(is_summary);
            title_label.set_label(step_title(step));
            step_indicator.set_label(&format!("Step {} of {}", idx + 1, STEPS.len()));

            // Update conditional field visibility when entering Connection Details
            if step == WizardStep::ConnectionDetails {
                Self::update_connection_visibility_static(connection_widgets, state);
            }

            // Update security mode lock when entering Mount Options (Req 11.5)
            if step == WizardStep::MountOptions {
                Self::update_security_lock_static(mount_options_widgets, state);
            }

            // Run validations when entering the Validation step (Req 13.1)
            if step == WizardStep::Validation {
                Self::run_validations_static(validation_widgets, state, next_button);
            }

            // Populate summary when entering the Summary step (Req 9.1–9.3, 8.1–8.4)
            if step == WizardStep::Summary {
                Self::populate_summary_static(summary_widgets, state, confirm_button);
            }
        }

        /// Static helper to update connection field visibility from signal closures.
        fn update_connection_visibility_static(
            connection_widgets: &Rc<RefCell<Option<ConnectionDetailsWidgets>>>,
            state: &Rc<RefCell<WizardState>>,
        ) {
            let widgets = connection_widgets.borrow();
            let widgets = match widgets.as_ref() {
                Some(w) => w,
                None => return,
            };

            let auth = state.borrow().auth_method;

            match auth {
                AuthMethod::Guest => {
                    widgets.credentials_group.set_visible(false);
                    widgets.domain_group_label.set_visible(false);
                    if let Some(parent) = widgets.domain_row.parent() {
                        if let Some(group) = parent.parent() {
                            group.set_visible(false);
                        }
                    }
                }
                AuthMethod::CredentialsFile => {
                    widgets.credentials_group.set_visible(true);
                    widgets.domain_group_label.set_visible(true);
                    widgets.domain_group_label.set_label(
                        "Optionally specify the Windows domain or workgroup for authentication.",
                    );
                    if let Some(parent) = widgets.domain_row.parent() {
                        if let Some(group) = parent.parent() {
                            group.set_visible(true);
                        }
                    }
                }
                AuthMethod::Kerberos => {
                    widgets.credentials_group.set_visible(false);
                    widgets.domain_group_label.set_visible(true);
                    widgets.domain_group_label.set_label(
                        "Specify the Kerberos realm or Windows domain for ticket-based authentication.",
                    );
                    if let Some(parent) = widgets.domain_row.parent() {
                        if let Some(group) = parent.parent() {
                            group.set_visible(true);
                        }
                    }
                }
            }
        }

        // ── Step 3: Mount Options ──────────────────────────────────

        /// Protocol version choices matching the design (Req 11.4).
        const PROTOCOL_VERSIONS: &'static [&'static str] =
            &["Auto", "1.0", "2.0", "2.1", "3.0", "3.0.2", "3.1.1"];

        /// Security mode choices for the combo row.
        const SECURITY_MODES: &'static [&'static str] = &[
            "Default", "none", "krb5", "krb5i", "ntlm", "ntlmi", "ntlmv2",
            "ntlmv2i", "ntlmssp", "ntlmsspi",
        ];

        /// Client SMB encrypt choices for the combo row.
        /// Maps to the `seal` mount option (required/desired → seal, off/if_required → no seal).
        const CLIENT_SMB_ENCRYPT_OPTS: &'static [&'static str] =
            &["Default", "off", "if_required", "desired", "required"];

        /// Remove the Mount Options placeholder and install the real widget.
        fn install_mount_options_step(&self) {
            if let Some(old) = self.stack.child_by_name(step_name(WizardStep::MountOptions)) {
                self.stack.remove(&old);
            }
            let page = self.build_mount_options_step();
            self.stack.add_named(&page, Some(step_name(WizardStep::MountOptions)));
        }

        /// Build the Mount Options step content (Req 11.1–11.6).
        ///
        /// Provides controls for:
        /// - Behaviour: automount, nofail, netdev, read-only, timeout
        /// - Ownership & permissions: UID, GID, file mode, dir mode
        /// - Protocol: SMB version, security mode
        /// - Extra comma-separated options
        ///
        /// When Kerberos is selected the security mode is locked to `krb5`
        /// and the combo is disabled (Req 11.5).
        fn build_mount_options_step(&self) -> gtk::ScrolledWindow {
            let scrolled = gtk::ScrolledWindow::builder()
                .hscrollbar_policy(gtk::PolicyType::Never)
                .vexpand(true)
                .build();

            let container = Box::builder()
                .orientation(Orientation::Vertical)
                .margin_start(24)
                .margin_end(24)
                .margin_top(24)
                .margin_bottom(24)
                .spacing(16)
                .build();

            let heading = Label::builder()
                .label("Mount Options")
                .css_classes(["title-3"])
                .halign(Align::Start)
                .build();
            container.append(&heading);

            let subtitle = Label::builder()
                .label("Configure mount behaviour, permissions, and protocol settings.")
                .css_classes(["dim-label"])
                .halign(Align::Start)
                .wrap(true)
                .build();
            container.append(&subtitle);

            // ── Behaviour group (Req 11.1) ─────────────────────────

            let behaviour_group = adw::PreferencesGroup::builder()
                .title("Behaviour")
                .margin_top(8)
                .build();

            let automount_switch = adw::SwitchRow::builder()
                .title("Automount")
                .subtitle("Mount automatically when the path is accessed")
                .build();

            let nofail_switch = adw::SwitchRow::builder()
                .title("No Fail")
                .subtitle("Do not report errors for this mount at boot")
                .build();

            let netdev_switch = adw::SwitchRow::builder()
                .title("Network Device")
                .subtitle("Wait for network before mounting (_netdev)")
                .build();

            let read_only_switch = adw::SwitchRow::builder()
                .title("Read Only")
                .subtitle("Mount the share as read-only (ro)")
                .build();

            let timeout_row = adw::EntryRow::builder()
                .title("Timeout (seconds)")
                .build();
            timeout_row.set_tooltip_text(Some(
                "Automount idle timeout in seconds (leave empty for no timeout)",
            ));

            behaviour_group.add(&automount_switch);
            behaviour_group.add(&nofail_switch);
            behaviour_group.add(&netdev_switch);
            behaviour_group.add(&read_only_switch);
            behaviour_group.add(&timeout_row);
            container.append(&behaviour_group);

            // ── Ownership & Permissions group (Req 11.2) ───────────

            let perms_group = adw::PreferencesGroup::builder()
                .title("Ownership & Permissions")
                .build();

            let uid_row = adw::EntryRow::builder()
                .title("UID")
                .build();
            uid_row.set_tooltip_text(Some("Owner user ID for mounted files (e.g. 1000)"));

            let gid_row = adw::EntryRow::builder()
                .title("GID")
                .build();
            gid_row.set_tooltip_text(Some("Owner group ID for mounted files (e.g. 1000)"));

            let file_mode_row = adw::EntryRow::builder()
                .title("File Mode")
                .build();
            file_mode_row.set_tooltip_text(Some("Permission mode for files (e.g. 0644)"));

            let dir_mode_row = adw::EntryRow::builder()
                .title("Directory Mode")
                .build();
            dir_mode_row.set_tooltip_text(Some("Permission mode for directories (e.g. 0755)"));

            perms_group.add(&uid_row);
            perms_group.add(&gid_row);
            perms_group.add(&file_mode_row);
            perms_group.add(&dir_mode_row);
            container.append(&perms_group);

            // ── Protocol group (Req 11.4, 11.5, 11.6) ─────────────

            let protocol_group = adw::PreferencesGroup::builder()
                .title("Protocol")
                .build();

            // Protocol version combo (Req 11.4)
            let version_model = StringList::new(Self::PROTOCOL_VERSIONS);
            let protocol_version_row = adw::ComboRow::builder()
                .title("SMB Protocol Version")
                .subtitle("Protocol version to negotiate with the server")
                .model(&version_model)
                .build();

            // Security mode combo (Req 11.5, 11.6)
            let security_model = StringList::new(Self::SECURITY_MODES);
            let security_mode_row = adw::ComboRow::builder()
                .title("Security Mode")
                .subtitle("Authentication security mechanism")
                .model(&security_model)
                .build();

            // Client SMB encrypt combo
            let encrypt_model = StringList::new(Self::CLIENT_SMB_ENCRYPT_OPTS);
            let client_smb_encrypt_row = adw::ComboRow::builder()
                .title("Client SMB Encrypt")
                .subtitle("SMB encryption for the session (maps to 'seal' mount option)")
                .model(&encrypt_model)
                .build();

            protocol_group.add(&protocol_version_row);
            protocol_group.add(&security_mode_row);
            protocol_group.add(&client_smb_encrypt_row);
            container.append(&protocol_group);

            // ── Extra options (Req 11.3) ───────────────────────────

            let extra_group = adw::PreferencesGroup::builder()
                .title("Additional Options")
                .build();

            let extra_options_row = adw::EntryRow::builder()
                .title("Extra Options")
                .build();
            extra_options_row.set_tooltip_text(Some(
                "Additional comma-separated mount options (e.g. noperm,seal)",
            ));

            extra_group.add(&extra_options_row);
            container.append(&extra_group);

            // ── Pre-populate from state ────────────────────────────

            {
                let state = self.state.borrow();
                automount_switch.set_active(state.automount);
                nofail_switch.set_active(state.nofail);
                netdev_switch.set_active(state.netdev);
                read_only_switch.set_active(state.read_only);

                if let Some(t) = state.timeout_sec {
                    timeout_row.set_text(&t.to_string());
                }

                uid_row.set_text(&state.uid);
                gid_row.set_text(&state.gid);
                file_mode_row.set_text(&state.file_mode);
                dir_mode_row.set_text(&state.dir_mode);

                // Protocol version — find the matching index
                let version_idx = Self::PROTOCOL_VERSIONS
                    .iter()
                    .position(|&v| {
                        if state.smb_version == "auto" {
                            v == "Auto"
                        } else {
                            v == state.smb_version
                        }
                    })
                    .unwrap_or(0);
                protocol_version_row.set_selected(version_idx as u32);

                // Security mode — find the matching index
                let sec_idx = if state.auth_method == AuthMethod::Kerberos {
                    // Kerberos locks to krb5 (Req 11.5)
                    Self::SECURITY_MODES
                        .iter()
                        .position(|&s| s == "krb5")
                        .unwrap_or(0)
                } else if state.security_mode.is_empty() {
                    0 // "Default"
                } else {
                    Self::SECURITY_MODES
                        .iter()
                        .position(|&s| s == state.security_mode)
                        .unwrap_or(0)
                };
                security_mode_row.set_selected(sec_idx as u32);

                // Lock security mode when Kerberos is selected (Req 11.5)
                if state.auth_method == AuthMethod::Kerberos {
                    security_mode_row.set_sensitive(false);
                    security_mode_row.set_subtitle("Locked to krb5 for Kerberos authentication");
                }

                // Client SMB encrypt — find the matching index
                let encrypt_idx = if state.client_smb_encrypt == "default" {
                    0
                } else {
                    Self::CLIENT_SMB_ENCRYPT_OPTS
                        .iter()
                        .position(|&e| e == state.client_smb_encrypt)
                        .unwrap_or(0)
                };
                client_smb_encrypt_row.set_selected(encrypt_idx as u32);

                extra_options_row.set_text(&state.extra_options);
            }

            // ── Sync UI → state on changes ─────────────────────────

            // Automount toggle
            {
                let state = self.state.clone();
                automount_switch.connect_active_notify(move |sw| {
                    state.borrow_mut().automount = sw.is_active();
                });
            }

            // Nofail toggle
            {
                let state = self.state.clone();
                nofail_switch.connect_active_notify(move |sw| {
                    state.borrow_mut().nofail = sw.is_active();
                });
            }

            // Netdev toggle
            {
                let state = self.state.clone();
                netdev_switch.connect_active_notify(move |sw| {
                    state.borrow_mut().netdev = sw.is_active();
                });
            }

            // Read-only toggle
            {
                let state = self.state.clone();
                read_only_switch.connect_active_notify(move |sw| {
                    state.borrow_mut().read_only = sw.is_active();
                });
            }

            // Timeout field
            {
                let state = self.state.clone();
                timeout_row.connect_changed(move |row| {
                    let text = row.text().trim().to_string();
                    state.borrow_mut().timeout_sec = if text.is_empty() {
                        None
                    } else {
                        text.parse::<u32>().ok()
                    };
                });
            }

            // UID
            {
                let state = self.state.clone();
                uid_row.connect_changed(move |row| {
                    state.borrow_mut().uid = row.text().trim().to_string();
                });
            }

            // GID
            {
                let state = self.state.clone();
                gid_row.connect_changed(move |row| {
                    state.borrow_mut().gid = row.text().trim().to_string();
                });
            }

            // File mode
            {
                let state = self.state.clone();
                file_mode_row.connect_changed(move |row| {
                    state.borrow_mut().file_mode = row.text().trim().to_string();
                });
            }

            // Dir mode
            {
                let state = self.state.clone();
                dir_mode_row.connect_changed(move |row| {
                    state.borrow_mut().dir_mode = row.text().trim().to_string();
                });
            }

            // Protocol version combo
            {
                let state = self.state.clone();
                protocol_version_row.connect_selected_notify(move |row| {
                    let idx = row.selected() as usize;
                    if idx < Self::PROTOCOL_VERSIONS.len() {
                        let version = Self::PROTOCOL_VERSIONS[idx];
                        state.borrow_mut().smb_version = if version == "Auto" {
                            "auto".to_string()
                        } else {
                            version.to_string()
                        };
                    }
                });
            }

            // Security mode combo (Req 11.5, 11.6)
            {
                let state = self.state.clone();
                security_mode_row.connect_selected_notify(move |row| {
                    // If Kerberos, the combo is disabled so this won't fire,
                    // but guard anyway.
                    if state.borrow().auth_method == AuthMethod::Kerberos {
                        return;
                    }
                    let idx = row.selected() as usize;
                    if idx < Self::SECURITY_MODES.len() {
                        let mode = Self::SECURITY_MODES[idx];
                        state.borrow_mut().security_mode = if mode == "Default" {
                            String::new()
                        } else {
                            mode.to_string()
                        };
                    }
                });
            }

            // Client SMB encrypt combo
            {
                let state = self.state.clone();
                client_smb_encrypt_row.connect_selected_notify(move |row| {
                    let idx = row.selected() as usize;
                    if idx < Self::CLIENT_SMB_ENCRYPT_OPTS.len() {
                        let opt = Self::CLIENT_SMB_ENCRYPT_OPTS[idx];
                        state.borrow_mut().client_smb_encrypt = if opt == "Default" {
                            "default".to_string()
                        } else {
                            opt.to_string()
                        };
                    }
                });
            }

            // Extra options
            {
                let state = self.state.clone();
                extra_options_row.connect_changed(move |row| {
                    state.borrow_mut().extra_options = row.text().trim().to_string();
                });
            }

            // ── Store widget references ────────────────────────────

            *self.mount_options_widgets.borrow_mut() = Some(MountOptionsWidgets {
                security_mode_row,
            });

            scrolled.set_child(Some(&container));
            scrolled
        }

        /// Static helper for updating security mode lock from signal closures.
        fn update_security_lock_static(
            mount_options_widgets: &Rc<RefCell<Option<MountOptionsWidgets>>>,
            state: &Rc<RefCell<WizardState>>,
        ) {
            let widgets = mount_options_widgets.borrow();
            let widgets = match widgets.as_ref() {
                Some(w) => w,
                None => return,
            };

            let auth = state.borrow().auth_method;
            if auth == AuthMethod::Kerberos {
                // Lock to krb5 (Req 11.5)
                let krb5_idx = Self::SECURITY_MODES
                    .iter()
                    .position(|&s| s == "krb5")
                    .unwrap_or(0);
                widgets.security_mode_row.set_selected(krb5_idx as u32);
                widgets.security_mode_row.set_sensitive(false);
                widgets.security_mode_row.set_subtitle("Locked to krb5 for Kerberos authentication");
                state.borrow_mut().security_mode = "krb5".to_string();
            } else {
                // Re-enable (Req 11.6)
                widgets.security_mode_row.set_sensitive(true);
                widgets.security_mode_row.set_subtitle("Authentication security mechanism");
            }
        }

        /// Static helper to run validations from signal closures (Req 13.1).
        ///
        /// This is the static equivalent of `run_validations()` for use in
        /// closures that cannot capture `&self`.
        fn run_validations_static(
            validation_widgets: &Rc<RefCell<Option<ValidationStepWidgets>>>,
            state: &Rc<RefCell<WizardState>>,
            next_button: &Button,
        ) {
            let widgets = validation_widgets.borrow();
            let widgets = match widgets.as_ref() {
                Some(w) => w,
                None => return,
            };

            // Show spinner, hide previous results (Req 13.2)
            widgets.spinner.set_spinning(true);
            widgets.spinner_label.set_visible(true);

            // Clear previous results
            while let Some(child) = widgets.results_box.first_child() {
                widgets.results_box.remove(&child);
            }
            widgets.kerberos_actions_box.set_visible(false);
            widgets.kinit_feedback_label.set_visible(false);
            widgets.kinit_service_feedback_label.set_visible(false);

            // Disable Next while validations run (Req 13.3)
            next_button.set_sensitive(false);

            let state_snapshot = state.borrow().clone();
            let vw = validation_widgets.clone();
            let st = state.clone();
            let nb = next_button.clone();

            spawn_blocking_then(
                move || {
                    let mut results = ValidationEngine::run_all(&state_snapshot);

                    if state_snapshot.auth_method == AuthMethod::Kerberos {
                        if let Some(hostname) = KerberosChecker::extract_hostname(&state_snapshot.share_address) {
                            results.push(KerberosChecker::validate_fqdn(&hostname));
                            results.push(KerberosChecker::resolve_hostname(&hostname));
                            if let Some(domain) = KerberosChecker::extract_domain(&hostname) {
                                results.push(KerberosChecker::check_dns_srv(&domain));
                            }
                        }

                        match KerberosChecker::has_valid_ticket() {
                            Ok(true) => {
                                results.push(ValidationResult {
                                    check_name: "kerberos_ticket".into(),
                                    severity: ValidationSeverity::Ok,
                                    message: "Valid Kerberos ticket found".into(),
                                });
                            }
                            Ok(false) => {
                                results.push(ValidationResult {
                                    check_name: "kerberos_ticket".into(),
                                    severity: ValidationSeverity::Warning,
                                    message: "No valid Kerberos ticket found. You can run kinit to obtain one.".into(),
                                });
                            }
                            Err(e) => {
                                results.push(ValidationResult {
                                    check_name: "kerberos_ticket".into(),
                                    severity: ValidationSeverity::Warning,
                                    message: format!("Could not check Kerberos ticket: {}", e),
                                });
                            }
                        }

                        match KinitServiceManager::service_exists_and_enabled() {
                            Ok(true) => {
                                results.push(ValidationResult {
                                    check_name: "kinit_service".into(),
                                    severity: ValidationSeverity::Ok,
                                    message: "Boot-time kinit service (krb5-kinit.service) is enabled".into(),
                                });
                            }
                            Ok(false) => {
                                results.push(ValidationResult {
                                    check_name: "kinit_service".into(),
                                    severity: ValidationSeverity::Warning,
                                    message: "No boot-time kinit service found. Kerberos mounts will fail after reboot.".into(),
                                });
                            }
                            Err(e) => {
                                results.push(ValidationResult {
                                    check_name: "kinit_service".into(),
                                    severity: ValidationSeverity::Warning,
                                    message: format!("Could not check kinit service: {}", e),
                                });
                            }
                        }
                    }

                    results
                },
                move |results: Vec<ValidationResult>| {
                    let widgets = vw.borrow();
                    let widgets = match widgets.as_ref() {
                        Some(w) => w,
                        None => return,
                    };

                    widgets.spinner.set_spinning(false);
                    widgets.spinner_label.set_visible(false);

                    let has_errors = results.iter().any(|r| r.severity == ValidationSeverity::Error);

                    let mut show_kinit_action = false;
                    let mut show_kinit_service_action = false;

                    for result in &results {
                        let row = Self::build_validation_result_row(result);
                        widgets.results_box.append(&row);

                        if result.check_name == "kerberos_ticket"
                            && result.severity != ValidationSeverity::Ok
                        {
                            show_kinit_action = true;
                        }
                        if result.check_name == "kinit_service"
                            && result.severity != ValidationSeverity::Ok
                        {
                            show_kinit_service_action = true;
                        }
                    }

                    if show_kinit_action || show_kinit_service_action {
                        widgets.kerberos_actions_box.set_visible(true);
                        widgets.kinit_button.set_visible(show_kinit_action);
                        widgets.kinit_service_button.set_visible(show_kinit_service_action);
                        widgets.keytab_row.set_visible(show_kinit_service_action);
                    } else {
                        widgets.kerberos_actions_box.set_visible(false);
                    }

                    let result_strings: Vec<String> = results
                        .iter()
                        .map(|r| format!("[{:?}] {}: {}", r.severity, r.check_name, r.message))
                        .collect();
                    st.borrow_mut().validation_results = result_strings;

                    nb.set_sensitive(!has_errors);
                },
            );
        }

        // ── Step 4: Validation ─────────────────────────────────────

        /// Remove the Validation placeholder and install the real widget.
        fn install_validation_step(&self) {
            if let Some(old) = self.stack.child_by_name(step_name(WizardStep::Validation)) {
                self.stack.remove(&old);
            }
            let page = self.build_validation_step();
            self.stack.add_named(&page, Some(step_name(WizardStep::Validation)));
        }

        /// Build the Validation step content (Req 3.1–3.4, 4.1–4.4, 5.1–5.5,
        /// 6.1–6.3, 6.6, 7.1–7.3, 8.4, 13.1–13.4).
        ///
        /// Displays a spinner while validations run on a background thread,
        /// then shows results as a list with severity icons. For Kerberos,
        /// offers kinit and kinit service creation actions.
        fn build_validation_step(&self) -> gtk::ScrolledWindow {
            let scrolled = gtk::ScrolledWindow::builder()
                .hscrollbar_policy(gtk::PolicyType::Never)
                .vexpand(true)
                .build();

            let container = Box::builder()
                .orientation(Orientation::Vertical)
                .margin_start(24)
                .margin_end(24)
                .margin_top(24)
                .margin_bottom(24)
                .spacing(16)
                .build();

            let heading = Label::builder()
                .label("Pre-flight Checks")
                .css_classes(["title-3"])
                .halign(Align::Start)
                .build();
            container.append(&heading);

            let subtitle = Label::builder()
                .label("Validating your configuration before creating mount units…")
                .css_classes(["dim-label"])
                .halign(Align::Start)
                .wrap(true)
                .build();
            container.append(&subtitle);

            // ── Spinner area (shown while validations run) ─────────

            let spinner_box = Box::builder()
                .orientation(Orientation::Horizontal)
                .spacing(12)
                .halign(Align::Center)
                .margin_top(16)
                .margin_bottom(16)
                .build();

            let spinner = gtk::Spinner::builder()
                .spinning(false)
                .build();

            let spinner_label = Label::builder()
                .label("Running validation checks…")
                .css_classes(["dim-label"])
                .visible(false)
                .build();

            spinner_box.append(&spinner);
            spinner_box.append(&spinner_label);
            container.append(&spinner_box);

            // ── Results list ───────────────────────────────────────

            let results_box = Box::builder()
                .orientation(Orientation::Vertical)
                .spacing(8)
                .build();
            container.append(&results_box);

            // ── Kerberos actions area ──────────────────────────────

            let kerberos_actions_box = Box::builder()
                .orientation(Orientation::Vertical)
                .spacing(12)
                .margin_top(16)
                .visible(false)
                .build();

            // Kinit action group
            let kinit_group = adw::PreferencesGroup::builder()
                .title("Kerberos Ticket")
                .description("No valid Kerberos ticket found. You can obtain one now.")
                .build();

            let principal_row = adw::EntryRow::builder()
                .title("Kerberos Principal")
                .build();
            principal_row.set_tooltip_text(Some(
                "Your Kerberos principal (e.g. user@EXAMPLE.COM)",
            ));
            kinit_group.add(&principal_row);

            let kinit_button = Button::builder()
                .label("Run kinit")
                .css_classes(["suggested-action"])
                .halign(Align::Start)
                .margin_top(8)
                .build();

            let kinit_feedback_label = Label::builder()
                .label("")
                .css_classes(["dim-label"])
                .halign(Align::Start)
                .wrap(true)
                .visible(false)
                .build();

            kerberos_actions_box.append(&kinit_group);
            kerberos_actions_box.append(&kinit_button);
            kerberos_actions_box.append(&kinit_feedback_label);

            // Kinit service creation group
            let kinit_service_separator = Separator::new(Orientation::Horizontal);
            kerberos_actions_box.append(&kinit_service_separator);

            let kinit_service_group = adw::PreferencesGroup::builder()
                .title("Boot-time Kinit Service")
                .description("No krb5-kinit service found. Kerberos mounts will fail after reboot without one.")
                .build();

            let keytab_row = adw::EntryRow::builder()
                .title("Keytab Path")
                .build();
            keytab_row.set_tooltip_text(Some(
                "Path to the keytab file (e.g. /etc/krb5.keytab)",
            ));

            // Browse button for keytab file
            let keytab_browse_btn = Button::builder()
                .icon_name("document-open-symbolic")
                .css_classes(["flat"])
                .valign(Align::Center)
                .tooltip_text("Browse for keytab file")
                .build();
            keytab_row.add_suffix(&keytab_browse_btn);

            {
                let kt_row = keytab_row.clone();
                let dialog_weak = self.dialog.downgrade();
                keytab_browse_btn.connect_clicked(move |_| {
                    let file_dialog = gtk::FileDialog::builder()
                        .title("Select Keytab File")
                        .modal(true)
                        .build();
                    let row = kt_row.clone();
                    let parent = dialog_weak.upgrade();
                    file_dialog.open(
                        parent.as_ref(),
                        None::<&gtk::gio::Cancellable>,
                        move |result| {
                            if let Ok(file) = result {
                                if let Some(path) = file.path() {
                                    row.set_text(&path.to_string_lossy());
                                }
                            }
                        },
                    );
                });
            }

            kinit_service_group.add(&keytab_row);

            let kinit_service_button = Button::builder()
                .label("Create kinit service")
                .css_classes(["suggested-action"])
                .halign(Align::Start)
                .margin_top(8)
                .build();

            let kinit_service_feedback_label = Label::builder()
                .label("")
                .css_classes(["dim-label"])
                .halign(Align::Start)
                .wrap(true)
                .visible(false)
                .build();

            kerberos_actions_box.append(&kinit_service_group);
            kerberos_actions_box.append(&kinit_service_button);
            kerberos_actions_box.append(&kinit_service_feedback_label);

            container.append(&kerberos_actions_box);

            // ── Store widget references ────────────────────────────

            *self.validation_widgets.borrow_mut() = Some(ValidationStepWidgets {
                spinner: spinner.clone(),
                spinner_label: spinner_label.clone(),
                results_box: results_box.clone(),
                kerberos_actions_box: kerberos_actions_box.clone(),
                kinit_button: kinit_button.clone(),
                kinit_service_button: kinit_service_button.clone(),
                keytab_row: keytab_row.clone(),
                kinit_feedback_label: kinit_feedback_label.clone(),
                kinit_service_feedback_label: kinit_service_feedback_label.clone(),
            });

            // ── Wire up kinit button ───────────────────────────────

            {
                let principal_row_ref = principal_row.clone();
                let kinit_feedback = kinit_feedback_label.clone();
                let kinit_btn = kinit_button.clone();
                let validation_widgets = self.validation_widgets.clone();
                let state = self.state.clone();
                let next_button = self.next_button.clone();
                let results_box_ref = results_box.clone();

                kinit_button.connect_clicked(move |_| {
                    let principal = principal_row_ref.text().trim().to_string();
                    if principal.is_empty() {
                        kinit_feedback.set_label("Please enter a Kerberos principal.");
                        kinit_feedback.set_css_classes(&["error"]);
                        kinit_feedback.set_visible(true);
                        return;
                    }

                    kinit_btn.set_sensitive(false);
                    kinit_feedback.set_label("Running kinit…");
                    kinit_feedback.set_css_classes(&["dim-label"]);
                    kinit_feedback.set_visible(true);

                    let feedback = kinit_feedback.clone();
                    let btn = kinit_btn.clone();
                    let vw = validation_widgets.clone();
                    let st = state.clone();
                    let nb = next_button.clone();
                    let rb = results_box_ref.clone();

                    spawn_blocking_then(
                        move || KerberosChecker::run_kinit(&principal),
                        move |result| {
                            btn.set_sensitive(true);
                            match result {
                                Ok(()) => {
                                    feedback.set_label("✓ kinit succeeded — Kerberos ticket obtained.");
                                    feedback.set_css_classes(&["success"]);
                                    feedback.set_visible(true);
                                    // Re-run validations to update the klist check
                                    Self::trigger_revalidation(&vw, &st, &nb, &rb);
                                }
                                Err(e) => {
                                    feedback.set_label(&format!("✗ kinit failed: {}", e));
                                    feedback.set_css_classes(&["error"]);
                                    feedback.set_visible(true);
                                }
                            }
                        },
                    );
                });
            }

            // ── Wire up kinit service button ───────────────────────

            {
                let principal_row_ref = principal_row.clone();
                let keytab_row_ref = keytab_row.clone();
                let service_feedback = kinit_service_feedback_label.clone();
                let service_btn = kinit_service_button.clone();
                let validation_widgets = self.validation_widgets.clone();
                let state = self.state.clone();
                let next_button = self.next_button.clone();
                let results_box_ref = results_box.clone();

                kinit_service_button.connect_clicked(move |_| {
                    let principal = principal_row_ref.text().trim().to_string();
                    let keytab_path = keytab_row_ref.text().trim().to_string();

                    if principal.is_empty() {
                        service_feedback.set_label("Please enter a Kerberos principal.");
                        service_feedback.set_css_classes(&["error"]);
                        service_feedback.set_visible(true);
                        return;
                    }
                    if keytab_path.is_empty() {
                        service_feedback.set_label("Please enter a keytab file path.");
                        service_feedback.set_css_classes(&["error"]);
                        service_feedback.set_visible(true);
                        return;
                    }

                    service_btn.set_sensitive(false);
                    service_feedback.set_label("Creating kinit service…");
                    service_feedback.set_css_classes(&["dim-label"]);
                    service_feedback.set_visible(true);

                    let feedback = service_feedback.clone();
                    let btn = service_btn.clone();
                    let vw = validation_widgets.clone();
                    let st = state.clone();
                    let nb = next_button.clone();
                    let rb = results_box_ref.clone();

                    spawn_blocking_then(
                        move || KinitServiceManager::create_service(&principal, &keytab_path),
                        move |result| {
                            btn.set_sensitive(true);
                            match result {
                                Ok(()) => {
                                    feedback.set_label("✓ krb5-kinit.service created and enabled.");
                                    feedback.set_css_classes(&["success"]);
                                    feedback.set_visible(true);
                                    // Re-run validations to update the kinit service check
                                    Self::trigger_revalidation(&vw, &st, &nb, &rb);
                                }
                                Err(e) => {
                                    feedback.set_label(&format!("✗ Failed to create service: {}", e));
                                    feedback.set_css_classes(&["error"]);
                                    feedback.set_visible(true);
                                }
                            }
                        },
                    );
                });
            }

            scrolled.set_child(Some(&container));
            scrolled
        }

        /// Build a single validation result row with a severity icon.
        fn build_validation_result_row(result: &ValidationResult) -> Box {
            let row = Box::builder()
                .orientation(Orientation::Horizontal)
                .spacing(12)
                .margin_start(8)
                .margin_end(8)
                .margin_top(4)
                .margin_bottom(4)
                .build();

            // Severity icon
            let (icon_text, icon_classes) = match result.severity {
                ValidationSeverity::Ok => ("✓", vec!["success"]),
                ValidationSeverity::Warning => ("⚠", vec!["warning"]),
                ValidationSeverity::Error => ("✗", vec!["error"]),
            };

            let icon_label = Label::builder()
                .label(icon_text)
                .css_classes(icon_classes)
                .valign(Align::Start)
                .build();

            // Check name and message
            let text_box = Box::builder()
                .orientation(Orientation::Vertical)
                .spacing(2)
                .hexpand(true)
                .build();

            let name_label = Label::builder()
                .label(&result.check_name.replace('_', " "))
                .css_classes(["heading"])
                .halign(Align::Start)
                .build();

            let message_label = Label::builder()
                .label(&result.message)
                .css_classes(["dim-label", "caption"])
                .halign(Align::Start)
                .wrap(true)
                .build();

            text_box.append(&name_label);
            text_box.append(&message_label);

            row.append(&icon_label);
            row.append(&text_box);

            row
        }

        /// Trigger a re-validation after a Kerberos action (kinit or service creation).
        /// This re-runs all checks on a background thread and updates the results.
        fn trigger_revalidation(
            validation_widgets: &Rc<RefCell<Option<ValidationStepWidgets>>>,
            state: &Rc<RefCell<WizardState>>,
            next_button: &Button,
            results_box: &Box,
        ) {
            let widgets = validation_widgets.borrow();
            let widgets = match widgets.as_ref() {
                Some(w) => w,
                None => return,
            };

            // Show spinner
            widgets.spinner.set_spinning(true);
            widgets.spinner_label.set_visible(true);

            // Clear previous results
            while let Some(child) = results_box.first_child() {
                results_box.remove(&child);
            }

            // Disable Next while re-validating
            next_button.set_sensitive(false);

            let state_snapshot = state.borrow().clone();
            let vw = validation_widgets.clone();
            let st = state.clone();
            let nb = next_button.clone();

            spawn_blocking_then(
                move || {
                    let mut results = ValidationEngine::run_all(&state_snapshot);

                    if state_snapshot.auth_method == AuthMethod::Kerberos {
                        if let Some(hostname) = KerberosChecker::extract_hostname(&state_snapshot.share_address) {
                            results.push(KerberosChecker::validate_fqdn(&hostname));
                            results.push(KerberosChecker::resolve_hostname(&hostname));
                            if let Some(domain) = KerberosChecker::extract_domain(&hostname) {
                                results.push(KerberosChecker::check_dns_srv(&domain));
                            }
                        }

                        match KerberosChecker::has_valid_ticket() {
                            Ok(true) => {
                                results.push(ValidationResult {
                                    check_name: "kerberos_ticket".into(),
                                    severity: ValidationSeverity::Ok,
                                    message: "Valid Kerberos ticket found".into(),
                                });
                            }
                            Ok(false) => {
                                results.push(ValidationResult {
                                    check_name: "kerberos_ticket".into(),
                                    severity: ValidationSeverity::Warning,
                                    message: "No valid Kerberos ticket found. You can run kinit to obtain one.".into(),
                                });
                            }
                            Err(e) => {
                                results.push(ValidationResult {
                                    check_name: "kerberos_ticket".into(),
                                    severity: ValidationSeverity::Warning,
                                    message: format!("Could not check Kerberos ticket: {}", e),
                                });
                            }
                        }

                        match KinitServiceManager::service_exists_and_enabled() {
                            Ok(true) => {
                                results.push(ValidationResult {
                                    check_name: "kinit_service".into(),
                                    severity: ValidationSeverity::Ok,
                                    message: "Boot-time kinit service (krb5-kinit.service) is enabled".into(),
                                });
                            }
                            Ok(false) => {
                                results.push(ValidationResult {
                                    check_name: "kinit_service".into(),
                                    severity: ValidationSeverity::Warning,
                                    message: "No boot-time kinit service found. Kerberos mounts will fail after reboot.".into(),
                                });
                            }
                            Err(e) => {
                                results.push(ValidationResult {
                                    check_name: "kinit_service".into(),
                                    severity: ValidationSeverity::Warning,
                                    message: format!("Could not check kinit service: {}", e),
                                });
                            }
                        }
                    }

                    results
                },
                move |results: Vec<ValidationResult>| {
                    let widgets = vw.borrow();
                    let widgets = match widgets.as_ref() {
                        Some(w) => w,
                        None => return,
                    };

                    widgets.spinner.set_spinning(false);
                    widgets.spinner_label.set_visible(false);

                    let has_errors = results.iter().any(|r| r.severity == ValidationSeverity::Error);

                    let mut show_kinit_action = false;
                    let mut show_kinit_service_action = false;

                    for result in &results {
                        let row = Self::build_validation_result_row(result);
                        widgets.results_box.append(&row);

                        if result.check_name == "kerberos_ticket"
                            && result.severity != ValidationSeverity::Ok
                        {
                            show_kinit_action = true;
                        }
                        if result.check_name == "kinit_service"
                            && result.severity != ValidationSeverity::Ok
                        {
                            show_kinit_service_action = true;
                        }
                    }

                    if show_kinit_action || show_kinit_service_action {
                        widgets.kerberos_actions_box.set_visible(true);
                        widgets.kinit_button.set_visible(show_kinit_action);
                        widgets.kinit_service_button.set_visible(show_kinit_service_action);
                        widgets.keytab_row.set_visible(show_kinit_service_action);
                    } else {
                        widgets.kerberos_actions_box.set_visible(false);
                    }

                    let result_strings: Vec<String> = results
                        .iter()
                        .map(|r| format!("[{:?}] {}: {}", r.severity, r.check_name, r.message))
                        .collect();
                    st.borrow_mut().validation_results = result_strings;

                    nb.set_sensitive(!has_errors);
                },
            );
        }

        // ── Step 5: Summary & Confirm ──────────────────────────────

        /// Remove the Summary placeholder and install the real widget.
        fn install_summary_step(&self) {
            if let Some(old) = self.stack.child_by_name(step_name(WizardStep::Summary)) {
                self.stack.remove(&old);
            }
            let page = self.build_summary_step();
            self.stack.add_named(&page, Some(step_name(WizardStep::Summary)));
        }

        /// Build the Summary & Confirm step content (Req 8.1–8.3, 9.1–9.6, 12.3, 12.4).
        ///
        /// Displays:
        /// - Share address, mount point, and assembled mount options
        /// - List of unit filenames that will be created
        /// - Connectivity check result (spinner → green/red)
        /// - Error label for write failures
        fn build_summary_step(&self) -> gtk::ScrolledWindow {
            let scrolled = gtk::ScrolledWindow::builder()
                .hscrollbar_policy(gtk::PolicyType::Never)
                .vexpand(true)
                .build();

            let container = Box::builder()
                .orientation(Orientation::Vertical)
                .margin_start(24)
                .margin_end(24)
                .margin_top(24)
                .margin_bottom(24)
                .spacing(16)
                .build();

            let heading = Label::builder()
                .label("Review & Confirm")
                .css_classes(["title-3"])
                .halign(Align::Start)
                .build();
            container.append(&heading);

            let subtitle = Label::builder()
                .label("Review the configuration below. Click Confirm to write the systemd unit files.")
                .css_classes(["dim-label"])
                .halign(Align::Start)
                .wrap(true)
                .build();
            container.append(&subtitle);

            // ── Configuration summary group ────────────────────────

            let config_group = adw::PreferencesGroup::builder()
                .title("Configuration")
                .margin_top(8)
                .build();

            let share_row = adw::ActionRow::builder()
                .title("Share Address")
                .subtitle_selectable(true)
                .build();
            config_group.add(&share_row);

            let mount_row = adw::ActionRow::builder()
                .title("Mount Point")
                .subtitle_selectable(true)
                .build();
            config_group.add(&mount_row);

            let options_row = adw::ActionRow::builder()
                .title("Mount Options")
                .subtitle_selectable(true)
                .build();
            config_group.add(&options_row);

            container.append(&config_group);

            // ── Unit files group ───────────────────────────────────

            let units_group = adw::PreferencesGroup::builder()
                .title("Unit Files to Create")
                .build();

            let units_list_box = Box::builder()
                .orientation(Orientation::Vertical)
                .spacing(4)
                .halign(Align::End)
                .hexpand(true)
                .build();

            // We wrap the units_list_box in an ActionRow for consistent styling
            let units_wrapper_row = adw::ActionRow::builder()
                .title("Files")
                .build();
            units_wrapper_row.add_suffix(&units_list_box);
            units_group.add(&units_wrapper_row);

            container.append(&units_group);

            // ── Connectivity check group ───────────────────────────

            let connectivity_group = adw::PreferencesGroup::builder()
                .title("Connectivity")
                .build();

            let connectivity_box = Box::builder()
                .orientation(Orientation::Horizontal)
                .spacing(8)
                .build();

            let connectivity_spinner = gtk::Spinner::builder()
                .spinning(false)
                .build();

            let connectivity_label = Label::builder()
                .label("")
                .css_classes(["dim-label"])
                .halign(Align::End)
                .hexpand(true)
                .wrap(true)
                .wrap_mode(pango::WrapMode::WordChar)
                .max_width_chars(40)
                .build();

            connectivity_box.append(&connectivity_spinner);
            connectivity_box.append(&connectivity_label);

            let connectivity_row = adw::ActionRow::builder()
                .title("Share Reachability")
                .build();
            connectivity_row.add_suffix(&connectivity_box);
            connectivity_group.add(&connectivity_row);

            container.append(&connectivity_group);

            // ── Write error label ──────────────────────────────────

            let write_error_label = Label::builder()
                .label("")
                .css_classes(["error"])
                .halign(Align::Start)
                .wrap(true)
                .visible(false)
                .margin_top(8)
                .build();
            container.append(&write_error_label);

            // ── Store widget references ────────────────────────────

            *self.summary_widgets.borrow_mut() = Some(SummaryStepWidgets {
                share_address_row: share_row,
                mount_point_row: mount_row,
                mount_options_row: options_row,
                units_list_box,
                connectivity_spinner,
                connectivity_label,
                write_error_label,
            });

            scrolled.set_child(Some(&container));
            scrolled
        }

        /// Static helper to populate the summary step from signal closures.
        fn populate_summary_static(
            summary_widgets: &Rc<RefCell<Option<SummaryStepWidgets>>>,
            state: &Rc<RefCell<WizardState>>,
            confirm_button: &Button,
        ) {
            let widgets = summary_widgets.borrow();
            let widgets = match widgets.as_ref() {
                Some(w) => w,
                None => return,
            };

            let st = state.borrow();

            // Populate configuration labels (Req 9.2, 9.3)
            widgets.share_address_row.set_subtitle(&st.share_address);
            widgets.mount_point_row.set_subtitle(&st.mount_point);

            let options = st.build_mount_options();
            widgets.mount_options_row.set_subtitle(&options.join(", "));

            // Populate unit filenames list (Req 9.1)
            while let Some(child) = widgets.units_list_box.first_child() {
                widgets.units_list_box.remove(&child);
            }
            for filename in st.summary_unit_filenames() {
                let file_label = Label::builder()
                    .label(&filename)
                    .css_classes(["monospace", "caption"])
                    .halign(Align::Start)
                    .build();
                widgets.units_list_box.append(&file_label);
            }

            // Clear previous error
            widgets.write_error_label.set_label("");
            widgets.write_error_label.set_visible(false);

            // Run connectivity check on background thread (Req 8.1, 8.4)
            widgets.connectivity_spinner.set_spinning(true);
            widgets.connectivity_label.set_label("Testing connectivity…");
            widgets.connectivity_label.set_css_classes(&["dim-label"]);

            // Disable confirm while connectivity check runs (Req 13.3)
            confirm_button.set_sensitive(false);

            let share_addr = st.share_address.clone();
            let auth_method = st.auth_method;
            let creds_path = if auth_method == AuthMethod::CredentialsFile {
                Some(st.credentials_file_path.clone())
            } else {
                None
            };

            drop(st); // Release borrow before spawning

            let sw = summary_widgets.clone();
            let cb = confirm_button.clone();

            spawn_blocking_then(
                move || {
                    ValidationEngine::check_share_connectivity(
                        &share_addr,
                        &auth_method,
                        creds_path.as_deref(),
                    )
                },
                move |result: ValidationResult| {
                    let widgets = sw.borrow();
                    let widgets = match widgets.as_ref() {
                        Some(w) => w,
                        None => return,
                    };

                    widgets.connectivity_spinner.set_spinning(false);

                    match result.severity {
                        ValidationSeverity::Ok => {
                            // Green status (Req 8.2)
                            widgets.connectivity_label.set_label("✓ Share is reachable");
                            widgets.connectivity_label.set_css_classes(&["success"]);
                        }
                        ValidationSeverity::Warning | ValidationSeverity::Error => {
                            // Red status with error message (Req 8.3)
                            widgets.connectivity_label.set_label(
                                &format!("✗ {}", result.message),
                            );
                            widgets.connectivity_label.set_css_classes(&["error"]);
                        }
                    }

                    // Re-enable confirm — user can proceed even if connectivity fails (Req 8.3)
                    cb.set_sensitive(true);
                },
            );
        }

        /// Write all unit files, handling edit mode removal, rollback, and success.
        ///
        /// - Edit mode: remove old units first via `remove_systemd_mount_unit()`,
        ///   abort if removal fails (Req 12.3, 12.4)
        /// - On write failure: roll back partially written units, display error,
        ///   keep wizard open (Req 9.5)
        /// - On success: close dialog, refresh mounts list, show success toast (Req 9.6)
        fn confirm_and_write(
            state: &Rc<RefCell<WizardState>>,
            summary_widgets: &Rc<RefCell<Option<SummaryStepWidgets>>>,
            confirm_button: &Button,
            back_button: &Button,
            dialog: &adw::Window,
            on_complete: &Rc<RefCell<Option<std::boxed::Box<dyn Fn()>>>>,
        ) {
            let st = state.borrow();
            let entry = st.to_mount_entry();
            let is_edit = st.editing.is_some();
            let old_mount_point = st.editing.as_ref().map(|e| e.mount_point.clone());
            drop(st);

            // Disable buttons during write
            confirm_button.set_sensitive(false);
            back_button.set_sensitive(false);

            // Show writing status
            {
                let widgets = summary_widgets.borrow();
                if let Some(w) = widgets.as_ref() {
                    w.write_error_label.set_label("");
                    w.write_error_label.set_visible(false);
                }
            }

            let sw = summary_widgets.clone();
            let cb = confirm_button.clone();
            let bb = back_button.clone();
            let dialog_weak = dialog.downgrade();
            let on_complete_cb = on_complete.clone();

            spawn_blocking_then(
                move || -> Result<String, String> {
                    // Edit mode: remove old units first (Req 12.3)
                    if is_edit {
                        if let Some(ref old_mp) = old_mount_point {
                            Self::remove_old_units(old_mp)?;
                        }
                    }

                    // Write new units
                    Self::write_all_units(&entry)
                        .map_err(|write_err| {
                            // Rollback on failure (Req 9.5)
                            log::error!("Write failed, rolling back: {}", write_err);
                            let _ = Self::rollback_units(&entry);
                            write_err
                        })?;

                    let msg = if is_edit { "Mount updated" } else { "Mount added" };
                    Ok(msg.to_string())
                },
                move |result: Result<String, String>| {
                    match result {
                        Ok(msg) => {
                            // Success: close dialog, show toast (Req 9.6)
                            crate::ui::gui::show_success_toast(&msg);
                            // Invoke on_complete callback to refresh mounts list
                            if let Some(ref f) = *on_complete_cb.borrow() {
                                f();
                            }
                            if let Some(d) = dialog_weak.upgrade() {
                                d.close();
                            }
                        }
                        Err(e) => {
                            // Failure: display error, keep wizard open (Req 9.5)
                            let widgets = sw.borrow();
                            if let Some(w) = widgets.as_ref() {
                                w.write_error_label.set_label(&format!("Error: {}", e));
                                w.write_error_label.set_visible(true);
                            }
                            cb.set_sensitive(true);
                            bb.set_sensitive(true);
                        }
                    }
                },
            );
        }

        /// Remove old units for edit mode (Req 12.3, 12.4).
        fn remove_old_units(mount_point: &str) -> Result<(), String> {
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
            let (_out, stderr, ok) = privileged_executor::run_privileged(
                "rm", &["-f", &mount_path],
            ).map_err(|e| format!("Failed to remove old mount unit: {}", e))?;
            if !ok && !stderr.is_empty() {
                return Err(format!("Failed to remove old mount unit: {}", stderr.trim()));
            }

            let (_out, stderr, ok) = privileged_executor::run_privileged(
                "rm", &["-f", &automount_path],
            ).map_err(|e| format!("Failed to remove old automount unit: {}", e))?;
            if !ok && !stderr.is_empty() {
                return Err(format!("Failed to remove old automount unit: {}", stderr.trim()));
            }

            // Reload daemon
            let (_out, stderr, ok) = privileged_executor::run_privileged(
                "systemctl", &["daemon-reload"],
            ).map_err(|e| format!("daemon-reload failed: {}", e))?;
            if !ok {
                log::warn!("systemctl daemon-reload after removal failed: {}", stderr.trim());
            }

            Ok(())
        }

        /// Write all unit files for the mount entry via PrivilegedExecutor.
        fn write_all_units(entry: &SystemdMountEntry) -> Result<(), String> {
            use crate::services::privileged_executor;
            use crate::services::SystemdMountManager;

            let mount_unit_name = SystemdMountManager::mount_unit_name(&entry.mount_point);
            let mount_path = format!("/etc/systemd/system/{}", mount_unit_name);
            let mount_content = SystemdMountManager::generate_mount_unit(entry);

            // Write .mount unit file
            let (_stdout, stderr, ok) = privileged_executor::run_privileged_with_stdin(
                "tee", &[&mount_path], &mount_content,
            ).map_err(|e| format!("Failed to write mount unit: {}", e))?;

            if !ok {
                return Err(format!("Failed to write mount unit: {}", stderr.trim()));
            }

            // Write .automount unit if requested
            if entry.automount {
                let automount_unit_name = SystemdMountManager::automount_unit_name(&entry.mount_point);
                let automount_path = format!("/etc/systemd/system/{}", automount_unit_name);
                let automount_content = SystemdMountManager::generate_automount_unit(entry);

                let (_stdout, stderr, ok) = privileged_executor::run_privileged_with_stdin(
                    "tee", &[&automount_path], &automount_content,
                ).map_err(|e| format!("Failed to write automount unit: {}", e))?;

                if !ok {
                    return Err(format!("Failed to write automount unit: {}", stderr.trim()));
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

            Ok(())
        }

        /// Roll back partially written units on failure (Req 9.5).
        fn rollback_units(entry: &SystemdMountEntry) -> Result<(), String> {
            use crate::services::privileged_executor;
            use crate::services::SystemdMountManager;

            let mount_unit_name = SystemdMountManager::mount_unit_name(&entry.mount_point);
            let mount_path = format!("/etc/systemd/system/{}", mount_unit_name);

            // Remove .mount unit if it was written
            let _ = privileged_executor::run_privileged("rm", &["-f", &mount_path]);

            // Remove .automount unit if it was written
            if entry.automount {
                let automount_unit_name = SystemdMountManager::automount_unit_name(&entry.mount_point);
                let automount_path = format!("/etc/systemd/system/{}", automount_unit_name);
                let _ = privileged_executor::run_privileged("rm", &["-f", &automount_path]);
            }

            // Reload daemon to clean up
            let _ = privileged_executor::run_privileged("systemctl", &["daemon-reload"]);

            Ok(())
        }

        // ── Signal wiring ─────────────────────────────────────────────

        fn connect_signals(&self) {
            // Cancel button — close without writing (Req 10.6)
            let dialog_weak = self.dialog.downgrade();
            self.cancel_button.connect_clicked(move |_| {
                if let Some(d) = dialog_weak.upgrade() {
                    d.close();
                }
            });

            // Back button (Req 10.2)
            {
                let current_step = self.current_step.clone();
                let stack = self.stack.clone();
                let back_button = self.back_button.clone();
                let next_button = self.next_button.clone();
                let confirm_button = self.confirm_button.clone();
                let title_label = self.title_label.clone();
                let step_indicator = self.step_indicator.clone();
                let error_label = self.error_label.clone();
                let connection_widgets = self.connection_widgets.clone();
                let mount_options_widgets = self.mount_options_widgets.clone();
                let state = self.state.clone();
                let validation_widgets = self.validation_widgets.clone();
                let summary_widgets = self.summary_widgets.clone();

                self.back_button.connect_clicked(move |_| {
                    let idx = step_index(current_step.get());
                    if idx > 0 {
                        Self::navigate_to(
                            STEPS[idx - 1],
                            &current_step,
                            &stack,
                            &back_button,
                            &next_button,
                            &confirm_button,
                            &title_label,
                            &step_indicator,
                            &error_label,
                            &connection_widgets,
                            &mount_options_widgets,
                            &state,
                            &validation_widgets,
                            &summary_widgets,
                        );
                    }
                });
            }

            // Next button — validate then advance (Req 10.3, 10.4, 10.5)
            {
                let state = self.state.clone();
                let current_step = self.current_step.clone();
                let stack = self.stack.clone();
                let back_button = self.back_button.clone();
                let next_button = self.next_button.clone();
                let confirm_button = self.confirm_button.clone();
                let title_label = self.title_label.clone();
                let step_indicator = self.step_indicator.clone();
                let error_label = self.error_label.clone();
                let connection_widgets = self.connection_widgets.clone();
                let mount_options_widgets = self.mount_options_widgets.clone();
                let validation_widgets = self.validation_widgets.clone();
                let summary_widgets = self.summary_widgets.clone();

                self.next_button.connect_clicked(move |_| {
                    let current = current_step.get();

                    // Validate current step (Req 10.4, 10.5)
                    let errors = state.borrow().validate_step(current);
                    if !errors.is_empty() {
                        let text = errors.join("\n");
                        error_label.set_label(&text);
                        error_label.set_visible(true);
                        return;
                    }

                    let idx = step_index(current);
                    if idx + 1 < STEPS.len() {
                        Self::navigate_to(
                            STEPS[idx + 1],
                            &current_step,
                            &stack,
                            &back_button,
                            &next_button,
                            &confirm_button,
                            &title_label,
                            &step_indicator,
                            &error_label,
                            &connection_widgets,
                            &mount_options_widgets,
                            &state,
                            &validation_widgets,
                            &summary_widgets,
                        );
                    }
                });
            }

            // Confirm button — write units and close (Req 9.4, 9.5, 9.6, 12.3, 12.4)
            {
                let state = self.state.clone();
                let summary_widgets = self.summary_widgets.clone();
                let confirm_button = self.confirm_button.clone();
                let back_button = self.back_button.clone();
                let dialog = self.dialog.clone();
                let on_complete = self.on_complete.clone();

                self.confirm_button.connect_clicked(move |_| {
                    Self::confirm_and_write(
                        &state,
                        &summary_widgets,
                        &confirm_button,
                        &back_button,
                        &dialog,
                        &on_complete,
                    );
                });
            }
        }

    }
}
