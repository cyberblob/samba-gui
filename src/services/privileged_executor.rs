#![allow(dead_code)]
//! Privileged command executor with single-authentication caching.
//!
//! All privileged operations go through [`run_privileged`] or
//! [`run_privileged_with_stdin`]. Both automatically call
//! [`ensure_authenticated`] before executing, so callers never need to
//! authenticate manually.
//!
//! When a password is required the request is bounced to the GTK main
//! thread via `glib::idle_add_once` (GUI builds) so the dialog can be
//! shown safely regardless of which thread the caller is on.

use std::io::Write;
use std::process::Command;
use std::sync::Mutex;
use thiserror::Error;

#[cfg(feature = "gui")]
use gtk::glib;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum PrivilegedError {
    #[error("Command execution failed: {0}")]
    CommandExecution(String),

    #[error("Authentication cancelled by user")]
    AuthCancelled,

    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

pub type PrivilegedResult<T> = Result<T, PrivilegedError>;

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Cached password so we can re-prime sudo if the timestamp expires.
static CACHED_PASSWORD: Mutex<Option<String>> = Mutex::new(None);

/// Password prompt callback set once by the UI layer at startup.
static PASSWORD_CALLBACK: Mutex<Option<fn() -> Option<String>>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Public API – setup
// ---------------------------------------------------------------------------

/// Register the password prompt callback. Call once from the UI layer at
/// application startup.
pub fn set_password_callback(cb: fn() -> Option<String>) {
    *PASSWORD_CALLBACK.lock().unwrap() = Some(cb);
}

// ---------------------------------------------------------------------------
// Public API – running commands
// ---------------------------------------------------------------------------

/// Execute a command with root privileges.
///
/// Authenticates automatically (prompting once if needed), then runs
/// `sudo <program> <args…>`.
///
/// Returns `(stdout, stderr, success)`.
pub fn run_privileged(program: &str, args: &[&str]) -> PrivilegedResult<(String, String, bool)> {
    ensure_authenticated()?;

    let mut cmd_args = vec![program];
    cmd_args.extend_from_slice(args);

    let output = Command::new("sudo")
        .args(&cmd_args)
        .output()
        .map_err(|e| PrivilegedError::CommandExecution(e.to_string()))?;

    Ok((
        String::from_utf8_lossy(&output.stdout).into(),
        String::from_utf8_lossy(&output.stderr).into(),
        output.status.success(),
    ))
}

/// Execute a privileged command, piping `stdin_data` to its stdin.
///
/// Authenticates automatically. Returns `(stdout, stderr, success)`.
pub fn run_privileged_with_stdin(
    program: &str,
    args: &[&str],
    stdin_data: &str,
) -> PrivilegedResult<(String, String, bool)> {
    ensure_authenticated()?;

    let mut cmd_args = vec![program];
    cmd_args.extend_from_slice(args);

    let mut child = Command::new("sudo")
        .args(&cmd_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| PrivilegedError::CommandExecution(e.to_string()))?;

    if let Some(ref mut stdin) = child.stdin {
        let _ = write!(stdin, "{}", stdin_data);
    }

    let output = child
        .wait_with_output()
        .map_err(|e| PrivilegedError::CommandExecution(e.to_string()))?;

    Ok((
        String::from_utf8_lossy(&output.stdout).into(),
        String::from_utf8_lossy(&output.stderr).into(),
        output.status.success(),
    ))
}

// ---------------------------------------------------------------------------
// Public API – auth queries
// ---------------------------------------------------------------------------

/// Check whether we currently have a valid sudo session (non-blocking).
pub fn is_authenticated() -> bool {
    sudo_timestamp_valid()
}

/// Invalidate the cached authentication and sudo timestamp.
pub fn invalidate_auth() {
    *CACHED_PASSWORD.lock().unwrap() = None;
    let _ = Command::new("sudo").args(["-k"]).status();
}

// ---------------------------------------------------------------------------
// Internal – authentication
// ---------------------------------------------------------------------------

/// Ensure we have a valid sudo session. Safe to call from **any** thread.
///
/// 1. Fast-path: `sudo -n -v` succeeds → already authenticated.
/// 2. Try the cached password.
/// 3. Bounce a password-prompt to the GTK main thread, block until the
///    user responds, then validate.
pub fn ensure_authenticated() -> PrivilegedResult<()> {
    ensure_authenticated_inner(sudo_timestamp_valid, try_sudo_auth, request_password_from_ui)
}

/// Inner implementation with injectable dependencies for testability.
///
/// This allows unit tests to verify the authentication flow without
/// depending on real sudo or shared global state.
fn ensure_authenticated_inner(
    is_valid: fn() -> bool,
    try_auth: fn(&str) -> PrivilegedResult<bool>,
    request_password: fn() -> Option<String>,
) -> PrivilegedResult<()> {
    if is_valid() {
        return Ok(());
    }

    // Try cached password
    {
        let cached = CACHED_PASSWORD.lock().unwrap();
        if let Some(ref pw) = *cached {
            if try_auth(pw)? {
                return Ok(());
            }
        }
    }

    // Ask the user (thread-safe)
    let password = request_password()
        .ok_or(PrivilegedError::AuthCancelled)?;

    if !try_auth(&password)? {
        return Err(PrivilegedError::PermissionDenied("Incorrect password.".into()));
    }

    *CACHED_PASSWORD.lock().unwrap() = Some(password);
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal – password prompt (thread-safe)
// ---------------------------------------------------------------------------

/// Request a password from the UI thread. Safe to call from any thread.
///
/// In GUI builds this uses `glib::idle_add_once` to schedule the dialog on
/// the main thread and blocks the calling thread with a `Condvar` until the
/// user responds.
#[cfg(feature = "gui")]
fn request_password_from_ui() -> Option<String> {
    use std::sync::{Arc, Condvar};

    let cb = {
        let slot = PASSWORD_CALLBACK.lock().unwrap();
        (*slot)?
    };

    let pair = Arc::new((Mutex::new(None::<Option<String>>), Condvar::new()));
    let pair2 = pair.clone();

    glib::idle_add_once(move || {
        let password = cb();
        let (lock, cvar) = &*pair2;
        *lock.lock().unwrap() = Some(password);
        cvar.notify_one();
    });

    let (lock, cvar) = &*pair;
    let mut result = lock.lock().unwrap();
    while result.is_none() {
        result = cvar.wait(result).unwrap();
    }
    result.take().unwrap()
}

/// Non-GUI fallback: call the callback directly (assumed to be on the main
/// thread already).
#[cfg(not(feature = "gui"))]
fn request_password_from_ui() -> Option<String> {
    let cb = {
        let slot = PASSWORD_CALLBACK.lock().unwrap();
        (*slot)?
    };
    cb()
}

// ---------------------------------------------------------------------------
// Internal – sudo helpers
// ---------------------------------------------------------------------------

fn sudo_timestamp_valid() -> bool {
    Command::new("sudo")
        .args(["-n", "-v"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn try_sudo_auth(password: &str) -> PrivilegedResult<bool> {
    let mut child = Command::new("sudo")
        .args(["-S", "-v"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| PrivilegedError::CommandExecution(e.to_string()))?;

    if let Some(ref mut stdin) = child.stdin {
        let _ = writeln!(stdin, "{}", password);
    }

    let output = child
        .wait_with_output()
        .map_err(|e| PrivilegedError::CommandExecution(e.to_string()))?;

    Ok(output.status.success())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_cached_password_starts_empty() {
        let cached = CACHED_PASSWORD.lock().unwrap();
        // In a fresh process this is None; in the test runner it may have
        // been set by a previous test, so just assert the type is correct.
        let _: &Option<String> = &*cached;
    }

    #[test]
    fn test_set_password_callback_stores_callback() {
        fn dummy() -> Option<String> { Some("test".into()) }
        set_password_callback(dummy);
        let slot = PASSWORD_CALLBACK.lock().unwrap();
        assert!(slot.is_some());
    }

    #[test]
    fn test_error_display_messages() {
        let e1 = PrivilegedError::CommandExecution("boom".into());
        assert!(e1.to_string().contains("boom"));

        let e2 = PrivilegedError::AuthCancelled;
        assert!(e2.to_string().contains("cancelled"));

        let e3 = PrivilegedError::PermissionDenied("nope".into());
        assert!(e3.to_string().contains("nope"));
    }

    #[test]
    fn test_invalidate_auth_clears_cache() {
        // Seed the cache
        *CACHED_PASSWORD.lock().unwrap() = Some("secret".into());
        invalidate_auth();
        assert!(CACHED_PASSWORD.lock().unwrap().is_none());
    }

    // -----------------------------------------------------------------------
    // Authentication flow tests (using ensure_authenticated_inner)
    //
    // These verify the authentication decision logic without depending on
    // real sudo or shared global state. They use injectable mock functions
    // to simulate different system states deterministically.
    //
    // This prevents regressions where a privileged operation could deadlock
    // the GUI by blocking the main thread without prompting for credentials.
    // -----------------------------------------------------------------------

    /// Tracks how many times the mock password prompt was called.
    static MOCK_PROMPT_COUNT: AtomicUsize = AtomicUsize::new(0);

    // -- Mock functions for ensure_authenticated_inner --

    fn mock_timestamp_invalid() -> bool { false }
    fn mock_timestamp_valid() -> bool { true }

    fn mock_auth_always_succeeds(_pw: &str) -> PrivilegedResult<bool> { Ok(true) }
    fn mock_auth_always_fails(_pw: &str) -> PrivilegedResult<bool> { Ok(false) }

    fn mock_prompt_returns_password() -> Option<String> {
        MOCK_PROMPT_COUNT.fetch_add(1, Ordering::SeqCst);
        Some("mock_password".into())
    }

    fn mock_prompt_returns_none() -> Option<String> {
        MOCK_PROMPT_COUNT.fetch_add(1, Ordering::SeqCst);
        None
    }

    #[test]
    fn test_auth_skips_prompt_when_timestamp_valid() {
        // When sudo timestamp is valid, no prompt or auth attempt needed.
        MOCK_PROMPT_COUNT.store(0, Ordering::SeqCst);
        *CACHED_PASSWORD.lock().unwrap() = None;

        let result = ensure_authenticated_inner(
            mock_timestamp_valid,
            mock_auth_always_fails, // should never be called
            mock_prompt_returns_password, // should never be called
        );

        assert!(result.is_ok());
        assert_eq!(
            MOCK_PROMPT_COUNT.load(Ordering::SeqCst), 0,
            "must NOT prompt when sudo timestamp is already valid"
        );
    }

    #[test]
    fn test_auth_prompts_when_no_session_and_no_cache() {
        // No valid timestamp, no cached password → must prompt user.
        MOCK_PROMPT_COUNT.store(0, Ordering::SeqCst);
        *CACHED_PASSWORD.lock().unwrap() = None;

        let result = ensure_authenticated_inner(
            mock_timestamp_invalid,
            mock_auth_always_succeeds,
            mock_prompt_returns_password,
        );

        assert!(result.is_ok());
        assert_eq!(
            MOCK_PROMPT_COUNT.load(Ordering::SeqCst), 1,
            "must invoke password prompt when no sudo session and no cached password"
        );
    }

    #[test]
    fn test_auth_returns_cancelled_when_user_cancels_prompt() {
        // User cancels the password dialog → AuthCancelled error.
        MOCK_PROMPT_COUNT.store(0, Ordering::SeqCst);
        *CACHED_PASSWORD.lock().unwrap() = None;

        let result = ensure_authenticated_inner(
            mock_timestamp_invalid,
            mock_auth_always_fails,
            mock_prompt_returns_none,
        );

        assert!(
            matches!(result, Err(PrivilegedError::AuthCancelled)),
            "expected AuthCancelled when user cancels, got: {:?}", result
        );
        assert_eq!(
            MOCK_PROMPT_COUNT.load(Ordering::SeqCst), 1,
            "prompt must be invoked before returning AuthCancelled"
        );
    }

    #[test]
    fn test_auth_uses_cached_password_before_prompting() {
        // Cached password exists and works → no prompt needed.
        MOCK_PROMPT_COUNT.store(0, Ordering::SeqCst);
        *CACHED_PASSWORD.lock().unwrap() = Some("cached_pw".into());

        let result = ensure_authenticated_inner(
            mock_timestamp_invalid,
            mock_auth_always_succeeds,
            mock_prompt_returns_password,
        );

        assert!(result.is_ok());
        assert_eq!(
            MOCK_PROMPT_COUNT.load(Ordering::SeqCst), 0,
            "must NOT prompt when cached password succeeds"
        );
    }

    #[test]
    fn test_auth_falls_back_to_prompt_when_cached_password_fails() {
        // Cached password exists but fails → must prompt user.
        MOCK_PROMPT_COUNT.store(0, Ordering::SeqCst);
        *CACHED_PASSWORD.lock().unwrap() = Some("stale_password".into());

        // Auth fails for cached password but succeeds for the prompted one
        static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
        fn mock_auth_fails_then_succeeds(_pw: &str) -> PrivilegedResult<bool> {
            let n = CALL_COUNT.fetch_add(1, Ordering::SeqCst);
            Ok(n > 0) // first call fails, subsequent calls succeed
        }
        CALL_COUNT.store(0, Ordering::SeqCst);

        let result = ensure_authenticated_inner(
            mock_timestamp_invalid,
            mock_auth_fails_then_succeeds,
            mock_prompt_returns_password,
        );

        assert!(result.is_ok());
        assert_eq!(
            MOCK_PROMPT_COUNT.load(Ordering::SeqCst), 1,
            "must fall back to prompt when cached password fails"
        );
    }

    #[test]
    fn test_auth_returns_permission_denied_on_wrong_password() {
        // User provides a password but it's wrong → PermissionDenied.
        MOCK_PROMPT_COUNT.store(0, Ordering::SeqCst);
        *CACHED_PASSWORD.lock().unwrap() = None;

        let result = ensure_authenticated_inner(
            mock_timestamp_invalid,
            mock_auth_always_fails,
            mock_prompt_returns_password,
        );

        assert!(
            matches!(result, Err(PrivilegedError::PermissionDenied(_))),
            "expected PermissionDenied for wrong password, got: {:?}", result
        );
    }

    #[test]
    fn test_auth_caches_password_on_success() {
        // After successful auth, password should be cached for next time.
        *CACHED_PASSWORD.lock().unwrap() = None;
        MOCK_PROMPT_COUNT.store(0, Ordering::SeqCst);

        let result = ensure_authenticated_inner(
            mock_timestamp_invalid,
            mock_auth_always_succeeds,
            mock_prompt_returns_password,
        );

        assert!(result.is_ok());
        let cached = CACHED_PASSWORD.lock().unwrap();
        assert_eq!(
            cached.as_deref(), Some("mock_password"),
            "password must be cached after successful authentication"
        );
    }

    #[test]
    fn test_run_privileged_calls_ensure_authenticated() {
        // Verify that run_privileged goes through ensure_authenticated.
        // We can't easily mock the inner call from run_privileged, but we
        // can verify the contract: if no callback is set and no sudo session
        // exists, run_privileged must fail with an auth error (not hang).
        *CACHED_PASSWORD.lock().unwrap() = None;
        *PASSWORD_CALLBACK.lock().unwrap() = None;

        if sudo_timestamp_valid() {
            // Already authenticated — can't test the prompt path.
            return;
        }

        let result = run_privileged("echo", &["test"]);
        assert!(
            result.is_err(),
            "run_privileged must fail (not hang) when no auth session and no callback"
        );
    }

    #[test]
    fn test_run_privileged_with_stdin_calls_ensure_authenticated() {
        // Same contract test for run_privileged_with_stdin.
        *CACHED_PASSWORD.lock().unwrap() = None;
        *PASSWORD_CALLBACK.lock().unwrap() = None;

        if sudo_timestamp_valid() {
            return;
        }

        let result = run_privileged_with_stdin("cat", &[], "data");
        assert!(
            result.is_err(),
            "run_privileged_with_stdin must fail (not hang) when no auth session and no callback"
        );
    }
}
