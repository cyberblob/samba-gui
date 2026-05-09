use std::fs;
use std::path::Path;

fn main() {
    let version_path = Path::new("VERSION");

    // Read current version from VERSION file
    let version = fs::read_to_string(version_path)
        .expect("Failed to read VERSION file")
        .trim()
        .to_string();

    if version.is_empty() {
        panic!("VERSION file is empty");
    }

    // Validate semver format
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        panic!("Version '{}' is not valid semver (expected x.y.z)", version);
    }
    parts[0].parse::<u32>().expect("Invalid major version");
    parts[1].parse::<u32>().expect("Invalid minor version");
    parts[2].parse::<u32>().expect("Invalid patch version");

    // Expose the version to the binary via env var
    println!("cargo:rustc-env=SAMBA_GUI_VERSION={}", version);

    // Re-run this build script when VERSION file changes.
    println!("cargo:rerun-if-changed=VERSION");
}
