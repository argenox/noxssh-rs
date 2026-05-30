use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let lock_path = manifest_dir.join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.to_string_lossy());

    let noxtls_version =
        read_locked_dep_version(&lock_path, "noxtls-crypto").unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=NOXTLS_VERSION={noxtls_version}");
}

fn read_locked_dep_version(lock_path: &PathBuf, dep_name: &str) -> Option<String> {
    let content = fs::read_to_string(lock_path).ok()?;
    let mut in_package = false;
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if in_package && current_name.as_deref() == Some(dep_name) {
                return current_version;
            }
            in_package = true;
            current_name = None;
            current_version = None;
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(value) = parse_toml_string_field(trimmed, "name") {
            current_name = Some(value);
            continue;
        }
        if let Some(value) = parse_toml_string_field(trimmed, "version") {
            current_version = Some(value);
        }
    }

    if in_package && current_name.as_deref() == Some(dep_name) {
        return current_version;
    }
    None
}

fn parse_toml_string_field(line: &str, key: &str) -> Option<String> {
    let (lhs, rhs) = line.split_once('=')?;
    if lhs.trim() != key {
        return None;
    }
    Some(rhs.trim().trim_matches('"').to_string())
}
