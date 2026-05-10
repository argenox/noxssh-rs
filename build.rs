use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let noxtls_crypto_manifest = manifest_dir.join("noxtls/crates/noxtls-crypto/Cargo.toml");

    println!(
        "cargo:rerun-if-changed={}",
        noxtls_crypto_manifest.to_string_lossy()
    );

    let noxtls_version = read_package_version(&noxtls_crypto_manifest).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=NOXTLS_VERSION={noxtls_version}");
}

fn read_package_version(path: &PathBuf) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let mut in_package = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_package = trimmed == "[package]";
            continue;
        }
        if in_package && trimmed.starts_with("version") {
            let mut parts = trimmed.splitn(2, '=');
            let _ = parts.next()?;
            let value = parts.next()?.trim().trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    None
}
