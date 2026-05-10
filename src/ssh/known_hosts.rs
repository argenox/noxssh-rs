use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKeyCheckingMode {
    Strict,
    AcceptNew,
    Off,
}

impl Default for HostKeyCheckingMode {
    fn default() -> Self {
        Self::Strict
    }
}

impl HostKeyCheckingMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "strict" | "yes" => Some(Self::Strict),
            "accept-new" => Some(Self::AcceptNew),
            "off" | "no" => Some(Self::Off),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct KnownHostsPolicy {
    pub mode: HostKeyCheckingMode,
    pub path: PathBuf,
    pub batch_mode: bool,
}

pub fn default_known_hosts_path() -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home).join(".ssh").join("known_hosts");
    }
    if let Ok(profile) = env::var("USERPROFILE") {
        return PathBuf::from(profile).join(".ssh").join("known_hosts");
    }
    PathBuf::from(".").join("known_hosts")
}

pub fn verify_or_add_host_key(
    hostname: &str,
    key_type: &str,
    key_data_b64: &str,
    policy: &KnownHostsPolicy,
) -> Result<(), String> {
    if policy.mode == HostKeyCheckingMode::Off {
        return Ok(());
    }

    let content = fs::read_to_string(&policy.path).unwrap_or_default();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut fields = trimmed.split_whitespace();
        let hosts = match fields.next() {
            Some(v) => v,
            None => continue,
        };
        let known_key_type = match fields.next() {
            Some(v) => v,
            None => continue,
        };
        let known_key_data = match fields.next() {
            Some(v) => v,
            None => continue,
        };

        if !host_field_matches(hosts, hostname) {
            continue;
        }

        if known_key_type == key_type && known_key_data == key_data_b64 {
            return Ok(());
        }

        return Err(format!(
            "host key mismatch for {hostname} (known_hosts has a different key)"
        ));
    }

    if policy.mode == HostKeyCheckingMode::Strict {
        return Err(format!(
            "unknown host key for {hostname}; add it to {} or use accept-new/off",
            policy.path.display()
        ));
    }

    if policy.batch_mode || !io::stdin().is_terminal() {
        return Err(format!(
            "unknown host key for {hostname} in non-interactive mode"
        ));
    }

    if !prompt_trust_new_host(hostname, key_type, key_data_b64)? {
        return Err("user rejected new host key".to_string());
    }

    append_known_host_line(hostname, key_type, key_data_b64, &policy.path)
        .map_err(|err| format!("failed to update known_hosts: {err}"))?;
    Ok(())
}

fn host_field_matches(hosts_field: &str, hostname: &str) -> bool {
    hosts_field.split(',').any(|entry| {
        let normalized = if entry.starts_with('[') {
            let suffix = format!("]:22");
            if entry.ends_with(&suffix) {
                entry.trim_start_matches('[').trim_end_matches(&suffix)
            } else {
                entry
            }
        } else {
            entry
        };
        normalized == hostname
    })
}

fn prompt_trust_new_host(hostname: &str, key_type: &str, key_data_b64: &str) -> Result<bool, String> {
    println!("The authenticity of host '{hostname}' can't be established.");
    println!("Server key type: {key_type}");
    println!("Server key (base64): {key_data_b64}");
    print!("Add this host to known_hosts? (yes/no): ");
    io::stdout()
        .flush()
        .map_err(|err| format!("stdout flush failed: {err}"))?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|err| format!("stdin read failed: {err}"))?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer == "yes" || answer == "y")
}

fn append_known_host_line(
    hostname: &str,
    key_type: &str,
    key_data_b64: &str,
    path: &PathBuf,
) -> Result<(), io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{hostname} {key_type} {key_data_b64}")?;
    Ok(())
}
