use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKeyCheckingMode {
    /// Refuse unknown hosts without prompting (CI / locked-down use).
    Strict,
    /// Prompt on unknown host when stdin is a TTY; refuse on key mismatch (OpenSSH `ask`).
    Ask,
    /// Silently add new host keys; refuse if the key changed (OpenSSH `accept-new`).
    AcceptNew,
    Off,
}

impl Default for HostKeyCheckingMode {
    fn default() -> Self {
        Self::Ask
    }
}

impl HostKeyCheckingMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "strict" | "yes" => Some(Self::Strict),
            "ask" => Some(Self::Ask),
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

    // Unknown host: behavior depends on mode (OpenSSH-aligned).
    match policy.mode {
        HostKeyCheckingMode::Strict => {
            return Err(format!(
                "unknown host key for {hostname}; add it to {} or use -o StrictHostKeyChecking=ask|accept-new|off",
                policy.path.display()
            ));
        }
        HostKeyCheckingMode::AcceptNew => {
            append_known_host_line(hostname, key_type, key_data_b64, &policy.path)
                .map_err(|err| format!("failed to update known_hosts: {err}"))?;
        }
        HostKeyCheckingMode::Ask => {
            if policy.batch_mode || !io::stdin().is_terminal() {
                return Err(format!(
                    "unknown host key for {hostname}; stdin is not a terminal (use --strict-host-key-checking accept-new, or add the key to {})",
                    policy.path.display()
                ));
            }
            if !prompt_trust_new_host(hostname, key_type, key_data_b64)? {
                return Err("user rejected new host key".to_string());
            }
            append_known_host_line(hostname, key_type, key_data_b64, &policy.path)
                .map_err(|err| format!("failed to update known_hosts: {err}"))?;
        }
        HostKeyCheckingMode::Off => {}
    }

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
    println!("{key_type} key fingerprint is {key_data_b64}.");
    println!("This key is not known by any other names.");
    print!("Are you sure you want to continue connecting (yes/no)? ");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes_including_ask() {
        assert_eq!(HostKeyCheckingMode::parse("ask"), Some(HostKeyCheckingMode::Ask));
        assert_eq!(HostKeyCheckingMode::default(), HostKeyCheckingMode::Ask);
    }
}
