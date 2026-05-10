use super::known_hosts::HostKeyCheckingMode;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default)]
pub struct SshHostConfig {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<PathBuf>,
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
    pub strict_host_key_checking: Option<HostKeyCheckingMode>,
    pub user_known_hosts_file: Option<PathBuf>,
    pub server_alive_interval: Option<u64>,
    pub batch_mode: Option<bool>,
    pub preferred_authentications: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct ConfigBlock {
    patterns: Vec<String>,
    config: SshHostConfig,
}

pub fn default_ssh_config_path() -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home).join(".ssh").join("config");
    }
    if let Ok(profile) = env::var("USERPROFILE") {
        return PathBuf::from(profile).join(".ssh").join("config");
    }
    PathBuf::from(".").join("config")
}

pub fn load_host_config(path: &Path, host: &str) -> Option<SshHostConfig> {
    let content = std::fs::read_to_string(path).ok()?;
    let blocks = parse_config_blocks(&content);
    let mut merged = SshHostConfig::default();
    let mut any = false;
    for block in blocks {
        if !block.patterns.iter().any(|pat| host_pattern_matches(pat, host)) {
            continue;
        }
        any = true;
        merge_host_config(&mut merged, block.config);
    }
    if any { Some(merged) } else { None }
}

fn parse_config_blocks(content: &str) -> Vec<ConfigBlock> {
    let mut blocks = Vec::new();
    let mut current = ConfigBlock::default();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let key = match parts.next() {
            Some(v) => v.trim(),
            None => continue,
        };
        let value = match parts.next() {
            Some(v) => v.trim(),
            None => continue,
        };
        if key.eq_ignore_ascii_case("Host") {
            if !current.patterns.is_empty() || has_any_field(&current.config) {
                blocks.push(current);
            }
            current = ConfigBlock::default();
            current.patterns = value
                .split_whitespace()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect();
            continue;
        }
        apply_config_kv(&mut current.config, key, value);
    }
    if !current.patterns.is_empty() || has_any_field(&current.config) {
        blocks.push(current);
    }
    blocks
}

fn apply_config_kv(config: &mut SshHostConfig, key: &str, value: &str) {
    if key.eq_ignore_ascii_case("User") {
        config.user = Some(value.to_string());
    } else if key.eq_ignore_ascii_case("Port") {
        if let Ok(v) = value.parse::<u16>() {
            config.port = Some(v);
        }
    } else if key.eq_ignore_ascii_case("IdentityFile") {
        config.identity_files.push(PathBuf::from(value));
    } else if key.eq_ignore_ascii_case("ProxyJump") {
        config.proxy_jump = Some(value.to_string());
    } else if key.eq_ignore_ascii_case("ProxyCommand") {
        config.proxy_command = Some(value.to_string());
    } else if key.eq_ignore_ascii_case("StrictHostKeyChecking") {
        config.strict_host_key_checking = HostKeyCheckingMode::parse(&value.to_ascii_lowercase());
    } else if key.eq_ignore_ascii_case("UserKnownHostsFile") {
        config.user_known_hosts_file = Some(PathBuf::from(value));
    } else if key.eq_ignore_ascii_case("ServerAliveInterval") {
        if let Ok(v) = value.parse::<u64>() {
            config.server_alive_interval = Some(v);
        }
    } else if key.eq_ignore_ascii_case("BatchMode") {
        config.batch_mode = Some(value.eq_ignore_ascii_case("yes") || value == "1");
    } else if key.eq_ignore_ascii_case("PreferredAuthentications") {
        config.preferred_authentications = value
            .split(',')
            .map(str::trim)
            .map(str::to_string)
            .filter(|v| !v.is_empty())
            .collect();
    }
}

fn has_any_field(config: &SshHostConfig) -> bool {
    config.user.is_some()
        || config.port.is_some()
        || !config.identity_files.is_empty()
        || config.proxy_jump.is_some()
        || config.proxy_command.is_some()
        || config.strict_host_key_checking.is_some()
        || config.user_known_hosts_file.is_some()
        || config.server_alive_interval.is_some()
        || config.batch_mode.is_some()
        || !config.preferred_authentications.is_empty()
}

fn merge_host_config(dst: &mut SshHostConfig, src: SshHostConfig) {
    if dst.user.is_none() {
        dst.user = src.user;
    }
    if dst.port.is_none() {
        dst.port = src.port;
    }
    if dst.identity_files.is_empty() && !src.identity_files.is_empty() {
        dst.identity_files = src.identity_files;
    }
    if dst.proxy_jump.is_none() {
        dst.proxy_jump = src.proxy_jump;
    }
    if dst.proxy_command.is_none() {
        dst.proxy_command = src.proxy_command;
    }
    if dst.strict_host_key_checking.is_none() {
        dst.strict_host_key_checking = src.strict_host_key_checking;
    }
    if dst.user_known_hosts_file.is_none() {
        dst.user_known_hosts_file = src.user_known_hosts_file;
    }
    if dst.server_alive_interval.is_none() {
        dst.server_alive_interval = src.server_alive_interval;
    }
    if dst.batch_mode.is_none() {
        dst.batch_mode = src.batch_mode;
    }
    if dst.preferred_authentications.is_empty() && !src.preferred_authentications.is_empty() {
        dst.preferred_authentications = src.preferred_authentications;
    }
}

fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') && !pattern.contains('?') {
        return pattern.eq_ignore_ascii_case(host);
    }
    wildcard_match(pattern, host)
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let p = pattern.as_bytes();
    let v = value.as_bytes();
    let (mut pi, mut vi, mut star_idx, mut match_idx) = (0usize, 0usize, None::<usize>, 0usize);
    while vi < v.len() {
        if pi < p.len() && (p[pi] == v[vi] || p[pi] == b'?') {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_idx = Some(pi);
            pi += 1;
            match_idx = vi;
        } else if let Some(star) = star_idx {
            pi = star + 1;
            match_idx += 1;
            vi = match_idx;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_host_matching_works() {
        assert!(host_pattern_matches("*", "example.com"));
        assert!(host_pattern_matches("*.example.com", "dev.example.com"));
        assert!(host_pattern_matches("dev-??.example.com", "dev-01.example.com"));
        assert!(!host_pattern_matches("prod-??.example.com", "dev-01.example.com"));
    }

    #[test]
    fn parse_and_merge_config_blocks() {
        let content = r#"
Host *
  User defaultuser
  Port 2222
Host dev.example.com
  User devuser
  IdentityFile ~/.ssh/dev_id
  StrictHostKeyChecking accept-new
"#;
        let blocks = parse_config_blocks(content);
        assert_eq!(blocks.len(), 2);
        let cfg = load_host_config_from_content(content, "dev.example.com").unwrap();
        assert_eq!(cfg.user.as_deref(), Some("defaultuser"));
        assert_eq!(cfg.port, Some(2222));
        assert_eq!(cfg.identity_files.len(), 1);
        assert_eq!(cfg.strict_host_key_checking, Some(HostKeyCheckingMode::AcceptNew));
    }

    fn load_host_config_from_content(content: &str, host: &str) -> Option<SshHostConfig> {
        let blocks = parse_config_blocks(content);
        let mut merged = SshHostConfig::default();
        let mut any = false;
        for block in blocks {
            if !block.patterns.iter().any(|pat| host_pattern_matches(pat, host)) {
                continue;
            }
            any = true;
            merge_host_config(&mut merged, block.config);
        }
        if any { Some(merged) } else { None }
    }
}
