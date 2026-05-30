//! SSH-2 client library.

pub mod client;
pub mod config;
pub mod kex;
pub mod known_hosts;

pub use client::SshClient;
pub use config::{default_ssh_config_path, load_host_config, SshHostConfig};
pub use known_hosts::{
    default_known_hosts_path, verify_or_add_host_key, HostKeyCheckingMode, KnownHostsPolicy,
};
pub use noxssh_core::error::SshError;
pub use noxssh_core::keys::HostKey;
