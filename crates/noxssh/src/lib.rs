//! SSH-2 client and server facade.

pub use noxssh_client as client;
pub use noxssh_core as core;
pub use noxssh_server as server;
pub use noxssh_shell as shell;

pub use noxssh_client::{
    default_known_hosts_path, default_ssh_config_path, load_host_config, verify_or_add_host_key,
    HostKeyCheckingMode, KnownHostsPolicy, SshClient, SshHostConfig,
};
pub use noxssh_core::{auth, error, kex, keys, protocol, transport, HostKey, SshError};
pub use noxssh_server::{
    handle_connection, serve_connections, AuthenticatedSession, Authenticator, ChannelSession,
    DefaultSessionHandler, PtySize, RemoteForwardManager, ServerConfig, SessionBackend,
    SessionHandler, SimpleAuthenticator, SshServer,
};
pub use noxssh_shell::{
    parse_command_line, CommandContext, CommandRegistry, CommandShellHandler, EmbeddedSession,
    RegisteredCommand,
};
