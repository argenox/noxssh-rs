//! Embedded interactive shell for noxssh server.

pub mod shell;

pub use shell::{
    parse_command_line, CommandContext, CommandRegistry, CommandShellHandler, EmbeddedSession,
    RegisteredCommand,
};
