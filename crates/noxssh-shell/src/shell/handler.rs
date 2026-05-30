use std::sync::Arc;

use noxssh_core::error::SshError;
use noxssh_server::{PtySize, SessionBackend, SessionHandler};
use super::{CommandRegistry, EmbeddedSession};

pub struct CommandShellHandler {
    registry: Arc<CommandRegistry>,
}

impl CommandShellHandler {
    pub fn new(registry: CommandRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
        }
    }

    pub fn from_arc(registry: Arc<CommandRegistry>) -> Self {
        Self { registry }
    }

    pub fn registry(&self) -> &Arc<CommandRegistry> {
        &self.registry
    }
}

impl SessionHandler for CommandShellHandler {
    fn exec(&self, user: &str, command: &str) -> Result<SessionBackend, SshError> {
        Ok(SessionBackend::Custom(Box::new(EmbeddedSession::exec(
            self.registry.clone(),
            user,
            command,
        ))))
    }

    fn shell(&self, user: &str, pty: Option<PtySize>) -> Result<SessionBackend, SshError> {
        Ok(SessionBackend::Custom(Box::new(EmbeddedSession::repl(
            self.registry.clone(),
            user,
            pty,
        ))))
    }
}
