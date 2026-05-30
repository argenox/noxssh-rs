use std::sync::{Arc, Mutex};

use noxssh_core::error::SshError;
use noxssh_core::protocol::constants::*;
use noxssh_core::protocol::encoding::{read_ssh_string_owned, read_u32_at};
use noxssh_server::{
    send_channel_data, send_channel_extended_data, ChannelSession, PtySize,
};
use super::{parse_command_line, CommandContext, CommandRegistry};
use noxssh_core::transport::TransportSession;

enum SessionMode {
    Exec {
        command: String,
        started: bool,
    },
    Repl {
        prompt_sent: bool,
    },
}

pub struct EmbeddedSession {
    registry: Arc<CommandRegistry>,
    user: String,
    mode: SessionMode,
    line_buf: Vec<u8>,
    stdout_pending: Vec<u8>,
    stderr_pending: Vec<u8>,
    done: bool,
    _pty: Option<PtySize>,
}

impl EmbeddedSession {
    pub fn exec(registry: Arc<CommandRegistry>, user: &str, command: &str) -> Self {
        Self {
            registry,
            user: user.to_string(),
            mode: SessionMode::Exec {
                command: command.to_string(),
                started: false,
            },
            line_buf: Vec::new(),
            stdout_pending: Vec::new(),
            stderr_pending: Vec::new(),
            done: false,
            _pty: None,
        }
    }

    pub fn repl(registry: Arc<CommandRegistry>, user: &str, pty: Option<PtySize>) -> Self {
        Self {
            registry,
            user: user.to_string(),
            mode: SessionMode::Repl { prompt_sent: false },
            line_buf: Vec::new(),
            stdout_pending: Vec::new(),
            stderr_pending: Vec::new(),
            done: false,
            _pty: pty,
        }
    }

    fn is_done(&self) -> bool {
        self.done && self.stdout_pending.is_empty() && self.stderr_pending.is_empty()
    }

    fn poll(
        &mut self,
        transport: &Arc<Mutex<TransportSession>>,
        channel: u32,
    ) -> Result<(), SshError> {
        self.flush_output(transport, channel)?;

        if self.done {
            return Ok(());
        }

        if let SessionMode::Exec { command, started } = &mut self.mode {
            if !*started {
                *started = true;
                let cmd = command.clone();
                self.run_command(&cmd)?;
                self.done = true;
                self.flush_output(transport, channel)?;
            }
            return Ok(());
        }

        if let SessionMode::Repl { prompt_sent } = &mut self.mode {
                if !*prompt_sent {
                    self.stdout_pending
                        .extend_from_slice(self.registry.prompt().as_bytes());
                    *prompt_sent = true;
                    self.flush_output(transport, channel)?;
                }
                if let Ok(Some(pkt)) = transport.lock().unwrap().recv_packet_with_timeout(1) {
                    if pkt.first() == Some(&MSG_CHANNEL_DATA) {
                        let mut off = 1usize;
                        let recipient = read_u32_at(&pkt, &mut off).ok();
                        if recipient == Some(channel) {
                            if let Ok(data) = read_ssh_string_owned(&pkt, &mut off) {
                                self.line_buf.extend_from_slice(&data);
                                while let Some(newline_pos) = self.line_buf.iter().position(|&b| b == b'\n')
                                {
                                    let line_bytes: Vec<u8> =
                                        self.line_buf.drain(..=newline_pos).collect();
                                    let line = String::from_utf8_lossy(&line_bytes);
                                    let args = parse_command_line(&line);
                                    if !args.is_empty() {
                                        let arg_refs: Vec<&str> =
                                            args.iter().map(String::as_str).collect();
                                        self.run_argv(&arg_refs)?;
                                    }
                                    self.stdout_pending
                                        .extend_from_slice(self.registry.prompt().as_bytes());
                                    self.flush_output(transport, channel)?;
                                }
                            }
                        }
                    } else if pkt.first() == Some(&MSG_CHANNEL_EOF)
                        || pkt.first() == Some(&MSG_CHANNEL_CLOSE)
                    {
                        self.done = true;
                    }
                }
        }
        Ok(())
    }

    fn run_command(&mut self, command: &str) -> Result<(), SshError> {
        let args = parse_command_line(command);
        if args.is_empty() {
            return Ok(());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run_argv(&arg_refs)
    }

    fn run_argv(&mut self, argv: &[&str]) -> Result<(), SshError> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut ctx = CommandContext::new(&self.user, &mut stdout, &mut stderr);
        let _exit_code = self.registry.dispatch(&mut ctx, argv)?;
        self.stdout_pending.extend_from_slice(&stdout);
        self.stderr_pending.extend_from_slice(&stderr);
        Ok(())
    }

    fn flush_output(
        &mut self,
        transport: &Arc<Mutex<TransportSession>>,
        channel: u32,
    ) -> Result<(), SshError> {
        if !self.stdout_pending.is_empty() {
            send_channel_data(transport, channel, &self.stdout_pending)?;
            self.stdout_pending.clear();
        }
        if !self.stderr_pending.is_empty() {
            send_channel_extended_data(transport, channel, &self.stderr_pending)?;
            self.stderr_pending.clear();
        }
        Ok(())
    }
}

impl ChannelSession for EmbeddedSession {
    fn poll(
        &mut self,
        transport: &Arc<Mutex<TransportSession>>,
        channel: u32,
    ) -> Result<(), SshError> {
        EmbeddedSession::poll(self, transport, channel)
    }

    fn is_done(&self) -> bool {
        EmbeddedSession::is_done(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_session_starts_not_done() {
        let registry = Arc::new(CommandRegistry::new());
        let session = EmbeddedSession::exec(registry, "user", "status");
        assert!(!session.is_done());
    }
}
