use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use noxssh_core::error::SshError;
use noxssh_core::protocol::constants::*;
use noxssh_core::protocol::encoding::{
    push_ssh_string, push_u32, read_ssh_string_owned, read_u32_at,
};
use crate::server::forwarding::RemoteForwardManager;
use crate::server::sftp::SftpState;
use crate::server::AuthenticatedSession;
use noxssh_core::transport::TransportSession;

#[derive(Clone, Copy, Debug)]
pub struct PtySize {
    pub cols: u32,
    pub rows: u32,
}

pub trait ChannelSession: Send {
    fn poll(
        &mut self,
        transport: &Arc<Mutex<TransportSession>>,
        channel: u32,
    ) -> Result<(), SshError>;
    fn is_done(&self) -> bool;
}

pub enum SessionBackend {
    Process(Child),
    Custom(Box<dyn ChannelSession>),
}

pub trait SessionHandler: Send + Sync {
    fn exec(&self, user: &str, command: &str) -> Result<SessionBackend, SshError>;
    fn shell(&self, user: &str, pty: Option<PtySize>) -> Result<SessionBackend, SshError>;
}

pub struct DefaultSessionHandler;

impl SessionHandler for DefaultSessionHandler {
    fn exec(&self, _user: &str, command: &str) -> Result<SessionBackend, SshError> {
        let shell = if cfg!(windows) { "cmd.exe" } else { "/bin/sh" };
        let arg = if cfg!(windows) { "/C" } else { "-c" };
        let child = Command::new(shell)
            .arg(arg)
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(SshError::Io)?;
        Ok(SessionBackend::Process(child))
    }

    fn shell(&self, _user: &str, _pty: Option<PtySize>) -> Result<SessionBackend, SshError> {
        let shell = if cfg!(windows) {
            std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string())
        } else {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
        };
        let child = Command::new(shell)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(SshError::Io)?;
        Ok(SessionBackend::Process(child))
    }
}

struct Channel {
    remote_id: u32,
    channel_type: String,
}

enum ActiveRelay {
    Session {
        channel: u32,
        backend: SessionBackend,
    },
    Tcp {
        channel: u32,
        tcp: TcpStream,
    },
    Sftp {
        channel: u32,
        state: SftpState,
    },
}

pub fn run_connection_loop<H: SessionHandler>(
    session: AuthenticatedSession,
    handler: &H,
    _forwards: Arc<Mutex<RemoteForwardManager>>,
) -> Result<(), SshError> {
    let transport = session.transport;
    let username = session.username;
    let mut channels: Vec<Channel> = Vec::new();
    let mut relays: Vec<ActiveRelay> = Vec::new();
    let mut next_channel_id = 0u32;

    loop {
        for relay in &mut relays {
            poll_relay(&transport, relay)?;
        }
        relays.retain_mut(|r| !relay_done(r));

        let payload = match transport.lock().unwrap().recv_packet_with_timeout(100)? {
            Some(p) => p,
            None => continue,
        };
        if payload.is_empty() {
            continue;
        }
        match payload[0] {
            MSG_SERVICE_REQUEST => {
                let mut off = 1usize;
                let service = read_ssh_string_owned(&payload, &mut off)?;
                if service == SSH_SERVICE_CONNECTION.as_bytes() {
                    let mut rsp = Vec::new();
                    rsp.push(MSG_SERVICE_ACCEPT);
                    push_ssh_string(&mut rsp, SSH_SERVICE_CONNECTION.as_bytes());
                    transport.lock().unwrap().send_packet(&rsp)?;
                }
            }
            MSG_CHANNEL_OPEN => {
                let mut off = 1usize;
                let channel_type = read_ssh_string_owned(&payload, &mut off)?;
                let sender_channel = read_u32_at(&payload, &mut off)?;
                let initial_window = read_u32_at(&payload, &mut off)?;
                let max_packet = read_u32_at(&payload, &mut off)?;
                let type_str = String::from_utf8_lossy(&channel_type).to_string();

                if type_str == "session" {
                    let local_id = next_channel_id;
                    next_channel_id = next_channel_id.wrapping_add(1);
                    send_channel_open_confirmation(
                        &transport,
                        sender_channel,
                        local_id,
                        NETNOX_SSH_CHANNEL_WINDOW_SIZE,
                        NETNOX_SSH_CHANNEL_MAX_PACKET_SIZE,
                    )?;
                    channels.push(Channel {
                        remote_id: sender_channel,
                        channel_type: type_str,
                    });
                } else if type_str == "direct-tcpip" {
                    let dest_host = read_ssh_string_owned(&payload, &mut off)?;
                    let dest_port = read_u32_at(&payload, &mut off)?;
                    let _origin_host = read_ssh_string_owned(&payload, &mut off)?;
                    let _origin_port = read_u32_at(&payload, &mut off)?;
                    let local_id = next_channel_id;
                    next_channel_id = next_channel_id.wrapping_add(1);
                    send_channel_open_confirmation(
                        &transport,
                        sender_channel,
                        local_id,
                        initial_window,
                        max_packet,
                    )?;
                    let host = String::from_utf8_lossy(&dest_host).to_string();
                    match TcpStream::connect(format!("{host}:{dest_port}")) {
                        Ok(tcp) => relays.push(ActiveRelay::Tcp {
                            channel: sender_channel,
                            tcp,
                        }),
                        Err(_) => send_channel_close(&transport, sender_channel)?,
                    }
                } else {
                    send_channel_open_failure(&transport, sender_channel)?;
                }
            }
            MSG_CHANNEL_REQUEST => {
                let mut off = 1usize;
                let recipient = read_u32_at(&payload, &mut off)?;
                let request = read_ssh_string_owned(&payload, &mut off)?;
                let want_reply = payload.get(off).copied().unwrap_or(0) != 0;
                off += 1;
                let req_str = String::from_utf8_lossy(&request);

                if channels.iter().any(|c| c.remote_id == recipient) {
                    if req_str == "exec" {
                        let command = read_ssh_string_owned(&payload, &mut off)?;
                        let cmd_str = String::from_utf8_lossy(&command).to_string();
                        if want_reply {
                            send_channel_success(&transport, recipient)?;
                        }
                        let backend = handler.exec(&username, &cmd_str)?;
                        relays.push(ActiveRelay::Session {
                            channel: recipient,
                            backend,
                        });
                    } else if req_str == "pty-req" {
                        if want_reply {
                            send_channel_success(&transport, recipient)?;
                        }
                    } else if req_str == "shell" {
                        if want_reply {
                            send_channel_success(&transport, recipient)?;
                        }
                        let backend = handler.shell(&username, None)?;
                        relays.push(ActiveRelay::Session {
                            channel: recipient,
                            backend,
                        });
                    } else if req_str == "subsystem" {
                        let subsystem = read_ssh_string_owned(&payload, &mut off)?;
                        let sub_str = String::from_utf8_lossy(&subsystem);
                        if want_reply {
                            send_channel_success(&transport, recipient)?;
                        }
                        if sub_str == "sftp" {
                            relays.push(ActiveRelay::Sftp {
                                channel: recipient,
                                state: SftpState::new(),
                            });
                        }
                    } else if want_reply {
                        send_channel_failure(&transport, recipient)?;
                    }
                } else if want_reply {
                    send_channel_failure(&transport, recipient)?;
                }
            }
            MSG_CHANNEL_EOF | MSG_CHANNEL_CLOSE => {
                let mut off = 1usize;
                let recipient = read_u32_at(&payload, &mut off)?;
                channels.retain(|c| c.remote_id != recipient);
                relays.retain(|r| relay_channel(r) != recipient);
            }
            MSG_GLOBAL_REQUEST => {
                let mut off = 1usize;
                let request = read_ssh_string_owned(&payload, &mut off)?;
                let want_reply = payload.get(off).copied().unwrap_or(0) != 0;
                off += 1;
                let req_str = String::from_utf8_lossy(&request);
                if req_str == "tcpip-forward" || req_str == "cancel-tcpip-forward" {
                    if want_reply {
                        transport.lock().unwrap().send_packet(&[MSG_REQUEST_SUCCESS])?;
                    }
                } else if want_reply {
                    transport.lock().unwrap().send_packet(&[MSG_REQUEST_FAILURE])?;
                }
            }
            MSG_IGNORE => {}
            _ => {}
        }
    }
}

fn relay_channel(r: &ActiveRelay) -> u32 {
    match r {
        ActiveRelay::Session { channel, .. } => *channel,
        ActiveRelay::Tcp { channel, .. } => *channel,
        ActiveRelay::Sftp { channel, .. } => *channel,
    }
}

fn relay_done(r: &mut ActiveRelay) -> bool {
    match r {
        ActiveRelay::Session { backend, .. } => match backend {
            SessionBackend::Process(child) => child.try_wait().ok().flatten().is_some(),
            SessionBackend::Custom(session) => session.is_done(),
        },
        ActiveRelay::Tcp { .. } => false,
        ActiveRelay::Sftp { .. } => false,
    }
}

fn poll_relay(transport: &Arc<Mutex<TransportSession>>, relay: &mut ActiveRelay) -> Result<(), SshError> {
    let mut buf = [0u8; NETNOX_SSH_MAX_DATA_LEN];
    match relay {
        ActiveRelay::Session { channel, backend } => match backend {
            SessionBackend::Process(child) => {
                if let Some(stdout) = child.stdout.as_mut() {
                    match stdout.read(&mut buf) {
                        Ok(0) => {}
                        Ok(n) => send_channel_data(transport, *channel, &buf[..n])?,
                        Err(_) => {}
                    }
                }
                if let Some(stderr) = child.stderr.as_mut() {
                    match stderr.read(&mut buf) {
                        Ok(0) => {}
                        Ok(n) => send_channel_extended_data(transport, *channel, &buf[..n])?,
                        Err(_) => {}
                    }
                }
                if let Some(stdin) = child.stdin.as_mut() {
                    if let Ok(Some(pkt)) = transport.lock().unwrap().recv_packet_with_timeout(1) {
                        if pkt.first() == Some(&MSG_CHANNEL_DATA) {
                            let mut off = 1usize;
                            let recipient = read_u32_at(&pkt, &mut off).ok();
                            if recipient == Some(*channel) {
                                if let Ok(data) = read_ssh_string_owned(&pkt, &mut off) {
                                    let _ = stdin.write_all(&data);
                                }
                            }
                        }
                    }
                }
            }
            SessionBackend::Custom(session) => {
                session.poll(transport, *channel)?;
            }
        },
        ActiveRelay::Tcp { channel, tcp } => {
            tcp.set_read_timeout(Some(std::time::Duration::from_millis(1)))
                .ok();
            match tcp.read(&mut buf) {
                Ok(0) => send_channel_close(transport, *channel)?,
                Ok(n) => send_channel_data(transport, *channel, &buf[..n])?,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => send_channel_close(transport, *channel)?,
            }
            if let Ok(Some(pkt)) = transport.lock().unwrap().recv_packet_with_timeout(1) {
                if pkt.first() == Some(&MSG_CHANNEL_DATA) {
                    let mut off = 1usize;
                    let recipient = read_u32_at(&pkt, &mut off).ok();
                    if recipient == Some(*channel) {
                        if let Ok(data) = read_ssh_string_owned(&pkt, &mut off) {
                            let _ = tcp.write_all(&data);
                        }
                    }
                }
            }
        }
        ActiveRelay::Sftp { channel, state } => {
            state.poll(transport, *channel)?;
        }
    }
    Ok(())
}

fn send_channel_open_confirmation(
    transport: &Arc<Mutex<TransportSession>>,
    recipient: u32,
    sender: u32,
    window: u32,
    max_packet: u32,
) -> Result<(), SshError> {
    let mut payload = Vec::new();
    payload.push(MSG_CHANNEL_OPEN_CONFIRMATION);
    push_u32(&mut payload, recipient);
    push_u32(&mut payload, sender);
    push_u32(&mut payload, window);
    push_u32(&mut payload, max_packet);
    transport.lock().unwrap().send_packet(&payload)
}

fn send_channel_open_failure(transport: &Arc<Mutex<TransportSession>>, recipient: u32) -> Result<(), SshError> {
    let mut payload = Vec::new();
    payload.push(MSG_CHANNEL_OPEN_FAILURE);
    push_u32(&mut payload, recipient);
    push_u32(&mut payload, 1);
    push_ssh_string(&mut payload, b"open failed");
    push_ssh_string(&mut payload, b"en");
    transport.lock().unwrap().send_packet(&payload)
}

fn send_channel_success(transport: &Arc<Mutex<TransportSession>>, recipient: u32) -> Result<(), SshError> {
    let mut payload = Vec::new();
    payload.push(MSG_CHANNEL_SUCCESS);
    push_u32(&mut payload, recipient);
    transport.lock().unwrap().send_packet(&payload)
}

fn send_channel_failure(transport: &Arc<Mutex<TransportSession>>, recipient: u32) -> Result<(), SshError> {
    let mut payload = Vec::new();
    payload.push(MSG_CHANNEL_FAILURE);
    push_u32(&mut payload, recipient);
    transport.lock().unwrap().send_packet(&payload)
}

pub fn send_channel_data(
    transport: &Arc<Mutex<TransportSession>>,
    channel: u32,
    data: &[u8],
) -> Result<(), SshError> {
    let mut payload = Vec::with_capacity(16 + data.len());
    payload.push(MSG_CHANNEL_DATA);
    push_u32(&mut payload, channel);
    push_ssh_string(&mut payload, data);
    transport.lock().unwrap().send_packet(&payload)
}

pub fn send_channel_extended_data(
    transport: &Arc<Mutex<TransportSession>>,
    channel: u32,
    data: &[u8],
) -> Result<(), SshError> {
    let mut payload = Vec::with_capacity(20 + data.len());
    payload.push(MSG_CHANNEL_EXTENDED_DATA);
    push_u32(&mut payload, channel);
    push_u32(&mut payload, 1);
    push_ssh_string(&mut payload, data);
    transport.lock().unwrap().send_packet(&payload)
}

fn send_channel_close(transport: &Arc<Mutex<TransportSession>>, channel: u32) -> Result<(), SshError> {
    let mut payload = Vec::new();
    payload.push(MSG_CHANNEL_CLOSE);
    push_u32(&mut payload, channel);
    transport.lock().unwrap().send_packet(&payload)
}
