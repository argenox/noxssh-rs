pub mod channels;
pub mod forwarding;
pub mod sftp;
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use noxssh_core::error::SshError;
use noxssh_core::keys::{parse_authorized_key, verify_publickey_signature, HostKey};
use noxssh_core::kex::server_exchange_kexinit;
use noxssh_core::protocol::constants::*;
use noxssh_core::protocol::encoding::{push_ssh_string, read_ssh_string_owned};
use noxssh_core::protocol::ssh_debug;
use noxssh_core::transport::{Role, TransportSession};

pub use channels::{
    ChannelSession, DefaultSessionHandler, PtySize, SessionBackend, SessionHandler,
};
pub use forwarding::RemoteForwardManager;

#[derive(Clone)]
pub struct ServerConfig {
    pub server_ident: String,
    pub host_keys: Vec<HostKey>,
    pub banner: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server_ident: NETNOX_SSH_DEFAULT_SERVER_IDENT.to_string(),
            host_keys: Vec::new(),
            banner: None,
        }
    }
}

pub trait Authenticator: Send + Sync {
    fn auth_password(&self, user: &str, password: &str) -> bool;
    fn auth_publickey(
        &self,
        user: &str,
        algorithm: &str,
        pub_blob: &[u8],
        signature: &[u8],
        session_id: &[u8],
        signed_payload: &[u8],
    ) -> bool;
    fn allows_publickey(&self, pub_blob: &[u8]) -> bool;
}

pub struct SimpleAuthenticator {
    pub users: HashMap<String, String>,
    pub authorized_keys: Vec<(String, Vec<u8>)>,
}

impl SimpleAuthenticator {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            authorized_keys: Vec::new(),
        }
    }

    pub fn add_user(&mut self, user: impl Into<String>, password: impl Into<String>) {
        self.users.insert(user.into(), password.into());
    }

    pub fn load_authorized_keys(&mut self, path: &PathBuf) -> Result<(), SshError> {
        let content = std::fs::read_to_string(path).map_err(SshError::Io)?;
        for line in content.lines() {
            if let Some((alg, blob)) = parse_authorized_key(line) {
                self.authorized_keys.push((alg, blob));
            }
        }
        Ok(())
    }
}

impl Default for SimpleAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator for SimpleAuthenticator {
    fn auth_password(&self, user: &str, password: &str) -> bool {
        self.users.get(user).map(|p| p == password).unwrap_or(false)
    }

    fn allows_publickey(&self, pub_blob: &[u8]) -> bool {
        self.authorized_keys.iter().any(|(_, blob)| blob == pub_blob)
    }

    fn auth_publickey(
        &self,
        _user: &str,
        algorithm: &str,
        pub_blob: &[u8],
        signature: &[u8],
        session_id: &[u8],
        signed_payload: &[u8],
    ) -> bool {
        if !self.allows_publickey(pub_blob) {
            return false;
        }
        verify_publickey_signature(algorithm, pub_blob, session_id, signed_payload, signature)
            .unwrap_or(false)
    }
}

pub struct AuthenticatedSession {
    pub transport: Arc<Mutex<TransportSession>>,
    pub username: String,
    pub client_ident: String,
    pub server_ident: String,
}

pub struct SshServer {
    listener: TcpListener,
    config: ServerConfig,
}

impl SshServer {
    pub fn bind(addr: &str, mut config: ServerConfig) -> Result<Self, SshError> {
        if config.host_keys.is_empty() {
            config.host_keys.push(HostKey::generate_ed25519()?);
        }
        let listener = TcpListener::bind(addr).map_err(SshError::Io)?;
        Ok(Self { listener, config })
    }

    pub fn accept(&self) -> Result<(TcpStream, ServerConfig), SshError> {
        let (stream, _) = self.listener.accept().map_err(SshError::Io)?;
        stream.set_nodelay(true).map_err(SshError::Io)?;
        Ok((stream, self.config.clone()))
    }

    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    pub fn listener(&self) -> &TcpListener {
        &self.listener
    }
}

pub fn serve_connections<H: SessionHandler + 'static>(
    listener: TcpListener,
    config: ServerConfig,
    auth: Arc<dyn Authenticator>,
    handler: Arc<H>,
    forwards: Arc<Mutex<RemoteForwardManager>>,
) -> Result<(), SshError> {
    for stream in listener.incoming() {
        let stream = stream.map_err(SshError::Io)?;
        let _ = stream.set_nodelay(true);
        let cfg = config.clone();
        let auth = auth.clone();
        let handler = handler.clone();
        let forwards = forwards.clone();
        thread::spawn(move || {
            if let Err(err) = handle_connection(stream, cfg, auth, handler, forwards) {
                ssh_debug(1, format_args!("connection error: {err}"));
            }
        });
    }
    Ok(())
}

pub fn handle_connection<H: SessionHandler + 'static>(
    stream: TcpStream,
    config: ServerConfig,
    auth: Arc<dyn Authenticator>,
    handler: Arc<H>,
    forwards: Arc<Mutex<RemoteForwardManager>>,
) -> Result<(), SshError> {
    let host_key = config
        .host_keys
        .first()
        .cloned()
        .ok_or(SshError::Failed("server host key missing"))?;
    let mut transport = TransportSession::new(stream, Role::Server);
    let server_ident = config.server_ident.clone();
    let client_ident = transport.exchange_ident(&server_ident, true)?;
    server_exchange_kexinit(&mut transport, &client_ident, &server_ident, &host_key)?;

    let transport = Arc::new(Mutex::new(transport));
    let username = run_auth_loop(transport.clone(), auth.as_ref())?;
    let session = AuthenticatedSession {
        transport,
        username,
        client_ident,
        server_ident,
    };
    channels::run_connection_loop(session, handler.as_ref(), forwards)
}

fn run_auth_loop(transport: Arc<Mutex<TransportSession>>, auth: &dyn Authenticator) -> Result<String, SshError> {
    loop {
        let payload = transport.lock().unwrap().recv_packet()?;
        if payload.is_empty() {
            continue;
        }
        match payload[0] {
            MSG_SERVICE_REQUEST => {
                let mut off = 1usize;
                let service = read_ssh_string_owned(&payload, &mut off)?;
                if service == SSH_SERVICE_USERAUTH.as_bytes() {
                    let mut rsp = Vec::new();
                    rsp.push(MSG_SERVICE_ACCEPT);
                    push_ssh_string(&mut rsp, SSH_SERVICE_USERAUTH.as_bytes());
                    transport.lock().unwrap().send_packet(&rsp)?;
                } else if service == SSH_SERVICE_CONNECTION.as_bytes() {
                    let mut rsp = Vec::new();
                    rsp.push(MSG_SERVICE_ACCEPT);
                    push_ssh_string(&mut rsp, SSH_SERVICE_CONNECTION.as_bytes());
                    transport.lock().unwrap().send_packet(&rsp)?;
                    return Err(SshError::Failed("connection service before authentication"));
                }
            }
            MSG_USERAUTH_REQUEST => {
                let mut off = 1usize;
                let username = read_ssh_string_owned(&payload, &mut off)?;
                let _service = read_ssh_string_owned(&payload, &mut off)?;
                let method = read_ssh_string_owned(&payload, &mut off)?;
                let username_str = String::from_utf8_lossy(&username).to_string();

                if method == b"password" {
                    off += 1;
                    let password = read_ssh_string_owned(&payload, &mut off)?;
                    let password_str = String::from_utf8_lossy(&password);
                    if auth.auth_password(&username_str, &password_str) {
                        transport.lock().unwrap().send_packet(&[MSG_USERAUTH_SUCCESS])?;
                        return finish_auth(transport, username_str);
                    } else {
                        send_auth_failure(&transport)?;
                    }
                } else if method == b"publickey" {
                    let has_sig = payload.get(off).copied().unwrap_or(0) != 0;
                    off += 1;
                    let algorithm = read_ssh_string_owned(&payload, &mut off)?;
                    let pub_blob = read_ssh_string_owned(&payload, &mut off)?;
                    let algorithm_str = String::from_utf8_lossy(&algorithm);

                    if !has_sig {
                        if auth.allows_publickey(&pub_blob) {
                            let mut rsp = Vec::new();
                            rsp.push(MSG_USERAUTH_PK_OK);
                            push_ssh_string(&mut rsp, &algorithm);
                            push_ssh_string(&mut rsp, &pub_blob);
                            transport.lock().unwrap().send_packet(&rsp)?;
                        } else {
                            send_auth_failure(&transport)?;
                        }
                    } else {
                        let signature = read_ssh_string_owned(&payload, &mut off)?;
                        if auth.auth_publickey(
                            &username_str,
                            &algorithm_str,
                            &pub_blob,
                            &signature,
                            transport.lock().unwrap().session_id(),
                            &payload,
                        ) {
                            transport.lock().unwrap().send_packet(&[MSG_USERAUTH_SUCCESS])?;
                            return finish_auth(transport, username_str);
                        } else {
                            send_auth_failure(&transport)?;
                        }
                    }
                } else {
                    send_auth_failure(&transport)?;
                }
            }
            MSG_IGNORE => {}
            _ => {}
        }
    }
}

fn finish_auth(transport: Arc<Mutex<TransportSession>>, username: String) -> Result<String, SshError> {
    loop {
        let payload = transport.lock().unwrap().recv_packet()?;
        if payload.is_empty() {
            continue;
        }
        if payload[0] == MSG_SERVICE_REQUEST {
            let mut off = 1usize;
            let service = read_ssh_string_owned(&payload, &mut off)?;
            if service == SSH_SERVICE_CONNECTION.as_bytes() {
                let mut rsp = Vec::new();
                rsp.push(MSG_SERVICE_ACCEPT);
                push_ssh_string(&mut rsp, SSH_SERVICE_CONNECTION.as_bytes());
                transport.lock().unwrap().send_packet(&rsp)?;
                return Ok(username);
            }
        }
    }
}

fn send_auth_failure(transport: &Arc<Mutex<TransportSession>>) -> Result<(), SshError> {
    let mut rsp = Vec::new();
    rsp.push(MSG_USERAUTH_FAILURE);
    push_ssh_string(&mut rsp, b"publickey,password");
    rsp.push(0);
    transport.lock().unwrap().send_packet(&rsp)
}
