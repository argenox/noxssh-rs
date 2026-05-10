use noxtls_crypto::{
    hmac_sha256, rsassa_sha256_sign, sha256, x25519_generate_private_key_auto, AesCipher,
    Ed25519PrivateKey, HmacDrbgSha256,
    X25519PublicKey,
};
use noxtls_x509::{
    parse_pkcs8_private_key_info_der, private_key_pem_to_der_pkcs8, rsa_private_key_from_pem_pkcs1,
    rsa_private_key_from_pem_pkcs8,
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;
mod ssh;
use ssh::config::{default_ssh_config_path, load_host_config};
use ssh::known_hosts::{default_known_hosts_path, verify_or_add_host_key, HostKeyCheckingMode, KnownHostsPolicy};
use std::env;
use std::fmt::{Display, Formatter};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// App version comes from Cargo package metadata.
const NOXSSH_VERSION_STRING: &str = env!("CARGO_PKG_VERSION");
// NoxTLS version is injected by build.rs from the local noxtls crate manifest.
const NOXTLS_VERSION_STRING: &str = env!("NOXTLS_VERSION");
const NETNOX_SSH_DEFAULT_PORT: u16 = 22;
const NETNOX_SSH_DEFAULT_CLIENT_IDENT: &str = "SSH-2.0-noxssh_0.1";
const NOXSSH_DEFAULT_USER: &str = "user";

// Protocol and buffer limits mirrored from the C implementation.
const NETNOX_SSH_MAX_IDENT_LEN: usize = 255;
const NETNOX_SSH_MAX_BANNER_LINES: usize = 8;
const NETNOX_SSH_MAX_USERNAME_LEN: usize = 64;
const NETNOX_SSH_MAX_HOST_LEN: usize = 255;
const NETNOX_SSH_MAX_COMMAND_LEN: usize = 512;
const NETNOX_SSH_MAX_DATA_LEN: usize = 4096;
const NETNOX_SSH_MAX_PACKET_LEN: usize = 35000;
const NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN: usize = 32768;
const NETNOX_SSH_MAX_PASSWORD_LEN: usize = 128;
const NETNOX_SSH_CHANNEL_WINDOW_SIZE: u32 = 65536;
const NETNOX_SSH_CHANNEL_MAX_PACKET_SIZE: u32 = 32768;
const NETNOX_SSH_MIN_PADDING_LEN: usize = 4;
const NETNOX_SSH_KEXINIT_COOKIE_LEN: usize = 16;
const NETNOX_SSH_AES_BLOCK_LEN: usize = 16;
const NETNOX_SSH_MAC_LEN: usize = 32;

const NETNOX_SSH_KEX_ALG_LIST: &str = "curve25519-sha256,diffie-hellman-group14-sha256";
const NETNOX_SSH_HOST_KEY_ALG_LIST: &str = "ssh-ed25519,rsa-sha2-256,ssh-rsa";
const NETNOX_SSH_CIPHER_ALG_LIST: &str = "aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com";
const NETNOX_SSH_MAC_ALG_LIST: &str = "hmac-sha2-256,hmac-sha1";
const NETNOX_SSH_COMPRESSION_ALG_LIST: &str = "none";
const NETNOX_SSH_REQUIRED_KEX_ALG: &str = "curve25519-sha256";

// SSH message numbers (RFC 4250+).
const MSG_SERVICE_REQUEST: u8 = 5;
const MSG_SERVICE_ACCEPT: u8 = 6;
const MSG_IGNORE: u8 = 2;
const MSG_KEXINIT: u8 = 20;
const MSG_NEWKEYS: u8 = 21;
const MSG_KEX_ECDH_INIT: u8 = 30;
const MSG_KEX_ECDH_REPLY: u8 = 31;
const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_FAILURE: u8 = 51;
const MSG_USERAUTH_SUCCESS: u8 = 52;
const MSG_USERAUTH_PK_OK: u8 = 60;
const MSG_GLOBAL_REQUEST: u8 = 80;
const MSG_REQUEST_SUCCESS: u8 = 81;
const MSG_REQUEST_FAILURE: u8 = 82;
const MSG_CHANNEL_OPEN: u8 = 90;
const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
const MSG_CHANNEL_DATA: u8 = 94;
const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
const MSG_CHANNEL_EOF: u8 = 96;
const MSG_CHANNEL_CLOSE: u8 = 97;
const MSG_CHANNEL_REQUEST: u8 = 98;
const MSG_CHANNEL_SUCCESS: u8 = 99;
const MSG_CHANNEL_FAILURE: u8 = 100;

const SSH_SERVICE_USERAUTH: &str = "ssh-userauth";
const SSH_SERVICE_CONNECTION: &str = "ssh-connection";
const SSH_AUTH_METHOD_PASSWORD: &str = "password";
const SSH_CHANNEL_TYPE_SESSION: &str = "session";
const SSH_CHANNEL_REQ_EXEC: &str = "exec";
const SSH_CHANNEL_REQ_SHELL: &str = "shell";
const SSH_CHANNEL_REQ_SUBSYSTEM: &str = "subsystem";

const SFTP_MSG_INIT: u8 = 1;
const SFTP_MSG_VERSION: u8 = 2;
const SFTP_MSG_REALPATH: u8 = 16;
const SFTP_MSG_NAME: u8 = 104;
const SFTP_MSG_STATUS: u8 = 101;

#[derive(Debug)]
enum SshError {
    BadParam(&'static str),
    Failed(&'static str),
    FailedOwned(String),
    AuthRejected,
    Io(io::Error),
}

impl Display for SshError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadParam(msg) | Self::Failed(msg) => f.write_str(msg),
            Self::FailedOwned(msg) => f.write_str(msg),
            Self::AuthRejected => f.write_str("authentication rejected"),
            Self::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl From<io::Error> for SshError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

struct SshClient {
    stream: TcpStream,
    // Peer + user state.
    client_ident: String,
    server_ident: String,
    username: String,
    host: String,
    password: String,
    identity_files: Vec<PathBuf>,
    preferred_auth_methods: Vec<String>,
    // High-level state flags for validating call ordering.
    connected: bool,
    kexinit_exchanged: bool,
    userauth_service_ready: bool,
    authenticated: bool,
    channel_open: bool,
    key_exchange_complete: bool,
    local_channel_id: u32,
    next_local_channel_id: u32,
    remote_channel_id: u32,
    local_window_size: u32,
    remote_window_size: u32,
    remote_max_packet_size: u32,
    kexinit_client_payload: Vec<u8>,
    kexinit_server_payload: Vec<u8>,
    session_id: [u8; 32],
    session_id_len: usize,
    shared_secret_raw: [u8; 32],
    c2s_iv: [u8; 16],
    s2c_iv: [u8; 16],
    c2s_key: [u8; 16],
    s2c_key: [u8; 16],
    c2s_mac_key: [u8; 32],
    s2c_mac_key: [u8; 32],
    send_seq: u32,
    recv_seq: u32,
    // AES-CTR counters are maintained per direction and incremented per block.
    c2s_counter: [u8; 16],
    s2c_counter: [u8; 16],
    c2s_cipher: Option<AesCipher>,
    s2c_cipher: Option<AesCipher>,
    host_key_policy: KnownHostsPolicy,
    connect_started_at: Instant,
    last_keepalive_at: Instant,
    keepalive_interval: Duration,
    last_kex_at: Instant,
    sent_packet_count: u64,
    recv_packet_count: u64,
    sent_payload_bytes: u64,
    recv_payload_bytes: u64,
    rekey_packet_threshold: u64,
    rekey_byte_threshold: u64,
    rekey_interval: Duration,
    in_rekey: bool,
}

impl SshClient {
    fn new(stream: TcpStream, _port: u16) -> Self {
        let now = Instant::now();
        Self {
            stream,
            client_ident: NETNOX_SSH_DEFAULT_CLIENT_IDENT.to_string(),
            server_ident: String::new(),
            username: String::new(),
            host: String::new(),
            password: String::new(),
            identity_files: Vec::new(),
            preferred_auth_methods: vec!["publickey".to_string(), "password".to_string()],
            connected: false,
            kexinit_exchanged: false,
            userauth_service_ready: false,
            authenticated: false,
            channel_open: false,
            key_exchange_complete: false,
            local_channel_id: 0,
            next_local_channel_id: 0,
            remote_channel_id: 0,
            local_window_size: 0,
            remote_window_size: 0,
            remote_max_packet_size: 0,
            kexinit_client_payload: Vec::new(),
            kexinit_server_payload: Vec::new(),
            session_id: [0; 32],
            session_id_len: 0,
            shared_secret_raw: [0; 32],
            c2s_iv: [0; 16],
            s2c_iv: [0; 16],
            c2s_key: [0; 16],
            s2c_key: [0; 16],
            c2s_mac_key: [0; 32],
            s2c_mac_key: [0; 32],
            send_seq: 0,
            recv_seq: 0,
            c2s_counter: [0; 16],
            s2c_counter: [0; 16],
            c2s_cipher: None,
            s2c_cipher: None,
            host_key_policy: KnownHostsPolicy {
                mode: HostKeyCheckingMode::Strict,
                path: default_known_hosts_path(),
                batch_mode: false,
            },
            connect_started_at: now,
            last_keepalive_at: now,
            keepalive_interval: Duration::ZERO,
            last_kex_at: now,
            sent_packet_count: 0,
            recv_packet_count: 0,
            sent_payload_bytes: 0,
            recv_payload_bytes: 0,
            rekey_packet_threshold: 500_000,
            rekey_byte_threshold: 512 * 1024 * 1024,
            rekey_interval: Duration::from_secs(3600),
            in_rekey: false,
        }
    }

    fn set_target(&mut self, username: &str, host: &str) -> Result<(), SshError> {
        if username.is_empty() || host.is_empty() {
            return Err(SshError::BadParam("invalid target"));
        }
        if username.len() > NETNOX_SSH_MAX_USERNAME_LEN || host.len() > NETNOX_SSH_MAX_HOST_LEN {
            return Err(SshError::BadParam("target too long"));
        }
        self.username = username.to_string();
        self.host = host.to_string();
        Ok(())
    }

    fn set_password(&mut self, password: &str) -> Result<(), SshError> {
        if password.len() > NETNOX_SSH_MAX_PASSWORD_LEN {
            return Err(SshError::BadParam("password too long"));
        }
        self.password = password.to_string();
        Ok(())
    }

    fn set_host_key_policy(&mut self, mode: HostKeyCheckingMode, path: Option<PathBuf>, batch_mode: bool) {
        self.host_key_policy.mode = mode;
        if let Some(p) = path {
            self.host_key_policy.path = p;
        }
        self.host_key_policy.batch_mode = batch_mode;
    }

    fn set_transport_timers(&mut self, keepalive_interval: Duration, rekey_interval: Duration) {
        self.keepalive_interval = keepalive_interval;
        self.rekey_interval = rekey_interval;
    }

    fn set_identity_files(&mut self, identity_files: Vec<PathBuf>) {
        self.identity_files = identity_files;
    }

    fn set_preferred_auth_methods(&mut self, methods: Vec<String>) {
        if methods.is_empty() {
            return;
        }
        self.preferred_auth_methods = methods;
    }

    fn connect(&mut self) -> Result<(), SshError> {
        // SSH starts with plaintext identification exchange.
        let tx_ident = format!("{}\r\n", self.client_ident);
        self.stream.write_all(tx_ident.as_bytes())?;
        self.stream.flush()?;
        ssh_debug(1, format_args!("sent ident: {}", self.client_ident));

        for _ in 0..NETNOX_SSH_MAX_BANNER_LINES {
            let line = self.recv_line()?;
            ssh_debug(1, format_args!("recv line: {line}"));
            if line.starts_with("SSH-") {
                self.server_ident = line;
                self.connected = true;
                let now = Instant::now();
                self.connect_started_at = now;
                self.last_keepalive_at = now;
                self.last_kex_at = now;
                return self.exchange_kexinit();
            }
        }
        Err(SshError::Failed("no SSH identification line"))
    }

    fn server_ident(&self) -> Option<&str> {
        if self.server_ident.is_empty() {
            None
        } else {
            Some(&self.server_ident)
        }
    }

    fn authenticate(&mut self) -> Result<(), SshError> {
        if !(self.connected && self.kexinit_exchanged && self.key_exchange_complete) {
            return Err(SshError::BadParam("invalid state for authentication"));
        }
        if self.username.is_empty() {
            return Err(SshError::BadParam("username missing"));
        }
        // OpenSSH-style flow: request ssh-userauth service, then send password request.
        if !self.userauth_service_ready {
            self.negotiate_userauth_service()?;
        }
        let methods = self.preferred_auth_methods.clone();
        for method in methods {
            let ok = match method.as_str() {
                "publickey" => self.try_publickey_auth()?,
                "password" => self.try_password_auth()?,
                "keyboard-interactive" => self.try_keyboard_interactive_auth()?,
                _ => false,
            };
            if ok {
                self.authenticated = true;
                return Ok(());
            }
        }

        Err(SshError::AuthRejected)
    }

    fn open_session(&mut self) -> Result<(), SshError> {
        if !(self.connected
            && self.kexinit_exchanged
            && self.key_exchange_complete
            && self.authenticated)
        {
            return Err(SshError::BadParam("invalid state for open session"));
        }
        self.local_channel_id = self.next_local_channel_id;
        self.next_local_channel_id = self.next_local_channel_id.wrapping_add(1);
        self.local_window_size = NETNOX_SSH_CHANNEL_WINDOW_SIZE;
        self.send_channel_open_session()?;
        let payload =
            self.wait_for_message(MSG_CHANNEL_OPEN_CONFIRMATION, Some(MSG_CHANNEL_OPEN_FAILURE))?;
        if payload.is_empty() {
            return Err(SshError::Failed("empty channel open response"));
        }
        if payload[0] == MSG_CHANNEL_OPEN_FAILURE {
            return Err(SshError::Failed("channel open rejected"));
        }
        if payload[0] != MSG_CHANNEL_OPEN_CONFIRMATION {
            return Err(SshError::Failed("unexpected channel open response"));
        }
        let mut off = 1usize;
        let recipient_channel = read_u32_at(&payload, &mut off)?;
        let sender_channel = read_u32_at(&payload, &mut off)?;
        let initial_window = read_u32_at(&payload, &mut off)?;
        let max_packet = read_u32_at(&payload, &mut off)?;
        if recipient_channel != self.local_channel_id {
            return Err(SshError::Failed("recipient channel mismatch"));
        }
        self.remote_channel_id = sender_channel;
        self.remote_window_size = initial_window;
        self.remote_max_packet_size = max_packet;
        self.channel_open = true;
        Ok(())
    }

    fn open_direct_tcpip(
        &mut self,
        destination_host: &str,
        destination_port: u16,
        originator_host: &str,
        originator_port: u16,
    ) -> Result<(), SshError> {
        if !(self.connected
            && self.kexinit_exchanged
            && self.key_exchange_complete
            && self.authenticated)
        {
            return Err(SshError::BadParam("invalid state for direct-tcpip"));
        }

        self.local_channel_id = self.next_local_channel_id;
        self.next_local_channel_id = self.next_local_channel_id.wrapping_add(1);
        self.local_window_size = NETNOX_SSH_CHANNEL_WINDOW_SIZE;

        let mut payload = Vec::with_capacity(256);
        payload.push(MSG_CHANNEL_OPEN);
        push_ssh_string(&mut payload, b"direct-tcpip");
        push_u32(&mut payload, self.local_channel_id);
        push_u32(&mut payload, self.local_window_size);
        push_u32(&mut payload, NETNOX_SSH_CHANNEL_MAX_PACKET_SIZE);
        push_ssh_string(&mut payload, destination_host.as_bytes());
        push_u32(&mut payload, destination_port as u32);
        push_ssh_string(&mut payload, originator_host.as_bytes());
        push_u32(&mut payload, originator_port as u32);
        self.send_packet(&payload)?;

        let response =
            self.wait_for_message(MSG_CHANNEL_OPEN_CONFIRMATION, Some(MSG_CHANNEL_OPEN_FAILURE))?;
        if response.is_empty() {
            return Err(SshError::Failed("empty direct-tcpip response"));
        }
        if response[0] == MSG_CHANNEL_OPEN_FAILURE {
            return Err(SshError::Failed("direct-tcpip open failed"));
        }
        if response[0] != MSG_CHANNEL_OPEN_CONFIRMATION {
            return Err(SshError::Failed("unexpected direct-tcpip response"));
        }

        let mut off = 1usize;
        let recipient_channel = read_u32_at(&response, &mut off)?;
        let sender_channel = read_u32_at(&response, &mut off)?;
        let initial_window = read_u32_at(&response, &mut off)?;
        let max_packet = read_u32_at(&response, &mut off)?;
        if recipient_channel != self.local_channel_id {
            return Err(SshError::Failed("direct-tcpip recipient channel mismatch"));
        }
        self.remote_channel_id = sender_channel;
        self.remote_window_size = initial_window;
        self.remote_max_packet_size = max_packet;
        self.channel_open = true;
        Ok(())
    }

    fn exec(&mut self, command: &str) -> Result<(), SshError> {
        if !(self.connected && self.kexinit_exchanged && self.key_exchange_complete && self.channel_open)
        {
            return Err(SshError::BadParam("invalid state for exec"));
        }
        if command.len() > NETNOX_SSH_MAX_COMMAND_LEN {
            return Err(SshError::BadParam("command too long"));
        }
        let mut payload = Vec::with_capacity(1024);
        payload.push(MSG_CHANNEL_REQUEST);
        push_u32(&mut payload, self.remote_channel_id);
        push_ssh_string(&mut payload, SSH_CHANNEL_REQ_EXEC.as_bytes());
        payload.push(1);
        push_ssh_string(&mut payload, command.as_bytes());
        self.send_packet(&payload)?;
        let rsp = self.wait_for_message(MSG_CHANNEL_SUCCESS, Some(MSG_CHANNEL_FAILURE))?;
        if rsp.first().copied() != Some(MSG_CHANNEL_SUCCESS) {
            return Err(SshError::Failed("exec request rejected"));
        }
        Ok(())
    }

    fn request_shell_ex(&mut self, request_pty: bool) -> Result<(), SshError> {
        if !(self.connected && self.kexinit_exchanged && self.key_exchange_complete && self.channel_open)
        {
            return Err(SshError::BadParam("invalid state for shell"));
        }

        if request_pty {
            // PTY request keeps shell UX interactive (prompting, line editing, colors).
            let mut pty_req = Vec::with_capacity(512);
            pty_req.push(MSG_CHANNEL_REQUEST);
            push_u32(&mut pty_req, self.remote_channel_id);
            push_ssh_string(&mut pty_req, b"pty-req");
            pty_req.push(1);
            push_ssh_string(&mut pty_req, b"xterm-256color");
            push_u32(&mut pty_req, 80);
            push_u32(&mut pty_req, 24);
            push_u32(&mut pty_req, 0);
            push_u32(&mut pty_req, 0);
            push_ssh_string(&mut pty_req, &[]);
            self.send_packet(&pty_req)?;
            let rsp = self.wait_for_message(MSG_CHANNEL_SUCCESS, Some(MSG_CHANNEL_FAILURE))?;
            if rsp.first().copied() != Some(MSG_CHANNEL_SUCCESS) {
                return Err(SshError::Failed("pty request rejected"));
            }
        }

        let mut shell_req = Vec::with_capacity(256);
        shell_req.push(MSG_CHANNEL_REQUEST);
        push_u32(&mut shell_req, self.remote_channel_id);
        push_ssh_string(&mut shell_req, SSH_CHANNEL_REQ_SHELL.as_bytes());
        shell_req.push(1);
        self.send_packet(&shell_req)?;
        let rsp = self.wait_for_message(MSG_CHANNEL_SUCCESS, Some(MSG_CHANNEL_FAILURE))?;
        if rsp.first().copied() != Some(MSG_CHANNEL_SUCCESS) {
            return Err(SshError::Failed("shell request rejected"));
        }
        Ok(())
    }

    fn send_window_change(&mut self, cols: u32, rows: u32) -> Result<(), SshError> {
        if !self.channel_open {
            return Err(SshError::BadParam("channel not open"));
        }
        let mut payload = Vec::with_capacity(128);
        payload.push(MSG_CHANNEL_REQUEST);
        push_u32(&mut payload, self.remote_channel_id);
        push_ssh_string(&mut payload, b"window-change");
        payload.push(0); // no reply requested
        push_u32(&mut payload, cols);
        push_u32(&mut payload, rows);
        push_u32(&mut payload, 0);
        push_u32(&mut payload, 0);
        self.send_packet(&payload)
    }

    fn request_subsystem(&mut self, subsystem: &str) -> Result<(), SshError> {
        if !(self.connected && self.kexinit_exchanged && self.key_exchange_complete && self.channel_open)
        {
            return Err(SshError::BadParam("invalid state for subsystem"));
        }
        let mut payload = Vec::with_capacity(256);
        payload.push(MSG_CHANNEL_REQUEST);
        push_u32(&mut payload, self.remote_channel_id);
        push_ssh_string(&mut payload, SSH_CHANNEL_REQ_SUBSYSTEM.as_bytes());
        payload.push(1);
        push_ssh_string(&mut payload, subsystem.as_bytes());
        self.send_packet(&payload)?;
        let rsp = self.wait_for_message(MSG_CHANNEL_SUCCESS, Some(MSG_CHANNEL_FAILURE))?;
        if rsp.first().copied() != Some(MSG_CHANNEL_SUCCESS) {
            return Err(SshError::Failed("subsystem request rejected"));
        }
        Ok(())
    }

    fn send_data(&mut self, data: &[u8]) -> Result<(), SshError> {
        if data.is_empty() || data.len() > NETNOX_SSH_MAX_DATA_LEN {
            return Err(SshError::BadParam("invalid send data length"));
        }
        if !(self.connected && self.channel_open) {
            return Err(SshError::BadParam("invalid state for send data"));
        }
        let mut chunk_len = data.len();
        if self.remote_max_packet_size > 0 && chunk_len > self.remote_max_packet_size as usize {
            chunk_len = self.remote_max_packet_size as usize;
        }
        chunk_len = chunk_len.min(NETNOX_SSH_MAX_DATA_LEN);

        let mut payload = Vec::with_capacity(16 + chunk_len);
        payload.push(MSG_CHANNEL_DATA);
        push_u32(&mut payload, self.remote_channel_id);
        push_ssh_string(&mut payload, &data[..chunk_len]);
        self.send_packet(&payload)
    }

    fn recv_data(&mut self, out_max: usize) -> Result<Vec<u8>, SshError> {
        if out_max == 0 || out_max > NETNOX_SSH_MAX_DATA_LEN {
            return Err(SshError::BadParam("invalid receive max"));
        }
        if !(self.connected && self.channel_open) {
            return Err(SshError::BadParam("invalid state for receive"));
        }
        loop {
            let payload = self.recv_packet()?;
            if payload.is_empty() {
                continue;
            }
            match payload[0] {
                MSG_CHANNEL_DATA => {
                    let mut off = 1usize;
                    let recipient = read_u32_at(&payload, &mut off)?;
                    if recipient != self.local_channel_id {
                        return Err(SshError::Failed("channel id mismatch"));
                    }
                    let data = read_ssh_string_owned(&payload, &mut off)?;
                    let take = out_max.min(data.len());
                    return Ok(data[..take].to_vec());
                }
                MSG_CHANNEL_EXTENDED_DATA => {
                    // Extended channel data is typically stderr.
                    let mut off = 1usize;
                    let recipient = read_u32_at(&payload, &mut off)?;
                    if recipient != self.local_channel_id {
                        return Err(SshError::Failed("channel id mismatch"));
                    }
                    let _ = read_u32_at(&payload, &mut off)?;
                    let data = read_ssh_string_owned(&payload, &mut off)?;
                    let take = out_max.min(data.len());
                    return Ok(data[..take].to_vec());
                }
                MSG_CHANNEL_EOF => return Ok(Vec::new()),
                MSG_CHANNEL_CLOSE => {
                    self.channel_open = false;
                    return Ok(Vec::new());
                }
                _ => {}
            }
        }
    }

    fn recv_data_with_timeout(
        &mut self,
        out_max: usize,
        timeout_ms: u64,
    ) -> Result<Option<Vec<u8>>, SshError> {
        let old = self.stream.read_timeout()?;
        self.stream
            .set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
        let recv = self.recv_data(out_max);
        self.stream.set_read_timeout(old)?;
        match recv {
            Ok(v) => Ok(Some(v)),
            Err(SshError::Io(err))
                if err.kind() == io::ErrorKind::TimedOut
                    || err.kind() == io::ErrorKind::WouldBlock =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn recv_packet_with_timeout(&mut self, timeout_ms: u64) -> Result<Option<Vec<u8>>, SshError> {
        let old = self.stream.read_timeout()?;
        self.stream
            .set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
        let recv = self.recv_packet();
        self.stream.set_read_timeout(old)?;
        match recv {
            Ok(v) => Ok(Some(v)),
            Err(SshError::Io(err))
                if err.kind() == io::ErrorKind::TimedOut
                    || err.kind() == io::ErrorKind::WouldBlock =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn maybe_send_keepalive(&mut self) -> Result<(), SshError> {
        if self.keepalive_interval.is_zero() {
            return Ok(());
        }
        if self.last_keepalive_at.elapsed() < self.keepalive_interval {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(5);
        payload.push(MSG_IGNORE);
        push_ssh_string(&mut payload, &[]);
        self.send_packet(&payload)?;
        self.last_keepalive_at = Instant::now();
        Ok(())
    }

    fn maybe_rekey(&mut self) -> Result<(), SshError> {
        if !self.key_exchange_complete || self.in_rekey {
            return Ok(());
        }
        let packet_triggered = self.sent_packet_count >= self.rekey_packet_threshold
            || self.recv_packet_count >= self.rekey_packet_threshold;
        let bytes_triggered = self.sent_payload_bytes >= self.rekey_byte_threshold
            || self.recv_payload_bytes >= self.rekey_byte_threshold;
        let time_triggered = self.last_kex_at.elapsed() >= self.rekey_interval;

        if !(packet_triggered || bytes_triggered || time_triggered) {
            return Ok(());
        }

        self.in_rekey = true;
        let rekey_result = self.exchange_kexinit();
        self.in_rekey = false;
        rekey_result?;
        self.sent_packet_count = 0;
        self.recv_packet_count = 0;
        self.sent_payload_bytes = 0;
        self.recv_payload_bytes = 0;
        self.last_kex_at = Instant::now();
        Ok(())
    }

    fn request_remote_tcpip_forward(&mut self, bind_host: &str, bind_port: u16) -> Result<(), SshError> {
        let mut payload = Vec::with_capacity(128);
        payload.push(MSG_GLOBAL_REQUEST);
        push_ssh_string(&mut payload, b"tcpip-forward");
        payload.push(1);
        push_ssh_string(&mut payload, bind_host.as_bytes());
        push_u32(&mut payload, bind_port as u32);
        self.send_packet(&payload)?;
        let rsp = self.wait_for_message(MSG_REQUEST_SUCCESS, Some(MSG_REQUEST_FAILURE))?;
        if rsp.first().copied() != Some(MSG_REQUEST_SUCCESS) {
            return Err(SshError::Failed("remote forward request rejected"));
        }
        Ok(())
    }

    fn close(&mut self) {
        self.connected = false;
        self.kexinit_exchanged = false;
        self.key_exchange_complete = false;
        self.userauth_service_ready = false;
        self.authenticated = false;
        self.channel_open = false;
        self.local_channel_id = 0;
        self.next_local_channel_id = 0;
        self.remote_channel_id = 0;
        self.local_window_size = 0;
        self.remote_window_size = 0;
        self.remote_max_packet_size = 0;
        self.server_ident.clear();
    }

    fn exchange_kexinit(&mut self) -> Result<(), SshError> {
        // KEXINIT negotiation decides compatible algorithms.
        let tx_payload = self.build_kexinit_payload();
        if tx_payload.len() > NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN {
            return Err(SshError::Failed("kexinit too large"));
        }
        self.kexinit_client_payload = tx_payload.clone();
        self.send_packet(&tx_payload)?;
        let rx_payload = self.recv_packet()?;
        if rx_payload.is_empty() || rx_payload[0] != MSG_KEXINIT {
            return Err(SshError::Failed("expected server kexinit"));
        }
        if rx_payload.len() > NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN {
            return Err(SshError::Failed("server kexinit too large"));
        }
        self.kexinit_server_payload = rx_payload.clone();
        validate_server_kexinit(&rx_payload)?;
        self.kexinit_exchanged = true;
        self.perform_curve25519_kex()
    }

    fn perform_curve25519_kex(&mut self) -> Result<(), SshError> {
        // Generate ephemeral X25519 keypair for this handshake.
        let mut drbg = new_drbg()?;
        let private_key = x25519_generate_private_key_auto(&mut drbg)
            .map_err(|_| SshError::Failed("x25519 key generation failed"))?;
        let client_pub = private_key.public_key().bytes;

        let mut init_payload = Vec::with_capacity(64);
        init_payload.push(MSG_KEX_ECDH_INIT);
        push_ssh_string(&mut init_payload, &client_pub);
        self.send_packet(&init_payload)?;

        let reply = self.wait_for_message(MSG_KEX_ECDH_REPLY, None)?;
        if reply.is_empty() || reply[0] != MSG_KEX_ECDH_REPLY {
            return Err(SshError::Failed("invalid kex reply"));
        }

        let mut off = 1usize;
        let host_key_blob = read_ssh_string_owned(&reply, &mut off)?;
        let server_pub = read_ssh_string_owned(&reply, &mut off)?;
        let signature = read_ssh_string_owned(&reply, &mut off)?;
        if signature.is_empty() || server_pub.len() != 32 {
            return Err(SshError::Failed("invalid kex ecdh reply fields"));
        }
        let host_key_type =
            ssh_host_key_type_from_blob(&host_key_blob).ok_or(SshError::Failed("invalid host key blob"))?;
        let host_key_b64 = base64_encode(&host_key_blob);
        verify_or_add_host_key(
            &self.host,
            &host_key_type,
            &host_key_b64,
            &self.host_key_policy,
        )
        .map_err(SshError::FailedOwned)?;
        let mut server_pub_arr = [0u8; 32];
        server_pub_arr.copy_from_slice(&server_pub);
        // Derive shared secret K = X25519(client_priv, server_pub).
        let shared = private_key
            .diffie_hellman_checked(X25519PublicKey::from_bytes(server_pub_arr))
            .map_err(|_| SshError::Failed("x25519 shared secret failed"))?;

        // Exchange hash H (also session_id for first key exchange).
        self.session_id = compute_exchange_hash(
            &self.client_ident,
            &self.server_ident,
            &self.kexinit_client_payload,
            &self.kexinit_server_payload,
            &host_key_blob,
            &client_pub,
            &server_pub_arr,
            &shared,
        )?;
        self.session_id_len = 32;
        self.shared_secret_raw.copy_from_slice(&shared);

        // Switch transport to encrypted packets after NEWKEYS roundtrip.
        self.send_packet(&[MSG_NEWKEYS])?;
        let newkeys = self.wait_for_message(MSG_NEWKEYS, None)?;
        if newkeys.first().copied() != Some(MSG_NEWKEYS) {
            return Err(SshError::Failed("expected newkeys"));
        }

        self.derive_transport_keys()?;
        self.key_exchange_complete = true;
        Ok(())
    }

    fn derive_transport_keys(&mut self) -> Result<(), SshError> {
        // RFC 4253 key schedule selectors A..F.
        let c2s_iv = self.derive_key_block(b'A', self.c2s_iv.len())?;
        let s2c_iv = self.derive_key_block(b'B', self.s2c_iv.len())?;
        let c2s_key = self.derive_key_block(b'C', self.c2s_key.len())?;
        let s2c_key = self.derive_key_block(b'D', self.s2c_key.len())?;
        let c2s_mac_key = self.derive_key_block(b'E', self.c2s_mac_key.len())?;
        let s2c_mac_key = self.derive_key_block(b'F', self.s2c_mac_key.len())?;

        self.c2s_iv.copy_from_slice(&c2s_iv);
        self.s2c_iv.copy_from_slice(&s2c_iv);
        self.c2s_key.copy_from_slice(&c2s_key);
        self.s2c_key.copy_from_slice(&s2c_key);
        self.c2s_mac_key.copy_from_slice(&c2s_mac_key);
        self.s2c_mac_key.copy_from_slice(&s2c_mac_key);
        self.c2s_counter = self.c2s_iv;
        self.s2c_counter = self.s2c_iv;
        self.c2s_cipher = Some(
            AesCipher::new(&self.c2s_key).map_err(|_| SshError::Failed("failed to init c2s aes"))?,
        );
        self.s2c_cipher = Some(
            AesCipher::new(&self.s2c_key).map_err(|_| SshError::Failed("failed to init s2c aes"))?,
        );
        Ok(())
    }

    fn derive_key_block(&self, selector: u8, out_len: usize) -> Result<Vec<u8>, SshError> {
        if self.session_id_len == 0 {
            return Err(SshError::BadParam("session id missing"));
        }
        // HASH(K || H || selector || session_id), then HASH(K || H || previous_output)...
        let mut seed = Vec::new();
        append_mpint_from_fixed_be(&mut seed, &self.shared_secret_raw);
        seed.extend_from_slice(&self.session_id[..self.session_id_len]);
        seed.push(selector);
        seed.extend_from_slice(&self.session_id[..self.session_id_len]);

        let mut out = sha256(&seed).to_vec();
        out.truncate(out_len.min(out.len()));

        while out.len() < out_len {
            let mut cont = Vec::new();
            append_mpint_from_fixed_be(&mut cont, &self.shared_secret_raw);
            cont.extend_from_slice(&self.session_id[..self.session_id_len]);
            cont.extend_from_slice(&out);
            out.extend_from_slice(&sha256(&cont));
        }
        out.truncate(out_len);
        Ok(out)
    }

    fn negotiate_userauth_service(&mut self) -> Result<(), SshError> {
        self.send_service_request(SSH_SERVICE_USERAUTH)?;
        let payload = self.wait_for_message(MSG_SERVICE_ACCEPT, None)?;
        if payload.first().copied() != Some(MSG_SERVICE_ACCEPT) {
            return Err(SshError::Failed("expected service accept"));
        }
        let mut off = 1usize;
        let service = read_ssh_string_owned(&payload, &mut off)?;
        if service != SSH_SERVICE_USERAUTH.as_bytes() {
            return Err(SshError::Failed("unexpected accepted service"));
        }
        self.userauth_service_ready = true;
        Ok(())
    }

    fn send_service_request(&mut self, service: &str) -> Result<(), SshError> {
        let mut payload = Vec::with_capacity(64);
        payload.push(MSG_SERVICE_REQUEST);
        push_ssh_string(&mut payload, service.as_bytes());
        self.send_packet(&payload)
    }

    fn send_userauth_password(&mut self) -> Result<(), SshError> {
        let mut payload = Vec::with_capacity(512);
        payload.push(MSG_USERAUTH_REQUEST);
        push_ssh_string(&mut payload, self.username.as_bytes());
        push_ssh_string(&mut payload, SSH_SERVICE_CONNECTION.as_bytes());
        push_ssh_string(&mut payload, SSH_AUTH_METHOD_PASSWORD.as_bytes());
        payload.push(0);
        push_ssh_string(&mut payload, self.password.as_bytes());
        self.send_packet(&payload)
    }

    fn try_password_auth(&mut self) -> Result<bool, SshError> {
        self.send_userauth_password()?;
        let payload = self.wait_for_message(MSG_USERAUTH_SUCCESS, Some(MSG_USERAUTH_FAILURE))?;
        match payload.first().copied() {
            Some(MSG_USERAUTH_SUCCESS) => Ok(true),
            Some(MSG_USERAUTH_FAILURE) => Ok(false),
            _ => Err(SshError::Failed("unexpected userauth response")),
        }
    }

    fn try_publickey_auth(&mut self) -> Result<bool, SshError> {
        // OpenSSH-compatible identity loading is plumbed here; full key-sign auth support
        // is staged for a follow-up implementation. We probe accepted methods and then
        // continue fallback order if signature-capable key handling is unavailable.
        if try_agent_publickey_auth(self)? {
            return Ok(true);
        }
        let identity_files = self.identity_files.clone();
        for identity in identity_files {
            if let Some((algorithm, public_key_b64)) = read_public_key_line(&identity) {
                let pub_blob = base64_decode(&public_key_b64)
                    .ok_or(SshError::Failed("invalid base64 in identity public key"))?;
                if !matches!(
                    algorithm.as_str(),
                    "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" | "ssh-ed25519"
                ) {
                    continue;
                }
                if !send_publickey_probe(self, &algorithm, &pub_blob)? {
                    continue;
                }
                if let Some(sig) = sign_publickey_auth_request(self, &identity, &algorithm, &pub_blob)?
                {
                    send_signed_publickey_request(self, &algorithm, &pub_blob, &sig)?;
                    let rsp = self.wait_for_message(MSG_USERAUTH_SUCCESS, Some(MSG_USERAUTH_FAILURE))?;
                    match rsp.first().copied() {
                        Some(MSG_USERAUTH_SUCCESS) => return Ok(true),
                        Some(MSG_USERAUTH_FAILURE) => continue,
                        _ => return Err(SshError::Failed("unexpected signed publickey response")),
                    }
                }
            }
        }
        Ok(false)
    }

    fn try_keyboard_interactive_auth(&mut self) -> Result<bool, SshError> {
        let mut payload = Vec::with_capacity(256);
        payload.push(MSG_USERAUTH_REQUEST);
        push_ssh_string(&mut payload, self.username.as_bytes());
        push_ssh_string(&mut payload, SSH_SERVICE_CONNECTION.as_bytes());
        push_ssh_string(&mut payload, b"keyboard-interactive");
        push_ssh_string(&mut payload, b"");
        push_ssh_string(&mut payload, b"");
        self.send_packet(&payload)?;
        let rsp = self.wait_for_message(MSG_USERAUTH_SUCCESS, Some(MSG_USERAUTH_FAILURE))?;
        match rsp.first().copied() {
            Some(MSG_USERAUTH_SUCCESS) => Ok(true),
            Some(MSG_USERAUTH_FAILURE) => Ok(false),
            _ => Ok(false),
        }
    }

    fn send_channel_open_session(&mut self) -> Result<(), SshError> {
        let mut payload = Vec::with_capacity(128);
        payload.push(MSG_CHANNEL_OPEN);
        push_ssh_string(&mut payload, SSH_CHANNEL_TYPE_SESSION.as_bytes());
        push_u32(&mut payload, self.local_channel_id);
        push_u32(&mut payload, self.local_window_size);
        push_u32(&mut payload, NETNOX_SSH_CHANNEL_MAX_PACKET_SIZE);
        self.send_packet(&payload)
    }

    fn wait_for_message(&mut self, expect_a: u8, expect_b: Option<u8>) -> Result<Vec<u8>, SshError> {
        for _ in 0..32 {
            let payload = self.recv_packet()?;
            if payload.is_empty() {
                continue;
            }
            if payload[0] == expect_a || expect_b == Some(payload[0]) {
                return Ok(payload);
            }
        }
        Err(SshError::Failed("wait_for_message exceeded max attempts"))
    }

    fn send_packet(&mut self, payload: &[u8]) -> Result<(), SshError> {
        if payload.is_empty() {
            return Err(SshError::BadParam("empty payload"));
        }
        self.maybe_rekey()?;
        // Prior to NEWKEYS, SSH packet framing uses minimum block size 8.
        let block_size = if self.key_exchange_complete {
            NETNOX_SSH_AES_BLOCK_LEN
        } else {
            8
        };

        let mut padding_len = NETNOX_SSH_MIN_PADDING_LEN;
        while (1 + payload.len() + padding_len + 4) % block_size != 0 {
            padding_len += 1;
        }
        let packet_len = 1 + payload.len() + padding_len;
        if packet_len > NETNOX_SSH_MAX_PACKET_LEN {
            return Err(SshError::BadParam("packet too large"));
        }

        let mut plain = Vec::with_capacity(4 + packet_len);
        push_u32(&mut plain, packet_len as u32);
        plain.push(padding_len as u8);
        plain.extend_from_slice(payload);
        let mut padding = vec![0u8; padding_len];
        fill_random(&mut padding)?;
        plain.extend_from_slice(&padding);

        if self.key_exchange_complete {
            // MAC is over sequence_number || plaintext_packet, then packet is encrypted.
            let mut mac_input = Vec::with_capacity(4 + plain.len());
            push_u32(&mut mac_input, self.send_seq);
            mac_input.extend_from_slice(&plain);
            let mac = hmac_sha256(&self.c2s_mac_key, &mac_input);

            let cipher = self
                .c2s_cipher
                .as_ref()
                .ok_or(SshError::Failed("c2s cipher unavailable"))?;
            let enc = aes_ctr_apply_with_counter(cipher, &mut self.c2s_counter, &plain);

            self.stream.write_all(&enc)?;
            self.stream.write_all(&mac)?;
            self.stream.flush()?;
            self.send_seq = self.send_seq.wrapping_add(1);
            self.sent_packet_count = self.sent_packet_count.saturating_add(1);
            self.sent_payload_bytes = self
                .sent_payload_bytes
                .saturating_add(payload.len() as u64);
            return Ok(());
        }

        self.stream.write_all(&plain)?;
        self.stream.flush()?;
        self.send_seq = self.send_seq.wrapping_add(1);
        self.sent_packet_count = self.sent_packet_count.saturating_add(1);
        self.sent_payload_bytes = self
            .sent_payload_bytes
            .saturating_add(payload.len() as u64);
        Ok(())
    }

    fn recv_packet(&mut self) -> Result<Vec<u8>, SshError> {
        if self.key_exchange_complete {
            let cipher = self
                .s2c_cipher
                .as_ref()
                .ok_or(SshError::Failed("s2c cipher unavailable"))?
                .clone();

            // Decrypt first block to discover packet length, then read/decrypt the remainder.
            let mut enc_first = [0u8; NETNOX_SSH_AES_BLOCK_LEN];
            self.recv_exact(&mut enc_first)?;
            let first_plain = aes_ctr_apply_with_counter(&cipher, &mut self.s2c_counter, &enc_first);
            if first_plain.len() != NETNOX_SSH_AES_BLOCK_LEN {
                return Err(SshError::Failed("invalid first block length"));
            }
            let packet_len = u32::from_be_bytes([
                first_plain[0],
                first_plain[1],
                first_plain[2],
                first_plain[3],
            ]) as usize;
            if packet_len < (1 + NETNOX_SSH_MIN_PADDING_LEN) || packet_len > NETNOX_SSH_MAX_PACKET_LEN
            {
                return Err(SshError::Failed("invalid encrypted packet length"));
            }
            let plain_len = 4 + packet_len;
            let rest_len = plain_len - NETNOX_SSH_AES_BLOCK_LEN;
            let mut enc_rest = vec![0u8; rest_len];
            self.recv_exact(&mut enc_rest)?;
            let rest_plain = aes_ctr_apply_with_counter(&cipher, &mut self.s2c_counter, &enc_rest);

            let mut plain = Vec::with_capacity(plain_len);
            plain.extend_from_slice(&first_plain);
            plain.extend_from_slice(&rest_plain);

            let mut mac_recv = [0u8; NETNOX_SSH_MAC_LEN];
            self.recv_exact(&mut mac_recv)?;

            // Verify packet MAC before exposing payload bytes.
            let mut mac_input = Vec::with_capacity(4 + plain_len);
            push_u32(&mut mac_input, self.recv_seq);
            mac_input.extend_from_slice(&plain);
            let mac_expected = hmac_sha256(&self.s2c_mac_key, &mac_input);
            if mac_expected != mac_recv {
                return Err(SshError::Failed("ssh packet mac verification failed"));
            }
            self.recv_seq = self.recv_seq.wrapping_add(1);

            let padding_len = plain[4] as usize;
            if padding_len < NETNOX_SSH_MIN_PADDING_LEN || padding_len >= packet_len {
                return Err(SshError::Failed("invalid encrypted padding"));
            }
            let payload_len = packet_len - 1 - padding_len;
            let start = 5;
            let end = start + payload_len;
            self.recv_packet_count = self.recv_packet_count.saturating_add(1);
            self.recv_payload_bytes = self
                .recv_payload_bytes
                .saturating_add(payload_len as u64);
            return Ok(plain[start..end].to_vec());
        }

        let mut len_buf = [0u8; 4];
        self.recv_exact(&mut len_buf)?;
        let packet_len = u32::from_be_bytes(len_buf) as usize;
        if packet_len < (1 + NETNOX_SSH_MIN_PADDING_LEN) || packet_len > NETNOX_SSH_MAX_PACKET_LEN {
            return Err(SshError::Failed("invalid packet length"));
        }
        let mut packet = vec![0u8; packet_len];
        self.recv_exact(&mut packet)?;
        let padding_len = packet[0] as usize;
        if padding_len < NETNOX_SSH_MIN_PADDING_LEN || padding_len >= packet_len {
            return Err(SshError::Failed("invalid padding"));
        }
        let payload_len = packet_len - 1 - padding_len;
        self.recv_seq = self.recv_seq.wrapping_add(1);
        self.recv_packet_count = self.recv_packet_count.saturating_add(1);
        self.recv_payload_bytes = self
            .recv_payload_bytes
            .saturating_add(payload_len as u64);
        Ok(packet[1..1 + payload_len].to_vec())
    }

    fn recv_exact(&mut self, out: &mut [u8]) -> Result<(), SshError> {
        let mut off = 0usize;
        while off < out.len() {
            let read = self.stream.read(&mut out[off..])?;
            if read == 0 {
                return Err(SshError::Failed("socket closed"));
            }
            off += read;
        }
        Ok(())
    }

    fn recv_line(&mut self) -> Result<String, SshError> {
        let mut out = Vec::new();
        while out.len() < NETNOX_SSH_MAX_IDENT_LEN {
            let mut ch = [0u8; 1];
            let n = self.stream.read(&mut ch)?;
            if n == 0 {
                return Err(SshError::Failed("socket closed during line read"));
            }
            if ch[0] == b'\n' {
                break;
            }
            if ch[0] != b'\r' {
                out.push(ch[0]);
            }
        }
        Ok(String::from_utf8_lossy(&out).to_string())
    }

    fn build_kexinit_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(1024);
        payload.push(MSG_KEXINIT);
        let mut cookie = [0u8; NETNOX_SSH_KEXINIT_COOKIE_LEN];
        let _ = fill_random(&mut cookie);
        payload.extend_from_slice(&cookie);
        push_namelist(&mut payload, NETNOX_SSH_KEX_ALG_LIST);
        push_namelist(&mut payload, NETNOX_SSH_HOST_KEY_ALG_LIST);
        push_namelist(&mut payload, NETNOX_SSH_CIPHER_ALG_LIST);
        push_namelist(&mut payload, NETNOX_SSH_CIPHER_ALG_LIST);
        push_namelist(&mut payload, NETNOX_SSH_MAC_ALG_LIST);
        push_namelist(&mut payload, NETNOX_SSH_MAC_ALG_LIST);
        push_namelist(&mut payload, NETNOX_SSH_COMPRESSION_ALG_LIST);
        push_namelist(&mut payload, NETNOX_SSH_COMPRESSION_ALG_LIST);
        push_namelist(&mut payload, "");
        push_namelist(&mut payload, "");
        payload.push(0);
        push_u32(&mut payload, 0);
        payload
    }
}

fn compute_exchange_hash(
    client_ident: &str,
    server_ident: &str,
    kexinit_client_payload: &[u8],
    kexinit_server_payload: &[u8],
    host_key_blob: &[u8],
    client_pub: &[u8; 32],
    server_pub: &[u8; 32],
    shared_secret_raw: &[u8; 32],
) -> Result<[u8; 32], SshError> {
    // H = HASH(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
    let mut input = Vec::with_capacity(4096);
    push_ssh_string(&mut input, client_ident.as_bytes());
    push_ssh_string(&mut input, server_ident.as_bytes());
    push_ssh_string(&mut input, kexinit_client_payload);
    push_ssh_string(&mut input, kexinit_server_payload);
    push_ssh_string(&mut input, host_key_blob);
    push_ssh_string(&mut input, client_pub);
    push_ssh_string(&mut input, server_pub);
    append_mpint_from_fixed_be(&mut input, shared_secret_raw);
    if input.len() > 4096 {
        return Err(SshError::Failed("exchange hash input too large"));
    }
    Ok(sha256(&input))
}

fn ssh_host_key_type_from_blob(blob: &[u8]) -> Option<String> {
    let mut off = 0usize;
    let key_type = read_ssh_string(blob, &mut off).ok()?;
    Some(String::from_utf8_lossy(key_type).to_string())
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0usize;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if i + 1 < input.len() {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < input.len() {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut quartet = [0u8; 4];
    let mut qlen = 0usize;
    for ch in input.bytes().filter(|b| !b" \r\n\t".contains(b)) {
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => 64,
            _ => return None,
        };
        quartet[qlen] = val;
        qlen += 1;
        if qlen == 4 {
            if quartet[0] == 64 || quartet[1] == 64 {
                return None;
            }
            let n = ((quartet[0] as u32) << 18)
                | ((quartet[1] as u32) << 12)
                | (((quartet[2] & 0x3f) as u32) << 6)
                | ((quartet[3] & 0x3f) as u32);
            out.push(((n >> 16) & 0xff) as u8);
            if quartet[2] != 64 {
                out.push(((n >> 8) & 0xff) as u8);
            }
            if quartet[3] != 64 {
                out.push((n & 0xff) as u8);
            }
            qlen = 0;
        }
    }
    if qlen != 0 {
        return None;
    }
    Some(out)
}

fn read_public_key_line(identity_path: &PathBuf) -> Option<(String, String)> {
    let pub_path = if identity_path
        .extension()
        .map(|ext| ext == "pub")
        .unwrap_or(false)
    {
        identity_path.clone()
    } else {
        PathBuf::from(format!("{}.pub", identity_path.display()))
    };
    let content = std::fs::read_to_string(pub_path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split_whitespace();
        let key_type = fields.next()?.to_string();
        let key_data = fields.next()?.to_string();
        return Some((key_type, key_data));
    }
    None
}

fn send_publickey_probe(client: &mut SshClient, algorithm: &str, pub_blob: &[u8]) -> Result<bool, SshError> {
    let mut payload = Vec::with_capacity(1024);
    payload.push(MSG_USERAUTH_REQUEST);
    push_ssh_string(&mut payload, client.username.as_bytes());
    push_ssh_string(&mut payload, SSH_SERVICE_CONNECTION.as_bytes());
    push_ssh_string(&mut payload, b"publickey");
    payload.push(0);
    push_ssh_string(&mut payload, algorithm.as_bytes());
    push_ssh_string(&mut payload, pub_blob);
    client.send_packet(&payload)?;

    for _ in 0..32 {
        let rsp = client.recv_packet()?;
        if rsp.is_empty() {
            continue;
        }
        match rsp[0] {
            MSG_USERAUTH_PK_OK => return Ok(true),
            MSG_USERAUTH_FAILURE => return Ok(false),
            MSG_USERAUTH_SUCCESS => return Ok(true),
            _ => {}
        }
    }
    Ok(false)
}

fn sign_publickey_auth_request(
    client: &SshClient,
    identity_path: &PathBuf,
    algorithm: &str,
    pub_blob: &[u8],
) -> Result<Option<Vec<u8>>, SshError> {
    let pem = std::fs::read_to_string(identity_path).map_err(SshError::Io)?;
    let mut signed_data = Vec::new();
    push_ssh_string(&mut signed_data, &client.session_id[..client.session_id_len]);
    signed_data.push(MSG_USERAUTH_REQUEST);
    push_ssh_string(&mut signed_data, client.username.as_bytes());
    push_ssh_string(&mut signed_data, SSH_SERVICE_CONNECTION.as_bytes());
    push_ssh_string(&mut signed_data, b"publickey");
    signed_data.push(1);
    push_ssh_string(&mut signed_data, algorithm.as_bytes());
    push_ssh_string(&mut signed_data, pub_blob);

    match load_private_signer(&pem)? {
        PrivateSigner::Rsa(private_key) => {
            let raw_sig = rsassa_sha256_sign(&private_key, &signed_data)
                .map_err(|_| SshError::Failed("rsa-sha256 signing failed"))?;
            let mut sig_blob = Vec::new();
            let sig_alg = if algorithm == "ssh-rsa" {
                "rsa-sha2-256"
            } else {
                algorithm
            };
            push_ssh_string(&mut sig_blob, sig_alg.as_bytes());
            push_ssh_string(&mut sig_blob, &raw_sig);
            Ok(Some(sig_blob))
        }
        PrivateSigner::Ed25519(private_key) => {
            if algorithm != "ssh-ed25519" {
                return Ok(None);
            }
            let raw_sig = private_key.sign(&signed_data);
            let mut sig_blob = Vec::new();
            push_ssh_string(&mut sig_blob, b"ssh-ed25519");
            push_ssh_string(&mut sig_blob, &raw_sig);
            Ok(Some(sig_blob))
        }
    }
}

fn send_signed_publickey_request(
    client: &mut SshClient,
    algorithm: &str,
    pub_blob: &[u8],
    signature_blob: &[u8],
) -> Result<(), SshError> {
    let mut payload = Vec::with_capacity(2048);
    payload.push(MSG_USERAUTH_REQUEST);
    push_ssh_string(&mut payload, client.username.as_bytes());
    push_ssh_string(&mut payload, SSH_SERVICE_CONNECTION.as_bytes());
    push_ssh_string(&mut payload, b"publickey");
    payload.push(1);
    push_ssh_string(&mut payload, algorithm.as_bytes());
    push_ssh_string(&mut payload, pub_blob);
    push_ssh_string(&mut payload, signature_blob);
    client.send_packet(&payload)
}

fn try_agent_publickey_auth(_client: &mut SshClient) -> Result<bool, SshError> {
    // Agent integration abstraction hook: we detect agent presence and leave a single
    // extension point for future SSH-agent protocol support.
    if std::env::var("SSH_AUTH_SOCK").is_ok() {
        ssh_debug(1, format_args!("SSH_AUTH_SOCK detected; agent auth hook not yet implemented"));
    }
    Ok(false)
}

enum PrivateSigner {
    Rsa(noxtls_crypto::RsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
}

fn load_private_signer(pem: &str) -> Result<PrivateSigner, SshError> {
    if let Ok(private_key) = rsa_private_key_from_pem_pkcs1(pem).or_else(|_| rsa_private_key_from_pem_pkcs8(pem)) {
        return Ok(PrivateSigner::Rsa(private_key));
    }

    let der = private_key_pem_to_der_pkcs8(pem)
        .map_err(|_| SshError::Failed("failed to parse private key from identity file"))?;
    let info = parse_pkcs8_private_key_info_der(&der)
        .map_err(|_| SshError::Failed("invalid pkcs8 private key"))?;
    // id-Ed25519 OID (1.3.101.112)
    if info.algorithm_oid.as_slice() == [0x2b, 0x65, 0x70] {
        let seed = parse_ed25519_seed_from_pkcs8_private_key(&info.private_key)
            .ok_or(SshError::Failed("invalid ed25519 private key payload"))?;
        return Ok(PrivateSigner::Ed25519(Ed25519PrivateKey::from_seed(&seed)));
    }

    Err(SshError::Failed("unsupported private key type"))
}

fn parse_ed25519_seed_from_pkcs8_private_key(private_key: &[u8]) -> Option<[u8; 32]> {
    // RFC 8410 PKCS#8 wraps Ed25519 seed in an OCTET STRING, often nested.
    if private_key.len() == 32 {
        return private_key.try_into().ok();
    }
    if private_key.len() >= 2 && private_key[0] == 0x04 {
        let len = private_key[1] as usize;
        if private_key.len() == len + 2 {
            let inner = &private_key[2..];
            if inner.len() == 32 {
                return inner.try_into().ok();
            }
            if inner.len() >= 2 && inner[0] == 0x04 {
                let inner_len = inner[1] as usize;
                if inner.len() == inner_len + 2 && inner_len == 32 {
                    return inner[2..].try_into().ok();
                }
            }
        }
    }
    None
}

fn validate_server_kexinit(payload: &[u8]) -> Result<(), SshError> {
    if payload.len() < 1 + NETNOX_SSH_KEXINIT_COOKIE_LEN || payload[0] != MSG_KEXINIT {
        return Err(SshError::Failed("invalid server kexinit"));
    }
    let mut off = 1 + NETNOX_SSH_KEXINIT_COOKIE_LEN;
    let kex_list = read_ssh_string(payload, &mut off)?;
    if !namelist_contains(kex_list, NETNOX_SSH_REQUIRED_KEX_ALG.as_bytes()) {
        return Err(SshError::Failed("required kex algorithm not offered"));
    }
    Ok(())
}

fn namelist_contains(list: &[u8], token: &[u8]) -> bool {
    list.split(|b| *b == b',').any(|part| part == token)
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    push_u32(out, data.len() as u32);
    out.extend_from_slice(data);
}

fn push_namelist(out: &mut Vec<u8>, text: &str) {
    push_ssh_string(out, text.as_bytes());
}

fn read_u32_at(payload: &[u8], offset: &mut usize) -> Result<u32, SshError> {
    if *offset + 4 > payload.len() {
        return Err(SshError::Failed("payload underflow reading u32"));
    }
    let out = u32::from_be_bytes([
        payload[*offset],
        payload[*offset + 1],
        payload[*offset + 2],
        payload[*offset + 3],
    ]);
    *offset += 4;
    Ok(out)
}

fn read_ssh_string<'a>(payload: &'a [u8], offset: &mut usize) -> Result<&'a [u8], SshError> {
    let len = read_u32_at(payload, offset)? as usize;
    if *offset + len > payload.len() {
        return Err(SshError::Failed("payload underflow reading string"));
    }
    let out = &payload[*offset..*offset + len];
    *offset += len;
    Ok(out)
}

fn read_ssh_string_owned(payload: &[u8], offset: &mut usize) -> Result<Vec<u8>, SshError> {
    Ok(read_ssh_string(payload, offset)?.to_vec())
}

fn append_mpint_from_fixed_be(out: &mut Vec<u8>, be_value: &[u8]) {
    // SSH mpint is signed two's complement; prepend 0x00 when high bit is set.
    let mut first = 0usize;
    while first < be_value.len() && be_value[first] == 0 {
        first += 1;
    }
    if first == be_value.len() {
        push_u32(out, 0);
        return;
    }
    let value = &be_value[first..];
    if value[0] & 0x80 != 0 {
        push_u32(out, (value.len() + 1) as u32);
        out.push(0);
        out.extend_from_slice(value);
    } else {
        push_u32(out, value.len() as u32);
        out.extend_from_slice(value);
    }
}

fn increment_be(counter: &mut [u8; 16]) {
    // CTR increment is big-endian over 128-bit counter value.
    for i in (0..16).rev() {
        let (new, carry) = counter[i].overflowing_add(1);
        counter[i] = new;
        if !carry {
            break;
        }
    }
}

fn aes_ctr_apply_with_counter(cipher: &AesCipher, counter: &mut [u8; 16], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; input.len()];
    let mut offset = 0usize;
    while offset < input.len() {
        let mut stream = *counter;
        cipher.encrypt_block(&mut stream);
        let chunk = (input.len() - offset).min(16);
        for i in 0..chunk {
            out[offset + i] = input[offset + i] ^ stream[i];
        }
        increment_be(counter);
        offset += chunk;
    }
    out
}

fn new_drbg() -> Result<HmacDrbgSha256, SshError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    // Lightweight runtime seed material for demo/client process randomness.
    let mut entropy = [0u8; 32];
    entropy[..8].copy_from_slice(&now.as_secs().to_be_bytes());
    entropy[8..16].copy_from_slice(&(now.subsec_nanos() as u64).to_be_bytes());
    entropy[16..24].copy_from_slice(&(std::process::id() as u64).to_be_bytes());
    entropy[24..32].copy_from_slice(&(now.as_nanos() as u64).to_be_bytes());
    HmacDrbgSha256::new(&entropy, b"noxssh-rs", b"noxssh-rs")
        .map_err(|_| SshError::Failed("drbg initialization failed"))
}

fn fill_random(out: &mut [u8]) -> Result<(), SshError> {
    let mut drbg = new_drbg()?;
    let bytes = drbg
        .generate(out.len(), b"fill_random")
        .map_err(|_| SshError::Failed("drbg generate failed"))?;
    out.copy_from_slice(&bytes);
    Ok(())
}

fn ssh_debug(level: u8, args: std::fmt::Arguments<'_>) {
    if ssh_debug_level() >= level {
        eprintln!("SSH_DEBUG: {args}");
    }
}

fn ssh_debug_level() -> u8 {
    match env::var("NETNOX_SSH_DEBUG") {
        Ok(v) if v == "1" || v == "2" || v == "3" => v.parse::<u8>().unwrap_or(0),
        Ok(v) if !v.is_empty() => v.parse::<u8>().ok().filter(|x| *x <= 3).unwrap_or(1),
        _ => 0,
    }
}

#[derive(Default)]
struct CliOptions {
    port: u16,
    target: String,
    command: Option<String>,
    password: Option<String>,
    identity_files: Vec<PathBuf>,
    preferred_auth_methods: Vec<String>,
    request_pty: bool,
    debug_level: u8,
    host_key_mode: HostKeyCheckingMode,
    known_hosts_path: Option<PathBuf>,
    batch_mode: bool,
    connect_timeout_ms: u64,
    read_timeout_ms: u64,
    keepalive_interval_ms: u64,
    rekey_interval_s: u64,
    use_ssh_config: bool,
    local_forward: Option<LocalForwardSpec>,
    remote_forward: Option<LocalForwardSpec>,
    dynamic_forward_port: Option<u16>,
    sftp_ls: Option<String>,
}

#[derive(Clone, Debug)]
struct LocalForwardSpec {
    listen_port: u16,
    destination_host: String,
    destination_port: u16,
}

fn print_usage(program: &str) {
    println!("{program} {NOXSSH_VERSION_STRING}");
    println!("Using NoxTLS Library {NOXTLS_VERSION_STRING}");
    println!(
        "Usage: {program} [-h] [-V] [-d|-dd|-ddd] [-T] [-p port] [-w password] [-i identity_file] [-L [bind_port:]host:hostport] [-R [bind_port:]host:hostport] [-D port] [--sftp-ls path] [-o key=value] [--strict-host-key-checking mode] [--known-hosts path] [--connect-timeout-ms ms] [--read-timeout-ms ms] [--server-alive-interval sec] [--batch-mode] [user@]host [command]"
    );
    println!("Options:");
    println!("  -h, --help     Show this help and exit.");
    println!("  -V, --version  Show application and library versions.");
    println!("  -d             Enable basic SSH debug output.");
    println!("  -dd            Enable verbose SSH debug output.");
    println!("  -ddd           Enable packet-level SSH debug output.");
    println!("  -T             Disable PTY allocation for shell sessions.");
    println!("  -p port        SSH server port (default: 22).");
    println!("  -w password    Password (avoid command line in production).");
    println!("  -L [bind_port:]host:hostport");
    println!("                 Local TCP forwarding (SSH direct-tcpip).");
    println!("  -R [bind_port:]host:hostport");
    println!("                 Remote TCP forwarding (tcpip-forward).");
    println!("  -D <port>      Dynamic SOCKS5 forwarding on local port.");
    println!("  --sftp-ls <path>");
    println!("                 Start SFTP subsystem and list canonical path entries.");
    println!("  -i identity_file");
    println!("                 Identity file path (public key probing and future key auth).");
    println!("  -o key=value   OpenSSH-style options (limited support).");
    println!("  -F none        Disable loading ~/.ssh/config.");
    println!("  --strict-host-key-checking <strict|accept-new|off>");
    println!("                 Host key verification policy (default: strict).");
    println!("  --known-hosts <path>");
    println!("                 Path to known_hosts file.");
    println!("  --connect-timeout-ms <ms>");
    println!("                 TCP connect timeout in milliseconds (default: 10000).");
    println!("  --read-timeout-ms <ms>");
    println!("                 Socket read timeout in milliseconds (default: 30000).");
    println!("  --server-alive-interval <sec>");
    println!("                 Send SSH keepalive ignore packets every N seconds.");
    println!("  --batch-mode   Disable interactive prompts (including TOFU host key trust).");
}

fn parse_target(target: &str) -> Result<(String, String), SshError> {
    if let Some((user, host)) = target.split_once('@') {
        if user.is_empty() || host.is_empty() {
            return Err(SshError::BadParam("invalid target"));
        }
        if user.len() > NETNOX_SSH_MAX_USERNAME_LEN || host.len() > NETNOX_SSH_MAX_HOST_LEN {
            return Err(SshError::BadParam("target too long"));
        }
        Ok((user.to_string(), host.to_string()))
    } else {
        if target.is_empty() || target.len() > NETNOX_SSH_MAX_HOST_LEN {
            return Err(SshError::BadParam("invalid target"));
        }
        Ok((NOXSSH_DEFAULT_USER.to_string(), target.to_string()))
    }
}

fn parse_openssh_option(option: &str, opts: &mut CliOptions) -> Result<(), SshError> {
    let (key, value) = option
        .split_once('=')
        .ok_or(SshError::BadParam("expected -o key=value"))?;
    match key {
        "StrictHostKeyChecking" => {
            opts.host_key_mode = HostKeyCheckingMode::parse(&value.to_ascii_lowercase())
                .ok_or(SshError::BadParam("invalid StrictHostKeyChecking value"))?;
        }
        "UserKnownHostsFile" => {
            opts.known_hosts_path = Some(PathBuf::from(value));
        }
        "ConnectTimeout" => {
            let secs = value
                .parse::<u64>()
                .map_err(|_| SshError::BadParam("invalid ConnectTimeout"))?;
            opts.connect_timeout_ms = secs.saturating_mul(1000);
        }
        "ServerAliveInterval" => {
            let secs = value
                .parse::<u64>()
                .map_err(|_| SshError::BadParam("invalid ServerAliveInterval"))?;
            opts.keepalive_interval_ms = secs.saturating_mul(1000);
        }
        "BatchMode" => {
            opts.batch_mode = value.eq_ignore_ascii_case("yes") || value == "1";
        }
        "PreferredAuthentications" => {
            opts.preferred_auth_methods = value
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
        }
        _ => return Err(SshError::BadParam("unsupported -o option")),
    }
    Ok(())
}

fn parse_args(args: &[String]) -> Result<CliOptions, SshError> {
    if args.len() < 2 {
        return Err(SshError::BadParam("missing arguments"));
    }
    let mut opts = CliOptions {
        port: NETNOX_SSH_DEFAULT_PORT,
        request_pty: true,
        host_key_mode: HostKeyCheckingMode::Strict,
        connect_timeout_ms: 10_000,
        read_timeout_ms: 30_000,
        rekey_interval_s: 3_600,
        preferred_auth_methods: vec!["publickey".to_string(), "password".to_string()],
        use_ssh_config: true,
        ..Default::default()
    };
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage(&args[0]);
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("{} {}", args[0], NOXSSH_VERSION_STRING);
                println!("Using NoxTLS Library {NOXTLS_VERSION_STRING}");
                std::process::exit(0);
            }
            "-T" => {
                opts.request_pty = false;
                i += 1;
            }
            "-d" | "-dd" | "-ddd" => {
                opts.debug_level = (args[i].len() - 1) as u8;
                i += 1;
            }
            "-p" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -p value"));
                }
                opts.port = args[i + 1]
                    .parse::<u16>()
                    .map_err(|_| SshError::BadParam("invalid port"))?;
                if opts.port == 0 {
                    return Err(SshError::BadParam("invalid port"));
                }
                i += 2;
            }
            "-w" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -w value"));
                }
                opts.password = Some(args[i + 1].clone());
                i += 2;
            }
            "-i" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -i value"));
                }
                opts.identity_files.push(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "-L" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -L value"));
                }
                opts.local_forward = Some(parse_local_forward_spec(&args[i + 1])?);
                i += 2;
            }
            "-R" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -R value"));
                }
                opts.remote_forward = Some(parse_local_forward_spec(&args[i + 1])?);
                i += 2;
            }
            "-D" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -D value"));
                }
                opts.dynamic_forward_port = Some(
                    args[i + 1]
                        .parse::<u16>()
                        .map_err(|_| SshError::BadParam("invalid -D port"))?,
                );
                i += 2;
            }
            "--strict-host-key-checking" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing host key checking mode"));
                }
                opts.host_key_mode = HostKeyCheckingMode::parse(&args[i + 1])
                    .ok_or(SshError::BadParam("invalid host key checking mode"))?;
                i += 2;
            }
            "--known-hosts" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing known-hosts path"));
                }
                opts.known_hosts_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--connect-timeout-ms" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing connect timeout"));
                }
                opts.connect_timeout_ms = args[i + 1]
                    .parse::<u64>()
                    .map_err(|_| SshError::BadParam("invalid connect timeout"))?;
                i += 2;
            }
            "--read-timeout-ms" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing read timeout"));
                }
                opts.read_timeout_ms = args[i + 1]
                    .parse::<u64>()
                    .map_err(|_| SshError::BadParam("invalid read timeout"))?;
                i += 2;
            }
            "--server-alive-interval" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing server alive interval"));
                }
                let secs = args[i + 1]
                    .parse::<u64>()
                    .map_err(|_| SshError::BadParam("invalid server alive interval"))?;
                opts.keepalive_interval_ms = secs.saturating_mul(1000);
                i += 2;
            }
            "--batch-mode" => {
                opts.batch_mode = true;
                i += 1;
            }
            "--sftp-ls" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing --sftp-ls path"));
                }
                opts.sftp_ls = Some(args[i + 1].clone());
                i += 2;
            }
            "-o" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -o option"));
                }
                parse_openssh_option(&args[i + 1], &mut opts)?;
                i += 2;
            }
            "-F" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -F value"));
                }
                if args[i + 1].eq_ignore_ascii_case("none") {
                    opts.use_ssh_config = false;
                } else {
                    return Err(SshError::BadParam("only -F none is currently supported"));
                }
                i += 2;
            }
            x if x.starts_with('-') => return Err(SshError::BadParam("unknown option")),
            _ => {
                if opts.target.is_empty() {
                    opts.target = args[i].clone();
                    i += 1;
                } else {
                    // Collect remaining args into one remote command string.
                    let mut cmd = args[i].clone();
                    i += 1;
                    while i < args.len() {
                        if cmd.len() + 1 + args[i].len() > NETNOX_SSH_MAX_COMMAND_LEN {
                            break;
                        }
                        cmd.push(' ');
                        cmd.push_str(&args[i]);
                        i += 1;
                    }
                    opts.command = Some(cmd);
                }
            }
        }
    }

    if opts.target.is_empty() {
        return Err(SshError::BadParam("missing target"));
    }
    Ok(opts)
}

fn apply_ssh_host_config(opts: &mut CliOptions, username: &mut String, host: &str) {
    if !opts.use_ssh_config {
        return;
    }
    let cfg_path = default_ssh_config_path();
    let Some(host_cfg) = load_host_config(&cfg_path, host) else {
        return;
    };

    if *username == NOXSSH_DEFAULT_USER {
        if let Some(user) = host_cfg.user {
            *username = user;
        }
    }
    if opts.port == NETNOX_SSH_DEFAULT_PORT {
        if let Some(port) = host_cfg.port {
            opts.port = port;
        }
    }
    if opts.identity_files.is_empty() && !host_cfg.identity_files.is_empty() {
        opts.identity_files = host_cfg.identity_files;
    }
    if opts.host_key_mode == HostKeyCheckingMode::Strict {
        if let Some(mode) = host_cfg.strict_host_key_checking {
            opts.host_key_mode = mode;
        }
    }
    if opts.known_hosts_path.is_none() {
        opts.known_hosts_path = host_cfg.user_known_hosts_file;
    }
    if opts.keepalive_interval_ms == 0 {
        if let Some(sec) = host_cfg.server_alive_interval {
            opts.keepalive_interval_ms = sec.saturating_mul(1000);
        }
    }
    if !opts.batch_mode {
        if let Some(batch) = host_cfg.batch_mode {
            opts.batch_mode = batch;
        }
    }
    if opts.preferred_auth_methods == ["publickey".to_string(), "password".to_string()] {
        if !host_cfg.preferred_authentications.is_empty() {
            opts.preferred_auth_methods = host_cfg.preferred_authentications;
        }
    }
}

fn parse_local_forward_spec(spec: &str) -> Result<LocalForwardSpec, SshError> {
    let mut parts: Vec<&str> = spec.split(':').collect();
    if parts.len() == 2 {
        // host:port with implicit local bind port == destination port.
        let destination_host = parts.remove(0).to_string();
        let destination_port = parts
            .remove(0)
            .parse::<u16>()
            .map_err(|_| SshError::BadParam("invalid -L destination port"))?;
        return Ok(LocalForwardSpec {
            listen_port: destination_port,
            destination_host,
            destination_port,
        });
    }
    if parts.len() != 3 {
        return Err(SshError::BadParam(
            "invalid -L format, expected [bind_port:]host:hostport",
        ));
    }
    let listen_port = parts[0]
        .parse::<u16>()
        .map_err(|_| SshError::BadParam("invalid -L bind port"))?;
    let destination_host = parts[1].to_string();
    let destination_port = parts[2]
        .parse::<u16>()
        .map_err(|_| SshError::BadParam("invalid -L destination port"))?;
    Ok(LocalForwardSpec {
        listen_port,
        destination_host,
        destination_port,
    })
}

fn connect_tcp(host: &str, port: u16, connect_timeout: Duration, read_timeout: Duration) -> Result<TcpStream, SshError> {
    let mut last_err: Option<io::Error> = None;
    for addr in (host, port)
        .to_socket_addrs()
        .map_err(SshError::Io)?
        .collect::<Vec<_>>()
    {
        match TcpStream::connect_timeout(&addr, connect_timeout) {
            Ok(stream) => {
                stream
                    .set_nodelay(true)
                    .map_err(|_| SshError::Failed("failed setting nodelay"))?;
                if !read_timeout.is_zero() {
                    stream
                        .set_read_timeout(Some(read_timeout))
                        .map_err(|_| SshError::Failed("failed setting read timeout"))?;
                }
                return Ok(stream);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(SshError::Io(last_err.unwrap_or_else(|| io::Error::other("connect failed"))))
}

fn prompt_password() -> Result<String, SshError> {
    rpassword::prompt_password("Password: ").map_err(SshError::Io)
}

fn print_channel_output(client: &mut SshClient) -> Result<(), SshError> {
    loop {
        match client.recv_data_with_timeout(NETNOX_SSH_MAX_DATA_LEN, 1000)? {
            Some(data) if data.is_empty() => return Ok(()),
            Some(data) => {
                io::stdout().write_all(&data)?;
                io::stdout().flush()?;
            }
            None => {
                client.maybe_send_keepalive()?;
            }
        }
    }
}

fn drain_shell_output(client: &mut SshClient, first_wait_ms: u64) -> Result<i32, SshError> {
    match client.recv_data_with_timeout(NETNOX_SSH_MAX_DATA_LEN, first_wait_ms)? {
        None => {
            client.maybe_send_keepalive()?;
            Ok(0)
        }
        Some(data) if data.is_empty() => Ok(1),
        Some(data) => {
            io::stdout().write_all(&data)?;
            io::stdout().flush()?;
            loop {
                match client.recv_data_with_timeout(NETNOX_SSH_MAX_DATA_LEN, 60)? {
                    None => break,
                    Some(next) if next.is_empty() => return Ok(1),
                    Some(next) => {
                        io::stdout().write_all(&next)?;
                        io::stdout().flush()?;
                    }
                }
            }
            Ok(0)
        }
    }
}

fn interactive_shell(client: &mut SshClient) -> Result<(), SshError> {
    println!("Interactive shell mode. Type 'exit' to quit.");
    terminal::enable_raw_mode().map_err(|_| SshError::Failed("failed to enable raw mode"))?;
    if let Ok((cols, rows)) = terminal::size() {
        let _ = client.send_window_change(cols as u32, rows as u32);
    }
    let mut line_buf = String::new();
    let result = (|| -> Result<(), SshError> {
        loop {
            let drain = drain_shell_output(client, 100)?;
            if drain < 0 {
                return Err(SshError::Failed("failed receiving shell output"));
            }
            if drain > 0 {
                println!("Remote channel closed.");
                return Ok(());
            }

            if !event::poll(Duration::from_millis(50))
                .map_err(|_| SshError::Failed("event polling failed"))?
            {
                continue;
            }

            match event::read().map_err(|_| SshError::Failed("event read failed"))? {
                Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                    KeyCode::Enter => {
                        if line_buf == "exit" {
                            return Ok(());
                        }
                        line_buf.push('\n');
                        client.send_data(line_buf.as_bytes())?;
                        line_buf.clear();
                    }
                    KeyCode::Backspace => {
                        line_buf.pop();
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        client.send_data(&[0x03])?;
                    }
                    KeyCode::Char(ch) => {
                        line_buf.push(ch);
                    }
                    _ => {}
                },
                Event::Resize(cols, rows) => {
                    let _ = client.send_window_change(cols as u32, rows as u32);
                }
                _ => {}
            }
        }
    })();
    let _ = terminal::disable_raw_mode();
    result
}

fn run_local_forward(client: &mut SshClient, spec: &LocalForwardSpec) -> Result<(), SshError> {
    let bind_addr = format!("127.0.0.1:{}", spec.listen_port);
    let listener = TcpListener::bind(&bind_addr).map_err(SshError::Io)?;
    println!(
        "Local forward active: {} -> {}:{}",
        bind_addr, spec.destination_host, spec.destination_port
    );

    loop {
        let (mut local, peer_addr) = listener.accept().map_err(SshError::Io)?;
        client.open_direct_tcpip(
            &spec.destination_host,
            spec.destination_port,
            &peer_addr.ip().to_string(),
            peer_addr.port(),
        )?;
        forward_local_socket_over_channel(client, &mut local)?;
    }
}

fn run_dynamic_forward(client: &mut SshClient, port: u16) -> Result<(), SshError> {
    let bind_addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&bind_addr).map_err(SshError::Io)?;
    println!("Dynamic SOCKS5 forward active on {bind_addr}");
    loop {
        let (mut local, peer_addr) = listener.accept().map_err(SshError::Io)?;
        let (dst_host, dst_port) = socks5_handshake_and_target(&mut local)?;
        client.open_direct_tcpip(
            &dst_host,
            dst_port,
            &peer_addr.ip().to_string(),
            peer_addr.port(),
        )?;
        forward_local_socket_over_channel(client, &mut local)?;
    }
}

fn run_remote_forward(client: &mut SshClient, spec: &LocalForwardSpec) -> Result<(), SshError> {
    client.request_remote_tcpip_forward("127.0.0.1", spec.listen_port)?;
    println!(
        "Remote forward active: remote 127.0.0.1:{} -> local {}:{}",
        spec.listen_port, spec.destination_host, spec.destination_port
    );

    loop {
        let Some(packet) = client.recv_packet_with_timeout(200)? else {
            client.maybe_send_keepalive()?;
            continue;
        };
        if packet.is_empty() {
            continue;
        }
        if packet[0] != MSG_CHANNEL_OPEN {
            continue;
        }
        let mut off = 1usize;
        let channel_type = read_ssh_string(&packet, &mut off)?;
        if channel_type != b"forwarded-tcpip" {
            continue;
        }
        let remote_sender_channel = read_u32_at(&packet, &mut off)?;
        let remote_window = read_u32_at(&packet, &mut off)?;
        let remote_max_packet = read_u32_at(&packet, &mut off)?;
        let _connected_address = read_ssh_string(&packet, &mut off)?;
        let _connected_port = read_u32_at(&packet, &mut off)?;
        let _originator_address = read_ssh_string(&packet, &mut off)?;
        let _originator_port = read_u32_at(&packet, &mut off)?;

        let local_target = format!("{}:{}", spec.destination_host, spec.destination_port);
        let mut local = TcpStream::connect(&local_target)
            .map_err(|_| SshError::Failed("failed to connect local target for remote forward"))?;
        local.set_read_timeout(Some(Duration::from_millis(50))).map_err(SshError::Io)?;
        local
            .set_write_timeout(Some(Duration::from_millis(2000)))
            .map_err(SshError::Io)?;

        let local_channel_id = client.next_local_channel_id;
        client.next_local_channel_id = client.next_local_channel_id.wrapping_add(1);
        let mut confirm = Vec::with_capacity(32);
        confirm.push(MSG_CHANNEL_OPEN_CONFIRMATION);
        push_u32(&mut confirm, remote_sender_channel);
        push_u32(&mut confirm, local_channel_id);
        push_u32(&mut confirm, NETNOX_SSH_CHANNEL_WINDOW_SIZE);
        push_u32(&mut confirm, NETNOX_SSH_CHANNEL_MAX_PACKET_SIZE);
        client.send_packet(&confirm)?;

        client.local_channel_id = local_channel_id;
        client.remote_channel_id = remote_sender_channel;
        client.remote_window_size = remote_window;
        client.remote_max_packet_size = remote_max_packet;
        client.channel_open = true;
        forward_local_socket_over_channel(client, &mut local)?;
    }
}

fn socks5_handshake_and_target(stream: &mut TcpStream) -> Result<(String, u16), SshError> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).map_err(SshError::Io)?;
    if head[0] != 5 {
        return Err(SshError::Failed("unsupported socks version"));
    }
    let method_count = head[1] as usize;
    let mut methods = vec![0u8; method_count];
    stream.read_exact(&mut methods).map_err(SshError::Io)?;
    // no-auth only
    stream.write_all(&[5, 0]).map_err(SshError::Io)?;

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).map_err(SshError::Io)?;
    if req[0] != 5 || req[1] != 1 {
        return Err(SshError::Failed("unsupported socks command"));
    }

    let host = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).map_err(SshError::Io)?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        3 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).map_err(SshError::Io)?;
            let mut buf = vec![0u8; l[0] as usize];
            stream.read_exact(&mut buf).map_err(SshError::Io)?;
            String::from_utf8_lossy(&buf).to_string()
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).map_err(SshError::Io)?;
            let addr = std::net::Ipv6Addr::from(ip);
            addr.to_string()
        }
        _ => return Err(SshError::Failed("unsupported socks address type")),
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).map_err(SshError::Io)?;
    let port = u16::from_be_bytes(port_buf);

    // success response with 0.0.0.0:0 bind.
    stream
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .map_err(SshError::Io)?;
    Ok((host, port))
}

fn forward_local_socket_over_channel(
    client: &mut SshClient,
    local: &mut TcpStream,
) -> Result<(), SshError> {
    local
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(SshError::Io)?;
    local
        .set_write_timeout(Some(Duration::from_millis(2000)))
        .map_err(SshError::Io)?;

    let mut local_closed = false;
    let mut local_buf = [0u8; NETNOX_SSH_MAX_DATA_LEN];
    loop {
        if !local_closed {
            match local.read(&mut local_buf) {
                Ok(0) => {
                    local_closed = true;
                }
                Ok(n) => {
                    client.send_data(&local_buf[..n])?;
                }
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::TimedOut => {}
                Err(err) => return Err(SshError::Io(err)),
            }
        }

        match client.recv_data_with_timeout(NETNOX_SSH_MAX_DATA_LEN, 50)? {
            Some(data) if data.is_empty() => break,
            Some(data) => local.write_all(&data).map_err(SshError::Io)?,
            None => {
                client.maybe_send_keepalive()?;
                if local_closed {
                    break;
                }
            }
        }
    }
    let _ = local.shutdown(Shutdown::Both);
    client.channel_open = false;
    Ok(())
}

fn sftp_list_path(client: &mut SshClient, path: &str) -> Result<(), SshError> {
    client.request_subsystem("sftp")?;

    // INIT(version=3)
    let mut init = Vec::with_capacity(9);
    push_u32(&mut init, 5);
    init.push(SFTP_MSG_INIT);
    push_u32(&mut init, 3);
    client.send_data(&init)?;

    let mut sftp_buf = Vec::new();
    let version_payload = recv_sftp_payload(client, &mut sftp_buf)?;
    if version_payload.first().copied() != Some(SFTP_MSG_VERSION) {
        return Err(SshError::Failed("invalid SFTP version response"));
    }

    let mut req = Vec::with_capacity(128);
    let mut req_payload = Vec::with_capacity(120);
    req_payload.push(SFTP_MSG_REALPATH);
    push_u32(&mut req_payload, 1);
    push_ssh_string(&mut req_payload, path.as_bytes());
    push_u32(&mut req, req_payload.len() as u32);
    req.extend_from_slice(&req_payload);
    client.send_data(&req)?;

    let reply = recv_sftp_payload(client, &mut sftp_buf)?;
    match reply.first().copied() {
        Some(SFTP_MSG_NAME) => {
            let mut off = 1usize;
            let _id = read_u32_at(&reply, &mut off)?;
            let count = read_u32_at(&reply, &mut off)? as usize;
            for _ in 0..count {
                let filename = read_ssh_string(&reply, &mut off)?;
                let _longname = read_ssh_string(&reply, &mut off)?;
                skip_sftp_attrs(&reply, &mut off)?;
                println!("{}", String::from_utf8_lossy(filename));
            }
            Ok(())
        }
        Some(SFTP_MSG_STATUS) => {
            let mut off = 1usize;
            let _id = read_u32_at(&reply, &mut off)?;
            let code = read_u32_at(&reply, &mut off)?;
            let msg = read_ssh_string(&reply, &mut off).unwrap_or(b"");
            Err(SshError::FailedOwned(format!(
                "sftp realpath failed: code={} message={}",
                code,
                String::from_utf8_lossy(msg)
            )))
        }
        _ => Err(SshError::Failed("unexpected SFTP reply")),
    }
}

fn recv_sftp_payload(client: &mut SshClient, pending: &mut Vec<u8>) -> Result<Vec<u8>, SshError> {
    loop {
        if pending.len() >= 4 {
            let mut off = 0usize;
            let packet_len = read_u32_at(pending, &mut off)? as usize;
            if pending.len() >= packet_len + 4 {
                let payload = pending[4..4 + packet_len].to_vec();
                pending.drain(..4 + packet_len);
                return Ok(payload);
            }
        }
        let chunk = client.recv_data(NETNOX_SSH_MAX_DATA_LEN)?;
        if chunk.is_empty() {
            return Err(SshError::Failed("channel closed while reading SFTP packet"));
        }
        pending.extend_from_slice(&chunk);
    }
}

fn skip_sftp_attrs(payload: &[u8], off: &mut usize) -> Result<(), SshError> {
    let flags = read_u32_at(payload, off)?;
    if flags & 0x0000_0001 != 0 {
        // size (u64)
        if *off + 8 > payload.len() {
            return Err(SshError::Failed("invalid sftp attrs size"));
        }
        *off += 8;
    }
    if flags & 0x0000_0002 != 0 {
        let _uid = read_u32_at(payload, off)?;
        let _gid = read_u32_at(payload, off)?;
    }
    if flags & 0x0000_0004 != 0 {
        let _perm = read_u32_at(payload, off)?;
    }
    if flags & 0x0000_0008 != 0 {
        let _atime = read_u32_at(payload, off)?;
        let _mtime = read_u32_at(payload, off)?;
    }
    if flags & 0x8000_0000 != 0 {
        let ext_count = read_u32_at(payload, off)? as usize;
        for _ in 0..ext_count {
            let _etype = read_ssh_string(payload, off)?;
            let _edata = read_ssh_string(payload, off)?;
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = match parse_args(&args) {
        Ok(v) => v,
        Err(_) => {
            print_usage(args.first().map_or("noxssh", String::as_str));
            std::process::exit(1);
        }
    };

    if opts.debug_level > 0 {
        // SAFETY: process environment updates are required to mirror C behavior.
        unsafe { env::set_var("NETNOX_SSH_DEBUG", format!("{}", opts.debug_level)) };
    } else {
        // SAFETY: process environment updates are required to mirror C behavior.
        unsafe { env::remove_var("NETNOX_SSH_DEBUG") };
    }

    let (mut username, host) = match parse_target(&opts.target) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("ERROR: Invalid target: {}", opts.target);
            std::process::exit(1);
        }
    };
    apply_ssh_host_config(&mut opts, &mut username, &host);

    let stream = match connect_tcp(
        &host,
        opts.port,
        Duration::from_millis(opts.connect_timeout_ms),
        Duration::from_millis(opts.read_timeout_ms),
    ) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("ERROR: Failed TCP connect to {}:{}", host, opts.port);
            std::process::exit(1);
        }
    };

    let mut client = SshClient::new(stream, opts.port);
    client.set_host_key_policy(opts.host_key_mode, opts.known_hosts_path.clone(), opts.batch_mode);
    client.set_transport_timers(
        Duration::from_millis(opts.keepalive_interval_ms),
        Duration::from_secs(opts.rekey_interval_s),
    );
    client.set_identity_files(opts.identity_files.clone());
    client.set_preferred_auth_methods(opts.preferred_auth_methods.clone());
    if let Err(err) = client.set_target(&username, &host) {
        eprintln!("ERROR: {err}");
        std::process::exit(1);
    }
    if let Err(err) = client.connect() {
        eprintln!("ERROR: SSH handshake failed ({err})");
        std::process::exit(1);
    }

    println!("Connected to {}:{}", host, opts.port);
    println!(
        "Server identification: {}",
        client.server_ident().unwrap_or("<none>")
    );

    let password = match opts.password {
        Some(p) => p,
        None => match prompt_password() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("ERROR: Failed to read password from stdin.");
                client.close();
                std::process::exit(1);
            }
        },
    };

    if let Err(err) = client.set_password(&password) {
        eprintln!("ERROR: Failed to configure password ({err})");
        client.close();
        std::process::exit(1);
    }

    if let Err(err) = client.authenticate() {
        match err {
            SshError::AuthRejected => eprintln!("Server rejected authentication (wrong password or user?)."),
            _ => eprintln!("Authentication failed. Use -d for debug details."),
        }
        client.close();
        std::process::exit(1);
    }
    println!("Authentication succeeded.");

    if let Some(spec) = opts.local_forward.as_ref() {
        if let Err(err) = run_local_forward(&mut client, spec) {
            eprintln!("ERROR: Local forwarding failed ({err}).");
            client.close();
            std::process::exit(1);
        }
        client.close();
        return;
    }
    if let Some(port) = opts.dynamic_forward_port {
        if let Err(err) = run_dynamic_forward(&mut client, port) {
            eprintln!("ERROR: Dynamic forwarding failed ({err}).");
            client.close();
            std::process::exit(1);
        }
        client.close();
        return;
    }
    if let Some(spec) = opts.remote_forward.as_ref() {
        if let Err(err) = run_remote_forward(&mut client, spec) {
            eprintln!("ERROR: Remote forwarding failed ({err}).");
            client.close();
            std::process::exit(1);
        }
        client.close();
        return;
    }

    if let Err(err) = client.open_session() {
        eprintln!("ERROR: Failed to open SSH session channel ({err}).");
        client.close();
        std::process::exit(1);
    }

    // Command mode runs once and drains output; shell mode stays interactive.
    let run_result = if let Some(path) = opts.sftp_ls.as_deref() {
        sftp_list_path(&mut client, path)
    } else if let Some(command) = opts.command.as_deref() {
        client.exec(command).and_then(|_| print_channel_output(&mut client))
    } else {
        client
            .request_shell_ex(opts.request_pty)
            .and_then(|_| interactive_shell(&mut client))
    };

    if let Err(err) = run_result {
        eprintln!("ERROR: {err}");
        client.close();
        std::process::exit(1);
    }

    client.close();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let input = b"ssh-test-binary-data";
        let enc = base64_encode(input);
        let dec = base64_decode(&enc).expect("base64 decode");
        assert_eq!(dec, input);
    }

    #[test]
    fn parse_target_user_host() {
        let (u, h) = parse_target("alice@example.com").expect("parse target");
        assert_eq!(u, "alice");
        assert_eq!(h, "example.com");
        let (u2, h2) = parse_target("example.com").expect("parse host only");
        assert_eq!(u2, NOXSSH_DEFAULT_USER);
        assert_eq!(h2, "example.com");
    }

    #[test]
    fn parse_openssh_strict_host_key() {
        let mut opts = CliOptions::default();
        parse_openssh_option("StrictHostKeyChecking=accept-new", &mut opts).expect("parse -o");
        assert_eq!(opts.host_key_mode, HostKeyCheckingMode::AcceptNew);
    }

    #[test]
    fn parse_local_forward_variants() {
        let spec = parse_local_forward_spec("8080:db.internal:5432").expect("parse explicit bind");
        assert_eq!(spec.listen_port, 8080);
        assert_eq!(spec.destination_host, "db.internal");
        assert_eq!(spec.destination_port, 5432);

        let spec2 = parse_local_forward_spec("db.internal:5432").expect("parse implicit bind");
        assert_eq!(spec2.listen_port, 5432);
        assert_eq!(spec2.destination_host, "db.internal");
        assert_eq!(spec2.destination_port, 5432);
    }

    #[test]
    fn base64_roundtrip_varied_lengths() {
        for len in 0usize..128 {
            let mut data = Vec::with_capacity(len);
            for i in 0..len {
                data.push(((i * 37 + 11) & 0xff) as u8);
            }
            let enc = base64_encode(&data);
            let dec = base64_decode(&enc).expect("decode");
            assert_eq!(dec, data, "mismatch at len={len}");
        }
    }
}
