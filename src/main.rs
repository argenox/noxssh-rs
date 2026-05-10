use noxtls_crypto::{
    hmac_sha256, sha256, x25519_generate_private_key_auto, AesCipher, HmacDrbgSha256,
    X25519PublicKey,
};
use std::env;
use std::fmt::{Display, Formatter};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
const MSG_KEXINIT: u8 = 20;
const MSG_NEWKEYS: u8 = 21;
const MSG_KEX_ECDH_INIT: u8 = 30;
const MSG_KEX_ECDH_REPLY: u8 = 31;
const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_FAILURE: u8 = 51;
const MSG_USERAUTH_SUCCESS: u8 = 52;
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

#[derive(Debug)]
enum SshError {
    BadParam(&'static str),
    Failed(&'static str),
    AuthRejected,
    Io(io::Error),
}

impl Display for SshError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadParam(msg) | Self::Failed(msg) => f.write_str(msg),
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
    // High-level state flags for validating call ordering.
    connected: bool,
    kexinit_exchanged: bool,
    userauth_service_ready: bool,
    authenticated: bool,
    channel_open: bool,
    key_exchange_complete: bool,
    local_channel_id: u32,
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
}

impl SshClient {
    fn new(stream: TcpStream, _port: u16) -> Self {
        Self {
            stream,
            client_ident: NETNOX_SSH_DEFAULT_CLIENT_IDENT.to_string(),
            server_ident: String::new(),
            username: String::new(),
            host: String::new(),
            password: String::new(),
            connected: false,
            kexinit_exchanged: false,
            userauth_service_ready: false,
            authenticated: false,
            channel_open: false,
            key_exchange_complete: false,
            local_channel_id: 0,
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
        self.send_userauth_password()?;
        let payload = self.wait_for_message(MSG_USERAUTH_SUCCESS, Some(MSG_USERAUTH_FAILURE))?;
        match payload.first().copied() {
            Some(MSG_USERAUTH_SUCCESS) => {
                self.authenticated = true;
                Ok(())
            }
            Some(MSG_USERAUTH_FAILURE) => Err(SshError::AuthRejected),
            _ => Err(SshError::Failed("unexpected userauth response")),
        }
    }

    fn open_session(&mut self) -> Result<(), SshError> {
        if !(self.connected
            && self.kexinit_exchanged
            && self.key_exchange_complete
            && self.authenticated)
        {
            return Err(SshError::BadParam("invalid state for open session"));
        }
        // Current client uses a single session channel with local id 0.
        self.local_channel_id = 0;
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

    fn close(&mut self) {
        self.connected = false;
        self.kexinit_exchanged = false;
        self.key_exchange_complete = false;
        self.userauth_service_ready = false;
        self.authenticated = false;
        self.channel_open = false;
        self.local_channel_id = 0;
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
            return Ok(());
        }

        self.stream.write_all(&plain)?;
        self.stream.flush()?;
        self.send_seq = self.send_seq.wrapping_add(1);
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
    request_pty: bool,
    debug_level: u8,
}

fn print_usage(program: &str) {
    println!("{program} {NOXSSH_VERSION_STRING}");
    println!("Using NoxTLS Library {NOXTLS_VERSION_STRING}");
    println!(
        "Usage: {program} [-h] [-V] [-d|-dd|-ddd] [-T] [-p port] [-w password] [user@]host [command]"
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

fn parse_args(args: &[String]) -> Result<CliOptions, SshError> {
    if args.len() < 2 {
        return Err(SshError::BadParam("missing arguments"));
    }
    let mut opts = CliOptions {
        port: NETNOX_SSH_DEFAULT_PORT,
        request_pty: true,
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

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, SshError> {
    let mut last_err: Option<io::Error> = None;
    for addr in (host, port)
        .to_socket_addrs()
        .map_err(SshError::Io)?
        .collect::<Vec<_>>()
    {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                stream
                    .set_nodelay(true)
                    .map_err(|_| SshError::Failed("failed setting nodelay"))?;
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
        let data = client.recv_data(NETNOX_SSH_MAX_DATA_LEN)?;
        if data.is_empty() {
            return Ok(());
        }
        io::stdout().write_all(&data)?;
        io::stdout().flush()?;
    }
}

fn drain_shell_output(client: &mut SshClient, first_wait_ms: u64) -> Result<i32, SshError> {
    match client.recv_data_with_timeout(NETNOX_SSH_MAX_DATA_LEN, first_wait_ms)? {
        None => Ok(0),
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
    loop {
        let drain = drain_shell_output(client, 250)?;
        if drain < 0 {
            return Err(SshError::Failed("failed receiving shell output"));
        }
        if drain > 0 {
            println!("Remote channel closed.");
            return Ok(());
        }
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            return Ok(());
        }
        if line == "exit\n" || line == "exit\r\n" {
            return Ok(());
        }
        client.send_data(line.as_bytes())?;
        let drain = drain_shell_output(client, 300)?;
        if drain < 0 {
            return Err(SshError::Failed("failed receiving shell output"));
        }
        if drain > 0 {
            println!("Remote channel closed.");
            return Ok(());
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let opts = match parse_args(&args) {
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

    let (username, host) = match parse_target(&opts.target) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("ERROR: Invalid target: {}", opts.target);
            std::process::exit(1);
        }
    };

    let stream = match connect_tcp(&host, opts.port) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("ERROR: Failed TCP connect to {}:{}", host, opts.port);
            std::process::exit(1);
        }
    };

    let mut client = SshClient::new(stream, opts.port);
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

    if let Err(err) = client.open_session() {
        eprintln!("ERROR: Failed to open SSH session channel ({err}).");
        client.close();
        std::process::exit(1);
    }

    // Command mode runs once and drains output; shell mode stays interactive.
    let run_result = if let Some(command) = opts.command.as_deref() {
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
