use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use noxtls_crypto::{hmac_sha256, AesCipher, HmacDrbgSha256};

use crate::error::SshError;
use crate::protocol::constants::*;
use crate::protocol::encoding::{append_mpint_from_fixed_be, push_u32};
use noxtls_crypto::sha256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

struct DirectionKeys {
    iv: [u8; 16],
    key: [u8; 16],
    mac_key: [u8; 32],
    counter: [u8; 16],
    cipher: Option<AesCipher>,
}

impl Default for DirectionKeys {
    fn default() -> Self {
        Self {
            iv: [0; 16],
            key: [0; 16],
            mac_key: [0; 32],
            counter: [0; 16],
            cipher: None,
        }
    }
}

pub struct TransportSession {
    pub stream: TcpStream,
    pub role: Role,
    pub key_exchange_complete: bool,
    send: DirectionKeys,
    recv: DirectionKeys,
    send_seq: u32,
    recv_seq: u32,
    pub session_id: [u8; 32],
    pub session_id_len: usize,
    shared_secret_raw: [u8; 32],
    pub sent_packet_count: u64,
    pub recv_packet_count: u64,
    pub sent_payload_bytes: u64,
    pub recv_payload_bytes: u64,
}

impl TransportSession {
    pub fn new(stream: TcpStream, role: Role) -> Self {
        Self {
            stream,
            role,
            key_exchange_complete: false,
            send: DirectionKeys::default(),
            recv: DirectionKeys::default(),
            send_seq: 0,
            recv_seq: 0,
            session_id: [0; 32],
            session_id_len: 0,
            shared_secret_raw: [0; 32],
            sent_packet_count: 0,
            recv_packet_count: 0,
            sent_payload_bytes: 0,
            recv_payload_bytes: 0,
        }
    }

    pub fn set_session_id(&mut self, session_id: [u8; 32]) {
        self.session_id = session_id;
        self.session_id_len = 32;
    }

    pub fn session_id(&self) -> &[u8] {
        &self.session_id[..self.session_id_len]
    }

    pub fn set_shared_secret(&mut self, secret: [u8; 32]) {
        self.shared_secret_raw = secret;
    }

    pub fn derive_transport_keys(&mut self) -> Result<(), SshError> {
        let (c2s_iv, s2c_iv, c2s_key, s2c_key, c2s_mac, s2c_mac) = match self.role {
            Role::Client => (
                self.derive_key_block(b'A', 16)?,
                self.derive_key_block(b'B', 16)?,
                self.derive_key_block(b'C', 16)?,
                self.derive_key_block(b'D', 16)?,
                self.derive_key_block(b'E', 32)?,
                self.derive_key_block(b'F', 32)?,
            ),
            Role::Server => (
                self.derive_key_block(b'A', 16)?,
                self.derive_key_block(b'B', 16)?,
                self.derive_key_block(b'C', 16)?,
                self.derive_key_block(b'D', 16)?,
                self.derive_key_block(b'E', 32)?,
                self.derive_key_block(b'F', 32)?,
            ),
        };

        let (send_iv, send_key, send_mac, recv_iv, recv_key, recv_mac) = match self.role {
            Role::Client => (c2s_iv, c2s_key, c2s_mac, s2c_iv, s2c_key, s2c_mac),
            Role::Server => (s2c_iv, s2c_key, s2c_mac, c2s_iv, c2s_key, c2s_mac),
        };

        self.send.iv.copy_from_slice(&send_iv);
        self.send.key.copy_from_slice(&send_key);
        self.send.mac_key.copy_from_slice(&send_mac);
        self.send.counter = self.send.iv;
        self.send.cipher = Some(
            AesCipher::new(&self.send.key).map_err(|_| SshError::Failed("failed to init send aes"))?,
        );

        self.recv.iv.copy_from_slice(&recv_iv);
        self.recv.key.copy_from_slice(&recv_key);
        self.recv.mac_key.copy_from_slice(&recv_mac);
        self.recv.counter = self.recv.iv;
        self.recv.cipher = Some(
            AesCipher::new(&self.recv.key).map_err(|_| SshError::Failed("failed to init recv aes"))?,
        );
        Ok(())
    }

    fn derive_key_block(&self, selector: u8, out_len: usize) -> Result<Vec<u8>, SshError> {
        if self.session_id_len == 0 {
            return Err(SshError::BadParam("session id missing"));
        }
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

    pub fn send_packet(&mut self, payload: &[u8]) -> Result<(), SshError> {
        if payload.is_empty() {
            return Err(SshError::BadParam("empty payload"));
        }
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
            let mut mac_input = Vec::with_capacity(4 + plain.len());
            push_u32(&mut mac_input, self.send_seq);
            mac_input.extend_from_slice(&plain);
            let mac = hmac_sha256(&self.send.mac_key, &mac_input);

            let cipher = self
                .send
                .cipher
                .as_ref()
                .ok_or(SshError::Failed("send cipher unavailable"))?;
            let enc = aes_ctr_apply_with_counter(cipher, &mut self.send.counter, &plain);

            self.stream.write_all(&enc)?;
            self.stream.write_all(&mac)?;
            self.stream.flush()?;
            self.send_seq = self.send_seq.wrapping_add(1);
            self.sent_packet_count = self.sent_packet_count.saturating_add(1);
            self.sent_payload_bytes = self.sent_payload_bytes.saturating_add(payload.len() as u64);
            return Ok(());
        }

        self.stream.write_all(&plain)?;
        self.stream.flush()?;
        self.send_seq = self.send_seq.wrapping_add(1);
        self.sent_packet_count = self.sent_packet_count.saturating_add(1);
        self.sent_payload_bytes = self.sent_payload_bytes.saturating_add(payload.len() as u64);
        Ok(())
    }

    pub fn recv_packet(&mut self) -> Result<Vec<u8>, SshError> {
        if self.key_exchange_complete {
            let cipher = self
                .recv
                .cipher
                .as_ref()
                .ok_or(SshError::Failed("recv cipher unavailable"))?
                .clone();

            let mut enc_first = [0u8; NETNOX_SSH_AES_BLOCK_LEN];
            self.recv_exact(&mut enc_first)?;
            let first_plain = aes_ctr_apply_with_counter(&cipher, &mut self.recv.counter, &enc_first);
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
            let rest_plain = aes_ctr_apply_with_counter(&cipher, &mut self.recv.counter, &enc_rest);

            let mut plain = Vec::with_capacity(plain_len);
            plain.extend_from_slice(&first_plain);
            plain.extend_from_slice(&rest_plain);

            let mut mac_recv = [0u8; NETNOX_SSH_MAC_LEN];
            self.recv_exact(&mut mac_recv)?;

            let mut mac_input = Vec::with_capacity(4 + plain_len);
            push_u32(&mut mac_input, self.recv_seq);
            mac_input.extend_from_slice(&plain);
            let mac_expected = hmac_sha256(&self.recv.mac_key, &mac_input);
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
            self.recv_payload_bytes = self.recv_payload_bytes.saturating_add(payload_len as u64);
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
        self.recv_payload_bytes = self.recv_payload_bytes.saturating_add(payload_len as u64);
        Ok(packet[1..1 + payload_len].to_vec())
    }

    pub fn recv_packet_with_timeout(&mut self, timeout_ms: u64) -> Result<Option<Vec<u8>>, SshError> {
        let timeout_ms = timeout_ms.max(1);
        let old = self.stream.read_timeout()?;
        self.stream
            .set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
        let recv = self.recv_packet();
        self.stream.set_read_timeout(old)?;
        match recv {
            Ok(v) => Ok(Some(v)),
            Err(SshError::Io(err))
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    pub fn wait_for_message(
        &mut self,
        expect_a: u8,
        expect_b: Option<u8>,
    ) -> Result<Vec<u8>, SshError> {
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

    pub fn recv_exact(&mut self, out: &mut [u8]) -> Result<(), SshError> {
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

    pub fn recv_line(&mut self) -> Result<String, SshError> {
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

    pub fn exchange_ident(&mut self, local_ident: &str, is_server: bool) -> Result<String, SshError> {
        if is_server {
            let tx_ident = format!("{local_ident}\r\n");
            self.stream.write_all(tx_ident.as_bytes())?;
            self.stream.flush()?;
            crate::protocol::ssh_debug(1, format_args!("sent ident: {local_ident}"));
        }

        let mut peer_ident = String::new();
        for _ in 0..NETNOX_SSH_MAX_BANNER_LINES {
            let line = self.recv_line()?;
            crate::protocol::ssh_debug(1, format_args!("recv line: {line}"));
            if line.starts_with("SSH-") {
                peer_ident = line;
                break;
            }
        }
        if peer_ident.is_empty() {
            return Err(SshError::Failed("no SSH identification line"));
        }

        if !is_server {
            let tx_ident = format!("{local_ident}\r\n");
            self.stream.write_all(tx_ident.as_bytes())?;
            self.stream.flush()?;
            crate::protocol::ssh_debug(1, format_args!("sent ident: {local_ident}"));
        }

        Ok(peer_ident)
    }
}

fn increment_be(counter: &mut [u8; 16]) {
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

pub fn new_drbg() -> Result<HmacDrbgSha256, SshError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    let mut entropy = [0u8; 32];
    entropy[..8].copy_from_slice(&now.as_secs().to_be_bytes());
    entropy[8..16].copy_from_slice(&(now.subsec_nanos() as u64).to_be_bytes());
    entropy[16..24].copy_from_slice(&(std::process::id() as u64).to_be_bytes());
    entropy[24..32].copy_from_slice(&(now.as_nanos() as u64).to_be_bytes());
    HmacDrbgSha256::new(&entropy, b"noxssh-rs", b"noxssh-rs")
        .map_err(|_| SshError::Failed("drbg initialization failed"))
}

pub fn fill_random(out: &mut [u8]) -> Result<(), SshError> {
    let mut drbg = new_drbg()?;
    let bytes = drbg
        .generate(out.len(), b"fill_random")
        .map_err(|_| SshError::Failed("drbg generate failed"))?;
    out.copy_from_slice(&bytes);
    Ok(())
}
