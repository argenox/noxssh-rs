use crate::error::SshError;
use crate::protocol::constants::*;

pub fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn push_ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    push_u32(out, data.len() as u32);
    out.extend_from_slice(data);
}

pub fn push_namelist(out: &mut Vec<u8>, text: &str) {
    push_ssh_string(out, text.as_bytes());
}

pub fn read_u32_at(payload: &[u8], offset: &mut usize) -> Result<u32, SshError> {
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

pub fn read_ssh_string<'a>(payload: &'a [u8], offset: &mut usize) -> Result<&'a [u8], SshError> {
    let len = read_u32_at(payload, offset)? as usize;
    if *offset + len > payload.len() {
        return Err(SshError::Failed("payload underflow reading string"));
    }
    let out = &payload[*offset..*offset + len];
    *offset += len;
    Ok(out)
}

pub fn read_ssh_string_owned(payload: &[u8], offset: &mut usize) -> Result<Vec<u8>, SshError> {
    Ok(read_ssh_string(payload, offset)?.to_vec())
}

pub fn read_ssh_mpint(payload: &[u8], offset: &mut usize) -> Result<Vec<u8>, SshError> {
    let raw = read_ssh_string(payload, offset)?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    if raw[0] == 0 {
        return Ok(raw[1..].to_vec());
    }
    Ok(raw.to_vec())
}

pub fn append_mpint_from_fixed_be(out: &mut Vec<u8>, be_value: &[u8]) {
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

pub fn namelist_contains(list: &[u8], token: &[u8]) -> bool {
    list.split(|b| *b == b',').any(|part| part == token)
}

pub fn base64_encode(input: &[u8]) -> String {
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

pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
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

pub fn ssh_host_key_type_from_blob(blob: &[u8]) -> Option<String> {
    let mut off = 0usize;
    let key_type = read_ssh_string(blob, &mut off).ok()?;
    Some(String::from_utf8_lossy(key_type).to_string())
}

pub fn build_kexinit_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity(1024);
    payload.push(MSG_KEXINIT);
    let mut cookie = [0u8; NETNOX_SSH_KEXINIT_COOKIE_LEN];
    let _ = crate::transport::fill_random(&mut cookie);
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
