use noxtls_crypto::{
    ed25519_verify, rsassa_sha256_sign, Ed25519PrivateKey, Ed25519PublicKey, RsaPrivateKey,
    RsaPublicKey,
};
use noxtls_x509::{
    parse_pkcs8_private_key_info_der, private_key_pem_to_der_pkcs8, rsa_private_key_from_pem_pkcs1,
    rsa_private_key_from_pem_pkcs8,
};

use crate::error::SshError;
use crate::protocol::encoding::{push_ssh_string, read_ssh_string, read_u32_at};
use crate::transport::new_drbg;

#[derive(Clone)]
pub enum HostKey {
    Ed25519(Ed25519PrivateKey),
    Rsa {
        private: RsaPrivateKey,
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    },
}

impl HostKey {
    pub fn generate_ed25519() -> Result<Self, SshError> {
        let mut drbg = new_drbg()?;
        let seed = drbg
            .generate(32, b"host-key")
            .map_err(|_| SshError::Failed("host key generation failed"))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&seed);
        Ok(Self::Ed25519(Ed25519PrivateKey::from_seed(&arr)))
    }

    pub fn from_pem(pem: &str) -> Result<Self, SshError> {
        match load_private_signer(pem, None)? {
            PrivateSigner::Ed25519(k) => Ok(Self::Ed25519(k)),
            PrivateSigner::Rsa { private, modulus, exponent } => Ok(Self::Rsa {
                private,
                modulus,
                exponent,
            }),
        }
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "ssh-ed25519",
            Self::Rsa { .. } => "rsa-sha2-256",
        }
    }

    pub fn public_blob(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(k) => {
                let public = k.verifying_key().to_bytes();
                let mut blob = Vec::new();
                push_ssh_string(&mut blob, b"ssh-ed25519");
                push_ssh_string(&mut blob, &public);
                blob
            }
            Self::Rsa { modulus, exponent, .. } => {
                let mut blob = Vec::new();
                push_ssh_string(&mut blob, b"ssh-rsa");
                push_ssh_string(&mut blob, exponent);
                push_ssh_string(&mut blob, modulus);
                blob
            }
        }
    }

    pub fn sign_exchange_hash(&self, exchange_hash: &[u8; 32]) -> Result<Vec<u8>, SshError> {
        match self {
            Self::Ed25519(k) => {
                let raw_sig = k.sign(exchange_hash);
                let mut sig_blob = Vec::new();
                push_ssh_string(&mut sig_blob, b"ssh-ed25519");
                push_ssh_string(&mut sig_blob, &raw_sig);
                Ok(sig_blob)
            }
            Self::Rsa { private, .. } => {
                let raw_sig = rsassa_sha256_sign(private, exchange_hash)
                    .map_err(|_| SshError::Failed("rsa host key signing failed"))?;
                let mut sig_blob = Vec::new();
                push_ssh_string(&mut sig_blob, b"rsa-sha2-256");
                push_ssh_string(&mut sig_blob, &raw_sig);
                Ok(sig_blob)
            }
        }
    }

    pub fn fingerprint_sha256(&self) -> String {
        let blob = self.public_blob();
        let hash = noxtls_crypto::sha256(&blob);
        use crate::protocol::encoding::base64_encode;
        format!("SHA256:{}", base64_encode(&hash).trim_end_matches('='))
    }
}

pub enum PrivateSigner {
    Rsa {
        private: RsaPrivateKey,
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    },
    Ed25519(Ed25519PrivateKey),
}

pub fn load_private_signer(pem: &str, identity_hint: Option<&std::path::PathBuf>) -> Result<PrivateSigner, SshError> {
    if pem.contains("BEGIN OPENSSH PRIVATE KEY") {
        return parse_openssh_private_key(pem, identity_hint);
    }

    if let Ok(private_key) =
        rsa_private_key_from_pem_pkcs1(pem).or_else(|_| rsa_private_key_from_pem_pkcs8(pem))
    {
        return Err(SshError::Failed(
            "RSA PEM host keys require OpenSSH format with public components",
        ));
    }

    let der = private_key_pem_to_der_pkcs8(pem)
        .map_err(|_| SshError::Failed("failed to parse private key from identity file"))?;
    let info = parse_pkcs8_private_key_info_der(&der)
        .map_err(|_| SshError::Failed("invalid pkcs8 private key"))?;
    if info.algorithm_oid.as_slice() == [0x2b, 0x65, 0x70] {
        let seed = parse_ed25519_seed_from_pkcs8_private_key(&info.private_key)
            .ok_or(SshError::Failed("invalid ed25519 private key payload"))?;
        return Ok(PrivateSigner::Ed25519(Ed25519PrivateKey::from_seed(&seed)));
    }

    Err(SshError::Failed("unsupported private key type"))
}

pub fn parse_authorized_key(line: &str) -> Option<(String, Vec<u8>)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let mut fields = trimmed.split_whitespace();
    let key_type = fields.next()?.to_string();
    let key_data = fields.next()?;
    let blob = crate::protocol::encoding::base64_decode(key_data)?;
    Some((key_type, blob))
}

pub fn verify_publickey_signature(
    algorithm: &str,
    pub_blob: &[u8],
    session_id: &[u8],
    signed_payload: &[u8],
    signature_blob: &[u8],
) -> Result<bool, SshError> {
    let mut off = 0usize;
    let sig_alg = read_ssh_string(signature_blob, &mut off)?;
    let raw_sig = read_ssh_string(signature_blob, &mut off)?;
    if off != signature_blob.len() {
        return Ok(false);
    }

    let mut signed_data = Vec::new();
    push_ssh_string(&mut signed_data, session_id);
    signed_data.extend_from_slice(signed_payload);

    if algorithm == "ssh-ed25519" || sig_alg == b"ssh-ed25519" {
        let mut poff = 0usize;
        let key_type = read_ssh_string(pub_blob, &mut poff)?;
        let pubkey = read_ssh_string(pub_blob, &mut poff)?;
        if key_type != b"ssh-ed25519" || pubkey.len() != 32 {
            return Ok(false);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pubkey);
        let pk = Ed25519PublicKey::from_bytes(&arr).map_err(|_| SshError::Failed("invalid ed25519 public key"))?;
        return Ok(ed25519_verify(&pk, &signed_data, raw_sig).is_ok());
    }

    if algorithm == "ssh-rsa" || algorithm == "rsa-sha2-256" || sig_alg == b"rsa-sha2-256" {
        let (n, e) = parse_rsa_public_blob(pub_blob)?;
        let public = RsaPublicKey::from_be_bytes(&n, &e)
            .map_err(|_| SshError::Failed("invalid rsa public key"))?;
        return Ok(public
            .verify_pkcs1_v15_sha256(&signed_data, raw_sig)
            .is_ok());
    }

    let _ = algorithm;
    Ok(false)
}

fn parse_rsa_public_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SshError> {
    let mut off = 0usize;
    let _key_type = read_ssh_string(blob, &mut off)?;
    let e = read_ssh_string(blob, &mut off)?;
    let n = read_ssh_string(blob, &mut off)?;
    Ok((n.to_vec(), e.to_vec()))
}

fn parse_openssh_private_key(text: &str, identity_hint: Option<&std::path::PathBuf>) -> Result<PrivateSigner, SshError> {
    let data = decode_pem_block(
        text,
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----END OPENSSH PRIVATE KEY-----",
    )
    .ok_or(SshError::Failed("not an OpenSSH private key"))?;

    let mut off = 0usize;
    if data.len() < 15 || &data[..15] != b"openssh-key-v1\0" {
        return Err(SshError::Failed("invalid OpenSSH key magic"));
    }
    off += 15;
    let ciphername = read_ssh_string(&data, &mut off)?;
    let kdfname = read_ssh_string(&data, &mut off)?;
    let kdfoptions = crate::protocol::encoding::read_ssh_string_owned(&data, &mut off)?;

    let key_count = read_u32_at(&data, &mut off)? as usize;
    if key_count == 0 {
        return Err(SshError::Failed("OpenSSH private key has no keys"));
    }
    for _ in 0..key_count {
        let _ = read_ssh_string(&data, &mut off)?;
    }
    let private_block_encrypted = crate::protocol::encoding::read_ssh_string_owned(&data, &mut off)?;
    let private_block = if ciphername == b"none" && kdfname == b"none" {
        private_block_encrypted
    } else if kdfname == b"bcrypt" {
        decrypt_openssh_private_block(ciphername, &kdfoptions, &private_block_encrypted, identity_hint)?
    } else {
        return Err(SshError::Failed("unsupported OpenSSH key encryption settings"));
    };
    let mut poff = 0usize;
    let check1 = read_u32_at(&private_block, &mut poff)?;
    let check2 = read_u32_at(&private_block, &mut poff)?;
    if check1 != check2 {
        return Err(SshError::Failed("OpenSSH private key checkints mismatch"));
    }
    let key_type = read_ssh_string(&private_block, &mut poff)?;
    if key_type == b"ssh-ed25519" {
        let _public = read_ssh_string(&private_block, &mut poff)?;
        let private = read_ssh_string(&private_block, &mut poff)?;
        if private.len() < 32 {
            return Err(SshError::Failed("invalid OpenSSH ed25519 private key"));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&private[..32]);
        return Ok(PrivateSigner::Ed25519(Ed25519PrivateKey::from_seed(&seed)));
    }
    if key_type == b"ssh-rsa" {
        let n = crate::protocol::encoding::read_ssh_mpint(&private_block, &mut poff)?;
        let e = crate::protocol::encoding::read_ssh_mpint(&private_block, &mut poff)?;
        let d = crate::protocol::encoding::read_ssh_mpint(&private_block, &mut poff)?;
        let _iqmp = crate::protocol::encoding::read_ssh_mpint(&private_block, &mut poff)?;
        let _p = crate::protocol::encoding::read_ssh_mpint(&private_block, &mut poff)?;
        let _q = crate::protocol::encoding::read_ssh_mpint(&private_block, &mut poff)?;
        let key = RsaPrivateKey::from_be_bytes(&n, &d)
            .map_err(|_| SshError::Failed("invalid OpenSSH RSA private key"))?;
        return Ok(PrivateSigner::Rsa {
            private: key,
            modulus: n,
            exponent: e,
        });
    }

    Err(SshError::Failed("unsupported OpenSSH private key type"))
}

fn decode_pem_block(text: &str, begin_marker: &str, end_marker: &str) -> Option<Vec<u8>> {
    let start = text.find(begin_marker)?;
    let end = text.find(end_marker)?;
    if end <= start {
        return None;
    }
    let body = &text[start + begin_marker.len()..end];
    let mut b64 = String::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.contains(':') {
            continue;
        }
        b64.push_str(trimmed);
    }
    crate::protocol::encoding::base64_decode(&b64)
}

#[derive(Clone, Copy)]
enum OpensshAesMode {
    Ctr,
    Cbc,
}

fn openssh_cipher_params(ciphername: &[u8]) -> Option<(usize, usize, OpensshAesMode)> {
    match ciphername {
        b"aes128-ctr" => Some((16, 16, OpensshAesMode::Ctr)),
        b"aes192-ctr" => Some((24, 16, OpensshAesMode::Ctr)),
        b"aes256-ctr" => Some((32, 16, OpensshAesMode::Ctr)),
        b"aes128-cbc" => Some((16, 16, OpensshAesMode::Cbc)),
        b"aes192-cbc" => Some((24, 16, OpensshAesMode::Cbc)),
        b"aes256-cbc" => Some((32, 16, OpensshAesMode::Cbc)),
        _ => None,
    }
}

fn parse_openssh_bcrypt_kdf_options(kdfoptions: &[u8]) -> Result<(Vec<u8>, u32), SshError> {
    let mut off = 0usize;
    let salt = crate::protocol::encoding::read_ssh_string_owned(kdfoptions, &mut off)?;
    let rounds = read_u32_at(kdfoptions, &mut off)?;
    if off != kdfoptions.len() {
        return Err(SshError::Failed("invalid OpenSSH bcrypt kdf options"));
    }
    if rounds == 0 {
        return Err(SshError::Failed("invalid OpenSSH bcrypt rounds"));
    }
    Ok((salt, rounds))
}

fn decrypt_openssh_private_block(
    ciphername: &[u8],
    kdfoptions: &[u8],
    encrypted: &[u8],
    identity_hint: Option<&std::path::PathBuf>,
) -> Result<Vec<u8>, SshError> {
    use noxtls_crypto::{aes_cbc_decrypt, aes_ctr_apply, bcrypt_pbkdf_sha512, AesCipher};

    let (key_len, iv_len, mode) = openssh_cipher_params(ciphername)
        .ok_or(SshError::Failed("unsupported OpenSSH ciphername"))?;
    let (salt, rounds) = parse_openssh_bcrypt_kdf_options(kdfoptions)?;
    let passphrase = prompt_key_passphrase(identity_hint)?;
    if passphrase.is_empty() {
        return Err(SshError::Failed("empty key passphrase"));
    }

    let key_iv = bcrypt_pbkdf_sha512(passphrase.as_bytes(), &salt, rounds, key_len + iv_len)
        .map_err(|e| SshError::FailedOwned(format!("bcrypt_pbkdf failed: {e}")))?;
    let key = &key_iv[..key_len];
    let iv_src = &key_iv[key_len..key_len + iv_len];
    let mut iv = [0u8; 16];
    iv.copy_from_slice(iv_src);

    let cipher = AesCipher::new(key).map_err(|e| SshError::FailedOwned(format!("invalid AES key: {e}")))?;
    match mode {
        OpensshAesMode::Ctr => Ok(aes_ctr_apply(&cipher, &iv, encrypted)),
        OpensshAesMode::Cbc => aes_cbc_decrypt(&cipher, &iv, encrypted)
            .map_err(|e| SshError::FailedOwned(format!("OpenSSH key decrypt failed: {e}"))),
    }
}

fn prompt_key_passphrase(identity_hint: Option<&std::path::PathBuf>) -> Result<String, SshError> {
    #[cfg(feature = "cli")]
    {
        let prompt = if let Some(path) = identity_hint {
            format!("Key passphrase ({}): ", path.display())
        } else {
            "Key passphrase: ".to_string()
        };
        return rpassword::prompt_password(prompt).map_err(SshError::Io);
    }
    #[cfg(not(feature = "cli"))]
    {
        let _ = identity_hint;
        Err(SshError::Failed("encrypted private key requires cli feature"))
    }
}

fn parse_ed25519_seed_from_pkcs8_private_key(private_key: &[u8]) -> Option<[u8; 32]> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::encoding::{push_u32, push_ssh_string};

    #[test]
    fn openssh_cipher_params_maps_known_ciphers() {
        assert!(openssh_cipher_params(b"aes256-ctr").is_some());
        assert!(openssh_cipher_params(b"aes256-cbc").is_some());
        assert!(openssh_cipher_params(b"chacha20-poly1305@openssh.com").is_none());
    }

    #[test]
    fn parse_bcrypt_kdf_options_roundtrip() {
        let mut opts = Vec::new();
        push_ssh_string(&mut opts, b"salt-bytes");
        push_u32(&mut opts, 16);
        let (salt, rounds) = parse_openssh_bcrypt_kdf_options(&opts).expect("kdf opts");
        assert_eq!(salt, b"salt-bytes");
        assert_eq!(rounds, 16);
    }
}
