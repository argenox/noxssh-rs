use noxtls_crypto::sha256;

use crate::error::SshError;
use crate::protocol::constants::*;
use crate::protocol::encoding::{
    append_mpint_from_fixed_be, namelist_contains, push_ssh_string, read_ssh_string,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KexAlgorithm {
    Curve25519Sha256,
    MlKem768Sha256,
    MlKem768X25519Sha256,
}

pub fn compute_exchange_hash(
    client_ident: &str,
    server_ident: &str,
    kexinit_client_payload: &[u8],
    kexinit_server_payload: &[u8],
    host_key_blob: &[u8],
    client_pub: &[u8],
    server_pub: &[u8],
    shared_secret_raw: &[u8],
) -> Result<[u8; 32], SshError> {
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

pub fn select_kex_algorithm(payload: &[u8]) -> Result<KexAlgorithm, SshError> {
    if payload.len() < 1 + NETNOX_SSH_KEXINIT_COOKIE_LEN || payload[0] != MSG_KEXINIT {
        return Err(SshError::Failed("invalid server kexinit"));
    }
    let mut off = 1 + NETNOX_SSH_KEXINIT_COOKIE_LEN;
    let kex_list = read_ssh_string(payload, &mut off)?;
    for candidate in NETNOX_SSH_KEX_ALG_LIST.split(',') {
        if namelist_contains(kex_list, candidate.as_bytes()) {
            return match candidate {
                SSH_KEX_MLKEM768_HYBRID => Ok(KexAlgorithm::MlKem768X25519Sha256),
                SSH_KEX_MLKEM768_NATIVE => Ok(KexAlgorithm::MlKem768Sha256),
                NETNOX_SSH_REQUIRED_KEX_ALG => Ok(KexAlgorithm::Curve25519Sha256),
                _ => Ok(KexAlgorithm::Curve25519Sha256),
            };
        }
    }
    Err(SshError::Failed("no compatible kex algorithm offered"))
}

pub fn select_host_key_algorithm(payload: &[u8]) -> Result<&'static str, SshError> {
    if payload.len() < 1 + NETNOX_SSH_KEXINIT_COOKIE_LEN || payload[0] != MSG_KEXINIT {
        return Err(SshError::Failed("invalid kexinit"));
    }
    let mut off = 1 + NETNOX_SSH_KEXINIT_COOKIE_LEN;
    let _kex_list = read_ssh_string(payload, &mut off)?;
    let host_key_list = read_ssh_string(payload, &mut off)?;
    for candidate in NETNOX_SSH_HOST_KEY_ALG_LIST.split(',') {
        if namelist_contains(host_key_list, candidate.as_bytes()) {
            return Ok(candidate);
        }
    }
    Err(SshError::Failed("no compatible host key algorithm offered"))
}
