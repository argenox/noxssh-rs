use noxtls_crypto::{
    mlkem_decapsulate, mlkem_encapsulate_auto, mlkem_generate_keypair_auto, sha256, MlKemPublicKey,
    x25519_generate_private_key_auto, X25519PublicKey,
};

use crate::error::SshError;
use crate::keys::HostKey;
use crate::protocol::constants::*;
use crate::protocol::encoding::{push_ssh_string, read_ssh_string, read_ssh_string_owned};
use crate::protocol::kex::{compute_exchange_hash, select_kex_algorithm, KexAlgorithm};
use crate::protocol::build_kexinit_payload;
use crate::transport::{new_drbg, TransportSession};

use super::KexResult;

pub fn server_exchange_kexinit(
    transport: &mut TransportSession,
    client_ident: &str,
    server_ident: &str,
    host_key: &HostKey,
) -> Result<KexResult, SshError> {
    let rx_payload = transport.recv_packet()?;
    if rx_payload.is_empty() || rx_payload[0] != MSG_KEXINIT {
        return Err(SshError::Failed("expected client kexinit"));
    }
    if rx_payload.len() > NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN {
        return Err(SshError::Failed("client kexinit too large"));
    }
    let tx_payload = build_kexinit_payload();
    transport.send_packet(&tx_payload)?;
    let selected = select_kex_algorithm(&rx_payload)?;
    run_server_kex(
        transport,
        client_ident,
        server_ident,
        &rx_payload,
        &tx_payload,
        selected,
        host_key,
    )
}

fn run_server_kex(
    transport: &mut TransportSession,
    client_ident: &str,
    server_ident: &str,
    kexinit_client: &[u8],
    kexinit_server: &[u8],
    algo: KexAlgorithm,
    host_key: &HostKey,
) -> Result<KexResult, SshError> {
    let (session_id, shared_secret) = match algo {
        KexAlgorithm::Curve25519Sha256 => server_curve25519(
            transport,
            client_ident,
            server_ident,
            kexinit_client,
            kexinit_server,
            host_key,
        )?,
        KexAlgorithm::MlKem768Sha256 => server_mlkem_native(
            transport,
            client_ident,
            server_ident,
            kexinit_client,
            kexinit_server,
            host_key,
        )?,
        KexAlgorithm::MlKem768X25519Sha256 => server_mlkem_hybrid(
            transport,
            client_ident,
            server_ident,
            kexinit_client,
            kexinit_server,
            host_key,
        )?,
    };
    transport.send_packet(&[MSG_NEWKEYS])?;
    let newkeys = transport.wait_for_message(MSG_NEWKEYS, None)?;
    if newkeys.first().copied() != Some(MSG_NEWKEYS) {
        return Err(SshError::Failed("expected newkeys"));
    }
    transport.set_session_id(session_id);
    transport.set_shared_secret(shared_secret);
    transport.derive_transport_keys()?;
    transport.key_exchange_complete = true;
    Ok(KexResult {
        session_id,
        shared_secret,
    })
}

fn server_curve25519(
    transport: &mut TransportSession,
    client_ident: &str,
    server_ident: &str,
    kexinit_client: &[u8],
    kexinit_server: &[u8],
    host_key: &HostKey,
) -> Result<([u8; 32], [u8; 32]), SshError> {
    let init = transport.wait_for_message(MSG_KEX_ECDH_INIT, None)?;
    let mut off = 1usize;
    let client_pub = read_ssh_string_owned(&init, &mut off)?;
    if client_pub.len() != 32 {
        return Err(SshError::Failed("invalid client ecdh public key"));
    }
    let mut drbg = new_drbg()?;
    let server_priv = x25519_generate_private_key_auto(&mut drbg)
        .map_err(|_| SshError::Failed("x25519 key generation failed"))?;
    let server_pub = server_priv.public_key().bytes;
    let mut client_pub_arr = [0u8; 32];
    client_pub_arr.copy_from_slice(&client_pub);
    let shared = server_priv
        .diffie_hellman_checked(X25519PublicKey::from_bytes(client_pub_arr))
        .map_err(|_| SshError::Failed("x25519 shared secret failed"))?;

    let host_key_blob = host_key.public_blob();
    let session_id = compute_exchange_hash(
        client_ident,
        server_ident,
        kexinit_client,
        kexinit_server,
        &host_key_blob,
        &client_pub,
        &server_pub,
        &shared,
    )?;
    let signature = host_key.sign_exchange_hash(&session_id)?;

    let mut reply = Vec::new();
    reply.push(MSG_KEX_ECDH_REPLY);
    push_ssh_string(&mut reply, &host_key_blob);
    push_ssh_string(&mut reply, &server_pub);
    push_ssh_string(&mut reply, &signature);
    transport.send_packet(&reply)?;
    Ok((session_id, shared))
}

fn server_mlkem_native(
    transport: &mut TransportSession,
    client_ident: &str,
    server_ident: &str,
    kexinit_client: &[u8],
    kexinit_server: &[u8],
    host_key: &HostKey,
) -> Result<([u8; 32], [u8; 32]), SshError> {
    let init = transport.wait_for_message(MSG_KEX_ECDH_INIT, None)?;
    let mut off = 1usize;
    let client_pk = read_ssh_string_owned(&init, &mut off)?;
    let client_public = MlKemPublicKey::from_bytes(&client_pk)
        .map_err(|_| SshError::Failed("invalid mlkem client public key"))?;
    let mut drbg = new_drbg()?;
    let (server_ct, mlkem_shared) = mlkem_encapsulate_auto(&client_public, &mut drbg)
        .map_err(|_| SshError::Failed("mlkem encapsulation failed"))?;

    let host_key_blob = host_key.public_blob();
    let session_id = compute_exchange_hash(
        client_ident,
        server_ident,
        kexinit_client,
        kexinit_server,
        &host_key_blob,
        &client_pk,
        &server_ct,
        &mlkem_shared,
    )?;
    let signature = host_key.sign_exchange_hash(&session_id)?;
    let mut reply = Vec::new();
    reply.push(MSG_KEX_ECDH_REPLY);
    push_ssh_string(&mut reply, &host_key_blob);
    push_ssh_string(&mut reply, &server_ct);
    push_ssh_string(&mut reply, &signature);
    transport.send_packet(&reply)?;
    Ok((session_id, mlkem_shared))
}

fn server_mlkem_hybrid(
    transport: &mut TransportSession,
    client_ident: &str,
    server_ident: &str,
    kexinit_client: &[u8],
    kexinit_server: &[u8],
    host_key: &HostKey,
) -> Result<([u8; 32], [u8; 32]), SshError> {
    let init = transport.wait_for_message(MSG_KEX_ECDH_INIT, None)?;
    let mut off = 1usize;
    let client_combo = read_ssh_string_owned(&init, &mut off)?;
    let mut coff = 0usize;
    let client_x25519 = read_ssh_string(&client_combo, &mut coff)?;
    let client_mlkem_pk = read_ssh_string(&client_combo, &mut coff)?;
    if coff != client_combo.len() || client_x25519.len() != 32 {
        return Err(SshError::Failed("invalid hybrid client payload"));
    }

    let mut drbg = new_drbg()?;
    let server_x_priv = x25519_generate_private_key_auto(&mut drbg)
        .map_err(|_| SshError::Failed("x25519 key generation failed"))?;
    let server_x_pub = server_x_priv.public_key().bytes;
    let mut client_x_arr = [0u8; 32];
    client_x_arr.copy_from_slice(client_x25519);
    let x_shared = server_x_priv
        .diffie_hellman_checked(X25519PublicKey::from_bytes(client_x_arr))
        .map_err(|_| SshError::Failed("x25519 shared secret failed"))?;

    let client_mlkem_public = MlKemPublicKey::from_bytes(client_mlkem_pk)
        .map_err(|_| SshError::Failed("invalid mlkem client public key"))?;
    let (server_mlkem_ct, mlkem_shared) = mlkem_encapsulate_auto(&client_mlkem_public, &mut drbg)
        .map_err(|_| SshError::Failed("mlkem encapsulation failed"))?;

    let mut hybrid_material = Vec::with_capacity(64);
    hybrid_material.extend_from_slice(&x_shared);
    hybrid_material.extend_from_slice(&mlkem_shared);
    let hybrid_shared = sha256(&hybrid_material);

    let mut server_combo = Vec::new();
    push_ssh_string(&mut server_combo, &server_x_pub);
    push_ssh_string(&mut server_combo, &server_mlkem_ct);

    let host_key_blob = host_key.public_blob();
    let session_id = compute_exchange_hash(
        client_ident,
        server_ident,
        kexinit_client,
        kexinit_server,
        &host_key_blob,
        &client_combo,
        &server_combo,
        &hybrid_shared,
    )?;
    let signature = host_key.sign_exchange_hash(&session_id)?;
    let mut reply = Vec::new();
    reply.push(MSG_KEX_ECDH_REPLY);
    push_ssh_string(&mut reply, &host_key_blob);
    push_ssh_string(&mut reply, &server_combo);
    push_ssh_string(&mut reply, &signature);
    transport.send_packet(&reply)?;
    Ok((session_id, hybrid_shared))
}
