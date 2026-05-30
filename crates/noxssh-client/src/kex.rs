use noxtls_crypto::{
    mlkem_decapsulate, mlkem_encapsulate_auto, mlkem_generate_keypair_auto, sha256, MlKemPublicKey,
    x25519_generate_private_key_auto, X25519PublicKey,
};

use crate::known_hosts::{verify_or_add_host_key, KnownHostsPolicy};
use noxssh_core::error::SshError;
use noxssh_core::protocol::constants::*;
use noxssh_core::protocol::encoding::{
    base64_encode, push_ssh_string, read_ssh_string, read_ssh_string_owned, ssh_host_key_type_from_blob,
};
use noxssh_core::protocol::kex::{compute_exchange_hash, select_kex_algorithm, KexAlgorithm};
use noxssh_core::protocol::build_kexinit_payload;
use noxssh_core::transport::{new_drbg, TransportSession};
use noxssh_core::kex::KexResult;

pub fn client_exchange_kexinit(
    transport: &mut TransportSession,
    client_ident: &str,
    server_ident: &str,
    host: &str,
    host_key_policy: &KnownHostsPolicy,
) -> Result<KexResult, SshError> {
    let tx_payload = build_kexinit_payload();
    if tx_payload.len() > NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN {
        return Err(SshError::Failed("kexinit too large"));
    }
    transport.send_packet(&tx_payload)?;
    let rx_payload = transport.recv_packet()?;
    if rx_payload.is_empty() || rx_payload[0] != MSG_KEXINIT {
        return Err(SshError::Failed("expected server kexinit"));
    }
    if rx_payload.len() > NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN {
        return Err(SshError::Failed("server kexinit too large"));
    }
    let selected = select_kex_algorithm(&rx_payload)?;
    run_client_kex(
        transport,
        client_ident,
        server_ident,
        &tx_payload,
        &rx_payload,
        selected,
        host,
        host_key_policy,
    )
}

fn run_client_kex(
    transport: &mut TransportSession,
    client_ident: &str,
    server_ident: &str,
    kexinit_client: &[u8],
    kexinit_server: &[u8],
    algo: KexAlgorithm,
    host: &str,
    host_key_policy: &KnownHostsPolicy,
) -> Result<KexResult, SshError> {
    let (session_id, shared_secret) = match algo {
        KexAlgorithm::Curve25519Sha256 => client_curve25519(
            transport,
            client_ident,
            server_ident,
            kexinit_client,
            kexinit_server,
            host,
            host_key_policy,
        )?,
        KexAlgorithm::MlKem768Sha256 => client_mlkem_native(
            transport,
            client_ident,
            server_ident,
            kexinit_client,
            kexinit_server,
            host,
            host_key_policy,
        )?,
        KexAlgorithm::MlKem768X25519Sha256 => client_mlkem_hybrid(
            transport,
            client_ident,
            server_ident,
            kexinit_client,
            kexinit_server,
            host,
            host_key_policy,
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

fn verify_client_host_key(
    host_key_blob: &[u8],
    host: &str,
    policy: &KnownHostsPolicy,
) -> Result<(), SshError> {
    let host_key_type =
        ssh_host_key_type_from_blob(host_key_blob).ok_or(SshError::Failed("invalid host key blob"))?;
    let host_key_b64 = base64_encode(host_key_blob);
    verify_or_add_host_key(host, &host_key_type, &host_key_b64, policy)
        .map_err(SshError::FailedOwned)
}

fn client_curve25519(
    transport: &mut TransportSession,
    client_ident: &str,
    server_ident: &str,
    kexinit_client: &[u8],
    kexinit_server: &[u8],
    host: &str,
    policy: &KnownHostsPolicy,
) -> Result<([u8; 32], [u8; 32]), SshError> {
    let mut drbg = new_drbg()?;
    let private_key = x25519_generate_private_key_auto(&mut drbg)
        .map_err(|_| SshError::Failed("x25519 key generation failed"))?;
    let client_pub = private_key.public_key().bytes;

    let mut init_payload = Vec::with_capacity(64);
    init_payload.push(MSG_KEX_ECDH_INIT);
    push_ssh_string(&mut init_payload, &client_pub);
    transport.send_packet(&init_payload)?;

    let reply = transport.wait_for_message(MSG_KEX_ECDH_REPLY, None)?;
    let mut off = 1usize;
    let host_key_blob = read_ssh_string_owned(&reply, &mut off)?;
    let server_pub = read_ssh_string_owned(&reply, &mut off)?;
    let _signature = read_ssh_string_owned(&reply, &mut off)?;
    if server_pub.len() != 32 {
        return Err(SshError::Failed("invalid kex ecdh reply fields"));
    }
    verify_client_host_key(&host_key_blob, host, policy)?;
    let mut server_pub_arr = [0u8; 32];
    server_pub_arr.copy_from_slice(&server_pub);
    let shared = private_key
        .diffie_hellman_checked(X25519PublicKey::from_bytes(server_pub_arr))
        .map_err(|_| SshError::Failed("x25519 shared secret failed"))?;
    let session_id = compute_exchange_hash(
        client_ident,
        server_ident,
        kexinit_client,
        kexinit_server,
        &host_key_blob,
        &client_pub,
        &server_pub_arr,
        &shared,
    )?;
    Ok((session_id, shared))
}

fn client_mlkem_native(
    transport: &mut TransportSession,
    client_ident: &str,
    server_ident: &str,
    kexinit_client: &[u8],
    kexinit_server: &[u8],
    host: &str,
    policy: &KnownHostsPolicy,
) -> Result<([u8; 32], [u8; 32]), SshError> {
    let mut drbg = new_drbg()?;
    let (mlkem_private, mlkem_public) = mlkem_generate_keypair_auto(&mut drbg)
        .map_err(|_| SshError::Failed("mlkem key generation failed"))?;

    let mut init_payload = Vec::new();
    init_payload.push(MSG_KEX_ECDH_INIT);
    push_ssh_string(&mut init_payload, mlkem_public.as_bytes());
    transport.send_packet(&init_payload)?;

    let reply = transport.wait_for_message(MSG_KEX_ECDH_REPLY, None)?;
    let mut off = 1usize;
    let host_key_blob = read_ssh_string_owned(&reply, &mut off)?;
    let server_ct = read_ssh_string_owned(&reply, &mut off)?;
    let _signature = read_ssh_string_owned(&reply, &mut off)?;
    verify_client_host_key(&host_key_blob, host, policy)?;
    let mlkem_shared = mlkem_decapsulate(&mlkem_private, &server_ct)
        .map_err(|_| SshError::Failed("mlkem decapsulation failed"))?;
    let session_id = compute_exchange_hash(
        client_ident,
        server_ident,
        kexinit_client,
        kexinit_server,
        &host_key_blob,
        mlkem_public.as_bytes(),
        &server_ct,
        &mlkem_shared,
    )?;
    Ok((session_id, mlkem_shared))
}

fn client_mlkem_hybrid(
    transport: &mut TransportSession,
    client_ident: &str,
    server_ident: &str,
    kexinit_client: &[u8],
    kexinit_server: &[u8],
    host: &str,
    policy: &KnownHostsPolicy,
) -> Result<([u8; 32], [u8; 32]), SshError> {
    let mut drbg = new_drbg()?;
    let x_priv = x25519_generate_private_key_auto(&mut drbg)
        .map_err(|_| SshError::Failed("x25519 key generation failed"))?;
    let x_pub = x_priv.public_key().bytes;
    let (mlkem_private, mlkem_public) = mlkem_generate_keypair_auto(&mut drbg)
        .map_err(|_| SshError::Failed("mlkem key generation failed"))?;

    let mut combined_init = Vec::new();
    push_ssh_string(&mut combined_init, &x_pub);
    push_ssh_string(&mut combined_init, mlkem_public.as_bytes());
    let mut init_payload = Vec::new();
    init_payload.push(MSG_KEX_ECDH_INIT);
    push_ssh_string(&mut init_payload, &combined_init);
    transport.send_packet(&init_payload)?;

    let reply = transport.wait_for_message(MSG_KEX_ECDH_REPLY, None)?;
    let mut off = 1usize;
    let host_key_blob = read_ssh_string_owned(&reply, &mut off)?;
    let server_combo = read_ssh_string_owned(&reply, &mut off)?;
    let _signature = read_ssh_string_owned(&reply, &mut off)?;
    verify_client_host_key(&host_key_blob, host, policy)?;

    let mut soff = 0usize;
    let server_x25519 = read_ssh_string(&server_combo, &mut soff)?;
    let server_mlkem_ct = read_ssh_string(&server_combo, &mut soff)?;
    if soff != server_combo.len() || server_x25519.len() != 32 {
        return Err(SshError::Failed("invalid hybrid server payload"));
    }
    let mut server_x_pub = [0u8; 32];
    server_x_pub.copy_from_slice(server_x25519);
    let x_shared = x_priv
        .diffie_hellman_checked(X25519PublicKey::from_bytes(server_x_pub))
        .map_err(|_| SshError::Failed("x25519 shared secret failed"))?;
    let mlkem_shared = mlkem_decapsulate(&mlkem_private, server_mlkem_ct)
        .map_err(|_| SshError::Failed("mlkem decapsulation failed"))?;
    let mut hybrid_material = Vec::with_capacity(64);
    hybrid_material.extend_from_slice(&x_shared);
    hybrid_material.extend_from_slice(&mlkem_shared);
    let hybrid_shared = sha256(&hybrid_material);
    let session_id = compute_exchange_hash(
        client_ident,
        server_ident,
        kexinit_client,
        kexinit_server,
        &host_key_blob,
        &combined_init,
        &server_combo,
        &hybrid_shared,
    )?;
    Ok((session_id, hybrid_shared))
}
