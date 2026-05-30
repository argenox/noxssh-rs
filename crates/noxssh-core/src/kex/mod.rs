pub mod server;
pub use server::server_exchange_kexinit;

pub struct KexResult {
    pub session_id: [u8; 32],
    pub shared_secret: [u8; 32],
}

#[cfg(test)]
mod tests {
    use crate::protocol::constants::*;
    use crate::protocol::encoding::{push_namelist, push_ssh_string, push_u32};
    use crate::protocol::kex::{select_kex_algorithm, KexAlgorithm};

    #[test]
    fn select_kex_algorithm_prefers_hybrid_then_native_then_curve() {
        let mut payload = vec![MSG_KEXINIT];
        payload.extend_from_slice(&[0u8; NETNOX_SSH_KEXINIT_COOKIE_LEN]);
        push_ssh_string(
            &mut payload,
            b"curve25519-sha256,mlkem768-sha256,mlkem768x25519-sha256",
        );
        for _ in 0..9 {
            push_namelist(&mut payload, "");
        }
        payload.push(0);
        push_u32(&mut payload, 0);
        let selected = select_kex_algorithm(&payload).expect("select kex");
        assert_eq!(selected, KexAlgorithm::MlKem768X25519Sha256);
    }
}
