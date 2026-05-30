use std::path::Path;
use std::sync::{Arc, Mutex};

use noxssh_core::error::SshError;
use noxssh_core::protocol::constants::*;
use noxssh_core::protocol::encoding::{push_ssh_string, push_u32, read_ssh_string_owned, read_u32_at};
use noxssh_core::transport::TransportSession;

pub struct SftpState {
    pending: Vec<u8>,
}

impl SftpState {
    pub fn new() -> Self {
        Self { pending: Vec::new() }
    }

    pub fn poll(
        &mut self,
        transport: &Arc<Mutex<TransportSession>>,
        channel: u32,
    ) -> Result<(), SshError> {
        if let Ok(Some(pkt)) = transport.lock().unwrap().recv_packet_with_timeout(1) {
            if pkt.first() == Some(&MSG_CHANNEL_DATA) {
                let mut off = 1usize;
                let _recipient = read_u32_at(&pkt, &mut off)?;
                let data = read_ssh_string_owned(&pkt, &mut off)?;
                self.pending.extend_from_slice(&data);
            }
        }

        while self.pending.len() >= 4 {
            let len = u32::from_be_bytes([
                self.pending[0],
                self.pending[1],
                self.pending[2],
                self.pending[3],
            ]) as usize;
            if self.pending.len() < 4 + len {
                break;
            }
            let payload = self.pending[4..4 + len].to_vec();
            self.pending.drain(..4 + len);
            self.handle_sftp_payload(transport, channel, &payload)?;
        }
        Ok(())
    }

    fn handle_sftp_payload(
        &self,
        transport: &Arc<Mutex<TransportSession>>,
        channel: u32,
        payload: &[u8],
    ) -> Result<(), SshError> {
        match payload.first().copied() {
            Some(SFTP_MSG_INIT) => {
                let mut rsp = vec![SFTP_MSG_VERSION];
                push_u32(&mut rsp, 3);
                send_sftp(transport, channel, &rsp)?;
            }
            Some(SFTP_MSG_REALPATH) => {
                let mut off = 1usize;
                let _id = read_u32_at(payload, &mut off)?;
                let path = read_ssh_string_owned(payload, &mut off)?;
                let path_str = String::from_utf8_lossy(&path);
                let canonical = std::fs::canonicalize(Path::new(path_str.trim()))
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| path_str.to_string());
                let mut entry = Vec::new();
                push_ssh_string(&mut entry, canonical.as_bytes());
                push_ssh_string(&mut entry, b"");
                push_u32(&mut entry, 0);
                let mut rsp = vec![SFTP_MSG_NAME];
                push_u32(&mut rsp, 1);
                push_u32(&mut rsp, 1);
                rsp.extend_from_slice(&entry);
                send_sftp(transport, channel, &rsp)?;
            }
            _ => {}
        }
        Ok(())
    }
}

fn send_sftp(
    transport: &Arc<Mutex<TransportSession>>,
    channel: u32,
    payload: &[u8],
) -> Result<(), SshError> {
    let mut frame = Vec::new();
    push_u32(&mut frame, payload.len() as u32);
    frame.extend_from_slice(payload);
    let mut pkt = Vec::new();
    pkt.push(MSG_CHANNEL_DATA);
    push_u32(&mut pkt, channel);
    push_ssh_string(&mut pkt, &frame);
    transport.lock().unwrap().send_packet(&pkt)
}
