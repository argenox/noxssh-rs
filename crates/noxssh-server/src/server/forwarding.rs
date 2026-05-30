use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Child;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use noxssh_core::error::SshError;

pub struct RemoteForwardManager {
    listeners: HashMap<(String, u16), thread::JoinHandle<()>>,
    next_id: AtomicU32,
}

impl RemoteForwardManager {
    pub fn new() -> Self {
        Self {
            listeners: HashMap::new(),
            next_id: AtomicU32::new(1),
        }
    }

    pub fn add_forward(
        &mut self,
        bind_host: String,
        bind_port: u16,
        mut ssh_stream: TcpStream,
    ) -> Result<(), SshError> {
        let key = (bind_host.clone(), bind_port);
        if self.listeners.contains_key(&key) {
            return Ok(());
        }
        let addr = format!("{bind_host}:{bind_port}");
        let listener = TcpListener::bind(&addr).map_err(SshError::Io)?;
        let handle = thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let _ = conn.set_nodelay(true);
                // Remote forward accept: client opens forwarded-tcpip; full relay needs
                // shared transport mutex — accepted connections are queued for main loop in future.
                let _ = ssh_stream;
            }
        });
        self.listeners.insert(key, handle);
        Ok(())
    }

    pub fn remove_forward(&mut self, bind_host: &str, bind_port: u16) {
        self.listeners.remove(&(bind_host.to_string(), bind_port));
    }
}

impl Default for RemoteForwardManager {
    fn default() -> Self {
        Self::new()
    }
}
