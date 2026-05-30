use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use noxssh_core::keys::HostKey;
use noxssh_core::protocol::constants::NETNOX_SSH_DEFAULT_PORT;
use noxssh_server::{
    serve_connections, DefaultSessionHandler, RemoteForwardManager, ServerConfig, SimpleAuthenticator,
};
use std::net::TcpListener;
use std::sync::Mutex;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut port = NETNOX_SSH_DEFAULT_PORT;
    let mut host_key_path: Option<PathBuf> = None;
    let mut auth_keys_path: Option<PathBuf> = None;
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;
    let mut debug = 0u8;

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help(&args[0]);
                return;
            }
            "-V" | "--version" => {
                println!("noxsshd {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "-p" => {
                i += 1;
                port = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(22);
            }
            "-H" => {
                i += 1;
                host_key_path = args.get(i).map(PathBuf::from);
            }
            "-a" => {
                i += 1;
                auth_keys_path = args.get(i).map(PathBuf::from);
            }
            "-u" => {
                i += 1;
                username = args.get(i).cloned();
            }
            "-w" => {
                i += 1;
                password = args.get(i).cloned();
            }
            "-d" | "-dd" | "-ddd" => {
                debug = (args[i].len() - 1) as u8;
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                print_help(&args[0]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if debug > 0 {
        unsafe { env::set_var("NETNOX_SSH_DEBUG", format!("{debug}")) };
    }

    let host_key = if let Some(path) = host_key_path {
        let pem = std::fs::read_to_string(&path).expect("read host key");
        HostKey::from_pem(&pem).expect("parse host key")
    } else {
        let key = HostKey::generate_ed25519().expect("generate host key");
        eprintln!(
            "Generated ephemeral host key fingerprint: {}",
            key.fingerprint_sha256()
        );
        key
    };

    let mut auth = SimpleAuthenticator::new();
    if let (Some(user), Some(pass)) = (username, password) {
        auth.add_user(user, pass);
    }
    if let Some(path) = auth_keys_path {
        auth.load_authorized_keys(&path).expect("load authorized keys");
    }

    let config = ServerConfig {
        host_keys: vec![host_key],
        ..ServerConfig::default()
    };

    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).expect("bind");
    eprintln!("noxsshd listening on {addr}");

    let auth = Arc::new(auth);
    let handler = Arc::new(DefaultSessionHandler);
    let forwards = Arc::new(Mutex::new(RemoteForwardManager::new()));
    if let Err(err) = serve_connections(listener, config, auth, handler, forwards) {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}

fn print_help(program: &str) {
    println!("{program} {}", env!("CARGO_PKG_VERSION"));
    println!(
        "Usage: {program} [-h] [-V] [-d] [-p port] [-H host_key] [-a authorized_keys] [-u user] [-w password]"
    );
}
