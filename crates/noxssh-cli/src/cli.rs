use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;

use noxssh_client::SshClient;
use noxssh_client::config::{default_ssh_config_path, load_host_config};
use noxssh_core::SshError;
use noxssh_client::known_hosts::HostKeyCheckingMode;
use noxssh_core::protocol::constants::*;
use noxssh_core::protocol::encoding::*;

use std::env;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

const NOXSSH_VERSION_STRING: &str = env!("CARGO_PKG_VERSION");
const NOXTLS_VERSION_STRING: &str = env!("NOXTLS_VERSION");

#[derive(Default)]
struct CliOptions {
    port: u16,
    target: String,
    command: Option<String>,
    password: Option<String>,
    identity_files: Vec<PathBuf>,
    preferred_auth_methods: Vec<String>,
    request_pty: bool,
    debug_level: u8,
    host_key_mode: HostKeyCheckingMode,
    /// When true, do not overwrite host key mode from `~/.ssh/config`.
    host_key_mode_explicit: bool,
    known_hosts_path: Option<PathBuf>,
    batch_mode: bool,
    connect_timeout_ms: u64,
    read_timeout_ms: u64,
    keepalive_interval_ms: u64,
    rekey_interval_s: u64,
    use_ssh_config: bool,
    local_forward: Option<LocalForwardSpec>,
    remote_forward: Option<LocalForwardSpec>,
    dynamic_forward_port: Option<u16>,
    sftp_ls: Option<String>,
}

#[derive(Clone, Debug)]
struct LocalForwardSpec {
    listen_port: u16,
    destination_host: String,
    destination_port: u16,
}

fn print_usage(program: &str) {
    println!("{program} {NOXSSH_VERSION_STRING}");
    println!("Using NoxTLS Library {NOXTLS_VERSION_STRING}");
    println!(
        "Usage: {program} [-h] [-V] [-d|-dd|-ddd] [-T] [-p port] [-w password] [-i identity_file] [-L [bind_port:]host:hostport] [-R [bind_port:]host:hostport] [-D port] [--sftp-ls path] [-o key=value] [--strict-host-key-checking mode] [--known-hosts path] [--connect-timeout-ms ms] [--read-timeout-ms ms] [--server-alive-interval sec] [--batch-mode] [user@]host [command]"
    );
    println!("Options:");
    println!("  -h, --help     Show this help and exit.");
    println!("  -V, --version  Show application and library versions.");
    println!("  -d             Enable basic SSH debug output.");
    println!("  -dd            Enable verbose SSH debug output.");
    println!("  -ddd           Enable packet-level SSH debug output.");
    println!("  -T             Disable PTY allocation for shell sessions.");
    println!("  -p port        SSH server port (default: 22).");
    println!("  -w password    Password (avoid command line in production).");
    println!("  -L [bind_port:]host:hostport");
    println!("                 Local TCP forwarding (SSH direct-tcpip).");
    println!("  -R [bind_port:]host:hostport");
    println!("                 Remote TCP forwarding (tcpip-forward).");
    println!("  -D <port>      Dynamic SOCKS5 forwarding on local port.");
    println!("  --sftp-ls <path>");
    println!("                 Start SFTP subsystem and list canonical path entries.");
    println!("  -i identity_file");
    println!("                 Identity file path (public key probing and future key auth).");
    println!("  -o key=value   OpenSSH-style options (limited support).");
    println!("  -F none        Disable loading ~/.ssh/config.");
    println!("  --strict-host-key-checking <strict|ask|accept-new|off>");
    println!("                 Host key policy (default: ask). ask=prompt on new keys; accept-new=auto-add;");
    println!("                 strict=fail on unknown hosts (no prompt).");
    println!("  --known-hosts <path>");
    println!("                 Path to known_hosts file.");
    println!("  --connect-timeout-ms <ms>");
    println!("                 TCP connect timeout in milliseconds (default: 10000).");
    println!("  --read-timeout-ms <ms>");
    println!("                 Socket read timeout in milliseconds (default: 30000).");
    println!("  --server-alive-interval <sec>");
    println!("                 Send SSH keepalive ignore packets every N seconds.");
    println!("  --batch-mode   Disable interactive prompts (including TOFU host key trust).");
}

fn parse_target(target: &str) -> Result<(String, String), SshError> {
    if let Some((user, host)) = target.split_once('@') {
        if user.is_empty() || host.is_empty() {
            return Err(SshError::BadParam("invalid target"));
        }
        if user.len() > NETNOX_SSH_MAX_USERNAME_LEN || host.len() > NETNOX_SSH_MAX_HOST_LEN {
            return Err(SshError::BadParam("target too long"));
        }
        Ok((user.to_string(), host.to_string()))
    } else {
        if target.is_empty() || target.len() > NETNOX_SSH_MAX_HOST_LEN {
            return Err(SshError::BadParam("invalid target"));
        }
        Ok((NOXSSH_DEFAULT_USER.to_string(), target.to_string()))
    }
}

fn parse_openssh_option(option: &str, opts: &mut CliOptions) -> Result<(), SshError> {
    let (key, value) = option
        .split_once('=')
        .ok_or(SshError::BadParam("expected -o key=value"))?;
    match key {
        "StrictHostKeyChecking" => {
            opts.host_key_mode = HostKeyCheckingMode::parse(&value.to_ascii_lowercase())
                .ok_or(SshError::BadParam("invalid StrictHostKeyChecking value"))?;
            opts.host_key_mode_explicit = true;
        }
        "UserKnownHostsFile" => {
            opts.known_hosts_path = Some(PathBuf::from(value));
        }
        "ConnectTimeout" => {
            let secs = value
                .parse::<u64>()
                .map_err(|_| SshError::BadParam("invalid ConnectTimeout"))?;
            opts.connect_timeout_ms = secs.saturating_mul(1000);
        }
        "ServerAliveInterval" => {
            let secs = value
                .parse::<u64>()
                .map_err(|_| SshError::BadParam("invalid ServerAliveInterval"))?;
            opts.keepalive_interval_ms = secs.saturating_mul(1000);
        }
        "BatchMode" => {
            opts.batch_mode = value.eq_ignore_ascii_case("yes") || value == "1";
        }
        "PreferredAuthentications" => {
            opts.preferred_auth_methods = value
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
        }
        _ => return Err(SshError::BadParam("unsupported -o option")),
    }
    Ok(())
}

fn parse_args(args: &[String]) -> Result<CliOptions, SshError> {
    if args.len() < 2 {
        return Err(SshError::BadParam("missing arguments"));
    }
    let mut opts = CliOptions {
        port: NETNOX_SSH_DEFAULT_PORT,
        request_pty: true,
        host_key_mode: HostKeyCheckingMode::Ask,
        connect_timeout_ms: 10_000,
        read_timeout_ms: 30_000,
        rekey_interval_s: 3_600,
        preferred_auth_methods: vec!["publickey".to_string(), "password".to_string()],
        use_ssh_config: true,
        ..Default::default()
    };
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage(&args[0]);
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("{} {}", args[0], NOXSSH_VERSION_STRING);
                println!("Using NoxTLS Library {NOXTLS_VERSION_STRING}");
                std::process::exit(0);
            }
            "-T" => {
                opts.request_pty = false;
                i += 1;
            }
            "-d" | "-dd" | "-ddd" => {
                opts.debug_level = (args[i].len() - 1) as u8;
                i += 1;
            }
            "-p" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -p value"));
                }
                opts.port = args[i + 1]
                    .parse::<u16>()
                    .map_err(|_| SshError::BadParam("invalid port"))?;
                if opts.port == 0 {
                    return Err(SshError::BadParam("invalid port"));
                }
                i += 2;
            }
            "-w" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -w value"));
                }
                opts.password = Some(args[i + 1].clone());
                i += 2;
            }
            "-i" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -i value"));
                }
                opts.identity_files.push(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "-L" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -L value"));
                }
                opts.local_forward = Some(parse_local_forward_spec(&args[i + 1])?);
                i += 2;
            }
            "-R" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -R value"));
                }
                opts.remote_forward = Some(parse_local_forward_spec(&args[i + 1])?);
                i += 2;
            }
            "-D" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -D value"));
                }
                opts.dynamic_forward_port = Some(
                    args[i + 1]
                        .parse::<u16>()
                        .map_err(|_| SshError::BadParam("invalid -D port"))?,
                );
                i += 2;
            }
            "--strict-host-key-checking" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing host key checking mode"));
                }
                opts.host_key_mode = HostKeyCheckingMode::parse(&args[i + 1])
                    .ok_or(SshError::BadParam("invalid host key checking mode"))?;
                opts.host_key_mode_explicit = true;
                i += 2;
            }
            "--known-hosts" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing known-hosts path"));
                }
                opts.known_hosts_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--connect-timeout-ms" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing connect timeout"));
                }
                opts.connect_timeout_ms = args[i + 1]
                    .parse::<u64>()
                    .map_err(|_| SshError::BadParam("invalid connect timeout"))?;
                i += 2;
            }
            "--read-timeout-ms" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing read timeout"));
                }
                opts.read_timeout_ms = args[i + 1]
                    .parse::<u64>()
                    .map_err(|_| SshError::BadParam("invalid read timeout"))?;
                i += 2;
            }
            "--server-alive-interval" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing server alive interval"));
                }
                let secs = args[i + 1]
                    .parse::<u64>()
                    .map_err(|_| SshError::BadParam("invalid server alive interval"))?;
                opts.keepalive_interval_ms = secs.saturating_mul(1000);
                i += 2;
            }
            "--batch-mode" => {
                opts.batch_mode = true;
                i += 1;
            }
            "--sftp-ls" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing --sftp-ls path"));
                }
                opts.sftp_ls = Some(args[i + 1].clone());
                i += 2;
            }
            "-o" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -o option"));
                }
                parse_openssh_option(&args[i + 1], &mut opts)?;
                i += 2;
            }
            "-F" => {
                if i + 1 >= args.len() {
                    return Err(SshError::BadParam("missing -F value"));
                }
                if args[i + 1].eq_ignore_ascii_case("none") {
                    opts.use_ssh_config = false;
                } else {
                    return Err(SshError::BadParam("only -F none is currently supported"));
                }
                i += 2;
            }
            x if x.starts_with('-') => return Err(SshError::BadParam("unknown option")),
            _ => {
                if opts.target.is_empty() {
                    opts.target = args[i].clone();
                    i += 1;
                } else {
                    // Collect remaining args into one remote command string.
                    let mut cmd = args[i].clone();
                    i += 1;
                    while i < args.len() {
                        if cmd.len() + 1 + args[i].len() > NETNOX_SSH_MAX_COMMAND_LEN {
                            break;
                        }
                        cmd.push(' ');
                        cmd.push_str(&args[i]);
                        i += 1;
                    }
                    opts.command = Some(cmd);
                }
            }
        }
    }

    if opts.target.is_empty() {
        return Err(SshError::BadParam("missing target"));
    }
    Ok(opts)
}

fn apply_ssh_host_config(opts: &mut CliOptions, username: &mut String, host: &str) {
    if !opts.use_ssh_config {
        return;
    }
    let cfg_path = default_ssh_config_path();
    let Some(host_cfg) = load_host_config(&cfg_path, host) else {
        return;
    };

    if *username == NOXSSH_DEFAULT_USER {
        if let Some(user) = host_cfg.user {
            *username = user;
        }
    }
    if opts.port == NETNOX_SSH_DEFAULT_PORT {
        if let Some(port) = host_cfg.port {
            opts.port = port;
        }
    }
    if opts.identity_files.is_empty() && !host_cfg.identity_files.is_empty() {
        opts.identity_files = host_cfg.identity_files;
    }
    if !opts.host_key_mode_explicit {
        if let Some(mode) = host_cfg.strict_host_key_checking {
            opts.host_key_mode = mode;
        }
    }
    if opts.known_hosts_path.is_none() {
        opts.known_hosts_path = host_cfg.user_known_hosts_file;
    }
    if opts.keepalive_interval_ms == 0 {
        if let Some(sec) = host_cfg.server_alive_interval {
            opts.keepalive_interval_ms = sec.saturating_mul(1000);
        }
    }
    if !opts.batch_mode {
        if let Some(batch) = host_cfg.batch_mode {
            opts.batch_mode = batch;
        }
    }
    if opts.preferred_auth_methods == ["publickey".to_string(), "password".to_string()] {
        if !host_cfg.preferred_authentications.is_empty() {
            opts.preferred_auth_methods = host_cfg.preferred_authentications;
        }
    }
}

fn parse_local_forward_spec(spec: &str) -> Result<LocalForwardSpec, SshError> {
    let mut parts: Vec<&str> = spec.split(':').collect();
    if parts.len() == 2 {
        // host:port with implicit local bind port == destination port.
        let destination_host = parts.remove(0).to_string();
        let destination_port = parts
            .remove(0)
            .parse::<u16>()
            .map_err(|_| SshError::BadParam("invalid -L destination port"))?;
        return Ok(LocalForwardSpec {
            listen_port: destination_port,
            destination_host,
            destination_port,
        });
    }
    if parts.len() != 3 {
        return Err(SshError::BadParam(
            "invalid -L format, expected [bind_port:]host:hostport",
        ));
    }
    let listen_port = parts[0]
        .parse::<u16>()
        .map_err(|_| SshError::BadParam("invalid -L bind port"))?;
    let destination_host = parts[1].to_string();
    let destination_port = parts[2]
        .parse::<u16>()
        .map_err(|_| SshError::BadParam("invalid -L destination port"))?;
    Ok(LocalForwardSpec {
        listen_port,
        destination_host,
        destination_port,
    })
}

fn connect_tcp(host: &str, port: u16, connect_timeout: Duration, read_timeout: Duration) -> Result<TcpStream, SshError> {
    let mut last_err: Option<io::Error> = None;
    for addr in (host, port)
        .to_socket_addrs()
        .map_err(SshError::Io)?
        .collect::<Vec<_>>()
    {
        match TcpStream::connect_timeout(&addr, connect_timeout) {
            Ok(stream) => {
                stream
                    .set_nodelay(true)
                    .map_err(|_| SshError::Failed("failed setting nodelay"))?;
                if !read_timeout.is_zero() {
                    stream
                        .set_read_timeout(Some(read_timeout))
                        .map_err(|_| SshError::Failed("failed setting read timeout"))?;
                }
                return Ok(stream);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(SshError::Io(last_err.unwrap_or_else(|| io::Error::other("connect failed"))))
}

fn prompt_password() -> Result<String, SshError> {
    rpassword::prompt_password("Password: ").map_err(SshError::Io)
}

fn print_channel_output(client: &mut SshClient) -> Result<(), SshError> {
    loop {
        match client.recv_data_with_timeout(NETNOX_SSH_MAX_DATA_LEN, 1000)? {
            Some(data) if data.is_empty() => return Ok(()),
            Some(data) => {
                io::stdout().write_all(&data)?;
                io::stdout().flush()?;
            }
            None => {
                client.maybe_send_keepalive()?;
            }
        }
    }
}

/// Pull remote shell output. `first_wait_ms` / `follow_wait_ms` are passed to socket reads; a value
/// of `0` is treated as **1 ms** internally so Windows accepts the timeout (zero is invalid there).
fn drain_shell_output(
    client: &mut SshClient,
    first_wait_ms: u64,
    follow_wait_ms: u64,
) -> Result<i32, SshError> {
    match client.recv_data_with_timeout(NETNOX_SSH_MAX_DATA_LEN, first_wait_ms)? {
        None => {
            client.maybe_send_keepalive()?;
            Ok(0)
        }
        Some(data) if data.is_empty() => Ok(1),
        Some(data) => {
            io::stdout().write_all(&data)?;
            io::stdout().flush()?;
            loop {
                match client.recv_data_with_timeout(NETNOX_SSH_MAX_DATA_LEN, follow_wait_ms)? {
                    None => break,
                    Some(next) if next.is_empty() => return Ok(1),
                    Some(next) => {
                        io::stdout().write_all(&next)?;
                        io::stdout().flush()?;
                    }
                }
            }
            Ok(0)
        }
    }
}

fn interactive_shell(client: &mut SshClient) -> Result<(), SshError> {
    println!("Interactive shell (each key is sent to the server; Ctrl+C sends interrupt).");
    terminal::enable_raw_mode().map_err(|_| SshError::Failed("failed to enable raw mode"))?;
    if let Ok((cols, rows)) = terminal::size() {
        let _ = client.send_window_change(cols as u32, rows as u32);
    }
    let result = (|| -> Result<(), SshError> {
        loop {
            // Short first read so we do not block ~100ms before every key poll (felt sluggish).
            let drain = drain_shell_output(client, 1, 0)?;
            if drain > 0 {
                println!("Remote channel closed.");
                return Ok(());
            }

            if !event::poll(Duration::from_millis(1))
                .map_err(|_| SshError::Failed("event polling failed"))?
            {
                // Idle: tiny sleep avoids a tight spin when there is no network data and no keys.
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }

            match event::read().map_err(|_| SshError::Failed("event read failed"))? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    // Raw mode turns off local echo; forward bytes immediately so the remote PTY
                    // can echo (same model as OpenSSH). Line-buffering here meant nothing was sent
                    // until Enter, so nothing appeared while typing.
                    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                    match key.code {
                        KeyCode::Char('c') if ctrl => client.send_data(&[0x03])?,
                        KeyCode::Char('d') if ctrl => client.send_data(&[0x04])?,
                        KeyCode::Char('z') if ctrl => client.send_data(&[0x1a])?,
                        KeyCode::Char('l') if ctrl => client.send_data(&[0x0c])?,
                        KeyCode::Char(ch) => {
                            let mut utf8_buf = [0u8; 4];
                            let seq = ch.encode_utf8(&mut utf8_buf);
                            client.send_data(seq.as_bytes())?;
                        }
                        KeyCode::Enter => client.send_data(b"\r")?,
                        KeyCode::Tab => client.send_data(b"\t")?,
                        KeyCode::Backspace | KeyCode::Delete => client.send_data(&[0x7f])?,
                        KeyCode::Home => client.send_data(b"\x1b[H")?,
                        KeyCode::End => client.send_data(b"\x1b[F")?,
                        KeyCode::Up => client.send_data(b"\x1b[A")?,
                        KeyCode::Down => client.send_data(b"\x1b[B")?,
                        KeyCode::Right => client.send_data(b"\x1b[C")?,
                        KeyCode::Left => client.send_data(b"\x1b[D")?,
                        KeyCode::PageUp => client.send_data(b"\x1b[5~")?,
                        KeyCode::PageDown => client.send_data(b"\x1b[6~")?,
                        KeyCode::Insert => client.send_data(b"\x1b[2~")?,
                        _ => {}
                    }
                    // Pull echo without waiting for the next main-loop network poll.
                    match drain_shell_output(client, 0, 0)? {
                        1 => {
                            println!("Remote channel closed.");
                            return Ok(());
                        }
                        _ => {}
                    }
                }
                Event::Resize(cols, rows) => {
                    let _ = client.send_window_change(cols as u32, rows as u32);
                }
                _ => {}
            }
        }
    })();
    let _ = terminal::disable_raw_mode();
    result
}

fn run_local_forward(client: &mut SshClient, spec: &LocalForwardSpec) -> Result<(), SshError> {
    let bind_addr = format!("127.0.0.1:{}", spec.listen_port);
    let listener = TcpListener::bind(&bind_addr).map_err(SshError::Io)?;
    println!(
        "Local forward active: {} -> {}:{}",
        bind_addr, spec.destination_host, spec.destination_port
    );

    loop {
        let (mut local, peer_addr) = listener.accept().map_err(SshError::Io)?;
        client.open_direct_tcpip(
            &spec.destination_host,
            spec.destination_port,
            &peer_addr.ip().to_string(),
            peer_addr.port(),
        )?;
        forward_local_socket_over_channel(client, &mut local)?;
    }
}

fn run_dynamic_forward(client: &mut SshClient, port: u16) -> Result<(), SshError> {
    let bind_addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&bind_addr).map_err(SshError::Io)?;
    println!("Dynamic SOCKS5 forward active on {bind_addr}");
    loop {
        let (mut local, peer_addr) = listener.accept().map_err(SshError::Io)?;
        let (dst_host, dst_port) = socks5_handshake_and_target(&mut local)?;
        client.open_direct_tcpip(
            &dst_host,
            dst_port,
            &peer_addr.ip().to_string(),
            peer_addr.port(),
        )?;
        forward_local_socket_over_channel(client, &mut local)?;
    }
}

fn run_remote_forward(client: &mut SshClient, spec: &LocalForwardSpec) -> Result<(), SshError> {
    client.request_remote_tcpip_forward("127.0.0.1", spec.listen_port)?;
    println!(
        "Remote forward active: remote 127.0.0.1:{} -> local {}:{}",
        spec.listen_port, spec.destination_host, spec.destination_port
    );

    loop {
        let Some(packet) = client.recv_packet_with_timeout(200)? else {
            client.maybe_send_keepalive()?;
            continue;
        };
        if packet.is_empty() {
            continue;
        }
        if packet[0] != MSG_CHANNEL_OPEN {
            continue;
        }
        let mut off = 1usize;
        let channel_type = read_ssh_string(&packet, &mut off)?;
        if channel_type != b"forwarded-tcpip" {
            continue;
        }
        let remote_sender_channel = read_u32_at(&packet, &mut off)?;
        let remote_window = read_u32_at(&packet, &mut off)?;
        let remote_max_packet = read_u32_at(&packet, &mut off)?;
        let _connected_address = read_ssh_string(&packet, &mut off)?;
        let _connected_port = read_u32_at(&packet, &mut off)?;
        let _originator_address = read_ssh_string(&packet, &mut off)?;
        let _originator_port = read_u32_at(&packet, &mut off)?;

        let local_target = format!("{}:{}", spec.destination_host, spec.destination_port);
        let mut local = TcpStream::connect(&local_target)
            .map_err(|_| SshError::Failed("failed to connect local target for remote forward"))?;
        local.set_read_timeout(Some(Duration::from_millis(50))).map_err(SshError::Io)?;
        local
            .set_write_timeout(Some(Duration::from_millis(2000)))
            .map_err(SshError::Io)?;

        let local_channel_id = client.next_local_channel_id;
        client.next_local_channel_id = client.next_local_channel_id.wrapping_add(1);
        let mut confirm = Vec::with_capacity(32);
        confirm.push(MSG_CHANNEL_OPEN_CONFIRMATION);
        push_u32(&mut confirm, remote_sender_channel);
        push_u32(&mut confirm, local_channel_id);
        push_u32(&mut confirm, NETNOX_SSH_CHANNEL_WINDOW_SIZE);
        push_u32(&mut confirm, NETNOX_SSH_CHANNEL_MAX_PACKET_SIZE);
        client.send_packet(&confirm)?;

        client.local_channel_id = local_channel_id;
        client.remote_channel_id = remote_sender_channel;
        client.remote_window_size = remote_window;
        client.remote_max_packet_size = remote_max_packet;
        client.channel_open = true;
        forward_local_socket_over_channel(client, &mut local)?;
    }
}

fn socks5_handshake_and_target(stream: &mut TcpStream) -> Result<(String, u16), SshError> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).map_err(SshError::Io)?;
    if head[0] != 5 {
        return Err(SshError::Failed("unsupported socks version"));
    }
    let method_count = head[1] as usize;
    let mut methods = vec![0u8; method_count];
    stream.read_exact(&mut methods).map_err(SshError::Io)?;
    // no-auth only
    stream.write_all(&[5, 0]).map_err(SshError::Io)?;

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).map_err(SshError::Io)?;
    if req[0] != 5 || req[1] != 1 {
        return Err(SshError::Failed("unsupported socks command"));
    }

    let host = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).map_err(SshError::Io)?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        3 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).map_err(SshError::Io)?;
            let mut buf = vec![0u8; l[0] as usize];
            stream.read_exact(&mut buf).map_err(SshError::Io)?;
            String::from_utf8_lossy(&buf).to_string()
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).map_err(SshError::Io)?;
            let addr = std::net::Ipv6Addr::from(ip);
            addr.to_string()
        }
        _ => return Err(SshError::Failed("unsupported socks address type")),
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).map_err(SshError::Io)?;
    let port = u16::from_be_bytes(port_buf);

    // success response with 0.0.0.0:0 bind.
    stream
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .map_err(SshError::Io)?;
    Ok((host, port))
}

fn forward_local_socket_over_channel(
    client: &mut SshClient,
    local: &mut TcpStream,
) -> Result<(), SshError> {
    local
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(SshError::Io)?;
    local
        .set_write_timeout(Some(Duration::from_millis(2000)))
        .map_err(SshError::Io)?;

    let mut local_closed = false;
    let mut local_buf = [0u8; NETNOX_SSH_MAX_DATA_LEN];
    loop {
        if !local_closed {
            match local.read(&mut local_buf) {
                Ok(0) => {
                    local_closed = true;
                }
                Ok(n) => {
                    client.send_data(&local_buf[..n])?;
                }
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::TimedOut => {}
                Err(err) => return Err(SshError::Io(err)),
            }
        }

        match client.recv_data_with_timeout(NETNOX_SSH_MAX_DATA_LEN, 50)? {
            Some(data) if data.is_empty() => break,
            Some(data) => local.write_all(&data).map_err(SshError::Io)?,
            None => {
                client.maybe_send_keepalive()?;
                if local_closed {
                    break;
                }
            }
        }
    }
    let _ = local.shutdown(Shutdown::Both);
    client.channel_open = false;
    Ok(())
}

fn sftp_list_path(client: &mut SshClient, path: &str) -> Result<(), SshError> {
    client.request_subsystem("sftp")?;

    // INIT(version=3)
    let mut init = Vec::with_capacity(9);
    push_u32(&mut init, 5);
    init.push(SFTP_MSG_INIT);
    push_u32(&mut init, 3);
    client.send_data(&init)?;

    let mut sftp_buf = Vec::new();
    let version_payload = recv_sftp_payload(client, &mut sftp_buf)?;
    if version_payload.first().copied() != Some(SFTP_MSG_VERSION) {
        return Err(SshError::Failed("invalid SFTP version response"));
    }

    let mut req = Vec::with_capacity(128);
    let mut req_payload = Vec::with_capacity(120);
    req_payload.push(SFTP_MSG_REALPATH);
    push_u32(&mut req_payload, 1);
    push_ssh_string(&mut req_payload, path.as_bytes());
    push_u32(&mut req, req_payload.len() as u32);
    req.extend_from_slice(&req_payload);
    client.send_data(&req)?;

    let reply = recv_sftp_payload(client, &mut sftp_buf)?;
    match reply.first().copied() {
        Some(SFTP_MSG_NAME) => {
            let mut off = 1usize;
            let _id = read_u32_at(&reply, &mut off)?;
            let count = read_u32_at(&reply, &mut off)? as usize;
            for _ in 0..count {
                let filename = read_ssh_string(&reply, &mut off)?;
                let _longname = read_ssh_string(&reply, &mut off)?;
                skip_sftp_attrs(&reply, &mut off)?;
                println!("{}", String::from_utf8_lossy(filename));
            }
            Ok(())
        }
        Some(SFTP_MSG_STATUS) => {
            let mut off = 1usize;
            let _id = read_u32_at(&reply, &mut off)?;
            let code = read_u32_at(&reply, &mut off)?;
            let msg = read_ssh_string(&reply, &mut off).unwrap_or(b"");
            Err(SshError::FailedOwned(format!(
                "sftp realpath failed: code={} message={}",
                code,
                String::from_utf8_lossy(msg)
            )))
        }
        _ => Err(SshError::Failed("unexpected SFTP reply")),
    }
}

fn recv_sftp_payload(client: &mut SshClient, pending: &mut Vec<u8>) -> Result<Vec<u8>, SshError> {
    loop {
        if pending.len() >= 4 {
            let mut off = 0usize;
            let packet_len = read_u32_at(pending, &mut off)? as usize;
            if pending.len() >= packet_len + 4 {
                let payload = pending[4..4 + packet_len].to_vec();
                pending.drain(..4 + packet_len);
                return Ok(payload);
            }
        }
        let chunk = client.recv_data(NETNOX_SSH_MAX_DATA_LEN)?;
        if chunk.is_empty() {
            return Err(SshError::Failed("channel closed while reading SFTP packet"));
        }
        pending.extend_from_slice(&chunk);
    }
}

fn skip_sftp_attrs(payload: &[u8], off: &mut usize) -> Result<(), SshError> {
    let flags = read_u32_at(payload, off)?;
    if flags & 0x0000_0001 != 0 {
        // size (u64)
        if *off + 8 > payload.len() {
            return Err(SshError::Failed("invalid sftp attrs size"));
        }
        *off += 8;
    }
    if flags & 0x0000_0002 != 0 {
        let _uid = read_u32_at(payload, off)?;
        let _gid = read_u32_at(payload, off)?;
    }
    if flags & 0x0000_0004 != 0 {
        let _perm = read_u32_at(payload, off)?;
    }
    if flags & 0x0000_0008 != 0 {
        let _atime = read_u32_at(payload, off)?;
        let _mtime = read_u32_at(payload, off)?;
    }
    if flags & 0x8000_0000 != 0 {
        let ext_count = read_u32_at(payload, off)? as usize;
        for _ in 0..ext_count {
            let _etype = read_ssh_string(payload, off)?;
            let _edata = read_ssh_string(payload, off)?;
        }
    }
    Ok(())
}

pub fn run() {
    let args: Vec<String> = env::args().collect();
    let mut opts = match parse_args(&args) {
        Ok(v) => v,
        Err(_) => {
            print_usage(args.first().map_or("noxssh", String::as_str));
            std::process::exit(1);
        }
    };

    if opts.debug_level > 0 {
        // SAFETY: process environment updates are required to mirror C behavior.
        unsafe { env::set_var("NETNOX_SSH_DEBUG", format!("{}", opts.debug_level)) };
    } else {
        // SAFETY: process environment updates are required to mirror C behavior.
        unsafe { env::remove_var("NETNOX_SSH_DEBUG") };
    }

    let (mut username, host) = match parse_target(&opts.target) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("ERROR: Invalid target: {}", opts.target);
            std::process::exit(1);
        }
    };
    apply_ssh_host_config(&mut opts, &mut username, &host);

    let stream = match connect_tcp(
        &host,
        opts.port,
        Duration::from_millis(opts.connect_timeout_ms),
        Duration::from_millis(opts.read_timeout_ms),
    ) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("ERROR: Failed TCP connect to {}:{}", host, opts.port);
            std::process::exit(1);
        }
    };

    let mut client = SshClient::new(stream, opts.port);
    client.set_host_key_policy(opts.host_key_mode, opts.known_hosts_path.clone(), opts.batch_mode);
    client.set_transport_timers(
        Duration::from_millis(opts.keepalive_interval_ms),
        Duration::from_secs(opts.rekey_interval_s),
    );
    client.set_identity_files(opts.identity_files.clone());
    client.set_preferred_auth_methods(opts.preferred_auth_methods.clone());
    if let Err(err) = client.set_target(&username, &host) {
        eprintln!("ERROR: {err}");
        std::process::exit(1);
    }
    if let Err(err) = client.connect() {
        eprintln!("ERROR: SSH handshake failed ({err})");
        std::process::exit(1);
    }

    println!("Connected to {}:{}", host, opts.port);
    println!(
        "Server identification: {}",
        client.server_ident().unwrap_or("<none>")
    );

    if let Some(password) = opts.password.as_deref() {
        if let Err(err) = client.set_password(password) {
            eprintln!("ERROR: Failed to configure password ({err})");
            client.close();
            std::process::exit(1);
        }
    }

    if let Err(err) = client.authenticate() {
        match err {
            SshError::AuthRejected => eprintln!("Server rejected authentication (wrong password or user?)."),
            _ => eprintln!("Authentication failed. Use -d for debug details."),
        }
        client.close();
        std::process::exit(1);
    }
    println!("Authentication succeeded.");

    if let Some(spec) = opts.local_forward.as_ref() {
        if let Err(err) = run_local_forward(&mut client, spec) {
            eprintln!("ERROR: Local forwarding failed ({err}).");
            client.close();
            std::process::exit(1);
        }
        client.close();
        return;
    }
    if let Some(port) = opts.dynamic_forward_port {
        if let Err(err) = run_dynamic_forward(&mut client, port) {
            eprintln!("ERROR: Dynamic forwarding failed ({err}).");
            client.close();
            std::process::exit(1);
        }
        client.close();
        return;
    }
    if let Some(spec) = opts.remote_forward.as_ref() {
        if let Err(err) = run_remote_forward(&mut client, spec) {
            eprintln!("ERROR: Remote forwarding failed ({err}).");
            client.close();
            std::process::exit(1);
        }
        client.close();
        return;
    }

    if let Err(err) = client.open_session() {
        eprintln!("ERROR: Failed to open SSH session channel ({err}).");
        client.close();
        std::process::exit(1);
    }

    // Command mode runs once and drains output; shell mode stays interactive.
    let run_result = if let Some(path) = opts.sftp_ls.as_deref() {
        sftp_list_path(&mut client, path)
    } else if let Some(command) = opts.command.as_deref() {
        client.exec(command).and_then(|_| print_channel_output(&mut client))
    } else {
        client
            .request_shell_ex(opts.request_pty)
            .and_then(|_| interactive_shell(&mut client))
    };

    if let Err(err) = run_result {
        eprintln!("ERROR: {err}");
        client.close();
        std::process::exit(1);
    }

    client.close();
}

