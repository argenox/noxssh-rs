# noxssh-rs

Rust SSH client implementation built on top of `noxtls-crypto`, mirroring the
CLI behavior of the C `noxssh` client.

## Usage

```bash
cargo run -- [-h] [-V] [-d|-dd|-ddd] [-T] [-p port] [-w password] [user@]host [command]
```
