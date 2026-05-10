# noxssh-rs

**noxssh-rs** is a small **SSH-2 client** written in Rust. It uses cryptographic primitives from the **[NoxTLS](https://github.com/argenox/noxtls)** stack (`noxtls-crypto` in this tree), not a third-party TLS or SSH library. The CLI and protocol scope are aligned with the C **[noxssh](https://github.com/argenox/noxssh)** reference client.

| | |
| --- | --- |
| **Language** | Rust (2021 edition) |
| **Default port** | 22 |
| **License** | [GPL-2.0-only](LICENSE) **or** commercial license from Argenox ([details](LICENSE.md)) |

---

## Features

- **SSH-2** — Version exchange, `KEXINIT`, Curve25519 key exchange (`curve25519-sha256`), `NEWKEYS`, transport encryption (**AES-128-CTR**) and **HMAC-SHA256**
- **Password authentication** — `ssh-userauth` with the `password` method
- **Session channel** — Open `session` channel, **remote exec** or **interactive shell**
- **PTY** — Optional `pty-req` before shell (disable with `-T`, similar to OpenSSH)
- **Cross-platform** — Linux, macOS (Intel and Apple silicon), Windows (see [releases](#releases--ci-builds))

---

## Requirements

- **Rust** toolchain **1.75** or newer ([rustup](https://rustup.rs/))
- **Git** with submodule support
- **noxtls** submodule — this repo expects `noxtls` as a git submodule (see `.gitmodules`). Initialize before building:

```bash
git submodule update --init --recursive
```

If your remote uses SSH for the submodule URL, ensure your SSH keys or HTTPS credentials are configured for that host.

---

## Build from source

```bash
git submodule update --init --recursive
cargo build --release
```

The binary is `target/release/noxssh` (on Windows, `target/release/noxssh.exe`).

### Version strings

- **Application version** comes from `Cargo.toml` (`[package].version`) and is shown with `-h`, `-V`, and in help output.
- **NoxTLS library version** shown next to it is read at build time from `noxtls/crates/noxtls-crypto/Cargo.toml` (see `build.rs`).

---

## Usage

```text
noxssh [-h] [-V] [-d|-dd|-ddd] [-T] [-p port] [-w password] [user@]host [command]
```

| Option | Meaning |
| --- | --- |
| `-h`, `--help` | Help text (includes app and NoxTLS versions) |
| `-V`, `--version` | Print application and NoxTLS versions |
| `-p port` | SSH port (default: 22) |
| `-w password` | Password on the command line (avoid in production) |
| `-T` | Do not request a PTY for shell mode |
| `-d`, `-dd`, `-ddd` | Debug verbosity (`NETNOX_SSH_DEBUG` for compatibility) |

If `user@` is omitted, the default username is **`user`**. Without `-w`, the client prompts for a password (hidden where the terminal supports it).

### Examples

```bash
noxssh user@example.com
noxssh -p 2222 user@example.com
noxssh user@example.com "uname -a"
noxssh -w 'secret' user@example.com "hostname"
noxssh -T user@example.com
```

### Run via Cargo

```bash
cargo run --release -- [-h] [-V] [-d|-dd|-ddd] [-T] [-p port] [-w password] [user@]host [command]
```

---

## Releases & CI builds

GitHub Actions (`.github/workflows/build.yml`) builds **release** binaries for:

- Linux `x86_64-unknown-linux-gnu`
- macOS Intel `x86_64-apple-darwin`
- macOS ARM `aarch64-apple-darwin`
- Windows `x86_64-pc-windows-msvc`

Artifacts are named with the **package version** from `Cargo.toml` (for example `noxssh-v0.1.10-<target>.exe`). Pushing a tag matching `v*` triggers attaching those artifacts to a GitHub Release.

To cut a release: bump `[package].version` in `Cargo.toml`, commit, then create and push a tag (for example `v0.1.10`).

---

## Project layout

```text
noxssh-rs/
├── src/main.rs           # CLI + SSH client implementation
├── build.rs              # Injects NoxTLS version from submodule manifest
├── Cargo.toml            # Package version and metadata
├── LICENSE               # Full GPLv2 license text
├── LICENSE.md            # Dual licensing notice (GPL or commercial)
├── COPYING.md            # Pointer to GPLv2 text
├── .github/workflows/    # CI release builds
└── noxtls/               # Git submodule — NoxTLS Rust crates
```

---

## Security notes

- This client implements a **narrow** SSH profile suitable for testing and controlled environments. It does **not** replace a full-featured audited SSH client for every deployment.
- Prefer **key-based** workflows where possible; `-w` on the command line exposes the password in process listings and shell history.
- Review server host keys and trust policies before relying on this tool in production.

---

## License

Copyright © 2022–2026 **Argenox Technologies LLC**

This project is **dual-licensed**, in line with the NoxTLS ecosystem:

1. **[GNU General Public License v2.0 only](LICENSE)** (GPL-2.0-only) — see [`LICENSE`](LICENSE) and [`COPYING.md`](COPYING.md).
2. **Commercial license** from Argenox Technologies LLC — for use that is not compatible with GPLv2, contact **info@argenox.com**.

The full dual-licensing explanation is in **[`LICENSE.md`](LICENSE.md)**.

---

## Contact

**Argenox Technologies LLC** — [https://argenox.com](https://argenox.com) — info@argenox.com
