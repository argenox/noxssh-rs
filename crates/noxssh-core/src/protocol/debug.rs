use std::env;

pub fn ssh_debug(level: u8, args: std::fmt::Arguments<'_>) {
    if ssh_debug_level() >= level {
        eprintln!("SSH_DEBUG: {args}");
    }
}

pub fn ssh_debug_level() -> u8 {
    match env::var("NETNOX_SSH_DEBUG") {
        Ok(v) if v == "1" || v == "2" || v == "3" => v.parse::<u8>().unwrap_or(0),
        Ok(v) if !v.is_empty() => v.parse::<u8>().ok().filter(|x| *x <= 3).unwrap_or(1),
        _ => 0,
    }
}
