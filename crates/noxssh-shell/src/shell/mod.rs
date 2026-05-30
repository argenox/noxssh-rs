mod handler;
mod session;

use std::collections::HashMap;
use std::sync::Arc;

use noxssh_core::error::SshError;

pub use handler::CommandShellHandler;
pub use session::EmbeddedSession;

pub struct RegisteredCommand {
    pub name: String,
    pub help: String,
    pub handler: Arc<dyn Fn(&mut CommandContext, &[&str]) -> Result<i32, SshError> + Send + Sync>,
}

pub struct CommandRegistry {
    commands: HashMap<String, Arc<RegisteredCommand>>,
    prompt: String,
    auto_help: bool,
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRegistry {
    pub fn new() -> Self {
        Self {
            commands: HashMap::new(),
            prompt: "> ".to_string(),
            auto_help: true,
        }
    }

    pub fn with_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = prompt.into();
        self
    }

    pub fn with_auto_help(mut self, auto_help: bool) -> Self {
        self.auto_help = auto_help;
        self
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    pub fn register(
        &mut self,
        name: &str,
        help: &str,
        handler: impl Fn(&mut CommandContext, &[&str]) -> Result<i32, SshError> + Send + Sync + 'static,
    ) {
        let cmd = Arc::new(RegisteredCommand {
            name: name.to_string(),
            help: help.to_string(),
            handler: Arc::new(handler),
        });
        self.commands.insert(name.to_string(), cmd);
    }

    pub fn commands(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        let mut names: Vec<_> = self.commands.values().map(|c| c.as_ref()).collect();
        names.sort_by(|a, b| a.name.cmp(&b.name));
        names.into_iter().map(|c| (c.name.as_str(), c.help.as_str()))
    }

    pub fn dispatch(&self, ctx: &mut CommandContext, argv: &[&str]) -> Result<i32, SshError> {
        if argv.is_empty() {
            return Ok(0);
        }
        if self.auto_help && argv[0] == "help" {
            return self.write_help(ctx);
        }
        match self.commands.get(argv[0]) {
            Some(cmd) => (cmd.handler)(ctx, argv),
            None => {
                ctx.writeln_stderr(&format!("command not found: {}", argv[0]))?;
                Ok(127)
            }
        }
    }

    fn write_help(&self, ctx: &mut CommandContext) -> Result<i32, SshError> {
        for (name, help) in self.commands() {
            ctx.writeln_stdout(&format!("  {name}: {help}"))?;
        }
        Ok(0)
    }
}

pub struct CommandContext<'a> {
    user: &'a str,
    stdout: &'a mut Vec<u8>,
    stderr: &'a mut Vec<u8>,
}

impl<'a> CommandContext<'a> {
    pub fn new(user: &'a str, stdout: &'a mut Vec<u8>, stderr: &'a mut Vec<u8>) -> Self {
        Self {
            user,
            stdout,
            stderr,
        }
    }

    pub fn user(&self) -> &str {
        self.user
    }

    pub fn write_stdout(&mut self, data: &[u8]) -> Result<(), SshError> {
        self.stdout.extend_from_slice(data);
        Ok(())
    }

    pub fn writeln_stdout(&mut self, line: &str) -> Result<(), SshError> {
        self.write_stdout(line.as_bytes())?;
        self.write_stdout(b"\n")
    }

    pub fn write_stderr(&mut self, data: &[u8]) -> Result<(), SshError> {
        self.stderr.extend_from_slice(data);
        Ok(())
    }

    pub fn writeln_stderr(&mut self, line: &str) -> Result<(), SshError> {
        self.write_stderr(line.as_bytes())?;
        self.write_stderr(b"\n")
    }
}

/// Parse a shell-like command line into arguments (whitespace split, quote support).
pub fn parse_command_line(line: &str) -> Vec<String> {
    let line = line.trim_end_matches(['\r', '\n']);
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = trimmed.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(ch) = chars.next() {
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                current.push(ch);
            }
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            } else if ch == '\\' {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            ' ' | '\t' => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_and_whitespace() {
        assert!(parse_command_line("").is_empty());
        assert!(parse_command_line("   \n").is_empty());
    }

    #[test]
    fn parse_simple_args() {
        assert_eq!(parse_command_line("status"), vec!["status"]);
        assert_eq!(parse_command_line("reboot now"), vec!["reboot", "now"]);
    }

    #[test]
    fn parse_quoted_args() {
        assert_eq!(
            parse_command_line(r#"reboot "factory default""#),
            vec!["reboot", "factory default"]
        );
        assert_eq!(
            parse_command_line("echo 'hello world'"),
            vec!["echo", "hello world"]
        );
    }

    #[test]
    fn dispatch_known_unknown_and_help() {
        let mut registry = CommandRegistry::new();
        registry.register("status", "Print status", |ctx, _args| {
            ctx.writeln_stdout("ok")?;
            Ok(0)
        });

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        {
            let mut ctx = CommandContext::new("user", &mut stdout, &mut stderr);
            assert_eq!(registry.dispatch(&mut ctx, &["status"]).unwrap(), 0);
        }
        assert_eq!(stdout, b"ok\n");

        stdout.clear();
        stderr.clear();
        {
            let mut ctx = CommandContext::new("user", &mut stdout, &mut stderr);
            assert_eq!(registry.dispatch(&mut ctx, &["missing"]).unwrap(), 127);
        }
        assert!(stderr.starts_with(b"command not found: missing"));

        stdout.clear();
        {
            let mut ctx = CommandContext::new("user", &mut stdout, &mut stderr);
            assert_eq!(registry.dispatch(&mut ctx, &["help"]).unwrap(), 0);
        }
        assert!(stdout.windows(6).any(|w| w == b"status"));
    }
}
