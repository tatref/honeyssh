use std::collections::HashMap;

use log::info;

struct FakeShellState {
    cwd: String,
    user: String,
    vars: HashMap<String, String>,
}

impl Default for FakeShellState {
    fn default() -> Self {
        Self {
            cwd: Default::default(),
            user: Default::default(),
            vars: vec![
                ("SHELL", "sh"),
                ("HOME", "/home/user"),
                ("USER", "user"),
                ("PATH", "/bin"),
                ("PS1", "$ "),
            ]
            .into_iter()
            .map(|(a, b)| (a.into(), b.into()))
            .collect(),
        }
    }
}

pub struct FakeShell {
    buffer: Vec<u8>,
    state: FakeShellState,
}

impl FakeShell {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(10 * 1024),
            state: FakeShellState::default(),
        }
    }

    fn prompt(&self) -> String {
        match self.state.vars.get("PS1") {
            Some(ps1) => {
                let mut result = ps1.clone();

                for (k, v) in &[("\\u", self.state.vars.get("USER").unwrap_or(&"".into()))] {
                    result = result.replace(k, v);
                }

                result
            }
            None => "$ ".into(),
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        let mut stdout = Vec::new();

        for &c in data {
            info!("char: {}", c);
            match c {
                b'\r' => {
                    let out = self.execute_buffer();
                    stdout.extend(out);
                    self.buffer.clear();
                }
                b'\x03' => {
                    stdout.clear();
                    stdout.extend(b"^C\r\n");
                    stdout.extend(self.prompt().as_bytes());
                    self.buffer.clear();
                }
                b'\x7f' => {
                    stdout.insert(0, b'\r');
                    stdout.pop();
                    //stdout.push(b' ');
                    self.buffer.pop();
                }
                _ => {
                    stdout.push(c);
                    self.buffer.push(c);
                }
            }
        }

        stdout
    }

    fn execute_buffer(&mut self) -> Vec<u8> {
        let mut stdout = Vec::new();
        stdout.extend(b"\r\n");

        let cmd = String::from_utf8_lossy(&self.buffer);
        let cmd = self.expand(&cmd);
        let cmd: Vec<_> = cmd.split_ascii_whitespace().collect();
        if let Some(exe) = cmd.get(0) {
            let cmdout = match *exe {
                "id" => "uid=1000(user) gid=1000(user) groups=1000(user)".into(),
                "ls" => "info.txt  passwords.txt".into(),
                "cat" => {
                    let args = cmd.get(1..);
                    "".into()
                }
                "echo" => {
                    let args = cmd.get(1..);
                    if let Some(args) = args {
                        for arg in args {
                            stdout.extend(arg.as_bytes());
                            stdout.push(b' ');
                        }
                    }
                    "".into()
                }
                x => format!("sh: {}: command not found...", x),
            };
            stdout.extend(cmdout.as_bytes());
            stdout.extend(b"\r\n");
        }

        //stdout.extend(b"\r\n");
        stdout.extend(self.prompt().as_bytes());
        stdout
    }

    fn expand(&self, s: &str) -> String {
        let mut result = s.to_string();

        for (k, v) in &self.state.vars {
            let k = format!("${}", k);
            result = result.replace(&k, &v);
        }
        result
    }
}
