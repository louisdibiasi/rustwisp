use rustwisp_proto::wisp::close;
use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) fn split(command: &str) -> Option<Vec<String>> {
    if command.is_empty() || command.len() > 4096 || command.contains('\0') {
        return None;
    }
    let mut args = Vec::new();
    let mut word = String::new();
    let (mut single, mut double, mut started) = (false, false, false);
    let mut chars = command.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' if !single => {
                word.push(chars.next().unwrap_or('\\'));
                started = true;
            }
            '\'' if !double => {
                single = !single;
                started = true;
            }
            '"' if !single => {
                double = !double;
                started = true;
            }
            ' ' | '\t' if !single && !double => {
                if started {
                    args.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            ch => {
                word.push(ch);
                started = true;
            }
        }
        if args.len() > 64 {
            return None;
        }
    }
    if single || double {
        return None;
    }
    if started {
        args.push(word);
    }
    if args.is_empty() || args.len() > 64 {
        None
    } else {
        Some(args)
    }
}

#[derive(Debug)]
struct Terminal {
    child: Child,
    closing: Option<Instant>,
}
#[derive(Debug, Default)]
struct State {
    children: HashMap<u32, Terminal>,
    stopping: bool,
}
#[derive(Debug, Default)]
pub(crate) struct Terminals(Mutex<State>);

#[derive(Debug)]
pub(crate) struct Handle {
    owner: Arc<Terminals>,
    pid: u32,
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.owner.close(self.pid);
    }
}

impl Terminals {
    pub(crate) fn spawn(self: &Arc<Self>, command: &str) -> Result<(OwnedFd, Handle), u8> {
        let args = split(command).ok_or(close::INVALID_INFO)?;
        let mut state = self.0.lock().map_err(|_| close::NETWORK_ERROR)?;
        if state.stopping || state.children.len() >= 32 {
            return Err(close::THROTTLED);
        }
        let (master, child) =
            crate::sys::spawn_terminal(&args).map_err(|_| close::NETWORK_ERROR)?;
        let pid = child.id();
        state.children.insert(
            pid,
            Terminal {
                child,
                closing: None,
            },
        );
        Ok((
            master,
            Handle {
                owner: Arc::clone(self),
                pid,
            },
        ))
    }
    pub(crate) fn close(&self, pid: u32) {
        let mut state = self.0.lock().unwrap();
        if let Some(terminal) = state.children.get_mut(&pid)
            && terminal.closing.is_none()
        {
            crate::sys::terminal_signal(pid, false);
            terminal.closing = Some(Instant::now());
        }
    }
    pub(crate) fn maintain(&self, stopping: bool) -> bool {
        let mut state = self.0.lock().unwrap();
        state.stopping |= stopping;
        state.children.retain(|&pid, terminal| {
            if stopping && terminal.closing.is_none() {
                crate::sys::terminal_signal(pid, false);
                terminal.closing = Some(Instant::now());
            }
            if terminal
                .closing
                .is_some_and(|at| at.elapsed() >= Duration::from_secs(1))
            {
                // Keep the leader unreaped until the group is killed, so its PID cannot be reused.
                crate::sys::terminal_signal(pid, true);
                match terminal.child.try_wait() {
                    Ok(Some(_)) => return false,
                    Ok(None) => {}
                    Err(e) => {
                        crate::log::error("twisp", format_args!("cannot reap terminal {pid}: {e}"))
                    }
                }
            }
            true
        });
        state.children.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_preserve_quotes_without_expansion() {
        assert_eq!(
            split("printf '%s' \"a b\" '$HOME' *").unwrap(),
            ["printf", "%s", "a b", "$HOME", "*"]
        );
        assert_eq!(split("printf '' a\\ b").unwrap(), ["printf", "", "a b"]);
        assert!(split("cat '").is_none());
        assert!(split("").is_none());
        assert!(split(&"x ".repeat(65)).is_none());
    }
}
