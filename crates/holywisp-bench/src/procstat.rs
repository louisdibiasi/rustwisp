//! What the kernel says about a process: CPU time, memory, context switches. Linux `/proc` only.

use std::fs;

/// Clock ticks per second. 100 on every Linux build that matters.
const TICKS_PER_SECOND: f64 = 100.0;

/// CPU seconds spent in user and kernel mode.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cpu {
    pub user: f64,
    pub system: f64,
}

impl Cpu {
    pub fn total(self) -> f64 {
        self.user + self.system
    }

    pub fn since(self, earlier: Cpu) -> Cpu {
        Cpu {
            user: self.user - earlier.user,
            system: self.system - earlier.system,
        }
    }
}

pub fn cpu(pid: u32) -> Option<Cpu> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name is in parentheses and may hold spaces; the numbers start after it.
    let rest: Vec<&str> = text.rsplit_once(')')?.1.split_whitespace().collect();
    Some(Cpu {
        user: rest.get(11)?.parse::<f64>().ok()? / TICKS_PER_SECOND,
        system: rest.get(12)?.parse::<f64>().ok()? / TICKS_PER_SECOND,
    })
}

/// Voluntary plus involuntary context switches over all threads.
pub fn context_switches(pid: u32) -> u64 {
    let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return 0;
    };
    tasks
        .flatten()
        .filter_map(|t| fs::read_to_string(t.path().join("status")).ok())
        .flat_map(|s| {
            s.lines()
                .filter(|l| l.contains("ctxt_switches"))
                .filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
                .collect::<Vec<_>>()
        })
        .sum()
}

/// Peak resident memory in MiB.
pub fn peak_rss_mib(pid: u32) -> Option<f64> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let kib = text
        .lines()
        .find(|l| l.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse::<f64>()
        .ok()?;
    Some(kib / 1024.0)
}

/// TCP segments sent, system wide.
pub fn tcp_segments_out() -> Option<u64> {
    let text = fs::read_to_string("/proc/net/snmp").ok()?;
    let mut lines = text.lines().filter(|l| l.starts_with("Tcp:"));
    let names: Vec<&str> = lines.next()?.split_whitespace().collect();
    let values: Vec<&str> = lines.next()?.split_whitespace().collect();
    let at = names.iter().position(|n| *n == "OutSegs")?;
    values.get(at)?.parse().ok()
}
