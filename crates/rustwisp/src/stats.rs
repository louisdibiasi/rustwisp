//! Process-wide counters behind `/stats`. Field names in the JSON match the C server.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug)]
pub struct Stats {
    started: Instant,
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub streams_total: AtomicU64,
    pub streams_active: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub refused_connection_rate: AtomicU64,
    pub refused_connection_limit: AtomicU64,
    pub refused_reputation: AtomicU64,
    pub blocked_filter: AtomicU64,
    pub blocked_egress: AtomicU64,
    pub throttled_source: AtomicU64,
    pub throttled_dest: AtomicU64,
    pub throttled_syns: AtomicU64,
    pub syn_signatures: AtomicU64,
    pub ws_closed_violations: AtomicU64,
    pub auth_failures: AtomicU64,
    pub dns_cache_entries: AtomicU64,
    pub reputation_sources: AtomicU64,
    pub reputation_dests: AtomicU64,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    pub fn new() -> Self {
        let z = || AtomicU64::new(0);
        Stats {
            started: Instant::now(),
            connections_total: z(),
            connections_active: z(),
            streams_total: z(),
            streams_active: z(),
            bytes_in: z(),
            bytes_out: z(),
            refused_connection_rate: z(),
            refused_connection_limit: z(),
            refused_reputation: z(),
            blocked_filter: z(),
            blocked_egress: z(),
            throttled_source: z(),
            throttled_dest: z(),
            throttled_syns: z(),
            syn_signatures: z(),
            ws_closed_violations: z(),
            auth_failures: z(),
            dns_cache_entries: z(),
            reputation_sources: z(),
            reputation_dests: z(),
        }
    }

    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }

    pub fn dec(c: &AtomicU64) {
        c.fetch_sub(1, Ordering::Relaxed);
    }

    /// The `/stats` body.
    pub fn to_json(&self) -> String {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        format!(
            "{{\"uptimeSeconds\":{},\
\"connections\":{{\"total\":{},\"active\":{}}},\
\"streams\":{{\"total\":{},\"active\":{}}},\
\"bytes\":{{\"in\":{},\"out\":{}}},\
\"refused\":{{\"connectionRate\":{},\"connectionLimit\":{},\"reputation\":{}}},\
\"blocked\":{{\"filter\":{},\"egress\":{}}},\
\"throttled\":{{\"source\":{},\"dest\":{},\"syns\":{}}},\
\"synSignatures\":{},\"wsClosedViolations\":{},\"authFailures\":{},\
\"dnsCacheEntries\":{},\"reputation\":{{\"sources\":{},\"destinations\":{}}}}}\n",
            self.started.elapsed().as_secs(),
            g(&self.connections_total),
            g(&self.connections_active),
            g(&self.streams_total),
            g(&self.streams_active),
            g(&self.bytes_in),
            g(&self.bytes_out),
            g(&self.refused_connection_rate),
            g(&self.refused_connection_limit),
            g(&self.refused_reputation),
            g(&self.blocked_filter),
            g(&self.blocked_egress),
            g(&self.throttled_source),
            g(&self.throttled_dest),
            g(&self.throttled_syns),
            g(&self.syn_signatures),
            g(&self.ws_closed_violations),
            g(&self.auth_failures),
            g(&self.dns_cache_entries),
            g(&self.reputation_sources),
            g(&self.reputation_dests),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_has_every_field_the_c_server_has() {
        let s = Stats::new();
        Stats::inc(&s.connections_total);
        Stats::add(&s.bytes_in, 42);
        let j = s.to_json();
        for key in [
            "uptimeSeconds",
            "connections",
            "streams",
            "bytes",
            "refused",
            "connectionRate",
            "connectionLimit",
            "blocked",
            "throttled",
            "synSignatures",
            "wsClosedViolations",
            "authFailures",
            "dnsCacheEntries",
            "reputation",
            "destinations",
        ] {
            assert!(j.contains(&format!("\"{key}\"")), "missing {key}");
        }
        assert!(j.contains("\"total\":1"));
        assert!(j.contains("\"in\":42"));
        assert!(j.ends_with("}\n"));
    }
}
