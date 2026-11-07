//! Host and port allow/block lists. A non-empty allow list wins: only listed targets pass and the
//! block list is not consulted. With an empty allow list the block list applies.

use holywisp_config::Config;

pub fn host_port_ok(cfg: &Config, host: &str, port: u16) -> bool {
    if !cfg.allow_hosts.is_empty() {
        if !cfg.allow_hosts.matches(host) {
            return false;
        }
    } else if cfg.block_hosts.matches(host) {
        return false;
    }
    if !cfg.allow_ports.is_empty() {
        cfg.allow_ports.contains(port)
    } else {
        cfg.block_ports.is_empty() || !cfg.block_ports.contains(port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(f: impl FnOnce(&mut Config)) -> Config {
        let mut c = Config::default();
        f(&mut c);
        c
    }

    #[test]
    fn empty_lists_allow_everything() {
        assert!(host_port_ok(&Config::default(), "example.com", 443));
    }

    #[test]
    fn allow_list_wins_over_block_list() {
        let c = cfg(|c| {
            c.allow_hosts.add("good.example").unwrap();
            c.block_hosts.add("good.example").unwrap();
        });
        assert!(host_port_ok(&c, "good.example", 80));
        assert!(!host_port_ok(&c, "other.example", 80));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let c = cfg(|c| c.block_hosts.add("*.bad.test").unwrap());
        assert!(!host_port_ok(&c, "a.bad.test", 80));
        assert!(host_port_ok(&c, "bad.test", 80));
        assert!(host_port_ok(&c, "notbad.test", 80));
    }

    #[test]
    fn ports() {
        let c = cfg(|c| {
            c.block_ports.add_spec("25").unwrap();
            c.block_ports.add_spec("6000-6010").unwrap();
        });
        assert!(!host_port_ok(&c, "h", 25));
        assert!(!host_port_ok(&c, "h", 6005));
        assert!(host_port_ok(&c, "h", 443));
        let c = cfg(|c| {
            c.allow_ports.add_spec("80").unwrap();
            c.allow_ports.add_spec("443").unwrap();
        });
        assert!(host_port_ok(&c, "h", 443));
        assert!(!host_port_ok(&c, "h", 8080));
    }
}
