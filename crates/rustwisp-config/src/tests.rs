use super::*;

fn cfg_from(lines: &str) -> Result<Config, String> {
    let mut c = Config::default();
    c.load_text("test.conf", lines)?;
    Ok(c)
}

fn no_files(_: &str) -> io::Result<String> {
    Err(io::Error::new(io::ErrorKind::NotFound, "no such file"))
}

fn run(args: &[&str]) -> Result<Config, String> {
    match parse_args(args, no_files)? {
        Parsed::Run(c) => Ok(*c),
        other => Err(format!("unexpected {other:?}")),
    }
}

#[test]
fn defaults_match_the_c_server() {
    let c = Config::default();
    assert_eq!(c.port, 6001);
    assert!(c.allow_tcp && c.allow_udp && c.enable_v2 && c.parse_real_ip);
    assert!(!c.allow_direct_ip && !c.allow_private && !c.allow_loopback && !c.enable_twisp);
    assert_eq!(c.buffer_remaining, 128);
    assert_eq!(c.max_message_size, 1_048_581);
    assert_eq!(c.ws_write_high_water, 8_388_608);
    assert_eq!(c.stream_queue_max, 16_777_216);
    assert_eq!(c.max_streams_per_conn, 2048);
    assert_eq!(c.connections_limit_per_ip, 200);
    assert_eq!(
        (
            c.reputation.warn,
            c.reputation.throttle,
            c.reputation.strict
        ),
        (21, 51, 81)
    );
    assert_eq!(c.flood.max_connects_per_dest_per_minute, 3000);
    assert_eq!(c.trusted_headers, ["CF-Connecting-IP", "X-Forwarded-For"]);
    assert_eq!(c.dns_order, DnsOrder::Ipv4First);
    assert!(c.non_ws_response.starts_with("rustwisp: a Wisp server"));
}

#[test]
fn the_shipped_example_file_loads_cleanly() {
    let text = include_str!("../../../rustwisp.conf.example");
    let c = cfg_from(text).expect("rustwisp.conf.example must parse");
    assert_eq!(c.port, 6001);
    assert_eq!(c.workers, 0);
    // the example repeats trusted-header, which appends to the two defaults
    assert!(c.trusted_headers.len() >= 2);
    assert_eq!(c.max_message_size, 1_048_581);
}

#[test]
fn file_syntax_comments_quotes_and_blanks() {
    let c = cfg_from(
        "# comment\n\n  port = 7000   # inline\nmotd = \"hello # not a comment\" trailing\n\
         host =\nallow-host = a.example # c\nallow-host = *.b.example\n",
    )
    .unwrap();
    assert_eq!(c.port, 7000);
    assert_eq!(c.motd, "hello # not a comment");
    assert_eq!(c.host, "");
    assert!(c.allow_hosts.matches("a.example"));
    assert!(c.allow_hosts.matches("x.b.example"));
}

#[test]
fn a_hash_inside_a_word_is_not_a_comment() {
    let c = cfg_from("password-user = bob:pa#ss\n").unwrap();
    assert_eq!(c.users[0].secret, "pa#ss");
}

#[test]
fn file_errors_carry_origin_and_line() {
    let e = cfg_from("port = 1\nnonsense\n").unwrap_err();
    assert_eq!(e, "test.conf:2: expected key = value");
    let e = cfg_from("\nport = abc\n").unwrap_err();
    assert_eq!(e, "test.conf:2: bad value 'abc' for 'port'");
    let e = cfg_from("frobnicate = 1\n").unwrap_err();
    assert_eq!(e, "test.conf:1: unknown option 'frobnicate'");
}

#[test]
fn integer_ranges_are_enforced() {
    assert!(cfg_from("port = 65535").is_ok());
    assert!(cfg_from("port = 65536").is_err());
    assert!(cfg_from("port = -1").is_err());
    assert!(cfg_from("workers = 1025").is_err());
    assert!(cfg_from("resolver-threads = 0").is_err());
    assert!(cfg_from("dns-timeout-ms = 99").is_err());
    assert!(cfg_from("max-message-size = 1023").is_err());
    assert!(cfg_from("max-message-size = 1024").is_ok());
    assert!(cfg_from("listen-backlog = 65536").is_err());
    assert!(cfg_from("syn-signature-min-samples = 257").is_err());
}

#[test]
fn booleans_accept_the_documented_words_only() {
    for t in ["on", "true", "yes", "1"] {
        assert!(
            cfg_from(&format!("allow-loopback = {t}"))
                .unwrap()
                .allow_loopback
        );
    }
    for f in ["off", "false", "no", "0"] {
        assert!(!cfg_from(&format!("tcp-nodelay = {f}")).unwrap().tcp_nodelay);
    }
    assert!(cfg_from("tcp-nodelay = enabled").is_err());
}

#[test]
fn ratio_and_enums() {
    assert_eq!(
        cfg_from("syn-signature-failed-ratio = 0.5")
            .unwrap()
            .flood
            .syn_signature_failed_ratio,
        0.5
    );
    assert!(cfg_from("syn-signature-failed-ratio = 1.5").is_err());
    assert!(cfg_from("syn-signature-failed-ratio = x").is_err());
    assert_eq!(
        cfg_from("dns-order = verbatim").unwrap().dns_order,
        DnsOrder::Verbatim
    );
    assert!(cfg_from("dns-order = random").is_err());
    assert!(cfg_from("proxy-udp = direct").unwrap().proxy_udp_direct);
    assert!(cfg_from("proxy-udp = never").is_err());
    assert_eq!(
        cfg_from("log-level = none").unwrap().log_level,
        LogLevel::None
    );
    assert!(cfg_from("log-level = loud").is_err());
}

#[test]
fn list_keys_accumulate() {
    let c = cfg_from(
        "allow-port = 80\nallow-port = 443\nblock-port = 6000-6100\ntrusted-proxy = 10.0.0.0/8\n\
         trusted-proxy = 127.0.0.1\ndns-server = 1.1.1.1\ndns-server = [2606:4700:4700::1111]:53\n",
    )
    .unwrap();
    assert!(c.allow_ports.contains(80) && c.allow_ports.contains(443));
    assert!(c.block_ports.contains(6050));
    assert_eq!(c.trusted_proxies.len(), 2);
    assert_eq!(c.dns_servers.len(), 2);
}

#[test]
fn trusted_headers_can_be_reset() {
    let c = cfg_from("trusted-headers-reset = x\ntrusted-header = X-Real-IP\n").unwrap();
    assert_eq!(c.trusted_headers, ["X-Real-IP"]);
}

#[test]
fn list_limits() {
    let many: String = (0..9).map(|i| format!("trusted-header = H{i}\n")).collect();
    assert!(cfg_from(&many).is_err()); // two defaults + 9 > 8
    let ok: String = (0..6).map(|i| format!("trusted-header = H{i}\n")).collect();
    assert!(cfg_from(&ok).is_ok());
    let cidrs: String = (0..65)
        .map(|i| format!("trusted-proxy = 10.0.{i}.0/24\n"))
        .collect();
    assert!(cfg_from(&cidrs).is_err());
}

#[test]
fn password_users() {
    let c = cfg_from("password-user = alice:$2b$12$abc:def\npassword-user = bob:plain\n").unwrap();
    assert_eq!(
        c.users[0],
        User {
            name: "alice".into(),
            secret: "$2b$12$abc:def".into()
        }
    );
    assert_eq!(c.users[1].name, "bob");
    assert!(cfg_from("password-user = nocolon").is_err());
    assert!(cfg_from("password-user = :secret").is_err());
}

#[test]
fn reputation_weights() {
    let c =
        cfg_from("reputation-weight = synSignature:25\nreputation-dest-weight = burstRate:-5\n")
            .unwrap();
    assert_eq!(c.reputation.source_weights["synSignature"], 25);
    assert_eq!(c.reputation.dest_weights["burstRate"], -5);
    assert!(
        cfg_from("reputation-weight = nope:1")
            .unwrap_err()
            .contains("unknown event")
    );
    assert!(cfg_from("reputation-weight = synSignature:101").is_err());
    assert!(cfg_from("reputation-weight = synSignature").is_err());
}

#[test]
fn flags_forms() {
    let c = run(&[
        "--port",
        "7001",
        "--allow-loopback",
        "--motd=hi there",
        "--allow-udp",
        "off",
    ])
    .unwrap();
    assert_eq!(c.port, 7001);
    assert!(c.allow_loopback);
    assert_eq!(c.motd, "hi there");
    assert!(!c.allow_udp);
}

#[test]
fn flags_override_the_file_whatever_the_order() {
    let read = |p: &str| -> io::Result<String> {
        assert_eq!(p, "my.conf");
        Ok("port = 7000\nallow-private = on\n".into())
    };
    for args in [
        ["--port=7100", "--config", "my.conf"],
        ["--config=my.conf", "--port=7100", "--x-ignored-below"],
        ["-c", "my.conf", "--port=7100"],
    ] {
        let args: Vec<&str> = args
            .iter()
            .copied()
            .filter(|a| *a != "--x-ignored-below")
            .collect();
        match parse_args(&args, read).unwrap() {
            Parsed::Run(c) => {
                assert_eq!(c.port, 7100, "{args:?}");
                assert!(c.allow_private);
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn help_version_and_errors() {
    assert_eq!(parse_args(&["--help"], no_files).unwrap(), Parsed::Help);
    assert_eq!(parse_args(&["-V"], no_files).unwrap(), Parsed::Version);
    assert_eq!(run(&["stray"]).unwrap_err(), "unexpected argument 'stray'");
    assert_eq!(run(&["--config"]).unwrap_err(), "--config needs a path");
    assert!(
        run(&["--config", "missing.conf"])
            .unwrap_err()
            .starts_with("missing.conf:")
    );
    assert!(
        run(&["--nope=1"])
            .unwrap_err()
            .contains("unknown option 'nope'")
    );
    assert!(
        run(&[&format!("--{}=1", "x".repeat(70))])
            .unwrap_err()
            .contains("option too long")
    );
}

#[test]
fn long_strings_are_rejected() {
    let long = "x".repeat(MAX_STRING + 1);
    assert!(cfg_from(&format!("motd = {long}")).is_err());
}
