#![cfg(target_os = "linux")]
//! Logins checked against crypt(3) style hashes, on the auth pool.

mod common;

use std::time::{Duration, Instant};

use common::*;
use rustwisp_config::{Config, User};
use rustwisp_proto::wisp::{self, close, ext, ptype};

const BCRYPT: &str = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"; // "U*U"
const SHA256: &str = "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"; // "Hello world!"
const SHA512: &str = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";

fn user(name: &str, secret: &str) -> User {
    User {
        name: name.into(),
        secret: secret.into(),
    }
}

fn login_body(user: &str, pass: &str) -> Vec<u8> {
    let mut meta = vec![user.len() as u8];
    meta.extend_from_slice(&(pass.len() as u16).to_le_bytes());
    meta.extend_from_slice(user.as_bytes());
    meta.extend_from_slice(pass.as_bytes());
    let mut body = vec![wisp::MAJOR, wisp::MINOR, ext::PASSWORD];
    body.extend_from_slice(&(meta.len() as u32).to_le_bytes());
    body.extend_from_slice(&meta);
    body
}

fn hashed_config() -> Config {
    let mut cfg = test_config();
    cfg.users = vec![
        user("alice", SHA512),
        user("bob", BCRYPT),
        user("carol", SHA256),
        user("dave", "plain-text"),
    ];
    cfg.password_required = true;
    cfg
}

fn try_login(port: u16, who: &str, pass: &str) -> Packet {
    let mut c = Client::connect(port, "p");
    let _ = c.recv_packet(); // the server's INFO
    c.send_packet(ptype::INFO, 0, &login_body(who, pass));
    c.recv_packet()
}

#[test]
fn hashed_and_plain_users_can_log_in() {
    let h = start(hashed_config());
    for (who, pass) in [
        ("alice", "Hello world!"),
        ("bob", "U*U"),
        ("carol", "Hello world!"),
        ("dave", "plain-text"),
    ] {
        let p = try_login(h.port(), who, pass);
        assert_eq!(
            (p.ptype, p.sid),
            (ptype::CONTINUE, 0),
            "{who} should get in"
        );
    }
    h.stop_and_join();
}

#[test]
fn wrong_passwords_and_unknown_names_are_refused() {
    let h = start(hashed_config());
    for (who, pass) in [
        ("alice", "hello world!"),
        ("bob", ""),
        ("carol", "x"),
        ("mallory", "Hello world!"),
        ("dave", "plain-texT"),
    ] {
        let p = try_login(h.port(), who, pass);
        assert_eq!(
            (p.ptype, p.sid, p.payload.as_slice()),
            (ptype::CLOSE, 0, &[close::AUTH_BAD_PASSWORD][..]),
            "{who}"
        );
    }
    h.stop_and_join();
}

#[test]
fn a_login_after_a_hashed_check_still_works_on_a_new_connection() {
    // many logins in a row: the pool hands answers back to the right connections
    let h = start(hashed_config());
    let started = Instant::now();
    let mut clients: Vec<(Client, bool)> = (0..12)
        .map(|i| {
            let mut c = Client::connect(h.port(), "p");
            let _ = c.recv_packet();
            let good = i % 2 == 0;
            let pass = if good { "Hello world!" } else { "nope" };
            c.send_packet(ptype::INFO, 0, &login_body("alice", pass));
            (c, good)
        })
        .collect();
    for (c, good) in &mut clients {
        let p = c.recv_packet();
        let want = if *good {
            (ptype::CONTINUE, vec![])
        } else {
            (ptype::CLOSE, vec![close::AUTH_BAD_PASSWORD])
        };
        assert_eq!(p.ptype, want.0);
        if !*good {
            assert_eq!(p.payload, want.1);
        }
    }
    assert!(started.elapsed() < Duration::from_secs(20));
    h.stop_and_join();
}

#[test]
fn unsupported_hash_types_stop_startup_with_a_clear_message() {
    for (secret, word) in [
        ("$y$j9T$salt$hash", "yescrypt"),
        ("$1$salt$hash", "MD5"),
        ("$9$what", "unknown"),
    ] {
        let mut cfg = test_config();
        cfg.users = vec![user("zed", secret)];
        match rustwisp::Server::bind(cfg) {
            Err(e) => {
                let text = e.to_string();
                assert!(text.contains("zed") && text.contains(word), "{text}");
                assert!(
                    !text.contains(secret),
                    "the stored secret must not be echoed"
                );
            }
            Ok(_) => panic!("{secret} should have been refused"),
        }
    }
}
