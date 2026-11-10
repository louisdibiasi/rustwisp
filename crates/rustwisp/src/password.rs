//! Checking a client's password against a `password-user` entry.
//!
//! An entry is either plain text or a crypt(3) style hash. Supported hashes are bcrypt (`$2a$`,
//! `$2b$`, `$2x$`, `$2y$`), SHA-256 crypt (`$5$`) and SHA-512 crypt (`$6$`). Older schemes (MD5,
//! DES) and yescrypt are not accepted; startup validation refuses them by name so a typo cannot
//! silently lock everyone out.

/// Longest client password that is checked at all. Longer ones cannot be right and would only
/// make a hash take longer.
pub const MAX_PASSWORD: usize = 1024;

/// How a stored secret is to be compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Plain,
    Bcrypt,
    Sha256Crypt,
    Sha512Crypt,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
struct WorkProfile {
    scheme: Scheme,
    rounds: u32,
    salt_len: usize,
    variant: u8,
}

#[cfg(any(target_os = "linux", test))]
fn work_profile(secret: &str) -> Result<WorkProfile, &'static str> {
    const MALFORMED: &str = "malformed password hash";
    let scheme = scheme(secret)?;
    let mut profile = WorkProfile {
        scheme,
        rounds: 0,
        salt_len: 0,
        variant: 0,
    };
    if scheme == Scheme::Plain {
        return Ok(profile);
    }
    let encoded = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
    };
    if scheme == Scheme::Bcrypt {
        let parts: Vec<_> = secret.split('$').collect();
        if parts.len() != 4
            || parts[2].len() != 2
            || !parts[2].bytes().all(|b| b.is_ascii_digit())
            || parts[3].len() != 53
            || !encoded(parts[3])
        {
            return Err(MALFORMED);
        }
        profile.rounds = parts[2].parse().map_err(|_| MALFORMED)?;
        if !(4..=31).contains(&profile.rounds) {
            return Err(MALFORMED);
        }
        profile.variant = secret.as_bytes()[2];
        profile.salt_len = 22;
    } else {
        let mut parts = secret[3..].split('$');
        let first = parts.next().ok_or(MALFORMED)?;
        let salt = if let Some(rounds) = first.strip_prefix("rounds=") {
            profile.rounds = rounds
                .parse::<u32>()
                .map_err(|_| MALFORMED)?
                .clamp(1000, 999_999_999);
            parts.next().ok_or(MALFORMED)?
        } else {
            profile.rounds = 5000;
            first
        };
        let checksum = parts.next().ok_or(MALFORMED)?;
        let checksum_len = if scheme == Scheme::Sha256Crypt {
            43
        } else {
            86
        };
        if parts.next().is_some()
            || !encoded(salt)
            || !encoded(checksum)
            || checksum.len() != checksum_len
        {
            return Err(MALFORMED);
        }
        profile.salt_len = salt.len().min(16);
    }
    Ok(profile)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn validate_profiles(users: &[rustwisp_config::User]) -> Result<(), &'static str> {
    let mut expected = None;
    for user in users {
        let profile = work_profile(&user.secret)?;
        if expected.as_ref().is_some_and(|first| first != &profile) {
            return Err(
                "password-user entries must all be plain text or use one hash scheme, variant, cost and salt length",
            );
        }
        expected = Some(profile);
    }
    Ok(())
}

/// Work out the scheme of a stored secret. `Err` carries the reason a `$...` value is refused.
pub fn scheme(secret: &str) -> Result<Scheme, &'static str> {
    if !secret.starts_with('$') {
        return Ok(Scheme::Plain);
    }
    let has = |p: &str| secret.starts_with(p);
    if has("$2a$") || has("$2b$") || has("$2x$") || has("$2y$") {
        Ok(Scheme::Bcrypt)
    } else if has("$5$") {
        Ok(Scheme::Sha256Crypt)
    } else if has("$6$") {
        Ok(Scheme::Sha512Crypt)
    } else if has("$y$") || has("$7$") {
        Err("yescrypt and scrypt hashes are not supported; use bcrypt ($2b$) or SHA-512 ($6$)")
    } else if has("$1$") {
        Err("MD5 crypt is too weak and is not supported; use bcrypt ($2b$) or SHA-512 ($6$)")
    } else {
        Err("unknown hash type; use bcrypt ($2b$), SHA-256 ($5$) or SHA-512 ($6$), or plain text")
    }
}

/// Plain text compared without stopping at the first difference.
pub fn verify_plain(secret: &str, pass: &[u8]) -> bool {
    let stored = secret.as_bytes();
    let mut diff = u8::from(stored.len() != pass.len());
    for (i, &b) in pass.iter().enumerate() {
        diff |= b ^ stored.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// Check `pass` against a hashed secret. This is slow on purpose, so callers run it off the
/// event loop. A secret of an unsupported scheme never matches.
pub fn verify_hash(secret: &str, pass: &[u8]) -> bool {
    if pass.len() > MAX_PASSWORD {
        return false;
    }
    match scheme(secret) {
        Ok(Scheme::Bcrypt) => pwhash::bcrypt::verify(pass, secret),
        Ok(Scheme::Sha256Crypt) => pwhash::sha256_crypt::verify(pass, secret),
        Ok(Scheme::Sha512Crypt) => pwhash::sha512_crypt::verify(pass, secret),
        Ok(Scheme::Plain) => verify_plain(secret, pass),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BCRYPT: &str = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    const SHA256: &str = "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5";
    const SHA512: &str = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";

    #[test]
    fn password_work_profiles_match_effective_parameters() {
        let users = |secrets: &[&str]| {
            secrets
                .iter()
                .enumerate()
                .map(|(i, s)| rustwisp_config::User {
                    name: format!("user{i}"),
                    secret: (*s).into(),
                })
                .collect::<Vec<_>>()
        };
        assert!(validate_profiles(&users(&["short", "longer plain password"])).is_ok());
        assert!(validate_profiles(&users(&[BCRYPT, BCRYPT])).is_ok());
        assert!(
            validate_profiles(&users(&[
                SHA512,
                &SHA512.replace("saltstring", "newsaltstr")
            ]))
            .is_ok()
        );
        assert!(
            validate_profiles(&users(&[
                SHA512,
                &SHA512.replacen("$6$", "$6$rounds=5000$", 1)
            ]))
            .is_ok()
        );
        for other in [
            "plain".to_string(),
            SHA256.to_string(),
            BCRYPT.replace("$05$", "$06$"),
            BCRYPT.replace("$2a$", "$2b$"),
        ] {
            assert!(validate_profiles(&users(&[BCRYPT, &other])).is_err());
        }
        assert!(
            validate_profiles(&users(&[SHA512, &SHA512.replace("saltstring", "short")])).is_err()
        );
        assert!(
            validate_profiles(&users(&[
                SHA512,
                &SHA512.replacen("$6$", "$6$rounds=6000$", 1)
            ]))
            .is_err()
        );
        for malformed in [
            "$2a$05$bad",
            "$2b$xx$bad",
            "$6$",
            "$5$rounds=x$salt$bad",
            "$6$salt$bad",
        ] {
            assert!(work_profile(malformed).is_err());
        }
    }

    #[test]
    fn plain_text_matches_exactly() {
        assert!(verify_plain("hunter2", b"hunter2"));
        assert!(!verify_plain("hunter2", b"hunter3"));
        assert!(!verify_plain("hunter2", b"hunter"));
        assert!(!verify_plain("hunter2", b"hunter22"));
        assert!(!verify_plain("", b"x"));
    }

    #[test]
    fn known_vectors_verify() {
        assert!(verify_hash(BCRYPT, b"U*U"));
        assert!(!verify_hash(BCRYPT, b"U*u"));
        assert!(verify_hash(SHA256, b"Hello world!"));
        assert!(!verify_hash(SHA256, b"Hello world"));
        assert!(verify_hash(SHA512, b"Hello world!"));
        assert!(!verify_hash(SHA512, b"hello world!"));
    }

    #[test]
    fn schemes_are_recognised_and_weak_ones_named() {
        assert_eq!(scheme("secret"), Ok(Scheme::Plain));
        assert_eq!(scheme(BCRYPT), Ok(Scheme::Bcrypt));
        assert_eq!(scheme("$2b$10$xxxxxxxxxxxxxxxxxxxxxx"), Ok(Scheme::Bcrypt));
        assert_eq!(scheme(SHA256), Ok(Scheme::Sha256Crypt));
        assert_eq!(scheme(SHA512), Ok(Scheme::Sha512Crypt));
        assert!(scheme("$y$j9T$salt$hash").unwrap_err().contains("yescrypt"));
        assert!(scheme("$1$salt$hash").unwrap_err().contains("MD5"));
        assert!(scheme("$9$what").unwrap_err().contains("unknown"));
    }

    #[test]
    fn unsupported_or_malformed_hashes_never_match() {
        assert!(!verify_hash("$1$salt$hash", b"anything"));
        assert!(!verify_hash("$y$j9T$salt$hash", b"anything"));
        assert!(!verify_hash("$2b$garbage", b"anything"));
        assert!(!verify_hash("$6$", b""));
    }

    #[test]
    fn oversized_passwords_are_refused_before_hashing() {
        let long = vec![b'x'; MAX_PASSWORD + 1];
        assert!(!verify_hash(SHA512, &long));
    }
}
