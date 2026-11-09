//! Sec-WebSocket-Accept and client key helpers.

use crate::{base64, sha1, ws};

/// Sec-WebSocket-Accept for a Sec-WebSocket-Key value: base64(sha1(key + GUID)).
pub fn accept_key(key: &str) -> String {
    let mut buf = Vec::with_capacity(key.len() + ws::GUID.len());
    buf.extend_from_slice(key.as_bytes());
    buf.extend_from_slice(ws::GUID.as_bytes());
    base64::encode(&sha1::digest(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn accept_value_has_the_fixed_length() {
        assert_eq!(accept_key("anything at all").len(), ws::ACCEPT_LEN);
    }
}
