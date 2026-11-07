//! Wire formats for holyWisp: the Wisp v1/v2 packet codec and RFC 6455 WebSocket framing.
//!
//! Everything here is a pure function over byte slices. There is no I/O and no allocation on the
//! parse paths, so the server and the client can share it and the fuzz targets can hammer it.

pub mod base64;
mod error;
pub mod sha1;
pub mod simd;
pub mod webkey;
pub mod wisp;
pub mod ws;

pub use error::ProtoError;
