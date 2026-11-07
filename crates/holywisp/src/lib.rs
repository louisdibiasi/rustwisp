//! The holyWisp server: a Wisp v1/v2 proxy over WebSocket, a Rust rewrite of the C server.
//!
//! The policy modules (`egress`, `filter`, `buf`, `slab`, `stats`, `pages`) are plain Rust and
//! build on every platform. The event loop, sockets and relay are Linux only.

pub mod buf;
pub mod egress;
pub mod filter;
pub mod pages;
pub mod slab;
pub mod stats;

#[cfg(target_os = "linux")]
mod conn;
#[cfg(target_os = "linux")]
mod dns;
#[cfg(target_os = "linux")]
mod link;
#[cfg(target_os = "linux")]
mod server;
#[cfg(target_os = "linux")]
mod stream;
#[cfg(target_os = "linux")]
pub mod sys;
#[cfg(target_os = "linux")]
mod worker;

#[cfg(target_os = "linux")]
pub use server::{Server, ServerHandle};
#[cfg(target_os = "linux")]
pub use worker::SpliceMode;
