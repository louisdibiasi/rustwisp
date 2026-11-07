use std::fmt;

/// Why a parser refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// The input is structurally wrong (truncated packet, bad extension length).
    Invalid,
    /// More bytes are needed before the input can be judged.
    Again,
    /// The peer broke the protocol (reserved bits, bad opcode, non-minimal length).
    Protocol,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProtoError::Invalid => "invalid input",
            ProtoError::Again => "more bytes needed",
            ProtoError::Protocol => "protocol violation",
        })
    }
}

impl std::error::Error for ProtoError {}
