//! Worker-side agentic-hub protocol, held to the shared `@nanobpm/agentic`
//! conformance corpus (issue #5).
//!
//! Submodules mirror the reference `@nanobpm/agentic/protocol` codec so this
//! repo's worker is held to identical wire bytes:
//!
//! - [`frame`] — the binary channel envelope (frame <-> bytes).
//! - [`control`] — the inbound steer vocabulary (prompt / cancel / permission).
//! - [`transcript`] — the ACP `session/update` -> transcript-chunk bridge.
//! - [`vocab`] — the registry vocabulary-document validator.
//! - [`token`] — the routing-token grammar parser.
//!
//! [`corpus`] loads the byte-exact fixture snapshot in `fixtures/hub/`
//! (`@nanobpm/agentic` version in `fixtures/hub/VERSION`). `tests/hub.rs`
//! replays it and diffs the frames.

pub mod control;
pub mod frame;
pub mod token;
pub mod transcript;
pub mod vocab;

pub mod corpus;

/// Decode a lowercase-hex string into bytes. Returns `None` on any non-hex
/// character or an odd length.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// Encode bytes as a lowercase-hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}
