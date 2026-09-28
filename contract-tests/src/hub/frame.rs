//! The agentic-channel frame codec (envelope only) — the worker side of the
//! `@nanobpm/agentic` protocol wire.
//!
//! Wire layout (all integers big-endian, unsigned), mirroring the reference
//! `protocol/frame.ts`:
//!
//! ```text
//!   offset  size  field
//!   0       2     magic       0x4E41 ("NA")
//!   2       1     version     = 1
//!   3       1     lane code   0=control | 1=interactive | 2=bulk
//!   4       1     family code 1..9
//!   5       4     seq         uint32
//!   9       4     payloadLen  uint32 (bytes of UTF-8 JSON that follow)
//!   13      N     payload     UTF-8 JSON
//! ```
//!
//! The codec does not interpret `payload` beyond round-tripping it as JSON.

use serde_json::Value;

pub const FRAME_MAGIC: u16 = 0x4e41;
pub const FRAME_VERSION: u8 = 1;
pub const FRAME_HEADER_BYTES: usize = 13;
pub const MAX_SEQ: u32 = u32::MAX;

/// A QoS lane a frame rides on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Control,
    Interactive,
    Bulk,
}

impl Lane {
    pub fn code(self) -> u8 {
        match self {
            Lane::Control => 0,
            Lane::Interactive => 1,
            Lane::Bulk => 2,
        }
    }

    pub fn from_code(code: u8) -> Option<Lane> {
        match code {
            0 => Some(Lane::Control),
            1 => Some(Lane::Interactive),
            2 => Some(Lane::Bulk),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Lane::Control => "control",
            Lane::Interactive => "interactive",
            Lane::Bulk => "bulk",
        }
    }

    pub fn from_name(s: &str) -> Option<Lane> {
        match s {
            "control" => Some(Lane::Control),
            "interactive" => Some(Lane::Interactive),
            "bulk" => Some(Lane::Bulk),
            _ => None,
        }
    }
}

/// The message family a frame belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Register,
    Heartbeat,
    Deregister,
    Serve,
    Demand,
    Blackboard,
    Relay,
    Claim,
    Release,
}

impl Family {
    pub fn code(self) -> u8 {
        match self {
            Family::Register => 1,
            Family::Heartbeat => 2,
            Family::Deregister => 3,
            Family::Serve => 4,
            Family::Demand => 5,
            Family::Blackboard => 6,
            Family::Relay => 7,
            Family::Claim => 8,
            Family::Release => 9,
        }
    }

    pub fn from_code(code: u8) -> Option<Family> {
        match code {
            1 => Some(Family::Register),
            2 => Some(Family::Heartbeat),
            3 => Some(Family::Deregister),
            4 => Some(Family::Serve),
            5 => Some(Family::Demand),
            6 => Some(Family::Blackboard),
            7 => Some(Family::Relay),
            8 => Some(Family::Claim),
            9 => Some(Family::Release),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Family::Register => "register",
            Family::Heartbeat => "heartbeat",
            Family::Deregister => "deregister",
            Family::Serve => "serve",
            Family::Demand => "demand",
            Family::Blackboard => "blackboard",
            Family::Relay => "relay",
            Family::Claim => "claim",
            Family::Release => "release",
        }
    }

    pub fn from_name(s: &str) -> Option<Family> {
        match s {
            "register" => Some(Family::Register),
            "heartbeat" => Some(Family::Heartbeat),
            "deregister" => Some(Family::Deregister),
            "serve" => Some(Family::Serve),
            "demand" => Some(Family::Demand),
            "blackboard" => Some(Family::Blackboard),
            "relay" => Some(Family::Relay),
            "claim" => Some(Family::Claim),
            "release" => Some(Family::Release),
            _ => None,
        }
    }
}

/// A single decoded agentic-channel frame.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub lane: Lane,
    pub family: Family,
    pub seq: u32,
    pub payload: Value,
}

/// The closed set of decode-error codes, matching `FrameDecodeErrorCode` in the
/// reference codec. The corpus pins one adversarial vector per code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeErrorCode {
    Empty,
    ShortHeader,
    BadMagic,
    UnsupportedVersion,
    UnknownLane,
    UnknownFamily,
    TruncatedPayload,
    TrailingBytes,
    InvalidPayloadJson,
}

impl DecodeErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            DecodeErrorCode::Empty => "empty",
            DecodeErrorCode::ShortHeader => "short-header",
            DecodeErrorCode::BadMagic => "bad-magic",
            DecodeErrorCode::UnsupportedVersion => "unsupported-version",
            DecodeErrorCode::UnknownLane => "unknown-lane",
            DecodeErrorCode::UnknownFamily => "unknown-family",
            DecodeErrorCode::TruncatedPayload => "truncated-payload",
            DecodeErrorCode::TrailingBytes => "trailing-bytes",
            DecodeErrorCode::InvalidPayloadJson => "invalid-payload-json",
        }
    }
}

/// The closed set of encode-error codes, matching `FrameEncodeErrorCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeErrorCode {
    InvalidSeq,
    UnserialisablePayload,
}

/// Encode a frame into its exact wire bytes.
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, EncodeErrorCode> {
    // `seq` is a `u32`, so lane/family/seq are structurally valid by
    // construction; the only encode failure the corpus can express is an
    // unserialisable payload (kept for parity with the reference codec).
    let json = serde_json::to_string(&frame.payload)
        .map_err(|_| EncodeErrorCode::UnserialisablePayload)?;
    let payload = json.into_bytes();
    let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    out.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
    out.push(FRAME_VERSION);
    out.push(frame.lane.code());
    out.push(frame.family.code());
    out.extend_from_slice(&frame.seq.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decode wire bytes into a frame, or the exact error code on rejection.
pub fn decode_frame(bytes: &[u8]) -> Result<Frame, DecodeErrorCode> {
    if bytes.is_empty() {
        return Err(DecodeErrorCode::Empty);
    }
    if bytes.len() < FRAME_HEADER_BYTES {
        return Err(DecodeErrorCode::ShortHeader);
    }
    let magic = u16::from_be_bytes([bytes[0], bytes[1]]);
    if magic != FRAME_MAGIC {
        return Err(DecodeErrorCode::BadMagic);
    }
    if bytes[2] != FRAME_VERSION {
        return Err(DecodeErrorCode::UnsupportedVersion);
    }
    let lane = Lane::from_code(bytes[3]).ok_or(DecodeErrorCode::UnknownLane)?;
    let family = Family::from_code(bytes[4]).ok_or(DecodeErrorCode::UnknownFamily)?;
    let seq = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
    let payload_len = u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]) as usize;
    let end = FRAME_HEADER_BYTES + payload_len;
    if end > bytes.len() {
        return Err(DecodeErrorCode::TruncatedPayload);
    }
    if end < bytes.len() {
        return Err(DecodeErrorCode::TrailingBytes);
    }
    let payload_bytes = &bytes[FRAME_HEADER_BYTES..end];
    // The reference decoder validates strict UTF-8 (fatal) then JSON; both a
    // non-JSON body and invalid UTF-8 surface the same `invalid-payload-json`.
    let text =
        std::str::from_utf8(payload_bytes).map_err(|_| DecodeErrorCode::InvalidPayloadJson)?;
    let payload: Value =
        serde_json::from_str(text).map_err(|_| DecodeErrorCode::InvalidPayloadJson)?;
    Ok(Frame {
        lane,
        family,
        seq,
        payload,
    })
}
