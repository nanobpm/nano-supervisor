//! The agentic-channel frame codec (envelope only) — the worker's live copy of
//! the `@nanobpm/agentic` protocol wire.
//!
//! This is byte-for-byte the layout the conformance suite pins in
//! `contract-tests/src/hub/frame.rs` (issue #5). The daemon's hub client speaks
//! these exact bytes so a Rust-run job's frames are indistinguishable from the
//! Node worker's on the same hub.
//!
//! ```text
//!   offset  size  field
//!   0       2     magic       0x4E41 ("NA")
//!   2       1     version     = 1
//!   3       1     lane code   0=control | 1=interactive | 2=bulk
//!   4       1     family code 1..9
//!   5       4     seq         uint32 (big-endian)
//!   9       4     payloadLen  uint32 (big-endian)
//!   13      N     payload     UTF-8 JSON
//! ```

use serde_json::Value;

pub const FRAME_MAGIC: u16 = 0x4e41;
pub const FRAME_VERSION: u8 = 1;
pub const FRAME_HEADER_BYTES: usize = 13;

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
}

/// A single decoded agentic-channel frame.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub lane: Lane,
    pub family: Family,
    pub seq: u32,
    pub payload: Value,
}

impl Frame {
    pub fn new(lane: Lane, family: Family, seq: u32, payload: Value) -> Frame {
        Frame {
            lane,
            family,
            seq,
            payload,
        }
    }
}

/// The closed set of decode-error codes, matching `FrameDecodeErrorCode` in the
/// reference codec.
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
    UnserialisablePayload,
    PayloadTooLarge,
}

fn header_payload_len(len: usize) -> Result<u32, EncodeErrorCode> {
    u32::try_from(len).map_err(|_| EncodeErrorCode::PayloadTooLarge)
}

/// Encode a frame into its exact wire bytes.
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, EncodeErrorCode> {
    let json = serde_json::to_string(&frame.payload)
        .map_err(|_| EncodeErrorCode::UnserialisablePayload)?;
    let payload = json.into_bytes();
    let payload_len = header_payload_len(payload.len())?;
    let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    out.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
    out.push(FRAME_VERSION);
    out.push(frame.lane.code());
    out.push(frame.family.code());
    out.extend_from_slice(&frame.seq.to_be_bytes());
    out.extend_from_slice(&payload_len.to_be_bytes());
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
    let text = std::str::from_utf8(&bytes[FRAME_HEADER_BYTES..end])
        .map_err(|_| DecodeErrorCode::InvalidPayloadJson)?;
    let payload: Value =
        serde_json::from_str(text).map_err(|_| DecodeErrorCode::InvalidPayloadJson)?;
    Ok(Frame {
        lane,
        family,
        seq,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trips_every_lane_and_family() {
        for lane in [Lane::Control, Lane::Interactive, Lane::Bulk] {
            for family in [
                Family::Register,
                Family::Heartbeat,
                Family::Deregister,
                Family::Serve,
                Family::Demand,
                Family::Blackboard,
                Family::Relay,
                Family::Claim,
                Family::Release,
            ] {
                let frame = Frame::new(lane, family, 7, json!({"k": "v"}));
                let bytes = encode_frame(&frame).expect("encode");
                assert_eq!(decode_frame(&bytes).expect("decode"), frame);
            }
        }
    }

    #[test]
    fn payload_keys_serialize_in_insertion_order() {
        // The live codec promises byte-exact payloads, so object keys MUST stay
        // in insertion order (requires the root crate's serde_json
        // `preserve_order` feature). A sorted `BTreeMap` backing would reorder
        // `{instance, capability}` to `{capability, instance}` — exactly the
        // REGISTER divergence from the golden corpus. This test fails (red) if
        // the feature is ever dropped from Cargo.toml.
        let frame = Frame::new(
            Lane::Control,
            Family::Register,
            0,
            json!({ "instance": "w-1", "capability": { "family": "senior" } }),
        );
        let bytes = encode_frame(&frame).expect("encode");
        let text = std::str::from_utf8(&bytes[FRAME_HEADER_BYTES..]).expect("utf8 payload");
        assert!(
            text.starts_with("{\"instance\":"),
            "payload keys must stay in insertion order (preserve_order), got: {text}"
        );
    }

    #[test]
    fn header_is_exactly_thirteen_bytes_before_payload() {
        let frame = Frame::new(Lane::Bulk, Family::Relay, 1, json!({}));
        let bytes = encode_frame(&frame).unwrap();
        // magic(2) + version(1) + lane(1) + family(1) + seq(4) + len(4) = 13.
        assert_eq!(&bytes[0..2], &FRAME_MAGIC.to_be_bytes());
        assert_eq!(bytes[2], FRAME_VERSION);
        assert_eq!(bytes[3], Lane::Bulk.code());
        assert_eq!(bytes[4], Family::Relay.code());
        assert_eq!(bytes.len(), FRAME_HEADER_BYTES + 2); // "{}" payload
    }

    #[test]
    fn rejects_every_corruption_with_its_code() {
        let good =
            encode_frame(&Frame::new(Lane::Control, Family::Register, 0, json!({}))).unwrap();
        assert_eq!(decode_frame(&[]), Err(DecodeErrorCode::Empty));
        assert_eq!(decode_frame(&good[..5]), Err(DecodeErrorCode::ShortHeader));

        let mut bad_magic = good.clone();
        bad_magic[0] = 0;
        assert_eq!(decode_frame(&bad_magic), Err(DecodeErrorCode::BadMagic));

        let mut bad_version = good.clone();
        bad_version[2] = 9;
        assert_eq!(
            decode_frame(&bad_version),
            Err(DecodeErrorCode::UnsupportedVersion)
        );

        let mut bad_lane = good.clone();
        bad_lane[3] = 9;
        assert_eq!(decode_frame(&bad_lane), Err(DecodeErrorCode::UnknownLane));

        let mut bad_family = good.clone();
        bad_family[4] = 99;
        assert_eq!(
            decode_frame(&bad_family),
            Err(DecodeErrorCode::UnknownFamily)
        );

        let mut truncated = good.clone();
        truncated.pop();
        assert_eq!(
            decode_frame(&truncated),
            Err(DecodeErrorCode::TruncatedPayload)
        );

        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(decode_frame(&trailing), Err(DecodeErrorCode::TrailingBytes));
    }
}
