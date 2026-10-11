//! The inbound control vocabulary (steer-in) for the `relay` family — the
//! worker's live copy of `@nanobpm/agentic`'s `protocol/control.ts`, matching
//! the conformance suite's `contract-tests/src/hub/control.rs`.
//!
//! A structured steer frame is a JSON envelope tagged `nanoControlFrame: 1`. A
//! bare inbound string that is not such an envelope (a keystroke, a shell line,
//! unrelated JSON) decodes as a `prompt` whose text is the chunk verbatim — the
//! legacy raw-byte steer path the hub still delivers.

use serde_json::{Map, Value};

pub const CONTROL_FRAME_MARKER: &str = "nanoControlFrame";
pub const CONTROL_FRAME_VERSION: u64 = 1;

/// The three inbound steer intents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlFrame {
    Prompt { text: String },
    Cancel { reason: Option<String> },
    Permission { request_id: String, outcome: String },
}

/// The result of decoding an inbound steer chunk. `structured` distinguishes a
/// recognised control envelope from the legacy bare-string-as-prompt fall-back.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlDecode {
    pub frame: ControlFrame,
    pub structured: bool,
}

/// Does `chunk` begin (after JSON-insignificant whitespace) with `{`? Only such
/// a chunk can be a tagged control envelope.
fn starts_with_json_object(chunk: &str) -> bool {
    for b in chunk.bytes() {
        match b {
            0x20 | 0x09 | 0x0a | 0x0d => continue,
            b'{' => return true,
            _ => return false,
        }
    }
    false
}

fn is_control_envelope(value: &Value) -> Option<&Map<String, Value>> {
    let obj = value.as_object()?;
    match obj.get(CONTROL_FRAME_MARKER) {
        Some(Value::Number(n)) if n.as_u64() == Some(CONTROL_FRAME_VERSION) => Some(obj),
        _ => None,
    }
}

/// Validate a tagged envelope into a typed frame, or `None` when the envelope is
/// tagged but malformed (an unknown `kind`, a bad field): the worker ignores a
/// malformed steer rather than acting on a guess.
fn validate_envelope(env: &Map<String, Value>) -> Option<ControlDecode> {
    let frame = match env.get("kind").and_then(Value::as_str)? {
        "prompt" => ControlFrame::Prompt {
            text: env.get("text").and_then(Value::as_str)?.to_string(),
        },
        "cancel" => match env.get("reason") {
            None => ControlFrame::Cancel { reason: None },
            Some(Value::String(reason)) => ControlFrame::Cancel {
                reason: Some(reason.clone()),
            },
            Some(_) => return None,
        },
        "permission" => {
            let request_id = match env.get("requestId") {
                Some(Value::String(s)) if !s.is_empty() => s.clone(),
                _ => return None,
            };
            let outcome = match env.get("outcome").and_then(Value::as_str) {
                Some(o @ ("granted" | "denied")) => o.to_string(),
                _ => return None,
            };
            ControlFrame::Permission {
                request_id,
                outcome,
            }
        }
        _ => return None,
    };
    Some(ControlDecode {
        frame,
        structured: true,
    })
}

/// Decode a raw inbound steer chunk. A tagged envelope is validated and returned
/// typed (`structured: true`); a tagged-but-malformed envelope yields `None`;
/// anything else is the legacy prompt carrying the chunk verbatim.
pub fn parse_inbound_relay_chunk(chunk: &str) -> Option<ControlDecode> {
    let legacy = || {
        Some(ControlDecode {
            frame: ControlFrame::Prompt {
                text: chunk.to_string(),
            },
            structured: false,
        })
    };
    if !starts_with_json_object(chunk) {
        return legacy();
    }
    let parsed: Value = match serde_json::from_str(chunk) {
        Ok(v) => v,
        Err(_) => return legacy(),
    };
    match is_control_envelope(&parsed) {
        Some(env) => validate_envelope(env),
        None => legacy(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_string_is_a_legacy_prompt() {
        let d = parse_inbound_relay_chunk("hello there").unwrap();
        assert_eq!(
            d.frame,
            ControlFrame::Prompt {
                text: "hello there".into()
            }
        );
        assert!(!d.structured);
    }

    #[test]
    fn tagged_prompt_cancel_and_permission_decode() {
        let p = parse_inbound_relay_chunk(r#"{"nanoControlFrame":1,"kind":"prompt","text":"go"}"#)
            .unwrap();
        assert_eq!(p.frame, ControlFrame::Prompt { text: "go".into() });
        assert!(p.structured);

        let c = parse_inbound_relay_chunk(r#"{"nanoControlFrame":1,"kind":"cancel"}"#).unwrap();
        assert_eq!(c.frame, ControlFrame::Cancel { reason: None });

        let perm = parse_inbound_relay_chunk(
            r#"{"nanoControlFrame":1,"kind":"permission","requestId":"r1","outcome":"granted"}"#,
        )
        .unwrap();
        assert_eq!(
            perm.frame,
            ControlFrame::Permission {
                request_id: "r1".into(),
                outcome: "granted".into()
            }
        );
    }

    #[test]
    fn tagged_but_malformed_is_ignored() {
        assert!(parse_inbound_relay_chunk(r#"{"nanoControlFrame":1,"kind":"bogus"}"#).is_none());
        assert!(parse_inbound_relay_chunk(
            r#"{"nanoControlFrame":1,"kind":"permission","requestId":"","outcome":"granted"}"#
        )
        .is_none());
    }

    #[test]
    fn untagged_json_object_is_a_legacy_prompt() {
        let d = parse_inbound_relay_chunk(r#"{"hello":"world"}"#).unwrap();
        assert!(matches!(d.frame, ControlFrame::Prompt { .. }));
        assert!(!d.structured);
    }
}
