//! The inbound control vocabulary (steer-in) for the `relay` family, mirroring
//! `protocol/control.ts`.
//!
//! A structured frame is a JSON envelope tagged with the marker
//! `nanoControlFrame: 1`. A bare inbound string that is not such an envelope (a
//! keystroke, a shell line, unrelated JSON) decodes as a `prompt` whose text is
//! the chunk verbatim — the legacy raw-byte steer path.

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

impl ControlFrame {
    /// The canonical typed-frame JSON (`kind` + fields), as the corpus records
    /// it. Key order is irrelevant here — callers compare by value.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        match self {
            ControlFrame::Prompt { text } => {
                m.insert("kind".into(), "prompt".into());
                m.insert("text".into(), text.clone().into());
            }
            ControlFrame::Cancel { reason } => {
                m.insert("kind".into(), "cancel".into());
                if let Some(r) = reason {
                    m.insert("reason".into(), r.clone().into());
                }
            }
            ControlFrame::Permission {
                request_id,
                outcome,
            } => {
                m.insert("kind".into(), "permission".into());
                m.insert("requestId".into(), request_id.clone().into());
                m.insert("outcome".into(), outcome.clone().into());
            }
        }
        Value::Object(m)
    }

    /// Encode a typed frame as its canonical wire chunk — a marker-tagged JSON
    /// envelope that round-trips back to an equal frame. Field order matches the
    /// reference encoder so the bytes are identical.
    pub fn encode(&self) -> String {
        let mut m = Map::new();
        m.insert(
            CONTROL_FRAME_MARKER.into(),
            Value::from(CONTROL_FRAME_VERSION),
        );
        match self {
            ControlFrame::Prompt { text } => {
                m.insert("kind".into(), "prompt".into());
                m.insert("text".into(), text.clone().into());
            }
            ControlFrame::Cancel { reason } => {
                m.insert("kind".into(), "cancel".into());
                if let Some(r) = reason {
                    m.insert("reason".into(), r.clone().into());
                }
            }
            ControlFrame::Permission {
                request_id,
                outcome,
            } => {
                m.insert("kind".into(), "permission".into());
                m.insert("requestId".into(), request_id.clone().into());
                m.insert("outcome".into(), outcome.clone().into());
            }
        }
        // `serde_json` with the `preserve_order` feature keeps insertion order.
        serde_json::to_string(&Value::Object(m)).expect("control envelope is serialisable")
    }
}

/// The closed set of control-envelope validation-error codes, matching
/// `InboundControlErrorCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlErrorCode {
    BadKind,
    BadPromptText,
    BadCancelReason,
    BadPermissionRequestId,
    BadPermissionOutcome,
}

impl ControlErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ControlErrorCode::BadKind => "bad-kind",
            ControlErrorCode::BadPromptText => "bad-prompt-text",
            ControlErrorCode::BadCancelReason => "bad-cancel-reason",
            ControlErrorCode::BadPermissionRequestId => "bad-permission-request-id",
            ControlErrorCode::BadPermissionOutcome => "bad-permission-outcome",
        }
    }
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

fn validate_envelope(env: &Map<String, Value>) -> Result<ControlDecode, Vec<ControlErrorCode>> {
    match env.get("kind").and_then(Value::as_str) {
        Some("prompt") => match env.get("text") {
            Some(Value::String(text)) => Ok(ControlDecode {
                frame: ControlFrame::Prompt { text: text.clone() },
                structured: true,
            }),
            _ => Err(vec![ControlErrorCode::BadPromptText]),
        },
        Some("cancel") => match env.get("reason") {
            None => Ok(ControlDecode {
                frame: ControlFrame::Cancel { reason: None },
                structured: true,
            }),
            Some(Value::String(reason)) => Ok(ControlDecode {
                frame: ControlFrame::Cancel {
                    reason: Some(reason.clone()),
                },
                structured: true,
            }),
            Some(_) => Err(vec![ControlErrorCode::BadCancelReason]),
        },
        Some("permission") => {
            let mut errors = Vec::new();
            let request_id = match env.get("requestId") {
                Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
                _ => {
                    errors.push(ControlErrorCode::BadPermissionRequestId);
                    None
                }
            };
            let outcome = match env.get("outcome").and_then(Value::as_str) {
                Some(o @ ("granted" | "denied")) => Some(o.to_string()),
                _ => {
                    errors.push(ControlErrorCode::BadPermissionOutcome);
                    None
                }
            };
            match (request_id, outcome) {
                (Some(request_id), Some(outcome)) if errors.is_empty() => Ok(ControlDecode {
                    frame: ControlFrame::Permission {
                        request_id,
                        outcome,
                    },
                    structured: true,
                }),
                _ => Err(errors),
            }
        }
        _ => Err(vec![ControlErrorCode::BadKind]),
    }
}

/// Decode a raw inbound steer chunk. A tagged envelope is validated and returned
/// typed (`structured: true`); a tagged-but-malformed envelope is a validation
/// error; anything else is the legacy prompt carrying the chunk verbatim.
pub fn parse_inbound_relay_chunk(chunk: &str) -> Result<ControlDecode, Vec<ControlErrorCode>> {
    let legacy = || ControlDecode {
        frame: ControlFrame::Prompt {
            text: chunk.to_string(),
        },
        structured: false,
    };
    if !starts_with_json_object(chunk) {
        return Ok(legacy());
    }
    let parsed: Value = match serde_json::from_str(chunk) {
        Ok(v) => v,
        Err(_) => return Ok(legacy()),
    };
    match is_control_envelope(&parsed) {
        Some(env) => validate_envelope(env),
        None => Ok(legacy()),
    }
}
