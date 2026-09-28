//! The ACP `session/update` -> transcript-chunk bridge and the one transcript
//! parser, mirroring `session/acp/transcript-bridge.ts`, `session/acp/normalize.ts`
//! and `transcript/events.ts`.
//!
//! A producer emits [`acp_update_to_transcript_chunk`] (skipping `None`); a
//! consumer decodes it with [`parse_transcript_event`]. The corpus pins the
//! exact `(update) -> (chunk bytes) -> (typed event)` round-trip so producer and
//! consumer can never diverge on the wire.

use serde_json::{Map, Value};

pub const TRANSCRIPT_EVENT_MARKER: &str = "nwfTranscriptEvent";
pub const TRANSCRIPT_EVENT_VERSION: u64 = 1;

const ROLES: [&str; 4] = ["assistant", "user", "system", "tool"];

/// Recursive text extraction from an ACP content block, matching
/// `contentBlockText`.
fn content_block_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => {
            let mut parts = String::new();
            let mut any = false;
            for item in items {
                if let Some(t) = content_block_text(item) {
                    parts.push_str(&t);
                    any = true;
                }
            }
            if any {
                Some(parts)
            } else {
                None
            }
        }
        Value::Object(obj) => match obj.get("type").and_then(Value::as_str) {
            Some("text") => obj.get("text").and_then(Value::as_str).map(str::to_string),
            Some("resource") => obj
                .get("resource")
                .and_then(Value::as_object)
                .and_then(|r| r.get("text"))
                .and_then(Value::as_str)
                .map(str::to_string),
            _ => None,
        },
        _ => None,
    }
}

/// One classified ACP update (only the canonical, wire-bearing variants; every
/// other update is `Ignored`).
enum Classified {
    Message {
        role: String,
        text: String,
    },
    ToolCall {
        call_id: String,
        name: String,
        args: Value,
    },
    ToolResult {
        call_id: String,
        ok: bool,
        result: Value,
    },
    Ignored,
}

fn classify_update(update: &Value) -> Classified {
    let obj = match update.as_object() {
        Some(o) => o,
        None => return Classified::Ignored,
    };
    let session_update = match obj.get("sessionUpdate").and_then(Value::as_str) {
        Some(s) => s,
        None => return Classified::Ignored,
    };
    match session_update {
        "agent_message_chunk" | "agent_thought_chunk" | "user_message_chunk" => {
            // ACP reasoning (`agent_thought_chunk`) has no transcript role, so it
            // folds to `assistant`, exactly as the bridge does.
            let role = match session_update {
                "user_message_chunk" => "user",
                _ => "assistant",
            };
            match obj.get("content").and_then(content_block_text) {
                Some(text) => Classified::Message {
                    role: role.to_string(),
                    text,
                },
                None => Classified::Ignored,
            }
        }
        "tool_call" => {
            let call_id = match obj.get("toolCallId").and_then(Value::as_str) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => return Classified::Ignored,
            };
            let name = match obj.get("title").and_then(Value::as_str) {
                Some(t) if !t.is_empty() => t.to_string(),
                _ => call_id.clone(),
            };
            let args = match obj.get("rawInput") {
                Some(v) if !v.is_null() => v.clone(),
                _ => Value::Null,
            };
            Classified::ToolCall {
                call_id,
                name,
                args,
            }
        }
        "tool_call_update" => {
            let call_id = match obj.get("toolCallId").and_then(Value::as_str) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => return Classified::Ignored,
            };
            let status = obj.get("status").and_then(Value::as_str);
            let ok = match status {
                Some("completed") => true,
                Some("failed") => false,
                _ => return Classified::Ignored,
            };
            let result = if obj.contains_key("rawOutput") {
                obj.get("rawOutput").cloned().unwrap_or(Value::Null)
            } else {
                obj.get("content").cloned().unwrap_or(Value::Null)
            };
            Classified::ToolResult {
                call_id,
                ok,
                result,
            }
        }
        _ => Classified::Ignored,
    }
}

/// Resolve an ACP tool-result's opaque `result` to the transcript `content`
/// string: a string is verbatim, `null` omits `content`, any other JSON value is
/// serialised.
fn tool_result_content(result: &Value) -> Option<String> {
    match result {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(serde_json::to_string(other).expect("wire JSON is serialisable")),
    }
}

/// THE CANONICAL BRIDGE: one ACP `session/update` `update` object -> the exact
/// on-wire transcript-chunk bytes, or `None` for an `ignored` update.
pub fn acp_update_to_transcript_chunk(update: &Value) -> Option<String> {
    let mut m = Map::new();
    m.insert(
        TRANSCRIPT_EVENT_MARKER.into(),
        Value::from(TRANSCRIPT_EVENT_VERSION),
    );
    match classify_update(update) {
        Classified::Message { role, text } => {
            m.insert("kind".into(), "message".into());
            m.insert("role".into(), role.into());
            m.insert("text".into(), text.into());
        }
        Classified::ToolCall {
            call_id,
            name,
            args,
        } => {
            m.insert("kind".into(), "tool-call".into());
            m.insert("name".into(), name.into());
            m.insert("callId".into(), call_id.into());
            m.insert("args".into(), args);
        }
        Classified::ToolResult {
            call_id,
            ok,
            result,
        } => {
            m.insert("kind".into(), "tool-result".into());
            m.insert("callId".into(), call_id.into());
            m.insert("ok".into(), Value::Bool(ok));
            if let Some(content) = tool_result_content(&result) {
                m.insert("content".into(), content.into());
            }
        }
        Classified::Ignored => return None,
    }
    Some(serde_json::to_string(&Value::Object(m)).expect("transcript event is serialisable"))
}

fn to_role(value: Option<&str>) -> &str {
    match value {
        Some(v) if ROLES.contains(&v) => v,
        _ => "assistant",
    }
}

/// Decode a stored chunk into a typed transcript event, matching the ONE parser
/// `parseTranscriptEvent`. A chunk that is not a marker-tagged envelope of a
/// known kind is retained verbatim as a `stream-chunk`, so raw-byte replay
/// fidelity is never lost.
pub fn parse_transcript_event(chunk: &str, offset: i64) -> Value {
    let raw = || {
        let mut m = Map::new();
        m.insert("kind".into(), "stream-chunk".into());
        m.insert("offset".into(), Value::from(offset));
        m.insert("chunk".into(), chunk.into());
        Value::Object(m)
    };
    let body = match decode_envelope(chunk) {
        Some(b) => b,
        None => return raw(),
    };
    let kind = match body.get("kind").and_then(Value::as_str) {
        Some(k) => k,
        None => return raw(),
    };
    match kind {
        "message" => decode_message(&body, offset).unwrap_or_else(raw),
        "tool-call" => decode_tool_call(&body, offset).unwrap_or_else(raw),
        "tool-result" => decode_tool_result(&body, offset),
        _ => raw(),
    }
}

fn decode_envelope(chunk: &str) -> Option<Map<String, Value>> {
    if !chunk.trim_start().starts_with('{') || !chunk.contains(TRANSCRIPT_EVENT_MARKER) {
        return None;
    }
    let parsed: Value = serde_json::from_str(chunk).ok()?;
    let obj = parsed.as_object()?;
    match obj.get(TRANSCRIPT_EVENT_MARKER) {
        Some(Value::Number(n)) if n.as_u64() == Some(TRANSCRIPT_EVENT_VERSION) => Some(obj.clone()),
        _ => None,
    }
}

fn decode_message(body: &Map<String, Value>, offset: i64) -> Option<Value> {
    let text = body.get("text").and_then(Value::as_str)?.to_string();
    let role = to_role(body.get("role").and_then(Value::as_str)).to_string();
    let mut m = Map::new();
    m.insert("kind".into(), "message".into());
    m.insert("offset".into(), Value::from(offset));
    m.insert("role".into(), role.into());
    m.insert("text".into(), text.into());
    Some(Value::Object(m))
}

fn decode_tool_call(body: &Map<String, Value>, offset: i64) -> Option<Value> {
    let name = body.get("name").and_then(Value::as_str)?.to_string();
    let mut m = Map::new();
    m.insert("kind".into(), "tool-call".into());
    m.insert("offset".into(), Value::from(offset));
    m.insert("name".into(), name.into());
    if let Some(call_id) = body.get("callId").and_then(Value::as_str) {
        m.insert("callId".into(), call_id.into());
    }
    if let Some(args) = body.get("args") {
        m.insert("args".into(), args.clone());
    }
    Some(Value::Object(m))
}

fn decode_tool_result(body: &Map<String, Value>, offset: i64) -> Value {
    let ok = body.get("ok").and_then(Value::as_bool).unwrap_or(true);
    let mut m = Map::new();
    m.insert("kind".into(), "tool-result".into());
    m.insert("offset".into(), Value::from(offset));
    m.insert("ok".into(), Value::Bool(ok));
    if let Some(call_id) = body.get("callId").and_then(Value::as_str) {
        m.insert("callId".into(), call_id.into());
    }
    if let Some(content) = body.get("content").and_then(Value::as_str) {
        m.insert("content".into(), content.into());
    }
    Value::Object(m)
}
