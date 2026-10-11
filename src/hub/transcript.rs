//! The ACP `session/update` → transcript-chunk bridge (producer side) — the
//! worker's live copy of `@nanobpm/agentic`'s transcript bridge, matching the
//! conformance suite's `contract-tests/src/hub/transcript.rs`.
//!
//! The daemon feeds every ACP `session/update` it receives from an agent to
//! [`acp_update_to_transcript_chunk`]; a non-`None` result is the exact on-wire
//! chunk the hub (and any observer) decodes back into a typed transcript event.
//! Producing identical bytes is what makes a Rust-run job's live transcript look
//! the same as a Node-run job's (issue #10 acceptance).

use serde_json::{Map, Value};

pub const TRANSCRIPT_EVENT_MARKER: &str = "nwfTranscriptEvent";
pub const TRANSCRIPT_EVENT_VERSION: u64 = 1;

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
            any.then_some(parts)
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
            let ok = match obj.get("status").and_then(Value::as_str) {
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

/// THE CANONICAL BRIDGE: one ACP `session/update` `update` object → the exact
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn agent_message_chunk_becomes_a_message_event() {
        let chunk = acp_update_to_transcript_chunk(&json!({
            "sessionUpdate": "agent_message_chunk",
            "content": { "type": "text", "text": "hi" }
        }))
        .expect("message produces a chunk");
        assert!(chunk.contains("\"nwfTranscriptEvent\":1"));
        assert!(chunk.contains("\"kind\":\"message\""));
        assert!(chunk.contains("\"role\":\"assistant\""));
        assert!(chunk.contains("\"text\":\"hi\""));
    }

    #[test]
    fn thought_chunk_folds_to_assistant() {
        let chunk = acp_update_to_transcript_chunk(&json!({
            "sessionUpdate": "agent_thought_chunk",
            "content": "pondering"
        }))
        .unwrap();
        assert!(chunk.contains("\"role\":\"assistant\""));
    }

    #[test]
    fn ignored_updates_produce_no_chunk() {
        assert!(acp_update_to_transcript_chunk(&json!({"sessionUpdate": "plan"})).is_none());
        assert!(acp_update_to_transcript_chunk(&json!({"no": "sessionUpdate"})).is_none());
    }

    #[test]
    fn tool_call_and_terminal_result_bridge() {
        let call = acp_update_to_transcript_chunk(&json!({
            "sessionUpdate": "tool_call",
            "toolCallId": "c1",
            "title": "grep",
            "rawInput": {"q": "x"}
        }))
        .unwrap();
        assert!(call.contains("\"kind\":\"tool-call\""));
        assert!(call.contains("\"callId\":\"c1\""));

        let done = acp_update_to_transcript_chunk(&json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": "c1",
            "status": "completed",
            "rawOutput": "ok"
        }))
        .unwrap();
        assert!(done.contains("\"kind\":\"tool-result\""));
        assert!(done.contains("\"ok\":true"));
        assert!(done.contains("\"content\":\"ok\""));

        // An in-progress update is not a terminal result.
        assert!(acp_update_to_transcript_chunk(&json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": "c1",
            "status": "in_progress"
        }))
        .is_none());
    }
}
