//! Agent result handling: read the agent's structured result from its result
//! file (`$AGENT_RESULT_FILE`) or a `::nano:result:: {json}` stdout sentinel /
//! trailing ```` ```json ```` fence, strip the harness-reserved keys, and decide
//! whether a run actually produced any work.
//!
//! Ported from the Node plugin (`c8ctl-plugin.js`): the harness stays
//! app-agnostic — it merges whatever object the agent returns; the app's prompt
//! owns the field vocabulary.

use std::collections::HashMap;

use serde_json::{Map, Value};

pub const RESULT_SENTINEL: &str = "::nano:result::";
const MAX_RESULT_FILE_BYTES: u64 = 1_048_576; // 1 MiB

/// Keys the harness owns — an agent's returned result can never overwrite these
/// (nor anything in the reserved `io.nanobpm.*` namespace).
const RESERVED_RESULT_KEYS: &[&str] = &[
    "output",
    "exitCode",
    "agent",
    "truncated",
    "branch",
    "commits",
    "pushed",
    "pullRequest",
    "forcedReap",
    "pushFailed",
    "pushError",
    "strandedCommits",
    "branchMismatch",
    "scanError",
    "worldMarker",
];

const PROTO_POLLUTION_KEYS: &[&str] = &["__proto__", "constructor", "prototype"];

/// Parse `text` as a JSON object, returning it only when it is a plain object.
fn parse_object(text: &str) -> Option<Map<String, Value>> {
    if text.trim().is_empty() {
        return None;
    }
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(m)) => Some(m),
        _ => None,
    }
}

/// Read and parse the agent's result file, if it wrote one. Best-effort: a
/// missing, oversized, non-regular, or malformed file is treated as "no
/// structured result". The file is agent-controlled, so a symlink or an
/// oversized payload is rejected (`symlink_metadata`, size cap).
pub fn read_result_file(path: &std::path::Path) -> Option<Map<String, Value>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_RESULT_FILE_BYTES {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    parse_object(&text)
}

/// Extract a result object from stdout: prefer the LAST `::nano:result:: {json}`
/// sentinel line, else the LAST ```` ```json ```` fenced block ("last wins").
pub fn parse_result_from_stdout(stdout: &str) -> Option<Map<String, Value>> {
    let lines: Vec<&str> = stdout.split('\n').collect();
    for line in lines.iter().rev() {
        if let Some(idx) = line.find(RESULT_SENTINEL) {
            let rest = &line[idx + RESULT_SENTINEL.len()..];
            if let Some(obj) = parse_object(rest.trim()) {
                return Some(obj);
            }
        }
    }
    // Fenced blocks: ```<tag>\n ... ```
    let fences = fenced_blocks(stdout);
    for block in fences.iter().rev() {
        if let Some(obj) = parse_object(block.trim()) {
            return Some(obj);
        }
    }
    None
}

/// Collect the inner text of every ```` ``` ````-fenced block in `text`.
fn fenced_blocks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("```") {
        let after_open = &rest[open + 3..];
        // Skip an optional language tag up to the newline.
        let Some(nl) = after_open.find('\n') else {
            break;
        };
        let body_start = &after_open[nl + 1..];
        let Some(close) = body_start.find("```") else {
            break;
        };
        out.push(body_start[..close].to_string());
        rest = &body_start[close + 3..];
    }
    out
}

/// The domain result variables an agent may return: the parsed object with the
/// harness-reserved keys, the prototype-pollution keys, and the `io.nanobpm.*`
/// namespace stripped, so it can never clobber the audit envelope or git facts.
pub fn sanitize_result_vars(obj: &Map<String, Value>) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    for (k, v) in obj {
        if RESERVED_RESULT_KEYS.contains(&k.as_str()) {
            continue;
        }
        if PROTO_POLLUTION_KEYS.contains(&k.as_str()) {
            continue;
        }
        if k.starts_with("io.nanobpm.") {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }
    out
}

/// True when `obj` carries at least one EFFECTIVE result var: a key that
/// survives [`sanitize_result_vars`] AND whose value is not null.
pub fn has_effective_result_vars(obj: &Map<String, Value>) -> bool {
    sanitize_result_vars(obj).values().any(|v| !v.is_null())
}

/// Remove from `stdout` only the value-less result markers (an empty /
/// reserved-only / null-valued `::nano:result::` sentinel or ```` ```json ````
/// fence). Substantive prose survives, so it still attests real work.
fn stdout_stripped_of_empty_result(stdout: &str) -> String {
    let kept: Vec<String> = stdout
        .split('\n')
        .map(|line| match line.find(RESULT_SENTINEL) {
            Some(idx) => {
                let rest = &line[idx + RESULT_SENTINEL.len()..];
                match parse_object(rest.trim()) {
                    Some(obj) if !has_effective_result_vars(&obj) => {
                        line[..idx].trim_end().to_string()
                    }
                    _ => line.to_string(),
                }
            }
            None => line.to_string(),
        })
        .collect();
    // Also drop value-less fenced blocks entirely.
    let joined = kept.join("\n");
    let mut result = joined.clone();
    for block in fenced_blocks(&joined) {
        if let Some(obj) = parse_object(block.trim()) {
            if !has_effective_result_vars(&obj) {
                // Remove the whole fence occurrence.
                if let Some(pos) = result.find(&block) {
                    // Cut back to the opening fence and forward to the closing one.
                    let before = result[..pos].rfind("```").unwrap_or(pos);
                    let after = result[pos + block.len()..]
                        .find("```")
                        .map(|i| pos + block.len() + i + 3)
                        .unwrap_or(result.len());
                    result.replace_range(before..after, "");
                }
            }
        }
    }
    result
}

/// The empty-job detector. A run that produced NOTHING — no effective result
/// vars, no substantive stdout, and (for ACP) no turns — did no work: completing
/// it would silently drop whatever the job carried, so the caller FAILS the job
/// (preserving retries) instead. Returns a reason when the run is empty.
pub fn detect_empty(
    result_vars: Option<&Map<String, Value>>,
    stdout: &str,
    had_turns: bool,
) -> Option<String> {
    if result_vars.is_some_and(has_effective_result_vars) {
        return None;
    }
    if !stdout_stripped_of_empty_result(stdout).trim().is_empty() {
        return None;
    }
    if had_turns {
        return None;
    }
    Some(
        "agent produced nothing — no result vars, no output, no transcript turns. This is the \
         signature of a protocol-mismatched or no-op harness; completing the job would silently \
         drop what it carried, so it is failed (retries preserved) instead of completed."
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn sentinel_last_wins() {
        let out =
            "noise\n::nano:result:: {\"status\":\"a\"}\nmore\n::nano:result:: {\"status\":\"b\"}\n";
        let r = parse_result_from_stdout(out).unwrap();
        assert_eq!(r["status"], json!("b"));
    }

    #[test]
    fn fenced_json_fallback() {
        let out = "prose\n```json\n{\"status\":\"ok\"}\n```\ntail";
        let r = parse_result_from_stdout(out).unwrap();
        assert_eq!(r["status"], json!("ok"));
    }

    #[test]
    fn sanitize_strips_reserved_and_namespace() {
        let o = obj(json!({"status":"ok","pushed":true,"io.nanobpm.x":1,"__proto__":2}));
        let s = sanitize_result_vars(&o);
        assert_eq!(s.len(), 1);
        assert_eq!(s["status"], json!("ok"));
    }

    #[test]
    fn effective_vars_ignores_null_and_reserved() {
        assert!(!has_effective_result_vars(&obj(json!({"pushed":true}))));
        assert!(!has_effective_result_vars(&obj(json!({"status":null}))));
        assert!(has_effective_result_vars(&obj(json!({"status":"x"}))));
    }

    #[test]
    fn empty_when_only_valueless_sentinel() {
        let out = "::nano:result:: {}\n";
        assert!(detect_empty(None, out, false).is_some());
    }

    #[test]
    fn not_empty_with_substantive_stdout() {
        assert!(detect_empty(None, "did real work\n", false).is_none());
    }

    #[test]
    fn not_empty_with_turns() {
        assert!(detect_empty(None, "", true).is_none());
    }

    #[test]
    fn not_empty_with_effective_vars() {
        let o = obj(json!({"status":"done"}));
        assert!(detect_empty(Some(&o), "", false).is_none());
    }
}
