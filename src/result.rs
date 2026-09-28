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
/// oversized payload is rejected (atomic no-follow open, size cap).
pub fn read_result_file(path: &std::path::Path) -> Option<Map<String, Value>> {
    use std::io::Read;
    // Open first, then bound the read against the OPEN file handle. Checking a
    // `symlink_metadata` snapshot and then `read_to_string`ing the path is a TOCTOU
    // gap: an agent could grow or swap the path in between and force an unbounded
    // allocation despite the cap. An atomic no-follow open (`O_NOFOLLOW` on unix,
    // `FILE_FLAG_OPEN_REPARSE_POINT` + reparse-point rejection on Windows)
    // preserves the no-symlink guarantee, and `take` caps the bytes we will
    // actually read/allocate.
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open the reparse point / symlink itself
        // rather than following it, the Windows analogue of `O_NOFOLLOW`. A
        // swapped-in symlink is then opened as the link and rejected below via
        // its reparse-point attribute, so the daemon never reads through it.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    // No atomic no-follow open on other platforms: reject a symlink explicitly so
    // the documented no-symlink guarantee still holds (best-effort; such targets
    // are not supported daemon hosts).
    #[cfg(not(any(unix, windows)))]
    {
        if std::fs::symlink_metadata(path).ok()?.file_type().is_symlink() {
            return None;
        }
    }
    let file = opts.open(path).ok()?;
    let meta = file.metadata().ok()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Reject a reparse point (symlink / junction) opened via
        // FILE_FLAG_OPEN_REPARSE_POINT above, so we never read through it.
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return None;
        }
    }
    if !meta.is_file() || meta.len() > MAX_RESULT_FILE_BYTES {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_RESULT_FILE_BYTES)
        .read_to_string(&mut text)
        .ok()?;
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
    fenced_spans(text).into_iter().map(|(_, body)| body).collect()
}

/// Every ```` ``` ````-fenced block as `(full-fence byte range, inner body)`. The
/// range covers the opening backticks through the closing backticks, so a caller
/// can excise a *specific* block unambiguously — a content search (`find(&body)`)
/// misbehaves for a zero-length body (`find("")` returns 0, matching the start of
/// the string) and for duplicate bodies (always the first match).
fn fenced_spans(text: &str) -> Vec<(std::ops::Range<usize>, String)> {
    let mut out = Vec::new();
    let mut base = 0usize;
    while let Some(open_rel) = text[base..].find("```") {
        let open = base + open_rel;
        let after_open = open + 3;
        // Skip an optional language tag up to the newline.
        let Some(nl_rel) = text[after_open..].find('\n') else {
            break;
        };
        let body_start = after_open + nl_rel + 1;
        let Some(close_rel) = text[body_start..].find("```") else {
            break;
        };
        let close = body_start + close_rel;
        out.push((open..close + 3, text[body_start..close].to_string()));
        base = close + 3;
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
    // Also drop value-less fenced blocks entirely. Iterate spans back-to-front so
    // each removal leaves earlier byte offsets valid. A zero-length or
    // reserved-only/null fence body carries no result, so it is excised too rather
    // than being mistaken for substantive stdout (an empty ```` ```json\n``` ````
    // fence would otherwise defeat `detect_empty`). Genuine prose/code fences
    // (non-empty, non-object bodies) are left untouched.
    let mut result = kept.join("\n");
    let spans = fenced_spans(&result);
    for (span, body) in spans.into_iter().rev() {
        let trimmed = body.trim();
        let value_less = trimmed.is_empty()
            || parse_object(trimmed).is_some_and(|obj| !has_effective_result_vars(&obj));
        if value_less {
            result.replace_range(span, "");
        }
    }
    result
}

/// The empty-job detector. A run that produced NOTHING — no effective result
/// vars and no substantive stdout (after value-less result markers/fences are
/// stripped) — did no work: completing it would silently drop whatever the job
/// carried, so the caller FAILS the job (preserving retries) instead. Note that
/// neither raw ACP `session/update` activity (tool-call/status notifications
/// without any assistant text) nor a lone value-less `::nano:result::` marker
/// counts as work — both leave nothing substantive behind and so are failed
/// rather than settled empty. Returns a reason when the run is empty.
pub fn detect_empty(
    result_vars: Option<&Map<String, Value>>,
    stdout: &str,
) -> Option<String> {
    if result_vars.is_some_and(has_effective_result_vars) {
        return None;
    }
    if !stdout_stripped_of_empty_result(stdout).trim().is_empty() {
        return None;
    }
    Some(
        "agent produced nothing — no result vars and no substantive output (only tool/status \
         activity or a value-less result marker). This is the signature of a protocol-mismatched \
         or no-op harness; completing the job would silently drop what it carried, so it is failed \
         (retries preserved) instead of completed."
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
        assert!(detect_empty(None, out).is_some());
    }

    #[test]
    fn empty_when_only_empty_fence() {
        // A fenced block with a zero-length body carries no result. It must be
        // stripped (not mistaken for substantive stdout) so `detect_empty` still
        // flags the run as empty — a `find(&block)` on the empty body would match
        // at offset 0 and leave the fence residue behind.
        let out = "```json\n```\n";
        assert!(
            detect_empty(None, out).is_some(),
            "empty fence should not count as work"
        );
    }

    #[test]
    fn empty_when_only_valueless_fence() {
        let out = "```json\n{}\n```\n";
        assert!(detect_empty(None, out).is_some());
    }

    #[test]
    fn not_empty_with_prose_fence() {
        // A non-empty, non-result fenced block is genuine output and is kept.
        let out = "```\nsome code the agent wrote\n```\n";
        assert!(detect_empty(None, out).is_none());
    }

    #[test]
    fn not_empty_with_substantive_stdout() {
        assert!(detect_empty(None, "did real work\n").is_none());
    }

    #[test]
    fn empty_when_no_substantive_output() {
        // An ACP run that emitted only tool-call/status `session/update`s (no
        // assistant text) and no structured result produced nothing to settle;
        // with no substantive stdout it must be failed, not silently completed.
        // (Finding: tool-only ACP updates must not bypass empty-run detection.)
        assert!(detect_empty(None, "").is_some());
    }

    #[test]
    fn not_empty_with_effective_vars() {
        let o = obj(json!({"status":"done"}));
        assert!(detect_empty(Some(&o), "").is_none());
    }

    #[test]
    fn result_file_reads_small_and_rejects_oversize() {
        let dir = std::env::temp_dir();
        let ok = dir.join(format!("nano-rf-ok-{}.json", std::process::id()));
        std::fs::write(&ok, br#"{"status":"done"}"#).unwrap();
        assert_eq!(read_result_file(&ok).unwrap()["status"], json!("done"));
        let _ = std::fs::remove_file(&ok);

        // A file over the cap is rejected rather than read into memory.
        let big = dir.join(format!("nano-rf-big-{}.json", std::process::id()));
        std::fs::write(&big, vec![b'x'; (MAX_RESULT_FILE_BYTES + 1) as usize]).unwrap();
        assert!(read_result_file(&big).is_none());
        let _ = std::fs::remove_file(&big);
    }
}
