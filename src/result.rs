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
/// (nor anything in the reserved `io.nanobpm.*` namespace). Exactly the Node
/// plugin's `RESERVED_RESULT_KEYS`.
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
    // Bind the parent inode, then open the leaf relative to it with no-follow.
    // Leaf-only `O_NOFOLLOW` guards only the final `result.json` component; the
    // kernel still *follows* the parent components during path lookup, so the
    // agent (which owns its run dir) could rename `<runs_dir>/<key>` and drop a
    // symlink in its place to redirect this read to an arbitrary `result.json`
    // outside the validated run directory. Opening the parent directory itself
    // no-follow and then `openat`-ing the leaf from that fd pins the directory
    // inode, closing the parent-swap TOCTOU rather than trusting the path string.
    #[cfg(unix)]
    let file = {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let parent = path.parent()?;
        let name = path.file_name()?;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
        let dir = opts.open(parent).ok()?;
        let cname = CString::new(name.as_bytes()).ok()?;
        // SAFETY: `dir` owns a valid directory fd for the duration of this call
        // and `cname` is a valid NUL-terminated C string.
        //
        // `O_NONBLOCK` is essential here: the leaf is agent-controlled, so it
        // could be a FIFO. Opening a reader end of a FIFO that has no writer
        // *blocks the open itself* indefinitely, which would wedge the Tokio
        // worker thread on this synchronous call. Opening non-blocking returns
        // immediately for any special file; the `meta.is_file()` guard below then
        // rejects the non-regular file. On a regular file `O_NONBLOCK` has no
        // effect on the subsequent `read`, so the happy path is unchanged.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                cname.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: `fd` is a fresh, owned fd just returned by `openat`.
        unsafe { std::fs::File::from_raw_fd(fd) }
    };
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open the reparse point / symlink itself
        // rather than following it, the Windows analogue of `O_NOFOLLOW`. A
        // swapped-in symlink is then opened as the link and rejected below via
        // its reparse-point attribute, so the daemon never reads through it.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        opts.open(path).ok()?
    };
    // No atomic no-follow open on other platforms: reject a symlink explicitly so
    // the documented no-symlink guarantee still holds (best-effort; such targets
    // are not supported daemon hosts).
    #[cfg(not(any(unix, windows)))]
    let file = {
        if std::fs::symlink_metadata(path)
            .ok()?
            .file_type()
            .is_symlink()
        {
            return None;
        }
        opts.open(path).ok()?
    };
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
    fenced_spans(text)
        .into_iter()
        .map(|(_, body)| body)
        .collect()
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

/// Select the agent's result across ordered candidate sources, mirroring the
/// Node plugin 1.70.1. The plugin walks file → stdout → ACP-outcome in order and
/// keeps going until a source yields EFFECTIVE result vars, rather than stopping
/// at the first source that merely *parses*. A result file of `{}` (or
/// reserved-/null-only data) must therefore not shadow a usable stdout sentinel
/// or ACP outcome written in the same run. When no source is effective, the
/// first present candidate is returned unchanged so empty detection still has a
/// shape to inspect (and so a value-less sentinel is still surfaced, not lost).
pub fn select_effective_result<I>(candidates: I) -> Option<Map<String, Value>>
where
    I: IntoIterator<Item = Option<Map<String, Value>>>,
{
    let mut first: Option<Map<String, Value>> = None;
    for candidate in candidates {
        let Some(obj) = candidate else { continue };
        if has_effective_result_vars(&obj) {
            return Some(obj);
        }
        if first.is_none() {
            first = Some(obj);
        }
    }
    first
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

/// The empty-job detector — the Node plugin's `detectEmptyAgentJob`. A run that
/// produced NOTHING — no effective result vars, no substantive stdout (after
/// value-less result markers/fences are stripped), no transcript turns (ACP
/// `session/update` activity) and no repository work — did no work: completing
/// it would silently drop whatever the job carried, so the caller FAILS the job
/// instead. Returns the Node plugin's reason text when the run is empty.
///
/// `has_commits` / `has_pushed` are the plugin's `gitResult.commits.length > 0`
/// and `gitResult.pushed === true` signals: a repository agent that commits or
/// pushes real work but emits no stdout/result is NOT empty and must complete,
/// not be failed into a retry. The Rust worker has no `finalizeGit` push stage
/// yet, so the caller derives `has_commits` from a pre/post `rev-parse` of the
/// checkout HEAD (any advance = a commit) and passes `has_pushed: false`.
///
/// `has_outcome` is the plugin's ACP-outcome signal: an agent that emitted an
/// explicit prompt outcome (e.g. `blocked`) did work and reported it, so the run
/// is NOT empty even when the outcome carried no effective vars of its own.
pub fn detect_empty(
    result_vars: Option<&Map<String, Value>>,
    stdout: &str,
    has_turns: bool,
    has_commits: bool,
    has_pushed: bool,
    has_outcome: bool,
) -> Option<String> {
    if result_vars.is_some_and(has_effective_result_vars) {
        return None;
    }
    if !stdout_stripped_of_empty_result(stdout).trim().is_empty() {
        return None;
    }
    if has_turns {
        return None;
    }
    // Node: `if ((gitResult?.commits?.length ?? 0) > 0) return null;` then
    // `if (gitResult?.pushed === true) return null;` — repository work alone
    // (commits or a push) is evidence the run was not a no-op husk.
    if has_commits || has_pushed {
        return None;
    }
    // Plugin 1.70.1: any explicit ACP prompt outcome also counts as evidence the
    // run did real work, so a blocked/outcome-bearing turn is not failed as empty.
    if has_outcome {
        return None;
    }
    Some(
        "agent exited 0 but produced nothing — no result vars, no output, no transcript turns, \
         no commits and no push. This is the signature of a protocol-mismatched or no-op harness \
         (e.g. an ACP-mode binary driven over protocol \"pipe\"): completing the job would silently \
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
        assert!(detect_empty(None, out, false, false, false, false).is_some());
    }

    #[test]
    fn empty_when_only_empty_fence() {
        // A fenced block with a zero-length body carries no result. It must be
        // stripped (not mistaken for substantive stdout) so `detect_empty` still
        // flags the run as empty — a `find(&block)` on the empty body would match
        // at offset 0 and leave the fence residue behind.
        let out = "```json\n```\n";
        assert!(
            detect_empty(None, out, false, false, false, false).is_some(),
            "empty fence should not count as work"
        );
    }

    #[test]
    fn empty_when_only_valueless_fence() {
        let out = "```json\n{}\n```\n";
        assert!(detect_empty(None, out, false, false, false, false).is_some());
    }

    #[test]
    fn not_empty_with_prose_fence() {
        // A non-empty, non-result fenced block is genuine output and is kept.
        let out = "```\nsome code the agent wrote\n```\n";
        assert!(detect_empty(None, out, false, false, false, false).is_none());
    }

    #[test]
    fn not_empty_with_substantive_stdout() {
        assert!(detect_empty(None, "did real work\n", false, false, false, false).is_none());
    }

    #[test]
    fn empty_when_no_substantive_output() {
        // An ACP run that emitted only tool-call/status `session/update`s (no
        // assistant text) and no structured result produced nothing to settle;
        // with no substantive stdout it must be failed, not silently completed.
        // (Finding: tool-only ACP updates must not bypass empty-run detection.)
        assert!(detect_empty(None, "", false, false, false, false).is_some());
        // Transcript turns (ACP session/update activity) count as work, as in Node.
        assert!(detect_empty(None, "", true, false, false, false).is_none());
    }

    #[test]
    fn not_empty_with_effective_vars() {
        let o = obj(json!({"status":"done"}));
        assert!(detect_empty(Some(&o), "", false, false, false, false).is_none());
    }

    #[test]
    fn not_empty_with_commits_or_push() {
        // Node's `gitResult.commits.length > 0` / `gitResult.pushed === true`:
        // a repository agent that committed or pushed real work is NOT empty
        // even with no result vars, no stdout and no transcript turns — failing
        // it would burn a retry (the advisory this regression pins).
        assert!(
            detect_empty(None, "", false, true, false, false).is_none(),
            "a commit alone must mark the run non-empty"
        );
        assert!(
            detect_empty(None, "", false, false, true, false).is_none(),
            "a push alone must mark the run non-empty"
        );
        // …but with neither, the otherwise-empty run is still failed.
        assert!(detect_empty(None, "", false, false, false, false).is_some());
    }

    #[test]
    fn not_empty_with_explicit_outcome() {
        // Plugin 1.70.1: an explicit ACP prompt outcome is evidence of real work
        // even when it carried no effective vars of its own, so the run is not
        // failed as empty (the advisory this regression pins).
        assert!(
            detect_empty(None, "", false, false, false, true).is_none(),
            "an explicit ACP outcome must mark the run non-empty"
        );
    }

    #[test]
    fn select_effective_skips_valueless_file_for_stdout() {
        // A `{}` (ineffective) result file must not shadow a usable stdout
        // sentinel or ACP outcome: selection walks on to the first EFFECTIVE
        // source (plugin 1.70.1), not merely the first that parses.
        let file = obj(json!({}));
        let stdout = obj(json!({"status":"ok"}));
        let picked = select_effective_result([Some(file), Some(stdout.clone()), None]).unwrap();
        assert_eq!(picked["status"], json!("ok"));
    }

    #[test]
    fn select_effective_prefers_first_effective_source() {
        // When an earlier source is already effective, it wins — later sources
        // (even if also effective) do not override it.
        let file = obj(json!({"status":"file"}));
        let stdout = obj(json!({"status":"stdout"}));
        let picked = select_effective_result([Some(file), Some(stdout)]).unwrap();
        assert_eq!(picked["status"], json!("file"));
    }

    #[test]
    fn select_effective_uses_acp_outcome_fallback() {
        // No file, an ineffective stdout object, but an effective ACP outcome:
        // the outcome is the selected effective result.
        let outcome = obj(json!({"status":"blocked","question":"why?"}));
        let picked =
            select_effective_result([None, Some(obj(json!({}))), Some(outcome)]).unwrap();
        assert_eq!(picked["status"], json!("blocked"));
    }

    #[test]
    fn select_effective_returns_first_present_when_none_effective() {
        // With no effective source, the first present candidate is still
        // returned (so a value-less sentinel is surfaced, not silently lost).
        let picked = select_effective_result([None, Some(obj(json!({}))), None]).unwrap();
        assert!(picked.is_empty());
    }

    #[test]
    fn select_effective_none_when_no_candidates() {
        assert!(select_effective_result([None, None]).is_none());
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

    #[cfg(unix)]
    #[test]
    fn result_file_rejects_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir();
        let fifo = dir.join(format!("nano-rf-fifo-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&fifo);
        let cpath = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `cpath` is a valid NUL-terminated path; mkfifo takes ownership
        // of nothing and only reads the pointer.
        let rc = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed");
        // A FIFO with no writer must be rejected as a non-regular file rather
        // than blocking the open indefinitely (O_NONBLOCK path).
        assert!(read_result_file(&fifo).is_none());
        let _ = std::fs::remove_file(&fifo);
    }
}
