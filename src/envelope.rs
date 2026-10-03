//! The task envelope: assemble the agent's prompt and the repository spec from a
//! job's variables and custom headers.
//!
//! The reserved `io.nanobpm.agentTask` namespace may arrive either as a single
//! key whose value is a JSON string/object, OR as flattened dot-path keys like
//! `io.nanobpm.agentTask.repository.ref` (element templates emit the latter).
//! Both customHeaders and variables are scanned; the header/variable merge and
//! the prompt-assembly precedence mirror the Node plugin's `normalizeTaskEnvelope`.

use serde_json::{Map, Value};

const AGENT_TASK_NS: &str = "io.nanobpm.agentTask";

/// A git repository to provision before the agent runs.
#[derive(Debug, Clone, Default)]
pub struct Repository {
    pub provider: String,
    pub url: String,
    pub ref_: Option<String>,
    pub sha: Option<String>,
    pub depth: Option<u32>,
    pub single_branch: bool,
    pub filter: Option<String>,
    pub base_ref: Option<String>,
    pub base_sha: Option<String>,
    pub submodules: bool,
    pub clone_timeout_ms: Option<u64>,
}

/// The assembled task envelope the daemon needs.
#[derive(Debug, Clone, Default)]
pub struct Envelope {
    pub prompt: Option<String>,
    pub repository: Option<Repository>,
    /// The schema-v1 normalized envelope — exactly the Node plugin's
    /// `normalizeTaskEnvelope` output — forwarded to the agent as the payload's
    /// `task`.
    pub normalized: Value,
}

/// Node's `str(v) = (v == null ? undefined : String(v))`: `null`/absent drops
/// the field, every other value is its JavaScript `String(v)`. Arrays join with
/// "," (`String(["x"])` is `"x"`) and a plain object is `"[object Object]"` —
/// NOT JSON — so `promptFile: ["x"]` normalizes to `"x"` and `ref: ["a","b"]`
/// to `"a,b"`, exactly as the plugin delivers them. A prior version used
/// `Value::to_string()` (JSON), so `promptFile: ["x"]` became the literal
/// `["x"]` — a divergence from the field-for-field Node parity this normalize
/// claims.
fn as_str(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        other => Some(js_stringify(other)),
    }
}

/// JavaScript's `String(v)` for the value shapes `coerceBool` can meet. Node's
/// `coerceBool` stringifies ANY non-boolean/non-null value before matching, so
/// arrays and objects coerce by their JS stringification — not by a hard
/// default: `String([])` is `""` (false), `String(["on"])` is `"on"` (true),
/// `String(["a","b"])` is `"a,b"`, and `String({})` is `"[object Object]"`.
/// Matching that exactly is load-bearing: a prior version returned the field
/// default for every array/object, so `branch.push: []` normalised to `true`
/// (the default) where Node yields `false`, and `allowPr: ["on"]` normalised to
/// `false` where Node yields `true`.
fn js_stringify(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        // `Array.prototype.toString` is `join(",")`: empty → `""`, nested
        // arrays/objects recurse through the same `String()` conversion —
        // except null/undefined ELEMENTS, which join renders as the empty
        // string (String([null]) is `""`, String([1,null,2]) is `"1,,2"`),
        // unlike a top-level String(null) → `"null"`.
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_stringify(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        // A plain object has no custom `toString`, so it stringifies to the
        // invariant `"[object Object]"` regardless of its contents.
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// Node's `coerceBool`: booleans pass through; `null`/absent yields the default;
/// any other value is stringified (JavaScript `String(v)`, see [`js_stringify`])
/// and matched against the true-set (`true`/`1`/`yes`/`on`) and the false-set
/// (`false`/`0`/`no`/`off`/empty), with anything unrecognised falling back to
/// the default. Matching Node here is load-bearing: a prior version only
/// recognised `true`/`1`/`yes` and returned `false` (not the default) for every
/// other string, so `"on"` normalised to false and an unrecognised string on a
/// default-`true` field (e.g. `push`) flipped to false.
fn coerce_bool(v: Option<&Value>, default: bool) -> bool {
    let s = match v {
        None | Some(Value::Null) => return default,
        Some(Value::Bool(b)) => return *b,
        Some(other) => js_stringify(other).trim().to_ascii_lowercase(),
    };
    match s.as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" | "" => false,
        _ => default,
    }
}

/// Node's `coerceInt` for the unsigned fields (`depth`, `cloneTimeoutMs`):
/// `null`/absent → `None`; otherwise `Number.parseInt(String(v), 10)` kept only
/// when finite and non-negative. Like [`coerce_int`], `String(v)` runs FIRST, so
/// a non-string is stringified the JavaScript way before the leading integer is
/// parsed: `depth: ["5"]` → `String(["5"])` is `"5"` → `5`, and `["1","2"]` →
/// `"1,2"` → `1`. A prior version matched only `Value::Number`/`Value::String`,
/// so an array/object value was dropped where Node parses it — e.g.
/// `cloneTimeoutMs: ["30000"]` normalised to absent (shallow clone / clone
/// timeout silently lost) where Node yields `30000`. Negative and non-numeric
/// results stay absent (the `u64` guard), matching the field's unsigned domain.
fn coerce_u(v: Option<&Value>) -> Option<u64> {
    match v {
        // A JSON number: `as_u64` keeps non-negative integers; a float is
        // truncated like `parseInt` (7.9 → 7); a NEGATIVE integer must NOT fall
        // through to the float arm (`-3 as u64` saturates to 0) — Node's
        // `parseInt` yields `-3`, which the unsigned domain rejects as absent.
        Some(Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64)),
        Some(other) => {
            let t = js_stringify(other);
            let t = t.trim_start();
            let end = t
                .char_indices()
                .find(|&(i, c)| !(c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+'))))
                .map(|(i, _)| i)
                .unwrap_or(t.len());
            t[..end].parse().ok()
        }
        None => None,
    }
}

/// Deep-merge `src` into `dst` (objects merged recursively, other values
/// overwritten).
fn deep_merge(dst: &mut Value, src: &Value) {
    match (dst, src) {
        (Value::Object(d), Value::Object(s)) => {
            for (k, v) in s {
                deep_merge(d.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (d, s) => *d = s.clone(),
    }
}

/// Set `value` at the dot-path `parts` within `root` (creating objects).
fn set_path(root: &mut Map<String, Value>, parts: &[&str], value: Value) {
    if parts.is_empty() {
        return;
    }
    if parts.len() == 1 {
        root.insert(parts[0].to_string(), value);
        return;
    }
    let entry = root
        .entry(parts[0].to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !entry.is_object() {
        *entry = Value::Object(Map::new());
    }
    if let Value::Object(m) = entry {
        set_path(m, &parts[1..], value);
    }
}

/// Collect the reserved namespace out of a flat key→value map (customHeaders or
/// variables): the whole-object `io.nanobpm.agentTask` key (JSON string or
/// object) plus any flattened `io.nanobpm.agentTask.<path>` keys.
fn collect_from(source: &Map<String, Value>) -> Value {
    let mut out = Map::new();
    if let Some(whole) = source.get(AGENT_TASK_NS) {
        let val = match whole {
            Value::String(s) => serde_json::from_str::<Value>(s).ok(),
            Value::Object(_) => Some(whole.clone()),
            _ => None,
        };
        if let Some(Value::Object(m)) = val {
            for (k, v) in m {
                out.insert(k, v);
            }
        }
    }
    let prefix = format!("{AGENT_TASK_NS}.");
    for (key, value) in source {
        if let Some(rest) = key.strip_prefix(&prefix) {
            if rest.is_empty() {
                continue;
            }
            let parts: Vec<&str> = rest.split('.').collect();
            set_path(&mut out, &parts, value.clone());
        }
    }
    Value::Object(out)
}

/// Assemble the envelope from a job's custom headers and variables.
pub fn assemble(custom_headers: &Map<String, Value>, variables: &Map<String, Value>) -> Envelope {
    let mut raw = collect_from(custom_headers);
    deep_merge(&mut raw, &collect_from(variables));
    let raw_obj = raw.as_object().cloned().unwrap_or_default();

    let task = raw_obj.get("task").and_then(Value::as_object);
    let base_prompt = task
        .and_then(|t| t.get("prompt"))
        .and_then(as_str)
        .or_else(|| variables.get("prompt").and_then(as_str))
        .or_else(|| variables.get("task").and_then(as_str));
    let append_prompt = task
        .and_then(|t| t.get("appendPrompt"))
        .and_then(as_str)
        .or_else(|| variables.get("appendPrompt").and_then(as_str));
    let prompt = match (base_prompt, append_prompt) {
        (base, Some(app)) if !app.is_empty() => {
            Some(format!("{}{}", base.unwrap_or_default(), app))
        }
        (base, _) => base,
    };

    let repository = raw_obj
        .get("repository")
        .and_then(Value::as_object)
        .and_then(parse_repository);

    let normalized = normalize(&raw_obj, prompt.as_deref());
    Envelope {
        prompt,
        repository,
        normalized,
    }
}

/// Node's `coerceInt`: `null`/`""` → absent; otherwise
/// `Number.parseInt(String(v), 10)` kept only when finite. `String(v)` runs
/// FIRST, so a non-string is stringified the JavaScript way before the leading
/// integer is parsed: `timeoutMs: ["1000"]` → `String(["1000"])` is `"1000"` →
/// `1000`, and `["1","2"]` → `"1,2"` → `1`. A prior version parsed only a JSON
/// string and dropped arrays/objects entirely, so `timeoutMs: ["1000"]` was
/// lost where Node yields `1000`. `parseInt` trims leading whitespace and reads
/// the longest `[+-]?digit*` prefix; a leading `+`/`-` with no digit, or no
/// leading digit at all, is `NaN` → absent.
fn coerce_int(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Some(other) => {
            let t = js_stringify(other);
            let t = t.trim_start();
            let end = t
                .char_indices()
                .find(|&(i, c)| !(c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+'))))
                .map(|(i, _)| i)
                .unwrap_or(t.len());
            t[..end].parse().ok()
        }
        None => None,
    }
}

/// Insert `key` only when the value is present — mirrors `JSON.stringify`
/// dropping `undefined` fields in the Node plugin.
fn put(m: &mut Map<String, Value>, key: &str, v: Option<Value>) {
    if let Some(v) = v {
        m.insert(key.to_string(), v);
    }
}

/// Normalize the merged envelope to schema v1, field for field as the Node
/// plugin's `normalizeTaskEnvelope` (so the agent sees an identical `task`).
fn normalize(raw: &Map<String, Value>, prompt: Option<&str>) -> Value {
    let s = |v: Option<&Value>| v.and_then(as_str).map(Value::String);
    let int = |v: Option<&Value>| coerce_int(v).map(Value::from);
    let mut env = Map::new();
    env.insert("schemaVersion".into(), Value::from(1));

    if let Some(repo) = raw.get("repository").and_then(Value::as_object) {
        if repo
            .get("url")
            .and_then(as_str)
            .is_some_and(|u| !u.is_empty())
        {
            let mut r = Map::new();
            let provider = repo
                .get("provider")
                .and_then(as_str)
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| "github".into())
                .to_lowercase();
            r.insert("provider".into(), Value::String(provider));
            put(&mut r, "url", s(repo.get("url")));
            put(&mut r, "ref", s(repo.get("ref")));
            put(&mut r, "sha", s(repo.get("sha")));
            put(&mut r, "depth", int(repo.get("depth")));
            r.insert(
                "singleBranch".into(),
                Value::Bool(coerce_bool(repo.get("singleBranch"), false)),
            );
            put(&mut r, "filter", s(repo.get("filter")));
            put(&mut r, "baseRef", s(repo.get("baseRef")));
            put(&mut r, "baseSha", s(repo.get("baseSha")));
            put(&mut r, "cloneTimeoutMs", int(repo.get("cloneTimeoutMs")));
            r.insert(
                "submodules".into(),
                Value::Bool(coerce_bool(repo.get("submodules"), false)),
            );
            put(&mut r, "authRef", s(repo.get("authRef")));
            env.insert("repository".into(), Value::Object(r));
        }
    }

    let empty = Map::new();
    let branch = raw
        .get("branch")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let mut b = Map::new();
    put(&mut b, "base", s(branch.get("base")));
    put(&mut b, "create", s(branch.get("create")));
    b.insert(
        "push".into(),
        Value::Bool(coerce_bool(branch.get("push"), true)),
    );
    env.insert("branch".into(), Value::Object(b));

    let setup = raw
        .get("setup")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    // Node: `Array.isArray(setup.commands) ? setup.commands.map(String) : []`.
    // Every element is `String(x)`, so a nested array joins with "," and an
    // object is `"[object Object]"` — via the shared `js_stringify`, never JSON.
    let strings = |v: Option<&Value>| -> Value {
        Value::Array(
            v.and_then(Value::as_array)
                .map(|a| a.iter().map(|x| Value::String(js_stringify(x))).collect())
                .unwrap_or_default(),
        )
    };
    let mut st = Map::new();
    st.insert("commands".into(), strings(setup.get("commands")));
    st.insert(
        "env".into(),
        setup
            .get("env")
            .filter(|v| v.is_object())
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new())),
    );
    st.insert("secretRefs".into(), strings(setup.get("secretRefs")));
    env.insert("setup".into(), Value::Object(st));

    let task = raw.get("task").and_then(Value::as_object).unwrap_or(&empty);
    let mut t = Map::new();
    put(
        &mut t,
        "prompt",
        prompt.map(|p| Value::String(p.to_string())),
    );
    put(&mut t, "promptFile", s(task.get("promptFile")));
    put(&mut t, "maxIterations", int(task.get("maxIterations")));
    put(&mut t, "timeoutMs", int(task.get("timeoutMs")));
    put(&mut t, "idleTimeoutMs", int(task.get("idleTimeoutMs")));
    put(
        &mut t,
        "recoveryWindowMs",
        int(task.get("recoveryWindowMs")),
    );
    t.insert(
        "allowPr".into(),
        Value::Bool(coerce_bool(task.get("allowPr"), false)),
    );
    put(&mut t, "prBase", s(task.get("prBase")));
    env.insert("task".into(), Value::Object(t));
    Value::Object(env)
}

fn parse_repository(repo: &Map<String, Value>) -> Option<Repository> {
    let url = repo
        .get("url")
        .and_then(as_str)
        .filter(|u| !u.trim().is_empty())?;
    Some(Repository {
        provider: repo
            .get("provider")
            .and_then(as_str)
            .unwrap_or_else(|| "github".into())
            .to_ascii_lowercase(),
        url,
        ref_: repo.get("ref").and_then(as_str).filter(|s| !s.is_empty()),
        sha: repo.get("sha").and_then(as_str).filter(|s| !s.is_empty()),
        depth: coerce_u(repo.get("depth")).map(|d| d as u32),
        single_branch: coerce_bool(repo.get("singleBranch"), false),
        filter: repo
            .get("filter")
            .and_then(as_str)
            .filter(|s| !s.is_empty()),
        base_ref: repo
            .get("baseRef")
            .and_then(as_str)
            .filter(|s| !s.is_empty()),
        base_sha: repo
            .get("baseSha")
            .and_then(as_str)
            .filter(|s| !s.is_empty()),
        submodules: coerce_bool(repo.get("submodules"), false),
        clone_timeout_ms: coerce_u(repo.get("cloneTimeoutMs")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalized_matches_node_normalize_task_envelope() {
        // The shape the Node plugin forwards as the payload's `task` for a job
        // carrying only a `prompt` variable (captured from plugin 1.69.x).
        let vars = json!({ "prompt": "do it" });
        let env = assemble(&Map::new(), vars.as_object().unwrap());
        assert_eq!(
            env.normalized,
            json!({
                "schemaVersion": 1,
                "branch": { "push": true },
                "setup": { "commands": [], "env": {}, "secretRefs": [] },
                "task": { "prompt": "do it", "allowPr": false },
            })
        );
    }

    #[test]
    fn coerce_bool_matches_node_true_false_sets() {
        let v = |x: Value| coerce_bool(Some(&x), false);
        // Whole true-set, case/whitespace-insensitive (incl. the formerly-missing "on").
        for t in ["true", "1", "yes", "on", "ON", " On ", "YES"] {
            assert!(v(json!(t)), "{t:?} should coerce true");
        }
        // Whole false-set, including empty string.
        for f in ["false", "0", "no", "off", "", "OFF", " No "] {
            assert!(!v(json!(f)), "{f:?} should coerce false");
        }
        // Booleans pass through; numbers stringify (1/0 recognised).
        assert!(coerce_bool(Some(&json!(true)), false));
        assert!(!coerce_bool(Some(&json!(false)), true));
        assert!(coerce_bool(Some(&json!(1)), false));
        assert!(!coerce_bool(Some(&json!(0)), true));
        // Unrecognised value falls back to the DEFAULT (not hard-false) — the
        // divergence that previously flipped a default-`true` field to false.
        assert!(coerce_bool(Some(&json!("maybe")), true));
        assert!(!coerce_bool(Some(&json!("maybe")), false));
        assert!(coerce_bool(Some(&json!(2)), true));
        // Absent / null yields the default.
        assert!(coerce_bool(None, true));
        assert!(!coerce_bool(Some(&Value::Null), false));
    }

    #[test]
    fn coerce_bool_matches_node_js_stringification_for_arrays_and_objects() {
        // Node stringifies ANY non-boolean value with `String(v)` before
        // matching, so arrays/objects coerce by their JS stringification rather
        // than a hard default. `String([])` is `""` (false), `String(["on"])`
        // is `"on"` (true), `String({})` is `"[object Object]"` (unrecognised →
        // default). A prior version returned the field default for every
        // array/object, so `push: []` normalised to `true` and `allowPr:
        // ["on"]` to `false` — both wrong.
        // Empty array → "" → false regardless of the default.
        assert!(!coerce_bool(Some(&json!([])), true));
        assert!(!coerce_bool(Some(&json!([])), false));
        // Single-element arrays stringify to the element: "on"/"true" → true,
        // "off" → false (the false-set wins over a `true` default).
        assert!(coerce_bool(Some(&json!(["on"])), false));
        assert!(coerce_bool(Some(&json!(["true"])), false));
        assert!(!coerce_bool(Some(&json!(["off"])), true));
        // Multi-element arrays join with "," — "a,b" is unrecognised → default.
        assert!(coerce_bool(Some(&json!(["a", "b"])), true));
        assert!(!coerce_bool(Some(&json!(["a", "b"])), false));
        // A plain object stringifies to "[object Object]" → unrecognised → default.
        assert!(coerce_bool(Some(&json!({})), true));
        assert!(!coerce_bool(Some(&json!({})), false));
        // Nested values recurse through String(): [["on"]] → "on" → true.
        assert!(coerce_bool(Some(&json!([["on"]])), false));
        // Array.prototype.join renders null/undefined ELEMENTS as the empty
        // string (unlike a top-level String(null) → "null", which coerce_bool
        // pre-filters to the default anyway): String([null]) is "" (false),
        // String([1,null,2]) is "1,,2" (unrecognised → default), and
        // String([null,"on"]) is ",on" (unrecognised → default). A prior
        // version joined null as the literal "null", so `push: [null]`
        // normalised to `true` (the default) where Node yields `false`.
        assert!(!coerce_bool(Some(&json!([null])), true));
        assert!(!coerce_bool(Some(&json!([null])), false));
        assert!(coerce_bool(Some(&json!([1, null, 2])), true));
        assert!(!coerce_bool(Some(&json!([1, null, 2])), false));
        assert!(coerce_bool(Some(&json!([null, "on"])), true));
        assert!(!coerce_bool(Some(&json!([null, "on"])), false));
        // Nested arrays recurse through join: [[null,"on"]] → ",on" → default.
        assert!(coerce_bool(Some(&json!([[null, "on"]])), true));
        assert!(!coerce_bool(Some(&json!([[null, "on"]])), false));
    }

    #[test]
    fn string_and_int_fields_apply_node_string_v() {
        // Node's `str(v) = String(v)` and `coerceInt(v) = parseInt(String(v),10)`
        // run on EVERY value shape, not just strings — a "previously missed"
        // parity gap where arrays were JSON-serialised or dropped instead of
        // JS-stringified.
        // String fields: String(["x"]) is "x"; String(["a","b"]) is "a,b";
        // String({}) is "[object Object]" (NOT JSON); String(null) drops the field.
        assert_eq!(as_str(&json!(["x"])).as_deref(), Some("x"));
        assert_eq!(as_str(&json!(["a", "b"])).as_deref(), Some("a,b"));
        assert_eq!(as_str(&json!({"k": 1})).as_deref(), Some("[object Object]"));
        assert_eq!(as_str(&json!("s")).as_deref(), Some("s"));
        assert_eq!(as_str(&json!(42)).as_deref(), Some("42"));
        assert!(as_str(&json!(null)).is_none());
        // Int fields: parseInt(String(["1000"])) → 1000 (was dropped); a
        // multi-element array parses only its leading integer ("1,2" → 1); a
        // non-numeric-leading value is NaN → absent.
        assert_eq!(coerce_int(Some(&json!(["1000"]))), Some(1000));
        assert_eq!(coerce_int(Some(&json!(["1", "2"]))), Some(1));
        assert_eq!(coerce_int(Some(&json!(" 42abc"))), Some(42));
        assert_eq!(coerce_int(Some(&json!("abc"))), None);
        assert_eq!(coerce_int(Some(&json!([]))), None); // String([]) is "" → NaN
        assert_eq!(coerce_int(Some(&json!(7))), Some(7));
        assert_eq!(coerce_int(None), None);
    }

    #[test]
    fn coerce_u_applies_node_string_v_to_unsigned_fields() {
        // The unsigned sibling of `coerce_int` (`depth`, `cloneTimeoutMs`) must
        // run the SAME `parseInt(String(v), 10)`: a non-string is JS-stringified
        // before the leading integer is parsed, so an array is no longer dropped.
        assert_eq!(coerce_u(Some(&json!(["5"]))), Some(5)); // depth: ["5"]
        assert_eq!(coerce_u(Some(&json!(["30000"]))), Some(30000)); // cloneTimeoutMs
        assert_eq!(coerce_u(Some(&json!(["1", "2"]))), Some(1)); // "1,2" → 1
        assert_eq!(coerce_u(Some(&json!(" 42abc"))), Some(42));
        assert_eq!(coerce_u(Some(&json!(7))), Some(7));
        assert_eq!(coerce_u(Some(&json!(7.9))), Some(7)); // parseInt truncates
        assert_eq!(coerce_u(Some(&json!("abc"))), None); // NaN → absent
        assert_eq!(coerce_u(Some(&json!([]))), None); // String([]) is "" → NaN
        assert_eq!(coerce_u(Some(&json!({}))), None); // "[object Object]" → NaN
        assert_eq!(coerce_u(Some(&json!(-3))), None); // u64 guard: negative absent
        assert_eq!(coerce_u(Some(&json!(null))), None);
        assert_eq!(coerce_u(None), None);
    }

    #[test]
    fn repository_depth_and_clone_timeout_survive_array_input() {
        // End-to-end through `parse_repository`: the daemon-side clone spec must
        // keep a `depth`/`cloneTimeoutMs` delivered as a single-element array,
        // exactly as Node's shared coerceInt parses it (a dropped `depth` loses
        // the shallow clone; a dropped `cloneTimeoutMs` loses the clone timeout).
        let headers = json!({
            "io.nanobpm.agentTask": {
                "repository": {
                    "url": "https://h/o/r.git",
                    "depth": ["5"],
                    "cloneTimeoutMs": ["30000"],
                }
            }
        });
        let env = assemble(headers.as_object().unwrap(), &Map::new());
        let repo = env.repository.expect("repository should parse");
        assert_eq!(repo.depth, Some(5));
        assert_eq!(repo.clone_timeout_ms, Some(30000));
        // And the normalized payload agrees (it already used coerce_int).
        assert_eq!(env.normalized["repository"]["depth"], json!(5));
        assert_eq!(env.normalized["repository"]["cloneTimeoutMs"], json!(30000));
    }

    #[test]
    fn normalize_applies_string_v_to_promptfile_timeout_and_commands() {
        // End-to-end through `normalize`: `promptFile: ["x"]` → "x",
        // `timeoutMs: ["1000"]` → 1000, and a non-string setup command is
        // String()-mapped (a nested array joins with ",").
        let raw = json!({
            "task": { "prompt": "p", "promptFile": ["x"], "timeoutMs": ["1000"] },
            "setup": { "commands": ["echo hi", ["a", "b"], 7] },
        });
        let n = normalize(raw.as_object().unwrap(), None);
        assert_eq!(n["task"]["promptFile"], json!("x"));
        assert_eq!(n["task"]["timeoutMs"], json!(1000));
        assert_eq!(n["setup"]["commands"], json!(["echo hi", "a,b", "7"]));
    }

    #[test]
    fn on_normalizes_true_across_bool_fields() {
        // "on" must normalize to true for every coerced boolean field (Node parity).
        let headers = json!({
            "io.nanobpm.agentTask.repository.url": "https://h/o/r.git",
            "io.nanobpm.agentTask.repository.singleBranch": "on",
            "io.nanobpm.agentTask.repository.submodules": "on",
            "io.nanobpm.agentTask.task.allowPr": "on",
            "io.nanobpm.agentTask.task.prompt": "p",
        });
        let env = assemble(headers.as_object().unwrap(), &Map::new());
        let n = &env.normalized;
        assert_eq!(n["repository"]["singleBranch"], true);
        assert_eq!(n["repository"]["submodules"], true);
        assert_eq!(n["task"]["allowPr"], true);
        // And the typed envelope agrees.
        let repo = env.repository.unwrap();
        assert!(repo.single_branch);
        assert!(repo.submodules);
    }

    #[test]
    fn normalized_coerces_header_strings() {
        let headers = json!({
            "io.nanobpm.agentTask.repository.url": "https://h/o/r.git",
            "io.nanobpm.agentTask.repository.depth": "5",
            "io.nanobpm.agentTask.branch.push": "false",
            "io.nanobpm.agentTask.task.allowPr": "true",
            "io.nanobpm.agentTask.task.prompt": "p",
        });
        let env = assemble(headers.as_object().unwrap(), &Map::new());
        let n = &env.normalized;
        assert_eq!(n["repository"]["provider"], "github");
        assert_eq!(n["repository"]["depth"], 5);
        assert_eq!(n["repository"]["singleBranch"], false);
        assert_eq!(n["branch"]["push"], false);
        assert_eq!(n["task"]["allowPr"], true);
        assert_eq!(n["task"]["prompt"], "p");
    }

    fn map(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn prompt_from_plain_variable() {
        let env = assemble(&Map::new(), &map(json!({"prompt":"do it"})));
        assert_eq!(env.prompt.as_deref(), Some("do it"));
    }

    #[test]
    fn append_prompt_concatenated() {
        let vars = map(json!({
            "io.nanobpm.agentTask": {"task": {"prompt": "base", "appendPrompt": "\nmore"}}
        }));
        let env = assemble(&Map::new(), &vars);
        assert_eq!(env.prompt.as_deref(), Some("base\nmore"));
    }

    #[test]
    fn flattened_dotpath_repository() {
        let headers = map(json!({
            "io.nanobpm.agentTask.repository.url": "https://github.com/o/r.git",
            "io.nanobpm.agentTask.repository.ref": "main",
            "io.nanobpm.agentTask.repository.singleBranch": "true"
        }));
        let env = assemble(&headers, &Map::new());
        let repo = env.repository.unwrap();
        assert_eq!(repo.url, "https://github.com/o/r.git");
        assert_eq!(repo.ref_.as_deref(), Some("main"));
        assert!(repo.single_branch);
        assert_eq!(repo.provider, "github");
    }

    #[test]
    fn variables_override_headers() {
        let headers = map(json!({"io.nanobpm.agentTask": {"task": {"prompt": "from-header"}}}));
        let vars = map(json!({"io.nanobpm.agentTask": {"task": {"prompt": "from-var"}}}));
        let env = assemble(&headers, &vars);
        assert_eq!(env.prompt.as_deref(), Some("from-var"));
    }

    #[test]
    fn no_repository_without_url() {
        let headers = map(json!({"io.nanobpm.agentTask": {"repository": {"ref": "main"}}}));
        let env = assemble(&headers, &Map::new());
        assert!(env.repository.is_none());
    }
}
