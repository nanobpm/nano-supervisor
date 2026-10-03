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
        Value::Number(n) => js_number_string(n),
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

/// ECMAScript's `Number::toString` (what Node's `String(number)` and
/// `Number.prototype.toString()` produce) for a JSON number. This is the
/// string `parseInt`/`String(v)` actually consume in the plugin, so the
/// normalizer must reproduce it exactly — serde_json's own `Number::to_string`
/// is NOT it: it renders an integral float with a trailing `.0` (`100.0`,
/// `9007199254740992.0`) where JS drops it (`"100"`, `"9007199254740992"`), and
/// it switches to exponential notation at different thresholds (`1e-6` → serde
/// `"1e-6"` vs JS `"0.000001"`; `1e20` → serde `"1e+20"` vs JS
/// `"100000000000000000000"`). Those divergences change the value `coerceInt`
/// derives (`String(0.000001)` parses to `0` in Node but `1` from serde's
/// `"1e-6"`) and the text a string field receives.
///
/// Integers (`i64`/`u64`) already render as plain digits under both serde_json
/// and JS, so they pass through unchanged. Only a float needs reformatting:
/// ryu yields the same shortest round-trip digits serde_json used, and the
/// ECMAScript `Number::toString` rules below place the decimal point / choose
/// exponential notation the way V8 does. Let the shortest digits be `d[0..k]`
/// and the decimal exponent `e` (value = `0.d[0..k] × 10^e`, equivalently
/// `d[0].d[1..k] × 10^(e-1)`):
///   * `k <= e <= 21`   → the digits followed by `e - k` zeros (plain integer);
///   * `0 < e < k` (and `e <= 21`) → `d[0..e].d[e..k]` (point inside the digits);
///   * `-6 < e <= 0`    → `0.` then `-e` zeros then the digits (small decimal);
///   * otherwise        → `d[0][.d[1..k]]e±(e-1)` (exponential).
fn js_number_string(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let x = match n.as_f64() {
        Some(x) if x.is_finite() => x,
        // serde_json never holds NaN/±Infinity (from_f64 rejects them), so this
        // is unreachable in practice; fall back to serde's rendering.
        _ => return n.to_string(),
    };
    if x == 0.0 {
        return "0".to_string(); // JS renders both 0 and -0 as "0"
    }
    let neg = x.is_sign_negative();

    // Shortest round-trip digits + decimal exponent, from ryu's rendering. ryu
    // emits either decimal ("1234.5678", "0.0001", and an integral float padded
    // with a cosmetic ".0" such as "100.0") or scientific ("1e20", "1.5e-7").
    let mut buf = ryu::Buffer::new();
    let rendered = buf.format(x.abs());
    let (mantissa, sci_exp) = match rendered.split_once(['e', 'E']) {
        Some((m, e)) => (m.to_string(), e.parse::<i32>().unwrap_or(0)),
        None => (rendered.to_string(), 0),
    };
    // Drop a trailing "." + all-zero fraction: that zero is ryu's float marker,
    // not a significant digit (`100.0` has digits "100", not "1000").
    let mantissa = match mantissa.split_once('.') {
        Some((int, frac)) if frac.chars().all(|c| c == '0') => int.to_string(),
        _ => mantissa,
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let frac_len = mantissa.split_once('.').map(|(_, f)| f.len()).unwrap_or(0) as i32;
    let k = digits.len() as i32;
    // e = (position of the decimal point) such that value = 0.digits × 10^e:
    // the integer formed by `digits` is scaled by 10^(sci_exp - frac_len), so
    // e = k + sci_exp - frac_len.
    let e = k + sci_exp - frac_len;

    let body = if e > 21 || e <= -6 {
        // Exponential: one digit, an optional fraction, then e±(e-1).
        let mut s = String::new();
        s.push_str(&digits[..1]);
        if k > 1 {
            s.push('.');
            s.push_str(&digits[1..]);
        }
        s.push('e');
        let m = e - 1;
        if m >= 0 {
            s.push('+');
        }
        s.push_str(&m.to_string());
        s
    } else if e <= 0 {
        // Small decimal: 0.000…digits.
        let mut s = String::from("0.");
        s.push_str(&"0".repeat((-e) as usize));
        s.push_str(&digits);
        s
    } else if e >= k {
        // Plain integer: digits then trailing zeros.
        let mut s = digits.clone();
        s.push_str(&"0".repeat((e - k) as usize));
        s
    } else {
        // Point inside the digits.
        let mut s = String::new();
        s.push_str(&digits[..e as usize]);
        s.push('.');
        s.push_str(&digits[e as usize..]);
        s
    };
    if neg {
        format!("-{body}")
    } else {
        body
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

/// Parse the leading integer of a string the way Node's
/// `Number.parseInt(String(v), 10)` does: trim leading whitespace, then read the
/// longest `[+-]?digit*` prefix. A leading `+`/`-` with no digit, or no leading
/// digit at all, is `NaN` → `None`. This is the shared core of [`coerce_int`]
/// and [`coerce_u`]; both stringify first (see [`js_stringify`]) so a non-string
/// is converted the JavaScript way before the leading integer is parsed.
///
/// The digit run is accumulated into an `f64`, not a fixed-width integer.
/// `parseInt` yields a JavaScript Number (an IEEE-754 double), so a digit run of
/// ANY magnitude stays a finite number in Node — `parseInt("9223372036854775808")`
/// is `9223372036854776000`, not an error. Parsing into `i64` instead overflows
/// to `None` past `i64::MAX`, silently DROPPING a field such as `cloneTimeoutMs`
/// (the clone then runs on the default timeout) and rounding values above 2^53
/// differently (`"9007199254740993"`). Accumulating into `f64` matches Node's
/// double exactly: the result is finite for any digit run, and the f64's own
/// rounding IS the JavaScript Number's rounding.
fn parse_int_str(s: &str) -> Option<f64> {
    let t = s.trim_start();
    let end = t
        .char_indices()
        .find(|&(i, c)| !(c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+'))))
        .map(|(i, _)| i)
        .unwrap_or(t.len());
    let tok = &t[..end];
    let (neg, digits) = match tok.as_bytes().first() {
        Some(b'-') => (true, &tok[1..]),
        Some(b'+') => (false, &tok[1..]),
        _ => (false, tok),
    };
    if digits.is_empty() {
        return None; // a bare sign, or no leading digit at all → NaN
    }
    // Accumulate the leading integer as a double. Beyond ~17 significant digits
    // the added digits no longer change the f64 (it is already at the limit of
    // double precision), which is exactly how far JavaScript's Number can
    // represent the value too — so this stays finite and identically-rounded
    // where an integer accumulator would overflow.
    let mut acc: f64 = 0.0;
    for &d in digits.as_bytes() {
        acc = acc * 10.0 + f64::from(d - b'0');
    }
    Some(if neg { -acc } else { acc })
}

/// Node's `coerceInt` for the unsigned fields (`depth`, `cloneTimeoutMs`):
/// `null`/absent → `None`; otherwise `Number.parseInt(String(v), 10)` kept only
/// when finite and non-negative. `String(v)` runs FIRST for EVERY value —
/// including a JSON number — so it is stringified the JavaScript way before the
/// leading integer is parsed: `depth: ["5"]` → `String(["5"])` is `"5"` → `5`,
/// `["1","2"]` → `"1,2"` → `1`, and a large number such as `1e21` → `"1e+21"`
/// → `1` (Node yields `1`; a numeric fast path that instead casts the `f64`
/// saturates to `u64::MAX`, silently turning a 1 ms timeout into an unbounded
/// one). Negative and non-numeric results stay absent (the `u64` guard),
/// matching the field's unsigned domain.
fn coerce_u(v: Option<&Value>) -> Option<u64> {
    match v {
        None => None,
        // parseInt yields a double; truncate toward zero (parseInt drops any
        // fraction) and keep only a finite, non-negative result in `u64` range.
        // `f64 -> u64` is a saturating cast, so a finite-but-huge value clamps
        // to `u64::MAX` rather than wrapping — and it is still PRESENT (not
        // dropped), which is the parity fix.
        Some(value) => parse_int_str(&js_stringify(value))
            .filter(|f| f.is_finite() && *f >= 0.0)
            .map(|f| f.trunc() as u64),
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
/// FIRST for EVERY value — including a JSON number — so it is stringified the
/// JavaScript way before the leading integer is parsed: `timeoutMs: ["1000"]` →
/// `String(["1000"])` is `"1000"` → `1000`, `["1","2"]` → `"1,2"` → `1`, and a
/// large number such as `1e21` → `"1e+21"` → `1` (Node yields `1`; a numeric
/// fast path that instead casts the `f64` saturates to `i64::MAX`). A leading
/// `+`/`-` with no digit, or no leading digit at all, is `NaN` → absent.
fn coerce_int(v: Option<&Value>) -> Option<i64> {
    match v {
        None => None,
        // parseInt yields a double; truncate toward zero and clamp to the `i64`
        // range. `f64 -> i64` saturates, so a finite-but-huge magnitude clamps
        // to `i64::MIN`/`MAX` instead of overflowing to absent — the value stays
        // present (the parity fix), matching Node keeping a finite Number.
        Some(value) => parse_int_str(&js_stringify(value))
            .filter(|f| f.is_finite())
            .map(|f| f.trunc() as i64),
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
    fn coerce_u_parses_large_numbers_the_js_way() {
        // `String(v)` runs BEFORE `parseInt`, so a JSON number is stringified the
        // JavaScript way first: `1e21` → `"1e+21"` → leading integer `1`. A
        // numeric fast path that casts the `f64` instead saturates to
        // `u64::MAX`, turning a 1 ms Node timeout into an unbounded one.
        assert_eq!(coerce_u(Some(&json!(1e21))), Some(1)); // "1e+21" → 1
        assert_eq!(coerce_u(Some(&json!(1e100))), Some(1)); // "1e+100" → 1
        assert_eq!(coerce_u(Some(&json!(1e-7))), Some(1)); // "1e-7" → 1
                                                           // A small sub-1 decimal is stringified the ECMAScript way — `0.000001`
                                                           // → `"0.000001"` (NOT serde_json's `"1e-6"`) — so `parseInt` reads the
                                                           // leading `0`, exactly as Node's `coerceInt(0.000001)` → `0`.
        assert_eq!(coerce_u(Some(&json!(0.000001))), Some(0)); // "0.000001" → 0
                                                               // A float within range still truncates like parseInt.
        assert_eq!(coerce_u(Some(&json!(7.9))), Some(7));
    }

    #[test]
    fn js_number_string_matches_ecmascript_number_to_string() {
        // The normalizer's `String(number)` must reproduce ECMAScript
        // `Number::toString`, not serde_json's JSON rendering. serde_json pads an
        // integral float with `.0` and switches to exponential at different
        // thresholds; each case below is a divergence serde_json gets wrong.
        let cases: &[(&str, &str)] = &[
            // Integral floats drop the `.0`.
            ("100.0", "100"),
            ("1.0", "1"),
            ("9007199254740992.0", "9007199254740992"),
            ("123456789.0", "123456789"),
            // Small decimals stay decimal down to 1e-6 inclusive (serde says "1e-6").
            ("0.000001", "0.000001"),
            ("1e-5", "0.00001"),
            ("0.0001", "0.0001"),
            // …but exponential below 1e-6.
            ("0.0000001", "1e-7"),
            ("5e-324", "5e-324"),
            // Large magnitudes stay decimal up to 1e21 exclusive…
            ("1e15", "1000000000000000"),
            ("1e16", "10000000000000000"),
            ("1e20", "100000000000000000000"),
            ("9.99e20", "999000000000000000000"),
            // …and exponential at 1e21 and beyond.
            ("1e21", "1e+21"),
            ("9.99e21", "9.99e+21"),
            ("1e100", "1e+100"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            // Ordinary decimals, signs, and integers.
            ("7.9", "7.9"),
            ("0.1", "0.1"),
            ("0.30000000000000004", "0.30000000000000004"),
            ("1234.5678", "1234.5678"),
            ("-0.000001", "-0.000001"),
            ("-1e21", "-1e+21"),
            ("7", "7"),
            ("-3", "-3"),
            ("0", "0"),
            ("-0.0", "0"),
        ];
        for (input, want) in cases {
            let v: Value = serde_json::from_str(input).unwrap();
            let n = match &v {
                Value::Number(n) => n,
                _ => panic!("{input} is not a number"),
            };
            assert_eq!(&js_number_string(n), want, "String({input})");
        }
    }

    #[test]
    fn coerce_u_keeps_finite_numbers_beyond_i64_range() {
        // parseInt yields a finite JavaScript Number for a digit run of ANY
        // magnitude, so a decimal outside `i64` range must stay PRESENT — not
        // overflow to `None` and silently drop the field (a dropped
        // `cloneTimeoutMs` makes the clone run on the default timeout).
        // `"9223372036854775808"` is past `i64::MAX`; Node parseInt yields the
        // finite `9223372036854776000`, so the field survives (saturating to
        // `u64` on the typed path) instead of being dropped.
        assert!(coerce_u(Some(&json!("9223372036854775808"))).is_some());
        // Above 2^53 the value rounds the JavaScript-double way, exactly as
        // Node's `parseInt("9007199254740993")` → `9007199254740992`.
        assert_eq!(
            coerce_u(Some(&json!("9007199254740993"))),
            Some(9007199254740992)
        );
    }

    #[test]
    fn coerce_int_keeps_finite_numbers_beyond_i64_range() {
        // Same parity for the signed fields: a finite-but-huge magnitude clamps
        // to the `i64` range instead of overflowing to absent.
        assert_eq!(
            coerce_int(Some(&json!("9007199254740993"))),
            Some(9007199254740992)
        );
        assert_eq!(
            coerce_int(Some(&json!("9223372036854775808"))),
            Some(i64::MAX)
        );
        assert_eq!(
            coerce_int(Some(&json!("-9223372036854775809"))),
            Some(i64::MIN)
        );
    }

    #[test]
    fn coerce_int_parses_large_numbers_the_js_way() {
        // Same `parseInt(String(v), 10)` for the signed fields: the number is
        // JS-stringified first, never cast, so a huge magnitude is not saturated.
        assert_eq!(coerce_int(Some(&json!(1e21))), Some(1)); // "1e+21" → 1
        assert_eq!(coerce_int(Some(&json!(-1e21))), Some(-1)); // "-1e+21" → -1
        assert_eq!(coerce_int(Some(&json!(7.9))), Some(7));
        assert_eq!(coerce_int(Some(&json!(-3))), Some(-3));
        assert_eq!(coerce_int(Some(&json!(["1000"]))), Some(1000));
        assert_eq!(coerce_int(Some(&json!(null))), None); // "null" → NaN
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
