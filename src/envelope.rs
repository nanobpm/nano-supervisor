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

fn as_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// Node's `coerceBool`: booleans pass through; `null`/absent yields the default;
/// any other value is stringified and matched against the true-set
/// (`true`/`1`/`yes`/`on`) and the false-set (`false`/`0`/`no`/`off`/empty),
/// with anything unrecognised falling back to the default. Matching Node here is
/// load-bearing: a prior version only recognised `true`/`1`/`yes` and returned
/// `false` (not the default) for every other string, so `"on"` normalised to
/// false and an unrecognised string on a default-`true` field (e.g. `push`)
/// flipped to false.
fn coerce_bool(v: Option<&Value>, default: bool) -> bool {
    let s = match v {
        None | Some(Value::Null) => return default,
        Some(Value::Bool(b)) => return *b,
        Some(Value::String(s)) => s.trim().to_ascii_lowercase(),
        Some(Value::Number(n)) => n.to_string(),
        Some(_) => return default,
    };
    match s.as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" | "" => false,
        _ => default,
    }
}

fn coerce_u(v: Option<&Value>) -> Option<u64> {
    match v {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
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

/// Node's `coerceInt`: a number, or a string with a leading integer.
fn coerce_int(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Some(Value::String(s)) => {
            let t = s.trim();
            let end = t
                .char_indices()
                .find(|&(i, c)| !(c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+'))))
                .map(|(i, _)| i)
                .unwrap_or(t.len());
            t[..end].parse().ok()
        }
        _ => None,
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
    let strings = |v: Option<&Value>| -> Value {
        Value::Array(
            v.and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|x| Value::String(as_str(x).unwrap_or_else(|| "null".into())))
                        .collect()
                })
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
