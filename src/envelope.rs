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
    /// The raw merged `io.nanobpm.agentTask` object, forwarded verbatim to the
    /// pipe agent as `task` so it sees the full envelope.
    pub raw: Value,
}

fn as_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn coerce_bool(v: Option<&Value>, default: bool) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => {
            matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes")
        }
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

    Envelope {
        prompt,
        repository,
        raw,
    }
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
