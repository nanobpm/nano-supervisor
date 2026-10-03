//! The four job commands the worker needs, over one of two back ends:
//!
//! - `Sdk`: `camunda-orchestration-sdk` (Camunda spec field names). This is the
//!   transport `Auto` resolves to — the same one the Node plugin uses. Nano
//!   engine ≥ 0.0.24 returns the spec's `jobLeaseToken` (alongside its legacy
//!   `leaseToken`), so the SDK round-trips the lease and CAN settle leased jobs.
//! - `Nano`: raw HTTP in the Nano engine's legacy `leaseToken` dialect, kept as
//!   an explicit fallback for OLDER engines (< 0.0.24) whose activation response
//!   names the token `leaseToken` where the Camunda 8.10 spec — and therefore
//!   the SDK — says `jobLeaseToken`. On those engines the SDK drops the token on
//!   activation and never sends it, so leased jobs can't be settled over the SDK
//!   (409). Remove this back end once the engines in the field all speak
//!   `jobLeaseToken`.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use camunda_orchestration_sdk::apis::job_api::UpdateJobParams;
use camunda_orchestration_sdk::models::{
    ActivatedJobResult, JobActivationRequest, JobChangeset, JobCompletionRequest, JobFailRequest,
    JobLeaseToken, JobUpdateRequest,
};
use camunda_orchestration_sdk::CamundaClient;
use serde_json::{json, Value};

/// An activated job plus its lease token (if leased).
pub struct Job {
    pub job: ActivatedJobResult,
    pub lease: Option<String>,
}

/// Reject any job key that is not the engine's canonical numeric key format
/// before it is joined onto a filesystem path. The engine hands out job keys as
/// decimal integer strings; a malformed or untrusted response carrying `../`, an
/// absolute path, or path separators must never reach `runs_dir.join(key)`, or a
/// per-job run directory (which is recursively removed and re-created every
/// attempt) could escape `runs_dir` and delete/run from an arbitrary location.
pub(crate) fn validate_job_key(key: &str) -> Result<()> {
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_digit()) {
        bail!("job key {key:?} is not a numeric engine key; refusing to use it as a run-dir name");
    }
    Ok(())
}

#[derive(Clone)]
pub enum Jobs {
    Sdk(Box<CamundaClient>),
    Nano(NanoHttp),
}

/// An HTTP error response from the Nano engine: carries the status code as a
/// STRUCTURED value (the refresh loop reads it via [`NanoHttp::status_of`]) so
/// fence detection never has to substring-match a message that also embeds the
/// `/jobs/{key}` path — a numeric job key can itself contain "404"/"409".
#[derive(Debug)]
struct HttpStatus {
    status: u16,
    message: String,
}

impl std::fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HttpStatus {}

/// Preserve an SDK error as a STRUCTURED [`anyhow`] link rather than flattening
/// it to text. The old `anyhow::anyhow!("{e}")` rendering destroyed the typed
/// [`camunda_orchestration_sdk::CamundaError`], so [`NanoHttp::status_of`] could
/// only recover the status by substring-scanning the flattened message — and an
/// `Api` error whose *body* echoes an `HTTP <status> ` marker (e.g. a 500 whose
/// RFC 7807 body mentions "HTTP 404 ") was then misclassified by the ascending
/// marker scan as the echoed status, treating a transient server error as a
/// lease fence. Keeping the typed link lets `status_of` read the authoritative
/// structured `status` and never reach the marker fallback.
fn sdk_error(e: camunda_orchestration_sdk::CamundaError) -> anyhow::Error {
    anyhow::Error::new(e)
}

#[derive(Clone)]
pub struct NanoHttp {
    http: reqwest::Client,
    /// e.g. `http://localhost:8080/v2`
    base: String,
    basic: Option<(String, String)>,
}

impl NanoHttp {
    pub fn new(rest_address: &str, basic: Option<(String, String)>) -> Result<Self> {
        let base = rest_address.trim_end_matches('/');
        let base = base.strip_suffix("/v2").unwrap_or(base);
        Ok(Self {
            http: reqwest::Client::builder().build()?,
            base: format!("{base}/v2"),
            basic,
        })
    }

    /// The HTTP status of a failing [`send`] error, if it was an HTTP error at
    /// all (as opposed to a transport/timeout failure, which carries no status).
    ///
    /// A STRUCTURED status anywhere in the chain is AUTHORITATIVE and is
    /// returned verbatim — either our own [`HttpStatus`] (Nano backend) or the
    /// SDK's [`camunda_orchestration_sdk::CamundaError::Api`] (SDK backend),
    /// which the [`Jobs`] methods preserve as a structured link via
    /// [`sdk_error`] rather than flattening to text. Only when no link carries
    /// one do we fall back to the unambiguous `HTTP <status> ` marker [`send`]
    /// puts in the message — never the bare digits, which a numeric job key in
    /// the interpolated `/jobs/{key}` path could itself contain. Critically, the
    /// marker fallback must NOT run when a structured status is present: `send`
    /// folds a bounded body excerpt into the message, so a genuine 500 whose
    /// body echoes `HTTP 404 ` would otherwise be misclassified as a 404 lease
    /// fence (the old scan was ascending). Structured-first closes that whole
    /// class.
    pub(crate) fn status_of(e: &anyhow::Error) -> Option<u16> {
        if let Some(h) = e.chain().find_map(|c| c.downcast_ref::<HttpStatus>()) {
            return Some(h.status);
        }
        if let Some(s) = e
            .chain()
            .find_map(|c| c.downcast_ref::<camunda_orchestration_sdk::CamundaError>())
            .and_then(|c| c.status())
        {
            return Some(s);
        }
        e.chain().find_map(|c| {
            let s = c.to_string();
            (400..=599u16).find(|&st| s.contains(&format!("HTTP {st} ")))
        })
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Value,
        timeout: Duration,
    ) -> Result<Value> {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .json(&body)
            .timeout(timeout);
        if let Some((u, p)) = &self.basic {
            req = req.basic_auth(u, Some(p));
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("{path}: request failed"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            // Bail with the status as a STRUCTURED HttpStatus error (the
            // refresh loop keys off the 404/409 fence statuses via
            // `status_of`, and a bare-digit match would misclassify a job key
            // containing those digits as a fence). The message keeps the
            // unambiguous `HTTP <status> ` marker plus a bounded body excerpt;
            // the path is added as context by the caller, so the formatted
            // chain still reads `/jobs/{key}: HTTP 404 Not Found :: {body}`.
            let mut msg = status
                .canonical_reason()
                .map(|r| format!("HTTP {} {r}", status.as_u16()))
                .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
            if !text.is_empty() {
                msg.push_str(" :: ");
                msg.push_str(&text.chars().take(300).collect::<String>());
            }
            return Err(anyhow::Error::new(HttpStatus {
                status: status.as_u16(),
                message: msg,
            }));
        }
        Ok(if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text)?
        })
    }
}

fn token_of(lease: &Option<String>) -> Option<Option<JobLeaseToken>> {
    lease
        .as_ref()
        .map(|t| Some(JobLeaseToken::assume_exists(t.clone())))
}

impl Jobs {
    pub async fn activate(
        &self,
        job_type: &str,
        worker: &str,
        timeout: Duration,
        poll: Duration,
        with_lease: bool,
    ) -> Result<Vec<Job>> {
        match self {
            Jobs::Sdk(c) => {
                let mut req =
                    JobActivationRequest::new(job_type.to_string(), timeout.as_millis() as i64, 1);
                req.worker = Some(worker.to_string());
                req.request_timeout = Some(poll.as_millis() as i64);
                if with_lease {
                    req.with_lease = Some(Some(true));
                }
                let r = c.activate_jobs(req).await.map_err(sdk_error)?;
                Ok(r.jobs
                    .into_iter()
                    .map(|j| {
                        let lease = j.job_lease_token.as_ref().map(|t| t.value().to_string());
                        Job { job: j, lease }
                    })
                    .collect())
            }
            Jobs::Nano(n) => {
                let body = json!({
                    "type": job_type, "worker": worker, "timeout": timeout.as_millis() as i64,
                    "maxJobsToActivate": 1, "requestTimeout": poll.as_millis() as i64,
                    "withLease": with_lease,
                });
                let v = n
                    .send(
                        reqwest::Method::POST,
                        "/jobs/activation",
                        body,
                        poll + Duration::from_secs(10),
                    )
                    .await
                    .with_context(|| "/jobs/activation".to_string())?;
                let mut out = Vec::new();
                for raw in v["jobs"].as_array().cloned().unwrap_or_default() {
                    let lease = raw["leaseToken"].as_str().map(String::from);
                    let job: ActivatedJobResult =
                        serde_json::from_value(raw).context("decoding activated job")?;
                    out.push(Job { job, lease });
                }
                Ok(out)
            }
        }
    }

    /// Extend the activation timeout (the lease refresh).
    pub async fn extend(&self, key: &str, timeout: Duration, lease: &Option<String>) -> Result<()> {
        // The Nano backend interpolates `key` straight into `/jobs/{key}`, so a
        // malformed (non-numeric) engine key must never reach the request. Guard
        // at the request boundary so no caller ordering can settle/refresh with
        // an unvalidated key.
        validate_job_key(key)?;
        match self {
            Jobs::Sdk(c) => {
                let mut changeset = JobChangeset::new();
                changeset.timeout = Some(Some(timeout.as_millis() as i64));
                let mut body = JobUpdateRequest::new(changeset);
                body.job_lease_token = token_of(lease);
                c.update_job(UpdateJobParams {
                    job_key: key.to_string(),
                    job_update_request: body,
                })
                .await
                .map_err(sdk_error)
            }
            Jobs::Nano(n) => {
                let body = json!({ "changeset": { "timeout": timeout.as_millis() as i64 }, "leaseToken": lease });
                n.send(
                    reqwest::Method::PATCH,
                    &format!("/jobs/{key}"),
                    body,
                    Duration::from_secs(15),
                )
                .await
                // Re-wrap so the path context sits BELOW the structured HTTP
                // status in the error chain: the refresh loop matches the
                // chain for the unambiguous `HTTP 404 ` / `HTTP 409 ` status
                // marker, and a bare `{path}: HTTP …` top line would put a job
                // key containing those digits ahead of it.
                .map_err(|e| e.context(format!("/jobs/{key}")))
                .map(|_| ())
            }
        }
    }

    pub async fn complete(
        &self,
        key: &str,
        vars: HashMap<String, Value>,
        lease: &Option<String>,
    ) -> Result<()> {
        // Guard the interpolated `/jobs/{key}/completion` path (Nano backend).
        validate_job_key(key)?;
        match self {
            Jobs::Sdk(c) => {
                let mut req = JobCompletionRequest::new();
                req.variables = Some(Some(vars));
                req.job_lease_token = token_of(lease);
                c.complete_job(key, Some(req)).await.map_err(sdk_error)
            }
            Jobs::Nano(n) => {
                let body = json!({ "variables": vars, "leaseToken": lease });
                n.send(
                    reqwest::Method::POST,
                    &format!("/jobs/{key}/completion"),
                    body,
                    Duration::from_secs(30),
                )
                .await
                .map_err(|e| e.context(format!("/jobs/{key}/completion")))
                .map(|_| ())
            }
        }
    }

    pub async fn fail(
        &self,
        key: &str,
        retries: i32,
        message: &str,
        vars: Option<HashMap<String, Value>>,
        lease: &Option<String>,
    ) -> Result<()> {
        // Guard the interpolated `/jobs/{key}/failure` path (Nano backend).
        validate_job_key(key)?;
        match self {
            Jobs::Sdk(c) => {
                let mut req = JobFailRequest::new();
                req.retries = Some(retries);
                req.error_message = Some(message.to_string());
                req.retry_back_off = Some(0);
                req.variables = vars;
                req.job_lease_token = token_of(lease);
                c.fail_job(key, Some(req)).await.map_err(sdk_error)
            }
            Jobs::Nano(n) => {
                let mut body = json!({ "retries": retries, "errorMessage": message, "retryBackOff": 0, "leaseToken": lease });
                if let Some(v) = vars {
                    body["variables"] = json!(v);
                }
                n.send(
                    reqwest::Method::POST,
                    &format!("/jobs/{key}/failure"),
                    body,
                    Duration::from_secs(30),
                )
                .await
                .map_err(|e| e.context(format!("/jobs/{key}/failure")))
                .map(|_| ())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_job_key;
    use super::{sdk_error, HttpStatus, NanoHttp};

    #[test]
    fn structured_status_wins_over_a_body_echoed_marker() {
        // A genuine 500 whose bounded body excerpt happens to echo "HTTP 404 ":
        // the structured `HttpStatus` must be authoritative, or the ascending
        // marker scan would misclassify it as a 404 lease fence.
        let e = anyhow::Error::new(HttpStatus {
            status: 500,
            message: "HTTP 500 Internal Server Error :: upstream said HTTP 404 Not Found".into(),
        })
        .context("/jobs/2251799813685250");
        assert_eq!(NanoHttp::status_of(&e), Some(500));
        assert_ne!(NanoHttp::status_of(&e), Some(404));

        // A real 404 fence still resolves to 404 even with a body excerpt.
        let fence = anyhow::Error::new(HttpStatus {
            status: 404,
            message: "HTTP 404 Not Found :: job gone".into(),
        })
        .context("/jobs/2251799813685250");
        assert_eq!(NanoHttp::status_of(&fence), Some(404));
    }

    #[test]
    fn marker_fallback_only_without_a_structured_status() {
        // No structured link: the `HTTP <status> ` marker is the fallback.
        let marker = anyhow::anyhow!("HTTP 409 Conflict").context("/jobs/9409");
        assert_eq!(NanoHttp::status_of(&marker), Some(409));
        // A transport failure whose key merely contains fence digits is None.
        let transport = anyhow::anyhow!("connection reset").context("/jobs/14041234567890");
        assert_eq!(NanoHttp::status_of(&transport), None);
    }

    #[test]
    fn sdk_api_status_is_authoritative_over_a_body_echoed_marker() {
        // The SDK backend (`Jobs::extend`/`complete`/`fail`) preserves the typed
        // `CamundaError` as a structured link via `sdk_error`. A genuine 500
        // whose RFC 7807 body echoes "HTTP 404 " must resolve to 500, NOT the
        // echoed 404 — otherwise the refresher treats a transient server error
        // as a lease fence and abandons a live activation. The old
        // `anyhow::anyhow!("{e}")` flattening destroyed the typed status and
        // left only the ascending marker scan, which returned 404.
        let e = sdk_error(camunda_orchestration_sdk::CamundaError::Api {
            status: 500,
            body: Some("upstream said HTTP 404 Not Found".into()),
        })
        .context("/jobs/2251799813685250");
        assert_eq!(NanoHttp::status_of(&e), Some(500));
        assert_ne!(NanoHttp::status_of(&e), Some(404));

        // A real SDK 404 fence still resolves to 404.
        let fence = sdk_error(camunda_orchestration_sdk::CamundaError::Api {
            status: 404,
            body: Some("job gone".into()),
        })
        .context("/jobs/2251799813685250");
        assert_eq!(NanoHttp::status_of(&fence), Some(404));

        // A non-HTTP SDK error (network/validation) carries no status.
        let network = sdk_error(camunda_orchestration_sdk::CamundaError::Validation(
            "bad request".into(),
        ));
        assert_eq!(NanoHttp::status_of(&network), None);
    }

    #[test]
    fn accepts_numeric_engine_keys() {
        assert!(validate_job_key("0").is_ok());
        assert!(validate_job_key("2251799813685249").is_ok());
    }

    #[test]
    fn rejects_traversal_and_non_numeric_keys() {
        for bad in [
            "",
            "../escape",
            "/abs",
            "12/34",
            "12..34",
            "12 34",
            "abc",
            "12a",
        ] {
            assert!(
                validate_job_key(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }
}
