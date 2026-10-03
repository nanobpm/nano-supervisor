//! The four job commands the worker needs, over one of two back ends:
//!
//! - `Sdk`: `camunda-orchestration-sdk` (Camunda spec field names).
//! - `Nano`: raw HTTP in the Nano engine's dialect. The engine names the lease
//!   token `leaseToken` (activation response *and* command bodies) where the
//!   Camunda 8.10 spec, and therefore the SDK, says `jobLeaseToken`. With the
//!   SDK the token is dropped on activation and never sent, so leased jobs can't
//!   be settled (409). Remove this back end once the names agree.

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

    /// Whether a formatted error from [`send`] carries the given HTTP status.
    /// Reads the STRUCTURED [`HttpStatus`] off the chain first, then falls back
    /// to the unambiguous `HTTP <status> ` marker [`send`] puts in the message —
    /// never the bare digits, which a numeric job key in the interpolated
    /// `/jobs/{key}` path could itself contain.
    pub(crate) fn is_status(e: &anyhow::Error, status: u16) -> bool {
        e.chain().any(|c| {
            c.downcast_ref::<HttpStatus>()
                .is_some_and(|h| h.status == status)
                || c.to_string().contains(&format!("HTTP {status} "))
        })
    }

    /// The HTTP status of a failing [`send`] error, if it was an HTTP error at
    /// all (as opposed to a transport/timeout failure, which carries no status).
    pub(crate) fn status_of(e: &anyhow::Error) -> Option<u16> {
        (400..=599u16).find(|&s| Self::is_status(e, s))
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
                let r = c
                    .activate_jobs(req)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
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
                .map_err(|e| anyhow::anyhow!("{e}"))
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
                c.complete_job(key, Some(req))
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))
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
                c.fail_job(key, Some(req))
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))
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
