//! The four job commands the worker needs, over the `camunda-orchestration-sdk`.
//!
//! The SDK speaks the Camunda 8.10 spec field names. Nano engine ≥ v0.0.24
//! normalised the lease-token name to the spec's `jobLeaseToken`, so the SDK
//! round-trips the lease and settles leased jobs end to end (verified in
//! nanobpm/nano-bpm#1284). The earlier raw-HTTP `--job-api nano` transport —
//! which spoke the engine's legacy `leaseToken` dialect for engines that named
//! the token differently from the spec — is gone; the SDK is the only transport.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Result};
use camunda_orchestration_sdk::apis::job_api::UpdateJobParams;
use camunda_orchestration_sdk::models::{
    ActivatedJobResult, JobActivationRequest, JobChangeset, JobCompletionRequest, JobFailRequest,
    JobLeaseToken, JobUpdateRequest,
};
use camunda_orchestration_sdk::CamundaClient;
use serde_json::Value;

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

/// The shared engine job client: one SDK `CamundaClient` (and its HTTP pool)
/// shared by all of a daemon's slots.
#[derive(Clone)]
pub struct Jobs {
    client: Box<CamundaClient>,
}

/// Preserve an SDK error as a STRUCTURED [`anyhow`] link rather than flattening
/// it to text. The old `anyhow::anyhow!("{e}")` rendering destroyed the typed
/// [`camunda_orchestration_sdk::CamundaError`], so [`status_of`] could only
/// recover the status by substring-scanning the flattened message — and an
/// `Api` error whose *body* echoes an `HTTP <status> ` marker (e.g. a 500 whose
/// RFC 7807 body mentions "HTTP 404 ") was then misclassified by the ascending
/// marker scan as the echoed status, treating a transient server error as a
/// lease fence. Keeping the typed link lets `status_of` read the authoritative
/// structured `status` and never reach the marker fallback.
fn sdk_error(e: camunda_orchestration_sdk::CamundaError) -> anyhow::Error {
    anyhow::Error::new(e)
}

/// The HTTP status of a failing job command, if it was an HTTP error at all (as
/// opposed to a transport/timeout failure, which carries no status). The refresh
/// loop keys off the 404/409 lease-fence statuses via this.
///
/// A STRUCTURED status in the chain is AUTHORITATIVE and is returned verbatim —
/// the SDK's [`camunda_orchestration_sdk::CamundaError::Api`], which the [`Jobs`]
/// methods preserve as a structured link via [`sdk_error`] rather than
/// flattening to text. Only when no link carries one do we fall back to the
/// unambiguous `HTTP <status> ` marker that may appear in a flattened message —
/// never the bare digits, which a numeric job key in an interpolated
/// `/jobs/{key}` path could itself contain. The marker fallback must NOT run
/// when a structured status is present: a genuine 500 whose body echoes
/// `HTTP 404 ` would otherwise be misclassified as a 404 lease fence (the scan
/// is ascending). Structured-first closes that whole class.
pub(crate) fn status_of(e: &anyhow::Error) -> Option<u16> {
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

fn token_of(lease: &Option<String>) -> Option<Option<JobLeaseToken>> {
    lease
        .as_ref()
        .map(|t| Some(JobLeaseToken::assume_exists(t.clone())))
}

impl Jobs {
    /// Build the shared job client from an SDK `CamundaClient`.
    pub fn new(client: CamundaClient) -> Self {
        Jobs {
            client: Box::new(client),
        }
    }

    pub async fn activate(
        &self,
        job_type: &str,
        worker: &str,
        timeout: Duration,
        poll: Duration,
        with_lease: bool,
    ) -> Result<Vec<Job>> {
        let mut req =
            JobActivationRequest::new(job_type.to_string(), timeout.as_millis() as i64, 1);
        req.worker = Some(worker.to_string());
        req.request_timeout = Some(poll.as_millis() as i64);
        if with_lease {
            req.with_lease = Some(Some(true));
        }
        let r = self.client.activate_jobs(req).await.map_err(sdk_error)?;
        Ok(r.jobs
            .into_iter()
            .map(|j| {
                let lease = j.job_lease_token.as_ref().map(|t| t.value().to_string());
                Job { job: j, lease }
            })
            .collect())
    }

    /// Extend the activation timeout (the lease refresh).
    pub async fn extend(&self, key: &str, timeout: Duration, lease: &Option<String>) -> Result<()> {
        // Guard the key before it reaches the SDK (which interpolates it into
        // the `/jobs/{key}` request path) so no caller ordering can refresh with
        // an unvalidated key.
        validate_job_key(key)?;
        let mut changeset = JobChangeset::new();
        changeset.timeout = Some(Some(timeout.as_millis() as i64));
        let mut body = JobUpdateRequest::new(changeset);
        body.job_lease_token = token_of(lease);
        self.client
            .update_job(UpdateJobParams {
                job_key: key.to_string(),
                job_update_request: body,
            })
            .await
            .map_err(sdk_error)
    }

    pub async fn complete(
        &self,
        key: &str,
        vars: HashMap<String, Value>,
        lease: &Option<String>,
    ) -> Result<()> {
        validate_job_key(key)?;
        let mut req = JobCompletionRequest::new();
        req.variables = Some(Some(vars));
        req.job_lease_token = token_of(lease);
        self.client
            .complete_job(key, Some(req))
            .await
            .map_err(sdk_error)
    }

    pub async fn fail(
        &self,
        key: &str,
        retries: i32,
        message: &str,
        vars: Option<HashMap<String, Value>>,
        lease: &Option<String>,
    ) -> Result<()> {
        validate_job_key(key)?;
        let mut req = JobFailRequest::new();
        req.retries = Some(retries);
        req.error_message = Some(message.to_string());
        req.retry_back_off = Some(0);
        req.variables = vars;
        req.job_lease_token = token_of(lease);
        self.client
            .fail_job(key, Some(req))
            .await
            .map_err(sdk_error)
    }
}

#[cfg(test)]
mod tests {
    use super::validate_job_key;
    use super::{sdk_error, status_of};

    #[test]
    fn sdk_api_status_is_authoritative_over_a_body_echoed_marker() {
        // The SDK (`Jobs::extend`/`complete`/`fail`) preserves the typed
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
        assert_eq!(status_of(&e), Some(500));
        assert_ne!(status_of(&e), Some(404));

        // A real SDK 404 fence still resolves to 404.
        let fence = sdk_error(camunda_orchestration_sdk::CamundaError::Api {
            status: 404,
            body: Some("job gone".into()),
        })
        .context("/jobs/2251799813685250");
        assert_eq!(status_of(&fence), Some(404));

        // A non-HTTP SDK error (network/validation) carries no status.
        let network = sdk_error(camunda_orchestration_sdk::CamundaError::Validation(
            "bad request".into(),
        ));
        assert_eq!(status_of(&network), None);
    }

    #[test]
    fn marker_fallback_only_without_a_structured_status() {
        // No structured link: the `HTTP <status> ` marker is the fallback.
        let marker = anyhow::anyhow!("HTTP 409 Conflict").context("/jobs/9409");
        assert_eq!(status_of(&marker), Some(409));
        // A transport failure whose key merely contains fence digits is None.
        let transport = anyhow::anyhow!("connection reset").context("/jobs/14041234567890");
        assert_eq!(status_of(&transport), None);
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
