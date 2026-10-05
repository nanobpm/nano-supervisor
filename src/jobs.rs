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
    /// A conservative lower bound on when the engine started this job's lease.
    ///
    /// The engine starts the lease when it *dispatches* the job, which is before
    /// the activation response crosses the wire and is decoded here. The anchor
    /// is derived in [`Jobs::activate`] from the engine-provided `deadline` (the
    /// authoritative server-side lease expiry) via [`lease_anchor`], falling
    /// back to the decode instant when the wall clock cannot be reconciled.
    /// Either way it is a *lower* bound on the true dispatch instant, so the
    /// refresher's initial deadline (`dispatched_at + window`) lands at or
    /// *before* the true server-side expiry: the refresher fences slightly
    /// early, never late — a delayed response cannot let it run past the lease.
    pub dispatched_at: std::time::Instant,
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

/// Derive a monotonic lease-start anchor from the engine-provided `deadline`.
///
/// The engine starts a job's lease when it *dispatches* the job and reports the
/// resulting lease expiry in `ActivatedJobResult.deadline` ("when the job can be
/// activated again", a UNIX epoch timestamp in milliseconds). That expiry is
/// `dispatch_wall + window` on the engine's clock — the authoritative
/// server-side lease boundary — so the dispatch instant is `deadline - window`.
/// The refresher, however, works on a monotonic [`std::time::Instant`], so this
/// converts the wall-clock dispatch into the local monotonic frame:
///
/// ```text
/// dispatch_ago = local_wall_now - (deadline_wall - window)
/// anchor       = decoded_at - dispatch_ago
/// ```
///
/// Because the response transits and is decoded *after* dispatch, `decoded_at`
/// is itself an upper bound on the true dispatch, so the resulting anchor is a
/// conservative LOWER bound: the refresher's `anchor + window` deadline lands at
/// or *before* the real server-side expiry, never after it — the overrun a
/// decode-time-only anchor allowed.
///
/// Two guards keep a wrong clock conservative rather than dangerous:
///   * the anchor is clamped to `<= decoded_at` (a deadline far in the future
///     would otherwise push the anchor — and the fence — *later* than decode);
///   * if the wall clock is unusable (before the UNIX epoch) the anchor falls
///     back to `decoded_at`, which is still no later than the even-later
///     handle-task start the previous code used.
pub(crate) fn lease_anchor(
    deadline_ms: i64,
    window: Duration,
    decoded_at: std::time::Instant,
    wall_now: std::time::SystemTime,
) -> std::time::Instant {
    use std::time::{Duration as D, UNIX_EPOCH};
    let wall_since_epoch = match wall_now.duration_since(UNIX_EPOCH) {
        Ok(d) => d,
        // Local wall clock before the epoch: cannot reconcile with the engine's
        // epoch deadline, so fall back to the (still conservative) decode instant.
        Err(_) => return decoded_at,
    };
    // The engine's deadline is `dispatch + window`, so the dispatch wall instant
    // is `deadline - window`. A deadline smaller than the window (or negative)
    // means the lease has already lapsed; saturating to the epoch makes
    // `dispatch_ago` the whole local wall age, which clamps the anchor to the
    // monotonic floor — conservatively early, so the refresher fences at once.
    let deadline_wall = D::from_millis(deadline_ms.max(0) as u64);
    let dispatch_wall = deadline_wall.saturating_sub(window);
    // How long ago dispatch happened on the local monotonic clock. `saturating_sub`
    // yields 0 when dispatch is at/after now (deadline in the future), which
    // leaves the anchor at `decoded_at` — never later.
    let dispatch_ago = wall_since_epoch.saturating_sub(dispatch_wall);
    // Subtract, clamping at the monotonic floor (a lapsed lease collapses to the
    // earliest representable instant so its deadline is already past and the
    // refresher fences) and never rising above `decoded_at` (`dispatch_ago` of 0
    // yields exactly `decoded_at`). `Instant::saturating_sub` is not on the
    // pinned toolchain, so use `checked_sub` against a far-past reference floor.
    let floor = decoded_at
        .checked_sub(D::from_secs(60 * 60 * 24 * 365 * 30))
        .unwrap_or(decoded_at);
    decoded_at.checked_sub(dispatch_ago).unwrap_or(floor)
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
        // The lease anchor must be a LOWER bound on when the engine started each
        // job's lease (at dispatch — before the response crossed the wire and was
        // decoded here). Anchor it on the engine-provided `deadline` (the
        // server-side lease expiry), which is authoritative; only when that is
        // unusable (clock skew) fall back to the decode instant, which is still
        // no later than the even-later handle-task start the previous code used.
        let decoded_at = std::time::Instant::now();
        let wall_now = std::time::SystemTime::now();
        Ok(r.jobs
            .into_iter()
            .map(|j| {
                let lease = j.job_lease_token.as_ref().map(|t| t.value().to_string());
                let dispatched_at = lease_anchor(j.deadline, timeout, decoded_at, wall_now);
                Job {
                    job: j,
                    lease,
                    dispatched_at,
                }
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
    use super::{lease_anchor, sdk_error, status_of};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

    #[test]
    fn lease_anchor_uses_the_engine_deadline_not_the_late_decode_instant() {
        // Regression for the review finding that a decode-time `Instant::now()`
        // anchor is an UPPER bound on dispatch: the engine started the lease
        // `transit` before the response was decoded, so anchoring at decode lets
        // `anchor + window` overrun the real server-side expiry by `transit`.
        //
        // The engine reports the authoritative expiry in `deadline` (epoch ms =
        // dispatch_wall + window). Drive the real `lease_anchor` and assert the
        // resulting deadline lands at the engine's expiry — NOT a full window
        // past the (late) decode instant.
        let window = Duration::from_secs(300);
        let transit = Duration::from_secs(2); // dispatch -> decode gap
        let decoded_at = Instant::now();
        // The engine dispatched `transit` ago: its deadline (dispatch + window)
        // is therefore `window - transit` in the future on the wall clock.
        let wall_now = SystemTime::now();
        let deadline_wall = wall_now + (window - transit);
        let deadline_ms = deadline_wall
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let anchor = lease_anchor(deadline_ms, window, decoded_at, wall_now);
        let deadline = anchor + window;

        // The deadline must sit ~`window - transit` out (the engine's expiry),
        // not ~`window` out (the over-granting decode anchor). Allow a few ms of
        // slop for the two clock reads straddling the call.
        let out = deadline.saturating_duration_since(decoded_at);
        assert!(
            out <= window - transit + Duration::from_millis(50),
            "deadline {out:?} out overruns the engine expiry (~{:?} out)",
            window - transit
        );
        assert!(
            out >= window - transit - Duration::from_millis(50),
            "deadline {out:?} out fences implausibly early (~{:?} expected)",
            window - transit
        );
        // And it must never grant MORE than the decode anchor the old code used.
        assert!(
            deadline <= decoded_at + window,
            "engine-deadline anchor must never grant a later deadline than decode-anchoring"
        );
    }

    #[test]
    fn lease_anchor_never_exceeds_decode_on_a_future_deadline() {
        // A deadline far in the future (clock skew, or a freshly extended lease
        // observed mid-flight) must not push the anchor — and thus the fence —
        // later than the decode instant. Clamp to `decoded_at`.
        let window = Duration::from_secs(300);
        let decoded_at = Instant::now();
        let wall_now = SystemTime::now();
        // Deadline a full window in the future => dispatch "now" => anchor at decode.
        let deadline_ms = (wall_now + window)
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let anchor = lease_anchor(deadline_ms, window, decoded_at, wall_now);
        assert!(
            anchor <= decoded_at + Duration::from_millis(50),
            "a future deadline must not move the anchor past decode"
        );
    }

    #[test]
    fn lease_anchor_fences_immediately_on_a_lapsed_lease() {
        // A deadline already in the past (or smaller than one window) means the
        // lease has lapsed: the anchor must collapse to the monotonic floor so
        // `anchor + window` is already in the past and the refresher fences.
        let window = Duration::from_secs(300);
        let decoded_at = Instant::now();
        let wall_now = SystemTime::now();
        // Deadline one second after the epoch — long lapsed.
        let anchor = lease_anchor(1_000, window, decoded_at, wall_now);
        let deadline = anchor + window;
        assert!(
            deadline <= decoded_at,
            "a lapsed lease must produce a deadline at/before now so the refresher fences"
        );
    }
}
