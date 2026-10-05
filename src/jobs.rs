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
    /// The pinned engine identity (`engine: <profile> (<baseUrl>)`), carried so
    /// the sanity guard can name the engine in its warning.
    engine_desc: Option<String>,
    /// The job-type prefixes that mark a throwaway contract-test engine
    /// (issue #41): a worker whose whole matrix matches only these is almost
    /// certainly pointed at a test cluster, so the first activation logs a
    /// prominent warning naming the engine.
    test_type_prefixes: Vec<String>,
    /// Fires the sanity-guard warning at most once per worker process. Kept for
    /// backwards compatibility with [`Jobs::with_identity`]; the daemon instead
    /// latches PER SLOT via [`Jobs::for_slot`] (see [`Jobs::activate_for`]).
    sanity_warned: std::sync::Arc<std::sync::atomic::AtomicBool>,
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

/// True when `prefixes` is non-empty and every entry looks like a throwaway
/// test type (`probe-*` / `ct-*`). Pure classifier behind
/// [`Jobs::looks_like_test_engine`], unit-tested without a live client.
fn all_test_looking(prefixes: &[String]) -> bool {
    !prefixes.is_empty()
        && prefixes
            .iter()
            .all(|t| t.starts_with("probe-") || t.starts_with("ct-"))
}

/// The one-shot issue-#41 sanity-warning decision, factored out of
/// [`Jobs::should_warn_sanity`] so it is testable without an engine round-trip.
/// Fires only when the activation returned jobs AND every served type looks
/// test-ish AND the latch had not already tripped; latches `true` on the first
/// qualifying call so the warning is emitted at most once per worker.
fn warn_sanity_decision(
    got_jobs: bool,
    looks_test: bool,
    latch: &std::sync::atomic::AtomicBool,
) -> bool {
    got_jobs && looks_test && !latch.swap(true, std::sync::atomic::Ordering::Relaxed)
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
            engine_desc: None,
            test_type_prefixes: Vec::new(),
            sanity_warned: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Attach the pinned engine identity and the worker's test-looking job-type
    /// prefixes for the issue-#41 sanity guard (see [`Jobs::activate`]).
    pub fn with_identity(self, engine_desc: String, test_type_prefixes: Vec<String>) -> Self {
        Jobs {
            engine_desc: Some(engine_desc),
            test_type_prefixes,
            ..self
        }
    }

    /// Derive a PER-SLOT view of this shared client for the issue-#41 sanity
    /// guard (issue #41, proposal 4). The daemon shares one `Jobs` across every
    /// slot, but the "every served type looks test-ish" judgement must be made
    /// against the SLOT's own job-type matrix — not the aggregate of every hire
    /// — or a daemon mixing a normal hire with a `ct-*`-only hire would see the
    /// normal type in the aggregate, make `all_test_looking` false, and never
    /// warn for the slot that is actually serving only test jobs. This view
    /// carries the slot's own matrix and a FRESH one-shot latch, so the warning
    /// fires once per slot. The underlying client (and its HTTP pool) is still
    /// shared — only the guard identity/latch are per-slot.
    pub fn for_slot(&self, slot_job_types: Vec<String>) -> Self {
        Jobs {
            client: self.client.clone(),
            engine_desc: self.engine_desc.clone(),
            test_type_prefixes: slot_job_types,
            sanity_warned: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// True when every served job type looks like a throwaway test type — the
    /// exact shape of the issue-#41 incident, where a retargeted fleet served a
    /// stray engine's `probe-*`/`ct-*` jobs. A production hire's matrix
    /// (`senior`, `senior:feature`, …) never matches, so this only fires for
    /// workers whose whole purpose is test types (an explicit `--job-type`
    /// selection, or a hire configured for them).
    fn looks_like_test_engine(&self) -> bool {
        all_test_looking(&self.test_type_prefixes)
    }

    /// Decide whether the issue-#41 sanity warning should fire for this
    /// activation, and latch it so it fires at most once per worker. Pure given
    /// the receiver's state: it is `true` only when the activation returned
    /// jobs, every served type looks test-ish ([`Self::looks_like_test_engine`]),
    /// and the one-shot latch had not already tripped. Extracted so the decision
    /// is unit-testable without a live engine round-trip.
    fn should_warn_sanity(&self, got_jobs: bool) -> bool {
        warn_sanity_decision(got_jobs, self.looks_like_test_engine(), &self.sanity_warned)
    }

    /// Activate against this view's own sanity-guard identity. This is the body
    /// of [`Jobs::activate`]; a slot calls it via [`Jobs::for_slot`] so the
    /// guard judges the slot's own matrix and latches per slot.
    pub async fn activate_for(
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
        // Sanity guard (issue #41, proposal 4): a worker that only serves
        // test-looking job types and got a LIVE answer from its engine is very
        // likely the retargeted-fleet incident — the only clue then was the
        // worker log. Warn once, prominently, naming the engine URL, so the
        // next retarget is diagnosable from the log instead of from burned
        // tokens. The worker keeps running: a contract-test fleet is a
        // legitimate configuration, so this must inform, never block.
        if self.should_warn_sanity(!r.jobs.is_empty()) {
            crate::runtime::log(&format!(
                "WARNING: worker {worker} is connected to {} but every job type it serves is \
                 test-looking ({:?}); if this is not a throwaway test engine, the worker was \
                 likely re-pointed by a changed c8ctl active profile — check the pinned \
                 connection in supervisor.json (issue #41)",
                self.engine_desc.as_deref().unwrap_or("the engine"),
                self.test_type_prefixes
            ));
        }
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

    pub async fn activate(
        &self,
        job_type: &str,
        worker: &str,
        timeout: Duration,
        poll: Duration,
        with_lease: bool,
    ) -> Result<Vec<Job>> {
        self.activate_for(job_type, worker, timeout, poll, with_lease)
            .await
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
    use super::{all_test_looking, warn_sanity_decision};
    use super::{sdk_error, status_of};
    use std::sync::atomic::AtomicBool;

    #[test]
    fn all_test_looking_classifies_prefix_sets() {
        // Empty matrix is never "all test-looking" (a plain worker, no types).
        assert!(!all_test_looking(&[]));
        // A pure test fleet (`ct-*` / `probe-*`) matches.
        assert!(all_test_looking(&["ct-foo".into(), "probe-bar".into()]));
        // A single production type anywhere in the matrix disqualifies it.
        assert!(!all_test_looking(&[
            "ct-foo".into(),
            "senior:feature".into()
        ]));
        assert!(!all_test_looking(&["senior".into()]));
    }

    #[test]
    fn warn_sanity_decision_is_one_shot_and_gated() {
        // No jobs → never warn, and the latch stays untripped so a later live
        // answer can still warn.
        let latch = AtomicBool::new(false);
        assert!(!warn_sanity_decision(false, true, &latch));
        assert!(!latch.load(std::sync::atomic::Ordering::Relaxed));

        // Jobs but not a test-looking engine → never warn, latch untouched.
        assert!(!warn_sanity_decision(true, false, &latch));
        assert!(!latch.load(std::sync::atomic::Ordering::Relaxed));

        // Jobs on a test-looking engine → warn exactly once, then latched off.
        assert!(warn_sanity_decision(true, true, &latch));
        assert!(!warn_sanity_decision(true, true, &latch));
        assert!(!warn_sanity_decision(true, true, &latch));
    }

    /// Issue #41, the mixed-hire gap: the sanity guard must judge each SLOT's
    /// own job-type matrix, not the daemon-wide aggregate. A daemon running one
    /// normal hire and one `ct-*`-only hire has a non-test-looking AGGREGATE,
    /// but the slot serving only `ct-*` must still warn. `for_slot` gives each
    /// slot its own matrix and warn-once latch while sharing the client.
    #[test]
    fn for_slot_judges_the_slots_own_matrix_with_a_fresh_latch() {
        let client = camunda_orchestration_sdk::CamundaClient::new(
            camunda_orchestration_sdk::CamundaOptions::new(),
        )
        .expect("a default client builds");
        // The shared daemon client carries the AGGREGATE matrix: a normal type
        // plus a test type, so the aggregate is NOT all-test-looking.
        let shared = super::Jobs::new(client).with_identity(
            "engine: test (http://engine:8080)".to_string(),
            vec!["senior".into(), "ct-smoke".into()],
        );
        assert!(
            !shared.looks_like_test_engine(),
            "the aggregate matrix (senior + ct-*) is not all-test-looking"
        );

        // Deriving the ct-*-only slot's view judges THAT slot's matrix…
        let ct_slot = shared.for_slot(vec!["ct-smoke".into()]);
        assert!(
            ct_slot.looks_like_test_engine(),
            "the ct-*-only slot must be judged test-looking on its own matrix"
        );
        // …with a FRESH latch, independent of the shared one and of a sibling
        // slot's latch.
        let normal_slot = shared.for_slot(vec!["senior".into()]);
        assert!(!normal_slot.looks_like_test_engine());
        assert!(
            ct_slot.should_warn_sanity(true),
            "first live activation warns"
        );
        assert!(
            !ct_slot.should_warn_sanity(true),
            "the ct slot's latch is one-shot"
        );
        assert!(
            !shared
                .sanity_warned
                .load(std::sync::atomic::Ordering::Relaxed),
            "the shared latch is untouched by the slot's latch"
        );
        assert!(
            !normal_slot.should_warn_sanity(true),
            "the normal slot never warns (its matrix is not test-looking)"
        );
    }
    use super::lease_anchor;
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

    #[test]
    fn lease_anchor_bounds_overrun_under_positive_engine_clock_skew() {
        // Positive engine-clock skew — the engine's wall clock runs AHEAD of the
        // worker's — understates `dispatch_ago` (it can even saturate to zero),
        // so the wall-clock reconciliation places the anchor slightly later than
        // the true dispatch. The `decoded_at` clamp bounds that residual: the
        // refresher deadline can exceed the true server-side expiry by at most
        // the response transit (dispatch -> decode), never by the full skew.
        //
        // Clamping the anchor to a monotonic instant captured BEFORE
        // `activate_jobs` (the fix the reviewer proposed) is NOT a safe
        // tightening here: that call long-polls for up to `poll_timeout`, so a
        // legitimately-later dispatch is indistinguishable from skew and the
        // clamp would drag the anchor back by the whole poll wait, fencing
        // still-valid leases up to a full poll early. The `min(REQUEST_MARGIN,
        // window/2)` reserve in `refresh_budget` already absorbs this
        // transit-bounded residual, so the fence still fires before real expiry.
        let window = Duration::from_secs(300);
        let transit = Duration::from_secs(2); // dispatch -> decode gap
        for skew in [Duration::from_secs(1), Duration::from_secs(5)] {
            let decoded_at = Instant::now();
            let wall_now = SystemTime::now();
            // Engine is `skew` AHEAD: it stamped the deadline from a clock
            // reading `skew` larger than ours, dispatching `transit` ago, so
            // `deadline = (wall_now + skew) + (window - transit)`.
            let deadline_wall = wall_now + skew + window - transit;
            let deadline_ms = deadline_wall
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;
            let anchor = lease_anchor(deadline_ms, window, decoded_at, wall_now);
            let deadline = anchor + window;
            // True server-side expiry in the monotonic frame is
            // `true_dispatch + window = (decoded_at - transit) + window`.
            let true_expiry = decoded_at + window - transit;
            // Reconciliation pulls the anchor back by `transit - skew` (saturating
            // at zero when `skew >= transit`), so the deadline overruns the true
            // server-side expiry by EXACTLY `min(skew, transit)` — never the full
            // `window`-scale skew. Asserting the exact residual (not just an upper
            // bound the `anchor <= decoded_at` clamp already guarantees) makes this
            // a real regression test: a no-op anchor that ignored reconciliation
            // and returned `decoded_at` would overrun by the full `transit` even
            // for `skew = 1s`, failing the `skew < transit` case below.
            let tol = Duration::from_millis(50);
            let expected_overrun = skew.min(transit);
            let overrun = deadline.saturating_duration_since(true_expiry);
            assert!(
                overrun <= expected_overrun + tol,
                "positive skew {skew:?}: overrun {overrun:?} exceeds the \
                 reconciled residual {expected_overrun:?}"
            );
            assert!(
                overrun + tol >= expected_overrun,
                "positive skew {skew:?}: overrun {overrun:?} falls short of the \
                 reconciled residual {expected_overrun:?} — anchor was not pulled \
                 back by reconciliation"
            );
            // LOWER bound: when `skew < transit` the reconciliation pulls the
            // anchor strictly earlier than the decode instant, so the deadline
            // lands strictly before the naive decode-anchor bound. This fails
            // against a no-op `return decoded_at`, proving the test exercises the
            // wall-clock reconciliation rather than only the `anchor <= decoded_at`
            // clamp.
            if skew < transit {
                assert!(
                    deadline + tol < decoded_at + window,
                    "positive skew {skew:?}: reconciliation should pull the \
                     deadline strictly before the decode-anchor bound"
                );
            }
        }
    }
}
