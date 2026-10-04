//! Shared worker runtime helpers: timestamped logging and the activation
//! lease-refresh loop used by every job slot (`work` and `daemon`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::jobs::Jobs;

/// First activation-failure delay. Small enough that a single transient error
/// barely slows pickup, large enough that a down engine is not hammered.
const ACTIVATION_BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Ceiling for the activation-failure backoff: an idle slot polls a DOWN engine
/// at most ~once per 30s (plus the SDK's own bounded in-call retries), so a
/// 16-slot fleet cannot churn the host's ephemeral TCP ports into `TIME_WAIT`
/// while the gateway is unreachable (the incident behind nanobpm/nano-supervisor#23).
const ACTIVATION_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// The activation-failure backoff for a streak of `failures` consecutive
/// failures (1 = the first), with full jitter: `random(0, min(max, base *
/// 2^(failures-1)))`. Full jitter spreads a fleet's retries across the whole
/// window so N slots started together do not reconnect in lockstep (a
/// thundering herd on a gateway that has just come back), and the bound keeps
/// the aggregate retry rate low no matter how long the outage lasts.
pub(crate) fn activation_backoff(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(20);
    let exp = ACTIVATION_BACKOFF_BASE.saturating_mul(1u32 << shift);
    let capped = exp.min(ACTIVATION_BACKOFF_MAX);
    Duration::from_millis((capped.as_millis() as u64 as f64 * rand_fraction()) as u64)
}

/// A small, dependency-free pseudo-random fraction in `[0, 1)`, used only for
/// backoff jitter (load spreading, not security). Seeded per thread from the
/// wall clock and this process's id so two slots started in the same tick do
/// not draw the same sequence.
fn rand_fraction() -> f64 {
    use std::cell::Cell;
    thread_local! {
        static RNG_STATE: Cell<u64> = Cell::new({
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9e37_79b9_7f4a_7c15);
            // Mix in the pid, then force the state odd/non-zero (xorshift
            // degenerates at 0).
            (nanos ^ ((std::process::id() as u64) << 32)) | 1
        });
    }
    RNG_STATE.with(|state| {
        let mut x = state.get();
        // xorshift64
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.set(x);
        // Top 53 bits -> [0, 1).
        ((x >> 11) as f64) / ((1u64 << 53) as f64)
    })
}

pub(crate) async fn refresh_loop(
    jobs: Jobs,
    key: String,
    lease: Option<String>,
    window: Duration,
    count: Arc<AtomicUsize>,
    lost: watch::Sender<bool>,
    mut stop: watch::Receiver<bool>,
) {
    // Refresh at a third of the window, but never a zero-length interval: a
    // sub-3ms window divides to `Duration::ZERO`, which would spin this loop and
    // hammer the engine (saturating a Tokio worker). Floor it at a positive
    // minimum so the loop always yields between extends.
    let every = (window / 3).max(Duration::from_millis(1));
    let mut failures = 0u32;
    loop {
        // After a transient failure, wait longer than the steady-state cadence
        // before retrying: an engine that is DOWN (connection refused — the
        // common case once a refresh has failed) must not be re-probed at the
        // refresh cadence, or a fleet of long-running jobs would churn TCP
        // connections into `TIME_WAIT` exactly like an activation storm
        // (nanobpm/nano-supervisor#23). Back off exponentially from the cadence
        // (with full jitter), bounded by the window itself so the second attempt
        // still lands inside the activation's remaining lifetime — the
        // `failures >= 2` give-up below then fences the job rather than letting
        // it expire silently.
        let wait = if failures == 0 {
            every
        } else {
            let exp = every.saturating_mul(1u32 << failures.min(20));
            let capped = exp.min(window.max(every));
            Duration::from_millis((capped.as_millis() as u64 as f64 * rand_fraction()) as u64)
        };
        tokio::select! {
            // A stop request during the idle interval ends the loop at once:
            // there is no in-flight extend to lose, so the loss watch already
            // holds its final value.
            _ = stop.changed() => return,
            _ = tokio::time::sleep(wait) => {}
        }
        // Honour a stop that landed exactly as the interval elapsed before
        // issuing another extend.
        if *stop.borrow() {
            return;
        }
        // Deliberately NOT wrapped in a cancellable select against `stop`: the
        // caller stops us by signalling `stop` and awaiting our JoinHandle (never
        // `abort()`), so an in-flight extend always runs to completion and
        // publishes a 404/409 fence on `lost` before we return. Cancelling
        // mid-extend would drop the very request that detects the fence, letting
        // the caller settle a job whose activation was already revoked.
        match jobs.extend(&key, window, &lease).await {
            Ok(()) => {
                failures = 0;
                count.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                let msg = format!("{e:#}");
                failures += 1;
                log(&format!("job {key}: refresh failed ({failures}): {msg}"));
                // 404 = gone, 409 = superseded by a newer (leased) activation: stop
                // now. Otherwise tolerate one transient error before giving up.
                // Read the STRUCTURED status off the error chain, never the bare
                // digits: the SDK interpolates `/jobs/{key}` into the request
                // path, so a numeric job key that merely CONTAINS "404"/"409"
                // would otherwise misclassify a transient refresh error as a
                // lease fence and abandon a live activation.
                if matches!(crate::jobs::status_of(&e), Some(404 | 409)) || failures >= 2 {
                    let _ = lost.send(true);
                    return;
                }
            }
        }
        // A stop that arrived while this extend was in flight: we have now
        // published its result (success or fence) on the watch, so it is safe to
        // exit.
        if *stop.borrow() {
            return;
        }
    }
}

pub fn log(msg: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    eprintln!("[{now:.3}] {msg}");
}

#[cfg(test)]
mod tests {
    use crate::jobs::status_of;
    use crate::runtime::{activation_backoff, ACTIVATION_BACKOFF_MAX};

    #[test]
    fn activation_backoff_is_bounded_and_jittered() {
        // Unbounded growth would eventually exceed the ceiling; the cap must
        // hold even after a very long outage (no overflow, no spin at zero).
        for failures in [1, 2, 3, 5, 10, 100, u32::MAX] {
            for _ in 0..64 {
                let d = activation_backoff(failures);
                assert!(
                    d <= ACTIVATION_BACKOFF_MAX,
                    "backoff {d:?} exceeds the {ACTIVATION_BACKOFF_MAX:?} ceiling (failures={failures})"
                );
            }
        }
        // Full jitter over a growing window: the first-failure delay must
        // sometimes land below the 1s base (it is random(0, base)), and the
        // ceiling-reached delays must vary rather than pinning to one value.
        let mut saw_sub_base = false;
        let mut capped = std::collections::HashSet::new();
        for _ in 0..256 {
            let first = activation_backoff(1);
            saw_sub_base |= first < std::time::Duration::from_secs(1);
            capped.insert(activation_backoff(50).as_millis());
        }
        assert!(saw_sub_base, "jitter never produced a sub-base delay");
        assert!(
            capped.len() > 1,
            "capped backoff must be jittered, not a fixed delay"
        );
    }

    #[test]
    fn fence_status_comes_from_the_chain_not_bare_digits() {
        // Real fence responses flatten to an `HTTP 404 ` / `HTTP 409 ` marker
        // re-wrapped with the `/jobs/{key}` path context.
        let not_found = anyhow::anyhow!("HTTP 404 Not Found").context("/jobs/2251799813685250");
        assert_eq!(status_of(&not_found), Some(404));
        let conflict = anyhow::anyhow!("HTTP 409 Conflict").context("/jobs/2251799813685250");
        assert_eq!(status_of(&conflict), Some(409));
        // A transient failure whose numeric job key merely CONTAINS the fence
        // digits must NOT stop the loop after the first error.
        let key_has_404 = anyhow::anyhow!("connection reset").context("/jobs/14041234567890");
        assert_eq!(status_of(&key_has_404), None);
        let key_is_9409 = anyhow::anyhow!("timeout").context("/jobs/9409");
        assert_eq!(status_of(&key_is_9409), None);
        // A non-fence HTTP status is reported but is not 404/409.
        let server_error = anyhow::anyhow!("HTTP 500 Internal Server Error").context("/jobs/123");
        assert_eq!(status_of(&server_error), Some(500));
        // A transport failure carries no status at all.
        let transport = anyhow::anyhow!("/jobs/404: request failed: connection refused");
        assert_eq!(status_of(&transport), None);
    }
}
