//! Shared worker runtime helpers: timestamped logging and the activation
//! lease-refresh loop used by every job slot (`work` and `daemon`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// The hard ceiling on one lease-`extend` request. The tuned reqwest client
/// carries no per-request timeout, so without this an extend to a stalled
/// (not refused) engine can hang for the kernel's whole TCP retransmit
/// window — far past the lease deadline — while the job keeps running on a
/// dead activation. Bounding the request is what makes the reserve in
/// `refresh_budget` meaningful: `REQUEST_MARGIN` is sized from THIS bound, so
/// a retry that starts before the deadline also FINISHES (or is abandoned)
/// before it. A timeout surfaces as a transient error (never a 404/409), so
/// the caller's `failures >= 2` fence still applies.
const EXTEND_TIMEOUT: Duration = Duration::from_secs(30);

/// The lease time `refresh_budget` reserves for the extend request that
/// follows the sleep: the request's whole bounded lifetime (`EXTEND_TIMEOUT`)
/// plus slack for scheduling and the response body. A retry that merely
/// STARTS before the deadline but can still be in flight when the lease
/// expires loses the in-flight work it was protecting, so the reserve must
/// cover the request's maximum latency, not just its dispatch.
const REQUEST_MARGIN: Duration = EXTEND_TIMEOUT.saturating_add(Duration::from_secs(2));

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

/// The sleep before the next lease-refresh attempt, capped by the lease time
/// *remaining* — never by the full window.
///
/// `failures` is the consecutive-failure streak (0 = the healthy steady state,
/// which waits the `every` cadence). On a failure the loop backs off
/// exponentially from `every` (full jitter) so a DOWN engine is not re-probed at
/// the refresh cadence. But the delay is then capped to what is actually left on
/// the lease (`deadline - now`), less a margin to issue the request: an extend
/// that fails after a long (e.g. 30s) timeout has already burned lease time, so
/// a delay sized from the FULL window could push the retry past the activation's
/// expiry and lose in-flight work. Capping to the remaining budget keeps the
/// retry inside the lease; the caller fences (via the `failures >= 2` give-up)
/// once the budget is exhausted rather than letting the activation lapse
/// silently. The deadline is reset by the caller after each successful extend.
///
/// The reserve (`REQUEST_MARGIN`) covers the request's WHOLE bounded lifetime
/// (`EXTEND_TIMEOUT` plus slack): the sleep is clamped so the retry that
/// follows it can finish — not merely start — before the deadline. A lease
/// with less than the reserve left yields no budget.
///
/// Returns `None` only when a normally-sized lease (`window > REQUEST_MARGIN`)
/// has effectively expired — the caller then makes one last immediate attempt,
/// whose 404/409 fences the job. A lease whose whole `window` is no larger than
/// the reserve can never satisfy it, so rather than returning `None` (which the
/// caller would busy-spin on), it falls back to the steady refresh cadence.
/// Pure and testable.
fn refresh_budget(
    now: Instant,
    deadline: Instant,
    every: Duration,
    window: Duration,
    failures: u32,
) -> Option<Duration> {
    let wait = if failures == 0 {
        every
    } else {
        let exp = every.saturating_mul(1u32 << failures.min(20));
        let capped = exp.min(window.max(every));
        Duration::from_millis((capped.as_millis() as u64 as f64 * rand_fraction()) as u64)
    };
    // The lease time left after `now`. `None` here means the deadline has
    // already passed: the lease is genuinely expired, so the caller should make
    // one last immediate attempt (whose 404/409 fences the job).
    let left = deadline.checked_duration_since(now)?;
    // The lease time left, less the reserve for the request that follows this
    // sleep: an extend can take up to `EXTEND_TIMEOUT` to finish (or be
    // abandoned), so the retry must START at least that far ahead of the
    // deadline to have finished — not merely started — before it. A *positive*
    // budget is required: a zero budget (`left == REQUEST_MARGIN` exactly) would
    // clamp the sleep to zero and spin, so it is routed through the same
    // reserve-exceeded handling below as an underflow.
    if let Some(budget) = left.checked_sub(REQUEST_MARGIN) {
        if !budget.is_zero() {
            return Some(wait.min(budget));
        }
    }
    // The reserve meets or exceeds the lease time left. Two very different
    // situations reach here, and they must NOT be conflated:
    //
    //   * A normally-sized lease (`window > REQUEST_MARGIN`) genuinely near its
    //     deadline — most of its window is already spent. Return `None` so the
    //     caller makes one last immediate attempt before the lease lapses.
    //
    //   * A lease whose WHOLE window is no larger than the reserve
    //     (`window <= REQUEST_MARGIN`, e.g. a user-set `--recovery-window` below
    //     ~32s). Here the reserve can NEVER be satisfied — even a freshly
    //     extended lease (`deadline ≈ now + window`) underflows on every
    //     iteration. Returning `None` would map to a zero sleep and busy-spin
    //     the refresh loop, hammering the engine back-to-back with extends
    //     (the exact nanobpm/nano-supervisor#23 behaviour the cadence floor
    //     exists to prevent). For such a window the reserve is meaningless, so
    //     fall back to the steady refresh cadence (`wait`, floored at `every`)
    //     rather than spinning: extend at `window / 3` and accept that a slow
    //     extend on a sub-reserve lease may miss — which no sleep policy can
    //     prevent once the window is smaller than one request's bounded lifetime.
    if window > REQUEST_MARGIN {
        None
    } else {
        Some(wait)
    }
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
    // The absolute instant the current lease expires. The activation was granted
    // for `window` when this loop was spawned, so start there; each successful
    // extend pushes it out by another `window`. Capping the retry sleep against
    // THIS deadline (not the full window) is what keeps a retry from landing
    // after the activation has already expired (see `refresh_budget`).
    let mut deadline = Instant::now() + window;
    loop {
        // After a transient failure, wait longer than the steady-state cadence
        // before retrying: an engine that is DOWN (connection refused — the
        // common case once a refresh has failed) must not be re-probed at the
        // refresh cadence, or a fleet of long-running jobs would churn TCP
        // connections into `TIME_WAIT` exactly like an activation storm
        // (nanobpm/nano-supervisor#23). Back off exponentially from the cadence
        // (with full jitter) — but cap the sleep to the lease time REMAINING,
        // not the full window: an extend that fails after a long timeout has
        // already burned lease time, so a window-sized delay could push the
        // retry past expiry and lose in-flight work. `refresh_budget` returns
        // `None` once the lease is effectively up; we then make one last
        // immediate attempt whose 404/409 fences the job (the `failures >= 2`
        // give-up below) rather than letting it expire silently.
        let wait = match refresh_budget(Instant::now(), deadline, every, window, failures) {
            Some(w) => w,
            None => Duration::ZERO,
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
        //
        // It IS, however, bounded by `EXTEND_TIMEOUT`: the HTTP client carries
        // no per-request timeout, so an extend to a stalled (not refused)
        // engine would otherwise hang for the kernel's whole TCP retransmit
        // window — long past the lease deadline — with the job still running
        // on a dead activation. The timeout is what lets `refresh_budget`'s
        // reserve guarantee a retry FINISHES before the deadline rather than
        // merely starting before it. Dropping the request future at the
        // timeout cancels it like any other dropped in-flight call; the
        // resulting error is transient (never a 404/409), so the
        // `failures >= 2` fence below still applies — and because the sleep
        // was clamped to `deadline - REQUEST_MARGIN`, that fence is published
        // before the lease expires.
        let extended = tokio::time::timeout(EXTEND_TIMEOUT, jobs.extend(&key, window, &lease))
            .await
            .unwrap_or_else(|_| {
                Err(anyhow::anyhow!(
                    "extend request exceeded the {EXTEND_TIMEOUT:?} budget"
                ))
            });
        match extended {
            Ok(()) => {
                failures = 0;
                count.fetch_add(1, Ordering::Relaxed);
                // The extend succeeded, so the lease now runs another full
                // `window` from now: reset the absolute deadline so a transient
                // timeout earlier in the streak cannot lose in-flight work.
                deadline = Instant::now() + window;
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
    use crate::runtime::{
        activation_backoff, refresh_budget, ACTIVATION_BACKOFF_MAX, REQUEST_MARGIN,
    };
    use std::time::{Duration, Instant};

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
    fn refresh_budget_is_capped_by_remaining_lease_not_full_window() {
        let every = Duration::from_secs(100); // window / 3 for a 300s lease
        let window = Duration::from_secs(300);

        // Steady state (no failures): the cadence, uncapped, while the lease is fresh.
        let now = Instant::now();
        let deadline = now + window;
        assert_eq!(
            refresh_budget(now, deadline, every, window, 0),
            Some(every),
            "a healthy loop waits the steady-state cadence"
        );

        // The regression: late in the lease, a jittered window-sized delay would
        // land AFTER expiry. The budget must clamp the sleep to what remains
        // (less the request reserve), never the full window. 40s left > the 32s
        // reserve, so there IS a budget — but it must leave room for the retry's
        // whole bounded lifetime, not just its dispatch.
        let now = Instant::now();
        let deadline = now + Duration::from_secs(40);
        for failures in [1, 2, 5, 20] {
            let w = refresh_budget(now, deadline, every, window, failures)
                .expect("budget while the lease is still live");
            assert!(
                now + w + crate::runtime::EXTEND_TIMEOUT <= deadline,
                "retry sleep {w:?} (failures={failures}) leaves the extend no time to FINISH \
                 before the lease deadline"
            );
        }

        // A lease with less than the request reserve left has no budget for a
        // retry that could still finish in time: the caller makes one last
        // immediate attempt instead of sleeping into a request that outlives
        // the lease.
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        assert_eq!(
            refresh_budget(now, deadline, every, window, 1),
            None,
            "a lease with less than the extend reserve left has no usable refresh budget"
        );

        // A lease that has already expired yields no budget: the caller makes a
        // final immediate attempt instead of sleeping past the deadline.
        let now = Instant::now();
        let deadline = now - Duration::from_secs(1);
        assert_eq!(
            refresh_budget(now, deadline, every, window, 1),
            None,
            "an expired lease leaves no refresh budget"
        );
    }

    #[test]
    fn refresh_budget_does_not_busy_spin_a_sub_reserve_window() {
        // Regression (nanobpm/nano-supervisor#23): a user-set `--recovery-window`
        // smaller than the request reserve must NOT degenerate the refresh loop
        // into a back-to-back extend storm. `REQUEST_MARGIN` (~32s) exceeds the
        // whole window here, so `deadline - now` underflows the reserve on EVERY
        // iteration — including the healthy, freshly-extended steady state. The
        // old code returned `None` there, which the caller maps to a zero sleep
        // and busy-spins. The budget must instead fall back to the steady
        // cadence so the loop always yields between extends.
        for &secs in &[1u64, 5, 10, 20, 31] {
            let window = Duration::from_secs(secs);
            assert!(
                window <= REQUEST_MARGIN,
                "test premise: window must be within the reserve"
            );
            let every = (window / 3).max(Duration::from_millis(1));

            // Steady state right after a successful extend: deadline ≈ now + window.
            let now = Instant::now();
            let deadline = now + window;
            let w = refresh_budget(now, deadline, every, window, 0)
                .expect("a sub-reserve window must yield a cadence sleep, never None");
            assert_eq!(
                w, every,
                "a fresh sub-reserve lease ({secs}s) must wait the steady cadence, not spin"
            );
            assert!(
                !w.is_zero(),
                "a sub-reserve window ({secs}s) must never produce a zero-length (busy-spin) sleep"
            );

            // Under a failure streak the loop still yields a positive, bounded
            // backoff rather than spinning.
            for failures in [1u32, 2, 5, 20] {
                let w = refresh_budget(now, deadline, every, window, failures)
                    .expect("a sub-reserve window must never return None (busy-spin) on failures");
                assert!(
                    w <= window.max(every),
                    "backoff {w:?} (failures={failures}) must stay bounded by the window"
                );
            }
        }
    }

    #[test]
    fn refresh_budget_does_not_spin_at_the_reserve_boundary() {
        // Knife-edge: a window exactly equal to the reserve, and a lease whose
        // remaining time is exactly the reserve, both make `left - REQUEST_MARGIN`
        // zero. A zero budget must NOT clamp the sleep to zero (a busy-spin); the
        // sub-reserve window falls back to the cadence instead.
        let window = REQUEST_MARGIN;
        let every = (window / 3).max(Duration::from_millis(1));
        let now = Instant::now();
        let deadline = now + window; // left == REQUEST_MARGIN exactly
        let w = refresh_budget(now, deadline, every, window, 0)
            .expect("a reserve-sized window must yield a cadence sleep, not None");
        assert!(
            !w.is_zero(),
            "a window == reserve must not produce a zero-length (busy-spin) sleep"
        );
        assert_eq!(w, every, "a reserve-sized window waits the steady cadence");
    }

    #[test]
    fn refresh_budget_still_fences_a_normal_lease_near_expiry() {
        // A normally-sized lease (window > reserve) that is genuinely near its
        // deadline must still return `None` so the caller makes its final
        // immediate fence attempt — the sub-reserve fallback must not swallow
        // this path.
        let window = Duration::from_secs(300);
        let every = window / 3;
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5); // < REQUEST_MARGIN, but window >> reserve
        assert_eq!(
            refresh_budget(now, deadline, every, window, 1),
            None,
            "a large lease near expiry must still fence with a final immediate attempt"
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
