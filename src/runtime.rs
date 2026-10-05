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
///
/// This is only the *ceiling*: the loop bounds each attempt by the lease time
/// actually remaining (`extend_timeout`), because a FIXED 30s timeout is unsafe
/// on a short recovery window. The CLI floor is 1s (`MIN_RECOVERY_WINDOW`), so a
/// 60s window refreshes every 20s; a single stalled extend starting near the
/// deadline could otherwise run the full 30s past it — and a tolerated second
/// attempt another 30s — publishing `lost` long after the lease expired while
/// the job still ran on a dead activation. Clamping each attempt to
/// `deadline - now` keeps the fence at or before the deadline on every window.
const EXTEND_TIMEOUT: Duration = Duration::from_secs(30);

/// The lease time `refresh_budget` reserves for the extend request that
/// follows the sleep: the request's whole bounded lifetime (`EXTEND_TIMEOUT`)
/// plus slack for scheduling and the response body. A retry that merely
/// STARTS before the deadline but can still be in flight when the lease
/// expires loses the in-flight work it was protecting, so the reserve must
/// cover the request's maximum latency, not just its dispatch.
const REQUEST_MARGIN: Duration = EXTEND_TIMEOUT.saturating_add(Duration::from_secs(2));

/// The activation-failure backoff for a streak of `failures` consecutive
/// failures (1 = the first), with equal jitter: `cap/2 + random(0, cap/2)`
/// where `cap = min(max, base * 2^(failures-1))`. Equal jitter spreads a
/// fleet's retries across the upper half of the window so N slots started
/// together do not reconnect in lockstep (a thundering herd on a gateway that
/// has just come back), while its NONZERO floor (`cap/2`) bounds the aggregate
/// retry rate no matter how the draws fall. Full jitter (`random(0, cap)`) was
/// rejected: it permits an unbounded run of near-zero delays, which would let a
/// fleet hammer a recovering gateway far faster than the advertised ~one
/// attempt per `cap` and weaken the storm guard behind nanobpm/nano-supervisor#23.
pub(crate) fn activation_backoff(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(20);
    let exp = ACTIVATION_BACKOFF_BASE.saturating_mul(1u32 << shift);
    let capped = exp.min(ACTIVATION_BACKOFF_MAX);
    equal_jitter(capped)
}

/// Equal-jitter delay in `[cap/2, cap)`: a fixed `cap/2` floor plus a random
/// share of the remaining half. The floor is the point — unlike full jitter
/// (`random(0, cap)`, whose draws can collapse arbitrarily close to zero any
/// number of times in a row), equal jitter guarantees every slot waits at least
/// `cap/2`, so a 16-slot fleet cannot probe a recovering gateway faster than
/// ~one attempt per `cap/2` per slot. That is what bounds the aggregate retry
/// rate (the TCP-`TIME_WAIT` storm guard behind nanobpm/nano-supervisor#23),
/// while the random upper half still de-synchronises slots started in the same
/// tick so they do not reconnect in lockstep. Jitter only (load spreading), not
/// security. `cap/2` rounds down, so a sub-millisecond `cap` floors at zero —
/// harmless, since such a `cap` is already below any meaningful cadence.
fn equal_jitter(cap: Duration) -> Duration {
    let half = cap / 2;
    let span = (half.as_millis() as u64 as f64 * rand_fraction()) as u64;
    half.saturating_add(Duration::from_millis(span))
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
/// exponentially from `every` (equal jitter, `cap/2 + random(0, cap/2)`) so a
/// DOWN engine is not re-probed at the refresh cadence and the per-slot delay
/// never collapses toward zero. But the delay is then capped to what is actually left on
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
        equal_jitter(capped)
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
        // The cadence fallback must still NOT outlive the lease. `wait` is sized
        // from the FULL window, so on a short lease near its deadline it can
        // exceed the time actually left — e.g. a 10s window whose first extend
        // fails at t=9s has only ~1s left, but a 3.3–6.6s jittered cadence would
        // push the retry (and the `failures >= 2` `lost` fence) several seconds
        // past expiry, leaving the job running unfenced on a dead activation.
        // Avoiding a zero sleep does not require the full cadence: cap the
        // fallback to the lease time REMAINING so the retry starts before the
        // deadline and the fence publishes at or before it. Floor at 1ms so a
        // lease with a sliver of time left still yields (never a zero-length
        // busy-spin); the attempt itself is bounded by `extend_timeout`, which
        // clamps to the same remaining lease.
        Some(wait.min(left).max(Duration::from_millis(1)))
    }
}

/// The timeout for a single lease-`extend` request: the `EXTEND_TIMEOUT` ceiling,
/// but never longer than the lease time actually remaining (`deadline - now`).
///
/// A FIXED timeout is unsafe on short recovery windows. `refresh_budget` sizes
/// the *sleep* so a retry starts early enough, but once the extend is in flight
/// only its own timeout bounds it — and a fixed 30s ceiling can outlast the whole
/// remaining lease (e.g. a 60s window whose first extend stalls near t=40 would
/// run to t=70, 10s past expiry, before the `failures >= 2` fence fires; a
/// tolerated second attempt would push `lost` another 30s out). Clamping each
/// attempt to what the lease has left means a stalled extend is abandoned no
/// later than the deadline, so the fence publishes before — not up to
/// `EXTEND_TIMEOUT` after — the lease lapses. Both tolerated attempts together
/// therefore cannot push `lost` past the deadline.
///
/// Floored at 1ms so the final fence attempt on an already-expired lease still
/// ISSUES its request (and can observe a real 404/409) rather than being
/// abandoned before it starts. Pure and testable.
fn extend_timeout(now: Instant, deadline: Instant) -> Duration {
    EXTEND_TIMEOUT
        .min(deadline.saturating_duration_since(now))
        .max(Duration::from_millis(1))
}

#[allow(
    clippy::too_many_arguments,
    reason = "a per-job refresher legitimately needs the client, job key, lease, window, \
              activation instant, success counter, and two watch channels; bundling them into \
              a one-shot struct would only move the same fields behind an indirection"
)]
pub(crate) async fn refresh_loop(
    jobs: Jobs,
    key: String,
    lease: Option<String>,
    window: Duration,
    // The instant the activation response was received by the caller (captured
    // in `handle` BEFORE validation/logging/spawn). The lease runs `window` from
    // when the engine dispatched the job, i.e. essentially when that response was
    // produced — NOT from the later instant this task starts executing. Basing
    // the initial deadline on `Instant::now()` here would grant a full fresh
    // window measured from an instant already past dispatch, over-granting by the
    // post-response scheduling gap and letting the refresher run past the
    // server-side lease. Take the caller's earlier timestamp instead.
    activated_at: Instant,
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
    // for `window` as of `activated_at` (the activation response), so start
    // there; each successful extend pushes it out by another `window` measured
    // from when THAT extend was SENT (see below). Capping the retry sleep against
    // THIS deadline (not the full window) is what keeps a retry from landing
    // after the activation has already expired (see `refresh_budget`).
    let mut deadline = activated_at + window;
    loop {
        // After a transient failure, wait longer than the steady-state cadence
        // before retrying: an engine that is DOWN (connection refused — the
        // common case once a refresh has failed) must not be re-probed at the
        // refresh cadence, or a fleet of long-running jobs would churn TCP
        // connections into `TIME_WAIT` exactly like an activation storm
        // (nanobpm/nano-supervisor#23). Back off exponentially from the cadence
        // (with equal jitter — a nonzero `cap/2` floor, so the per-slot retry
        // rate stays bounded) — but cap the sleep to the lease time REMAINING,
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
        // It IS, however, bounded — by `extend_timeout`, which is the
        // `EXTEND_TIMEOUT` ceiling clamped to the lease time still REMAINING.
        // The HTTP client carries no per-request timeout, so an extend to a
        // stalled (not refused) engine would otherwise hang for the kernel's
        // whole TCP retransmit window — long past the lease deadline — with the
        // job still running on a dead activation. Bounding by the ceiling lets
        // `refresh_budget`'s reserve guarantee a retry FINISHES before the
        // deadline rather than merely starting; bounding ALSO by the remaining
        // lease guarantees it even on a short recovery window the fixed ceiling
        // would overrun (a 30s timeout cannot outlast a 20s-remaining lease).
        // Dropping the request future at the timeout cancels it like any other
        // dropped in-flight call; the resulting error is transient (never a
        // 404/409), so the `failures >= 2` fence below still applies — and
        // because the attempt is clamped to the lease, that fence is published
        // at or before the deadline, never up to `EXTEND_TIMEOUT` past it.
        let sent_at = Instant::now();
        let attempt_timeout = extend_timeout(sent_at, deadline);
        let extended = tokio::time::timeout(attempt_timeout, jobs.extend(&key, window, &lease))
            .await
            .unwrap_or_else(|_| {
                Err(anyhow::anyhow!(
                    "extend request exceeded its {attempt_timeout:?} lease-bounded budget \
                     (ceiling {EXTEND_TIMEOUT:?})"
                ))
            });
        match extended {
            Ok(()) => {
                failures = 0;
                count.fetch_add(1, Ordering::Relaxed);
                // The extend succeeded, so the lease now runs another full
                // `window` — but measured from when the engine received this
                // extend, not from now. Base the new deadline on `sent_at`
                // (captured BEFORE the request) rather than `Instant::now()`:
                // a slow extend response otherwise resets the deadline a full
                // window past the response, over-granting by the round-trip and
                // letting the refresher and agent run past the server-side lease.
                // Resetting here (vs. only on the first success) still ensures a
                // transient timeout earlier in the streak cannot lose in-flight
                // work, now without the over-grant.
                deadline = sent_at + window;
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
        activation_backoff, extend_timeout, refresh_budget, ACTIVATION_BACKOFF_MAX, EXTEND_TIMEOUT,
        REQUEST_MARGIN,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn extend_timeout_never_outlasts_the_remaining_lease() {
        let now = Instant::now();

        // Ample lease: the full ceiling, so a healthy extend is unaffected.
        assert_eq!(
            extend_timeout(now, now + Duration::from_secs(300)),
            EXTEND_TIMEOUT,
            "an ample lease must allow the full extend ceiling"
        );

        // Short recovery window: the attempt is clamped to the lease time left,
        // so a stalled extend is abandoned no later than the deadline and the
        // `failures >= 2` fence publishes `lost` before the lease lapses — the
        // regression the reviewer flagged (a fixed 30s timeout outliving a short
        // window). The attempt must never reach past the deadline.
        for &secs in &[1u64, 5, 10, 20, 29] {
            let deadline = now + Duration::from_secs(secs);
            let t = extend_timeout(now, deadline);
            assert!(
                now + t <= deadline,
                "a {secs}s-remaining lease must bound the extend to at most that (got {t:?})"
            );
            assert_eq!(t, Duration::from_secs(secs));
        }

        // The ceiling still caps a huge remaining lease (a stalled extend must
        // not hang for the kernel's whole retransmit window).
        assert_eq!(
            extend_timeout(now, now + Duration::from_secs(10_000)),
            EXTEND_TIMEOUT
        );

        // At or past the deadline, the final fence attempt still ISSUES its
        // request (positive floor) rather than being abandoned before it starts —
        // so it can still observe a real 404/409 — while not sleeping into a
        // request that outlives the lease.
        assert_eq!(extend_timeout(now, now), Duration::from_millis(1));
        assert_eq!(
            extend_timeout(now, now - Duration::from_secs(10)),
            Duration::from_millis(1),
            "an already-expired lease must still issue a bounded final fence attempt"
        );
    }

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
        // Equal jitter over a growing window: the first-failure delay is drawn
        // from `[cap/2, cap)` = `[0.5s, 1s)`, so it still sometimes lands below
        // the 1s base, and the ceiling-reached delays must vary rather than
        // pinning to one value.
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
        // The storm-guard invariant: equal jitter keeps a NONZERO floor of
        // `cap/2`, so no run of unlucky draws can collapse the reconnect rate
        // toward zero (which full jitter permitted). Every draw must sit at or
        // above `cap/2` for both the first-failure cap (1s -> 0.5s floor) and
        // the ceiling-reached cap (30s -> 15s floor).
        for _ in 0..512 {
            assert!(
                activation_backoff(1) >= Duration::from_millis(500),
                "first-failure backoff fell below the cap/2 floor"
            );
            assert!(
                activation_backoff(50) >= ACTIVATION_BACKOFF_MAX / 2,
                "ceiling backoff fell below the cap/2 floor"
            );
        }
    }

    #[test]
    fn refresh_budget_backoff_keeps_a_nonzero_floor() {
        // The failure-path sleep must also keep the equal-jitter floor (`cap/2`)
        // when the lease has ample time left, so a fleet retrying a DOWN engine
        // cannot reconnect in an unbounded near-zero storm
        // (nanobpm/nano-supervisor#23). With `every = 100s` and `failures = 1`
        // the cap is `min(every*2, window) = 200s`, so the floor is `100s`; the
        // 300s lease (268s budget after the reserve) never clamps below it.
        let every = Duration::from_secs(100);
        let window = Duration::from_secs(300);
        let now = Instant::now();
        let deadline = now + window;
        for _ in 0..512 {
            let w = refresh_budget(now, deadline, every, window, 1)
                .expect("an ample lease yields a budget");
            assert!(
                w >= every,
                "failure backoff {w:?} fell below the cap/2 floor"
            );
        }
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
    fn refresh_budget_sub_reserve_fallback_is_capped_by_the_remaining_lease() {
        // Regression: the sub-reserve cadence fallback must NOT outlive the
        // lease. `wait` is sized from the FULL window, so on a short lease near
        // its deadline it exceeds the time actually left. With a 10s window
        // (`every` = 3.3s) whose first extend fails at t=9s, only ~1s remains;
        // the uncapped 3.3–6.6s cadence would push the retry — and the
        // `failures >= 2` `lost` fence — several seconds past expiry, leaving
        // the job running unfenced on a dead activation. The fallback must cap
        // to the remaining lease so the retry starts before the deadline and
        // the fence publishes at or before it.
        let window = Duration::from_secs(10);
        assert!(window <= REQUEST_MARGIN, "test premise: sub-reserve window");
        let every = (window / 3).max(Duration::from_millis(1));
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1); // ~1s left, as at t=9s
        for failures in [0u32, 1, 2, 5] {
            let w = refresh_budget(now, deadline, every, window, failures)
                .expect("a sub-reserve window still yields a (capped) sleep, not None");
            assert!(
                now + w <= deadline,
                "the sub-reserve fallback {w:?} (failures={failures}) must not sleep past the \
                 lease deadline — the retry and lost fence must land before expiry"
            );
        }

        // A sliver of time left still yields (never a zero-length busy-spin):
        // the 1ms floor keeps the loop from spinning while staying inside the lease.
        let now = Instant::now();
        let deadline = now + Duration::from_millis(1);
        let w = refresh_budget(now, deadline, every, window, 1)
            .expect("a sub-reserve window with a sliver left must still yield, not spin");
        assert!(!w.is_zero(), "a sliver of lease left must not busy-spin");
        assert!(now + w <= deadline, "the floor must stay within the lease");
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
