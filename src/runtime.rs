//! Shared worker runtime helpers: timestamped logging and the activation
//! lease-refresh loop used by every job slot (`work` and `daemon`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::jobs::Jobs;

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
    let mut failures = 0;
    loop {
        tokio::select! {
            // A stop request during the idle interval ends the loop at once:
            // there is no in-flight extend to lose, so the loss watch already
            // holds its final value.
            _ = stop.changed() => return,
            _ = tokio::time::sleep(every) => {}
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
                if msg.contains("404") || msg.contains("409") || failures >= 2 {
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
