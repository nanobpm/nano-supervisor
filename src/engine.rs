//! The shared engine connection. All of a daemon's slots service jobs through a
//! single [`crate::jobs::Jobs`] built once from the resolved c8ctl profile (or
//! `CAMUNDA_*` environment), so N slots share one SDK client / HTTP pool.

use anyhow::Result;

use crate::jobs::Jobs;
use crate::profile::{self, Profile};

/// Log which connection was picked and build the shared job client (the
/// `camunda-orchestration-sdk` transport — the same one the Node plugin uses)
/// from the **already-resolved** profile.
///
/// `resolved` is the profile `pin::resolve_or_pin` loaded for this start
/// ([`crate::pin::PinDecision::profile`]); it is passed in rather than
/// re-resolved so the client connects with the exact snapshot the pin recorded
/// and the startup banner reported. Re-reading `profiles.json` here would open
/// a window where a concurrent `c8 use profile` / profile edit between pinning
/// and connecting could point the client at a different URL or credentials than
/// the pin — defeating the whole guarantee of issue #41.
///
/// `engine_desc` is the pinned connection's `engine: <profile> (<baseUrl>)`
/// banner identity; `job_types` is the worker's served matrix, used by the
/// sanity guard that warns when a worker only serves test-looking
/// (`probe-*`/`ct-*`) types on a live engine. `pinned_base_url` is the env-only
/// pin's recorded baseUrl fingerprint: when the connection resolved to no
/// profile it is applied OVER the process environment, so a drifted
/// `CAMUNDA_REST_ADDRESS` cannot silently retarget a pinned worker — the pin
/// is enforced, not just recorded.
pub fn connect(
    resolved: Option<&Profile>,
    engine_desc: &str,
    job_types: &[String],
    pinned_base_url: Option<&str>,
) -> Result<Jobs> {
    match resolved {
        Some(p) => crate::runtime::log(&format!(
            "using c8ctl profile {:?} ({})",
            p.name,
            // Redact any embedded HTTP(S) userinfo before logging: the profile's
            // baseUrl may carry an engine credential, and this line lands on
            // stdout/journald. The un-redacted URL still drives the client.
            crate::slot::redact_url(p.base_url.as_deref().unwrap_or("no baseUrl"))
        )),
        None => crate::runtime::log("no c8ctl profile; using CAMUNDA_* environment"),
    }
    let jobs = build(resolved, pinned_base_url)?
        .with_identity(engine_desc.to_string(), job_types.to_vec());
    Ok(jobs)
}

/// Build the shared job client from an already-resolved profile. When there is
/// no profile, `pinned_base_url` (the env-only pin's fingerprint) beats the
/// process environment for the engine address.
pub fn build(profile: Option<&Profile>, pinned_base_url: Option<&str>) -> Result<Jobs> {
    Ok(Jobs::new(profile::client_with_base_override(
        profile,
        pinned_base_url,
    )?))
}
