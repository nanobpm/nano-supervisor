//! The shared engine connection. All of a daemon's slots service jobs through a
//! single [`crate::jobs::Jobs`] built once from the resolved c8ctl profile (or
//! `CAMUNDA_*` environment), so N slots share one SDK client / HTTP pool.

use anyhow::Result;

use crate::jobs::Jobs;
use crate::profile::{self, Profile};

/// Resolve a profile, log which connection it picked, and build the shared job
/// client (the `camunda-orchestration-sdk` transport — the same one the Node
/// plugin uses).
pub fn connect(profile_name: Option<&str>) -> Result<(Option<Profile>, Jobs)> {
    let resolved = profile::resolve(profile_name)?;
    match &resolved {
        Some(p) => crate::runtime::log(&format!(
            "using c8ctl profile {:?} ({})",
            p.name,
            p.base_url.as_deref().unwrap_or("no baseUrl")
        )),
        None => crate::runtime::log("no c8ctl profile; using CAMUNDA_* environment"),
    }
    let jobs = build(resolved.as_ref())?;
    Ok((resolved, jobs))
}

/// Build the shared job client from an already-resolved profile.
pub fn build(profile: Option<&Profile>) -> Result<Jobs> {
    Ok(Jobs::new(profile::client(profile)?))
}
