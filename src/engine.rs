//! The shared engine connection. All of a daemon's slots service jobs through a
//! single [`crate::jobs::Jobs`] built once from the resolved c8ctl profile (or
//! `CAMUNDA_*` environment), so N slots share one SDK client / HTTP pool.

use anyhow::{bail, Result};

use crate::jobs::{Jobs, NanoHttp};
use crate::profile::{self, Profile};

/// Which job-command transport to use. `Auto` resolves to `Nano` (raw HTTP in
/// Nano's `leaseToken` dialect) when leases are requested, else the SDK.
#[derive(Debug, Clone, Copy)]
pub enum JobApi {
    Sdk,
    Nano,
    Auto,
}

impl JobApi {
    pub fn parse(raw: &str) -> Result<JobApi> {
        match raw {
            "sdk" => Ok(JobApi::Sdk),
            "nano" => Ok(JobApi::Nano),
            "auto" => Ok(JobApi::Auto),
            other => bail!("--job-api must be sdk, nano or auto (got {other:?})"),
        }
    }

    fn resolve(self, with_lease: bool) -> JobApi {
        match self {
            JobApi::Auto if with_lease => JobApi::Nano,
            JobApi::Auto => JobApi::Sdk,
            other => other,
        }
    }
}

/// Resolve a profile, log which connection it picked, and build the shared job
/// client for the chosen transport.
pub fn connect(
    profile_name: Option<&str>,
    job_api: JobApi,
    with_lease: bool,
) -> Result<(Option<Profile>, Jobs)> {
    let resolved = profile::resolve(profile_name)?;
    match &resolved {
        Some(p) => crate::worker::log(&format!(
            "using c8ctl profile {:?} ({})",
            p.name,
            p.base_url.as_deref().unwrap_or("no baseUrl")
        )),
        None => crate::worker::log("no c8ctl profile; using CAMUNDA_* environment"),
    }
    let jobs = build(resolved.as_ref(), job_api, with_lease)?;
    Ok((resolved, jobs))
}

/// Build the shared job client from an already-resolved profile.
pub fn build(profile: Option<&Profile>, job_api: JobApi, with_lease: bool) -> Result<Jobs> {
    Ok(match job_api.resolve(with_lease) {
        JobApi::Sdk => Jobs::Sdk(Box::new(profile::client(profile)?)),
        JobApi::Nano => {
            let (address, basic) = profile::rest_address_and_basic(profile);
            Jobs::Nano(NanoHttp::new(&address, basic)?)
        }
        JobApi::Auto => unreachable!("resolve() removes Auto"),
    })
}
