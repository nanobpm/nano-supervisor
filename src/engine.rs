//! The shared engine connection. All of a daemon's slots service jobs through a
//! single [`crate::jobs::Jobs`] built once from the resolved c8ctl profile (or
//! `CAMUNDA_*` environment), so N slots share one SDK client / HTTP pool.

use anyhow::{bail, Result};

use crate::jobs::{Jobs, NanoHttp};
use crate::profile::{self, Profile};

/// Which job-command transport to use. `Auto` resolves to the SDK — the same
/// transport the Node plugin uses. Nano ≥ 0.0.24 returns the spec's
/// `jobLeaseToken` (alongside its legacy `leaseToken`), so the SDK round-trips
/// leases. `Nano` (raw HTTP in the legacy `leaseToken` dialect) remains as an
/// explicit fallback for older engines.
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

    fn resolve(self) -> JobApi {
        match self {
            JobApi::Auto => JobApi::Sdk,
            other => other,
        }
    }
}

/// Resolve a profile, log which connection it picked, and build the shared job
/// client for the chosen transport.
pub fn connect(profile_name: Option<&str>, job_api: JobApi) -> Result<(Option<Profile>, Jobs)> {
    let resolved = profile::resolve(profile_name)?;
    match &resolved {
        Some(p) => crate::runtime::log(&format!(
            "using c8ctl profile {:?} ({})",
            p.name,
            p.base_url.as_deref().unwrap_or("no baseUrl")
        )),
        None => crate::runtime::log("no c8ctl profile; using CAMUNDA_* environment"),
    }
    let jobs = build(resolved.as_ref(), job_api)?;
    Ok((resolved, jobs))
}

/// Build the shared job client from an already-resolved profile.
pub fn build(profile: Option<&Profile>, job_api: JobApi) -> Result<Jobs> {
    Ok(match job_api.resolve() {
        JobApi::Sdk => Jobs::Sdk(Box::new(profile::client(profile)?)),
        JobApi::Nano => {
            // The raw Nano client only speaks none/basic. OAuth — whether from a
            // resolved profile OR the ambient CAMUNDA_*/ZEEBE_* environment (when
            // no profile resolved) — would otherwise silently send unauthenticated
            // requests, so refuse the combination up front rather than claim its
            // credentials are honoured.
            let oauth_source = match profile {
                Some(p) if profile::has_oauth(p) => Some(format!("c8ctl profile {:?}", p.name)),
                None if profile::env_has_oauth() => Some("the CAMUNDA_* environment".to_string()),
                _ => None,
            };
            if let Some(src) = oauth_source {
                bail!(
                    "{src} uses OAuth, which the nano/lease job transport does not support; \
                     use --job-api sdk or none/basic credentials"
                );
            }
            let (address, basic) = profile::rest_address_and_basic(profile);
            Jobs::Nano(NanoHttp::new(&address, basic)?)
        }
        JobApi::Auto => unreachable!("resolve() removes Auto"),
    })
}
