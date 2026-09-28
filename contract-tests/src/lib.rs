//! Black-box contract-test harness for the nano fleet.
//!
//! This crate never links to `nano-supervisor` internals: it exercises the
//! published wire contracts (CLI, state files, control socket, agentic hub) so
//! the same tests describe both the Node plugin and the Rust supervisor.
//!
//! Issue #5 owns the [`hub`] module and `fixtures/hub/`: the worker-side
//! agentic-hub protocol, held to the shared `@nanobpm/agentic` conformance
//! corpus (see `fixtures/hub/VERSION`).

pub mod hub;

use std::path::PathBuf;

/// Absolute path to the crate's `fixtures/` directory, independent of the
/// working directory a test runs from.
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}
