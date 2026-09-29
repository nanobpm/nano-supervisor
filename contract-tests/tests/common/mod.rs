//! Shared test support: `insta` settings pre-loaded with the harness redactions
//! so every golden file (both the exact `--json` snapshots and the loose
//! human-readable ones) ignores timestamps, PIDs, temp paths and the like.

#![allow(dead_code)]

use std::path::Path;

use contract_tests::{home_redaction, redactions, TempHome};

/// Build `insta::Settings` with the shared static redactions plus the per-test
/// home-path redaction applied. Snapshots taken inside `settings.bind(...)`
/// (or via [`bound`]) are stable across runs and machines.
pub fn settings(home: &Path) -> insta::Settings {
    let mut s = insta::Settings::clone_current();
    s.set_prepend_module_to_snapshot(false);
    s.set_snapshot_path("../snapshots");
    let (home_pat, home_tok) = home_redaction(home);
    s.add_filter(&home_pat, home_tok);
    for r in redactions() {
        s.add_filter(r.pattern, r.replacement);
    }
    s
}

/// Run `body` with the shared redaction settings bound for the given home.
pub fn bound<R>(home: &TempHome, body: impl FnOnce() -> R) -> R {
    settings(home.path()).bind(body)
}
