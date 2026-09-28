//! #3 — command surface: every command, flag, default and exit code, plus the
//! golden `--json` and `hire --list` output (compared exactly after redaction).
//! Human-readable output is asserted by fields and facts, not byte-for-byte.
//!
//! Written against the Node plugin (`c8ctl-plugin-nano` 1.69.2) first, so the
//! snapshots describe what users rely on today; the same tests run against the
//! Rust target with `NS_TARGET=rust`.

mod common;

use contract_tests::{require_target, Target, TempHome};

/// A standard hire used across several cases.
fn hire_coder(home: &TempHome) {
    let out = home.run(&[
        "hire",
        "--name",
        "coder",
        "--rank",
        "senior",
        "--command",
        "nano-coder",
        "--capabilities",
        "pr-review,feature",
        "--model",
        "gpt5",
        "--protocol",
        "acp",
        "--permission",
        "yolo",
    ]);
    assert_eq!(out.code, Some(0), "hire failed: {}", out.stderr);
}

#[test]
fn hire_list_empty_human() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    let out = home.run(&["hire", "--list"]);
    assert_eq!(out.code, Some(0));
    // `hire --list` is a golden-exact surface (scripts parse it).
    common::bound(&home, || {
        insta::assert_snapshot!("hire_list_empty", out.stdout)
    });
}

#[test]
fn hire_list_empty_json() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    let out = home.run(&["hire", "--list", "--json"]);
    assert_eq!(out.code, Some(0));
    // NODE-QUIRK: `--json` NDJSON is emitted on **stderr** (the c8ctl host's
    // structured log channel); stdout stays empty.
    // https://github.com/nanobpm/nano-supervisor/issues/3
    assert_eq!(out.stdout, "", "stdout should be empty under --json");
    common::bound(&home, || {
        insta::assert_snapshot!("hire_list_empty_json", out.stderr)
    });
}

#[test]
fn hire_create_reports_job_types() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    let out = home.run(&[
        "hire",
        "--name",
        "coder",
        "--rank",
        "senior",
        "--command",
        "nano-coder",
        "--capabilities",
        "pr-review,feature",
        "--model",
        "gpt5",
        "--protocol",
        "acp",
        "--permission",
        "yolo",
    ]);
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    // Human output — asserted by facts, not byte-identical: capabilities are
    // sorted, and the rank × capability job-type matrix is reported.
    assert!(out.stdout.contains("[senior]"), "{}", out.stdout);
    assert!(out.stdout.contains("nano-coder"), "{}", out.stdout);
    assert!(
        out.stdout.contains("capabilities: feature, pr-review"),
        "caps should be listed sorted: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("senior:feature+pr-review"),
        "combined job type missing: {}",
        out.stdout
    );
    assert!(out.stdout.contains("protocol: acp"), "{}", out.stdout);
    assert!(out.stdout.contains("permission: yolo"), "{}", out.stdout);
}

#[test]
fn hire_list_populated_human_and_json() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    hire_coder(&home);

    let human = home.run(&["hire", "--list"]);
    assert_eq!(human.code, Some(0));
    common::bound(&home, || {
        insta::assert_snapshot!("hire_list_one", human.stdout)
    });

    let json = home.run(&["hire", "--list", "--json"]);
    assert_eq!(json.code, Some(0));
    // NODE-QUIRK: `--json` NDJSON is on stderr (see hire_list_empty_json).
    assert_eq!(json.stdout, "", "stdout should be empty under --json");
    common::bound(&home, || {
        insta::assert_snapshot!("hire_list_one_json", json.stderr)
    });
}

#[test]
fn assign_adds_capability() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    hire_coder(&home);
    let out = home.run(&["assign", "coder", "feature,pr-review,fix"]);
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert!(
        out.stdout.contains("capabilities: feature, fix, pr-review"),
        "{}",
        out.stdout
    );
    // The stored profile reflects the new capability set.
    let cfg = home.read_json("config.json").expect("config.json");
    let caps = &cfg["hires"]["coder"]["capabilities"];
    assert_eq!(
        caps,
        &serde_json::json!(["feature", "fix", "pr-review"]),
        "assign should persist the merged, sorted caps"
    );
}

// --- Error cases: unknown profile, bad flag values, no daemon ---------------

#[test]
fn work_unknown_profile_exits_nonzero() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    let out = home.run(&["work", "nosuch"]);
    // NODE-QUIRK: `work` on an unknown profile exits non-zero (exit 1), like the
    // other validation-failure paths (e.g. an invalid `hire --rank`); many plain
    // "not found" lookups instead print ✗ and still exit 0.
    // https://github.com/nanobpm/nano-supervisor/issues/3
    assert_eq!(
        out.code,
        Some(1),
        "stdout={} stderr={}",
        out.stdout,
        out.stderr
    );
    let combined = format!("{}{}", out.stdout, out.stderr);
    assert!(
        combined.contains("No hire named \"nosuch\""),
        "message: {combined}"
    );
}

#[test]
fn hire_bad_rank_is_rejected() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    let out = home.run(&["hire", "--name", "x", "--rank", "bogus", "--command", "foo"]);
    // A rejected hire is a validation failure, so it must exit non-zero (exit 1):
    // asserting only the message would let a build that prints the same error but
    // exits 0 pass, silently dropping the failure contract.
    assert_eq!(
        out.code,
        Some(1),
        "invalid rank must exit non-zero; stdout={} stderr={}",
        out.stdout,
        out.stderr
    );
    let combined = format!("{}{}", out.stdout, out.stderr);
    assert!(
        combined.contains("Invalid rank \"bogus\"")
            && combined.contains("principal, senior, junior, decider"),
        "message: {combined}"
    );
    // No profile is written for a rejected hire.
    assert!(
        home.read_json("config.json")
            .and_then(|c| c["hires"].get("x").cloned())
            .is_none(),
        "a rejected hire must not persist a profile"
    );
}

#[test]
fn supervisor_add_unknown_profile_reports_error() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    let out = home.run(&["supervisor", "add", "nosuch"]);
    let combined = format!("{}{}", out.stdout, out.stderr);
    assert!(
        combined.contains("no hire named \"nosuch\""),
        "message: {combined}"
    );
}

#[test]
fn supervisor_status_without_daemon() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    let out = home.run(&["supervisor", "status"]);
    assert_eq!(out.code, Some(0));
    assert!(
        out.stdout.contains("not running"),
        "status with no daemon: {}",
        out.stdout
    );
}

#[test]
fn workforce_list_missing_manifest() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    let out = home.run(&["workforce", "list"]);
    assert_eq!(out.code, Some(0));
    assert!(
        out.stdout.contains("Workforce \"default\" does not exist"),
        "{}",
        out.stdout
    );
}

#[test]
fn workforce_status_json_golden() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    home.run(&[
        "hire",
        "--name",
        "coder",
        "--rank",
        "senior",
        "--command",
        "nano-coder",
        "--capabilities",
        "feature",
    ]);
    home.run(&["workforce", "add", "coder", "--instances", "2"]);
    let out = home.run(&["workforce", "status", "--json"]);
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    // Unlike `hire --list --json`, `workforce status --json` emits a single JSON
    // *data* object on stdout. Golden-exact (scripts parse it).
    let value: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("workforce status --json is a JSON object");
    common::bound(&home, || {
        insta::assert_json_snapshot!("workforce_status_json", value)
    });
}
