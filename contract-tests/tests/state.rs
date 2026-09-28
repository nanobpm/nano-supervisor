//! #3 — state files: golden tests for the on-disk formats the plugin reads and
//! writes under `C8CTL_NANO_HOME`. Volatile fields (timestamps) are redacted;
//! everything structural is compared exactly.
//!
//! Covered here without an engine: `config.json` (hires) and
//! `workforce/<manifest>.json`. The daemon-written files (`supervisor.json`,
//! `supervisor-activity/*.json`) and the `logs/supervisor/worker-<id>.log`
//! layout need a live supervisor with workers — see the engine-gated cases in
//! `tests/socket.rs` and the worker suite (#4).

mod common;

use contract_tests::{require_target, Target, TempHome};

#[test]
fn config_json_after_hire() {
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

    let cfg = home
        .read("config.json")
        .expect("config.json written under home");
    let value: serde_json::Value = serde_json::from_str(&cfg).expect("config.json is valid JSON");
    // Golden shape (createdAt redacted). This is the persisted hire contract.
    common::bound(&home, || {
        insta::assert_json_snapshot!("config_after_hire", value, {
            ".hires.coder.createdAt" => "[timestamp]"
        })
    });
}

#[test]
fn workforce_manifest_after_add() {
    let target = Target::from_env();
    require_target!(target);
    let home = TempHome::with_target(target);
    let hire = home.run(&[
        "hire",
        "--name",
        "coder",
        "--rank",
        "senior",
        "--command",
        "nano-coder",
        "--capabilities",
        "pr-review,feature",
    ]);
    assert_eq!(hire.code, Some(0), "{}", hire.stderr);

    let add = home.run(&["workforce", "add", "coder", "--instances", "2"]);
    assert_eq!(add.code, Some(0), "{}", add.stderr);

    let manifest = home
        .read("workforce/default.json")
        .expect("workforce/default.json written under home");
    let value: serde_json::Value = serde_json::from_str(&manifest).expect("valid JSON");
    common::bound(&home, || {
        insta::assert_json_snapshot!("workforce_manifest_default", value)
    });
}

#[test]
fn state_writes_stay_under_home() {
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
    home.run(&["workforce", "add", "coder", "--instances", "1"]);
    // The plugin keeps its config and manifests under C8CTL_NANO_HOME. (The
    // control socket itself lives in the system temp dir — a known deviation
    // covered by tests/socket.rs.)
    assert!(home.path().join("config.json").is_file());
    assert!(home.path().join("workforce/default.json").is_file());

    // Confinement is part of the contract: an implementation that leaked config
    // or manifests to an unexpected path would still pass the two `is_file`
    // checks above. So enumerate every file actually written under the home and
    // assert it is *exactly* the documented set — any extra file is a leak.
    let mut written = files_under(home.path());
    written.sort();
    assert_eq!(
        written,
        vec![
            "config.json".to_string(),
            "workforce/default.json".to_string()
        ],
        "unexpected files written under C8CTL_NANO_HOME (possible state leak)"
    );

    // These daemon-less commands must not create the one documented *external*
    // artifact — the control socket in the system temp dir. Its absence here
    // proves nothing escaped the home outside of a live supervisor.
    assert!(
        !home.socket_path().exists(),
        "no daemon was started, so the external control socket must not exist"
    );
}

/// Every regular file under `root`, as `/`-joined paths relative to `root`.
fn files_under(root: &std::path::Path) -> Vec<String> {
    fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<String>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let rel = path.strip_prefix(base).unwrap_or(&path);
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}
