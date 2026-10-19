//! Unit tests for the pure checkpoint logic and real-git integration tests for
//! the snapshot → push → fetch → restore → delete lifecycle and the orphan sweep.

use super::*;
use serde_json::json;
use std::path::{Path, PathBuf};

// --- pure logic ------------------------------------------------------------

#[test]
fn mode_parsing() {
    assert_eq!(checkpoint_mode(""), CheckpointMode::Auto);
    assert_eq!(checkpoint_mode("auto"), CheckpointMode::Auto);
    assert_eq!(checkpoint_mode("AUTO"), CheckpointMode::Auto);
    assert_eq!(checkpoint_mode("on"), CheckpointMode::On);
    assert_eq!(checkpoint_mode("true"), CheckpointMode::On);
    assert_eq!(checkpoint_mode("1"), CheckpointMode::On);
    assert_eq!(checkpoint_mode("off"), CheckpointMode::Off);
    assert_eq!(checkpoint_mode("disabled"), CheckpointMode::Off);
    assert_eq!(checkpoint_mode("nonsense"), CheckpointMode::Auto);
}

#[test]
fn config_defaults_and_floor() {
    let cfg = CheckpointConfig::build(|_| None);
    assert_eq!(cfg.mode, CheckpointMode::Auto);
    assert_eq!(cfg.min_interval_ms, 60_000);
    assert_eq!(cfg.ttl_ms, 7 * 24 * 60 * 60 * 1000);
    // A below-floor min interval is clamped to the floor.
    let cfg = CheckpointConfig::build(|k| match k {
        "NANO_AGENT_CHECKPOINT_MIN_INTERVAL_MS" => Some("10".into()),
        _ => None,
    });
    assert_eq!(cfg.min_interval_ms, MIN_INTERVAL_FLOOR_MS);
    let cfg = CheckpointConfig::build(|k| match k {
        "NANO_AGENT_CHECKPOINT" => Some("off".into()),
        _ => None,
    });
    assert!(!cfg.enabled());
}

#[test]
fn eligibility_rules() {
    // off disables unconditionally.
    assert!(
        !checkpoint_eligibility(CheckpointMode::Off, true, Some(true), true, Some("b")).enabled
    );
    // on requires a workspace but nothing else.
    assert!(checkpoint_eligibility(CheckpointMode::On, true, Some(false), false, None).enabled);
    assert!(
        !checkpoint_eligibility(CheckpointMode::On, false, Some(true), true, Some("b")).enabled
    );
    // auto requires push + auth + a working branch.
    assert!(
        checkpoint_eligibility(CheckpointMode::Auto, true, Some(true), true, Some("main")).enabled
    );
    assert!(
        !checkpoint_eligibility(CheckpointMode::Auto, true, Some(false), true, Some("main"))
            .enabled
    );
    assert!(
        !checkpoint_eligibility(CheckpointMode::Auto, true, Some(true), false, Some("main"))
            .enabled
    );
    assert!(!checkpoint_eligibility(CheckpointMode::Auto, true, Some(true), true, None).enabled);
    assert!(!checkpoint_eligibility(CheckpointMode::Auto, true, None, true, Some("")).enabled);
}

#[test]
fn authenticated_remote_detection() {
    assert!(is_authenticated_remote("git@github.com:org/repo.git"));
    assert!(is_authenticated_remote("ssh://git@host/repo.git"));
    assert!(is_authenticated_remote(
        "https://user:tok@github.com/o/r.git"
    ));
    assert!(is_authenticated_remote("https://user@github.com/o/r.git"));
    assert!(!is_authenticated_remote("https://github.com/o/r.git"));
    assert!(!is_authenticated_remote(""));
    assert!(!is_authenticated_remote(
        "http://example.com/path@segment/x"
    ));
}

#[test]
fn deny_paths() {
    for p in [
        ".env",
        ".env.local",
        ".envrc",
        "sub/.env.production",
        ".npmrc",
        "a/b/.netrc",
        "id_rsa",
        "deep/id_ed25519",
        "id_token",
        "server.pem",
        "a/b/c.key",
        "cert.p12",
        "store.keystore",
        ".aws/credentials",
        "x/.ssh/known_hosts",
        ".gnupg/secring",
        "credentials",
        "credentials.json",
        "secret.json",
        "secrets.yaml",
        "config/secrets.toml",
        ".git-credentials",
    ] {
        assert!(is_denied_path(p), "{p} should be denied");
    }
    for p in [
        "src/main.rs",
        "README.md",
        "environment.txt",
        "idea.md",
        "package.json",
    ] {
        assert!(!is_denied_path(p), "{p} should be allowed");
    }
}

#[test]
fn secret_content_detection() {
    assert!(contains_secret(
        "-----BEGIN RSA PRIVATE KEY-----\nMII...",
        &[]
    ));
    assert!(contains_secret(
        &format!("token=ghp_{}", "a".repeat(36)),
        &[]
    ));
    assert!(contains_secret(
        &format!("github_pat_{}", "a".repeat(60)),
        &[]
    ));
    assert!(contains_secret("AKIAABCDEFGHIJKLMNOP", &[]));
    assert!(contains_secret(&format!("xoxb-{}", "1234567890abc"), &[]));
    assert!(contains_secret(&format!("sk-{}", "a".repeat(32)), &[]));
    assert!(contains_secret(&format!("AIza{}", "b".repeat(35)), &[]));
    assert!(contains_secret(&format!("npm_{}", "c".repeat(36)), &[]));
    // injected value match (any length).
    assert!(contains_secret(
        "prefix-hunter2-suffix",
        &["hunter2".to_string()]
    ));
    assert!(!contains_secret("nothing to see here", &[]));
    assert!(!contains_secret("ghp_tooshort", &[]));
}

#[test]
fn rotating_batch_bounds_and_rotates() {
    let mk = |n: usize| -> Vec<(String, String)> {
        (0..n)
            .map(|i| (format!("refs/nano/wip/{i:03}"), format!("sha{i}")))
            .collect()
    };
    // Fits within the batch: returned unchanged (same length).
    assert_eq!(rotating_batch(mk(10), 25, 0).len(), 10);
    // Oversized: bounded to the batch size.
    let b = rotating_batch(mk(100), 25, 0);
    assert_eq!(b.len(), 25);
    // Rotating: different `now_ms` offsets select different windows, so refs
    // starved by one window are eventually covered by another.
    let w0: Vec<String> = rotating_batch(mk(100), 25, 0)
        .into_iter()
        .map(|e| e.0)
        .collect();
    let w1: Vec<String> = rotating_batch(mk(100), 25, 40)
        .into_iter()
        .map(|e| e.0)
        .collect();
    assert_ne!(w0, w1);
    // A zero batch still makes progress (never selects nothing).
    assert_eq!(rotating_batch(mk(5), 0, 0).len(), 1);
}

#[test]
fn pem_private_key_after_benign_block() {
    // A benign CERTIFICATE / PUBLIC KEY block FIRST, then a private key: the
    // filter must scan every BEGIN marker, not just the first, or the private
    // key would be published.
    let cert_then_key = "-----BEGIN CERTIFICATE-----\nMIIBhTCC\n-----END CERTIFICATE-----\n\
         -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB\n-----END RSA PRIVATE KEY-----";
    assert!(contains_secret(cert_then_key, &[]));
    let pub_then_key = "-----BEGIN PUBLIC KEY-----\nMFkwEwYH\n-----END PUBLIC KEY-----\n\
         -----BEGIN PRIVATE KEY-----\nMC4CAQAw\n-----END PRIVATE KEY-----";
    assert!(contains_secret(pub_then_key, &[]));
    // Benign blocks with NO private key must not false-positive.
    assert!(!contains_secret(
        "-----BEGIN CERTIFICATE-----\nMIIBhTCC\n-----END CERTIFICATE-----\n\
         -----BEGIN PUBLIC KEY-----\nMFkwEwYH\n-----END PUBLIC KEY-----",
        &[]
    ));
}

#[test]
fn err_text_truncation_is_utf8_safe() {
    // A git diagnostic whose byte-400 cut falls inside a multi-byte char must
    // NOT panic (String::truncate would); the cut backs up to a char boundary.
    let mut s = "a".repeat(399);
    s.push('é'); // 2 bytes at offset 399..401 — byte 400 is mid-character.
    s.push_str(&"b".repeat(50));
    let out = GitOut {
        status: Some(1),
        stdout: String::new(),
        stdout_bytes: Vec::new(),
        stderr: s,
    }
    .err_text();
    assert!(out.len() <= 400);
    assert!(out.is_char_boundary(out.len()));

    // Direct helper coverage for a few boundary positions.
    let mut t = "x".repeat(10);
    t.push('界'); // 3 bytes at 10..13.
    truncate_on_char_boundary(&mut t, 12);
    assert_eq!(t, "x".repeat(10)); // backed up past the split char.
    let mut u = "short".to_string();
    truncate_on_char_boundary(&mut u, 400);
    assert_eq!(u, "short"); // under the cap: unchanged.
}

#[test]
fn normalize_and_url_credentials() {
    let n = normalize_secret_values(&["  a ".into(), "".into(), "a".into(), "b".into()]);
    assert_eq!(n, vec!["a".to_string(), "b".to_string()]);
    let creds = credentials_from_url("https://user:p%40ss@github.com/o/r.git");
    assert!(creds.contains(&"p%40ss".to_string()));
    assert!(creds.contains(&"p@ss".to_string()));
    assert!(creds.contains(&"user".to_string()));
    assert!(credentials_from_url("ssh://git@host/r.git").is_empty());
    assert!(credentials_from_url("https://github.com/o/r.git").is_empty());
}

#[test]
fn ref_naming() {
    assert_eq!(
        checkpoint_ref("12345").as_deref(),
        Some("refs/nano/wip/12345")
    );
    assert_eq!(
        recovered_checkpoint_ref("abc-DEF_9").as_deref(),
        Some("refs/nano/recovered/abc-DEF_9")
    );
    assert!(checkpoint_ref("bad/key").is_none());
    assert!(checkpoint_ref("").is_none());
    assert!(checkpoint_ref(&"x".repeat(129)).is_none());
}

#[test]
fn predecessor_ref_parsing() {
    // bare string
    let v = json!({ "resumeFromCheckpoint": "refs/nano/wip/999" });
    assert_eq!(
        predecessor_checkpoint_ref(&v, None, None).as_deref(),
        Some("refs/nano/wip/999")
    );
    // recovered namespace
    let v = json!({ "resumeFromCheckpoint": "refs/nano/recovered/999" });
    assert_eq!(
        predecessor_checkpoint_ref(&v, None, None).as_deref(),
        Some("refs/nano/recovered/999")
    );
    // object with matching elementId
    let v = json!({ "resumeFromCheckpoint": { "ref": "refs/nano/wip/5", "elementId": "task-a" } });
    assert_eq!(
        predecessor_checkpoint_ref(&v, None, Some("task-a")).as_deref(),
        Some("refs/nano/wip/5")
    );
    // object with mismatched elementId -> refused
    assert!(predecessor_checkpoint_ref(&v, None, Some("task-b")).is_none());
    // object with recorded elementId but no caller -> adopted (correlation skipped)
    assert!(predecessor_checkpoint_ref(&v, None, None).is_some());
    // self-ref refused
    let v = json!({ "resumeFromCheckpoint": "refs/nano/wip/self" });
    assert!(predecessor_checkpoint_ref(&v, Some("refs/nano/wip/self"), None).is_none());
    // malformed / absent
    assert!(predecessor_checkpoint_ref(&json!({}), None, None).is_none());
    assert!(predecessor_checkpoint_ref(
        &json!({ "resumeFromCheckpoint": "refs/heads/main" }),
        None,
        None
    )
    .is_none());
    assert!(predecessor_checkpoint_ref(
        &json!({ "resumeFromCheckpoint": "refs/nano/wip/bad/key" }),
        None,
        None
    )
    .is_none());
}

#[test]
fn resume_ref_explicitness() {
    assert!(resume_ref_is_explicit(
        &json!({ "resumeFromCheckpoint": "refs/nano/wip/1" })
    ));
    assert!(resume_ref_is_explicit(
        &json!({ "resumeFromCheckpoint": "refs/nano/recovered/1" })
    ));
    // object form is never explicit
    assert!(!resume_ref_is_explicit(
        &json!({ "resumeFromCheckpoint": { "ref": "refs/nano/wip/1" } })
    ));
    assert!(!resume_ref_is_explicit(
        &json!({ "resumeFromCheckpoint": "refs/heads/main" })
    ));
    assert!(!resume_ref_is_explicit(&json!({})));
}

#[test]
fn push_failure_classification() {
    assert_eq!(
        classify_push_failure("hint: (stale info)"),
        PushFailure::Lease
    );
    assert_eq!(
        classify_push_failure("! [rejected] main -> main"),
        PushFailure::Lease
    );
    assert_eq!(
        classify_push_failure("remote rejected: push protection"),
        PushFailure::Policy
    );
    assert_eq!(
        classify_push_failure("error GH013 secret"),
        PushFailure::Policy
    );
    assert_eq!(
        classify_push_failure("fatal: Authentication failed"),
        PushFailure::Auth
    );
    assert_eq!(classify_push_failure("403 Forbidden"), PushFailure::Auth);
    assert_eq!(
        classify_push_failure("could not resolve host"),
        PushFailure::Transient
    );
}

#[test]
fn orphan_decision_spares_active_process() {
    // terminal element, process finished -> orphan
    assert!(orphan_decision(
        Some("TERMINATED"),
        true,
        Some("TERMINATED")
    ));
    assert!(orphan_decision(Some("COMPLETED"), true, Some("COMPLETED")));
    assert!(orphan_decision(Some("TERMINATED"), true, Some("CANCELED")));
    // terminal element, process STILL ACTIVE -> SPARED (the #295 case)
    assert!(!orphan_decision(Some("TERMINATED"), true, Some("ACTIVE")));
    // terminal element, process unknown -> spared
    assert!(!orphan_decision(Some("TERMINATED"), true, None));
    // non-terminal element -> spared
    assert!(!orphan_decision(Some("ACTIVE"), true, Some("TERMINATED")));
    assert!(!orphan_decision(None, true, None));
    // no process reader -> legacy element-only behaviour
    assert!(orphan_decision(Some("TERMINATED"), false, None));
    assert!(!orphan_decision(Some("ACTIVE"), false, None));
}

#[test]
fn restored_note_mentions_commits() {
    let r = RestoreResult {
        restored: true,
        commits_recovered: true,
        ..Default::default()
    };
    let note = checkpoint_restored_note(&r);
    assert!(note.contains("WORKSPACE RESTORED"));
    assert!(note.contains("local commits were recovered"));
    let r = RestoreResult {
        restored: false,
        ..Default::default()
    };
    assert!(checkpoint_restored_note(&r).is_empty());
}

#[test]
fn url_redaction() {
    assert_eq!(
        redact_url_userinfo("push to https://user:tok@github.com/o/r.git failed"),
        "push to https://***@github.com/o/r.git failed"
    );
    assert_eq!(redact_url_userinfo("no url here"), "no url here");
}

// --- real-git integration --------------------------------------------------

fn tmp_root(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nano-ckpt-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::canonicalize(&d).unwrap()
}

fn runner_at(path: &Path) -> GitRunner {
    GitRunner::new(
        CwdHandle::open(path).expect("open cwd"),
        Duration::from_secs(30),
    )
}

async fn commit_all(git: &GitRunner, msg: &str) -> String {
    let r = git.run(&["add", "-A"]).await;
    assert!(r.ok(), "add: {}", r.stderr);
    let r = git
        .run(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            msg,
        ])
        .await;
    assert!(r.ok(), "commit: {} {}", r.stdout, r.stderr);
    git.run(&["rev-parse", "HEAD"]).await.out()
}

/// Build a bare remote with an initial commit on `main`, and return (root, bare_path).
async fn setup_remote_with_main(tag: &str) -> (PathBuf, String) {
    let root = tmp_root(tag);
    let root_git = runner_at(&root);
    assert!(root_git.run(&["init", "--bare", "remote.git"]).await.ok());
    // seed clone
    assert!(root_git.run(&["clone", "remote.git", "seed"]).await.ok());
    let seed = runner_at(&root.join("seed"));
    assert!(seed
        .run(&["symbolic-ref", "HEAD", "refs/heads/main"])
        .await
        .ok());
    std::fs::write(root.join("seed/README.md"), "base\n").unwrap();
    commit_all(&seed, "initial").await;
    assert!(seed.run(&["push", "origin", "main"]).await.ok());
    // Point the bare remote's HEAD at main so fresh clones check it out
    // regardless of the host's init.defaultBranch.
    let bare_git = runner_at(&root.join("remote.git"));
    assert!(bare_git
        .run_in(
            &["symbolic-ref", "HEAD", "refs/heads/main"],
            &[("GIT_DIR", ".")],
            None
        )
        .await
        .ok());
    (root, "remote.git".to_string())
}

#[tokio::test]
async fn checkpoint_pushed_on_interruption_and_resumed_run_restores_it() {
    if which_git().is_none() {
        return;
    }
    let (root, _bare) = setup_remote_with_main("roundtrip").await;

    // Worker A clones, has uncommitted WIP, is "interrupted" -> snapshot + push.
    let work_a = root.join("a");
    let root_git = runner_at(&root);
    assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
    let git_a = runner_at(&work_a);
    let base_sha = git_a.run(&["rev-parse", "HEAD"]).await.out();
    std::fs::write(work_a.join("WIP.txt"), "in progress work\n").unwrap();

    let snap = snapshot_worktree(
        &git_a,
        &base_sha,
        "main",
        "run-A",
        None,
        5 * 1024 * 1024,
        &[],
        "nano: WIP checkpoint",
    )
    .await;
    let sha = match snap {
        Snapshot::Committed { sha, .. } => sha,
        Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
    };
    let reference = checkpoint_ref("elem-1").unwrap();
    assert_eq!(
        push_checkpoint(&git_a, &reference, &sha, "", "origin").await,
        PushResult::Ok
    );

    // Worker B (resume) fresh clone discovers & restores the predecessor checkpoint.
    let work_b = root.join("b");
    assert!(root_git.run(&["clone", "remote.git", "b"]).await.ok());
    let git_b = runner_at(&work_b);
    let fetched = fetch_checkpoint(&git_b, &reference, "origin")
        .await
        .unwrap()
        .expect("checkpoint present on remote");
    assert_eq!(fetched.base, base_sha);

    let restore = restore_checkpoint(&git_b, &fetched, None, false, "").await;
    assert!(restore.restored, "restore failed: {}", restore.reason);
    assert_eq!(
        std::fs::read_to_string(work_b.join("WIP.txt")).unwrap(),
        "in progress work\n"
    );

    // Finalize: delete the WIP ref; a subsequent fetch finds nothing.
    assert_eq!(
        delete_checkpoint_ref(&git_b, &reference, "origin", Some(&sha)).await,
        PushResult::Ok
    );
    assert!(fetch_checkpoint(&git_b, &reference, "origin")
        .await
        .unwrap()
        .is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn snapshot_excludes_denied_and_secret_paths() {
    if which_git().is_none() {
        return;
    }
    let (root, _bare) = setup_remote_with_main("exclude").await;
    let work = root.join("a");
    let root_git = runner_at(&root);
    assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
    let git = runner_at(&work);
    let base_sha = git.run(&["rev-parse", "HEAD"]).await.out();

    std::fs::write(work.join("keep.txt"), "normal\n").unwrap();
    std::fs::write(work.join(".env"), "SECRET=1\n").unwrap();
    std::fs::write(work.join("leak.txt"), format!("ghp_{}", "a".repeat(40))).unwrap();

    let snap = snapshot_worktree(
        &git,
        &base_sha,
        "main",
        "run-x",
        None,
        5 * 1024 * 1024,
        &[],
        "msg",
    )
    .await;
    let (sha, excluded) = match snap {
        Snapshot::Committed { sha, excluded, .. } => (sha, excluded),
        Snapshot::Skipped { reason } => panic!("skipped: {reason}"),
    };
    let names: Vec<&str> = excluded.iter().map(|(p, _)| p.as_str()).collect();
    assert!(names.contains(&".env"), "excluded: {names:?}");
    assert!(names.contains(&"leak.txt"), "excluded: {names:?}");

    // The shadow tree keeps keep.txt but not the excluded files.
    let ls = git.run(&["ls-tree", "-r", "--name-only", &sha]).await.out();
    assert!(ls.contains("keep.txt"));
    assert!(!ls.contains(".env"));
    assert!(!ls.contains("leak.txt"));

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn restore_refuses_off_branch_snapshot() {
    if which_git().is_none() {
        return;
    }
    let (root, _bare) = setup_remote_with_main("branchguard").await;
    let work = root.join("a");
    let root_git = runner_at(&root);
    assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
    let git = runner_at(&work);
    let head = git.run(&["rev-parse", "HEAD"]).await.out();
    let branch = git.run(&["symbolic-ref", "--short", "HEAD"]).await.out();

    // A checkpoint claiming it was taken on a DIFFERENT branch must be refused.
    let fetched = FetchedCheckpoint {
        sha: head.clone(),
        parent: head,
        base: String::new(),
        base_ref: String::new(),
        branch: "some-other-branch".to_string(),
    };
    let r = restore_checkpoint(&git, &fetched, Some(&branch), false, "").await;
    assert!(!r.restored);
    assert!(r.branch_mismatch, "reason: {}", r.reason);

    let _ = std::fs::remove_dir_all(&root);
}

/// A clean worktree that returns to its base AFTER a prior interval snapshot a
/// WIP file must still publish a fresh (clean) snapshot to supersede the stale
/// one — otherwise the remote checkpoint keeps the discarded file and an
/// interrupted run restores it. A later still-clean interval then no-ops.
#[tokio::test]
async fn clean_snapshot_supersedes_a_stale_prior_checkpoint() {
    if which_git().is_none() {
        return;
    }
    let (root, _bare) = setup_remote_with_main("cleansupersede").await;
    let work = root.join("a");
    let root_git = runner_at(&root);
    assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
    let git = runner_at(&work);
    let base_sha = git.run(&["rev-parse", "HEAD"]).await.out();

    // Interval 1: a WIP file is present -> a dirty snapshot is committed.
    std::fs::write(work.join("WIP.txt"), "in progress\n").unwrap();
    let snap1 = snapshot_worktree(
        &git,
        &base_sha,
        "main",
        "run-c",
        None,
        5 * 1024 * 1024,
        &[],
        "m1",
    )
    .await;
    let (tree1, head1) = match snap1 {
        Snapshot::Committed { tree, head, .. } => (tree, head),
        Snapshot::Skipped { reason } => panic!("interval 1 skipped: {reason}"),
    };

    // The agent deletes the WIP file -> the worktree is clean again (== base).
    std::fs::remove_file(work.join("WIP.txt")).unwrap();

    // Interval 2: clean, but a DIFFERENT checkpoint was already pushed this
    // session, so a fresh (clean) snapshot MUST be produced to supersede it.
    let snap2 = snapshot_worktree(
        &git,
        &base_sha,
        "main",
        "run-c",
        Some((tree1.as_str(), head1.as_str())),
        5 * 1024 * 1024,
        &[],
        "m2",
    )
    .await;
    let (tree2, head2) = match snap2 {
        Snapshot::Committed {
            sha, tree, head, ..
        } => {
            // The superseding snapshot drops the discarded file.
            let ls = git.run(&["ls-tree", "-r", "--name-only", &sha]).await.out();
            assert!(!ls.contains("WIP.txt"), "stale WIP.txt still present: {ls}");
            (tree, head)
        }
        Snapshot::Skipped { reason } => {
            panic!("clean interval wrongly skipped a stale checkpoint: {reason}")
        }
    };

    // Interval 3: still clean and the last push already matches -> genuine no-op.
    let snap3 = snapshot_worktree(
        &git,
        &base_sha,
        "main",
        "run-c",
        Some((tree2.as_str(), head2.as_str())),
        5 * 1024 * 1024,
        &[],
        "m3",
    )
    .await;
    match snap3 {
        Snapshot::Skipped { reason } => assert_eq!(reason, "unchanged"),
        Snapshot::Committed { .. } => panic!("idle clean interval should no-op"),
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// A RESUMED run seeds its supersession state from the restored checkpoint. If
/// the agent then discards the restored work (back to the base) before the first
/// tick, the seeded `last_tree` (the restored checkpoint's tree) differs from the
/// now-clean tree, so the tick must publish a clean snapshot that supersedes the
/// stale remote checkpoint — not skip as `clean` and leave the discarded work to
/// be restored again after the next interruption.
#[tokio::test]
async fn seeded_supersession_state_replaces_a_discarded_restored_checkpoint() {
    if which_git().is_none() {
        return;
    }
    let (root, _bare) = setup_remote_with_main("resumesupersede").await;
    let work = root.join("a");
    let root_git = runner_at(&root);
    assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
    let git = runner_at(&work);
    let base_sha = git.run(&["rev-parse", "HEAD"]).await.out();

    // Attempt 1: snapshot a WIP file (this is the checkpoint a retry restores).
    std::fs::write(work.join("WIP.txt"), "in progress\n").unwrap();
    let snap1 = snapshot_worktree(
        &git,
        &base_sha,
        "main",
        "run-r",
        None,
        5 * 1024 * 1024,
        &[],
        "m1",
    )
    .await;
    let (sha1, tree1, head1) = match snap1 {
        Snapshot::Committed {
            sha, tree, head, ..
        } => (sha, tree, head),
        Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
    };

    // Resume: the supersession seed is the restored checkpoint's (tree, head) —
    // exactly what `restore()` reads from `FetchedCheckpoint` (`sha^{tree}` +
    // parent). The agent then DISCARDS the restored file, returning to the base.
    let seed_tree = git
        .run(&["rev-parse", "--verify", "-q", &format!("{sha1}^{{tree}}")])
        .await
        .out();
    assert_eq!(seed_tree, tree1, "seed must be the checkpoint's tree");
    std::fs::remove_file(work.join("WIP.txt")).unwrap();

    // First tick of the resumed run: with the seed, the clean tree differs from
    // the seeded (stale) tree, so a clean superseding snapshot is produced.
    let snap2 = snapshot_worktree(
        &git,
        &base_sha,
        "main",
        "run-r",
        Some((seed_tree.as_str(), head1.as_str())),
        5 * 1024 * 1024,
        &[],
        "m2",
    )
    .await;
    match snap2 {
        Snapshot::Committed { sha, .. } => {
            let ls = git.run(&["ls-tree", "-r", "--name-only", &sha]).await.out();
            assert!(
                !ls.contains("WIP.txt"),
                "discarded WIP.txt still present: {ls}"
            );
        }
        Snapshot::Skipped { reason } => {
            panic!("a seeded clean tick must supersede the stale checkpoint, not skip: {reason}")
        }
    }

    // Contrast: WITHOUT the seed (the old behaviour) the same clean tick wrongly
    // reports `clean` and leaves the stale checkpoint in place.
    let snap3 = snapshot_worktree(
        &git,
        &base_sha,
        "main",
        "run-r",
        None, // no seed — the bug F5 fixes
        5 * 1024 * 1024,
        &[],
        "m3",
    )
    .await;
    match snap3 {
        Snapshot::Skipped { reason } => assert_eq!(reason, "clean"),
        Snapshot::Committed { .. } => {}
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// Supersession must compare HEAD, not only the tree. A checkpoint can capture a
/// commit/revert pair whose tree equals the provisioned base; if the agent then
/// resets HEAD back to that base, every later tick sees a tree identical to the
/// last push. A tree-only supersession check would read that as "already pushed
/// this tree" and skip forever, leaving the discarded commits alive in the stale
/// remote checkpoint's ancestry (a same-branch restore would then recover them).
/// Including the last snapshotted HEAD forces a superseding clean snapshot.
#[tokio::test]
async fn supersession_detects_discarded_history_with_an_unchanged_tree() {
    if which_git().is_none() {
        return;
    }
    let (root, _bare) = setup_remote_with_main("discardhistory").await;
    let work = root.join("a");
    let root_git = runner_at(&root);
    assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
    let git = runner_at(&work);
    let base_sha = git.run(&["rev-parse", "HEAD"]).await.out();

    // The agent commits a change and then reverts it: HEAD advances by two
    // commits but the worktree tree returns to the base tree.
    std::fs::write(work.join("scratch.txt"), "work in flight\n").unwrap();
    assert!(git.run(&["add", "-A"]).await.ok());
    assert!(git
        .run(&[
            "-c",
            "user.email=a@b.c",
            "-c",
            "user.name=a",
            "commit",
            "-m",
            "c1"
        ])
        .await
        .ok());
    std::fs::remove_file(work.join("scratch.txt")).unwrap();
    assert!(git.run(&["add", "-A"]).await.ok());
    assert!(git
        .run(&[
            "-c",
            "user.email=a@b.c",
            "-c",
            "user.name=a",
            "commit",
            "-m",
            "c2"
        ])
        .await
        .ok());
    let advanced_head = git.run(&["rev-parse", "HEAD"]).await.out();
    assert_ne!(advanced_head, base_sha, "HEAD should have advanced");

    // Interval 1: the worktree tree equals base, but HEAD is ahead, so a dirty
    // snapshot capturing the (soon-to-be-discarded) history is committed.
    let snap1 = snapshot_worktree(
        &git,
        &base_sha,
        "main",
        "run-h",
        None,
        5 * 1024 * 1024,
        &[],
        "m1",
    )
    .await;
    let (tree1, head1) = match snap1 {
        Snapshot::Committed { tree, head, .. } => (tree, head),
        Snapshot::Skipped { reason } => panic!("interval 1 skipped: {reason}"),
    };
    assert_eq!(
        head1, advanced_head,
        "snapshot should record the advanced HEAD"
    );

    // The agent DISCARDS the history, resetting HEAD back to base. The tree is
    // unchanged from interval 1 (both equal the base tree), so a tree-only check
    // would skip here and strand the discarded commits in the remote checkpoint.
    assert!(git.run(&["reset", "--hard", &base_sha]).await.ok());
    let reset_tree = git.run(&["rev-parse", "HEAD^{tree}"]).await.out();
    assert_eq!(
        reset_tree, tree1,
        "the reset tree must equal interval 1's tree"
    );

    // Interval 2: clean and tree-unchanged, but HEAD moved, so a superseding
    // clean snapshot (parented on base) MUST be committed — not skipped.
    let snap2 = snapshot_worktree(
        &git,
        &base_sha,
        "main",
        "run-h",
        Some((tree1.as_str(), head1.as_str())),
        5 * 1024 * 1024,
        &[],
        "m2",
    )
    .await;
    match snap2 {
        Snapshot::Committed { head, .. } => {
            assert_eq!(
                head, base_sha,
                "superseding snapshot must re-parent on base"
            );
        }
        Snapshot::Skipped { reason } => {
            panic!("discarded history was wrongly skipped as {reason}")
        }
    }

    let _ = std::fs::remove_dir_all(&root);
}

struct FakeProbe {
    orphan: bool,
}
impl OrphanProbe for FakeProbe {
    fn is_orphan<'a>(&'a self, _key: &'a str) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        let o = self.orphan;
        Box::pin(async move { o })
    }
}

#[tokio::test]
async fn sweep_spares_active_escalation_but_reclaims_orphans_and_ttl() {
    if which_git().is_none() {
        return;
    }
    let (root, _bare) = setup_remote_with_main("sweep").await;
    let work = root.join("a");
    let root_git = runner_at(&root);
    assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
    let git = runner_at(&work);
    let base_sha = git.run(&["rev-parse", "HEAD"]).await.out();

    // Push two WIP checkpoints.
    std::fs::write(work.join("w.txt"), "a\n").unwrap();
    let snap = snapshot_worktree(&git, &base_sha, "main", "r1", None, 5_000_000, &[], "m").await;
    let sha = match snap {
        Snapshot::Committed { sha, .. } => sha,
        Snapshot::Skipped { reason } => panic!("{reason}"),
    };
    let ref_live = checkpoint_ref("live").unwrap();
    let ref_orphan = checkpoint_ref("orphan").unwrap();
    assert_eq!(
        push_checkpoint(&git, &ref_live, &sha, "", "origin").await,
        PushResult::Ok
    );
    assert_eq!(
        push_checkpoint(&git, &ref_orphan, &sha, "", "origin").await,
        PushResult::Ok
    );

    // now_ms far in the future so age > grace; probe spares -> nothing deleted.
    let now = 10_u64.pow(15);
    let spare = FakeProbe { orphan: false };
    let res =
        sweep_stale_checkpoints(&git, None, u64::MAX, 0, Some(&spare), now, 50, 20, "origin").await;
    assert_eq!(res.deleted.len(), 0, "active escalation must be spared");
    assert_eq!(res.scanned, 2);

    // probe reports orphan -> both reclaimed.
    let orphan = FakeProbe { orphan: true };
    let res = sweep_stale_checkpoints(
        &git,
        None,
        u64::MAX,
        0,
        Some(&orphan),
        now,
        50,
        20,
        "origin",
    )
    .await;
    assert_eq!(res.deleted.len(), 2, "orphans reclaimed: {:?}", res);
    for d in &res.deleted {
        assert_eq!(d.why, "element-terminal");
    }
    assert!(fetch_checkpoint(&git, &ref_live, "origin")
        .await
        .unwrap()
        .is_none());

    // TTL backstop: a fresh ref past the TTL is reclaimed even without a probe.
    let ref_ttl = checkpoint_ref("ttl").unwrap();
    assert_eq!(
        push_checkpoint(&git, &ref_ttl, &sha, "", "origin").await,
        PushResult::Ok
    );
    let res = sweep_stale_checkpoints(&git, None, 1, 0, None, now, 50, 20, "origin").await;
    assert_eq!(res.deleted.len(), 1);
    assert_eq!(res.deleted[0].why, "ttl");

    let _ = std::fs::remove_dir_all(&root);
}

/// The orphan sweep runs against a dedicated scratch `--git-dir` that has no
/// `origin` remote. Driven through that scratch runner, the sweep must target the
/// repository by URL/path (as `maybe_sweep` now resolves it) rather than the
/// `"origin"` alias: with the scratch git-dir, `"origin"` resolves to nothing and
/// the first `ls-remote` fails, so neither TTL nor orphan reclamation runs.
#[tokio::test]
async fn sweep_reclaims_through_a_scratch_git_dir_runner() {
    if which_git().is_none() {
        return;
    }
    let (root, _bare) = setup_remote_with_main("sweepscratch").await;
    let work = root.join("a");
    let root_git = runner_at(&root);
    assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
    let git = runner_at(&work);
    let base_sha = git.run(&["rev-parse", "HEAD"]).await.out();

    // Push a WIP checkpoint to the shared remote.
    std::fs::write(work.join("w.txt"), "a\n").unwrap();
    let snap = snapshot_worktree(&git, &base_sha, "main", "r1", None, 5_000_000, &[], "m").await;
    let sha = match snap {
        Snapshot::Committed { sha, .. } => sha,
        Snapshot::Skipped { reason } => panic!("{reason}"),
    };
    let ref_ttl = checkpoint_ref("scratchttl").unwrap();
    assert_eq!(
        push_checkpoint(&git, &ref_ttl, &sha, "", "origin").await,
        PushResult::Ok
    );

    // A fresh daemon-owned scratch bare repo, exactly as `sweep_scratch_repo`
    // prepares — no named remotes.
    let scratch = root.join("scratch.git");
    assert!(root_git
        .run(&["init", "--bare", "--quiet", &scratch.to_string_lossy()])
        .await
        .ok());
    let scratch_runner = runner_at(&work).with_git_dir(scratch.clone());
    let remote_url = root.join("remote.git").to_string_lossy().into_owned();
    let now = 10_u64.pow(15);

    // Through the scratch git-dir, "origin" is undefined -> the sweep errors and
    // reclaims nothing (this is the bug the fix guards against).
    let via_origin =
        sweep_stale_checkpoints(&scratch_runner, None, 1, 0, None, now, 50, 20, "origin").await;
    assert!(
        via_origin.error.is_some() && via_origin.deleted.is_empty(),
        "origin must not resolve against the scratch git-dir: {via_origin:?}"
    );

    // Targeting the repository by path works through the scratch git-dir: the
    // TTL-expired orphan is reclaimed.
    let via_url =
        sweep_stale_checkpoints(&scratch_runner, None, 1, 0, None, now, 50, 20, &remote_url).await;
    assert!(
        via_url.error.is_none(),
        "scratch-path sweep errored: {via_url:?}"
    );
    assert_eq!(
        via_url.deleted.len(),
        1,
        "orphan not reclaimed: {via_url:?}"
    );
    assert_eq!(via_url.deleted[0].why, "ttl");
    assert!(fetch_checkpoint(&git, &ref_ttl, "origin")
        .await
        .unwrap()
        .is_none());

    let _ = std::fs::remove_dir_all(&root);
}

fn which_git() -> Option<()> {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| ())
}

#[test]
fn fallback_branch_parts_peels_the_full_per_activation_uniq() {
    // `<uniq>` is EXACTLY `<rand(16hex)>-<pid>-<nanos>-<seq>`; the base is
    // everything before it, even when the base itself contains dashes.
    assert_eq!(
        fallback_branch_parts("nano/agent-work/main-aabbccddeeff0011-1234-99887766-0"),
        Some((
            "main".to_string(),
            "aabbccddeeff0011-1234-99887766-0".to_string()
        ))
    );
    assert_eq!(
        fallback_branch_parts("nano/agent-work/feat-my-thing-00112233445566ff-7-8-9"),
        Some((
            "feat-my-thing".to_string(),
            "00112233445566ff-7-8-9".to_string()
        ))
    );
    // Two production-shaped activations of the SAME base must compare equal on the
    // base segment (the bug: the old last-dash split left the pid/nanos glued on).
    let a = fallback_branch_parts("nano/agent-work/main-aaaaaaaaaaaaaaaa-100-200-0").unwrap();
    let b = fallback_branch_parts("nano/agent-work/main-bbbbbbbbbbbbbbbb-101-201-1").unwrap();
    assert_eq!(a.0, b.0);
    assert_ne!(a.1, b.1);
}

#[test]
fn fallback_branch_parts_rejects_malformed_shapes() {
    // Wrong prefix.
    assert_eq!(fallback_branch_parts("refs/heads/main"), None);
    // Too few components (missing seq).
    assert_eq!(
        fallback_branch_parts("nano/agent-work/main-aaaaaaaaaaaaaaaa-100-200"),
        None
    );
    // `rand` not hex.
    assert_eq!(
        fallback_branch_parts("nano/agent-work/main-zzzz-100-200-0"),
        None
    );
    // `pid` not decimal.
    assert_eq!(
        fallback_branch_parts("nano/agent-work/main-aaaaaaaaaaaaaaaa-pid-200-0"),
        None
    );
}

#[tokio::test]
async fn restore_recognises_a_per_activation_fallback_rename() {
    if which_git().is_none() {
        return;
    }
    let (root, _bare) = setup_remote_with_main("fallback-rename").await;
    let root_git = runner_at(&root);

    // Worker A runs on a generated fallback branch cut from `main` and snapshots
    // its WIP (recording `main` as the configured base ref).
    let branch_a = "nano/agent-work/main-aaaaaaaaaaaaaaaa-100-200-0";
    let branch_b = "nano/agent-work/main-bbbbbbbbbbbbbbbb-101-201-1";
    let work_a = root.join("a");
    assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
    let git_a = runner_at(&work_a);
    assert!(git_a.run(&["checkout", "-b", branch_a]).await.ok());
    let base_sha = git_a.run(&["rev-parse", "HEAD"]).await.out();
    std::fs::write(work_a.join("WIP.txt"), "in progress\n").unwrap();
    let snap = snapshot_worktree(
        &git_a,
        &base_sha,
        "main",
        "run-A",
        None,
        5 * 1024 * 1024,
        &[],
        "nano: WIP checkpoint",
    )
    .await;
    let sha = match snap {
        Snapshot::Committed { sha, .. } => sha,
        Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
    };
    let reference = checkpoint_ref("elem-fb").unwrap();
    assert_eq!(
        push_checkpoint(&git_a, &reference, &sha, "", "origin").await,
        PushResult::Ok
    );

    // Worker B is a DIFFERENT activation of the same base: its fallback branch has
    // a fresh `<uniq>`. A restore must recognise the rename (same base segment +
    // same recorded base ref) and apply the predecessor's WIP.
    let work_b = root.join("b");
    assert!(root_git.run(&["clone", "remote.git", "b"]).await.ok());
    let git_b = runner_at(&work_b);
    let fetched = fetch_checkpoint(&git_b, &reference, "origin")
        .await
        .unwrap()
        .expect("checkpoint present");
    assert_eq!(fetched.base_ref, "main");

    let ok = restore_checkpoint(&git_b, &fetched, Some(branch_b), true, "main").await;
    assert!(ok.restored, "rename not recognised: {}", ok.reason);
    assert_eq!(
        std::fs::read_to_string(work_b.join("WIP.txt")).unwrap(),
        "in progress\n"
    );

    // A DIFFERENT configured base must NOT cross-restore: same base SEGMENT is not
    // enough when the recorded base ref differs.
    let work_c = root.join("c");
    assert!(root_git.run(&["clone", "remote.git", "c"]).await.ok());
    let git_c = runner_at(&work_c);
    let refused = restore_checkpoint(&git_c, &fetched, Some(branch_b), true, "release").await;
    assert!(!refused.restored);
    assert!(refused.branch_mismatch, "reason: {}", refused.reason);

    let _ = std::fs::remove_dir_all(&root);
}

/// A diverged restore replays the base→snapshot diff through `git apply`. The
/// patch must be transported as RAW bytes: a non-UTF-8 hunk (Latin-1 without NUL
/// bytes) must survive intact, or the apply corrupts/fails the restored content.
#[tokio::test]
async fn diverged_restore_preserves_non_utf8_patch_bytes() {
    if which_git().is_none() {
        return;
    }
    let (root, _bare) = setup_remote_with_main("latin1").await;
    let root_git = runner_at(&root);

    // Worker A commits a Latin-1 (non-UTF-8, no NUL) file on a fallback branch and
    // snapshots it. `snapshot_worktree` records the configured base ref.
    let branch_a = "nano/agent-work/main-aaaaaaaaaaaaaaaa-100-200-0";
    let work_a = root.join("a");
    assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
    let git_a = runner_at(&work_a);
    assert!(git_a.run(&["checkout", "-b", branch_a]).await.ok());
    let base_sha = git_a.run(&["rev-parse", "HEAD"]).await.out();
    // 0xE9 = 'é' in Latin-1: a lone continuation-invalid byte, no NUL.
    std::fs::write(
        work_a.join("latin1.txt"),
        [b"caf".as_slice(), &[0xE9u8], b"\n"].concat(),
    )
    .unwrap();
    let snap = snapshot_worktree(
        &git_a,
        &base_sha,
        "main",
        "run-l1",
        None,
        5 * 1024 * 1024,
        &[],
        "nano: WIP checkpoint",
    )
    .await;
    let sha = match snap {
        Snapshot::Committed { sha, .. } => sha,
        Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
    };
    let reference = checkpoint_ref("elem-l1").unwrap();
    assert_eq!(
        push_checkpoint(&git_a, &reference, &sha, "", "origin").await,
        PushResult::Ok
    );

    // Worker B: a DIFFERENT activation whose HEAD has advanced past the snapshot's
    // parent (diverged), forcing the 3-way patch path. Its fallback branch shares
    // the base segment but has a fresh uniq.
    let branch_b = "nano/agent-work/main-bbbbbbbbbbbbbbbb-101-201-1";
    let work_b = root.join("b");
    assert!(root_git.run(&["clone", "remote.git", "b"]).await.ok());
    let git_b = runner_at(&work_b);
    assert!(git_b.run(&["checkout", "-b", branch_b]).await.ok());
    // Advance HEAD so the restore is genuinely diverged (not a fast-forward).
    std::fs::write(work_b.join("other.txt"), "unrelated\n").unwrap();
    commit_all(&git_b, "advance head").await;

    let fetched = fetch_checkpoint(&git_b, &reference, "origin")
        .await
        .unwrap()
        .expect("checkpoint present");
    let ok = restore_checkpoint(&git_b, &fetched, Some(branch_b), true, "main").await;
    assert!(ok.restored, "diverged restore refused: {}", ok.reason);
    // The non-UTF-8 byte must survive the patch round-trip byte-for-byte.
    let restored = std::fs::read(work_b.join("latin1.txt")).unwrap();
    assert_eq!(
        restored,
        [b"caf".as_slice(), &[0xE9u8], b"\n"].concat(),
        "non-UTF-8 content corrupted by lossy patch decoding"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A clean `git apply --3way` prints `Applied patch to 'conflict.rs' cleanly.`
/// for a file named `conflict.rs`. Apply-failure detection must use the EXIT
/// STATUS, not a "conflict" substring match, or that filename is misread as a
/// conflict and the cleanly-restored work is reset away.
#[tokio::test]
async fn diverged_restore_does_not_mistake_a_conflict_named_file_for_a_conflict() {
    if which_git().is_none() {
        return;
    }
    let (root, _bare) = setup_remote_with_main("conflictname").await;
    let root_git = runner_at(&root);

    let branch_a = "nano/agent-work/main-aaaaaaaaaaaaaaaa-100-200-0";
    let work_a = root.join("a");
    assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
    let git_a = runner_at(&work_a);
    assert!(git_a.run(&["checkout", "-b", branch_a]).await.ok());
    let base_sha = git_a.run(&["rev-parse", "HEAD"]).await.out();
    // A file literally named `conflict.rs`, with content that applies cleanly.
    std::fs::write(work_a.join("conflict.rs"), "fn conflict() {}\n").unwrap();
    let snap = snapshot_worktree(
        &git_a,
        &base_sha,
        "main",
        "run-cf",
        None,
        5 * 1024 * 1024,
        &[],
        "nano: WIP checkpoint",
    )
    .await;
    let sha = match snap {
        Snapshot::Committed { sha, .. } => sha,
        Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
    };
    let reference = checkpoint_ref("elem-cf").unwrap();
    assert_eq!(
        push_checkpoint(&git_a, &reference, &sha, "", "origin").await,
        PushResult::Ok
    );

    let branch_b = "nano/agent-work/main-bbbbbbbbbbbbbbbb-101-201-1";
    let work_b = root.join("b");
    assert!(root_git.run(&["clone", "remote.git", "b"]).await.ok());
    let git_b = runner_at(&work_b);
    assert!(git_b.run(&["checkout", "-b", branch_b]).await.ok());
    std::fs::write(work_b.join("other.txt"), "unrelated\n").unwrap();
    commit_all(&git_b, "advance head").await;

    let fetched = fetch_checkpoint(&git_b, &reference, "origin")
        .await
        .unwrap()
        .expect("checkpoint present");
    let ok = restore_checkpoint(&git_b, &fetched, Some(branch_b), true, "main").await;
    assert!(
        ok.restored,
        "a file named conflict.rs must not be misread as a merge conflict: {}",
        ok.reason
    );
    assert_eq!(
        std::fs::read_to_string(work_b.join("conflict.rs")).unwrap(),
        "fn conflict() {}\n"
    );

    let _ = std::fs::remove_dir_all(&root);
}
