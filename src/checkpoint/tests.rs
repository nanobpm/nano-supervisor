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
        run_id: String::new(),
        branch: "some-other-branch".to_string(),
    };
    let r = restore_checkpoint(&git, &fetched, Some(&branch), false, "").await;
    assert!(!r.restored);
    assert!(r.branch_mismatch, "reason: {}", r.reason);

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

fn which_git() -> Option<()> {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| ())
}
