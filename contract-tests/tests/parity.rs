//! The **parity ledger guard** (issues #57 / #59).
//!
//! `contract_tests::PARITY_GAPS` is the single list of behaviours a target does
//! not implement yet. Each row cites an issue; this test fails when a row's issue
//! is **closed** (the gap is fixed, so its `expect_parity` marker is stale and
//! must be removed — leaving it would rot into silent red) or when the row is
//! malformed. It is the guard that makes an XFAIL self-expiring.
//!
//! Resolution needs `gh` and network access; without either the test **skips**,
//! in the same spirit as the engine-backed tests. The CI `contract-tests-*` jobs
//! have `gh` and a token, so the guard is live there.

use std::process::Command;

use contract_tests::PARITY_GAPS;

/// `repo#N` → `(repo, number)`, e.g. `nanobpm/nano-supervisor#59`.
fn parse_issue(reference: &str) -> Option<(&str, &str)> {
    let (repo, number) = reference.rsplit_once('#')?;
    if repo.split('/').count() != 2 || number.parse::<u64>().is_err() {
        return None;
    }
    Some((repo, number))
}

/// Whether `gh` can resolve `repo#N` at all, and if so its state.
enum Resolution {
    Open,
    Closed(String),
    /// `gh` absent, unauthenticated, offline, or the issue is not visible.
    Unavailable,
}

fn resolve(repo: &str, number: &str) -> Resolution {
    let out = Command::new("gh")
        .args([
            "api",
            &format!("repos/{repo}/issues/{number}"),
            "--jq",
            r#""\(.state)\t\(.title)""#,
        ])
        .output();
    match out {
        Ok(out) if out.status.success() => {
            let body = String::from_utf8_lossy(&out.stdout);
            let (state, title) = body.trim().split_once('\t').unwrap_or((body.trim(), ""));
            if state.eq_ignore_ascii_case("open") {
                Resolution::Open
            } else {
                Resolution::Closed(title.to_string())
            }
        }
        _ => Resolution::Unavailable,
    }
}

#[test]
fn parity_gaps_are_tracked_by_open_issues() {
    assert!(
        !PARITY_GAPS.is_empty(),
        "PARITY_GAPS is empty — if every parity gap is closed, delete this guard's \
         expectations accordingly and drop the expect_parity markers"
    );

    let mut closed = Vec::new();
    let mut unresolved = Vec::new();
    let mut malformed = Vec::new();
    for gap in PARITY_GAPS {
        let Some((repo, number)) = parse_issue(gap.issue) else {
            malformed.push(format!("{:?} {:?}", gap.target, gap.issue));
            continue;
        };
        match resolve(repo, number) {
            Resolution::Open => {}
            Resolution::Closed(title) => {
                closed.push(format!("{:?} → {} (now: {title})", gap.target, gap.issue))
            }
            Resolution::Unavailable => unresolved.push(gap.issue.to_string()),
        }
    }

    assert!(
        malformed.is_empty(),
        "PARITY_GAPS rows must cite `owner/repo#N`; malformed: {malformed:#?}"
    );

    if !unresolved.is_empty() {
        eprintln!(
            "SKIP parity_gaps_are_tracked_by_open_issues: could not resolve {unresolved:?} \
             (gh missing/unauthenticated/offline); the guard is enforced where gh is available"
        );
        return;
    }

    assert!(
        closed.is_empty(),
        "these parity gaps cite a CLOSED issue, so their `expect_parity` markers are \
         stale: the target should now pass — remove the marker and the PARITY_GAPS row \
         (or re-point it at the issue that actually still tracks the gap):\n{}",
        closed.join("\n")
    );
}

/// The ledger must not merely be well-formed: every row has to name a target that
/// exists, so a typo cannot silently waive a test on the wrong implementation.
#[test]
fn parity_gaps_name_a_real_target() {
    for gap in PARITY_GAPS {
        assert!(
            gap.target == contract_tests::Target::Node
                || gap.target == contract_tests::Target::Rust,
            "PARITY_GAPS row names an unknown target: {gap:?}"
        );
    }
}
