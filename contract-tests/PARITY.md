# Parity ledger

One row per **behaviour-changing** plugin issue or PR from the JS supervisor
(`jwulf/c8ctl-plugin-nano`), with the disposition of its port into this repo.
This is the ledger proposed in #57; it will replace the README's
"Issue-numbered worker fixes covered" table and grow a CI check and a full
backfill under that issue. It is seeded here (#68) with the first triaged rows.

Every row carries exactly one disposition:

- **`contract-test: <path>`** — the behaviour is covered by a contract test (and,
  where relevant, already holds in Rust). Cite the test.
- **`rust-issue: #N`** — a port is needed; an **open** issue tracks it.
- **`n/a: <reason>`** — the change does not apply to the Rust worker (e.g. a
  JS-language-specific bug), with the reason.

The CI-enforced guard is [`PARITY_GAPS`](src/lib.rs) (asserted by
[`tests/parity.rs`](tests/parity.rs)), which fails when a cited issue closes.
That guard checks only the separately registered typed parity gaps (today Rust
#59 and plugin #274 / #289); it does **not** read this Markdown file, so a
`rust-issue` row here (e.g. #78) is **not** enforced by it — closing #78 would
not fail the guard. CI enforcement of these ledger rows remains deferred to
#57. The `contract-test` rows mirror the README fixes table.

| Plugin change | Behaviour | Disposition |
| --- | --- | --- |
| jwulf/c8ctl-plugin-nano#285 | Hoist `preGuardDrainTimedOut` to settlement scope; **fail** jobs on settlement-path throws (don't escape to `run failed` and loop forever) | **n/a** (the `preGuardDrainTimedOut is not defined` `ReferenceError` is a JS variable-scope regression that cannot occur in Rust — `result::detect_empty` is a total function over real work signals, not an out-of-scope producer read) + **contract-test**: the class behaviour is covered. See below. |
| jwulf/c8ctl-plugin-nano#262 | Record ACP `plan` updates as history turns and carry the latest plan across resume (plus `planSeed`-gated `session/new` seeding) | **rust-issue: #78** (port needed — the Rust worker has no AgentInstance producer (#59) or `agent-resume.mjs` port yet, so there is nowhere to persist/replay plans) |

## Notes

### jwulf/c8ctl-plugin-nano#285 — settlement-path throws

The plugin fix has two parts; both are already satisfied in the Rust worker:

1. **The `preGuardDrainTimedOut` scope bug is JS-specific.** In the plugin a
   `let` declared inside the run `try { … }` block was read by the empty-job
   guard *after* the block closed, throwing a `ReferenceError`. Rust's
   empty-job guard is [`result::detect_empty`](../src/result.rs), a total function
   taking `has_turns: bool` and real work signals (commits, pushed,
   `acp_outcome`, stdout). There is no out-of-scope variable to read and no
   dependence on an AgentInstance producer's field, so a successful producerless
   job is completed with its result vars, never dropped. Covered by
   `worker_result::non_empty_result_completes_the_job` and
   `worker_result::empty_result_fails_never_completes`.

2. **The class fix (settlement-path throw fails the job, not a forever loop)**
   is how [`slot::run`](../src/slot.rs) already settles: `execute` returns
   `Result<Settle>` and the settlement `match` turns any `Err` into
   `jobs.fail(&key, retries - 1, …)` — the job **fails** (retries preserved,
   surfaced as an incident when exhausted) instead of escaping to a `run failed`
   log and re-activating forever. Two qualifications keep this from overstating
   parity with #285:

   - **Scope of the panic capture.** `reconcile_exec_join` captures a panic of
     the *execution* task into `Some(Err(e))`, so an execution panic fails the
     job. It does **not** wrap the subsequent settlement code (`jobs.complete` /
     `jobs.fail`) — a throw there is not recovered into a fallback settle (see
     the next point).
   - **Daemon vs standalone panic policy.** The execution-panic downgrade holds
     in **daemon** mode (`propagate_job_panic: false`). In **standalone**
     `work` mode (`propagate_job_panic: true`) an execution panic is instead
     **re-raised** to crash the worker with a non-zero exit (so a swallowed
     crash cannot exit 0); it is not downgraded to a `jobs.fail`.
   - **A rejected settle request is logged, not recovered.** A `complete` or
     `fail` request that itself rejects is only **logged** (`complete failed: …`
     / `fail failed: … (original error: …)`); the worker does **not** fall back
     to the other settle command. So a settlement-path failure is surfaced but
     not retried/failed-over — a narrower guarantee than the plugin's
     wrapped-settlement branch.

   An **aborted** run (lost activation / force-stop) takes the
   `outcome.is_none()` branch and returns *without* settling ("job NOT settled
   (the engine will redeliver it)"), so the force-stop yield wins. The
   execution-error and aborted-returns branches mirror the plugin; the
   settlement-rejection branch is logged-and-surfaced rather than
   recovered.

### jwulf/c8ctl-plugin-nano#262 — ACP plan carry-over

Tracked by #78. Rust already treats a valid ACP `plan` update as an effective
transcript turn and renders a `📋 [plan updated]` marker
([`src/acp.rs`](../src/acp.rs)), but it does not persist the `nanobpm.plan/v1`
blob, read `latestPlan` back, restate it in the resume prompt, or seed
`_meta.plan` into `session/new`. That port depends on the AgentInstance producer
(#59) and the `agent-resume.mjs` port (#7).
