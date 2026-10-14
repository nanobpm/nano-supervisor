# Parity ledger (issue #57)

This repo (`nano-supervisor`) is a Rust re-implementation of the JS supervisor
that ships in [`jwulf/c8ctl-plugin-nano`](https://github.com/jwulf/c8ctl-plugin-nano).
Nothing in the toolchain forces a *behaviour-changing* JS fix into the Rust
worker — ports used to happen only when someone remembered, so nobody could tell
**ported vs. deliberately skipped vs. missed**.

This file is the ledger that fixes that: **one row per behaviour-changing plugin
issue or PR**, each with an explicit *disposition*. It replaces the old
"Issue-numbered worker fixes covered" table in
[`README.md`](README.md).

## How it is enforced

- **Code gate (gaps).** A behaviour a target does **not** implement yet is a
  typed XFAIL: a [`ParityGap`] row in `PARITY_GAPS`
  ([`contract-tests/src/lib.rs`](src/lib.rs)) cited by an `expect_parity` marker
  at the assertion that depends on it. `tests/parity.rs` fails when a row's issue
  closes, so a gap cannot outlive its fix. This ledger does **not** replace that
  mechanism — a `rust-issue: #N` disposition below points at the same open issue
  a `PARITY_GAPS` row cites.
- **Coverage gate (dispositions).** [`scripts/parity-ledger`](../scripts/parity-ledger)
  (run in CI) lists plugin issues that are **behaviour changes** — those labelled
  [`behaviour-change`](https://github.com/jwulf/c8ctl-plugin-nano/labels/behaviour-change)
  (open or closed), plus (informationally) issues closed since the pinned plugin
  version in [`.github/reference-versions.env`](../.github/reference-versions.env)
  — and **fails** when a labelled one has no row here. That is what stops a new
  JS behaviour change from landing un-dispositioned.

[`ParityGap`]: src/lib.rs

## Disposition vocabulary

Every row carries exactly one disposition:

- **`contract-test: <test path>`** — the behaviour is pinned as an executable
  spec in `contract-tests/`, so both implementations build to it. This is the
  preferred disposition.
- **`rust-issue: #N`** — the Rust worker does not implement it yet; open
  `nano-supervisor` issue `#N` tracks the gap (and, where the behaviour is
  asserted, a `PARITY_GAPS` row + `expect_parity` marker cite the same issue).
- **`n/a: <reason>`** — the change does not alter the engine-observable worker
  contract (e.g. host-sandbox setup, observability/logging, a JS-internal
  control-flow fix), so there is nothing for the Rust worker to mirror. The
  reason names where it was ported when it *was* ported.

## Contract-first for new behaviour

A JS behaviour change should land its `contract-tests` spec (red on Rust is fine
— it is tracked by a `rust-issue` row + `PARITY_GAPS` marker) **before or with**
the JS fix, so both implementations build to one spec. Start new rows at the top.

## Ledger

Backfilled from the fork point (≈ plugin #229 onward). `PR` names the plugin PR
that shipped the behaviour; `Issue` its tracking issue where distinct. Rows for
new behaviour start at the top; the historical backfill follows in descending
issue order after them.

| Plugin change | Behaviour | Disposition |
| --- | --- | --- |
| [jwulf/c8ctl-plugin-nano#274](https://github.com/jwulf/c8ctl-plugin-nano/issues/274) | AgentInstance completion 422s: the producer PATCHes `status:COMPLETED`, but `UPDATE` only accepts active statuses, stranding every instance non-terminal. Completion is the engine's (when the process ends); the worker must not drive it. | `contract-test: tests/worker_resume.rs::agent_instance_stays_active_while_the_process_stays_open` (Node XFAIL, `PARITY_GAPS` / `jwulf/c8ctl-plugin-nano#274`) |
| [jwulf/c8ctl-plugin-nano#289](https://github.com/jwulf/c8ctl-plugin-nano/issues/289) (PR [#291](https://github.com/jwulf/c8ctl-plugin-nano/pull/291)) | AgentInstance transcript: copilot workers never record one ("producer unavailable"), token metrics 0, late completion. On a 409 "already associated" the worker must **adopt** the existing instance and append, not retry a create it cannot win. | `contract-test: tests/worker_resume.rs::agent_instance_creation_conflict_is_adopted_not_retried` (Node XFAIL, `PARITY_GAPS` / `jwulf/c8ctl-plugin-nano#289`) |
| [jwulf/c8ctl-plugin-nano#250](https://github.com/jwulf/c8ctl-plugin-nano/issues/250) | Reactivating a terminal (COMPLETED) AgentInstance re-runs the agent instead of re-settling the job. | `rust-issue: nanobpm/nano-supervisor#59` — engine-observable (reactivating a terminal AgentInstance must re-settle the job, not re-run the agent); #59 explicitly lists #250 under the AgentInstance-producer gap. No reproducible scenario is asserted yet — deliberately not contract-tested until the engine exposes one — but that is a deferred gap tracked by #59, not an `n/a` exemption |
| [jwulf/c8ctl-plugin-nano#244](https://github.com/jwulf/c8ctl-plugin-nano/issues/244) | Support engine-transcript resume when the host SDK exposes only a history surface. | `rust-issue: nanobpm/nano-supervisor#59` — depends on the AgentInstance producer the Rust worker does not have yet |
| [jwulf/c8ctl-plugin-nano#296](https://github.com/jwulf/c8ctl-plugin-nano/pull/296) (closes #295) | Spare SLA-cancelled WIP checkpoints from the orphan GC so a cancelled-mid-run job can still resume. | `rust-issue: nanobpm/nano-supervisor#66` — the cited sweep tests (`tests/worker_sweeps.rs::keep_runs_preserves_completed_run`, `startup_sweep_reaps_stale_runs`) pin the local run-directory reap/keep policy the carve-out refines, but neither exercises recoverable Git refs for an SLA-cancelled element, so this is **not** contract-tested yet |
| [jwulf/c8ctl-plugin-nano#294](https://github.com/jwulf/c8ctl-plugin-nano/pull/294) (closes #293) | Keep the `gh` auth token fresh for a worker's lifetime. | `n/a: not engine-observable` — deliberately NOT a like-for-like port. The plugin refreshes the host's cached `gh auth token`; the Rust worker uses a DIFFERENT credential model: it hands `gh` the job `repo.url` token via `GH_TOKEN` and isolates it from ambient tokens and the host login (src/provision.rs lifts the `user:token@` userinfo out-of-band, scrubs `GH_TOKEN`/`GITHUB_TOKEN`/`GH_HOST`/`GH_REPO`, and points `GH_CONFIG_DIR` at a private empty dir so a stored `hosts.yml`/keychain never authenticates as the operator). No host-token refresh is needed because no host token is used |
| [jwulf/c8ctl-plugin-nano#285](https://github.com/jwulf/c8ctl-plugin-nano/pull/285) | Hoist `preGuardDrainTimedOut` to settlement scope; fail jobs on settlement-path throws. | `n/a: JS-internal control-flow hardening; the Rust worker fences settlement already (tests/worker_lease.rs::settling_commands_are_fenced_by_the_lease_token)` |
| [jwulf/c8ctl-plugin-nano#283](https://github.com/jwulf/c8ctl-plugin-nano/issues/283) (PR [#284](https://github.com/jwulf/c8ctl-plugin-nano/pull/284)) | Set non-interactive `GIT_EDITOR`/`GIT_SEQUENCE_EDITOR` for agent runs so git never blocks on an editor. | `n/a: host-sandbox env setup, ported to src/slot.rs; not an engine-observable worker contract` |
| [jwulf/c8ctl-plugin-nano#275](https://github.com/jwulf/c8ctl-plugin-nano/issues/275) (PR [#276](https://github.com/jwulf/c8ctl-plugin-nano/pull/276)) | `work`: an empty agent job (exit 0, no result) **fails**, never completes; validate the hire command against its protocol. | `contract-test: tests/worker_result.rs` (`empty_result_fails_never_completes`, `empty_agent_turn_is_observably_empty`, `non_empty_result_completes_the_job`) |
| [jwulf/c8ctl-plugin-nano#273](https://github.com/jwulf/c8ctl-plugin-nano/pull/273) | Advertise `harnessProtocol` on the presence REGISTER frame. | `rust-issue: nanobpm/nano-supervisor#59` — the shared-contract gap rides `PARITY_GAPS` / #59. Rust unit evidence exists: `src/hub/client.rs::tests::register_advertises_harness_protocol_version` asserts the worker's REGISTER capability carries the version. But `tests/hub.rs` exercises codec fixtures only (its external-worker replay is unimplemented) and would stay green if the field were removed, so there is **no shared contract** for this yet |
| [jwulf/c8ctl-plugin-nano#270](https://github.com/jwulf/c8ctl-plugin-nano/issues/270) (PR [#271](https://github.com/jwulf/c8ctl-plugin-nano/pull/271)) | review/fix-ci/rebase shapes push their commit to the **PR head**, not a `nano/agent-work` fallback. | `contract-test: tests/worker_finalize.rs` pins the two halves — `provisioned_completion_detects_the_provider_pr` (the provider PR is discovered, not a fallback branch) and `agent_reported_pr_is_forwarded` (an agent-reported PR is forwarded) — and `src/provision.rs::branch_cut_does_not_treat_non_base_pr_head_as_base` (Rust unit) pins the head-advance: a non-base PR head is never treated as the base, so work cannot be pushed past it to the wrong ref |
| [jwulf/c8ctl-plugin-nano#264](https://github.com/jwulf/c8ctl-plugin-nano/issues/264) | Checkpoint interim agent work to a recoverable ref so a job resumes rather than restarts. | `rust-issue: nanobpm/nano-supervisor#66` — `tests/worker_resume.rs::killed_worker_job_resumes_not_restarts` pins engine **redelivery** (same jobKey, full retry budget; it skips Node and deliberately starts the retry from a clean slate), not checkpoint save/restore, so the checkpoint contract is **not** demonstrated yet |
| [jwulf/c8ctl-plugin-nano#262](https://github.com/jwulf/c8ctl-plugin-nano/pull/262) | Record ACP plans and carry them across resume. | `rust-issue: nanobpm/nano-supervisor#78` — the previously cited `killed_worker_job_resumes_not_restarts` covers engine redelivery only: it saves/restores no interim work and emits/restores no ACP plan, so plan continuity is **not** contract-tested |
| [jwulf/c8ctl-plugin-nano#238](https://github.com/jwulf/c8ctl-plugin-nano/issues/238) | Abort the running harness on activation-ownership loss (fence the compute, not just the settlement). | `rust-issue: nanobpm/nano-supervisor#7` — the live-abort contract is **not** contract-tested yet and no narrower issue tracks it; #7 (full per-slot worker parity) carries the port. The Rust worker implements the behaviour (`src/slot.rs`: the lease refresher's 404/409 sets a `lost` watch; `handle` races it against execution and on loss aborts the task — child processes are `kill_on_drop`), and `tests/worker_lease.rs::killed_workers_activation_is_lost_and_redelivered` pins engine redelivery after a **killed** worker's activation lapses — but the worker is dead before the deadline expires, so a **live** worker detecting ownership loss and stopping its harness is not exercised |
| [jwulf/c8ctl-plugin-nano#231](https://github.com/jwulf/c8ctl-plugin-nano/issues/231) | An agent that commits on the base branch with a non-fast-forward push silently strands the work; an unprovisioned run creates **no** fallback branch. | `contract-test: tests/worker_finalize.rs` (`unprovisioned_run_creates_no_fallback_branch`, `provisioned_repo_finalize_pushes_a_fallback_branch`) |
| [jwulf/c8ctl-plugin-nano#230](https://github.com/jwulf/c8ctl-plugin-nano/issues/230) (PR [#234](https://github.com/jwulf/c8ctl-plugin-nano/pull/234)) | Retry a failed `createAgentInstance` (a second-0 lease fence or transient 400) instead of setting `disabled=true` and silently forfeiting the durable transcript for the whole run. | `rust-issue: nanobpm/nano-supervisor#59` — the retry policy lives in the AgentInstance producer the Rust worker does not have yet; lands with the #59 producer port (cf. #289's adopt-on-409, a different create-conflict behaviour) |
| [jwulf/c8ctl-plugin-nano#243](https://github.com/jwulf/c8ctl-plugin-nano/issues/243) (PR [#257](https://github.com/jwulf/c8ctl-plugin-nano/pull/257)) | Capture harness name/version and nano-supervisor (runtime) version as CONFIGURATION-turn provenance in the durable AgentInstance transcript. | `rust-issue: nanobpm/nano-supervisor#59` — provenance is written by the AgentInstance producer the Rust worker does not have yet; lands with the #59 producer port |
| [jwulf/c8ctl-plugin-nano#229](https://github.com/jwulf/c8ctl-plugin-nano/issues/229) | Instrument the AgentInstance producer, transcript relay, and git-finalize silent-failure paths. | `n/a: observability/logging + metrics only; token metrics tracked under #289; no engine-observable worker-contract change` |
| [jwulf/c8ctl-plugin-nano#239](https://github.com/jwulf/c8ctl-plugin-nano/issues/239) (PR [#241](https://github.com/jwulf/c8ctl-plugin-nano/pull/241)) | Resume a re-activated agent job from its durable engine transcript (`agent-resume.mjs` reframes the prompt as a continuation) instead of cold-rerunning, so at-least-once redelivery is a continuation, not a duplicate. | `rust-issue: nanobpm/nano-supervisor#59` — resume consumes the AgentInstance/AgentHistory transcript the Rust worker does not produce or read yet (the #59 producer gap). `tests/worker_resume.rs::killed_worker_job_resumes_not_restarts` pins engine redelivery with a deliberate clean-slate retry, not transcript-seeded continuation |
| [jwulf/c8ctl-plugin-nano#245](https://github.com/jwulf/c8ctl-plugin-nano/issues/245) (PR [#246](https://github.com/jwulf/c8ctl-plugin-nano/pull/246)) | Paginate `searchAgentInstanceHistory` when reading the prior transcript, so the newest turns survive into the seeded resume envelope. | `rust-issue: nanobpm/nano-supervisor#59` — refines the engine-transcript resume path (#239); no Rust transcript reader exists to paginate until the #59 producer/reader lands |
| [jwulf/c8ctl-plugin-nano#247](https://github.com/jwulf/c8ctl-plugin-nano/issues/247) (PR [#249](https://github.com/jwulf/c8ctl-plugin-nano/pull/249)) | Namespace `historyItemId` per activation so a resumed session's restarted ACP ids are not deduped as stale history. | `rust-issue: nanobpm/nano-supervisor#59` — the dedup-naming rule lives in the AgentInstance producer the Rust worker does not have yet; lands with the #59 producer port |
| [jwulf/c8ctl-plugin-nano#258](https://github.com/jwulf/c8ctl-plugin-nano/issues/258) (PR [#259](https://github.com/jwulf/c8ctl-plugin-nano/pull/259)) | Graceful drain wedges forever when the agentic hub is unreachable (0 in-flight, the worker never exits); tear down the half-open agentic client on an interrupted connect so a drained worker can exit. | `rust-issue: nanobpm/nano-supervisor#15` — the agentic-hub client's connect/teardown lifecycle (presence connect, reconnect, `NANO_AGENTIC=off`) is tracked under hub conformance #15; the Rust worker has a hub client (`src/hub/client.rs`) but the interrupted-connect teardown that lets a draining worker exit when the hub is unreachable is not contract-tested yet |
| [jwulf/c8ctl-plugin-nano#254](https://github.com/jwulf/c8ctl-plugin-nano/issues/254) (PR [#256](https://github.com/jwulf/c8ctl-plugin-nano/pull/256)) | Surface an operator-facing `settlement-pending` JOB state for a job stuck between an agent's external side effect and broker settlement (the fenced settle was rejected after the activation lease was lost). | `n/a: observational status change` — purely operator-facing visibility in `supervisor status`; it records the in-flight settle outcome the worker already knows (a bounded ghost map, never counted busy/in-flight) and changes no engine-observable worker-contract behaviour. Recovery itself is owned by the lease-fence + transcript-resume path (#221/#236/#241), not this status |
| [jwulf/c8ctl-plugin-nano#253](https://github.com/jwulf/c8ctl-plugin-nano/pull/253) | Hot code reload: `nano supervisor reload` / `nano workforce reload` roll updated harness code into a running fleet by draining + respawning each worker one at a time (zero fleet downtime, no in-flight job killed). | `rust-issue: nanobpm/nano-supervisor#8` — a supervisor/daemon fleet-lifecycle capability, not an engine-observable job-worker contract; the Rust daemon answers the `reload` control op "not yet implemented on the Rust supervisor" (`src/control.rs`), and daemon parity (control socket + reload) is tracked under #8 |
| [jwulf/c8ctl-plugin-nano#222](https://github.com/jwulf/c8ctl-plugin-nano/issues/222) (PR [#236](https://github.com/jwulf/c8ctl-plugin-nano/pull/236)) | Make agent-run **setup** abort-aware: a definitive lease loss (or `stop --force`) that wins the race *during setup* stops the whole run before any transcript-husk (`lifecycle/open`) or repository side effect, instead of letting the abandoned run continue. | `rust-issue: nanobpm/nano-supervisor#7` — the setup-phase abort is structurally present in Rust (`src/slot.rs`: the whole `execute` task — provisioning, prompt setup, agent run — is raced against the lease-loss watch in `handle`'s `select!`, and a loss aborts it; child processes are `kill_on_drop`), but no contract test exercises a lease loss *during setup* specifically (`tests/worker_lease.rs::killed_workers_activation_is_lost_and_redelivered` kills the worker mid-**run**, after the agent has started). Distinct from #238's running-harness abort; the setup-phase variant rides the same per-slot parity port under #7 |
| [jwulf/c8ctl-plugin-nano#235](https://github.com/jwulf/c8ctl-plugin-nano/issues/235) (PR [#242](https://github.com/jwulf/c8ctl-plugin-nano/pull/242)) | Single-convention scan on an external `agentDefinition` for external-agent discovery, plus an `autoSubscribe` opt-out namespace. | `n/a: plugin-side agentDefinition discovery convention + autoSubscribe opt-out namespace` — the Rust worker subscribes to job types from explicit hire configuration rather than scanning external `agentDefinition`s, so there is no engine-observable worker-contract change to mirror |
| [jwulf/c8ctl-plugin-nano#189](https://github.com/jwulf/c8ctl-plugin-nano/issues/189) (PR [#237](https://github.com/jwulf/c8ctl-plugin-nano/pull/237)) | Honour the per-invocation `--profile` connection override for `work`/`supervisor` instead of silently using the active c8ctl session profile. | `n/a: host-side connection-profile selection (which cluster to dial), not an engine-observable job-worker contract` — the Rust worker honours an explicit `--profile` over the mutable active session and pins it (`src/work.rs`, `src/profile.rs`; issue #41), covered by `tests/pin.rs` (an explicit `--profile` re-pins; `moved_active_profile_does_not_retarget_a_pinned_worker`) |
| [jwulf/c8ctl-plugin-nano#263](https://github.com/jwulf/c8ctl-plugin-nano/pull/263) | Honour an ACP `_meta.outcome` end-of-task report: record it as `io.nanobpm.agentResult.outcome`; a `blocked` outcome with no result file/stdout arms the escalation vars. | `rust-issue: nanobpm/nano-supervisor#60` — engine-observable, so NOT `n/a`: `src/acp.rs::outcome_result_vars` maps a `blocked` outcome into result variables (incl. `question`) and `src/slot.rs` uses them as a result fallback. Ported with Rust unit coverage (`src/acp.rs` `prompt_outcome_*` / `outcome_result_vars_maps_only_blocked`; `src/result.rs` `not_empty_with_explicit_outcome`, `select_effective_uses_acp_outcome_fallback`), but the fake-agent emits no ACP `_meta.outcome` step so there is **no cross-target contract test** yet; #60 (zero unwaived gaps before cutover #11) tracks adding one |

## Rust-side producer gap

The Rust worker has no AgentInstance/AgentHistory **producer** yet, so several
rows above depend on it. That gap is tracked as a single `PARITY_GAPS` row and
open issue:

| Behaviour | Target | Issue |
| --- | --- | --- |
| No AgentInstance producer (job transcript is local-only) | rust | [nanobpm/nano-supervisor#59](https://github.com/nanobpm/nano-supervisor/issues/59) |

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
