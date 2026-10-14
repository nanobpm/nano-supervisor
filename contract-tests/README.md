# contract-tests

Black-box contract tests for the Nano job worker. The suite runs the CLIs as
subprocesses, reads and writes their state files, and talks to the engine REST
API. It never links to `nano-supervisor` internals, so the same test runs
against `c8 nano work` (Node) and `nano-supervisor` (Rust).

> **Harness ownership.** The shared harness (`Target`, `TempHome`, `Engine`,
> redaction) belongs to issue #3. Until #3's skeleton PR lands, this crate
> carries a faithful, additive copy so it builds on its own; rebase onto #3 when
> it merges and keep `lib.rs` changes additive.
>
> This suite (issue #4) owns `src/bin/fake-agent.rs` and `tests/worker_*.rs`.

## Layout

```
src/lib.rs              harness: Target, TempHome, Engine, redaction, job runner
src/bin/fake-agent.rs   the scripted stand-in for Copilot/nano-coder (ACP + pipe)
src/bpmn.rs             a one-task BPMN generator for engine tests
tests/fake_agent.rs     the fake agent's own contract (runs in CI, no engine)
tests/worker_*.rs       one file per area of the job-worker contract
fixtures/ snapshots/    BPMN, recorded frames and golden files
```

## The fake agent

`fake-agent` is a scripted stand-in for Copilot / nano-coder. It speaks **ACP**
(`--acp`, the same JSON-RPC handshake `src/acp.rs` drives) and **pipe** mode
(prompt on stdin, output on stdout, result via `AGENT_RESULT_FILE` /
`::nano:result::`).

- **Scripted** with `NS_FAKE_SCRIPT` (inline JSON or `@file`): a JSON array of
  steps — `{"emit": "text"}`, `{"tool_call": {…}}`, `{"request_permission": {…}}`,
  `{"write_result": <json>}`, `{"result_marker": <json>}`, `{"sleep_ms": n}`,
  `{"go_silent": n}` (silence → the worker's idle timeout), `{"exit": code}`,
  `{"crash": true}`, `{"stop_reason": "…"}`.
- **Records** what it received to `NS_FAKE_RECORD`: argv, the `AGENT_*` / `NANO_*`
  environment, the working directory, the prompt and any steers, the client's
  `initialize` / `session/new` params, and the permission requests it raised.

## Running it

```sh
c8 nano start                                              # local cluster; never merlin
NS_TARGET=node cargo test -p contract-tests                # today's plugin
NS_TARGET=rust NS_BIN=target/debug/nano-supervisor cargo test -p contract-tests
```

Engine-dependent tests read `NS_ENGINE_URL` (default `http://localhost:8080`).
It refuses anything that is not localhost / 127.0.0.1 unless
`NS_ALLOW_REMOTE_ENGINE=1` — **never point it at merlin**. When no engine is
reachable, those tests **skip with a message** (look for `SKIP`), they do not
fail. A behavior a target has not implemented yet is a **typed XFAIL** (see
[Parity gaps](#parity-gaps-typed-xfail-issue-60--59)), also not a failure. The
fake-agent and redaction tests run with no engine, so CI stays green.

## Issue-numbered worker fixes covered

Every issue-numbered fix in the plugin's worker code that changes behavior gets a
test. Keep this list current as tests are added:

| Fix | Behavior | Test |
| --- | --- | --- |
| jwulf/c8ctl-plugin-nano#275 | Empty agent result → **fail**, never complete | `worker_result::empty_result_fails_never_completes`, `worker_result::empty_agent_turn_is_observably_empty` |
| nanobpm/nano-bpm#1283 | Lease token name mismatch (`leaseToken` vs `jobLeaseToken`): the worker takes a lease on every activation (engine 0.0.24 issues `jobLeaseToken`) | `worker_lease::*` |
| Settlement fencing | Complete/fail are fenced by the lease token and land exactly once | `worker_lease::settling_commands_are_fenced_by_the_lease_token` |
| Refresh cadence | Refresh the activation every third of `--recovery-window` | `worker_lease::leased_worker_refreshes_every_third_of_the_window` |
| Nudge | Nudge an agent that stops without a result | `worker_result::stop_without_result_is_nudged` |
| Finalize / PR vs fallback | An agent-reported PR is forwarded; an **unprovisioned** run creates no fallback branch | `worker_finalize::agent_reported_pr_is_forwarded`, `worker_finalize::unprovisioned_run_creates_no_fallback_branch` |
| Reclaim / reap sweeps | Startup and periodic sweeps reap stale runs (`--reap-age`, `--reap-interval`, `--keep-runs`) | `worker_sweeps::startup_sweep_reaps_stale_runs` |
| Disk-space check | `--min-free-mb` is the container disk floor; it does **not** gate host-sandbox runs (Node behaviour) | `worker_sweeps::min_free_mb_does_not_gate_host_runs` |
| Checkpoint / resume | A job resumes after its worker is killed mid-run | `worker_resume::killed_worker_job_resumes_not_restarts` |
| AgentInstance producer (issue #59) | A worker records an engine **AgentInstance** for its job (transcript = the durable artifact), not just a local run dir | `worker_resume::job_writes_an_agent_instance_record` |
| AgentInstance on conflict (jwulf/c8ctl-plugin-nano#289) | When the element instance is **already associated**, the worker adopts the existing AgentInstance and appends its turn instead of retrying a create it cannot win | `worker_resume::agent_instance_creation_conflict_is_adopted_not_retried` |
| Engine-owned AgentInstance completion (jwulf/c8ctl-plugin-nano#274) | While the process **stays open**, the AgentInstance stays ACTIVE and the worker does **not** send/retry the unsupported `status:COMPLETED` update (completion is the engine's, when the process ends) | `worker_resume::agent_instance_stays_active_while_the_process_stays_open` |

Where the Node plugin's observed behavior looks like a bug, the test captures it
anyway, marks it `// NODE-QUIRK: <issue link>`, and it is raised on issue #1
rather than silently "fixed" in the test.

## Parity gaps (typed XFAIL, issue #60 / #59)

A behavior a target does **not** implement yet is recorded in `PARITY_GAPS`
(`contract-tests/src/lib.rs`) with the issue that tracks it, and asserted at the
call site:

```rust
let check = /* Ok(()) if the behavior holds, Err(why) if not */;
assert_parity(expect_parity(target, Some("owner/repo#123"), check), || why);
```

`expect_parity` turns a failure under a declared gap into `XFAIL` (not a
regression) and a *pass* under one into `XPASS` — the marker is stale and must go.
`tests/parity.rs` fails when any `PARITY_GAPS` row cites a **closed** issue, so a
gap cannot outlive its fix. Look for `XFAIL`/`XPASS`/`SKIP` in `--nocapture`
output.

| Gap | Target | Issue |
| --- | --- | --- |
| No AgentInstance producer yet (job transcript only local) | rust | nanobpm/nano-supervisor#59 |
| Create conflict (409) is retried, not adopted | node | jwulf/c8ctl-plugin-nano#289 (fixed in 1.70.3) |
| Producer drives the terminal AgentInstance update the engine owns (422s, instance stranded) | node | jwulf/c8ctl-plugin-nano#274 |

#250 (reactivating a terminal AgentInstance re-runs the agent) has **no
reproducible scenario yet**, so it is deliberately not asserted here; it is a
follow-up once the engine exposes one.
