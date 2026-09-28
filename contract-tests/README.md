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
fail. The fake-agent and redaction tests run with no engine, so CI stays green.

## Issue-numbered worker fixes covered

Every issue-numbered fix in the plugin's worker code that changes behavior gets a
test. Keep this list current as tests are added:

| Fix | Behavior | Test |
| --- | --- | --- |
| jwulf/c8ctl-plugin-nano#275 | Empty agent result → **fail**, never complete | `worker_result::empty_result_fails_never_completes`, `worker_result::empty_agent_turn_is_observably_empty` |
| nanobpm/nano-bpm#1283 | Lease token name mismatch (`leaseToken` vs `jobLeaseToken`); leased commands go over Nano's dialect | `worker_lease::*` |
| Last-activation guard | Losing the lease (404/409 on refresh) stops the agent and does **not** settle the job | `worker_lease::losing_the_lease_stops_the_agent_without_settling` |
| Refresh cadence | Refresh the activation every third of `--recovery-window` | `worker_lease::leased_worker_refreshes_every_third_of_the_window` |
| Nudge | Nudge an agent that stops without a result | `worker_result::stop_without_result_is_nudged` |
| Finalize / fallback branch | No PR → fall back to a `nano/agent-work/…` branch | `worker_finalize::no_pr_falls_back_to_nano_agent_work_branch` |
| Reclaim / reap sweeps | Startup and periodic sweeps reap stale runs (`--reap-age`, `--reap-interval`, `--keep-runs`) | `worker_sweeps::startup_sweep_reaps_stale_runs` |
| Disk-space check | `--min-free-mb` gates taking work | `worker_sweeps::min_free_mb_gates_work` |
| Checkpoint / resume | A job resumes after its worker is killed mid-run | `worker_resume::killed_worker_job_resumes_not_restarts` |

Where the Node plugin's observed behavior looks like a bug, the test captures it
anyway, marks it `// NODE-QUIRK: <issue link>`, and it is raised on issue #1
rather than silently "fixed" in the test.
