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

The per-fix coverage table now lives in the **parity ledger**,
[`PARITY.md`](PARITY.md): one row per behaviour-changing plugin issue or PR, each
with a disposition (`contract-test: <path>` | `rust-issue: #N` | `n/a: <reason>`).
It is backfilled from the fork point and CI-checked by
[`scripts/parity-ledger`](../scripts/parity-ledger), which fails when a plugin
issue labelled `behaviour-change` has no ledger row — so a new JS behaviour
change cannot land un-dispositioned.

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
