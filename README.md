# nano-supervisor
Standalone Rust supervisor and job workers for Nano BPM coding agents (replaces c8ctl nano supervisor/work)

- `nano-supervisor daemon` — the MVP daemon: N slots per hire (from `config.json`),
  one shared engine connection, host sandbox, ACP + pipe protocols. See
  [`daemon/README.md`](daemon/README.md).
- `nano-supervisor work <hire>` — one worker for a hired profile, the Rust
  `c8 nano work <profile>`. See [`spike/README.md`](spike/README.md).

## Leases

Both workers run the same leased activation + lease-refresh fencing
(`src/jobs.rs`, `src/slot.rs`). Every activation asks for a lease (engine ≥
0.0.24 issues `jobLeaseToken`, which the SDK carries) and is refreshed every
third of `--recovery-window`. A 404/409 on refresh is a lost activation: the
agent is stopped and the job is **not** settled, so no job is ever settled
without its lease.

The two workers differ only in what they do when the engine issues **no** token:

- `daemon` **leases by default** and refuses to run unfenced — an unleased
  activation shuts the slot down loudly. Pass `--no-lease` to run unfenced.
- `work` requests a lease too but, like the Node plugin, runs unfenced when the
  engine does not issue one.

## Contract tests

`contract-tests/` is a black-box suite (issues #3/#4/#5) that pins the fleet
surface — the CLI commands, state files and control socket — as an executable
spec. It runs the CLIs as subprocesses, so the same tests describe the Node
plugin today and `nano-supervisor` after the port. Select the target with one
variable:

```sh
# Today's Node plugin (default target):
NS_TARGET=node cargo test -p contract-tests

# The Rust binary:
cargo build
NS_TARGET=rust NS_BIN=target/debug/nano-supervisor cargo test -p contract-tests
```

Each test uses an isolated `C8CTL_NANO_HOME` in a temp dir and never touches a
real fleet. Engine-backed and live-supervisor cases skip cleanly when no local
cluster is reachable (`NS_ENGINE_URL`, default `http://localhost:8080`); the CLI,
state-file and socket-schema cases need no engine. When the target CLI is not
installed, its cases skip with a message. See
`contract-tests/fixtures/socket-protocol.md` for the recorded control-socket
protocol.
