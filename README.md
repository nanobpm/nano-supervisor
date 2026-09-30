# nano-supervisor
Standalone Rust supervisor and job workers for Nano BPM coding agents (replaces c8ctl nano supervisor/work)

- `nano-supervisor daemon` — the MVP daemon: N slots per hire (from `config.json`),
  one shared engine connection, host sandbox, ACP + pipe protocols. See
  [`daemon/README.md`](daemon/README.md).
- `nano-supervisor spike` — one worker slot, for memory/architecture measurement.
  See [`spike/README.md`](spike/README.md).

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
