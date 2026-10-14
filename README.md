# nano-supervisor
Standalone Rust supervisor and job workers for Nano BPM coding agents (replaces c8ctl nano supervisor/work)

- `nano-supervisor daemon` — the MVP daemon: N slots per hire (from `config.json`),
  one shared engine connection, host sandbox, ACP + pipe protocols. See
  [`daemon/README.md`](daemon/README.md).
- `nano-supervisor supervisor start|status|stop` — start the daemon (detached),
  query it over the control socket, or drain and stop it (`stop --force` cancels
  in-flight work immediately instead of draining). Only one daemon may own a
  given state home at a time: a second `start` for the same home refuses rather
  than racing the first off its control socket. The control socket
  (`supervisor.sock`) speaks the Node daemon's NDJSON protocol, so a Node client
  can drive a Rust daemon and vice-versa (`src/control.rs`,
  [`contract-tests/fixtures/socket-protocol.md`](contract-tests/fixtures/socket-protocol.md)).
- `nano-supervisor work <hire>` — one worker for a hired profile, the Rust
  `c8 nano work <profile>`. See [`spike/README.md`](spike/README.md).

## Leases

Both workers run the same leased activation + lease-refresh fencing
(`src/jobs.rs`, `src/slot.rs`). Every activation asks for a lease (engine ≥
0.0.24 issues `jobLeaseToken`, which the SDK carries) and is refreshed every
third of `--recovery-window`. A 404/409 on refresh is a lost activation: the
agent is stopped and the job is **not** settled, so a *leased* activation is
never settled after losing its lease. (This says nothing about unleased runs:
`work`, and `daemon --no-lease`, settle activations the engine never leased —
see below.)

The two workers differ only in what they do when the engine issues **no** token:

- `daemon` **leases by default** and refuses to run unfenced — an unleased
  activation shuts the slot down loudly. Pass `--no-lease` to run unfenced.
- `work` requests a lease too but, like the Node plugin, runs unfenced when the
  engine does not issue one.

## The pinned connection (issue #41)

The supervisor never follows c8ctl's **mutable active profile** more than once.
On its first start, `daemon`/`work` resolves the connection — an explicit
`--profile`, else the active profile, else the `CAMUNDA_*` env — and records it
in `<state home>/connection.json` as `connection: {profile, baseUrl}` (the
baseUrl is the fingerprint). This is a **dedicated, Rust-owned file**, kept
separate from the shared `supervisor.json` that the external Node supervisor
(`c8ctl-plugin-nano`) rewrites on every worker persist and deletes on stop — so
the pin's durability never depends on the Node side's state lifecycle. Every
later start of the same state home reuses
the **pinned** profile, so an agent's (or anyone's) `c8 use profile` cannot
retarget the fleet on its next restart; an explicit `--profile` re-pins. Both
processes lead their startup output with `engine: <profile> (<baseUrl>)` and
warn loudly when the session's active profile has drifted from the pin, or when
the pinned profile's baseUrl no longer matches the fingerprint. For an env-only
pin (no c8ctl profile) the recorded baseUrl fingerprint is **enforced**: a
later start whose `CAMUNDA_REST_ADDRESS` drifted keeps connecting to the pinned
engine and warns, instead of silently following the env. A worker whose
job types are all test-looking (`probe-*`/`ct-*`) logs a prominent warning
naming the engine on its first live activation.

Agents are quarantined from the operator's c8ctl session: every agent runs with
`C8CTL_DATA_DIR` pointed at an isolated per-run dir (`<run dir>/c8ctl`) —
created for **every** job and seeded with the pinned connection: a
`session.json` whose `activeProfile` names the pinned profile and a
`profiles.json` carrying only that profile's non-secret connection identity.
An env-only pin (no c8ctl profile) is **synthesized** into a stable `pinned`
profile from the recorded baseUrl, so the agent's `c8` still resolves exactly
the pinned engine (the dir is never left empty). An agent's `c8 use profile` /
`c8 profile add` writes stay inside its run and the operator's
`~/.config/c8ctl/session.json` is never touched.

`C8CTL_DATA_DIR` is c8ctl's **entire** user-data root, so relocating it to
isolate `session.json`/`profiles.json` would also hide the operator's installed
`c8` plugins (e.g. `c8 nano`), which live under `<data dir>/plugins` — and
c8ctl exposes no narrower lever (it ignores `C8CTL_CONFIG_DIR`). To isolate the
session **without** hiding plugins, the seeder links the operator's real plugins
dir back into the per-run root as `<run dir>/c8ctl/plugins` → `<default data
dir>/plugins`, so the agent's `c8` resolves plugins from the operator's install
while its `session.json`/`profiles.json` writes stay quarantined in the run dir.
The link is created by the worker (never the agent), and only when the operator
actually has a plugins dir to share. On Linux it goes through the same pinned
no-follow handle as the seed files; on other platforms (e.g. macOS) the seeder
uses a path-based fallback that still fails closed on a symlinked `c8ctl` leaf,
so the pinned-handle guarantee is Linux-only. The seed files themselves stay
**real files** (never links), so `c8 use profile` can never escape the run dir
([#51](https://github.com/nanobpm/nano-supervisor/issues/51)).

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

### Reference versions and JS-drift detection (issue #58)

The Node reference the suite pins against — the `c8ctl-plugin-nano` release and
the `@camunda8/cli` host version — lives in **one** place,
[`.github/reference-versions.env`](.github/reference-versions.env). CI
(`contract-tests-node`/`contract-tests-rust`) and
[`start-nano-engine.sh`](.github/scripts/start-nano-engine.sh) all read it, so a
pin is bumped by editing that single file.

A nightly job,
[`contract-drift.yml`](.github/workflows/contract-drift.yml) (`schedule:` +
`workflow_dispatch`), runs the Node-target suite against the **latest** plugin
release and the **latest** CLI alpha instead of the pin. A failure means JS
behaviour has moved; it never blocks PRs — it opens or updates a tracking issue
(label `contract-drift`) listing the failing tests, and closes it when the run
goes green again. When the drift job is red, bump the pins in a deliberate PR
that also refreshes the snapshots/tests and adds parity-ledger rows.
