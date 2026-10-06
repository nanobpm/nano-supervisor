# nano-supervisor daemon (issue #6)

`nano-supervisor daemon` is the first real daemon: it runs **N capacity-1 slots
per hire** as tokio tasks that share **one** engine connection, next to the Node
supervisor on a single hire, to gather real-world evidence early.

Each slot is a worker that services one hire's rank×capability job-type matrix,
one job at a time. It reuses the leased activation + lease-refresh fencing
(`src/jobs.rs`, `src/slot.rs`) proven by the spike and adds the MVP job
handling: prompt assembly, repo clone, ACP **and** pipe protocols, result-file /
`::nano:result::` parsing, and the empty-result → fail guard.

## What it does

- **Hires** are read from the existing `config.json` (the c8ctl-nano state home,
  `$C8CTL_NANO_HOME` or the platform data dir). Each hire's `rank` + sorted
  `capabilities` expand to the job-type matrix (`rank`, `rank:cap`,
  `rank:cap1+cap2`).
- **Connection** settings come from c8ctl profiles (`--profile`, else the active
  profile, else `CAMUNDA_*` env) — resolved **once** and **pinned** in
  `<state home>/supervisor.json` (`connection: {profile, baseUrl}`, issue #41).
  Every later start reuses the pin, so a moved `activeProfile` (e.g. an agent's
  `c8 use profile`) can never silently retarget the fleet; drift between the
  pin and the session is warned about loudly at startup, and the startup banner
  names the engine (`engine: <profile> (<baseUrl>)`). Job commands always use
  the `camunda-orchestration-sdk` transport (the same one the Node plugin uses).
  Agents additionally run with `C8CTL_DATA_DIR` pointed at an isolated per-run
  dir so their `c8 use profile` writes stay in the run, never touching the
  operator's global session. Because `C8CTL_DATA_DIR` is c8ctl's whole user-data
  root, this also hides operator-installed `c8` plugins (e.g. `c8 nano`) from
  agents — an accepted MVP tradeoff (agents run `NANO_AGENTIC=off` and
  `guard_nested_supervisor` blocks nested fleets); a narrower lever is tracked
  in [#51](https://github.com/nanobpm/nano-supervisor/issues/51).
  **Lease compatibility:** the daemon **leases by default** — the SDK speaks the
  Camunda 8.10 spec field names, so leasing needs an engine that returns the
  lease as `jobLeaseToken` (Nano engine ≥ v0.0.24 does; see `src/jobs.rs`). An
  engine that still returns only the legacy `leaseToken` field gives the SDK no
  lease to carry, so activations arrive unleased and the daemon shuts down
  loudly rather than run unfenced — such an engine is incompatible with the
  default leasing (pass `--no-lease` to run unfenced on one).
- **Own worker names** — `‹host›-nanod-‹hire›-‹slot›` — so the daemon's jobs are
  told apart from the Node workers' (`‹host›-‹hire›-‹random›`).
- **Host sandbox only**; a container-sandbox hire is skipped with a warning. A
  `pipe` hire whose command actually selects ACP is refused (issue #275).
- **`NANO_AGENTIC=off`** is set for every agent (no visibility channel in the MVP).
- A **panic in one slot fails only that job**: each job runs on its own task and
  a join error is turned into a job failure (retries preserved); the slot loops on.
- Agents run in **their own process group** and **die with the daemon**:
  `PR_SET_PDEATHSIG` on Linux, a kqueue watchdog on macOS — so a `kill -9` of the
  daemon leaves **no orphaned agent processes**.
- **Refuses to nest inside an agent run** (#40): the worker stamps
  `NANO_AGENT_RUN=<job key>` (and `NANO_AGENT_RUN_DIR`) on every agent's
  environment, and `nano-supervisor daemon` / `work` refuse to start when that
  variable is set — exiting non-zero with an explanation. Left unguarded, an
  agent could start its own supervisor/worker and build an unintended nested
  fleet that leases real jobs outside the job's lifecycle; refusing to start
  closes that hole. The hermetic contract
  tests opt in with `--foreground-for-tests` (or `NANO_ALLOW_NESTED_SUPERVISOR=1`)
  to run **attached** — staying in the invoking process group, so the job's
  teardown still kills it: on
  **Linux** the attached process is bound to the invoking process via
  `PR_SET_PDEATHSIG` (and startup fails if that binding cannot be installed);
  on **macOS** there is no `PR_SET_PDEATHSIG`, so containment relies on staying
  in the invoking process group — the job's process-group kill takes it down.
- **Lease-fenced settling**: a 404/409 on lock refresh is treated as a lost
  activation — the agent is stopped and the job is **not** settled, so no job is
  ever settled without its lease.

## Run it against a throwaway local cluster

Never point this at a production engine: it takes any job matching a hire's matrix.

```sh
c8 nano start                                   # local cluster on :8080
# hire an agent first (persists into config.json):
c8 nano hire --name coder --rank senior --command copilot --capabilities pr-review

cargo build --release
target/release/nano-supervisor daemon --profile local --slots 1
```

Useful flags (all optional): `--hire <name>` (repeatable) to run a subset,
`--slots N`, `--no-lease` (run unfenced; leasing is on by default),
`--recovery-window`/`--idle-timeout`/`--poll-timeout`/`--clone-timeout`
(ms), `--runs-dir <dir>`, `--config <path>`.

## Run as a systemd user service (omarchy)

`nano-supervisor.service` in this directory is a hand-written user unit (the
`install` command lands in the daemon-parity issue). Install and start it with:

```sh
mkdir -p ~/.config/systemd/user
cp daemon/nano-supervisor.service ~/.config/systemd/user/
# edit ExecStart if the binary isn't on PATH or you want a specific --profile
systemctl --user daemon-reload
systemctl --user enable --now nano-supervisor
journalctl --user -u nano-supervisor -f
```

`KillMode=control-group` means `systemctl --user stop` (or a crash) tears down
the whole cgroup — the daemon, its slots, and every agent process group — which,
together with the parent-death cleanup above, is why stopping the service leaves
nothing behind.

## Trial (acceptance)

Running the `nano-coder` hire on `senior:pr-review` beside the Node supervisor on
omarchy for at least a week — and posting the outcome numbers on #1 — is an
operational task that needs a go-ahead from @jwulf before it runs beside the live
fleet. It is tracked separately; the daemon here is what makes it possible.
