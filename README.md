# nano-supervisor
Standalone Rust supervisor and job workers for Nano BPM coding agents (replaces c8ctl nano supervisor/work)

- `nano-supervisor daemon` — the MVP daemon: N slots per hire (from `config.json`),
  one shared engine connection, host sandbox, ACP + pipe protocols. See
  [`daemon/README.md`](daemon/README.md).
- `nano-supervisor spike` — one worker slot, for memory/architecture measurement.
  See [`spike/README.md`](spike/README.md).

