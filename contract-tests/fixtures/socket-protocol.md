# Control-socket protocol (`supervisor.sock`) — c8ctl-plugin-nano 1.70.1

Recorded from the Node plugin. The Rust `nano-supervisor` must speak the same
protocol so a Node client can drive a Rust daemon and vice-versa during the
switch-over.

## Transport

- A Unix domain socket. Path: `join(tmpdir(), "c8ctl-nano-sup-<h>.sock")`, where
  `<h>` is the first 8 hex chars of `sha1(C8CTL_NANO_HOME)`. **It lives in the
  system temp dir, not under the home** (recorded quirk — the daemon also
  records the chosen path in `supervisor.json.socket`, which clients prefer).
- **Framing**: newline-delimited JSON (NDJSON) — `JSON.stringify(obj) + "\n"`
  per frame, in both directions. Blank lines are ignored; malformed lines are
  skipped.
- **Request**: a single JSON object with an `op` field.
- **Response**: one or more frames. The client reads until the first frame with
  `"final": true`. Streaming ops (`reload`, `stop`) emit interim frames first.

## Requests and responses, by `op`

| `op` | Request fields | Terminal reply |
|---|---|---|
| `status` | — | `{ ok, type:"status", daemon, pluginVersion, workers[], final:true }` |
| `add` | `profile` (required), `args?` (string[]), `name?` | `{ ok:true, type:"added", worker, final:true }` — or `{ ok:false, error, final:true }` |
| `remove` | `target` (id\|profile\|"all"), `force?` (default true) | `{ ok:true, type:"removed", removed[], draining, final:true }` |
| `restart` | `target` | `{ ok:true, type:"restarted", restarted[], final:true }` |
| `reload` | `target` or `targets[]` | interim `{type:"reloading",targets}`, `{type:"status"}`, worker events; terminal `{ ok:true, type:"reloaded", reloaded[], skipped[], final:true }` |
| `attach` | — | `{ type:"status" }` then a live event stream (no `final`) |
| `stop` | `force?` | interim `{type:"draining"}` or `{type:"stopping",force:true}`, `{type:"status"}`; terminal `{type:"stopped", final:true}` |
| _unknown_ | — | `{ ok:false, error:"unknown op \"<op>\"", final:true }` |

### Error frames

Every op returns `{ ok:false, error:"<message>", final:true }` on failure — e.g.
`add` with no profile, `add`/`remove`/`restart`/`reload` while shutting down,
`reload` on Windows or when one is already in progress. See
`socket-status-frame.json` for the shape of a live `status` reply (redacted).

### `daemon` descriptor (in `status`)

`{ pid, startedAt, version, socket, logFile }`.

### `worker` object (in `status.workers[]` and `added.worker`)

`{ id, profile, pid, state, restarts, uptimeMs, startedAtMs, lastExit, args,
logFile, activity:{state,jobs[]}, engine, agentic:{status,mode,url,discovered,message} }`.

> Recording the live frame connects a worker to the engine/agentic hub the host
> is configured for. Tests therefore never start a real worker on shared
> infrastructure: the live round-trip in `tests/socket.rs` is opt-in
> (`NS_ALLOW_LIVE_SUPERVISOR=1`), engine-gated to localhost, and pins
> `NANO_BASE_URL` + `NANO_AGENTIC=off` so it cannot reach a real fleet.
