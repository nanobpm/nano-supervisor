//! The worker-side agentic-hub client: ONE WebSocket per daemon, multiplexed
//! across every slot (mirroring how `@nanobpm/agentic/emit`'s `AgenticEmitClient`
//! does it in the Node plugin).
//!
//! A single background task owns the connection. It reconnects with jittered
//! exponential backoff, and while the hub is down outbound frames accumulate in
//! a bounded, QoS-aware ring buffer (per-lane FIFO; overflow sheds the
//! least-important lane first so a bulk transcript flood can never evict a
//! control frame) so the job keeps running and the transcript resumes on
//! reconnect without unbounded memory growth.
//!
//! The protocol is the live twin of the Node emit client's wire:
//!
//!   - worker **presence** is a `register {instance, capability}` /
//!     `heartbeat {instance}` / `deregister {instance, reason}` family;
//!   - job **ownership** is a separate `claim {instance, jobKey}` /
//!     `release {instance, jobKey}` family;
//!   - a job's **transcript** rides the `relay` family as
//!     `{op: "produce", stream, incarnation, chunk}`, where `stream` is the
//!     per-`(instance, jobKey)` composed stream id and `incarnation` is the
//!     producer generation (bumped on every reconnect so a resumed producer
//!     fences its stale predecessor);
//!   - **inbound steer** is a `relay {stream, …chunk}` delivery routed to the
//!     one job owning that stream (foreign/invalid streams are dropped, never
//!     broadcast), decoded to a typed control and applied to the running turn.
//!
//! Each running job registers a [`HubSession`]: it REGISTERs its worker
//! instance (once), CLAIMs the job, bridges the agent's ACP `session/update`
//! stream to transcript produce frames, and receives inbound steer routed to
//! it. The session RELEASEs the job when dropped.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep, timeout};

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

use crate::hub::config::HubConfig;
use crate::hub::control::{parse_inbound_relay_chunk, ControlFrame};
use crate::hub::frame::{decode_frame, encode_frame, Family, Frame, Lane};
use crate::hub::stream::{compose_stream_id, parse_stream_id};
use crate::hub::transcript::acp_update_to_transcript_chunk;
use crate::runtime::log;

/// First reconnect delay after a dropped/failed hub connection.
const BACKOFF_BASE: Duration = Duration::from_millis(500);
/// Ceiling on the reconnect backoff.
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How often the client sends a presence heartbeat while connected.
const HEARTBEAT: Duration = Duration::from_secs(15);
/// Ceiling on a single connect/handshake attempt. Without it a hung TCP/TLS or
/// WebSocket handshake would park the connection task indefinitely, wedging both
/// reconnect backoff and a requested shutdown (which only lands between attempts).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on the ACP-update → transcript bridge channel. It sits in front of the
/// already-bounded outbound [`LaneBuffer`], so leaving it unbounded would let a
/// fast agent's `session/update` stream (each frame up to ~1 MiB) grow without
/// limit and defeat the buffer's memory cap. On overflow the producer drops the
/// update rather than blocking the ACP read loop (see `acp.rs`).
const TRANSCRIPT_CHANNEL_BOUND: usize = 1024;
/// Bound on each session's inbound-steer channel. A hub delivering controls
/// faster than the ACP turn consumes them (e.g. while setup or the agent is
/// stalled) must not grow daemon memory without limit, so the channel is
/// bounded and `route_inbound` drops the control on overflow rather than
/// blocking the socket read loop.
const STEER_CHANNEL_BOUND: usize = 256;
/// Ceiling on how long `HubSession::drop` waits for the transcript bridge to
/// drain its accepted updates before RELEASE (finding: RELEASE must not
/// overtake the transcript tail). Bounded so a wedged bridge can never hang the
/// dropping task; on timeout the RELEASE proceeds (the tail is best-effort).
const TRANSCRIPT_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// A bounded, QoS-aware outbound buffer: one FIFO queue per lane, with a single
/// shared capacity. Draining prefers control → interactive → bulk; overflow
/// eviction sheds the least-important non-empty lane first (bulk, then
/// interactive, then control), so a bulk transcript flood can never displace a
/// `register`/`claim`/`deregister` control frame and break presence.
#[derive(Default)]
struct LaneBuffer {
    control: VecDeque<Frame>,
    interactive: VecDeque<Frame>,
    bulk: VecDeque<Frame>,
    capacity: usize,
}

impl LaneBuffer {
    fn with_capacity(capacity: usize) -> LaneBuffer {
        LaneBuffer {
            capacity,
            ..LaneBuffer::default()
        }
    }

    fn len(&self) -> usize {
        self.control.len() + self.interactive.len() + self.bulk.len()
    }

    /// Append `frame` to its lane. When the shared capacity is reached, evict to
    /// make room — but only ever shed a frame whose priority is at or below the
    /// incoming frame's, least-important lane first. A bulk flood can therefore
    /// displace only other bulk frames; it can never evict an interactive or
    /// control frame to admit itself. When nothing at or below the incoming
    /// priority is available to evict (the buffer holds only higher-priority
    /// traffic), the incoming frame is dropped instead — presence/steer control
    /// is never sacrificed for lower-priority transcript.
    fn push(&mut self, frame: Frame) {
        if self.capacity == 0 {
            return; // no room at all: drop on the floor
        }
        while self.len() >= self.capacity {
            if !self.evict_for(frame.lane) {
                return; // only higher-priority frames remain: drop the newcomer
            }
        }
        match frame.lane {
            Lane::Control => self.control.push_back(frame),
            Lane::Interactive => self.interactive.push_back(frame),
            Lane::Bulk => self.bulk.push_back(frame),
        }
    }

    /// Evict the oldest frame whose lane priority is at or below `incoming`'s,
    /// least-important lane first. Returns `false` when no such frame exists —
    /// i.e. every buffered frame strictly outranks `incoming` — so the caller
    /// drops the incoming frame rather than displacing higher-priority traffic.
    fn evict_for(&mut self, incoming: Lane) -> bool {
        match incoming {
            // Bulk may only evict bulk.
            Lane::Bulk => self.bulk.pop_front().is_some(),
            // Interactive may evict bulk, then interactive — never control.
            Lane::Interactive => self
                .bulk
                .pop_front()
                .or_else(|| self.interactive.pop_front())
                .is_some(),
            // Control may evict anything, least-important first.
            Lane::Control => self
                .bulk
                .pop_front()
                .or_else(|| self.interactive.pop_front())
                .or_else(|| self.control.pop_front())
                .is_some(),
        }
    }

    /// Pop the next frame to send, draining the highest-priority lane first.
    fn pop(&mut self) -> Option<Frame> {
        self.control
            .pop_front()
            .or_else(|| self.interactive.pop_front())
            .or_else(|| self.bulk.pop_front())
    }

    /// Re-admit a popped frame to the FRONT of its lane (a write failed; retry
    /// it first on reconnect, preserving its lane priority).
    fn push_front(&mut self, frame: Frame) {
        match frame.lane {
            Lane::Control => self.control.push_front(frame),
            Lane::Interactive => self.interactive.push_front(frame),
            Lane::Bulk => self.bulk.push_front(frame),
        }
    }

    /// Prepend a CONTROL frame to the front of its lane while honouring the
    /// shared capacity: shed lower-priority (bulk, then interactive) traffic to
    /// make room — never another control frame, so presence/ownership ordering
    /// is preserved. Used by the reconnect resync snapshot, which must land at
    /// the front in REGISTER-then-CLAIM order without bypassing the advertised
    /// bound (a raw `push_front` would let a large snapshot exceed it).
    fn push_front_control_bounded(&mut self, frame: Frame) {
        debug_assert_eq!(frame.lane, Lane::Control);
        while self.len() >= self.capacity {
            // Shed the least-important non-control frame. If only control
            // frames remain, stop evicting (presence is never sacrificed) and
            // prepend anyway — the snapshot is bounded by live instances+jobs.
            if self.bulk.pop_front().is_none() && self.interactive.pop_front().is_none() {
                break;
            }
        }
        self.control.push_front(frame);
    }

    /// Drop every buffered `REGISTER`/`CLAIM` frame from the control lane. The
    /// (re)connect resync snapshot supersedes them, so leaving the stale ones
    /// in place would duplicate presence/ownership and let a `CLAIM` buffered
    /// while disconnected drain ahead of the snapshot's `REGISTER`. Other
    /// control families (`RELEASE`/`DEREGISTER`/`HEARTBEAT`) are preserved.
    fn drop_control_presence(&mut self) {
        self.control
            .retain(|f| !matches!(f.family, Family::Register | Family::Claim));
    }

    /// Test-only: iterate every buffered frame (across all lanes) so a test can
    /// read each frame's `seq` — the enqueue order — independent of drain order.
    #[cfg(test)]
    fn iter_frames(&self) -> impl Iterator<Item = &Frame> {
        self.control
            .iter()
            .chain(self.interactive.iter())
            .chain(self.bulk.iter())
    }
}

/// The shared hub client. Construct with [`HubClient::spawn`]; share it as
/// `Arc<HubClient>` across slots and open one [`HubSession`] per running job.
pub struct HubClient {
    config: HubConfig,
    /// Bounded, QoS-aware outbound buffer, drained to the socket when connected
    /// and retained (least-important-lane-dropped) while disconnected.
    outbound: Mutex<LaneBuffer>,
    /// Woken whenever a frame is enqueued so the connection task drains promptly.
    outbound_notify: Notify,
    /// Monotonic per-frame sequence number.
    seq: AtomicU32,
    /// True while the WebSocket is up (presence is live).
    connected: AtomicBool,
    /// The producer generation stamped as each transcript frame's `incarnation`.
    /// Bumped on every reconnect (never on the first connect) so a resumed
    /// producer strictly outranks its stale predecessor.
    generation: AtomicU32,
    /// Registered worker instances → their declared capability, for reconnect
    /// re-`register`. Worker presence is tracked separately from job ownership.
    instances: Mutex<HashMap<String, Value>>,
    /// Per-instance set of in-flight (claimed, un-released) job keys, for
    /// reconnect re-`claim`.
    in_flight: Mutex<HashMap<String, HashSet<String>>>,
    /// Per-session steer sinks, keyed by the session's composed **stream id**,
    /// used to route an inbound relay delivery to the one job owning it.
    sessions: Mutex<HashMap<String, mpsc::Sender<ControlFrame>>>,
    /// Flipped to request the connection task to deregister and exit.
    shutdown_tx: watch::Sender<bool>,
    /// The spawned connection task's handle, awaited by [`HubClient::shutdown`]
    /// so a clean shutdown blocks until the task has flushed its `DEREGISTER`
    /// and torn the socket down — not merely signalled the watch.
    conn_task: Mutex<Option<JoinHandle<()>>>,
    /// Per-session transcript-bridge flush handles, keyed by a unique session
    /// sequence (NOT the stream id, which a later session for the same job
    /// would reuse and so could steal a predecessor's flush handle). Lets a
    /// dropping [`HubSession`] close its bridge's input and synchronously wait
    /// for its accepted updates to reach the outbound buffer BEFORE enqueuing
    /// the job's RELEASE (see [`HubSession::flush_transcript`]).
    bridge_tasks: Mutex<HashMap<u64, BridgeFlush>>,
    /// Allocates the unique per-session key for `bridge_tasks`.
    next_session_seq: AtomicU64,
    /// Per-client PRNG state for reconnect jitter (seeded once at spawn from a
    /// real entropy mix), so a fleet of daemons does not reconnect in lockstep.
    rng: AtomicU64,
}

impl std::fmt::Debug for HubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubClient")
            .field("url", &self.config.url)
            .field("connected", &self.connected.load(Ordering::Relaxed))
            .field("buffer_capacity", &self.config.buffer_capacity)
            .finish_non_exhaustive()
    }
}

impl HubClient {
    /// Start the single hub connection task and return the shared client. The
    /// task runs until [`HubClient::shutdown`] (or the process exits).
    pub fn spawn(config: HubConfig) -> Arc<HubClient> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let capacity = config.buffer_capacity;
        let client = Arc::new(HubClient {
            config,
            outbound: Mutex::new(LaneBuffer::with_capacity(capacity)),
            outbound_notify: Notify::new(),
            seq: AtomicU32::new(0),
            connected: AtomicBool::new(false),
            generation: AtomicU32::new(0),
            instances: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            shutdown_tx,
            conn_task: Mutex::new(None),
            bridge_tasks: Mutex::new(HashMap::new()),
            next_session_seq: AtomicU64::new(0),
            rng: AtomicU64::new(seed_rng()),
        });
        log(&format!(
            "agentic hub: enabled → {} (buffer {} frame(s){})",
            client.config.url,
            client.config.buffer_capacity,
            if client.config.terminal {
                ", terminal relay on"
            } else {
                ""
            }
        ));
        let handle = tokio::spawn(connection_loop(client.clone(), shutdown_rx));
        *client.conn_task.lock().unwrap() = Some(handle);
        client
    }

    /// Register a job as a live hub session: REGISTERs its worker `instance`
    /// (once, with `capability`), CLAIMs the job, and returns the handle the
    /// slot wires into the ACP agent for transcript + steer. Worker presence
    /// (register) is kept distinct from job ownership (claim).
    pub fn register_session(
        self: &Arc<Self>,
        instance: &str,
        capability: Value,
        job_key: &str,
    ) -> HubSession {
        let stream = compose_stream_id(instance, job_key);
        // Bounded (see `STEER_CHANNEL_BOUND`): a hub delivering steer faster
        // than the turn consumes it must not grow memory without limit.
        let (steer_tx, steer_rx) = mpsc::channel::<ControlFrame>(STEER_CHANNEL_BOUND);
        self.sessions
            .lock()
            .unwrap()
            .insert(stream.clone(), steer_tx);

        // Worker presence: REGISTER this instance exactly once (its lifetime is
        // the worker's, not any single job's), folding in the config-level
        // advertisement fields the hub exposes.
        let newly_registered = {
            let mut insts = self.instances.lock().unwrap();
            if insts.contains_key(instance) {
                false
            } else {
                let cap = self.capability_payload(capability);
                insts.insert(instance.to_string(), cap);
                true
            }
        };
        if newly_registered {
            let cap = self.instances.lock().unwrap().get(instance).cloned();
            if let Some(cap) = cap {
                self.enqueue(
                    Lane::Control,
                    Family::Register,
                    json!({ "instance": instance, "capability": cap }),
                );
            }
        }

        // Job ownership: CLAIM {instance, jobKey}; track in-flight so a reconnect
        // re-claims it.
        self.in_flight
            .lock()
            .unwrap()
            .entry(instance.to_string())
            .or_default()
            .insert(job_key.to_string());
        self.enqueue(
            Lane::Control,
            Family::Claim,
            json!({ "instance": instance, "jobKey": job_key }),
        );

        // Bridge ACP updates → transcript produce frames on a dedicated task.
        // A *bounded* channel (see `TRANSCRIPT_CHANNEL_BOUND`): it fronts the
        // already-bounded outbound buffer, so an unbounded one here would let a
        // fast agent's updates grow without limit and defeat that cap.
        let (updates_tx, mut updates_rx) = mpsc::channel::<Value>(TRANSCRIPT_CHANNEL_BOUND);
        let bridge_client = self.clone();
        let bridge_stream = stream.clone();
        // The bridge drains updates until EITHER the channel closes (all senders
        // dropped) OR the session's drop signals a flush, whichever first — then
        // it finishes and notifies the (synchronous) flush waiter. The flush
        // signal lets a drop close input and wait for the tail without needing
        // the last sender to be gone first.
        let (close_tx, mut close_rx) = watch::channel(false);
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let bridge_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Prioritise draining any queued update; only when none is
                    // immediately ready does a flush signal take effect.
                    biased;
                    maybe = updates_rx.recv() => {
                        match maybe {
                            Some(update) => {
                                if let Some(chunk) = acp_update_to_transcript_chunk(&update) {
                                    let incarnation = bridge_client.generation.load(Ordering::Relaxed);
                                    bridge_client.enqueue(
                                        Lane::Bulk,
                                        Family::Relay,
                                        json!({
                                            "op": "produce",
                                            "stream": bridge_stream,
                                            "incarnation": incarnation,
                                            "chunk": chunk,
                                        }),
                                    );
                                }
                            }
                            // Channel closed (all senders dropped): drained.
                            None => break,
                        }
                    }
                    // Flush requested by the session's drop: stop accepting and
                    // finish so the tail already enqueued is what gets sent.
                    _ = close_rx.changed() => break,
                }
            }
            // Signal completion (ignore a gone waiter).
            let _ = done_tx.send(());
        });
        // Detach the JoinHandle (the flush uses `done_rx`, not the handle).
        drop(bridge_handle);
        // Track the flush handle under a UNIQUE session id (not the stream id,
        // which a later session for the same job would reuse and so could steal
        // this session's flush handle), so this session's drop flushes exactly
        // its own bridge before RELEASE.
        let session_id = self.next_session_seq.fetch_add(1, Ordering::Relaxed);
        self.bridge_tasks
            .lock()
            .unwrap()
            .insert(session_id, BridgeFlush { close_tx, done_rx });

        HubSession {
            client: self.clone(),
            instance: instance.to_string(),
            job_key: job_key.to_string(),
            stream,
            session_id,
            transcript: Some(updates_tx),
            steer: Some(steer_rx),
        }
    }

    /// Stop the hub: signal the connection task to deregister and exit, then
    /// await it so this returns only once the worker's `DEREGISTER` has been
    /// flushed and the socket torn down. Idempotent — the handle is taken on the
    /// first call; later calls just re-signal and return.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        let handle = self.conn_task.lock().unwrap().take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }

    /// Merge the hub's config-level advertisement fields (permission policy,
    /// attribution, terminal flag, runtime) into the slot-supplied capability
    /// object without overwriting any field the slot already set. The result is
    /// always a JSON object, as the `register` validator requires.
    fn capability_payload(&self, capability: Value) -> Value {
        let mut cap = match capability {
            Value::Object(map) => Value::Object(map),
            _ => Value::Object(serde_json::Map::new()),
        };
        if let Some(obj) = cap.as_object_mut() {
            if let Some(perm) = &self.config.permission {
                obj.entry("permission")
                    .or_insert_with(|| Value::String(perm.clone()));
            }
            if let Some(attr) = &self.config.attribution {
                obj.entry("attribution")
                    .or_insert_with(|| Value::String(attr.clone()));
            }
            obj.entry("terminal")
                .or_insert_with(|| Value::Bool(self.config.terminal));
            obj.entry("runtime")
                .or_insert_with(|| Value::String("nano-supervisor".into()));
        }
        cap
    }

    /// The resolved hub configuration this client was spawned with. Exposed so
    /// a slot can honour the `NANO_AGENTIC_PROTOCOL` harness override when
    /// resolving a job's hire protocol (it is a harness setting, not a wire
    /// subprotocol — see [`HubConfig::hire_protocol_override`]).
    pub fn config(&self) -> &HubConfig {
        &self.config
    }

    /// Enqueue a frame for delivery. Bounded and QoS-aware: see [`LaneBuffer`].
    fn enqueue(&self, lane: Lane, family: Family, payload: Value) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let frame = Frame::new(lane, family, seq, payload);
        self.outbound.lock().unwrap().push(frame);
        self.outbound_notify.notify_one();
    }

    /// Test-only probe recording the order frames are enqueued (their `seq`),
    /// so a test can assert enqueue order independent of the drain order
    /// `buffered()` reports (which always pulls control lanes first).
    #[cfg(test)]
    fn enqueue_log(&self) -> Vec<(u32, Lane, Family)> {
        self.outbound
            .lock()
            .unwrap()
            .iter_frames()
            .map(|f| (f.seq, f.lane, f.family))
            .collect()
    }

    /// Rebuild worker presence + job ownership at the FRONT of the outbound
    /// buffer on every (re)connect. Builds the ordered snapshot — every
    /// REGISTER, then every CLAIM — then drops any REGISTER/CLAIM already
    /// buffered (a disconnected `register_session` may have queued some) and
    /// prepends the snapshot ahead of ordinary traffic. Prepending (rather than
    /// tail-enqueuing) guarantees two invariants the hub relies on: REGISTER
    /// strictly precedes CLAIM, and neither presence frame is duplicated —
    /// a CLAIM buffered while disconnected can otherwise drain before the
    /// tail-appended REGISTER and desync ownership.
    fn resync_presence(&self) {
        // Build the ordered snapshot (REGISTERs first, then CLAIMs) with fresh
        // sequence numbers, holding each source lock only long enough to read it.
        // Reversed, so the capacity-aware re-admission below lands the snapshot
        // in its intended front order (REGISTER…REGISTER, CLAIM…CLAIM).
        let mut snapshot: Vec<Frame> = Vec::new();
        for (inst, cap) in self.instances.lock().unwrap().iter() {
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            snapshot.push(Frame::new(
                Lane::Control,
                Family::Register,
                seq,
                json!({ "instance": inst, "capability": cap }),
            ));
        }
        for (inst, jobs) in self.in_flight.lock().unwrap().iter() {
            for job_key in jobs {
                let seq = self.seq.fetch_add(1, Ordering::Relaxed);
                snapshot.push(Frame::new(
                    Lane::Control,
                    Family::Claim,
                    seq,
                    json!({ "instance": inst, "jobKey": job_key }),
                ));
            }
        }
        {
            let mut buf = self.outbound.lock().unwrap();
            // Drop the superseded REGISTER/CLAIM frames first so the snapshot
            // re-admits them within the SAME shared capacity rather than
            // bypassing it. Prepending in REVERSE via `push_front_control_bounded`
            // lands the snapshot at the front in REGISTER-then-CLAIM order while
            // shedding only lower-priority (bulk/interactive) traffic to make
            // room — never another control frame — so presence ordering holds and
            // the advertised bound is honoured (a raw `push_front` would exceed it).
            buf.drop_control_presence();
            for frame in snapshot.into_iter().rev() {
                buf.push_front_control_bounded(frame);
            }
        }
        self.outbound_notify.notify_one();
    }

    /// Draw the next 64 bits of per-client jitter entropy (xorshift64*).
    fn next_rand(&self) -> u64 {
        let mut x = self.rng.load(Ordering::Relaxed);
        loop {
            let mut y = x;
            y ^= y << 13;
            y ^= y >> 7;
            y ^= y << 17;
            if y == 0 {
                y = 0x9E37_79B9_7F4A_7C15;
            }
            match self
                .rng
                .compare_exchange_weak(x, y, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return y.wrapping_mul(0x2545_F491_4F6C_DD1D),
                Err(current) => x = current,
            }
        }
    }

    /// Deliver an inbound relay delivery to the one session that owns its
    /// `stream`. A delivery for an unknown/foreign/invalid stream is dropped —
    /// never broadcast — so a targeted steer can only ever reach its own job.
    fn route_inbound(&self, payload: &Value) {
        // A relay *delivery* is `{stream, offset, chunk}` and carries NO `op`:
        // only producer/control frames have an `op` (e.g. our own echoed
        // `{op:"produce", stream, chunk}` transcript). Routing one of those as a
        // delivery would decode our own produced transcript as inbound steer and
        // inject it back into its own agent — a feedback loop. Accept only the
        // delivery shape; anything carrying `op` (or missing `offset`) is dropped.
        // A relay *delivery* is `{stream, …, chunk}` and carries NO `op`: only
        // producer/control frames have an `op` (e.g. our own echoed
        // `{op:"produce", stream, chunk}` transcript). Routing one of those as a
        // delivery would decode our own produced transcript as inbound steer and
        // inject it back into its own agent — a feedback loop. Reject anything
        // carrying `op`; only genuine deliveries are routed.
        if payload.get("op").is_some() {
            return; // not a delivery: producer/control frame echoed back
        }
        let Some(stream) = payload.get("stream").and_then(Value::as_str) else {
            return; // no stream id: not a routable delivery
        };
        let Some(chunk) = payload.get("chunk").and_then(Value::as_str) else {
            return;
        };
        // The stream id MUST parse to a single `(instance, jobKey)` ref; a
        // structurally-invalid id off the wire is dropped rather than guessed at.
        if parse_stream_id(stream).is_none() {
            return;
        }
        // Look up the owning session by exact stream id. Absent ⇒ foreign or
        // stale stream: drop it rather than steering unrelated jobs.
        let sink = {
            let sessions = self.sessions.lock().unwrap();
            match sessions.get(stream) {
                Some(tx) => tx.clone(),
                None => return,
            }
        };
        let decoded = match parse_inbound_relay_chunk(chunk) {
            Some(d) => d,
            None => return, // tagged-but-malformed steer: ignore it
        };
        // Preserve the typed control end-to-end; the ACP steer task maps it to
        // the matching session semantics (prompt injection / cancellation /
        // permission outcome). The channel is bounded (`STEER_CHANNEL_BOUND`):
        // on overflow drop the control rather than block the socket read loop
        // or grow memory — a stalled turn must not wedge inbound routing.
        let _ = sink.try_send(decoded.frame);
    }
}

/// A handle to flush one session's transcript bridge: closing `close_tx` makes
/// the bridge drain its accepted updates and exit, and `done_rx` resolves once
/// the bridge task has finished (so the tail is enqueued before RELEASE). Both
/// are synchronous primitives so a synchronous `Drop` can drive the flush
/// without a runtime context.
struct BridgeFlush {
    close_tx: watch::Sender<bool>,
    done_rx: std::sync::mpsc::Receiver<()>,
}

/// A per-job hub session: worker presence is live for its instance, the job is
/// CLAIMed for its lifetime, the agent's ACP updates are bridged to transcript
/// produce frames, and inbound steer is routed here. Dropping it RELEASEs the
/// job.
pub struct HubSession {
    client: Arc<HubClient>,
    instance: String,
    job_key: String,
    /// The composed relay stream id for this `(instance, jobKey)` pair.
    stream: String,
    /// Unique per-session key into `HubClient::bridge_tasks` (NOT the stream
    /// id, which a later session for the same job would reuse), so this drop
    /// flushes exactly its own transcript bridge.
    session_id: u64,
    transcript: Option<mpsc::Sender<Value>>,
    steer: Option<mpsc::Receiver<ControlFrame>>,
}

impl HubSession {
    /// The sink the ACP agent forwards each `session/update` to. Taken once.
    /// Bounded: on overflow the ACP side drops the update rather than blocking.
    pub fn transcript_sink(&mut self) -> Option<mpsc::Sender<Value>> {
        self.transcript.clone()
    }

    /// The inbound-steer receiver handed to the ACP agent so a hub-delivered
    /// control is applied to the running turn. Taken once. Bounded: on overflow
    /// `route_inbound` drops the control rather than growing memory.
    pub fn take_steer(&mut self) -> Option<mpsc::Receiver<ControlFrame>> {
        self.steer.take()
    }

    /// Flush this session's accepted-but-not-yet-bridged transcript updates into
    /// the outbound buffer, so they are queued BEFORE the RELEASE enqueued on
    /// drop. The bridge task converts updates to bulk frames asynchronously, so
    /// without this barrier a RELEASE (control lane, always drained first) can
    /// overtake tail transcript chunks — emitting them for a job the hub has
    /// already released. Closing the channel lets the bridge drain every accepted
    /// update and exit; awaiting its handle guarantees the tail is enqueued
    /// first. Best-effort and bounded by `TRANSCRIPT_FLUSH_TIMEOUT` so a wedged
    /// bridge can never hang the dropping task; on timeout the RELEASE proceeds.
    fn flush_transcript(&mut self) {
        // Take the sender out so no new update can be accepted from this side,
        // then signal the bridge to finish and synchronously wait (bounded) for
        // it to drain its accepted backlog into the outbound buffer. This is
        // runtime-free: `Drop` cannot `.await`, so the flush rides a synchronous
        // watch + std channel rather than the tokio task handle.
        let _tx = self.transcript.take();
        let Some(flush) = self
            .client
            .bridge_tasks
            .lock()
            .unwrap()
            .remove(&self.session_id)
        else {
            return; // never attached to an agent, or already flushed
        };
        let _ = flush.close_tx.send(true);
        // Bounded wait: a wedged bridge must never hang the dropping task. On
        // timeout the RELEASE proceeds and the (already-closed) tail is dropped.
        let _ = flush.done_rx.recv_timeout(TRANSCRIPT_FLUSH_TIMEOUT);
    }
}

impl Drop for HubSession {
    fn drop(&mut self) {
        // Flush the transcript tail BEFORE releasing, so no chunk is emitted for
        // a job the hub has already released (see `flush_transcript`).
        self.flush_transcript();
        self.client.sessions.lock().unwrap().remove(&self.stream);
        // RELEASE the job (worker REGISTER persists until shutdown/deregister).
        if let Some(jobs) = self
            .client
            .in_flight
            .lock()
            .unwrap()
            .get_mut(&self.instance)
        {
            jobs.remove(&self.job_key);
        }
        self.client.enqueue(
            Lane::Control,
            Family::Release,
            json!({ "instance": self.instance, "jobKey": self.job_key }),
        );
    }
}

/// Seed the per-client jitter PRNG from a real entropy mix (wall-clock nanos,
/// process id, and a stack address), never zero (xorshift's fixed point).
fn seed_rng() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let stack = &nanos as *const u64 as u64;
    let seed = nanos ^ pid.rotate_left(32) ^ stack.rotate_left(17);
    if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    }
}

/// Jittered exponential backoff: `delay/2 + random(0, delay/2)`, so a fleet of
/// daemons reconnecting after a shared hub outage does not thunder together.
/// `rand` is a fresh draw from the per-client PRNG.
fn jittered(delay: Duration, rand: u64) -> Duration {
    let half = delay / 2;
    let span = half.as_millis() as u64;
    let extra = if span == 0 { 0 } else { rand % span };
    half + Duration::from_millis(extra)
}

async fn connection_loop(client: Arc<HubClient>, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = BACKOFF_BASE;
    let mut first_connect = true;
    loop {
        if *shutdown.borrow() {
            break;
        }
        // Race the connect/handshake against both a hard timeout and a shutdown
        // request: an unbounded `connect().await` on a hung handshake would park
        // here forever, starving reconnect backoff AND a requested shutdown
        // (which otherwise only lands between attempts).
        let attempt = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
                continue;
            }
            result = timeout(CONNECT_TIMEOUT, connect(&client.config)) => result,
        };
        match attempt {
            Ok(Ok(stream)) => {
                backoff = BACKOFF_BASE;
                // Bump the producer generation on every reconnect (never the
                // first connect) so resumed transcript producers strictly
                // outrank the predecessor.
                if first_connect {
                    first_connect = false;
                } else {
                    client.generation.fetch_add(1, Ordering::Relaxed);
                }
                client.connected.store(true, Ordering::Relaxed);
                log("agentic hub: connected");
                // Resync BEFORE any transcript resumes: re-REGISTER every known
                // worker instance, then re-CLAIM every in-flight job, so hub
                // presence and ownership are whole again first. Ordering is the
                // contract (presence + ownership before transcript): the snapshot
                // is PREPENDED to the control lane (deduplicating any REGISTER/
                // CLAIM a disconnected `register_session` already buffered) so a
                // CLAIM can never drain ahead of its REGISTER, and neither is
                // duplicated.
                client.resync_presence();
                pump(&client, stream, &mut shutdown).await;
                client.connected.store(false, Ordering::Relaxed);
                log("agentic hub: disconnected");
            }
            Ok(Err(e)) => {
                log(&format!("agentic hub: connect failed: {e:#}"));
            }
            Err(_) => {
                log(&format!(
                    "agentic hub: connect timed out after {}s",
                    CONNECT_TIMEOUT.as_secs()
                ));
            }
        }
        if *shutdown.borrow() {
            break;
        }
        let wait = jittered(backoff, client.next_rand());
        tokio::select! {
            _ = sleep(wait) => {}
            _ = shutdown.changed() => {}
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
    log("agentic hub: stopped");
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Build the authenticated channel URL. The hub's shared-secret authenticator
/// reads the identity `token` and capability `credential` as **query params on
/// the upgrade URL** (the same `?token=…&capability=…` the Node worker sends),
/// so they MUST be on the URL before the handshake — a payload-only token is
/// rejected before any `register` can be read. The bearer `secret` is still
/// carried as an `Authorization` header when configured.
fn authenticated_url(config: &HubConfig) -> String {
    let mut params: Vec<(&str, &str)> = Vec::new();
    if let Some(token) = &config.token {
        params.push(("token", token));
    }
    if let Some(credential) = &config.credential {
        params.push(("capability", credential));
    }
    if params.is_empty() {
        return config.url.clone();
    }
    let mut url = config.url.clone();
    let mut sep = if url.contains('?') { '&' } else { '?' };
    for (key, value) in params {
        url.push(sep);
        url.push_str(key);
        url.push('=');
        url.push_str(&percent_encode_query(value));
        sep = '&';
    }
    url
}

/// Percent-encode a query-parameter value, escaping everything outside the
/// unreserved set so a routing token's `#`/`/`/`&`/`=` can never be mistaken for
/// URL structure (a bare `#` would otherwise start a fragment and truncate it).
fn percent_encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn connect(config: &HubConfig) -> anyhow::Result<WsStream> {
    let url = authenticated_url(config);
    let mut request = url.as_str().into_client_request()?;
    if let Some(secret) = &config.secret {
        request.headers_mut().insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {secret}"))?,
        );
    }
    // NOTE: `config.protocol` (`NANO_AGENTIC_PROTOCOL`) is deliberately NOT sent
    // as a `Sec-WebSocket-Protocol` header. It names the worker's *harness*
    // override (`pipe`/`acp`), not a WebSocket subprotocol; presenting it as one
    // can make a configured hub handshake fail. It is applied when resolving the
    // hire protocol (see `HubConfig::hire_protocol_override`), never on the wire.
    let (stream, _response) = tokio_tungstenite::connect_async(request).await?;
    Ok(stream)
}

/// Drive one live connection: drain outbound frames, heartbeat, and dispatch
/// inbound frames until the socket drops or shutdown is requested.
async fn pump(client: &Arc<HubClient>, stream: WsStream, shutdown: &mut watch::Receiver<bool>) {
    let (mut write, mut read) = stream.split();
    let mut heartbeat = interval(HEARTBEAT);
    heartbeat.tick().await; // the first tick is immediate; skip it
    loop {
        tokio::select! {
            _ = client.outbound_notify.notified() => {
                if drain(client, &mut write).await.is_err() { break; }
            }
            _ = heartbeat.tick() => {
                // One heartbeat per registered worker instance.
                for inst in client.instances.lock().unwrap().keys() {
                    client.enqueue(Lane::Control, Family::Heartbeat, json!({ "instance": inst }));
                }
                if drain(client, &mut write).await.is_err() { break; }
            }
            incoming = read.next() => {
                match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        match decode_frame(&bytes) {
                            Ok(frame) if frame.family == Family::Relay => {
                                client.route_inbound(&frame.payload);
                            }
                            Ok(_) => {}
                            Err(code) => log(&format!(
                                "agentic hub: dropped an undecodable inbound frame ({})",
                                code.as_str()
                            )),
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        if write.send(Message::Pong(p)).await.is_err() { break; }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    // Best-effort graceful deregister of every worker before exit.
                    for inst in client.instances.lock().unwrap().keys() {
                        client.enqueue(
                            Lane::Control,
                            Family::Deregister,
                            json!({ "instance": inst, "reason": "shutdown" }),
                        );
                    }
                    let _ = drain(client, &mut write).await;
                    let _ = write.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    }
}

/// Send every currently buffered frame. A write error returns `Err` so the
/// caller tears the connection down and reconnects (the frames stay buffered).
async fn drain(
    client: &Arc<HubClient>,
    write: &mut futures_util::stream::SplitSink<WsStream, Message>,
) -> anyhow::Result<()> {
    // The incarnation fences a transcript producer to the connection that
    // generated it. It is stamped HERE — at drain on the live socket — not at
    // buffer-enqueue time: a transcript chunk queued during an outage (or
    // re-buffered after a failed write) would otherwise keep the previous
    // generation even though the reconnect bumped `generation`, so frames sent
    // on the new socket would fail to fence the stale producer. Re-stamping at
    // drain guarantees every relay produce frame carries the CURRENT generation.
    let incarnation = client.generation.load(Ordering::Relaxed);
    loop {
        let mut frame = {
            let mut buf = client.outbound.lock().unwrap();
            match buf.pop() {
                Some(f) => f,
                None => return Ok(()),
            }
        };
        if frame.family == Family::Relay && frame.payload.get("op") == Some(&Value::from("produce"))
        {
            frame.payload["incarnation"] = Value::from(incarnation);
        }
        match encode_frame(&frame) {
            Ok(bytes) => {
                if let Err(e) = write.send(Message::Binary(bytes)).await {
                    // Re-buffer the frame we popped so it is retried on reconnect.
                    client.outbound.lock().unwrap().push_front(frame);
                    return Err(e.into());
                }
            }
            // An unserialisable/too-large frame is dropped, not retried forever.
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::stream::parse_stream_id;

    fn test_config() -> HubConfig {
        HubConfig {
            url: "ws://127.0.0.1:1/na".into(),
            token: Some("implementation.ci.fix#red".into()),
            secret: None,
            credential: None,
            protocol: None,
            permission: Some("yolo".into()),
            terminal: false,
            attribution: Some("nano".into()),
            buffer_capacity: 8,
        }
    }

    fn capability() -> Value {
        json!({ "cognition": "opus", "family": "senior", "host": "mac-01" })
    }

    /// Drain every buffered frame into a `(lane, family, payload)` list for
    /// assertions.
    fn buffered(client: &Arc<HubClient>) -> Vec<(Lane, Family, Value)> {
        let mut buf = client.outbound.lock().unwrap();
        let mut out = Vec::new();
        while let Some(f) = buf.pop() {
            out.push((f.lane, f.family, f.payload));
        }
        out
    }

    #[tokio::test]
    async fn buffer_drops_oldest_at_capacity() {
        let mut cfg = test_config();
        cfg.buffer_capacity = 3;
        let client = HubClient::spawn(cfg);
        // The connection cannot establish (port 1), so nothing drains: the ring
        // buffer must cap at `buffer_capacity`, dropping the oldest frames.
        for i in 0..10 {
            client.enqueue(Lane::Bulk, Family::Relay, json!({ "n": i }));
        }
        assert!(client.outbound.lock().unwrap().len() <= 3);
        client.shutdown().await;
    }

    #[tokio::test]
    async fn bulk_flood_never_evicts_control_frames() {
        let mut cfg = test_config();
        cfg.buffer_capacity = 4;
        let client = HubClient::spawn(cfg);
        // Two control frames, then a bulk flood far past capacity.
        client.enqueue(Lane::Control, Family::Register, json!({ "instance": "w" }));
        client.enqueue(Lane::Control, Family::Claim, json!({ "instance": "w" }));
        for i in 0..50 {
            client.enqueue(Lane::Bulk, Family::Relay, json!({ "n": i }));
        }
        let frames = buffered(&client);
        // Both control frames survive; only bulk was shed.
        let controls = frames.iter().filter(|(l, _, _)| *l == Lane::Control).count();
        assert_eq!(controls, 2, "control frames must not be evicted by bulk");
        client.shutdown().await;
    }

    #[tokio::test]
    async fn control_drains_before_bulk() {
        let client = HubClient::spawn(test_config());
        client.enqueue(Lane::Bulk, Family::Relay, json!({ "n": 1 }));
        client.enqueue(Lane::Control, Family::Register, json!({ "instance": "w" }));
        let frames = buffered(&client);
        assert_eq!(frames[0].0, Lane::Control, "control lane drains first");
        client.shutdown().await;
    }

    #[tokio::test]
    async fn session_register_claims_and_release_on_drop() {
        let client = HubClient::spawn(test_config());
        {
            let _session = client.register_session("w-1", capability(), "job-1");
            assert!(client.sessions.lock().unwrap().contains_key("3:w-1/job-1"));
            assert!(client.instances.lock().unwrap().contains_key("w-1"));
            let frames = buffered(&client);
            // First session for the instance: a REGISTER then a CLAIM.
            assert_eq!(frames[0].1, Family::Register);
            assert_eq!(frames[0].2["instance"], "w-1");
            assert!(frames[0].2["capability"].is_object());
            assert_eq!(frames[1].1, Family::Claim);
            assert_eq!(frames[1].2["jobKey"], "job-1");
        }
        // Dropping the session RELEASEs the job and drops its route.
        assert!(!client.sessions.lock().unwrap().contains_key("3:w-1/job-1"));
        let frames = buffered(&client);
        assert!(frames
            .iter()
            .any(|(_, fam, p)| *fam == Family::Release && p["jobKey"] == "job-1"));
        client.shutdown().await;
    }

    #[tokio::test]
    async fn second_job_for_same_instance_does_not_reregister() {
        let client = HubClient::spawn(test_config());
        let _s1 = client.register_session("w-1", capability(), "job-1");
        let _ = buffered(&client);
        let _s2 = client.register_session("w-1", capability(), "job-2");
        let frames = buffered(&client);
        // The instance is already registered: only a CLAIM for job-2, no second
        // REGISTER.
        assert!(frames.iter().all(|(_, fam, _)| *fam != Family::Register));
        assert!(frames
            .iter()
            .any(|(_, fam, p)| *fam == Family::Claim && p["jobKey"] == "job-2"));
        client.shutdown().await;
    }

    #[tokio::test]
    async fn inbound_steer_is_routed_by_stream_to_its_session() {
        let client = HubClient::spawn(test_config());
        let mut session = client.register_session("w-7", capability(), "job-7");
        let mut steer = session.take_steer().expect("steer receiver");
        let stream = compose_stream_id("w-7", "job-7");
        client.route_inbound(&json!({ "stream": stream, "offset": 0, "chunk": "do the thing" }));
        let got = steer.recv().await.expect("steer delivered");
        assert_eq!(got, ControlFrame::Prompt { text: "do the thing".into() });
        client.shutdown().await;
    }

    #[tokio::test]
    async fn inbound_steer_for_foreign_stream_is_dropped_not_broadcast() {
        let client = HubClient::spawn(test_config());
        let mut session = client.register_session("w-7", capability(), "job-7");
        let mut steer = session.take_steer().expect("steer receiver");
        // A delivery for a different stream must NOT reach this session.
        let foreign = compose_stream_id("w-7", "other-job");
        client.route_inbound(&json!({ "stream": foreign, "offset": 0, "chunk": "nope" }));
        // And a structurally-invalid stream id is dropped too.
        client.route_inbound(&json!({ "stream": "garbage", "offset": 0, "chunk": "nope" }));
        assert!(steer.try_recv().is_err(), "foreign stream must not be routed here");
        client.shutdown().await;
    }

    #[tokio::test]
    async fn inbound_cancel_is_delivered_as_a_typed_control() {
        let client = HubClient::spawn(test_config());
        let mut session = client.register_session("w-8", capability(), "job-8");
        let mut steer = session.take_steer().expect("steer receiver");
        let stream = compose_stream_id("w-8", "job-8");
        client.route_inbound(&json!({
            "stream": stream,
            "chunk": r#"{"nanoControlFrame":1,"kind":"cancel","reason":"stop"}"#,
        }));
        let got = steer.recv().await.expect("steer delivered");
        assert_eq!(got, ControlFrame::Cancel { reason: Some("stop".into()) });
        client.shutdown().await;
    }

    #[tokio::test]
    async fn transcript_sink_bridges_updates_to_produce_frames() {
        let client = HubClient::spawn(test_config());
        let mut session = client.register_session("w-9", capability(), "job-9");
        let sink = session.transcript_sink().expect("transcript sink");
        let _ = buffered(&client); // discard the register/claim frames
        sink.try_send(json!({
            "sessionUpdate": "agent_message_chunk",
            "content": { "type": "text", "text": "hello" }
        }))
        .unwrap();
        // Give the bridge task a moment to enqueue the transcript frame.
        let mut produce = None;
        for _ in 0..50 {
            if let Some(f) = client
                .outbound
                .lock()
                .unwrap()
                .bulk
                .iter()
                .find(|f| f.family == Family::Relay)
                .cloned()
            {
                produce = Some(f);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let produce = produce.expect("transcript update was not bridged to a relay frame");
        assert_eq!(produce.lane, Lane::Bulk);
        assert_eq!(produce.payload["op"], "produce");
        assert_eq!(produce.payload["incarnation"], 0);
        // The stream id round-trips back to (instance, jobKey).
        let stream = produce.payload["stream"].as_str().unwrap();
        assert_eq!(
            parse_stream_id(stream),
            Some(("w-9".to_string(), "job-9".to_string()))
        );
        client.shutdown().await;
    }

    #[test]
    fn authenticated_url_appends_token_and_capability_query_params() {
        let mut cfg = test_config();
        cfg.url = "ws://host:8787/agentic".into();
        cfg.token = Some("implementation.ci.fix#red".into());
        cfg.credential = Some("cred/1".into());
        let url = authenticated_url(&cfg);
        // `#` and `/` are percent-encoded so they are not URL structure.
        assert_eq!(
            url,
            "ws://host:8787/agentic?token=implementation.ci.fix%23red&capability=cred%2F1"
        );
    }

    #[test]
    fn authenticated_url_preserves_an_existing_query() {
        let mut cfg = test_config();
        cfg.url = "ws://host/agentic?v=1".into();
        cfg.token = Some("tok".into());
        cfg.credential = None;
        assert_eq!(authenticated_url(&cfg), "ws://host/agentic?v=1&token=tok");
    }

    #[tokio::test]
    async fn jitter_spans_the_half_delay_with_real_entropy() {
        let client = HubClient::spawn(test_config());
        let delay = Duration::from_millis(1000);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let j = jittered(delay, client.next_rand());
            // Always within [half, delay).
            assert!(j >= Duration::from_millis(500));
            assert!(j < Duration::from_millis(1000));
            seen.insert(j.as_millis());
        }
        // A real RNG produces many distinct delays, not one lockstep value.
        assert!(seen.len() > 8, "jitter is not varying: {} distinct", seen.len());
        client.shutdown().await;
    }

    // --- In-process live WebSocket acceptance (#10) ----------------------

    /// A full end-to-end pass against a real in-process hub server: the upgrade
    /// handshake carries the auth query params, the exact REGISTER/CLAIM/produce
    /// frames arrive on the wire, a targeted inbound relay steers this session,
    /// and shutdown emits a DEREGISTER. This closes the issue-#5 live-worker
    /// acceptance seam that the contract-test corpus only panics on.
    #[tokio::test]
    async fn live_connection_handshake_presence_transcript_steer_and_shutdown() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_hdr_async;
        use tokio_tungstenite::tungstenite::handshake::server::{
            ErrorResponse, Request, Response,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (uri_tx, uri_rx) = tokio::sync::oneshot::channel::<String>();
        let (frames_tx, mut frames_rx) = mpsc::unbounded_channel::<(Family, Value)>();
        let steer_stream = compose_stream_id("w-live", "job-live");
        let steer_stream_srv = steer_stream.clone();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let callback = move |req: &Request, resp: Response| {
                let _ = uri_tx.send(req.uri().to_string());
                Ok::<Response, ErrorResponse>(resp)
            };
            let ws = accept_hdr_async(sock, callback).await.unwrap();
            let (mut write, mut read) = ws.split();
            let mut claimed = false;
            while let Some(Ok(msg)) = read.next().await {
                match msg {
                    Message::Binary(bytes) => {
                        let frame = decode_frame(&bytes).expect("server decodes a client frame");
                        let is_claim = frame.family == Family::Claim;
                        let _ = frames_tx.send((frame.family, frame.payload));
                        if is_claim && !claimed {
                            claimed = true;
                            // Targeted inbound steer for this exact stream.
                            let relay = Frame::new(
                                Lane::Interactive,
                                Family::Relay,
                                0,
                                json!({
                                    "stream": steer_stream_srv,
                                    "offset": 0,
                                    "chunk": "steer-me",
                                }),
                            );
                            let _ = write
                                .send(Message::Binary(encode_frame(&relay).unwrap()))
                                .await;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        });

        let mut cfg = test_config();
        cfg.url = format!("ws://127.0.0.1:{port}/na");
        cfg.token = Some("tkn#1".into());
        cfg.credential = Some("cap/1".into());
        let client = HubClient::spawn(cfg);
        let mut session = client.register_session("w-live", capability(), "job-live");
        let mut steer = session.take_steer().expect("steer receiver");
        let sink = session.transcript_sink().expect("transcript sink");

        // Auth: the upgrade URL carried percent-encoded token + capability.
        let uri = tokio::time::timeout(Duration::from_secs(5), uri_rx)
            .await
            .expect("handshake did not arrive")
            .expect("uri channel closed");
        assert!(uri.contains("token=tkn%231"), "upgrade URL missing token: {uri}");
        assert!(
            uri.contains("capability=cap%2F1"),
            "upgrade URL missing capability: {uri}"
        );

        // A transcript update must bridge to a produce relay on the wire.
        sink.send(json!({
            "sessionUpdate": "agent_message_chunk",
            "content": { "type": "text", "text": "hi" }
        }))
        .await
        .unwrap();

        // Collect frames until REGISTER, CLAIM, and the produce relay all land,
        // recording arrival order to assert presence+ownership precede transcript.
        let mut order: Vec<Family> = Vec::new();
        let (mut reg, mut claim, mut produce) = (None, None, None);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while reg.is_none() || claim.is_none() || produce.is_none() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let (fam, payload) = tokio::time::timeout(remaining, frames_rx.recv())
                .await
                .expect("timed out awaiting wire frames")
                .expect("server frame channel closed");
            order.push(fam);
            match fam {
                Family::Register => reg = Some(payload),
                Family::Claim => claim = Some(payload),
                Family::Relay => produce = Some(payload),
                _ => {}
            }
        }
        let reg = reg.unwrap();
        assert_eq!(reg["instance"], "w-live");
        assert!(reg["capability"].is_object(), "REGISTER capability must be an object");
        let claim = claim.unwrap();
        assert_eq!(claim["instance"], "w-live");
        assert_eq!(claim["jobKey"], "job-live");
        let produce = produce.unwrap();
        assert_eq!(produce["op"], "produce");
        assert_eq!(produce["stream"], steer_stream);
        assert_eq!(produce["incarnation"], 0);
        // Presence (REGISTER) and ownership (CLAIM) precede the transcript relay.
        let idx = |f: Family| order.iter().position(|x| *x == f).unwrap();
        assert!(idx(Family::Register) < idx(Family::Claim));
        assert!(idx(Family::Claim) < idx(Family::Relay));

        // Targeted steer: the server's relay for this stream reached THIS session.
        let got = tokio::time::timeout(Duration::from_secs(5), steer.recv())
            .await
            .expect("steer timed out")
            .expect("steer channel closed");
        assert_eq!(got, ControlFrame::Prompt { text: "steer-me".into() });

        // Shutdown deregisters the worker instance.
        drop(session);
        client.shutdown().await;
        let mut saw_deregister = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !saw_deregister {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, frames_rx.recv()).await {
                Ok(Some((Family::Deregister, payload))) => {
                    assert_eq!(payload["instance"], "w-live");
                    saw_deregister = true;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        assert!(saw_deregister, "shutdown did not emit a DEREGISTER");
        let _ = server.await;
    }

    /// On reconnect the client must resync presence before ownership: every
    /// worker is re-REGISTERed and only then is each in-flight job re-CLAIMed,
    /// so the hub never sees a claim from an unknown worker.
    #[tokio::test]
    async fn live_reconnect_reregisters_before_reclaiming() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (frames_tx, mut frames_rx) = mpsc::unbounded_channel::<(u8, Family)>();

        let server = tokio::spawn(async move {
            // First connection: accept, read one frame, then drop it to force a
            // reconnect.
            let (sock, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(sock).await.unwrap();
            let _ = ws.next().await; // let at least the REGISTER arrive
            drop(ws); // close → client reconnects

            // Second connection: record the control-frame order of the resync.
            let (sock, _) = listener.accept().await.unwrap();
            let ws = accept_async(sock).await.unwrap();
            let (_write, mut read) = ws.split();
            while let Some(Ok(msg)) = read.next().await {
                if let Message::Binary(bytes) = msg {
                    if let Ok(frame) = decode_frame(&bytes) {
                        if frames_tx.send((1, frame.family)).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let mut cfg = test_config();
        cfg.url = format!("ws://127.0.0.1:{port}/na");
        let client = HubClient::spawn(cfg);
        let _session = client.register_session("w-rc", capability(), "job-rc");

        // On the reconnect, REGISTER must be observed before CLAIM.
        let mut first_register = None;
        let mut first_claim = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut i = 0usize;
        while first_register.is_none() || first_claim.is_none() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let (_conn, fam) = tokio::time::timeout(remaining, frames_rx.recv())
                .await
                .expect("timed out awaiting reconnect resync")
                .expect("server frame channel closed");
            match fam {
                Family::Register if first_register.is_none() => first_register = Some(i),
                Family::Claim if first_claim.is_none() => first_claim = Some(i),
                _ => {}
            }
            i += 1;
        }
        assert!(
            first_register.unwrap() < first_claim.unwrap(),
            "reconnect re-CLAIMed before re-REGISTERing"
        );
        client.shutdown().await;
        let _ = server.await;
    }

    // --- Regression tests for round-3 review findings ---

    // Finding A: eviction must respect lane priority. A buffer holding only
    // control frames must DROP an incoming bulk frame rather than evict a
    // control frame to admit it (the old eviction shed the least-important
    // *non-empty* lane, which was control here).
    #[tokio::test]
    async fn bulk_push_is_dropped_rather_than_evicting_control() {
        let mut cfg = test_config();
        cfg.buffer_capacity = 2;
        let client = HubClient::spawn(cfg);
        client.enqueue(Lane::Control, Family::Register, json!({ "instance": "w", "n": 1 }));
        client.enqueue(Lane::Control, Family::Claim, json!({ "instance": "w", "n": 2 }));
        // Buffer is now full of control. A bulk push must be dropped on the floor.
        client.enqueue(Lane::Bulk, Family::Relay, json!({ "n": 3 }));
        let frames = buffered(&client);
        assert_eq!(frames.len(), 2, "bulk must be dropped, not buffered");
        assert!(
            frames.iter().all(|(l, _, _)| *l == Lane::Control),
            "both control frames must survive a bulk push at capacity"
        );
        client.shutdown().await;
    }

    // Finding A sibling: an interactive frame may evict bulk but never control.
    #[tokio::test]
    async fn interactive_push_evicts_bulk_not_control_at_capacity() {
        let mut cfg = test_config();
        cfg.buffer_capacity = 2;
        let client = HubClient::spawn(cfg);
        client.enqueue(Lane::Control, Family::Register, json!({ "instance": "w" }));
        client.enqueue(Lane::Bulk, Family::Relay, json!({ "n": 1 }));
        // Full: one control + one bulk. Interactive evicts the bulk, keeps control.
        client.enqueue(Lane::Interactive, Family::Relay, json!({ "steer": true }));
        let frames = buffered(&client);
        assert_eq!(frames.len(), 2);
        assert!(
            frames.iter().any(|(l, _, _)| *l == Lane::Control),
            "control must survive an interactive push"
        );
        assert!(
            frames.iter().any(|(l, _, _)| *l == Lane::Interactive),
            "interactive frame must be admitted"
        );
        assert!(
            !frames.iter().any(|(l, _, _)| *l == Lane::Bulk),
            "bulk must be the evicted lane"
        );
        client.shutdown().await;
    }

    // Finding C: route_inbound must reject a payload carrying `op` — our own
    // `{op:"produce", stream, chunk}` transcript echoed back must NOT be decoded
    // as inbound steer and re-injected into its own agent.
    #[tokio::test]
    async fn inbound_produce_echo_with_op_is_not_routed_as_steer() {
        let client = HubClient::spawn(test_config());
        let mut session = client.register_session("w-op", capability(), "job-op");
        let mut steer = session.take_steer().expect("steer receiver");
        let stream = compose_stream_id("w-op", "job-op");
        client.route_inbound(&json!({
            "op": "produce",
            "stream": stream,
            "chunk": "do the thing",
        }));
        assert!(
            steer.try_recv().is_err(),
            "a produce echo (has `op`) must not be routed as steer"
        );
        client.shutdown().await;
    }

    // Finding F: resync must not duplicate a REGISTER/CLAIM already buffered
    // while disconnected, and must emit REGISTER before CLAIM.
    #[tokio::test]
    async fn resync_dedups_buffered_presence_and_orders_register_before_claim() {
        let client = HubClient::spawn(test_config());
        // Buffered by register_session while "disconnected": a REGISTER + CLAIM.
        let _session = client.register_session("w-rs", capability(), "job-rs");
        client.resync_presence();
        let frames = buffered(&client);
        let registers = frames
            .iter()
            .filter(|(_, f, _)| *f == Family::Register)
            .count();
        let claims = frames.iter().filter(|(_, f, _)| *f == Family::Claim).count();
        assert_eq!(registers, 1, "REGISTER must not be duplicated by resync");
        assert_eq!(claims, 1, "CLAIM must not be duplicated by resync");
        let reg_pos = frames.iter().position(|(_, f, _)| *f == Family::Register);
        let claim_pos = frames.iter().position(|(_, f, _)| *f == Family::Claim);
        assert!(
            reg_pos < claim_pos,
            "REGISTER must drain before CLAIM after resync"
        );
        client.shutdown().await;
    }

    // Finding B: the transcript sink is bounded, so a stalled consumer cannot
    // grow it without limit.
    #[tokio::test]
    async fn transcript_sink_is_bounded() {
        let client = HubClient::spawn(test_config());
        let mut session = client.register_session("w-b", capability(), "job-b");
        let sink = session.transcript_sink().expect("transcript sink");
        assert_eq!(sink.max_capacity(), TRANSCRIPT_CHANNEL_BOUND);
        client.shutdown().await;
    }

    // Findings D + E: shutdown signals AND awaits the connection task, and the
    // connect loop is racing shutdown — so shutdown returns promptly even when
    // the client has never managed to connect (and is mid-backoff/connect).
    #[tokio::test]
    async fn shutdown_awaits_task_and_returns_promptly_when_never_connected() {
        let client = HubClient::spawn(test_config()); // port 1: never connects
        let _session = client.register_session("w-sd", capability(), "job-sd");
        tokio::time::timeout(Duration::from_secs(5), client.shutdown())
            .await
            .expect("shutdown must return promptly, not hang on connect/backoff");
    }

    // Finding (round 4): the inbound steer channel is bounded, so a hub flooding
    // controls faster than the turn consumes them cannot grow memory without
    // limit — overflow is dropped, not queued.
    #[tokio::test]
    async fn inbound_steer_channel_is_bounded_and_drops_on_overflow() {
        let client = HubClient::spawn(test_config());
        let mut session = client.register_session("w-sb", capability(), "job-sb");
        let steer = session.take_steer().expect("steer receiver");
        assert_eq!(steer.max_capacity(), STEER_CHANNEL_BOUND);
        let stream = compose_stream_id("w-sb", "job-sb");
        // Flood well past the bound without consuming; the receiver must cap at
        // the bound (the rest are dropped), never grow to the full flood.
        for _ in 0..(STEER_CHANNEL_BOUND * 4) {
            client.route_inbound(&json!({
                "stream": stream,
                "offset": 0,
                "chunk": "x",
            }));
        }
        let mut drained = 0usize;
        let mut steer = steer;
        while steer.try_recv().is_ok() {
            drained += 1;
        }
        assert!(
            drained <= STEER_CHANNEL_BOUND,
            "steer channel grew past its bound: {drained} > {STEER_CHANNEL_BOUND}"
        );
        client.shutdown().await;
    }

    // Finding (round 4): the transcript incarnation is re-stamped at DRAIN time
    // from the current generation, so a chunk buffered during an outage (or
    // re-buffered after a failed write) fences the stale producer on the new
    // connection rather than carrying the old generation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_restamps_relay_incarnation_to_current_generation() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (frames_tx, mut frames_rx) = mpsc::unbounded_channel::<Value>();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let ws = accept_async(sock).await.unwrap();
            let (_write, mut read) = ws.split();
            while let Some(Ok(Message::Binary(bytes))) = read.next().await {
                let frame = decode_frame(&bytes).expect("server decodes a frame");
                if frame.family == Family::Relay {
                    let _ = frames_tx.send(frame.payload);
                }
            }
        });

        let mut cfg = test_config();
        cfg.url = format!("ws://127.0.0.1:{port}/na");
        let client = HubClient::spawn(cfg);
        // Buffer a relay produce frame stamped with the OLD generation (0) while
        // "disconnected", as if queued during an outage.
        client.enqueue(
            Lane::Bulk,
            Family::Relay,
            json!({ "op": "produce", "stream": "s", "incarnation": 0, "chunk": "c" }),
        );
        // Simulate the reconnect bump: the new connection is generation 1.
        client.generation.fetch_add(1, Ordering::Relaxed);
        client.connected.store(true, Ordering::Relaxed);
        // Wait for the produce frame to arrive on the wire.
        let payload = tokio::time::timeout(Duration::from_secs(5), frames_rx.recv())
            .await
            .expect("produce frame did not drain")
            .expect("server channel closed");
        assert_eq!(
            payload["incarnation"], 1,
            "drain must re-stamp the incarnation to the current generation"
        );
        client.shutdown().await;
        server.abort();
    }

    // Finding (round 4): the reconnect resync snapshot is admitted within the
    // shared buffer capacity — it sheds lower-priority (bulk) traffic to make
    // room rather than bypassing the bound with a raw push_front.
    #[tokio::test]
    async fn resync_snapshot_respects_buffer_capacity() {
        let mut cfg = test_config();
        cfg.buffer_capacity = 4;
        let client = HubClient::spawn(cfg);
        // Fill the buffer with bulk traffic while "disconnected".
        for i in 0..4 {
            client.enqueue(Lane::Bulk, Family::Relay, json!({ "n": i }));
        }
        assert_eq!(client.outbound.lock().unwrap().len(), 4);
        // Register a session so the resync snapshot has a REGISTER + a CLAIM.
        let _session = client.register_session("w-cap", capability(), "job-cap");
        client.resync_presence();
        let frames = buffered(&client);
        // The snapshot's REGISTER + CLAIM are present, and the total stays
        // within the advertised capacity (bulk was shed to make room).
        assert!(frames.iter().any(|(_, f, _)| *f == Family::Register));
        assert!(frames.iter().any(|(_, f, _)| *f == Family::Claim));
        assert!(
            frames.len() <= 4,
            "resync must not exceed buffer capacity: {} > 4",
            frames.len()
        );
        client.shutdown().await;
    }

    // Finding (round 4): dropping a session flushes its accepted transcript tail
    // into the buffer BEFORE the RELEASE is enqueued, so no chunk is emitted for
    // a job the hub has already released.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn release_is_enqueued_after_transcript_tail() {
        let client = HubClient::spawn(test_config());
        let mut session = client.register_session("w-fl", capability(), "job-fl");
        let sink = session.transcript_sink().expect("transcript sink");
        let _ = buffered(&client); // discard register/claim
        sink.try_send(json!({
            "sessionUpdate": "agent_message_chunk",
            "content": { "type": "text", "text": "tail" }
        }))
        .unwrap();
        // Dropping the session flushes the bridged chunk, then RELEASEs.
        drop(session);
        // Assert ENQUEUE order (frame `seq`), not drain order: the buffer always
        // drains control (RELEASE) before bulk (transcript), so the guarantee
        // being tested is that the tail was enqueued first — i.e. it sits in the
        // buffer ahead of the RELEASE in insertion order.
        let log = client.enqueue_log();
        let relay_seq = log
            .iter()
            .find(|(_, _, f)| *f == Family::Relay)
            .map(|(s, _, _)| *s);
        let release_seq = log
            .iter()
            .find(|(_, _, f)| *f == Family::Release)
            .map(|(s, _, _)| *s);
        let relay_seq = relay_seq.expect("the accepted transcript chunk must be flushed, not lost");
        let release_seq = release_seq.expect("drop must enqueue a RELEASE");
        assert!(
            relay_seq < release_seq,
            "transcript tail (seq {relay_seq}) must be enqueued before RELEASE (seq {release_seq})"
        );
        client.shutdown().await;
    }
}
