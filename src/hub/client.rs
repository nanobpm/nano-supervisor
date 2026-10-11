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
use crate::hub::frame::{decode_frame, encode_frame, Family, Frame, Lane, FRAME_HEADER_BYTES};
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
/// Ceiling on any single socket write/flush. A hub that stops reading lets TCP
/// backpressure fill the kernel send buffer; without this bound `drain` (and so
/// the entire connection task, including the `shutdown`-watch branch that only
/// runs between `select!` iterations) could park inside one `send` forever,
/// wedging reconnect and shutdown alike. On timeout the in-flight frame is
/// re-buffered and the connection is torn down so reconnect — or shutdown — can
/// proceed instead of blocking on the wedged socket.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Count ceiling on the ACP-update → transcript bridge channel. It sits in
/// front of the already-byte-bounded outbound [`LaneBuffer`]; the EFFECTIVE
/// bound used per session is the smaller of this and a byte-derived bound (see
/// [`transcript_channel_bound`]), so this queue's own worst-case memory is held
/// to the configured byte budget instead of `1024 × 1 MiB ≈ 1 GiB`. On overflow
/// the producer drops the update rather than blocking the ACP read loop (see
/// `acp.rs`).
const TRANSCRIPT_CHANNEL_BOUND: usize = 1024;
/// Upper bound on a single buffered `session/update` value. The ACP reader caps
/// each JSON-RPC line (hence each update) at ~1 MiB, so this mirrors `acp.rs`'s
/// `MAX_ACP_FRAME` and lets [`transcript_channel_bound`] translate the byte
/// budget into a worst-case item count for the pre-buffer queue.
const MAX_TRANSCRIPT_UPDATE_BYTES: usize = 1 << 20; // 1 MiB, mirrors acp::MAX_ACP_FRAME
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
/// Maximum frames `drain` writes to the socket before yielding back to the
/// connection `select!` loop (finding: a sustained transcript producer must not
/// keep the outbound buffer non-empty and so starve `read.next()` and
/// `shutdown.changed()`, which would stop an inbound cancel from ever reaching a
/// noisy job). After this many writes `drain` re-arms the outbound notify (if
/// frames remain) and returns, so reads and shutdown stay serviceable while the
/// backlog still drains promptly. A terminal shutdown drain passes `0` to drain
/// the whole DEREGISTER snapshot in one pass.
const DRAIN_BATCH: usize = 256;

/// A buffered frame carrying its precomputed on-wire byte size, so the buffer
/// can enforce a memory (byte) budget without re-serialising the payload on
/// every eviction/drain.
struct BufferedFrame {
    bytes: usize,
    frame: Frame,
}

/// Approximate on-wire byte size of a frame: the fixed header plus its
/// serialised JSON payload. Used only for the buffer's memory budget, so a
/// serialisation failure (never expected for frames we construct) counts as the
/// header alone.
fn frame_bytes(frame: &Frame) -> usize {
    FRAME_HEADER_BYTES
        + serde_json::to_string(&frame.payload)
            .map(|s| s.len())
            .unwrap_or(0)
}

/// Compose the `<instance>/<jobKey>` stream id from a presence frame payload
/// (`CLAIM`/`RELEASE` both carry `{instance, jobKey}`). `None` when either field
/// is absent, so a malformed frame never matches a real stream.
fn presence_stream_id(payload: &Value) -> Option<String> {
    let instance = payload.get("instance").and_then(Value::as_str)?;
    let job_key = payload.get("jobKey").and_then(Value::as_str)?;
    Some(compose_stream_id(instance, job_key))
}

/// Effective count bound for one session's pre-buffer transcript channel,
/// derived from the configured outbound byte budget. Each queued update is
/// bounded to [`MAX_TRANSCRIPT_UPDATE_BYTES`] by the ACP reader, so capping the
/// channel at `byte_budget / MAX_TRANSCRIPT_UPDATE_BYTES` holds this queue's
/// worst-case memory to the same budget as the outbound buffer (rather than a
/// flat `1024 × 1 MiB ≈ 1 GiB`). A disabled byte budget (`0`, meaning the
/// outbound buffer enforces no byte cap) falls back to the flat count ceiling.
/// The result is clamped to `1..=TRANSCRIPT_CHANNEL_BOUND` so a tiny budget
/// still admits at least one update and a large one never exceeds the ceiling.
fn transcript_channel_bound(byte_budget: usize) -> usize {
    if byte_budget == 0 {
        return TRANSCRIPT_CHANNEL_BOUND;
    }
    (byte_budget / MAX_TRANSCRIPT_UPDATE_BYTES).clamp(1, TRANSCRIPT_CHANNEL_BOUND)
}

/// A bounded, QoS-aware outbound buffer: one FIFO queue per lane, with a shared
/// frame-count cap AND a shared byte budget. Draining prefers control →
/// interactive → bulk; overflow eviction sheds the least-important non-empty
/// lane first (bulk, then interactive, then control), so a bulk transcript
/// flood can never displace a `register`/`claim`/`deregister` control frame and
/// break presence. The byte budget bounds *memory*: a count cap alone cannot,
/// because a single transcript chunk may be ~1 MiB, so `capacity` frames could
/// otherwise retain ~1 GiB.
#[derive(Default)]
struct LaneBuffer {
    control: VecDeque<BufferedFrame>,
    interactive: VecDeque<BufferedFrame>,
    bulk: VecDeque<BufferedFrame>,
    capacity: usize,
    byte_capacity: usize,
    bytes: usize,
}

impl LaneBuffer {
    fn with_limits(capacity: usize, byte_capacity: usize) -> LaneBuffer {
        LaneBuffer {
            capacity,
            byte_capacity,
            ..LaneBuffer::default()
        }
    }

    fn len(&self) -> usize {
        self.control.len() + self.interactive.len() + self.bulk.len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Would admitting `incoming` more bytes still fit the byte budget? A zero
    /// budget means "unbounded" (never used in production, but keeps tests that
    /// only exercise the count cap simple).
    fn bytes_fit(&self, incoming: usize) -> bool {
        self.byte_capacity == 0 || self.bytes + incoming <= self.byte_capacity
    }

    /// Append `frame` to its lane. When either the count cap OR the byte budget
    /// would be exceeded, evict to make room — but only ever shed a frame whose
    /// priority is at or below the incoming frame's, least-important lane first,
    /// and NEVER a control frame. A bulk flood can therefore displace only other
    /// bulk frames; it can never evict an interactive or control frame to admit
    /// itself. When nothing at or below the incoming priority remains to evict
    /// (the buffer holds only higher-priority traffic, or the frame alone
    /// exceeds the whole byte budget), the incoming frame is dropped instead —
    /// presence/steer control is never sacrificed, even for another control
    /// frame (see [`LaneBuffer::evict_for`]).
    fn push(&mut self, frame: Frame) {
        if self.capacity == 0 {
            return; // no room at all: drop on the floor
        }
        let bytes = frame_bytes(&frame);
        while self.len() >= self.capacity || !self.bytes_fit(bytes) {
            if !self.evict_for(frame.lane) {
                return; // only higher-priority frames remain / too large: drop
            }
        }
        self.store_back(BufferedFrame { bytes, frame });
    }

    fn store_back(&mut self, bf: BufferedFrame) {
        self.bytes += bf.bytes;
        match bf.frame.lane {
            Lane::Control => self.control.push_back(bf),
            Lane::Interactive => self.interactive.push_back(bf),
            Lane::Bulk => self.bulk.push_back(bf),
        }
    }

    fn store_front(&mut self, bf: BufferedFrame) {
        self.bytes += bf.bytes;
        match bf.frame.lane {
            Lane::Control => self.control.push_front(bf),
            Lane::Interactive => self.interactive.push_front(bf),
            Lane::Bulk => self.bulk.push_front(bf),
        }
    }

    fn account_removed(&mut self, bf: &BufferedFrame) {
        self.bytes = self.bytes.saturating_sub(bf.bytes);
    }

    /// Evict the oldest frame whose lane priority is at or below `incoming`'s,
    /// least-important lane first. Returns `false` when no such frame exists —
    /// i.e. every buffered frame strictly outranks `incoming` — so the caller
    /// drops the incoming frame rather than displacing higher-priority traffic.
    ///
    /// CONTROL IS NEVER EVICTED, not even by another control frame: presence
    /// frames are an ordered, interdependent set (a `CLAIM` is meaningless
    /// without its prerequisite `REGISTER`, and `REGISTER` strictly precedes
    /// `CLAIM`), so shedding one control frame to admit another can silently
    /// desync ownership — e.g. under a tiny `NANO_AGENTIC_BUFFER_CAPACITY` a
    /// `register_session`'s CLAIM would evict the REGISTER it was enqueued
    /// after, and the hub would learn ownership of an instance it never saw
    /// registered. Control is low-volume by design, so when only control
    /// remains the incoming frame is dropped instead (a bounded buffer must
    /// drop *something*; dropping the newcomer preserves the ordering of what
    /// is already queued). The reconnect resync rebuilds the full presence set
    /// from state via `push_front_control_bounded`, so a dropped frame is
    /// repaired on the next reconnect.
    fn evict_for(&mut self, incoming: Lane) -> bool {
        let evicted = match incoming {
            // Bulk may only evict bulk.
            Lane::Bulk => self.bulk.pop_front(),
            // Interactive may evict bulk, then interactive — never control.
            Lane::Interactive => self.bulk.pop_front().or_else(|| self.interactive.pop_front()),
            // Control may shed lower-priority traffic (bulk, then interactive)
            // to make room, but NEVER another control frame (see above).
            Lane::Control => self.bulk.pop_front().or_else(|| self.interactive.pop_front()),
        };
        match evicted {
            Some(bf) => {
                self.account_removed(&bf);
                true
            }
            None => false,
        }
    }

    /// Pop the next frame to send, draining the highest-priority lane first.
    fn pop(&mut self) -> Option<Frame> {
        let bf = self
            .control
            .pop_front()
            .or_else(|| self.interactive.pop_front())
            .or_else(|| self.bulk.pop_front())?;
        self.account_removed(&bf);
        Some(bf.frame)
    }

    /// Pop the next NON-control frame (interactive first, then bulk). Used by
    /// the RELEASE drain barrier to write a session's transcript tail to the
    /// socket before its RELEASE: control frames are left in place while the
    /// lower lanes are flushed. Returns `None` when only control frames remain.
    fn pop_lower_lane(&mut self) -> Option<Frame> {
        let bf = self.interactive.pop_front().or_else(|| self.bulk.pop_front())?;
        self.account_removed(&bf);
        Some(bf.frame)
    }

    /// Pop the next CONTROL frame only, leaving the lower (interactive/bulk)
    /// lanes untouched. Used by the terminal shutdown drain ([`drain_control`]),
    /// which must flush the DEREGISTER control snapshot to the socket but
    /// deliberately DISCARDS the lower-lane backlog (bulk transcript,
    /// interactive steer) rather than blocking shutdown on it. Returns `None`
    /// when the control lane is empty, even if lower lanes still hold frames.
    fn pop_control(&mut self) -> Option<Frame> {
        let bf = self.control.pop_front()?;
        self.account_removed(&bf);
        Some(bf.frame)
    }

    /// Re-admit a popped frame to the FRONT of its lane (a write failed or timed
    /// out; retry it first on reconnect, preserving its lane priority). The
    /// buffer is NOT guaranteed to still be at its pre-pop size: producers can
    /// refill the freed slot while the failing write is awaited, so this re-runs
    /// the SAME priority-aware eviction as `push` before restoring the frame —
    /// otherwise repeated write failures could grow the buffer past its
    /// advertised count/byte caps. When only strictly-higher-priority traffic
    /// remains (or the frame alone exceeds the whole byte budget), the retry
    /// frame is dropped rather than displacing more important frames. Like
    /// `push`, a control retry never evicts another control frame (see
    /// [`LaneBuffer::evict_for`]).
    fn push_front(&mut self, frame: Frame) {
        if self.capacity == 0 {
            return; // no room at all: drop on the floor
        }
        let bytes = frame_bytes(&frame);
        while self.len() >= self.capacity || !self.bytes_fit(bytes) {
            if !self.evict_for(frame.lane) {
                return; // only higher-priority frames remain / too large: drop
            }
        }
        self.store_front(BufferedFrame { bytes, frame });
    }

    /// Re-admit a popped frame to the FRONT of its lane after a failed or
    /// timed-out write, like [`push_front`] — but a MUST-DELIVER control frame
    /// (`RELEASE` / `DEREGISTER`) is re-admitted EXEMPT from the buffer bound
    /// (via [`push_front_control_bounded`]) so a write failure can NEVER silently
    /// drop it. A `RELEASE` for a job already removed from `in_flight` cannot be
    /// rebuilt by the reconnect resync, so dropping it on re-buffer would strand
    /// the job's CLAIM on the hub (ownership desync); a `DEREGISTER` is the only
    /// frame that retires a worker's presence. Everything else re-buffers through
    /// the ordinary bounded [`push_front`], which may shed it under pressure
    /// (transcript/steer is repairable, presence is not).
    fn requeue_front(&mut self, frame: Frame) {
        if frame.lane == Lane::Control
            && matches!(frame.family, Family::Release | Family::Deregister)
        {
            self.push_front_control_bounded(frame);
        } else {
            self.push_front(frame);
        }
    }

    /// Prepend a CONTROL frame to the front of its lane, shedding lower-priority
    /// (bulk, then interactive) traffic to make room — never another control
    /// frame, so presence/ownership ordering is preserved. Used by the reconnect
    /// resync snapshot, which must land at the front in REGISTER-then-CLAIM
    /// order.
    ///
    /// PRESENCE IS EXEMPT FROM THE BUFFER BOUND (a deliberate capacity-semantics
    /// decision, not an oversight): when only control frames remain and the
    /// count/byte cap is still exceeded, this stops evicting and prepends the
    /// snapshot frame anyway, so a presence set larger than a tiny
    /// `NANO_AGENTIC_BUFFER_CAPACITY` is NOT dropped or fragmented. Rationale:
    /// presence is already bounded by live instances + in-flight jobs (a small,
    /// meaningful set), and dropping or fragmenting it would hide workers from
    /// the hub or desync ownership — a worse failure than transiently exceeding a
    /// memory bound by a few small control frames. The count/byte budget still
    /// bounds the *transcript/bulk* traffic that dominates memory; presence
    /// frames are exempt because their correctness (every worker visible, every
    /// claim owned) matters more than their negligible bytes.
    fn push_front_control_bounded(&mut self, frame: Frame) {
        debug_assert_eq!(frame.lane, Lane::Control);
        let bytes = frame_bytes(&frame);
        while self.len() >= self.capacity || !self.bytes_fit(bytes) {
            // Shed the least-important non-control frame. If only control
            // frames remain, stop evicting (presence is EXEMPT from the bound —
            // see the doc comment) and prepend anyway: the snapshot is bounded
            // by live instances+jobs, never by the configured buffer limits.
            let evicted = self.bulk.pop_front().or_else(|| self.interactive.pop_front());
            match evicted {
                Some(bf) => self.account_removed(&bf),
                None => break,
            }
        }
        self.store_front(BufferedFrame { bytes, frame });
    }

    /// Append a CONTROL frame to the BACK of the control lane, shedding only
    /// lower-priority (bulk, then interactive) traffic to make room and NEVER
    /// dropping the control frame itself — the same capacity EXEMPTION as
    /// [`push_front_control_bounded`], but preserving enqueue order at the tail.
    /// Used for the shutdown DEREGISTER snapshot: a clean shutdown must emit a
    /// DEREGISTER for EVERY registered worker, so when the configured capacity is
    /// smaller than the number of registered slots the ordinary bounded `push`
    /// (which drops a control newcomer once the control lane fills, since control
    /// never evicts control) would silently send only a subset. Presence is
    /// bounded by live instances, so admitting the whole snapshot is safe.
    fn push_back_control_bounded(&mut self, frame: Frame) {
        debug_assert_eq!(frame.lane, Lane::Control);
        let bytes = frame_bytes(&frame);
        while self.len() >= self.capacity || !self.bytes_fit(bytes) {
            let evicted = self.bulk.pop_front().or_else(|| self.interactive.pop_front());
            match evicted {
                Some(bf) => self.account_removed(&bf),
                None => break,
            }
        }
        self.store_back(BufferedFrame { bytes, frame });
    }
    /// supersedes presence for live instances + in-flight jobs, so leaving those
    /// stale frames in place would duplicate presence/ownership and let a
    /// `CLAIM` buffered while disconnected drain ahead of the snapshot's
    /// `REGISTER`.
    ///
    /// A `CLAIM` WHOSE STREAM HAS A PENDING `RELEASE` IS KEPT: that is a job
    /// which started and finished during the outage. `release_job` has already
    /// removed it from `in_flight`, so the resync snapshot CANNOT recreate its
    /// `CLAIM`; dropping the buffered one would send the preserved transcript
    /// and the `RELEASE` without the prerequisite ownership frame, desyncing the
    /// hub (a `RELEASE`/transcript for a job it never saw claimed). Preserving
    /// the `CLAIM` keeps the whole `CLAIM → tail → RELEASE` sequence intact.
    /// Other control families (`RELEASE`/`DEREGISTER`/`HEARTBEAT`) are preserved.
    fn drop_control_presence(&mut self) {
        // Streams with a buffered RELEASE: their CLAIM is for a completed job
        // the snapshot cannot rebuild, so it must survive this prune.
        let pending_release: HashSet<String> = self
            .control
            .iter()
            .filter(|bf| bf.frame.family == Family::Release)
            .filter_map(|bf| presence_stream_id(&bf.frame.payload))
            .collect();
        let mut freed = 0;
        self.control.retain(|bf| {
            let drop_it = match bf.frame.family {
                Family::Register => true,
                Family::Claim => presence_stream_id(&bf.frame.payload)
                    .map(|s| !pending_release.contains(&s))
                    .unwrap_or(true),
                _ => false,
            };
            if drop_it {
                freed += bf.bytes;
            }
            !drop_it
        });
        self.bytes = self.bytes.saturating_sub(freed);
    }

    /// Test-only: iterate every buffered frame (across all lanes) so a test can
    /// read each frame's `seq` — the enqueue order — independent of drain order.
    #[cfg(test)]
    fn iter_frames(&self) -> impl Iterator<Item = &Frame> {
        self.control
            .iter()
            .chain(self.interactive.iter())
            .chain(self.bulk.iter())
            .map(|bf| &bf.frame)
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
    /// Per-session RELEASE drain barriers, keyed by the session's composed
    /// **stream id** (`<instance>/<jobKey>`) — the same identity a drained
    /// RELEASE frame carries, so `drain` can look the barrier up directly.
    /// [`HubSession::close`] arms the barrier when it enqueues the RELEASE;
    /// `drain` then flushes the buffered lower-lane transcript tail to the
    /// socket BEFORE writing that RELEASE. This preserves the cross-lane
    /// ordering `LaneBuffer::pop` alone cannot (control drains before bulk).
    release_barriers: Mutex<HashMap<String, ReleaseBarrier>>,
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
            .field("buffer_byte_budget", &self.config.buffer_byte_budget)
            .finish_non_exhaustive()
    }
}

impl HubClient {
    /// Start the single hub connection task and return the shared client. The
    /// task runs until [`HubClient::shutdown`] (or the process exits).
    ///
    /// `slots` is the identity `(instance, capability)` of every configured
    /// worker slot this daemon serves. Each is REGISTERed at spawn — and
    /// re-REGISTERed on every reconnect — independently of any job, so idle
    /// capacity is visible on the hub from the moment the daemon connects
    /// (register-on-connect), not lazily on a slot's first job. An "instance"
    /// is one configured slot's worker identity (e.g. `host-nanod-<hire>-<n>`);
    /// it stays registered for the daemon's lifetime and heartbeats while
    /// connected, whether or not it is running a job. Job ownership (CLAIM /
    /// RELEASE) remains per-job via [`HubClient::register_session`].
    pub fn spawn(config: HubConfig, slots: &[(String, Value)]) -> Arc<HubClient> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let capacity = config.buffer_capacity;
        let byte_capacity = config.buffer_byte_budget;
        // Pre-seed the presence set with every configured slot so the very first
        // connect's resync snapshot (and each heartbeat) covers idle slots too.
        // Fold the config-level advertisement into each capability exactly as
        // `register_session` would, so a slot's identity is identical whether it
        // is idle or running a job.
        let mut instances = HashMap::new();
        for (instance, capability) in slots {
            instances.insert(instance.clone(), capability.clone());
        }
        let slot_count = instances.len();
        let client = Arc::new(HubClient {
            config,
            outbound: Mutex::new(LaneBuffer::with_limits(capacity, byte_capacity)),
            outbound_notify: Notify::new(),
            seq: AtomicU32::new(0),
            connected: AtomicBool::new(false),
            generation: AtomicU32::new(0),
            instances: Mutex::new(instances),
            in_flight: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            shutdown_tx,
            conn_task: Mutex::new(None),
            bridge_tasks: Mutex::new(HashMap::new()),
            next_session_seq: AtomicU64::new(0),
            release_barriers: Mutex::new(HashMap::new()),
            rng: AtomicU64::new(seed_rng()),
        });
        // Fold the config-level advertisement into each pre-seeded capability.
        // Done after the Arc is built because `capability_payload` reads config.
        {
            let mut insts = client.instances.lock().unwrap();
            let seeded: Vec<(String, Value)> = insts
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (instance, cap) in seeded {
                insts.insert(instance, client.capability_payload(cap));
            }
        }
        log(&format!(
            "agentic hub: enabled → {} (buffer {} frame(s), {} slot(s) registered{})",
            client.config.url,
            client.config.buffer_capacity,
            slot_count,
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

        // Worker presence + job ownership. The state mutations (instances,
        // in_flight) AND the matching REGISTER/CLAIM enqueues are performed
        // together under the SINGLE outbound lock, so they are atomic with
        // respect to `resync_presence` (which also takes the outbound lock while
        // it snapshots that state and replaces the buffered presence frames).
        // Without this, a reconnect snapshot could read the state BEFORE this
        // insert, then `drop_control_presence` could delete the REGISTER/CLAIM
        // this call just enqueued — leaving the live job unregistered until the
        // next reconnect. Lock order is always outbound → instances/in_flight
        // (the heartbeat/shutdown loops snapshot keys first to honour it), so no
        // deadlock is possible.
        {
            let mut buf = self.outbound.lock().unwrap();
            // REGISTER this instance exactly once (its lifetime is the worker's,
            // not any single job's), folding in the config-level advertisement.
            let register = {
                let mut insts = self.instances.lock().unwrap();
                if insts.contains_key(instance) {
                    None
                } else {
                    let cap = self.capability_payload(capability);
                    insts.insert(instance.to_string(), cap.clone());
                    Some(cap)
                }
            };
            if let Some(cap) = register {
                buf.push(self.make_frame(
                    Lane::Control,
                    Family::Register,
                    json!({ "instance": instance, "capability": cap }),
                ));
            }
            // Job ownership: CLAIM {instance, jobKey}; track in-flight so a
            // reconnect re-claims it.
            self.in_flight
                .lock()
                .unwrap()
                .entry(instance.to_string())
                .or_default()
                .insert(job_key.to_string());
            buf.push(self.make_frame(
                Lane::Control,
                Family::Claim,
                json!({ "instance": instance, "jobKey": job_key }),
            ));
        }
        self.outbound_notify.notify_one();

        // Bridge ACP updates → transcript produce frames on a dedicated task.
        // A *bounded* channel: it fronts the already-byte-bounded outbound
        // buffer, so an unbounded (or loosely count-bounded) one here would let a
        // fast agent's updates — each up to ~1 MiB — accumulate and defeat that
        // memory cap. The bound is derived from the configured byte budget (see
        // `transcript_channel_bound`), not the flat count ceiling, so this
        // pre-buffer queue's own worst case stays within the documented budget.
        let channel_bound = transcript_channel_bound(self.config.buffer_byte_budget);
        let (updates_tx, mut updates_rx) = mpsc::channel::<Value>(channel_bound);
        let bridge_client = self.clone();
        let bridge_stream = stream.clone();
        // The bridge drains updates until EITHER the channel closes (all senders
        // dropped) OR the session's drop signals a flush, whichever first — then
        // it finishes and notifies the (synchronous) flush waiter. The flush
        // signal lets a drop close input and wait for the tail without needing
        // the last sender to be gone first.
        let (close_tx, mut close_rx) = watch::channel(false);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
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
        // Retain the bridge's JoinHandle (do NOT detach it): `close` aborts and
        // joins it on a flush timeout so a wedged bridge cannot keep producing
        // transcript AFTER the RELEASE. Track the flush handle under a UNIQUE
        // session id (not the stream id, which a later session for the same job
        // would reuse and so could steal this session's flush handle), so this
        // session's drop flushes exactly its own bridge before RELEASE.
        let session_id = self.next_session_seq.fetch_add(1, Ordering::Relaxed);
        self.bridge_tasks.lock().unwrap().insert(
            session_id,
            BridgeFlush {
                close_tx,
                done_rx,
                handle: bridge_handle,
            },
        );
        // Arm the RELEASE drain barrier for this session, keyed by its stream id
        // (the identity a drained RELEASE carries). `close` arms it before
        // enqueueing the RELEASE; `drain` then flushes the transcript tail to
        // the socket before writing that RELEASE.
        self.release_barriers
            .lock()
            .unwrap()
            .insert(stream.clone(), ReleaseBarrier::default());

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

    /// Build a frame with the next monotonic sequence number (but do not
    /// enqueue it). Used where the caller must push into an already-held
    /// outbound lock (e.g. [`HubClient::register_session`], which mutates
    /// presence state and enqueues the matching control frame atomically so a
    /// concurrent reconnect resync cannot delete it).
    fn make_frame(&self, lane: Lane, family: Family, payload: Value) -> Frame {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        Frame::new(lane, family, seq, payload)
    }

    /// Enqueue a frame for delivery. Bounded and QoS-aware: see [`LaneBuffer`].
    fn enqueue(&self, lane: Lane, family: Family, payload: Value) {
        let frame = self.make_frame(lane, family, payload);
        self.outbound.lock().unwrap().push(frame);
        self.outbound_notify.notify_one();
    }

    /// Enqueue a CONTROL frame EXEMPT from the buffer bound (see
    /// [`LaneBuffer::push_back_control_bounded`]): it sheds lower-priority
    /// traffic to make room but is never itself dropped. Used for the shutdown
    /// DEREGISTER snapshot so a clean shutdown deregisters every worker even when
    /// capacity is smaller than the number of registered slots.
    fn enqueue_control_exempt(&self, family: Family, payload: Value) {
        let frame = self.make_frame(Lane::Control, family, payload);
        self.outbound
            .lock()
            .unwrap()
            .push_back_control_bounded(frame);
        self.outbound_notify.notify_one();
    }

    /// RELEASE a job: remove it from the in-flight set (so a reconnect stops
    /// re-claiming it) and enqueue the `release {instance, jobKey}` control
    /// frame. Called by [`HubSession::close`] (behind the drain barrier) and, as
    /// a best-effort fallback, by `Drop` when a session was never closed.
    ///
    /// The RELEASE is enqueued EXEMPT from the buffer bound (via
    /// [`HubClient::enqueue_control_exempt`] /
    /// [`LaneBuffer::push_back_control_bounded`]), NOT the ordinary bounded
    /// [`HubClient::enqueue`]. Once the job is removed from `in_flight` the
    /// reconnect resync can no longer recreate its CLAIM, so this RELEASE is the
    /// ONLY frame that can retire the hub's ownership of the job. The bounded
    /// `enqueue` drops a control newcomer when the control lane is full (control
    /// never evicts control), which would silently strand the job's CLAIM on the
    /// hub forever — an unrepairable ownership desync. The exempt admission sheds
    /// lower-priority traffic to make room but never drops the RELEASE itself.
    fn release_job(&self, instance: &str, job_key: &str) {
        if let Some(jobs) = self.in_flight.lock().unwrap().get_mut(instance) {
            jobs.remove(job_key);
        }
        self.enqueue_control_exempt(
            Family::Release,
            json!({ "instance": instance, "jobKey": job_key }),
        );
    }

    /// Arm a session's RELEASE drain barrier: the RELEASE `close` is about to
    /// enqueue must be deferred at the socket until the transcript tail already
    /// buffered ahead of it has been written. Called by [`HubSession::close`]
    /// AFTER the bridge flush and BEFORE the RELEASE is enqueued.
    fn arm_release_barrier(&self, stream: &str) {
        if let Some(barrier) = self.release_barriers.lock().unwrap().get_mut(stream) {
            barrier.armed = true;
        }
    }

    /// Decide what `drain` should do with a just-popped RELEASE. Looks the
    /// barrier up by the RELEASE's own `(instance, jobKey)` (composed to its
    /// stream id). A RELEASE with an ARMED barrier is deferred (`Defer`) so the
    /// transcript tail drains first; any other RELEASE (a `Drop` fallback, or an
    /// already-consumed barrier) is sent immediately (`SendNow`).
    fn release_gate(&self, payload: &Value) -> ReleaseGate {
        let (Some(instance), Some(job_key)) = (
            payload.get("instance").and_then(Value::as_str),
            payload.get("jobKey").and_then(Value::as_str),
        ) else {
            return ReleaseGate::SendNow;
        };
        let stream = compose_stream_id(instance, job_key);
        let barriers = self.release_barriers.lock().unwrap();
        match barriers.get(&stream) {
            Some(ReleaseBarrier { armed: true }) => ReleaseGate::Defer { stream },
            _ => ReleaseGate::SendNow,
        }
    }

    /// Consume a session's RELEASE barrier once `drain` has finally written the
    /// RELEASE (so a late duplicate or a reconnect resync does not re-defer).
    fn disarm_release_barrier(&self, stream: &str) {
        self.release_barriers.lock().unwrap().remove(stream);
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
        // Hold the outbound lock for the WHOLE snapshot-and-replace so it is
        // atomic with `register_session` (which mutates presence state and
        // enqueues its REGISTER/CLAIM under the same lock). Reading the state
        // inside this lock guarantees the snapshot and the buffered frames we
        // drop reflect the same instant: a concurrent registration either lands
        // entirely before us (its instance is in the snapshot) or entirely after
        // (its frames are enqueued after we replace) — never half-applied, which
        // is what let `drop_control_presence` delete a just-enqueued REGISTER.
        // Lock order is outbound → instances/in_flight everywhere, so no
        // deadlock (heartbeat/shutdown snapshot their keys before enqueuing).
        let mut buf = self.outbound.lock().unwrap();
        // Build the ordered snapshot (REGISTERs first, then CLAIMs) with fresh
        // sequence numbers. Reversed, so the capacity-aware re-admission below
        // lands the snapshot in its intended front order (REGISTER…, CLAIM…).
        let mut snapshot: Vec<Frame> = Vec::new();
        for (inst, cap) in self.instances.lock().unwrap().iter() {
            snapshot.push(self.make_frame(
                Lane::Control,
                Family::Register,
                json!({ "instance": inst, "capability": cap }),
            ));
        }
        for (inst, jobs) in self.in_flight.lock().unwrap().iter() {
            for job_key in jobs {
                snapshot.push(self.make_frame(
                    Lane::Control,
                    Family::Claim,
                    json!({ "instance": inst, "jobKey": job_key }),
                ));
            }
        }
        // Drop the superseded REGISTER/CLAIM frames first so the snapshot
        // re-admits them deduplicated. Prepending in REVERSE via
        // `push_front_control_bounded` lands the snapshot at the front in
        // REGISTER-then-CLAIM order while shedding only lower-priority
        // (bulk/interactive) traffic to make room — never another control frame
        // — so presence ordering holds. Presence is EXEMPT from the buffer bound
        // (see `push_front_control_bounded`): a presence set larger than a tiny
        // configured capacity is prepended whole rather than dropped or
        // fragmented, because it is already bounded by live instances+jobs and
        // hiding a worker from the hub is worse than transiently exceeding the
        // bulk-traffic memory budget by a few small control frames.
        buf.drop_control_presence();
        for frame in snapshot.into_iter().rev() {
            buf.push_front_control_bounded(frame);
        }
        drop(buf);
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
        // full delivery shape; anything carrying `op`, or missing the integer
        // `offset`, is dropped.
        if payload.get("op").is_some() {
            return; // not a delivery: producer/control frame echoed back
        }
        // A genuine delivery carries an unsigned integer byte `offset`; a
        // producer/control frame (or a hand-rolled `{stream, chunk}` object)
        // does not. Require it — a non-negative integer — BEFORE the session
        // lookup, so a frame lacking an offset (or carrying a non-integer one)
        // cannot masquerade as a delivery and inject steer into a live job.
        if !payload.get("offset").is_some_and(Value::is_u64) {
            return; // no integer offset: not a routable delivery
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
/// the bridge task has finished (so the tail is enqueued before RELEASE).
/// `done_rx` is a Tokio oneshot so the preferred async [`HubSession::close`] can
/// await it WITHOUT parking a runtime worker thread; the synchronous `Drop`
/// fallback never waits on it (it only signals `close_tx`).
///
/// `handle` is the bridge task's `JoinHandle`, retained (NOT detached) so
/// `close` can ABORT-AND-JOIN the bridge if the flush times out: a detached,
/// still-running bridge could otherwise keep enqueuing transcript chunks AFTER
/// `close` has armed and enqueued the RELEASE, breaking tail-before-RELEASE.
struct BridgeFlush {
    close_tx: watch::Sender<bool>,
    done_rx: tokio::sync::oneshot::Receiver<()>,
    handle: JoinHandle<()>,
}

/// A per-session RELEASE drain barrier (finding: a job's RELEASE must not
/// overtake its transcript tail ON THE WIRE). `LaneBuffer::pop` always drains
/// the control lane (RELEASE) before the bulk lane (transcript), so enqueue
/// order alone does not order them on the socket. While a barrier is armed for
/// a stream, `drain` flushes that stream's buffered lower-lane transcript tail
/// to the socket ([`drain_lower_lanes`]) BEFORE writing the RELEASE — so the
/// tail is on the wire first, without giving up control-over-bulk priority for
/// any other frame.
///
/// The barrier is armed by [`HubSession::close`] (which flushes the bridge tail
/// into the buffer first) and consumed by `drain` when it finally sends the
/// RELEASE. A `Drop` fallback RELEASE (a session dropped without `close`) arms
/// no barrier, so it is sent immediately — best-effort, as documented.
#[derive(Default)]
struct ReleaseBarrier {
    /// True once `close` has armed the barrier (the RELEASE is expected and the
    /// tail must be flushed first). Distinguishes an armed barrier from a
    /// `Drop`-fallback RELEASE that should be sent immediately.
    armed: bool,
}

/// What `drain` should do with a just-popped RELEASE frame (see
/// [`HubClient::release_gate`]).
enum ReleaseGate {
    /// No barrier applies — write the RELEASE to the socket immediately.
    SendNow,
    /// Flush this stream's buffered lower-lane tail to the socket first, then
    /// write the RELEASE. `stream` identifies the barrier to consume.
    Defer { stream: String },
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
    /// Asynchronously flush this session's transcript tail all the way toward
    /// the socket, then enqueue the job's RELEASE behind a drain barrier so it
    /// cannot overtake that tail on the wire. Steps: (1) close the bridge input
    /// and await its accepted updates reaching the outbound buffer; (2) arm this
    /// session's drain barrier; (3) enqueue the RELEASE. When `drain` pops that
    /// RELEASE it first flushes the buffered lower-lane tail to the socket
    /// ([`drain_lower_lanes`]) and only then writes the RELEASE — so the
    /// transcript tail is on the wire first even though the control lane
    /// (RELEASE) drains before the bulk lane. This is the PREFERRED close path:
    /// it awaits on the runtime, so (unlike `Drop`) it never parks a Tokio worker
    /// thread. Bounded by `TRANSCRIPT_FLUSH_TIMEOUT` so a wedged bridge can never
    /// hang the caller. Idempotent: after it runs, `Drop` finds the barrier
    /// already armed and does not re-enqueue the RELEASE.
    pub async fn close(&mut self) {
        // Take the sender so no new update is accepted, remove the bridge handle
        // (so Drop's fallback is a no-op), signal the bridge to finish, then
        // await completion on the runtime. Bind the removed handle FIRST so the
        // bridge_tasks MutexGuard drops before the `.await` (a held guard is not
        // `Send` and would make the surrounding `execute` future non-`Send`).
        let _tx = self.transcript.take();
        let flush = self
            .client
            .bridge_tasks
            .lock()
            .unwrap()
            .remove(&self.session_id);
        if let Some(flush) = flush {
            let BridgeFlush {
                close_tx,
                done_rx,
                handle,
            } = flush;
            let _ = close_tx.send(true);
            if timeout(TRANSCRIPT_FLUSH_TIMEOUT, done_rx).await.is_err() {
                // The bridge did not finish flushing within the timeout. ABORT it
                // so it is guaranteed to enqueue NO further transcript chunks:
                // otherwise the detached-but-live bridge (its biased `recv` branch
                // can stay ready) would keep producing while we arm and enqueue
                // the RELEASE below, and those chunks would reach the socket AFTER
                // the RELEASE — breaking tail-before-RELEASE. Transcript loss on
                // this wedged-bridge path is accepted and documented.
                handle.abort();
            }
            // Join the (finished or aborted) task so it is provably stopped and
            // can produce nothing more before we enqueue the RELEASE.
            let _ = handle.await;
        }
        // Arm the drain barrier BEFORE enqueueing the RELEASE: the RELEASE must
        // be deferred at the socket until the transcript tail already buffered
        // ahead of it has been written.
        self.client.arm_release_barrier(&self.stream);
        // RELEASE the job now that its transcript tail is queued behind the
        // barrier. Worker REGISTER persists until shutdown/deregister. The
        // barrier entry stays in the map; `drain` consumes it when it sends the
        // RELEASE (and `Drop` below finds it already armed, so it does not
        // re-RELEASE).
        self.client.release_job(&self.instance, &self.job_key);
    }

    /// Nonblocking transcript-flush fallback for drop paths that did not call
    /// the async [`close`](Self::close) (e.g. a panic unwind). It signals the
    /// bridge to stop accepting and finish, but — unlike `close` — NEVER waits:
    /// a blocking wait inside `Drop` would park a Tokio worker thread, and the
    /// bridge (spawned on the same runtime) might never make progress on a
    /// saturated runtime, stalling every completing job. The tail is therefore
    /// best-effort on this fallback path; `close` is what preserves it.
    fn flush_transcript(&mut self) {
        let _tx = self.transcript.take();
        let Some(flush) = self
            .client
            .bridge_tasks
            .lock()
            .unwrap()
            .remove(&self.session_id)
        else {
            return; // already flushed by `close`, or never attached
        };
        // Signal the bridge to finish; do NOT wait (see the doc comment). ABORT
        // the task too so a wedged bridge cannot keep producing transcript after
        // this drop's best-effort RELEASE — abort only schedules cancellation
        // (it does not block the way joining would), so `Drop` stays non-parking.
        let _ = flush.close_tx.send(true);
        flush.handle.abort();
    }
}

impl Drop for HubSession {
    fn drop(&mut self) {
        // Nonblocking transcript-flush fallback (the preferred path is the async
        // `close`, which awaits the tail first). Signals the bridge to finish but
        // never waits, so drop can never park a Tokio worker thread.
        self.flush_transcript();
        self.client.sessions.lock().unwrap().remove(&self.stream);
        // RELEASE the job — but ONLY if `close` did not already do so. `close`
        // arms this session's barrier before enqueueing its RELEASE; a barrier
        // still present but UNARMED here means the session was dropped without a
        // close (e.g. a panic unwind), so RELEASE best-effort with no drain
        // barrier (the bridge tail was not awaited). If the barrier is armed or
        // gone, `close`/`drain` already handled the RELEASE — a no-op. The
        // in_flight removal is idempotent.
        let needs_release = matches!(
            self.client
                .release_barriers
                .lock()
                .unwrap()
                .get(&self.stream),
            Some(ReleaseBarrier { armed: false })
        );
        if needs_release {
            // Disarm so a double-drop cannot re-RELEASE, then release.
            self.client
                .release_barriers
                .lock()
                .unwrap()
                .remove(&self.stream);
            self.client.release_job(&self.instance, &self.job_key);
        }
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
                if drain(client, &mut write, DRAIN_BATCH).await.is_err() { break; }
            }
            _ = heartbeat.tick() => {
                // One heartbeat per registered worker instance. Snapshot the
                // instance keys FIRST (releasing the instances lock) before
                // `enqueue` takes the outbound lock, so this path never nests
                // instances → outbound — preserving the outbound → instances
                // lock order that `register_session`/`resync_presence` rely on.
                let insts: Vec<String> =
                    client.instances.lock().unwrap().keys().cloned().collect();
                for inst in insts {
                    client.enqueue(Lane::Control, Family::Heartbeat, json!({ "instance": inst }));
                }
                if drain(client, &mut write, DRAIN_BATCH).await.is_err() { break; }
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
                        // Bounded like every other write: a stalled socket must
                        // not wedge the pump inside the Pong send.
                        if !matches!(
                            timeout(WRITE_TIMEOUT, write.send(Message::Pong(p))).await,
                            Ok(Ok(()))
                        ) {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    // Best-effort graceful deregister of every worker before exit.
                    // Snapshot keys first (see the heartbeat note) to keep the
                    // outbound → instances lock order. Enqueue EXEMPT from the
                    // buffer bound so a clean shutdown sends a DEREGISTER for
                    // every registered worker even when the configured capacity
                    // is smaller than the number of registered slots (the bounded
                    // `enqueue` would drop the overflow, since control never
                    // evicts control).
                    let insts: Vec<String> =
                        client.instances.lock().unwrap().keys().cloned().collect();
                    for inst in insts {
                        client.enqueue_control_exempt(
                            Family::Deregister,
                            json!({ "instance": inst, "reason": "shutdown" }),
                        );
                    }
                    // Terminal path: drain ONLY the control lane (the DEREGISTER
                    // snapshot, plus any still-buffered RELEASE/HEARTBEAT) so
                    // every DEREGISTER reaches the socket before the Close,
                    // WITHOUT blocking shutdown on the lower-lane (bulk
                    // transcript / interactive steer) backlog. That backlog is
                    // discarded with the socket, so draining it would only delay
                    // deregistration by up to WRITE_TIMEOUT per buffered frame.
                    let _ = drain_control(client, &mut write).await;
                    let _ = timeout(WRITE_TIMEOUT, write.send(Message::Close(None))).await;
                    break;
                }
            }
        }
    }
}

/// Send every currently buffered frame. A write error returns `Err` so the
/// caller tears the connection down and reconnects (the frames stay buffered).
///
/// RELEASE DRAIN BARRIER: `LaneBuffer::pop` always drains the control lane
/// (RELEASE) before the bulk lane (transcript), so a RELEASE can otherwise
/// overtake the transcript tail that was enqueued before it. When `drain` pops a
/// RELEASE whose session armed a barrier (`HubSession::close`), it first flushes
/// the buffered lower-lane tail to the socket ([`drain_lower_lanes`]) and only
/// then writes the RELEASE — so a job's transcript tail is always on the wire
/// before its RELEASE. On a reconnect the not-yet-sent tail is re-buffered ahead
/// of the still-armed RELEASE, so the ordering is re-established.
///
/// BOUNDED BATCH: `batch_limit` caps how many frames are written before `drain`
/// yields back to the connection `select!` loop (re-arming the outbound notify
/// if frames remain), so a sustained producer cannot keep `read.next()` and
/// `shutdown.changed()` from being polled. `0` means unbounded (drain the entire
/// buffer in a single pass).
async fn drain(
    client: &Arc<HubClient>,
    write: &mut futures_util::stream::SplitSink<WsStream, Message>,
    batch_limit: usize,
) -> anyhow::Result<()> {
    // The incarnation fences a transcript producer to the connection that
    // generated it. It is stamped HERE — at drain on the live socket — not at
    // buffer-enqueue time: a transcript chunk queued during an outage (or
    // re-buffered after a failed write) would otherwise keep the previous
    // generation even though the reconnect bumped `generation`, so frames sent
    // on the new socket would fail to fence the stale producer. Re-stamping at
    // drain guarantees every relay produce frame carries the CURRENT generation.
    let incarnation = client.generation.load(Ordering::Relaxed);
    let mut written = 0usize;
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
        // RELEASE drain barrier: a RELEASE armed by `close` must not reach the
        // socket before the transcript tail that was buffered ahead of it. Since
        // `pop` drains control before bulk, the RELEASE would otherwise win. So
        // when an armed RELEASE is popped while the lower lanes still hold the
        // tail, FIRST drain those lower-lane frames to the socket (preserving
        // their order), THEN write the RELEASE. This holds tail-before-RELEASE
        // on the wire without yielding control-over-bulk priority for any OTHER
        // frame (a different session's control frame already drained ahead).
        if frame.family == Family::Release {
            if let ReleaseGate::Defer { stream } = client.release_gate(&frame.payload) {
                // Write every buffered bulk/interactive frame (the tail) first.
                // On a write error the connection is torn down: re-buffer the
                // held RELEASE too (its barrier stays armed) so it is retried on
                // reconnect AFTER the not-yet-written tail — ordering preserved.
                if let Err(e) = drain_lower_lanes(client, write, incarnation).await {
                    client.outbound.lock().unwrap().requeue_front(frame);
                    return Err(e);
                }
                // The tail is now on the socket: consume the barrier and let the
                // RELEASE be written.
                client.disarm_release_barrier(&stream);
            }
        }
        match encode_frame(&frame) {
            Ok(bytes) => {
                // Bound the write: a hub that stops reading must not park the
                // connection task (and its shutdown branch) inside `send`
                // forever. On error OR timeout, re-buffer the popped frame (so
                // it is retried on reconnect) and tear the connection down.
                match timeout(WRITE_TIMEOUT, write.send(Message::Binary(bytes))).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        client.outbound.lock().unwrap().requeue_front(frame);
                        return Err(e.into());
                    }
                    Err(_) => {
                        client.outbound.lock().unwrap().requeue_front(frame);
                        return Err(anyhow::anyhow!(
                            "agentic hub: socket write timed out; tearing down the stalled connection"
                        ));
                    }
                }
            }
            // An unserialisable/too-large frame is dropped, not retried forever.
            Err(_) => continue,
        }
        written += 1;
        if batch_limit != 0 && written >= batch_limit {
            // Yield back to the `select!` loop so reads and shutdown stay
            // serviceable under a sustained producer. Re-arm the notify if the
            // backlog is non-empty so the next loop iteration re-enters `drain`.
            if !client.outbound.lock().unwrap().is_empty() {
                client.outbound_notify.notify_one();
            }
            return Ok(());
        }
    }
}

/// Write every buffered NON-control (interactive, then bulk) frame to the
/// socket, leaving the control lane untouched. Used by the RELEASE drain
/// barrier: when an armed RELEASE is popped, the session's transcript tail
/// (buffered in the lower lanes) is flushed to the socket FIRST so the RELEASE
/// cannot overtake it on the wire. Shares `drain`'s write-timeout/re-buffer
/// behaviour; a write error tears the connection down (the not-yet-written
/// frames stay buffered and are retried on reconnect, ahead of the RELEASE,
/// whose barrier is still armed — so ordering is re-established).
async fn drain_lower_lanes(
    client: &Arc<HubClient>,
    write: &mut futures_util::stream::SplitSink<WsStream, Message>,
    incarnation: u32,
) -> anyhow::Result<()> {
    loop {
        let mut frame = {
            let mut buf = client.outbound.lock().unwrap();
            match buf.pop_lower_lane() {
                Some(f) => f,
                None => return Ok(()),
            }
        };
        if frame.family == Family::Relay && frame.payload.get("op") == Some(&Value::from("produce"))
        {
            frame.payload["incarnation"] = Value::from(incarnation);
        }
        match encode_frame(&frame) {
            Ok(bytes) => match timeout(WRITE_TIMEOUT, write.send(Message::Binary(bytes))).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    client.outbound.lock().unwrap().push_front(frame);
                    return Err(e.into());
                }
                Err(_) => {
                    client.outbound.lock().unwrap().push_front(frame);
                    return Err(anyhow::anyhow!(
                        "agentic hub: socket write timed out; tearing down the stalled connection"
                    ));
                }
            },
            Err(_) => continue,
        }
    }
}

/// Terminal shutdown drain: write ONLY the control lane (the DEREGISTER
/// snapshot, plus any still-buffered RELEASE/HEARTBEAT) to the socket, then
/// return so the caller can send the Close. Unlike [`drain`], it deliberately
/// leaves the lower lanes (bulk transcript, interactive steer) buffered and
/// UNSENT: a clean shutdown must deregister every worker promptly and must not
/// block for up to `WRITE_TIMEOUT` per frame on a potentially large bulk/steer
/// backlog the process is about to discard with the socket anyway.
///
/// There is no RELEASE drain barrier here — the transcript tail a RELEASE orders
/// against is exactly the lower-lane backlog being discarded — and no
/// incarnation re-stamping, since control frames are never transcript `produce`
/// relays. A write error or timeout ends the drain WITHOUT re-buffering: this is
/// the terminal path, so there is no reconnect to retry on.
async fn drain_control(
    client: &Arc<HubClient>,
    write: &mut futures_util::stream::SplitSink<WsStream, Message>,
) -> anyhow::Result<()> {
    loop {
        let frame = {
            let mut buf = client.outbound.lock().unwrap();
            match buf.pop_control() {
                Some(f) => f,
                None => return Ok(()),
            }
        };
        match encode_frame(&frame) {
            Ok(bytes) => match timeout(WRITE_TIMEOUT, write.send(Message::Binary(bytes))).await {
                Ok(Ok(())) => {}
                // Terminal path: a failed/stalled socket ends the drain. Do not
                // re-buffer — the process is exiting and will not reconnect.
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "agentic hub: socket write timed out during the shutdown deregister drain"
                    ))
                }
            },
            // An unserialisable/too-large control frame is skipped, not retried.
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
            buffer_byte_budget: 0,
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
        let client = HubClient::spawn(cfg, &[]);
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
        let client = HubClient::spawn(cfg, &[]);
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
        let client = HubClient::spawn(test_config(), &[]);
        client.enqueue(Lane::Bulk, Family::Relay, json!({ "n": 1 }));
        client.enqueue(Lane::Control, Family::Register, json!({ "instance": "w" }));
        let frames = buffered(&client);
        assert_eq!(frames[0].0, Lane::Control, "control lane drains first");
        client.shutdown().await;
    }

    #[test]
    fn push_front_retry_respects_count_cap() {
        // A write failed/timed out: `drain` popped a frame, then producers
        // refilled the freed slot while the write was awaiting. Re-admitting the
        // retry frame at the front must NOT grow the buffer past its count cap —
        // otherwise repeated failures keep the "bounded" buffer growing.
        let mut buf = LaneBuffer::with_limits(2, 0);
        buf.push(Frame::new(Lane::Bulk, Family::Relay, 1, json!({ "n": 1 })));
        buf.push(Frame::new(Lane::Bulk, Family::Relay, 2, json!({ "n": 2 })));
        let popped = buf.pop().expect("a frame to send");
        assert_eq!(buf.len(), 1);
        // Producers refill the freed slot (and more) during the await.
        buf.push(Frame::new(Lane::Bulk, Family::Relay, 3, json!({ "n": 3 })));
        buf.push(Frame::new(Lane::Bulk, Family::Relay, 4, json!({ "n": 4 })));
        assert_eq!(buf.len(), 2, "buffer back at capacity before the retry");
        buf.push_front(popped);
        assert!(buf.len() <= 2, "retry re-admission must honour the count cap");
    }

    #[test]
    fn push_front_retry_respects_byte_budget() {
        // Same race, byte budget instead of count. The budget holds two frames;
        // after a refill fills it, a retry must shed to fit rather than exceed.
        let one = frame_bytes(&Frame::new(Lane::Bulk, Family::Relay, 0, json!({ "n": 0 })));
        let mut buf = LaneBuffer::with_limits(1000, one * 2);
        buf.push(Frame::new(Lane::Bulk, Family::Relay, 1, json!({ "n": 1 })));
        let popped = buf.pop().expect("a frame");
        buf.push(Frame::new(Lane::Bulk, Family::Relay, 2, json!({ "n": 2 })));
        buf.push(Frame::new(Lane::Bulk, Family::Relay, 3, json!({ "n": 3 })));
        buf.push_front(popped);
        assert!(buf.bytes <= one * 2, "retry re-admission must honour the byte budget");
    }

    #[test]
    fn push_front_retry_never_evicts_higher_priority() {
        // When a full buffer holds only strictly-higher-priority traffic, a
        // low-priority retry is dropped rather than displacing control frames.
        let mut buf = LaneBuffer::with_limits(2, 0);
        let popped = Frame::new(Lane::Bulk, Family::Relay, 1, json!({ "n": 1 }));
        buf.push(Frame::new(Lane::Control, Family::Register, 2, json!({ "instance": "w" })));
        buf.push(Frame::new(Lane::Control, Family::Claim, 3, json!({ "instance": "w" })));
        assert_eq!(buf.len(), 2);
        buf.push_front(popped);
        assert_eq!(buf.len(), 2, "bulk retry dropped; control preserved");
        assert_eq!(buf.control.len(), 2, "both control frames survive");
    }

    // Finding (round 10, HIGH): a RELEASE must survive a saturated control lane.
    // `release_job` removes the job from `in_flight` BEFORE enqueuing the
    // RELEASE, so the reconnect resync can no longer recreate its CLAIM — the
    // RELEASE is the ONLY frame that can retire the hub's ownership of the job.
    // The ordinary bounded `push` drops a control newcomer once the control lane
    // fills (control never evicts control), which would strand the CLAIM on the
    // hub forever. The exempt admission (`push_back_control_bounded`, used by
    // `enqueue_control_exempt`/`release_job`) must keep it instead.
    #[test]
    fn release_survives_a_full_control_lane() {
        let has_release =
            |buf: &LaneBuffer| buf.iter_frames().any(|f| f.family == Family::Release);

        // Baseline (red without the fix): the ordinary bounded `push` DROPS the
        // RELEASE when the control lane is already at capacity.
        let mut dropped = LaneBuffer::with_limits(2, 0);
        dropped.push(Frame::new(Lane::Control, Family::Register, 1, json!({ "instance": "a" })));
        dropped.push(Frame::new(
            Lane::Control,
            Family::Claim,
            2,
            json!({ "instance": "a", "jobKey": "j" }),
        ));
        dropped.push(Frame::new(
            Lane::Control,
            Family::Release,
            3,
            json!({ "instance": "a", "jobKey": "j" }),
        ));
        assert!(!has_release(&dropped), "ordinary push drops the RELEASE");

        // The fix: exempt admission sheds lower lanes (none here) but never
        // drops the RELEASE itself, so the ownership-retiring frame survives.
        let mut kept = LaneBuffer::with_limits(2, 0);
        kept.push(Frame::new(Lane::Control, Family::Register, 1, json!({ "instance": "a" })));
        kept.push(Frame::new(
            Lane::Control,
            Family::Claim,
            2,
            json!({ "instance": "a", "jobKey": "j" }),
        ));
        kept.push_back_control_bounded(Frame::new(
            Lane::Control,
            Family::Release,
            3,
            json!({ "instance": "a", "jobKey": "j" }),
        ));
        assert!(has_release(&kept), "exempt admission keeps the RELEASE");
    }

    // Finding (round 10, HIGH, sibling): a write failure/timeout that re-buffers
    // a popped frame must not silently drop a must-deliver control frame either.
    // `requeue_front` re-admits RELEASE/DEREGISTER EXEMPT from the bound (while a
    // sheddable transcript/steer frame still goes through the bounded path).
    #[test]
    fn requeue_front_preserves_must_deliver_control() {
        let mut buf = LaneBuffer::with_limits(2, 0);
        buf.push(Frame::new(Lane::Control, Family::Register, 1, json!({ "instance": "a" })));
        buf.push(Frame::new(
            Lane::Control,
            Family::Claim,
            2,
            json!({ "instance": "a", "jobKey": "j" }),
        ));
        // Control lane is full; a plain `push_front` would drop this RELEASE.
        buf.requeue_front(Frame::new(
            Lane::Control,
            Family::Release,
            3,
            json!({ "instance": "a", "jobKey": "j" }),
        ));
        assert!(
            buf.iter_frames().any(|f| f.family == Family::Release),
            "requeue_front must not drop a re-buffered RELEASE"
        );

        // A DEREGISTER (the only frame that retires a worker's presence) is
        // likewise exempt on re-buffer.
        buf.requeue_front(Frame::new(
            Lane::Control,
            Family::Deregister,
            4,
            json!({ "instance": "a", "reason": "shutdown" }),
        ));
        assert!(
            buf.iter_frames().any(|f| f.family == Family::Deregister),
            "requeue_front must not drop a re-buffered DEREGISTER"
        );

        // A sheddable bulk retry still honours the bound (dropped, not grown).
        let before = buf.len();
        buf.requeue_front(Frame::new(Lane::Bulk, Family::Relay, 5, json!({ "n": 1 })));
        assert_eq!(buf.len(), before, "a sheddable bulk retry stays bounded");
    }

    // Finding (round 10, MEDIUM): the terminal shutdown drain must flush the
    // control lane (DEREGISTER snapshot) WITHOUT draining the lower-lane backlog,
    // so deregistration is not delayed by up to WRITE_TIMEOUT per buffered bulk
    // transcript / interactive steer frame. `pop_control` pops ONLY control.
    #[test]
    fn pop_control_drains_only_the_control_lane() {
        let mut buf = LaneBuffer::with_limits(100, 0);
        buf.push(Frame::new(Lane::Control, Family::Deregister, 1, json!({ "instance": "a" })));
        buf.push(Frame::new(Lane::Bulk, Family::Relay, 2, json!({ "n": 1 })));
        buf.push(Frame::new(Lane::Control, Family::Deregister, 3, json!({ "instance": "b" })));
        buf.push(Frame::new(Lane::Bulk, Family::Relay, 4, json!({ "n": 2 })));

        // Yields ONLY the control frames (DEREGISTERs), in order...
        assert_eq!(buf.pop_control().map(|f| f.family), Some(Family::Deregister));
        assert_eq!(buf.pop_control().map(|f| f.family), Some(Family::Deregister));
        assert!(buf.pop_control().is_none(), "no control frames left");
        // ...leaving the two bulk (transcript) frames buffered to be discarded
        // with the socket rather than blocking the shutdown.
        assert_eq!(buf.len(), 2, "lower lanes are retained, not drained");
        assert_eq!(buf.pop().map(|f| f.lane), Some(Lane::Bulk));
        assert_eq!(buf.pop().map(|f| f.lane), Some(Lane::Bulk));
    }

    // Finding (round 8): control admission must NEVER evict an earlier control
    // frame. Presence frames are an ordered, interdependent set — a CLAIM is
    // meaningless without its prerequisite REGISTER — so under a tiny capacity a
    // `register_session`'s CLAIM must not evict the REGISTER it was enqueued
    // after. The newcomer is dropped instead, preserving the ordering of what is
    // already queued (the reconnect resync rebuilds the full set from state).
    #[test]
    fn control_push_never_evicts_control() {
        let mut buf = LaneBuffer::with_limits(1, 0);
        buf.push(Frame::new(Lane::Control, Family::Register, 1, json!({ "instance": "w" })));
        // Capacity 1 and already holding a control frame: a second control frame
        // must NOT evict the REGISTER — it is dropped on the floor instead.
        buf.push(Frame::new(Lane::Control, Family::Claim, 2, json!({ "instance": "w", "jobKey": "j" })));
        assert_eq!(buf.len(), 1, "a full control-only buffer drops the newcomer");
        assert_eq!(
            buf.control.len(),
            1,
            "the REGISTER must survive the CLAIM's admission"
        );
        assert_eq!(
            buf.control[0].frame.family,
            Family::Register,
            "REGISTER (not the later CLAIM) is what remains buffered"
        );
    }

    #[test]
    fn control_push_sheds_lower_priority_to_make_room() {
        // A control frame may still evict bulk/interactive traffic to make room
        // — only control-vs-control eviction is forbidden.
        let mut buf = LaneBuffer::with_limits(1, 0);
        buf.push(Frame::new(Lane::Bulk, Family::Relay, 1, json!({ "n": 1 })));
        buf.push(Frame::new(Lane::Control, Family::Register, 2, json!({ "instance": "w" })));
        assert_eq!(buf.len(), 1);
        assert_eq!(
            buf.control.len(),
            1,
            "control evicts the bulk frame and is admitted"
        );
        assert!(buf.bulk.is_empty(), "the bulk frame was shed for control");
    }

    #[tokio::test]
    async fn session_register_claims_and_release_on_drop() {
        let client = HubClient::spawn(test_config(), &[]);
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
        let client = HubClient::spawn(test_config(), &[]);
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
        let client = HubClient::spawn(test_config(), &[]);
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
        let client = HubClient::spawn(test_config(), &[]);
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
        let client = HubClient::spawn(test_config(), &[]);
        let mut session = client.register_session("w-8", capability(), "job-8");
        let mut steer = session.take_steer().expect("steer receiver");
        let stream = compose_stream_id("w-8", "job-8");
        client.route_inbound(&json!({
            "stream": stream,
            "offset": 0,
            "chunk": r#"{"nanoControlFrame":1,"kind":"cancel","reason":"stop"}"#,
        }));
        let got = steer.recv().await.expect("steer delivered");
        assert_eq!(got, ControlFrame::Cancel { reason: Some("stop".into()) });
        client.shutdown().await;
    }

    #[tokio::test]
    async fn transcript_sink_bridges_updates_to_produce_frames() {
        let client = HubClient::spawn(test_config(), &[]);
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
                .find(|bf| bf.frame.family == Family::Relay)
                .map(|bf| bf.frame.clone())
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
        let client = HubClient::spawn(test_config(), &[]);
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
        let client = HubClient::spawn(cfg, &[]);
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
        let client = HubClient::spawn(cfg, &[]);
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
        let client = HubClient::spawn(cfg, &[]);
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
        let client = HubClient::spawn(cfg, &[]);
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
        let client = HubClient::spawn(test_config(), &[]);
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
        let client = HubClient::spawn(test_config(), &[]);
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
        let client = HubClient::spawn(test_config(), &[]);
        let mut session = client.register_session("w-b", capability(), "job-b");
        let sink = session.transcript_sink().expect("transcript sink");
        assert_eq!(sink.max_capacity(), TRANSCRIPT_CHANNEL_BOUND);
        client.shutdown().await;
    }

    // Finding (round 6): the pre-buffer transcript channel is byte-aware. It
    // fronts the byte-bounded outbound buffer, so a flat 1024-item count bound
    // (each item up to ~1 MiB) could hold ~1 GiB before the byte budget bites.
    // `transcript_channel_bound` derives the item count from the byte budget.
    #[test]
    fn transcript_channel_bound_derives_from_byte_budget() {
        // Disabled byte budget (0) falls back to the flat count ceiling.
        assert_eq!(transcript_channel_bound(0), TRANSCRIPT_CHANNEL_BOUND);
        // 64 MiB / 1 MiB = 64 items (matches the outbound buffer's worst case).
        assert_eq!(transcript_channel_bound(64 * 1024 * 1024), 64);
        // A tiny-but-nonzero budget still admits at least one update.
        assert_eq!(transcript_channel_bound(1), 1);
        assert_eq!(transcript_channel_bound(MAX_TRANSCRIPT_UPDATE_BYTES - 1), 1);
        // A huge budget is clamped to the count ceiling, never above it.
        assert_eq!(
            transcript_channel_bound(usize::MAX),
            TRANSCRIPT_CHANNEL_BOUND
        );
    }

    // Finding (round 6): a session's transcript sink capacity actually follows
    // the configured byte budget, not the flat ceiling.
    #[tokio::test]
    async fn transcript_sink_capacity_follows_byte_budget() {
        let mut cfg = test_config();
        cfg.buffer_byte_budget = 8 * 1024 * 1024; // 8 MiB => 8 items
        let client = HubClient::spawn(cfg, &[]);
        let mut session = client.register_session("w-bb", capability(), "job-bb");
        let sink = session.transcript_sink().expect("transcript sink");
        assert_eq!(sink.max_capacity(), 8);
        client.shutdown().await;
    }

    // Finding (round 6): the async `close` flushes the transcript tail BEFORE
    // the session is dropped (and thus before RELEASE), and returns promptly —
    // it must never park a worker the way the old blocking Drop could.
    #[tokio::test]
    async fn session_close_flushes_transcript_tail_and_returns_promptly() {
        let client = HubClient::spawn(test_config(), &[]);
        let mut session = client.register_session("w-cl", capability(), "job-cl");
        let sink = session.transcript_sink().expect("transcript sink");
        let _ = buffered(&client); // discard register/claim frames
        sink.try_send(json!({
            "sessionUpdate": "agent_message_chunk",
            "content": { "type": "text", "text": "tail" }
        }))
        .unwrap();
        // close() awaits the bridge drain on the runtime, bounded by the flush
        // timeout, so it must return well within it.
        tokio::time::timeout(TRANSCRIPT_FLUSH_TIMEOUT, session.close())
            .await
            .expect("close must return promptly, not hang");
        // The tail update was flushed to a relay frame before any RELEASE.
        let relay = client
            .outbound
            .lock()
            .unwrap()
            .bulk
            .iter()
            .find(|bf| bf.frame.family == Family::Relay)
            .map(|bf| bf.frame.clone());
        assert!(
            relay.is_some(),
            "close() must flush the queued transcript update before returning"
        );
        // A second close is a no-op (idempotent) and still returns promptly.
        tokio::time::timeout(TRANSCRIPT_FLUSH_TIMEOUT, session.close())
            .await
            .expect("second close must be a prompt no-op");
        client.shutdown().await;
    }

    // Findings D + E: shutdown signals AND awaits the connection task, and the
    // connect loop is racing shutdown — so shutdown returns promptly even when
    // the client has never managed to connect (and is mid-backoff/connect).
    #[tokio::test]
    async fn shutdown_awaits_task_and_returns_promptly_when_never_connected() {
        let client = HubClient::spawn(test_config(), &[]); // port 1: never connects
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
        let client = HubClient::spawn(test_config(), &[]);
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
        let client = HubClient::spawn(cfg, &[]);
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
        let client = HubClient::spawn(cfg, &[]);
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

    // Finding (round 4 → round 6): the flush-before-RELEASE guarantee now lives
    // on the async `close` (Drop is nonblocking so it can never park a worker).
    // Closing a session flushes its accepted transcript tail into the buffer
    // BEFORE the RELEASE is enqueued, so no chunk is emitted for a job the hub
    // has already released.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn release_is_enqueued_after_transcript_tail() {
        let client = HubClient::spawn(test_config(), &[]);
        let mut session = client.register_session("w-fl", capability(), "job-fl");
        let sink = session.transcript_sink().expect("transcript sink");
        let _ = buffered(&client); // discard register/claim
        sink.try_send(json!({
            "sessionUpdate": "agent_message_chunk",
            "content": { "type": "text", "text": "tail" }
        }))
        .unwrap();
        // `close` awaits the bridged chunk into the buffer; the subsequent drop
        // enqueues the RELEASE.
        session.close().await;
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

    // Finding (round 5): `route_inbound` must require the protocol's integer
    // `offset` before routing a delivery. A `{stream, chunk}` object lacking an
    // offset (or carrying a non-integer one) is NOT a delivery frame and must be
    // dropped, so it cannot masquerade as one and inject steer into a live job.
    #[tokio::test]
    async fn route_inbound_requires_integer_offset_to_route_steer() {
        let client = HubClient::spawn(test_config(), &[]);
        let mut session = client.register_session("w-of", capability(), "job-of");
        let mut steer = session.take_steer().expect("steer receiver");
        let stream = compose_stream_id("w-of", "job-of");
        let chunk = r#"{"nanoControlFrame":1,"kind":"cancel","reason":"x"}"#;
        // Missing offset: dropped.
        client.route_inbound(&json!({ "stream": stream, "chunk": chunk }));
        // Non-integer offset (string): dropped.
        client.route_inbound(&json!({ "stream": stream, "offset": "0", "chunk": chunk }));
        // Negative offset (not a u64): dropped.
        client.route_inbound(&json!({ "stream": stream, "offset": -1, "chunk": chunk }));
        assert!(
            steer.try_recv().is_err(),
            "a payload without a valid integer offset must not be routed as steer"
        );
        // A genuine delivery (integer offset) IS routed.
        client.route_inbound(&json!({ "stream": stream, "offset": 7, "chunk": chunk }));
        let got = steer.recv().await.expect("valid delivery must be routed");
        assert_eq!(got, ControlFrame::Cancel { reason: Some("x".into()) });
        client.shutdown().await;
    }

    // Finding (round 5): a frame-COUNT cap alone cannot bound memory because a
    // single transcript chunk may be ~1 MiB. The buffer also enforces a BYTE
    // budget: pushing many large bulk frames never retains more than the budget
    // of bytes, regardless of how far the count cap would otherwise allow.
    #[tokio::test]
    async fn buffer_byte_budget_bounds_retained_memory_regardless_of_count() {
        let mut cfg = test_config();
        cfg.buffer_capacity = 10_000; // a very permissive COUNT cap
        cfg.buffer_byte_budget = 64 * 1024; // but a tight BYTE budget
        let client = HubClient::spawn(cfg, &[]);
        let big = "x".repeat(16 * 1024); // ~16 KiB payload each
        for _ in 0..1000 {
            client.enqueue(Lane::Bulk, Family::Relay, json!({ "chunk": big }));
        }
        let (bytes, byte_capacity, len) = {
            let buf = client.outbound.lock().unwrap();
            (buf.bytes, buf.byte_capacity, buf.len())
        };
        assert!(
            bytes <= byte_capacity,
            "retained bytes {bytes} exceeded the byte budget {byte_capacity}"
        );
        // A handful of 16 KiB frames, not the full 1000-frame count cap.
        assert!(
            len < 10,
            "count should be bounded by the byte budget, got {len}"
        );
        client.shutdown().await;
    }

    // Finding (round 5): a control frame must never be dropped by the byte
    // budget to admit lower-priority bulk — presence/steer is never sacrificed
    // for transcript, and a control frame exceeding the budget is still admitted.
    #[tokio::test]
    async fn byte_budget_never_sheds_control_for_bulk() {
        let mut cfg = test_config();
        cfg.buffer_capacity = 10_000;
        cfg.buffer_byte_budget = 8 * 1024;
        let client = HubClient::spawn(cfg, &[]);
        client.enqueue(Lane::Control, Family::Register, json!({ "instance": "w" }));
        let big = "x".repeat(16 * 1024); // larger than the whole budget
        for _ in 0..50 {
            client.enqueue(Lane::Bulk, Family::Relay, json!({ "chunk": big.clone() }));
        }
        let buf_control_len = {
            let buf = client.outbound.lock().unwrap();
            buf.control.len()
        };
        assert_eq!(
            buf_control_len, 1,
            "the control REGISTER must survive a bulk flood under the byte budget"
        );
        client.shutdown().await;
    }

    // Finding (round 5): the reconnect snapshot is atomic with session
    // registration. Under concurrent `register_session` and `resync_presence`,
    // no live job's presence may be lost — every in-flight job keeps exactly one
    // buffered CLAIM and every instance exactly one REGISTER. (The old
    // non-atomic snapshot could `drop_control_presence` a just-enqueued frame.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn resync_is_atomic_with_concurrent_registration() {
        let mut cfg = test_config();
        cfg.buffer_capacity = 100_000; // never shed presence during the stress
        let client = HubClient::spawn(cfg, &[]);
        let resync_client = client.clone();
        let resyncer = tokio::task::spawn_blocking(move || {
            for _ in 0..2000 {
                resync_client.resync_presence();
            }
        });
        let mut sessions = Vec::new();
        for i in 0..200 {
            sessions.push(client.register_session("w-atomic", capability(), &format!("job-{i}")));
            if i % 7 == 0 {
                std::thread::yield_now();
            }
        }
        resyncer.await.unwrap();
        // One final resync establishes a clean, fully-rebuilt presence snapshot.
        client.resync_presence();
        let frames = client.enqueue_log();
        let registers = frames
            .iter()
            .filter(|(_, _, f)| *f == Family::Register)
            .count();
        let claims = frames.iter().filter(|(_, _, f)| *f == Family::Claim).count();
        assert_eq!(registers, 1, "exactly one REGISTER for the single instance");
        assert_eq!(
            claims, 200,
            "every registered job must retain its CLAIM after concurrent resync, got {claims}"
        );
        drop(sessions);
        client.shutdown().await;
    }

    // --- Round-8 design decisions (human-directed) ----------------------

    // Decision 3 (register-on-connect): every configured slot's identity is
    // REGISTERed at spawn, independently of any job, so idle capacity is visible
    // on the hub. A daemon spawned with two slots must REGISTER both before any
    // `register_session` runs, and heartbeat them while connected.
    #[tokio::test]
    async fn spawn_registers_every_configured_slot_before_any_job() {
        let client = HubClient::spawn(
            test_config(),
            &[
                ("host-nanod-a-0".to_string(), capability()),
                ("host-nanod-a-1".to_string(), capability()),
            ],
        );
        // No register_session call at all: both slots are already present.
        let insts = client.instances.lock().unwrap();
        assert!(insts.contains_key("host-nanod-a-0"), "slot 0 must be pre-registered");
        assert!(insts.contains_key("host-nanod-a-1"), "slot 1 must be pre-registered");
        assert_eq!(insts.len(), 2, "exactly the two configured slots");
        drop(insts);
        // The resync snapshot (what the first connect sends) covers both slots.
        client.resync_presence();
        let frames = buffered(&client);
        let registers: Vec<&Value> = frames
            .iter()
            .filter(|(_, f, _)| *f == Family::Register)
            .map(|(_, _, p)| p)
            .collect();
        assert_eq!(registers.len(), 2, "both slots REGISTERed on connect");
        assert!(registers.iter().any(|p| p["instance"] == "host-nanod-a-0"));
        assert!(registers.iter().any(|p| p["instance"] == "host-nanod-a-1"));
        // The config-level advertisement is folded into each slot's capability.
        assert!(registers.iter().all(|p| p["capability"].is_object()));
        client.shutdown().await;
    }

    // Decision 3 (sibling): a slot that later runs a job must NOT be
    // re-REGISTERed (it is already present from spawn) — only CLAIMed.
    #[tokio::test]
    async fn job_on_preregistered_slot_claims_without_reregistering() {
        let client = HubClient::spawn(
            test_config(),
            &[("w-idle".to_string(), capability())],
        );
        let _ = buffered(&client); // discard the spawn-time REGISTER
        let _session = client.register_session("w-idle", capability(), "job-1");
        let frames = buffered(&client);
        assert!(
            frames.iter().all(|(_, f, _)| *f != Family::Register),
            "an already-registered slot must not be re-REGISTERed on its first job"
        );
        assert!(frames
            .iter()
            .any(|(_, f, p)| *f == Family::Claim && p["jobKey"] == "job-1"));
        client.shutdown().await;
    }

    // Decision 1 (presence exempt from the buffer bound): a presence set larger
    // than a tiny configured capacity is prepended WHOLE, not dropped or
    // fragmented — it is bounded by live instances+jobs, not by the buffer.
    #[tokio::test]
    async fn resync_presence_is_exempt_from_buffer_capacity() {
        let mut cfg = test_config();
        cfg.buffer_capacity = 1; // absurdly tiny: cannot hold even REGISTER+CLAIM
        let client = HubClient::spawn(cfg, &[("w-x".to_string(), capability())]);
        let _session = client.register_session("w-x", capability(), "job-x");
        client.resync_presence();
        let frames = buffered(&client);
        // Both presence frames survive even though capacity is 1: presence is
        // exempt from the bound (bounded by live instances+jobs instead).
        assert!(
            frames.iter().any(|(_, f, _)| *f == Family::Register),
            "REGISTER must survive a tiny capacity (presence is exempt)"
        );
        assert!(
            frames.iter().any(|(_, f, _)| *f == Family::Claim),
            "CLAIM must survive a tiny capacity (presence is exempt)"
        );
        client.shutdown().await;
    }

    // Decision 2 (RELEASE never overtakes the transcript tail ON THE WIRE): a
    // live-socket test. The transcript tail is buffered (bulk lane) BEFORE the
    // RELEASE is enqueued (control lane). Because `LaneBuffer::pop` drains the
    // control lane first, the RELEASE would reach the socket ahead of the bulk
    // tail without the drain barrier. With it, the hub must observe the produce
    // frame(s) BEFORE the release. To make the race deterministic, the tail is
    // enqueued while the socket is NOT yet draining (the client connects only
    // after both frames are buffered), so the RELEASE genuinely starts behind
    // the tail in lane order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn release_is_written_after_transcript_tail_on_the_wire() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (frames_tx, mut frames_rx) = mpsc::unbounded_channel::<Family>();
        // Gate the server so the client connects only once we release it.
        let (accept_tx, accept_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let _ = accept_rx.await;
            let (sock, _) = listener.accept().await.unwrap();
            let ws = accept_async(sock).await.unwrap();
            let (_write, mut read) = ws.split();
            while let Some(Ok(Message::Binary(bytes))) = read.next().await {
                if let Ok(frame) = decode_frame(&bytes) {
                    if frames_tx.send(frame.family).is_err() {
                        break;
                    }
                }
            }
        });

        let mut cfg = test_config();
        cfg.url = format!("ws://127.0.0.1:{port}/na");
        let client = HubClient::spawn(cfg, &[]);
        let mut session = client.register_session("w-ord", capability(), "job-ord");
        let sink = session.transcript_sink().expect("transcript sink");
        // Enqueue the transcript tail and immediately close — the server is not
        // accepting yet, so NOTHING has drained: the bulk tail sits in the buffer
        // behind the (control) REGISTER/CLAIM, and the RELEASE is enqueued after
        // it. close() commits the barrier over the whole pre-close backlog.
        sink.send(json!({
            "sessionUpdate": "agent_message_chunk",
            "content": { "type": "text", "text": "tail" }
        }))
        .await
        .unwrap();
        session.close().await;
        drop(session);
        // Now let the connection happen: control drains first, so without the
        // barrier the RELEASE would precede the bulk produce on the wire.
        let _ = accept_tx.send(());

        // Collect the wire order until we have seen a produce relay AND a release.
        let mut order: Vec<Family> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut saw_produce = false;
        let mut saw_release = false;
        while !(saw_produce && saw_release) {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let fam = tokio::time::timeout(remaining, frames_rx.recv())
                .await
                .expect("timed out awaiting wire frames")
                .expect("server frame channel closed");
            order.push(fam);
            match fam {
                Family::Relay => saw_produce = true,
                Family::Release => saw_release = true,
                _ => {}
            }
        }
        let idx = |f: Family| order.iter().position(|x| *x == f).unwrap();
        assert!(
            idx(Family::Relay) < idx(Family::Release),
            "the transcript tail must be written to the socket BEFORE the RELEASE, got {order:?}"
        );
        client.shutdown().await;
        server.abort();
    }

    // Decision 2 (sibling): the barrier holds even when OTHER control frames are
    // queued ahead of the RELEASE. A heartbeat (control) enqueued alongside the
    // tail must not let the RELEASE jump the bulk transcript — the RELEASE still
    // waits for the tail to be written first. Deterministic: the tail is buffered
    // while the socket is not yet draining (gated accept), so the RELEASE starts
    // behind it in lane order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn release_waits_for_tail_even_with_control_frames_queued() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (frames_tx, mut frames_rx) = mpsc::unbounded_channel::<Family>();
        let (accept_tx, accept_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let _ = accept_rx.await;
            let (sock, _) = listener.accept().await.unwrap();
            let ws = accept_async(sock).await.unwrap();
            let (_write, mut read) = ws.split();
            while let Some(Ok(Message::Binary(bytes))) = read.next().await {
                if let Ok(frame) = decode_frame(&bytes) {
                    if frames_tx.send(frame.family).is_err() {
                        break;
                    }
                }
            }
        });

        let mut cfg = test_config();
        cfg.url = format!("ws://127.0.0.1:{port}/na");
        let client = HubClient::spawn(cfg, &[]);
        let mut session = client.register_session("w-ord2", capability(), "job-ord2");
        let sink = session.transcript_sink().expect("transcript sink");
        sink.send(json!({
            "sessionUpdate": "agent_message_chunk",
            "content": { "type": "text", "text": "tail" }
        }))
        .await
        .unwrap();
        // Queue an unrelated control frame (a heartbeat) BEFORE closing, so the
        // control lane is non-empty when the RELEASE is enqueued.
        client.enqueue(Lane::Control, Family::Heartbeat, json!({ "instance": "w-ord2" }));
        session.close().await;
        drop(session);
        let _ = accept_tx.send(());

        let mut order: Vec<Family> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut saw_produce = false;
        let mut saw_release = false;
        while !(saw_produce && saw_release) {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let fam = tokio::time::timeout(remaining, frames_rx.recv())
                .await
                .expect("timed out awaiting wire frames")
                .expect("server frame channel closed");
            order.push(fam);
            match fam {
                Family::Relay => saw_produce = true,
                Family::Release => saw_release = true,
                _ => {}
            }
        }
        let idx = |f: Family| order.iter().position(|x| *x == f).unwrap();
        assert!(
            idx(Family::Relay) < idx(Family::Release),
            "RELEASE must wait for the transcript tail even with control frames queued, got {order:?}"
        );
        client.shutdown().await;
        server.abort();
    }

    // Finding 1 (round 9): the reconnect presence prune must NOT drop a CLAIM
    // for a job that STARTED AND FINISHED during the outage. Such a job has a
    // buffered CLAIM, transcript tail, and RELEASE, and `release_job` already
    // removed it from `in_flight` — so the resync snapshot cannot recreate its
    // CLAIM. Dropping the buffered CLAIM would ship the RELEASE/transcript with
    // no prerequisite ownership frame, desyncing the hub. A CLAIM for a still
    // live job (no buffered RELEASE) IS pruned — the snapshot rebuilds it — as
    // is every REGISTER.
    #[test]
    fn drop_control_presence_keeps_claim_paired_with_a_pending_release() {
        let mut buf = LaneBuffer::with_limits(16, 0);
        // Live job on w: REGISTER + CLAIM, no RELEASE -> both pruned.
        buf.push(Frame::new(Lane::Control, Family::Register, 1, json!({ "instance": "w" })));
        buf.push(Frame::new(
            Lane::Control,
            Family::Claim,
            2,
            json!({ "instance": "w", "jobKey": "live" }),
        ));
        // Completed-during-outage job on w: CLAIM + RELEASE -> CLAIM survives.
        buf.push(Frame::new(
            Lane::Control,
            Family::Claim,
            3,
            json!({ "instance": "w", "jobKey": "done" }),
        ));
        buf.push(Frame::new(
            Lane::Control,
            Family::Release,
            4,
            json!({ "instance": "w", "jobKey": "done" }),
        ));
        buf.drop_control_presence();
        let claims: Vec<&Value> = buf
            .control
            .iter()
            .filter(|bf| bf.frame.family == Family::Claim)
            .map(|bf| &bf.frame.payload)
            .collect();
        assert_eq!(claims.len(), 1, "only the completed job's CLAIM survives the prune");
        assert_eq!(
            claims[0]["jobKey"], "done",
            "the preserved CLAIM is the one paired with a buffered RELEASE"
        );
        assert!(
            buf.control.iter().any(|bf| bf.frame.family == Family::Release),
            "the buffered RELEASE is preserved (its CLAIM→tail→RELEASE stays intact)"
        );
        assert!(
            !buf.control.iter().any(|bf| bf.frame.family == Family::Register),
            "every REGISTER is pruned — the resync snapshot rebuilds it"
        );
    }

    // Finding 3 (round 9): the shutdown DEREGISTER snapshot must be exempt from
    // the control bound. With a capacity smaller than the registered-slot count,
    // the ordinary bounded `push` drops control newcomers once the control lane
    // fills (control never evicts control), so only a subset would DEREGISTER.
    // The exempt back-push admits the whole snapshot.
    #[test]
    fn deregister_snapshot_is_exempt_from_the_control_bound() {
        let mut exempt = LaneBuffer::with_limits(2, 0);
        for i in 0..5u32 {
            exempt.push_back_control_bounded(Frame::new(
                Lane::Control,
                Family::Deregister,
                i,
                json!({ "instance": format!("w-{i}"), "reason": "shutdown" }),
            ));
        }
        assert_eq!(
            exempt.control.len(),
            5,
            "every DEREGISTER is admitted despite a capacity of 2"
        );
        // Contrast: the ordinary bounded push drops the control overflow.
        let mut bounded = LaneBuffer::with_limits(2, 0);
        for i in 0..5u32 {
            bounded.push(Frame::new(
                Lane::Control,
                Family::Deregister,
                i,
                json!({ "instance": format!("w-{i}"), "reason": "shutdown" }),
            ));
        }
        assert_eq!(
            bounded.control.len(),
            2,
            "the bounded push drops the control overflow once the lane is full"
        );
    }

    // Finding 3 (round 9), end-to-end: a worker with MORE registered slots than
    // the buffer capacity must still DEREGISTER every slot on shutdown. Before
    // the exempt back-push, the surplus DEREGISTERs were dropped on the floor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_deregisters_every_slot_even_below_capacity() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (frames_tx, mut frames_rx) = mpsc::unbounded_channel::<(Family, Value)>();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let ws = accept_async(sock).await.unwrap();
            let (_write, mut read) = ws.split();
            while let Some(Ok(Message::Binary(bytes))) = read.next().await {
                if let Ok(frame) = decode_frame(&bytes) {
                    if frames_tx.send((frame.family, frame.payload)).is_err() {
                        break;
                    }
                }
            }
        });

        let mut cfg = test_config();
        cfg.url = format!("ws://127.0.0.1:{port}/na");
        cfg.buffer_capacity = 1; // far smaller than the slot count below
        let slots: Vec<(String, Value)> =
            (0..4).map(|i| (format!("w-{i}"), capability())).collect();
        let client = HubClient::spawn(cfg, &slots);

        // Wait until all four slots have REGISTERed on the wire (connection up).
        let mut registered = std::collections::HashSet::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while registered.len() < 4 {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, frames_rx.recv()).await {
                Ok(Some((Family::Register, p))) => {
                    registered.insert(p["instance"].as_str().unwrap().to_string());
                }
                Ok(Some(_)) => {}
                _ => panic!("timed out before all slots REGISTERed, saw {registered:?}"),
            }
        }

        client.shutdown().await;

        // Every slot must now DEREGISTER, despite the capacity-1 control lane.
        let mut deregistered = std::collections::HashSet::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while deregistered.len() < 4 {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, frames_rx.recv()).await {
                Ok(Some((Family::Deregister, p))) => {
                    deregistered.insert(p["instance"].as_str().unwrap().to_string());
                }
                Ok(Some(_)) => {}
                _ => break,
            }
        }
        assert_eq!(
            deregistered.len(),
            4,
            "every slot must be DEREGISTERed at shutdown, got {deregistered:?}"
        );
        server.abort();
    }

    // Finding 4 (round 9): the outbound drain must yield a bounded batch so a
    // sustained transcript producer cannot starve `read.next()`. With an
    // UNBOUNDED drain the notified branch loops as long as the buffer keeps
    // refilling, so an inbound steer frame on the socket is never polled and the
    // session is never steered. The bounded batch returns to the `select!` loop
    // between batches, so inbound routing stays responsive even under a flood.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn inbound_routing_stays_responsive_under_a_transcript_flood() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        let steer_stream = compose_stream_id("w-flood", "job-flood");
        let steer_stream_srv = steer_stream.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // The server drains the socket fast and, on the first CLAIM, sends a
        // targeted inbound steer for this session's stream — then keeps reading.
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let ws = accept_async(sock).await.unwrap();
            let (mut write, mut read) = ws.split();
            let mut steered = false;
            while let Some(Ok(msg)) = read.next().await {
                if let Message::Binary(bytes) = msg {
                    if let Ok(frame) = decode_frame(&bytes) {
                        if frame.family == Family::Claim && !steered {
                            steered = true;
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
                }
            }
        });

        let mut cfg = test_config();
        cfg.url = format!("ws://127.0.0.1:{port}/na");
        cfg.buffer_capacity = 4096;
        let client = HubClient::spawn(cfg, &[]);
        let mut session = client.register_session("w-flood", capability(), "job-flood");
        let mut steer = session.take_steer().expect("steer receiver");

        // A sustained producer that keeps the outbound buffer saturated: it
        // enqueues directly (no bridge back-pressure) in a tight loop, so the
        // buffer is continuously non-empty until `stop` is set.
        let stop = Arc::new(AtomicBool::new(false));
        let producer_client = client.clone();
        let producer_stop = stop.clone();
        let producer = tokio::spawn(async move {
            while !producer_stop.load(Ordering::Relaxed) {
                producer_client.enqueue(
                    Lane::Bulk,
                    Family::Relay,
                    json!({ "op": "produce", "stream": "w-flood/job-flood", "chunk": "x" }),
                );
            }
        });

        // The inbound steer must reach THIS session despite the ongoing flood —
        // only a bounded drain yields the select loop back to `read.next()`.
        let got = tokio::time::timeout(Duration::from_secs(10), steer.recv()).await;
        stop.store(true, Ordering::Relaxed);
        let _ = producer.await;
        let got = got
            .expect("inbound steer was starved by the transcript flood (drain did not yield)")
            .expect("steer channel closed");
        assert_eq!(got, ControlFrame::Prompt { text: "steer-me".into() });

        drop(session);
        client.shutdown().await;
        server.abort();
    }
}
