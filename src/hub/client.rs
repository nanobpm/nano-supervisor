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
use tokio::time::{interval, sleep};

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL};
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

    /// Append `frame` to its lane, evicting the oldest frame from the
    /// least-important non-empty lane first whenever the shared capacity is
    /// reached.
    fn push(&mut self, frame: Frame) {
        while self.len() >= self.capacity {
            if self.bulk.pop_front().is_some()
                || self.interactive.pop_front().is_some()
                || self.control.pop_front().is_some()
            {
                continue;
            }
            break; // capacity 0: nothing to evict, drop on the floor below
        }
        if self.capacity == 0 {
            return;
        }
        match frame.lane {
            Lane::Control => self.control.push_back(frame),
            Lane::Interactive => self.interactive.push_back(frame),
            Lane::Bulk => self.bulk.push_back(frame),
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
    sessions: Mutex<HashMap<String, mpsc::UnboundedSender<ControlFrame>>>,
    /// Flipped to request the connection task to deregister and exit.
    shutdown_tx: watch::Sender<bool>,
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
        tokio::spawn(connection_loop(client.clone(), shutdown_rx));
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
        let (steer_tx, steer_rx) = mpsc::unbounded_channel::<ControlFrame>();
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
        let (updates_tx, mut updates_rx) = mpsc::unbounded_channel::<Value>();
        let bridge_client = self.clone();
        let bridge_stream = stream.clone();
        tokio::spawn(async move {
            while let Some(update) = updates_rx.recv().await {
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
        });

        HubSession {
            client: self.clone(),
            instance: instance.to_string(),
            job_key: job_key.to_string(),
            stream,
            transcript: Some(updates_tx),
            steer: Some(steer_rx),
        }
    }

    /// Stop the hub: deregister every worker and let the connection task exit.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
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

    /// Enqueue a frame for delivery. Bounded and QoS-aware: see [`LaneBuffer`].
    fn enqueue(&self, lane: Lane, family: Family, payload: Value) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let frame = Frame::new(lane, family, seq, payload);
        self.outbound.lock().unwrap().push(frame);
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
        // permission outcome).
        let _ = sink.send(decoded.frame);
    }
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
    transcript: Option<mpsc::UnboundedSender<Value>>,
    steer: Option<mpsc::UnboundedReceiver<ControlFrame>>,
}

impl HubSession {
    /// The sink the ACP agent forwards each `session/update` to. Taken once.
    pub fn transcript_sink(&mut self) -> Option<mpsc::UnboundedSender<Value>> {
        self.transcript.clone()
    }

    /// The inbound-steer receiver handed to the ACP agent so a hub-delivered
    /// control is applied to the running turn. Taken once.
    pub fn take_steer(&mut self) -> Option<mpsc::UnboundedReceiver<ControlFrame>> {
        self.steer.take()
    }
}

impl Drop for HubSession {
    fn drop(&mut self) {
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
        match connect(&client.config).await {
            Ok(stream) => {
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
                // contract (presence + ownership before transcript).
                for (inst, cap) in client.instances.lock().unwrap().iter() {
                    client.enqueue(
                        Lane::Control,
                        Family::Register,
                        json!({ "instance": inst, "capability": cap }),
                    );
                }
                for (inst, jobs) in client.in_flight.lock().unwrap().iter() {
                    for job_key in jobs {
                        client.enqueue(
                            Lane::Control,
                            Family::Claim,
                            json!({ "instance": inst, "jobKey": job_key }),
                        );
                    }
                }
                pump(&client, stream, &mut shutdown).await;
                client.connected.store(false, Ordering::Relaxed);
                log("agentic hub: disconnected");
            }
            Err(e) => {
                log(&format!("agentic hub: connect failed: {e:#}"));
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
    if let Some(protocol) = &config.protocol {
        request
            .headers_mut()
            .insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_str(protocol)?);
    }
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
    loop {
        let frame = {
            let mut buf = client.outbound.lock().unwrap();
            match buf.pop() {
                Some(f) => f,
                None => return Ok(()),
            }
        };
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
        client.shutdown();
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
        client.shutdown();
    }

    #[tokio::test]
    async fn control_drains_before_bulk() {
        let client = HubClient::spawn(test_config());
        client.enqueue(Lane::Bulk, Family::Relay, json!({ "n": 1 }));
        client.enqueue(Lane::Control, Family::Register, json!({ "instance": "w" }));
        let frames = buffered(&client);
        assert_eq!(frames[0].0, Lane::Control, "control lane drains first");
        client.shutdown();
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
        client.shutdown();
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
        client.shutdown();
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
        client.shutdown();
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
        client.shutdown();
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
        client.shutdown();
    }

    #[tokio::test]
    async fn transcript_sink_bridges_updates_to_produce_frames() {
        let client = HubClient::spawn(test_config());
        let mut session = client.register_session("w-9", capability(), "job-9");
        let sink = session.transcript_sink().expect("transcript sink");
        let _ = buffered(&client); // discard the register/claim frames
        sink.send(json!({
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
        client.shutdown();
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
        client.shutdown();
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
        client.shutdown();
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
        client.shutdown();
        let _ = server.await;
    }
}
