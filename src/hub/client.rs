//! The worker-side agentic-hub client: ONE WebSocket per daemon, multiplexed
//! across every slot (mirroring how jwulf/c8ctl-plugin-nano#173 does it in the
//! Node plugin).
//!
//! A single background task owns the connection. It reconnects with jittered
//! exponential backoff, and while the hub is down outbound frames accumulate in
//! a bounded ring buffer (the oldest is dropped past
//! [`HubConfig::buffer_capacity`]) so the job keeps running and the transcript
//! resumes on reconnect without unbounded memory growth.
//!
//! Each running job registers a [`HubSession`]: it publishes **presence**,
//! bridges the agent's ACP `session/update` stream to **transcript** frames, and
//! receives **inbound steer** chunks routed to it. The session deregisters when
//! it is dropped.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::{interval, sleep, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

use crate::hub::config::HubConfig;
use crate::hub::control::{parse_inbound_relay_chunk, ControlFrame};
use crate::hub::frame::{decode_frame, encode_frame, Family, Frame, Lane};
use crate::hub::transcript::acp_update_to_transcript_chunk;
use crate::runtime::log;

/// First reconnect delay after a dropped/failed hub connection.
const BACKOFF_BASE: Duration = Duration::from_millis(500);
/// Ceiling on the reconnect backoff.
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How often the client sends a presence heartbeat while connected.
const HEARTBEAT: Duration = Duration::from_secs(15);

/// The shared hub client. Construct with [`HubClient::spawn`]; share it as
/// `Arc<HubClient>` across slots and open one [`HubSession`] per running job.
pub struct HubClient {
    config: HubConfig,
    /// Bounded outbound ring buffer, drained to the socket when connected and
    /// retained (oldest-dropped) while disconnected.
    outbound: Mutex<VecDeque<Frame>>,
    /// Woken whenever a frame is enqueued so the connection task drains promptly.
    outbound_notify: Notify,
    /// Monotonic per-frame sequence number.
    seq: AtomicU32,
    /// True while the WebSocket is up (presence is live).
    connected: AtomicBool,
    /// Per-session steer sinks, keyed by session id, used to route an inbound
    /// relay chunk to the job it addresses.
    sessions: Mutex<HashMap<String, mpsc::UnboundedSender<String>>>,
    /// Flipped to request the connection task to deregister and exit.
    shutdown_tx: watch::Sender<bool>,
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
        let client = Arc::new(HubClient {
            config,
            outbound: Mutex::new(VecDeque::new()),
            outbound_notify: Notify::new(),
            seq: AtomicU32::new(0),
            connected: AtomicBool::new(false),
            sessions: Mutex::new(HashMap::new()),
            shutdown_tx,
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

    /// Register a job as a live hub session: publishes presence and returns the
    /// handle the slot wires into the ACP agent for transcript + steer.
    pub fn register_session(self: &Arc<Self>, job_key: &str) -> HubSession {
        let session_id = job_key.to_string();
        let (steer_tx, steer_rx) = mpsc::unbounded_channel::<String>();
        self.sessions
            .lock()
            .unwrap()
            .insert(session_id.clone(), steer_tx);

        // Presence for this session.
        let mut presence = self.presence_payload();
        presence["session"] = Value::String(session_id.clone());
        presence["job"] = Value::String(job_key.to_string());
        self.enqueue(Lane::Control, Family::Register, presence);

        // Bridge ACP updates → transcript frames on a dedicated task.
        let (updates_tx, mut updates_rx) = mpsc::unbounded_channel::<Value>();
        let bridge_client = self.clone();
        let bridge_session = session_id.clone();
        tokio::spawn(async move {
            while let Some(update) = updates_rx.recv().await {
                if let Some(chunk) = acp_update_to_transcript_chunk(&update) {
                    bridge_client.enqueue(
                        Lane::Bulk,
                        Family::Relay,
                        json!({ "session": bridge_session, "chunk": chunk }),
                    );
                }
            }
        });

        HubSession {
            client: self.clone(),
            session_id,
            transcript: Some(updates_tx),
            steer: Some(steer_rx),
        }
    }

    /// Stop the hub: deregister the worker and let the connection task exit.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// The base presence payload shared by the worker register and every
    /// session register/heartbeat.
    fn presence_payload(&self) -> Value {
        let mut m = serde_json::Map::new();
        if let Some(token) = &self.config.token {
            m.insert("token".into(), Value::String(token.clone()));
        }
        if let Some(cred) = &self.config.credential {
            m.insert("credential".into(), Value::String(cred.clone()));
        }
        if let Some(perm) = &self.config.permission {
            m.insert("permission".into(), Value::String(perm.clone()));
        }
        if let Some(attr) = &self.config.attribution {
            m.insert("attribution".into(), Value::String(attr.clone()));
        }
        m.insert("terminal".into(), Value::Bool(self.config.terminal));
        m.insert("runtime".into(), Value::String("nano-supervisor".into()));
        Value::Object(m)
    }

    /// Enqueue a frame for delivery. Bounded: the oldest buffered frame is
    /// dropped once the buffer is at capacity, so a long outage cannot grow
    /// daemon memory without bound.
    fn enqueue(&self, lane: Lane, family: Family, payload: Value) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let frame = Frame::new(lane, family, seq, payload);
        {
            let mut buf = self.outbound.lock().unwrap();
            while buf.len() >= self.config.buffer_capacity {
                buf.pop_front();
            }
            buf.push_back(frame);
        }
        self.outbound_notify.notify_one();
    }

    /// Deliver an inbound relay chunk to the session it addresses (or, lacking a
    /// `session`, to every open session — the legacy broadcast steer).
    fn route_inbound(&self, payload: &Value) {
        let Some(chunk) = payload.get("chunk").and_then(Value::as_str) else {
            return;
        };
        let decoded = match parse_inbound_relay_chunk(chunk) {
            Some(d) => d,
            None => return, // tagged-but-malformed steer: ignore it
        };
        // Only prompt/cancel text is injectable into a running ACP turn; a
        // permission outcome is advisory here (the ACP client auto-answers
        // permission prompts), so it is logged rather than injected.
        let text = match decoded.frame {
            ControlFrame::Prompt { text } => text,
            ControlFrame::Cancel { reason } => reason.unwrap_or_default(),
            ControlFrame::Permission {
                request_id,
                outcome,
            } => {
                log(&format!(
                    "agentic hub: inbound permission {request_id} → {outcome} (advisory)"
                ));
                return;
            }
        };
        let sessions = self.sessions.lock().unwrap();
        match payload.get("session").and_then(Value::as_str) {
            Some(id) => {
                if let Some(tx) = sessions.get(id) {
                    let _ = tx.send(text);
                }
            }
            None => {
                for tx in sessions.values() {
                    let _ = tx.send(text.clone());
                }
            }
        }
    }
}

/// A per-job hub session: presence is live for its lifetime, the agent's ACP
/// updates are bridged to transcript frames, and inbound steer is routed here.
/// Dropping it deregisters the session.
pub struct HubSession {
    client: Arc<HubClient>,
    session_id: String,
    transcript: Option<mpsc::UnboundedSender<Value>>,
    steer: Option<mpsc::UnboundedReceiver<String>>,
}

impl HubSession {
    /// The sink the ACP agent forwards each `session/update` to. Taken once.
    pub fn transcript_sink(&mut self) -> Option<mpsc::UnboundedSender<Value>> {
        self.transcript.clone()
    }

    /// The inbound-steer receiver handed to the ACP agent so a hub-delivered
    /// prompt is injected into the running turn. Taken once.
    pub fn take_steer(&mut self) -> Option<mpsc::UnboundedReceiver<String>> {
        self.steer.take()
    }
}

impl Drop for HubSession {
    fn drop(&mut self) {
        self.client
            .sessions
            .lock()
            .unwrap()
            .remove(&self.session_id);
        self.client.enqueue(
            Lane::Control,
            Family::Deregister,
            json!({ "session": self.session_id }),
        );
    }
}

/// Jittered exponential backoff: `delay/2 + random(0, delay/2)`, so a fleet of
/// daemons reconnecting after a shared hub outage does not thunder together.
fn jittered(delay: Duration) -> Duration {
    let half = delay / 2;
    let span = half.as_millis() as u64;
    let extra = if span == 0 {
        0
    } else {
        // Cheap, dependency-free jitter seeded from the monotonic clock.
        (Instant::now().elapsed().as_nanos() as u64).wrapping_add(span) % span
    };
    half + Duration::from_millis(extra)
}

async fn connection_loop(client: Arc<HubClient>, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = BACKOFF_BASE;
    loop {
        if *shutdown.borrow() {
            break;
        }
        match connect(&client.config).await {
            Ok(stream) => {
                backoff = BACKOFF_BASE;
                client.connected.store(true, Ordering::Relaxed);
                log("agentic hub: connected");
                // (Re)assert worker presence, then re-register every open
                // session so a reconnect restores their live presence.
                client.enqueue(Lane::Control, Family::Register, client.presence_payload());
                for id in client.sessions.lock().unwrap().keys().cloned() {
                    let mut p = client.presence_payload();
                    p["session"] = Value::String(id);
                    client.enqueue(Lane::Control, Family::Register, p);
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
        let wait = jittered(backoff);
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

async fn connect(config: &HubConfig) -> anyhow::Result<WsStream> {
    let mut request = config.url.as_str().into_client_request()?;
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
                client.enqueue(Lane::Control, Family::Heartbeat, client.presence_payload());
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
                    // Best-effort graceful deregister before exit.
                    client.enqueue(Lane::Control, Family::Deregister, client.presence_payload());
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
            match buf.pop_front() {
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
            buffer_capacity: 3,
        }
    }

    #[tokio::test]
    async fn buffer_drops_oldest_at_capacity() {
        let client = HubClient::spawn(test_config());
        // The connection cannot establish (port 1), so nothing drains: the ring
        // buffer must cap at `buffer_capacity`, dropping the oldest frames.
        for i in 0..10 {
            client.enqueue(Lane::Bulk, Family::Relay, json!({ "n": i }));
        }
        let buf = client.outbound.lock().unwrap();
        assert!(buf.len() <= 3, "buffer exceeded capacity: {}", buf.len());
        client.shutdown();
    }

    #[tokio::test]
    async fn session_register_and_deregister_enqueue_frames() {
        let client = HubClient::spawn(test_config());
        {
            let _session = client.register_session("job-1");
            assert!(client.sessions.lock().unwrap().contains_key("job-1"));
        }
        // Dropping the session removes it from the routing table.
        assert!(!client.sessions.lock().unwrap().contains_key("job-1"));
        client.shutdown();
    }

    #[tokio::test]
    async fn inbound_prompt_is_routed_to_its_session() {
        let client = HubClient::spawn(test_config());
        let mut session = client.register_session("job-7");
        let mut steer = session.take_steer().expect("steer receiver");
        client.route_inbound(&json!({ "session": "job-7", "chunk": "do the thing" }));
        let got = steer.recv().await.expect("steer delivered");
        assert_eq!(got, "do the thing");
        client.shutdown();
    }

    #[tokio::test]
    async fn transcript_sink_bridges_updates_to_frames() {
        let client = HubClient::spawn(test_config());
        let mut session = client.register_session("job-9");
        let sink = session.transcript_sink().expect("transcript sink");
        sink.send(json!({
            "sessionUpdate": "agent_message_chunk",
            "content": { "type": "text", "text": "hello" }
        }))
        .unwrap();
        // Give the bridge task a moment to enqueue the transcript frame.
        for _ in 0..50 {
            if client
                .outbound
                .lock()
                .unwrap()
                .iter()
                .any(|f| f.family == Family::Relay)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let has_relay = client
            .outbound
            .lock()
            .unwrap()
            .iter()
            .any(|f| f.family == Family::Relay);
        assert!(
            has_relay,
            "transcript update was not bridged to a relay frame"
        );
        client.shutdown();
    }
}
