//! Typed loaders for the `fixtures/hub/` conformance-corpus snapshot.
//!
//! Every vector carries the same fields the reference `@nanobpm/agentic`
//! conformance export publishes (see `fixtures/hub/VERSION` for the provenance
//! and version). Loading is fail-loud: a missing or malformed fixture panics, so
//! a corpus drift can never silently skip a vector.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

fn hub_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("hub")
}

fn load<T: for<'de> Deserialize<'de>>(file: &str) -> T {
    let path = hub_dir().join(file);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read corpus fixture {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("parse corpus fixture {}: {e}", path.display()))
}

/// A golden `(frame <-> exact wire bytes)` pair.
#[derive(Debug, Deserialize)]
pub struct GoldenFrame {
    pub name: String,
    pub direction: String,
    pub frame: GoldenFrameBody,
    pub hex: String,
}

#[derive(Debug, Deserialize)]
pub struct GoldenFrameBody {
    pub lane: String,
    pub family: String,
    pub seq: u32,
    pub payload: Value,
}

/// An adversarial byte sequence that must be rejected with `expected`.
#[derive(Debug, Deserialize)]
pub struct MalformedFrame {
    pub name: String,
    pub hex: String,
    pub expected: String,
}

/// A valid inbound-steer chunk and the typed frame it must decode to.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlVector {
    pub name: String,
    pub chunk: String,
    pub frame: Value,
    pub structured: bool,
    pub round_trips: bool,
}

/// A tagged-but-malformed steer chunk and the error code it must raise.
#[derive(Debug, Deserialize)]
pub struct MalformedControlVector {
    pub name: String,
    pub chunk: String,
    pub expected: String,
}

/// One `(ACP update) -> (chunk bytes) -> (typed event)` transcript golden.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscriptVector {
    pub name: String,
    pub session_update: String,
    pub update: Value,
    pub chunk: Option<String>,
    pub event: Option<Value>,
    pub offset: i64,
}

pub fn golden_frames() -> Vec<GoldenFrame> {
    load("golden-frames.json")
}

pub fn malformed_frames() -> Vec<MalformedFrame> {
    load("malformed-frames.json")
}

pub fn control_frames() -> Vec<ControlVector> {
    load("control-frames.json")
}

pub fn malformed_control_frames() -> Vec<MalformedControlVector> {
    load("malformed-control-frames.json")
}

pub fn transcript_vectors() -> Vec<TranscriptVector> {
    load("transcript-vectors.json")
}
