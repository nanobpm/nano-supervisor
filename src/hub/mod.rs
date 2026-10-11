//! Worker-side agentic-hub client (issue #10).
//!
//! The daemon opens ONE WebSocket to the agentic hub, multiplexed across all
//! slots, and makes a Rust-run job observable exactly like a Node-run one:
//! live **presence**, a live **transcript** (the agent's ACP `session/update`
//! stream bridged to the shared `@nanobpm/agentic` wire), **inbound steer**
//! injected into the running ACP turn, and — for PTY agents — a **terminal
//! relay**.
//!
//! The wire codec here ([`frame`], [`control`], [`transcript`]) is the live
//! twin of the conformance suite's codec in `contract-tests/src/hub/` (issue
//! #5), so the bytes a Rust worker emits match the bytes the Node plugin emits
//! and both pass the same cross-repo golden corpus.
//!
//! Configuration comes entirely from the `NANO_AGENTIC*` environment
//! ([`config::HubConfig::from_env`]); with it unset the daemon runs exactly as
//! before, so the hub is purely additive.

pub mod client;
pub mod config;
pub mod control;
pub mod frame;
pub mod transcript;

pub use client::HubClient;
pub use config::HubConfig;
