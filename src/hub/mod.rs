//! Worker-side agentic-hub client (issue #10).
//!
//! The daemon opens ONE WebSocket to the agentic hub, multiplexed across all
//! slots, and makes a Rust-run job observable exactly like a Node-run one:
//! live **presence**, a live **transcript** (the agent's ACP `session/update`
//! stream bridged to the shared `@nanobpm/agentic` wire), and **inbound steer**
//! (prompt / cancel) injected into the running ACP turn.
//!
//! A PTY **terminal relay** is NOT wired in this PR: the pipe/PTY transport is
//! a follow-up, so [`client`] always advertises `terminal: false` in its
//! capability payload rather than promise an unavailable capability.
//!
//! The wire codec here ([`frame`], [`control`], [`transcript`]) is the live
//! twin of the conformance suite's codec in `contract-tests/src/hub/` (issue
//! #5), so the bytes a Rust worker emits match the bytes the Node plugin emits
//! and both pass the same cross-repo golden corpus.
//!
//! Configuration comes entirely from the `NANO_AGENTIC*` environment
//! ([`config::HubConfig::from_env`]). Local-first: the hub is ON BY DEFAULT and
//! `NANO_AGENTIC` is an opt-OUT (only `off`/`0`/`false`/`no` disables it); with
//! no secure identity the worker joins in LOCAL mode.

pub mod client;
pub mod config;
pub mod control;
pub mod frame;
pub mod stream;
pub mod transcript;

pub use client::HubClient;
pub use client::HubSession;
pub use config::HubConfig;
