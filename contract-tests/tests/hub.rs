//! Issue #5 — agentic hub conformance (worker side).
//!
//! Replays the shared `@nanobpm/agentic` conformance corpus (snapshotted under
//! `fixtures/hub/`, version in `fixtures/hub/VERSION`) against this repo's
//! worker-side hub codec and diffs the frames. The corpus is deliberately
//! cross-repo: the SAME golden vectors hold the Node worker
//! (jwulf/c8ctl-plugin-nano) and this codec to identical wire bytes, so passing
//! it here is passing against the Node plugin's own contract.
//!
//! Coverage assertions mirror the reference `corpus.test.ts` completeness tests:
//! a new family, lane, direction or error code cannot be added to the corpus
//! without a covering vector.

use std::collections::BTreeSet;

use contract_tests::hub::control::{parse_inbound_relay_chunk, ControlErrorCode, ControlFrame};
use contract_tests::hub::corpus;
use contract_tests::hub::frame::{decode_frame, encode_frame, DecodeErrorCode, Family, Lane};
use contract_tests::hub::token::{parse_token, RoutingToken, TokenErrorCode};
use contract_tests::hub::transcript::{acp_update_to_transcript_chunk, parse_transcript_event};
use contract_tests::hub::vocab::{validate_vocab, VocabErrorCode};
use contract_tests::hub::{hex_decode, hex_encode};

// --- Frame codec ---------------------------------------------------------

#[test]
fn golden_frames_round_trip_to_exact_bytes() {
    let frames = corpus::golden_frames();
    assert!(!frames.is_empty(), "golden-frames corpus is empty");
    for g in &frames {
        let bytes = hex_decode(&g.hex).unwrap_or_else(|| panic!("{}: bad hex", g.name));

        // Decode diffs against the declared frame.
        let decoded = decode_frame(&bytes)
            .unwrap_or_else(|e| panic!("{}: decode failed: {}", g.name, e.as_str()));
        assert_eq!(decoded.lane.as_str(), g.frame.lane, "{}: lane", g.name);
        assert_eq!(
            decoded.family.as_str(),
            g.frame.family,
            "{}: family",
            g.name
        );
        assert_eq!(decoded.seq, g.frame.seq, "{}: seq", g.name);
        assert_eq!(decoded.payload, g.frame.payload, "{}: payload", g.name);

        // Re-encode diffs against the exact golden wire bytes.
        let reencoded =
            encode_frame(&decoded).unwrap_or_else(|e| panic!("{}: encode failed: {:?}", g.name, e));
        assert_eq!(
            hex_encode(&reencoded),
            g.hex,
            "{}: re-encoded bytes differ from golden",
            g.name
        );
    }
}

#[test]
fn golden_frames_cover_every_family_lane_and_direction() {
    let frames = corpus::golden_frames();

    let families: BTreeSet<&str> = frames.iter().map(|g| g.frame.family.as_str()).collect();
    for f in [
        Family::Register,
        Family::Heartbeat,
        Family::Deregister,
        Family::Serve,
        Family::Demand,
        Family::Blackboard,
        Family::Relay,
        Family::Claim,
        Family::Release,
    ] {
        assert!(
            families.contains(f.as_str()),
            "no golden frame covers family {}",
            f.as_str()
        );
    }

    let lanes: BTreeSet<&str> = frames.iter().map(|g| g.frame.lane.as_str()).collect();
    for l in [Lane::Control, Lane::Interactive, Lane::Bulk] {
        assert!(
            lanes.contains(l.as_str()),
            "no golden frame covers lane {}",
            l.as_str()
        );
    }

    let directions: BTreeSet<&str> = frames.iter().map(|g| g.direction.as_str()).collect();
    for d in ["worker->hub", "hub->worker", "hub->observers"] {
        assert!(
            directions.contains(d),
            "no golden frame covers direction {d}"
        );
    }
}

#[test]
fn golden_frame_names_are_unique() {
    let frames = corpus::golden_frames();
    let names: BTreeSet<&str> = frames.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names.len(), frames.len(), "duplicate golden frame name");
}

#[test]
fn malformed_frames_are_rejected_with_the_expected_code() {
    let vectors = corpus::malformed_frames();
    assert!(!vectors.is_empty(), "malformed-frames corpus is empty");
    for m in &vectors {
        let bytes = hex_decode(&m.hex).unwrap_or_else(|| panic!("{}: bad hex", m.name));
        match decode_frame(&bytes) {
            Ok(_) => panic!(
                "{}: expected rejection ({}), decoded ok",
                m.name, m.expected
            ),
            Err(code) => assert_eq!(
                code.as_str(),
                m.expected,
                "{}: wrong decode-error code",
                m.name
            ),
        }
    }
}

#[test]
fn malformed_corpus_covers_every_decode_error_code() {
    let covered: BTreeSet<String> = corpus::malformed_frames()
        .into_iter()
        .map(|m| m.expected)
        .collect();
    for code in [
        DecodeErrorCode::Empty,
        DecodeErrorCode::ShortHeader,
        DecodeErrorCode::BadMagic,
        DecodeErrorCode::UnsupportedVersion,
        DecodeErrorCode::UnknownLane,
        DecodeErrorCode::UnknownFamily,
        DecodeErrorCode::TruncatedPayload,
        DecodeErrorCode::TrailingBytes,
        DecodeErrorCode::InvalidPayloadJson,
    ] {
        assert!(
            covered.contains(code.as_str()),
            "no malformed vector covers code {}",
            code.as_str()
        );
    }
}

// --- Inbound control vocabulary (steer-in) -------------------------------

fn control_frame_from_value(v: &serde_json::Value) -> ControlFrame {
    let obj = v.as_object().expect("control frame is an object");
    match obj.get("kind").and_then(|k| k.as_str()) {
        Some("prompt") => ControlFrame::Prompt {
            text: obj
                .get("text")
                .and_then(|t| t.as_str())
                .expect("prompt text")
                .to_string(),
        },
        Some("cancel") => ControlFrame::Cancel {
            reason: obj
                .get("reason")
                .and_then(|r| r.as_str())
                .map(str::to_string),
        },
        Some("permission") => ControlFrame::Permission {
            request_id: obj
                .get("requestId")
                .and_then(|r| r.as_str())
                .expect("requestId")
                .to_string(),
            outcome: obj
                .get("outcome")
                .and_then(|o| o.as_str())
                .expect("outcome")
                .to_string(),
        },
        other => panic!("unknown control kind: {other:?}"),
    }
}

#[test]
fn valid_control_corpus_decodes_to_its_declared_frame() {
    let vectors = corpus::control_frames();
    assert!(!vectors.is_empty(), "control-frames corpus is empty");
    for v in &vectors {
        let decoded = parse_inbound_relay_chunk(&v.chunk)
            .unwrap_or_else(|e| panic!("{}: expected ok, got {:?}", v.name, e));
        assert_eq!(
            decoded.frame,
            control_frame_from_value(&v.frame),
            "{}: frame",
            v.name
        );
        assert_eq!(
            decoded.structured, v.structured,
            "{}: structured flag",
            v.name
        );
    }
}

#[test]
fn structured_control_frames_round_trip_through_the_encoder() {
    for v in corpus::control_frames() {
        if !v.round_trips {
            continue;
        }
        let frame = control_frame_from_value(&v.frame);
        let encoded = frame.encode();
        assert_eq!(encoded, v.chunk, "{}: encoded chunk differs", v.name);
        let back = parse_inbound_relay_chunk(&encoded)
            .unwrap_or_else(|e| panic!("{}: re-decode failed: {:?}", v.name, e));
        assert_eq!(back.frame, frame, "{}: round-trip frame", v.name);
        assert!(back.structured, "{}: round-trip is structured", v.name);
    }
}

#[test]
fn legacy_bare_string_steer_still_decodes_as_a_prompt() {
    let legacy: Vec<_> = corpus::control_frames()
        .into_iter()
        .filter(|v| !v.structured)
        .collect();
    assert!(
        !legacy.is_empty(),
        "corpus must retain legacy bare-string vectors"
    );
    for v in &legacy {
        let decoded = parse_inbound_relay_chunk(&v.chunk).expect("legacy chunk decodes");
        match decoded.frame {
            ControlFrame::Prompt { ref text } => {
                assert_eq!(
                    text, &v.chunk,
                    "{}: prompt carries the chunk verbatim",
                    v.name
                )
            }
            ref other => panic!("{}: expected prompt, got {other:?}", v.name),
        }
        assert!(!decoded.structured, "{}: legacy is not structured", v.name);
    }
}

#[test]
fn malformed_control_corpus_is_rejected_with_the_expected_code() {
    let vectors = corpus::malformed_control_frames();
    assert!(!vectors.is_empty(), "malformed-control corpus is empty");
    for m in &vectors {
        match parse_inbound_relay_chunk(&m.chunk) {
            Ok(ok) => panic!(
                "{}: expected rejection ({}), got {:?}",
                m.name, m.expected, ok
            ),
            Err(errors) => assert!(
                errors.iter().any(|e| e.as_str() == m.expected),
                "{}: expected code {}, got {:?}",
                m.name,
                m.expected,
                errors.iter().map(|e| e.as_str()).collect::<Vec<_>>()
            ),
        }
    }
}

#[test]
fn malformed_control_corpus_covers_every_control_error_code() {
    let covered: BTreeSet<String> = corpus::malformed_control_frames()
        .into_iter()
        .map(|m| m.expected)
        .collect();
    for code in [
        ControlErrorCode::BadKind,
        ControlErrorCode::BadPromptText,
        ControlErrorCode::BadCancelReason,
        ControlErrorCode::BadPermissionRequestId,
        ControlErrorCode::BadPermissionOutcome,
    ] {
        assert!(
            covered.contains(code.as_str()),
            "no malformed control vector covers code {}",
            code.as_str()
        );
    }
}

// --- ACP transcript bridge ----------------------------------------------

#[test]
fn transcript_vectors_produce_the_exact_chunk_and_decode_back() {
    let vectors = corpus::transcript_vectors();
    assert!(!vectors.is_empty(), "transcript corpus is empty");
    for v in &vectors {
        // Producer: ACP update -> exact on-wire chunk bytes (or None when ignored).
        let produced = acp_update_to_transcript_chunk(&v.update);
        assert_eq!(
            produced.as_deref(),
            v.chunk.as_deref(),
            "{}: produced chunk differs",
            v.name
        );

        // Consumer: the chunk decodes back to the golden typed event.
        match (&v.chunk, &v.event) {
            (Some(chunk), Some(event)) => {
                let decoded = parse_transcript_event(chunk, v.offset);
                assert_eq!(&decoded, event, "{}: decoded event differs", v.name);
            }
            (None, None) => { /* ignored update: nothing to emit or decode */ }
            _ => panic!("{}: corpus chunk/event nullability mismatch", v.name),
        }
    }
}

// --- Vocabulary documents (registry schema) -----------------------------

#[test]
fn valid_vocab_corpus_is_accepted() {
    let vectors = corpus::valid_vocabs();
    assert!(!vectors.is_empty(), "valid-vocabs corpus is empty");
    for v in &vectors {
        validate_vocab(&v.document).unwrap_or_else(|e| {
            panic!("{}: expected accept, rejected with {}", v.name, e.as_str())
        });
    }
}

#[test]
fn invalid_vocab_corpus_is_rejected_with_the_expected_code() {
    let vectors = corpus::invalid_vocabs();
    assert!(!vectors.is_empty(), "invalid-vocabs corpus is empty");
    for v in &vectors {
        match validate_vocab(&v.document) {
            Ok(()) => panic!(
                "{}: expected rejection ({}), accepted",
                v.name, v.expected_code
            ),
            Err(code) => assert_eq!(
                code.as_str(),
                v.expected_code,
                "{}: wrong vocab-error code",
                v.name
            ),
        }
    }
}

#[test]
fn invalid_vocab_corpus_covers_every_vocab_error_code() {
    let covered: BTreeSet<String> = corpus::invalid_vocabs()
        .into_iter()
        .map(|v| v.expected_code)
        .collect();
    for code in [
        VocabErrorCode::NotObject,
        VocabErrorCode::BadVersion,
        VocabErrorCode::BadNetworks,
        VocabErrorCode::UnknownDocumentField,
        VocabErrorCode::BadNetworkName,
        VocabErrorCode::UnknownRoleField,
        VocabErrorCode::BadWeight,
        VocabErrorCode::BadSeats,
        VocabErrorCode::BadSeatLabel,
        VocabErrorCode::BadRequires,
        VocabErrorCode::BadSeatsDistinctFamily,
    ] {
        assert!(
            covered.contains(code.as_str()),
            "no invalid-vocab vector covers code {}",
            code.as_str()
        );
    }
}

// --- Routing tokens ------------------------------------------------------

fn routing_token_from_value(v: &serde_json::Value) -> RoutingToken {
    let obj = v.as_object().expect("parsed token is an object");
    RoutingToken {
        network: obj
            .get("network")
            .and_then(|n| n.as_str())
            .map(str::to_string),
        subnetworks: obj
            .get("subnetworks")
            .and_then(|s| s.as_array())
            .expect("parsed token has subnetworks array")
            .iter()
            .map(|s| s.as_str().expect("subnetwork is a string").to_string())
            .collect(),
        role: obj
            .get("role")
            .and_then(|r| r.as_str())
            .expect("parsed token has role")
            .to_string(),
        seat: obj.get("seat").and_then(|s| s.as_str()).map(str::to_string),
    }
}

#[test]
fn valid_token_corpus_parses_to_its_declared_form() {
    let vectors = corpus::valid_tokens();
    assert!(!vectors.is_empty(), "valid-tokens corpus is empty");
    for v in &vectors {
        let parsed = parse_token(&v.token)
            .unwrap_or_else(|e| panic!("{}: expected parse, got {}", v.name, e.as_str()));
        assert_eq!(
            parsed,
            routing_token_from_value(&v.parsed),
            "{}: parsed token differs",
            v.name
        );
    }
}

#[test]
fn invalid_token_corpus_is_rejected_with_the_expected_code() {
    let vectors = corpus::invalid_tokens();
    assert!(!vectors.is_empty(), "invalid-tokens corpus is empty");
    for v in &vectors {
        match parse_token(&v.token) {
            Ok(_) => panic!("{}: expected rejection ({}), parsed ok", v.name, v.expected),
            Err(code) => assert_eq!(
                code.as_str(),
                v.expected,
                "{}: wrong token-error code",
                v.name
            ),
        }
    }
}

#[test]
fn invalid_token_corpus_covers_every_token_error_code() {
    let covered: BTreeSet<String> = corpus::invalid_tokens()
        .into_iter()
        .map(|v| v.expected)
        .collect();
    for code in [
        TokenErrorCode::Empty,
        TokenErrorCode::Whitespace,
        TokenErrorCode::EmptySegment,
        TokenErrorCode::BadSegment,
        TokenErrorCode::MultipleSeatMarkers,
        TokenErrorCode::EmptySeat,
        TokenErrorCode::BadSeat,
    ] {
        assert!(
            covered.contains(code.as_str()),
            "no invalid-token vector covers code {}",
            code.as_str()
        );
    }
}

// --- Live-worker replay seam --------------------------------------------

/// The same corpus is designed to replay against a *running* worker's hub
/// connection (presence, transcript, steer, relay) once the Rust hub client
/// (#10) and MVP daemon (#6) exist. That end-to-end path needs a live
/// supervisor + hub endpoint, which CI does not provide, so — like the engine
/// tests — it skips cleanly when `NS_HUB_ENDPOINT` is unset.
///
/// The deferred runtime path (hub client + daemon) does not exist yet, so there
/// is nothing to replay against a real endpoint. Rather than report a green
/// "live replay" that exercises nothing, an explicitly configured endpoint
/// **fails loudly** until #6/#10 land: a requested live run that silently does
/// no work is worse than an honest "not implemented yet".
#[test]
fn replay_corpus_against_live_worker() {
    match std::env::var("NS_HUB_ENDPOINT") {
        Ok(ep) if !ep.is_empty() => {
            // Seam for #6/#10: connect to `ep`, drive the corpus against the live
            // worker, and diff its emitted frames against the goldens above.
            panic!(
                "NS_HUB_ENDPOINT={ep} requests a live-worker replay, but the hub client (#10) \
                 and MVP daemon (#6) do not exist yet, so there is nothing to replay against. \
                 Unset NS_HUB_ENDPOINT to skip until the deferred runtime path lands."
            );
        }
        _ => eprintln!(
            "skipping live-worker replay: set NS_HUB_ENDPOINT to run the corpus against a worker"
        ),
    }
}
