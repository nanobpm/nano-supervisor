//! The transcript relay stream-id codec — the worker's live copy of
//! `@nanobpm/agentic/emit`'s `composeStreamId`/`parseStreamId`.
//!
//! A relay stream names a single `(instance, jobKey)` producer. The id is the
//! length-prefixed form `"<N>:<instance>/<stream>"`, where `N` is the
//! **UTF-16 code-unit length** of `instance` (JS `String.length`, so an astral
//! character counts as 2) and `stream` is `String(jobKey)`. The explicit length
//! prefix makes the encoding injective: no two distinct `(instance, stream)`
//! pairs collide, regardless of what `:`/`/` characters either name contains —
//! the isolation guarantee inbound routing rests on, so one job's steer can
//! never cross into another's.
//!
//! Producing and parsing these ids byte-identically to the Node emit client is
//! what lets a Rust worker's transcript frames route exactly like a Node
//! worker's on the same hub.

/// Compose the relay stream id for a `(instance, stream)` pair. `stream` is the
/// job key stringified. The length prefix counts UTF-16 code units of
/// `instance`, matching JS `instance.length`.
pub fn compose_stream_id(instance: &str, stream: &str) -> String {
    format!("{}:{}/{}", instance.encode_utf16().count(), instance, stream)
}

/// The exact inverse of [`compose_stream_id`]: decode `"<N>:<instance>/<stream>"`
/// back into `(instance, stream)`. Returns `None` for any malformed id — a
/// missing/non-decimal or non-canonical (leading-zero) length prefix, a length
/// that overruns the string, or a missing `/` delimiter after the instance — so
/// a bad id off the wire can never be mistaken for a valid ref.
pub fn parse_stream_id(id: &str) -> Option<(String, String)> {
    let colon = id.find(':')?;
    let len_part = &id[..colon];
    if len_part.is_empty() || !len_part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let length: usize = len_part.parse().ok()?;
    // Reject non-canonical prefixes (e.g. a leading zero the composer never
    // emits) so parse stays a strict inverse of compose.
    if length.to_string() != len_part {
        return None;
    }
    // The length counts UTF-16 code units of `instance`, measured from just
    // after the `:` — the same units the composer emitted — so slice the tail in
    // UTF-16 space to recover a `:`/`/` inside the instance losslessly.
    let tail: Vec<u16> = id[colon + 1..].encode_utf16().collect();
    // The code unit right after the N-unit instance MUST be `/`; an overrun
    // length makes this `None` and rejects too.
    if tail.get(length) != Some(&(b'/' as u16)) {
        return None;
    }
    let instance = String::from_utf16(&tail[..length]).ok()?;
    let stream = String::from_utf16(&tail[length + 1..]).ok()?;
    Some((instance, stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composes_the_length_prefixed_form() {
        assert_eq!(compose_stream_id("w-abc123", "8519"), "8:w-abc123/8519");
        assert_eq!(compose_stream_id("", "job"), "0:/job");
    }

    #[test]
    fn round_trips_including_delimiters_in_the_instance() {
        for (inst, stream) in [
            ("w-abc123", "8519"),
            ("w:with/delims", "job-1"),
            ("", "s"),
            ("inst", ""),
            ("café", "42"),
        ] {
            let id = compose_stream_id(inst, stream);
            assert_eq!(
                parse_stream_id(&id),
                Some((inst.to_string(), stream.to_string())),
                "round-trip {id:?}"
            );
        }
    }

    #[test]
    fn astral_instance_counts_in_utf16_units() {
        // "😀" is one code point but two UTF-16 code units, so the prefix is 2.
        let id = compose_stream_id("😀", "9");
        assert_eq!(id, "2:😀/9");
        assert_eq!(parse_stream_id(&id), Some(("😀".to_string(), "9".to_string())));
    }

    #[test]
    fn rejects_malformed_ids() {
        assert_eq!(parse_stream_id("no-colon"), None);
        assert_eq!(parse_stream_id(":/x"), None); // empty length
        assert_eq!(parse_stream_id("01:ab/x"), None); // non-canonical leading zero
        assert_eq!(parse_stream_id("9:ab/x"), None); // length overruns
        assert_eq!(parse_stream_id("3:abcx"), None); // no `/` after instance
        assert_eq!(parse_stream_id("x:ab/y"), None); // non-decimal length
    }
}
