//! Reference parser for agentic-hub **routing tokens**, mirroring the
//! `@nanobpm/agentic` token grammar. It holds this repo to the same parse /
//! reject decisions as the shared corpus (`fixtures/hub/valid-tokens.json`,
//! `fixtures/hub/invalid-tokens.json`).
//!
//! A routing token is a dotted path `[network.[subnetwork...].]role` with an
//! optional `#seat` suffix, e.g. `implementation.ci.fix#red`. The last segment
//! is the role; any leading segments are the network then its subnetworks.

/// A parsed routing token. `network` is absent for a bare single-segment role;
/// `subnetworks` holds any segments between the network and the role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingToken {
    pub network: Option<String>,
    pub subnetworks: Vec<String>,
    pub role: String,
    pub seat: Option<String>,
}

/// The closed set of token-parse error codes, matching the reference
/// `TokenErrorCode`. Each maps to the `expected` recorded in the corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenErrorCode {
    Empty,
    Whitespace,
    EmptySegment,
    BadSegment,
    MultipleSeatMarkers,
    EmptySeat,
    BadSeat,
}

impl TokenErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenErrorCode::Empty => "empty",
            TokenErrorCode::Whitespace => "whitespace",
            TokenErrorCode::EmptySegment => "empty-segment",
            TokenErrorCode::BadSegment => "bad-segment",
            TokenErrorCode::MultipleSeatMarkers => "multiple-seat-markers",
            TokenErrorCode::EmptySeat => "empty-seat",
            TokenErrorCode::BadSeat => "bad-seat",
        }
    }
}

/// A path segment: starts with a lowercase letter, then lowercase letters,
/// digits or hyphens.
fn is_segment(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A seat label: lowercase letters, digits or hyphens (a numeric seat like `1`
/// is allowed), non-empty, never uppercase.
fn is_seat(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Parse a routing token into its structured form, or the first grammar rule it
/// violates.
pub fn parse_token(token: &str) -> Result<RoutingToken, TokenErrorCode> {
    if token.is_empty() {
        return Err(TokenErrorCode::Empty);
    }
    if token.chars().any(char::is_whitespace) {
        return Err(TokenErrorCode::Whitespace);
    }

    let markers = token.matches('#').count();
    if markers > 1 {
        return Err(TokenErrorCode::MultipleSeatMarkers);
    }

    let (path, seat) = match token.split_once('#') {
        Some((path, seat)) => {
            if seat.is_empty() {
                return Err(TokenErrorCode::EmptySeat);
            }
            if !is_seat(seat) {
                return Err(TokenErrorCode::BadSeat);
            }
            (path, Some(seat.to_string()))
        }
        None => (token, None),
    };

    let segments: Vec<&str> = path.split('.').collect();
    for segment in &segments {
        if segment.is_empty() {
            return Err(TokenErrorCode::EmptySegment);
        }
        if !is_segment(segment) {
            return Err(TokenErrorCode::BadSegment);
        }
    }

    // The last segment is the role; any leading segments are network + subnetworks.
    let (role, lead) = segments
        .split_last()
        .expect("segments is non-empty: an empty path yields one empty segment");
    let (network, subnetworks) = match lead.split_first() {
        Some((net, subs)) => (
            Some((*net).to_string()),
            subs.iter().map(|s| (*s).to_string()).collect(),
        ),
        None => (None, Vec::new()),
    };

    Ok(RoutingToken {
        network,
        subnetworks,
        role: (*role).to_string(),
        seat,
    })
}
