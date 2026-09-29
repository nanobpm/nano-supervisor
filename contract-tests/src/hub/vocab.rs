//! Reference validator for agentic-hub **vocabulary documents**, mirroring the
//! `@nanobpm/agentic` registry schema. It holds this repo to the same accept /
//! reject decisions as the shared corpus (`fixtures/hub/valid-vocabs.json`,
//! `fixtures/hub/invalid-vocabs.json`).
//!
//! A vocabulary document declares the networks, roles and seating a fleet
//! recognises. Validation is structural and fail-loud: the first rule a document
//! violates yields the corresponding [`VocabErrorCode`].

use serde_json::Value;

/// The closed set of vocabulary-validation error codes, matching the reference
/// `VocabErrorCode`. Each maps to the `expectedCode` recorded in the corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VocabErrorCode {
    NotObject,
    BadVersion,
    BadNetworks,
    UnknownDocumentField,
    BadNetworkName,
    UnknownRoleField,
    BadWeight,
    BadSeats,
    BadSeatLabel,
    BadRequires,
    BadSeatsDistinctFamily,
}

impl VocabErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            VocabErrorCode::NotObject => "not-object",
            VocabErrorCode::BadVersion => "bad-version",
            VocabErrorCode::BadNetworks => "bad-networks",
            VocabErrorCode::UnknownDocumentField => "unknown-document-field",
            VocabErrorCode::BadNetworkName => "bad-network-name",
            VocabErrorCode::UnknownRoleField => "unknown-role-field",
            VocabErrorCode::BadWeight => "bad-weight",
            VocabErrorCode::BadSeats => "bad-seats",
            VocabErrorCode::BadSeatLabel => "bad-seat-label",
            VocabErrorCode::BadRequires => "bad-requires",
            VocabErrorCode::BadSeatsDistinctFamily => "bad-seats-distinct-family",
        }
    }
}

/// A lowercase dotted-path segment / name: starts with a letter, then lowercase
/// letters, digits or hyphens. Governs network names and seat labels.
fn is_lower_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn validate_role(role: &Value) -> Result<(), VocabErrorCode> {
    let obj = role.as_object().ok_or(VocabErrorCode::UnknownRoleField)?;
    for (field, value) in obj {
        match field.as_str() {
            "requires" => match value {
                Value::Array(items) if items.iter().all(Value::is_string) => {}
                _ => return Err(VocabErrorCode::BadRequires),
            },
            "weight" => {
                if !value.is_i64() && !value.is_u64() {
                    return Err(VocabErrorCode::BadWeight);
                }
            }
            "seats" => match value {
                Value::Number(n) => match n.as_i64() {
                    Some(count) if count >= 0 => {}
                    _ => return Err(VocabErrorCode::BadSeats),
                },
                Value::Array(labels) => {
                    for label in labels {
                        match label.as_str() {
                            Some(l) if is_lower_name(l) => {}
                            _ => return Err(VocabErrorCode::BadSeatLabel),
                        }
                    }
                }
                _ => return Err(VocabErrorCode::BadSeats),
            },
            "seatsDistinctFamily" => {
                if !value.is_boolean() {
                    return Err(VocabErrorCode::BadSeatsDistinctFamily);
                }
            }
            _ => return Err(VocabErrorCode::UnknownRoleField),
        }
    }
    Ok(())
}

fn validate_network(network: &Value) -> Result<(), VocabErrorCode> {
    let obj = network.as_object().ok_or(VocabErrorCode::BadNetworkName)?;
    for (field, value) in obj {
        match field.as_str() {
            "roles" => {
                let roles = value.as_object().ok_or(VocabErrorCode::UnknownRoleField)?;
                for role in roles.values() {
                    validate_role(role)?;
                }
            }
            "subnetworks" => {
                let subs = value.as_object().ok_or(VocabErrorCode::BadNetworkName)?;
                for (name, sub) in subs {
                    if !is_lower_name(name) {
                        return Err(VocabErrorCode::BadNetworkName);
                    }
                    validate_network(sub)?;
                }
            }
            _ => { /* other network fields are not constrained by the corpus */ }
        }
    }
    Ok(())
}

/// Validate a vocabulary document. `Ok(())` for a document the registry accepts;
/// `Err(code)` for the first rule it violates.
pub fn validate_vocab(document: &Value) -> Result<(), VocabErrorCode> {
    let obj = document.as_object().ok_or(VocabErrorCode::NotObject)?;

    match obj.get("version") {
        Some(Value::Number(n)) => match n.as_i64() {
            Some(v) if v >= 1 => {}
            _ => return Err(VocabErrorCode::BadVersion),
        },
        _ => return Err(VocabErrorCode::BadVersion),
    }

    let networks = match obj.get("networks") {
        Some(Value::Object(m)) => m,
        _ => return Err(VocabErrorCode::BadNetworks),
    };

    for field in obj.keys() {
        if field != "version" && field != "networks" {
            return Err(VocabErrorCode::UnknownDocumentField);
        }
    }

    for (name, network) in networks {
        if !is_lower_name(name) {
            return Err(VocabErrorCode::BadNetworkName);
        }
        validate_network(network)?;
    }

    Ok(())
}
