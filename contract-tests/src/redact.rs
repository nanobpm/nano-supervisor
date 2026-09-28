//! Redaction helpers for golden files and stable assertions.
//!
//! Timestamps, PIDs, temporary paths, keys and lease tokens change every run;
//! redact them so `--json` output and recordings compare stably. `--json` and
//! `hire --list` are compared exactly after redaction; human-readable output
//! only asserts the fields and facts (the decision on issue #1).

/// A configurable redactor: register the run-specific literals (a temp home, an
/// engine URL, a job key, a lease token), then `apply` collapses them along with
/// generic UUIDs, long hex tokens and epoch-like numbers.
#[derive(Default)]
pub struct Redactor {
    literals: Vec<(String, String)>,
}

impl Redactor {
    pub fn new() -> Self {
        Redactor::default()
    }

    /// Replace every occurrence of `literal` with `placeholder` (e.g. a temp
    /// path with `<tmp>`). Longer literals are applied first so a path prefix
    /// does not shadow a longer match.
    pub fn literal(mut self, literal: &str, placeholder: &str) -> Self {
        if !literal.is_empty() {
            self.literals
                .push((literal.to_string(), placeholder.to_string()));
        }
        self
    }

    /// Apply the registered literals then the built-in generic passes.
    pub fn apply(&self, input: &str) -> String {
        let mut lits = self.literals.clone();
        lits.sort_by_key(|(l, _)| std::cmp::Reverse(l.len()));
        let mut out = input.to_string();
        for (lit, ph) in &lits {
            out = out.replace(lit, ph);
        }
        out = redact_uuids(&out);
        out = redact_hex_tokens(&out);
        redact_epochs(&out)
    }
}

/// Collapse `8-4-4-4-12` hex UUIDs to `<uuid>`.
pub fn redact_uuids(s: &str) -> String {
    replace_matches(s, is_uuid, "<uuid>")
}

/// Collapse hex runs of 16+ chars (lease tokens, keys) to `<hex>`.
pub fn redact_hex_tokens(s: &str) -> String {
    replace_matches(
        s,
        |w| w.len() >= 16 && w.chars().all(|c| c.is_ascii_hexdigit()),
        "<hex>",
    )
}

/// Collapse 10-13 digit runs (epoch seconds / millis) to `<ts>`.
pub fn redact_epochs(s: &str) -> String {
    replace_matches(
        s,
        |w| (10..=13).contains(&w.len()) && w.chars().all(|c| c.is_ascii_digit()),
        "<ts>",
    )
}

fn is_uuid(w: &str) -> bool {
    let parts: Vec<&str> = w.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    parts.len() == 5
        && parts
            .iter()
            .zip(lens)
            .all(|(p, n)| p.len() == n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Split on characters that never appear inside the tokens we redact, test each
/// piece with `matches`, and swap the whole piece for `placeholder`.
fn replace_matches(s: &str, matches: impl Fn(&str) -> bool, placeholder: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        if !token.is_empty() {
            if matches(token) {
                out.push_str(placeholder);
            } else {
                out.push_str(token);
            }
            token.clear();
        }
    };
    for c in s.chars() {
        // Tokens can contain hex digits and '-' (for UUIDs); everything else is a
        // separator we pass through verbatim.
        if c.is_ascii_alphanumeric() || c == '-' {
            token.push(c);
        } else {
            flush(&mut token, &mut out);
            out.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_uuid_hex_and_epoch() {
        let r = redact_uuids("job 3f7c1e2a-1b2c-4d5e-8f90-abcdef012345 done");
        assert_eq!(r, "job <uuid> done");
        assert_eq!(redact_hex_tokens("token=deadbeefdeadbeef99"), "token=<hex>");
        assert_eq!(redact_epochs("at 1735689600123 ok"), "at <ts> ok");
    }

    #[test]
    fn literals_apply_longest_first() {
        let out = Redactor::new()
            .literal("/tmp/ns-home-abc", "<home>")
            .literal("/tmp/ns-home-abc/runs", "<runs>")
            .apply("path /tmp/ns-home-abc/runs/1");
        assert_eq!(out, "path <runs>/1");
    }

    #[test]
    fn short_hex_and_numbers_survive() {
        // A short id or a small number is not a token we redact.
        assert_eq!(redact_hex_tokens("id=abc123"), "id=abc123");
        assert_eq!(redact_epochs("retries=3"), "retries=3");
    }
}
