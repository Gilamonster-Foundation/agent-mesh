//! Small shared helpers for CLI subcommands.
//!
//! Only stuff that more than one subcommand needs lives here.
//! Currently: a `2s`/`30s`/`5m`/`1h` duration parser and a hostname
//! resolver.

use anyhow::{anyhow, Result};
use std::time::Duration;

/// Parse a human-friendly duration string like `100ms`, `5s`, `2m`,
/// `1h`. Bare digits are interpreted as seconds.
///
/// This is intentionally tiny — the CLI only needs it for "how long
/// should we listen / announce", not for arbitrary chrono parsing.
pub fn parse_duration(s: &str) -> Result<Duration> {
    if let Some(num) = s.strip_suffix("ms") {
        Ok(Duration::from_millis(
            num.parse().map_err(|_| bad_duration(s))?,
        ))
    } else if let Some(num) = s.strip_suffix('s') {
        Ok(Duration::from_secs(
            num.parse().map_err(|_| bad_duration(s))?,
        ))
    } else if let Some(num) = s.strip_suffix('m') {
        let n: u64 = num.parse().map_err(|_| bad_duration(s))?;
        Ok(Duration::from_secs(n * 60))
    } else if let Some(num) = s.strip_suffix('h') {
        let n: u64 = num.parse().map_err(|_| bad_duration(s))?;
        Ok(Duration::from_secs(n * 3600))
    } else {
        Ok(Duration::from_secs(s.parse().map_err(|_| bad_duration(s))?))
    }
}

fn bad_duration(s: &str) -> anyhow::Error {
    anyhow!("invalid duration '{s}' — expected e.g. '5s', '2m', '1h', '500ms'")
}

/// Resolve the system hostname via `hostname(1)`. Falls back to
/// `"unknown-host"` if the command is missing or fails.
#[must_use]
pub fn current_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".to_string())
}

/// Format the current wall-clock time as RFC 3339 with second
/// granularity, in UTC. Used as the `issued_at` *claim* on agent
/// certificates — see `AgentMetadata` docstring; wall-clock is fine
/// as a claim in a signed cert, but never as a coordination
/// primitive.
#[must_use]
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn parse_duration_milliseconds() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn parse_duration_bare_digits_are_seconds() {
        assert_eq!(parse_duration("42").unwrap(), Duration::from_secs(42));
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(parse_duration("five seconds").is_err());
        assert!(parse_duration("xyzs").is_err());
        assert!(parse_duration("12x").is_err());
    }

    #[test]
    fn parse_duration_rejects_empty_unit_prefix() {
        // "s" alone has no number — empty parses fail.
        assert!(parse_duration("s").is_err());
    }

    #[test]
    fn current_hostname_returns_nonempty() {
        let h = current_hostname();
        assert!(!h.is_empty());
    }

    #[test]
    fn now_rfc3339_looks_like_iso_8601() {
        let s = now_rfc3339();
        // YYYY-MM-DDTHH:MM:SSZ — 20 chars
        assert_eq!(s.len(), 20, "unexpected timestamp shape: {s}");
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
    }
}
