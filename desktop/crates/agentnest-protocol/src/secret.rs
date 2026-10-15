//! [`Secret`]: a string that never shows up in logs.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A secret string (device token, nonce, proof, pairing secret).
///
/// * `Debug`/`Display` print `<redacted>` (security.md I9).
/// * The value is zeroized on drop.
/// * `PartialEq` compares in constant time.
/// * Serde is transparent: the real value is written to / read from the wire. Never log the serialised form.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Wraps a string.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the secret text. Callers must not log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Constant-time comparison with another string.
    pub fn ct_eq(&self, other: &str) -> bool {
        crate::canonical::ct_eq(self.0.as_bytes(), other.as_bytes())
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(&other.0)
    }
}

impl Eq for Secret {}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_are_redacted() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(format!("{s}"), "<redacted>");
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn equality_is_by_value() {
        assert_eq!(Secret::new("a"), Secret::new("a"));
        assert_ne!(Secret::new("a"), Secret::new("b"));
        assert!(Secret::new("abc").ct_eq("abc"));
        assert!(!Secret::new("abc").ct_eq("abd"));
    }
}
