//! Small shared utilities.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RFC 3339 timestamp for "now" (used in InternalData auth_info).
pub fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Generate a URL-safe random token of `n` bytes of entropy (base64url, no pad).
pub fn random_token(n: usize) -> String {
    use base64::Engine;
    let mut buf = vec![0u8; n];
    fill_random(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Fill a buffer with OS randomness via jose-rs's transitive `rand`.
fn fill_random(buf: &mut [u8]) {
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(buf);
}

// Re-export the rand_core used by our crypto deps so random_token works without
// adding a separate dependency line.
use p256::elliptic_curve::rand_core;
