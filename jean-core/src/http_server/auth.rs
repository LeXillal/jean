use axum::http::{header, HeaderMap};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use std::path::Path;

/// Name of the session cookie set after a successful `/api/login`.
pub const SESSION_COOKIE_NAME: &str = "jean_session";

/// How long an issued session stays valid (30 days). The cookie is refreshed on
/// each new login, so an active user is never logged out mid-use.
pub const SESSION_TTL_SECS: u64 = 60 * 60 * 24 * 30;

/// Filename of the persisted HMAC key that signs session cookies. Rotating this
/// file (delete it) invalidates every outstanding session — the "log out
/// everywhere" lever.
const SESSION_KEY_FILE: &str = "web-session-key";

/// Generate a cryptographically random token (32 bytes, base64url-encoded).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// Validate a token against the expected value (constant-time comparison).
pub fn validate_token(provided: &str, expected: &str) -> bool {
    if provided.len() != expected.len() {
        return false;
    }
    // Simple constant-time compare
    provided
        .as_bytes()
        .iter()
        .zip(expected.as_bytes().iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

// ── Session cookies ──────────────────────────────────────────────────────────
//
// A session is a stateless, HMAC-signed value: `v1.<expiry_unix>.<sig>` where
// `sig = base64url(HMAC-SHA256(key, "v1.<expiry_unix>"))`. No server-side store,
// so sessions survive restarts; revocation is by rotating the key file or
// letting the expiry pass. The signing key never leaves the server; the cookie
// is set `HttpOnly` so JS (an XSS) cannot read it.

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sign(key: &[u8], message: &str) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(message.as_bytes());
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        mac.finalize().into_bytes(),
    )
}

/// Load the session-signing key from `<app_data_dir>/web-session-key`, creating
/// a fresh random 32-byte key (chmod 600 on unix) if absent or malformed.
pub fn load_or_create_session_key(app_data_dir: &Path) -> Result<Vec<u8>, String> {
    let path = app_data_dir.join(SESSION_KEY_FILE);
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            return Ok(bytes);
        }
    }
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    std::fs::create_dir_all(app_data_dir)
        .map_err(|e| format!("failed to create app data dir: {e}"))?;
    std::fs::write(&path, key).map_err(|e| format!("failed to write session key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(key.to_vec())
}

/// Mint a fresh session cookie value valid for [`SESSION_TTL_SECS`] from `now`.
pub fn issue_session_cookie(key: &[u8], now: u64) -> String {
    let exp = now.saturating_add(SESSION_TTL_SECS);
    let message = format!("v1.{exp}");
    let sig = sign(key, &message);
    format!("{message}.{sig}")
}

/// True when `value` is a well-formed, correctly-signed, non-expired session.
pub fn session_value_is_valid(key: &[u8], value: &str, now: u64) -> bool {
    let Some((message, sig)) = value.rsplit_once('.') else {
        return false;
    };
    // Constant-time signature check (reuses the token comparator).
    if !validate_token(sig, &sign(key, message)) {
        return false;
    }
    let Some(exp) = message.strip_prefix("v1.").and_then(|e| e.parse::<u64>().ok()) else {
        return false;
    };
    now < exp
}

/// Read the `jean_session` cookie from the request headers and verify it.
pub fn session_cookie_valid(headers: &HeaderMap, key: &[u8]) -> bool {
    let Some(value) = cookie_value(headers, SESSION_COOKIE_NAME) else {
        return false;
    };
    session_value_is_valid(key, &value, now_unix())
}

/// Extract a single cookie value from the `Cookie` request header.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(name) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_round_trip_and_expiry() {
        let key = [7u8; 32];
        let cookie = issue_session_cookie(&key, 1_000);
        // Valid now, valid just before expiry, invalid at/after expiry.
        assert!(session_value_is_valid(&key, &cookie, 1_000));
        assert!(session_value_is_valid(&key, &cookie, 1_000 + SESSION_TTL_SECS - 1));
        assert!(!session_value_is_valid(&key, &cookie, 1_000 + SESSION_TTL_SECS));
    }

    #[test]
    fn session_rejects_tamper_and_wrong_key() {
        let key = [7u8; 32];
        let other = [9u8; 32];
        let cookie = issue_session_cookie(&key, 1_000);
        // Wrong signing key → invalid.
        assert!(!session_value_is_valid(&other, &cookie, 1_000));
        // Tampered expiry (re-sign attempt with a flipped byte) → invalid.
        let mut tampered = cookie.clone();
        tampered.push('x');
        assert!(!session_value_is_valid(&key, &tampered, 1_000));
        // Garbage → invalid, never panics.
        assert!(!session_value_is_valid(&key, "not-a-cookie", 1_000));
        assert!(!session_value_is_valid(&key, "v1.999", 1_000));
    }

    #[test]
    fn cookie_value_parses_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "foo=bar; jean_session=abc.def; baz=1".parse().unwrap(),
        );
        assert_eq!(cookie_value(&headers, "jean_session").as_deref(), Some("abc.def"));
        assert!(cookie_value(&headers, "missing").is_none());
        // A prefix collision must not match.
        assert!(cookie_value(&headers, "jean_sess").is_none());
    }

    #[test]
    fn session_cookie_valid_reads_headers() {
        let key = [3u8; 32];
        let cookie = issue_session_cookie(&key, now_unix());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("jean_session={cookie}").parse().unwrap(),
        );
        assert!(session_cookie_valid(&headers, &key));
        assert!(!session_cookie_valid(&HeaderMap::new(), &key));
    }
}
