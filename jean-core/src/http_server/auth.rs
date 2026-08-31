use axum::http::{header, HeaderMap};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};

/// Name of the session cookie set after a successful `/api/login`.
pub const SESSION_COOKIE_NAME: &str = "jean_session";

/// How long an issued session stays valid (30 days). Sessions slide: an active
/// browser gets a fresh 30 days once it passes half-life, so only a genuinely
/// idle session ever expires.
pub const SESSION_TTL_SECS: u64 = 60 * 60 * 24 * 30;

/// Filename of the persisted HMAC key that signs session cookies. Deleting it
/// invalidates every outstanding cookie (the nuclear "log out everywhere").
const SESSION_KEY_FILE: &str = "web-session-key";

/// Filename of the session allowlist. Matches the rest of Jean's persistence:
/// a small JSON file in app-data, not a database.
const SESSIONS_FILE: &str = "web-sessions.json";

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
// A cookie is `v2.<sid>.<expiry_unix>.<sig>`, signed with HMAC-SHA256 so it
// cannot be forged. The signature alone is not enough to authorize: the `sid`
// must ALSO still be listed in the session store. That indirection is what makes
// per-device revocation possible — dropping a `sid` from the store instantly
// kills that one cookie without touching the others.

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
    restrict_permissions(&path);
    Ok(key.to_vec())
}

fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Mint a cookie value binding `sid` and `expires_at` under the signing key.
pub fn issue_session_cookie(key: &[u8], sid: &str, expires_at: u64) -> String {
    let message = format!("v2.{sid}.{expires_at}");
    let sig = sign(key, &message);
    format!("{message}.{sig}")
}

/// Verify a cookie's signature and return `(sid, expires_at)`. Does NOT check
/// expiry or revocation — the caller consults the store for that.
pub fn parse_session_cookie(key: &[u8], value: &str) -> Option<(String, u64)> {
    let (message, sig) = value.rsplit_once('.')?;
    if !validate_token(sig, &sign(key, message)) {
        return None;
    }
    let rest = message.strip_prefix("v2.")?;
    let (sid, exp) = rest.rsplit_once('.')?;
    if sid.is_empty() {
        return None;
    }
    Some((sid.to_string(), exp.parse::<u64>().ok()?))
}

/// Read the raw `jean_session` cookie value from the request headers.
pub fn session_cookie_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(SESSION_COOKIE_NAME) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Short human label for a session row, derived from the User-Agent. Purely
/// cosmetic (for a future "active sessions" list); never used for auth.
pub fn label_from_user_agent(headers: &HeaderMap) -> String {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if ua.is_empty() {
        return "Unknown device".to_string();
    }
    ua.chars().take(120).collect()
}

// ── Session store (JSON allowlist) ───────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SessionRecord {
    pub sid: String,
    pub issued_at: u64,
    pub last_seen: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub label: String,
}

/// The set of sessions allowed to authenticate. Persisted as a small JSON file
/// (Jean has no database — see the JSON/JSONL persistence used everywhere else).
/// Held in memory behind a lock and rewritten only on mutation.
#[derive(Default, Serialize, Deserialize)]
pub struct SessionStore {
    #[serde(default)]
    sessions: Vec<SessionRecord>,
    #[serde(skip)]
    path: PathBuf,
}

impl SessionStore {
    /// Load from `<app_data_dir>/web-sessions.json`, dropping expired rows. A
    /// missing or corrupt file yields an empty store (fail closed: nobody is
    /// authorized until they log in again).
    pub fn load(app_data_dir: &Path) -> Self {
        let path = app_data_dir.join(SESSIONS_FILE);
        let mut store = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<SessionStore>(&raw).ok())
            .unwrap_or_default();
        store.path = path;
        store.prune(now_unix());
        store
    }

    fn prune(&mut self, now: u64) {
        self.sessions.retain(|s| s.expires_at > now);
    }

    /// Atomic write (temp file + rename), chmod 600 — same pattern as the other
    /// secret-bearing files in app-data.
    fn persist(&self) -> Result<(), String> {
        if self.path.as_os_str().is_empty() {
            return Ok(()); // in-memory store (tests)
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create app data dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize sessions: {e}"))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| format!("failed to write sessions: {e}"))?;
        restrict_permissions(&tmp);
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("failed to replace sessions file: {e}"))?;
        Ok(())
    }

    /// Register a new session and return `(sid, expires_at)`.
    pub fn create(&mut self, label: String, now: u64) -> (String, u64) {
        let mut raw = [0u8; 16];
        rand::thread_rng().fill(&mut raw);
        let sid = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw);
        let expires_at = now.saturating_add(SESSION_TTL_SECS);
        self.prune(now);
        self.sessions.push(SessionRecord {
            sid: sid.clone(),
            issued_at: now,
            last_seen: now,
            expires_at,
            label,
        });
        if let Err(e) = self.persist() {
            log::warn!("Failed to persist web sessions: {e}");
        }
        (sid, expires_at)
    }

    /// True when `sid` is still listed and unexpired.
    pub fn is_active(&self, sid: &str, now: u64) -> bool {
        self.sessions
            .iter()
            .any(|s| s.sid == sid && s.expires_at > now)
    }

    /// Slide the expiry when the session is past half-life. Returns the new
    /// expiry when it actually moved, so the caller re-issues the cookie. Keeps
    /// writes rare: an active session persists roughly once per half-TTL.
    pub fn refresh(&mut self, sid: &str, now: u64) -> Option<u64> {
        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.sid == sid && s.expires_at > now)?;
        let remaining = session.expires_at.saturating_sub(now);
        if remaining > SESSION_TTL_SECS / 2 {
            return None; // still fresh — no write, no new cookie
        }
        session.last_seen = now;
        session.expires_at = now.saturating_add(SESSION_TTL_SECS);
        let expires_at = session.expires_at;
        if let Err(e) = self.persist() {
            log::warn!("Failed to persist refreshed web session: {e}");
        }
        Some(expires_at)
    }

    /// Revoke one session (sign-out on this device, or kick a device from the UI).
    pub fn revoke(&mut self, sid: &str) {
        let before = self.sessions.len();
        self.sessions.retain(|s| s.sid != sid);
        if self.sessions.len() != before {
            if let Err(e) = self.persist() {
                log::warn!("Failed to persist session revocation: {e}");
            }
        }
    }

    /// Revoke every session ("sign out everywhere").
    pub fn revoke_all(&mut self) {
        self.sessions.clear();
        if let Err(e) = self.persist() {
            log::warn!("Failed to persist session revocation: {e}");
        }
    }

    /// Snapshot of live sessions, newest first — for an "active sessions" UI.
    pub fn active(&self, now: u64) -> Vec<SessionRecord> {
        let mut rows: Vec<SessionRecord> = self
            .sessions
            .iter()
            .filter(|s| s.expires_at > now)
            .cloned()
            .collect();
        rows.sort_by_key(|s| std::cmp::Reverse(s.last_seen));
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SessionStore {
        SessionStore::default() // empty path → persist() is a no-op
    }

    #[test]
    fn cookie_round_trip_carries_sid_and_expiry() {
        let key = [7u8; 32];
        let cookie = issue_session_cookie(&key, "abc", 5_000);
        let (sid, exp) = parse_session_cookie(&key, &cookie).unwrap();
        assert_eq!(sid, "abc");
        assert_eq!(exp, 5_000);
    }

    #[test]
    fn cookie_rejects_tamper_and_wrong_key() {
        let key = [7u8; 32];
        let other = [9u8; 32];
        let cookie = issue_session_cookie(&key, "abc", 5_000);
        assert!(parse_session_cookie(&other, &cookie).is_none());
        assert!(parse_session_cookie(&key, &format!("{cookie}x")).is_none());
        assert!(parse_session_cookie(&key, "garbage").is_none());
        assert!(parse_session_cookie(&key, "v2.abc.5000").is_none());
        // A forged sid cannot be swapped in: the signature covers it.
        let forged = cookie.replace("v2.abc.", "v2.evil.");
        assert!(parse_session_cookie(&key, &forged).is_none());
    }

    #[test]
    fn store_create_activate_and_revoke() {
        let mut s = store();
        let (sid, exp) = s.create("phone".into(), 1_000);
        assert_eq!(exp, 1_000 + SESSION_TTL_SECS);
        assert!(s.is_active(&sid, 1_000));
        // Unknown sid is never active — a validly-signed cookie is not enough.
        assert!(!s.is_active("other", 1_000));
        s.revoke(&sid);
        assert!(!s.is_active(&sid, 1_000));
    }

    #[test]
    fn store_revoking_one_leaves_the_others() {
        let mut s = store();
        let (a, _) = s.create("phone".into(), 1_000);
        let (b, _) = s.create("laptop".into(), 1_000);
        s.revoke(&a);
        assert!(!s.is_active(&a, 1_000));
        assert!(s.is_active(&b, 1_000));
        s.revoke_all();
        assert!(!s.is_active(&b, 1_000));
    }

    #[test]
    fn store_expires_and_prunes() {
        let mut s = store();
        let (sid, _) = s.create("phone".into(), 1_000);
        assert!(!s.is_active(&sid, 1_000 + SESSION_TTL_SECS));
        s.prune(1_000 + SESSION_TTL_SECS);
        assert!(s.active(1_000 + SESSION_TTL_SECS).is_empty());
    }

    #[test]
    fn refresh_only_slides_past_half_life() {
        let mut s = store();
        let (sid, exp) = s.create("phone".into(), 1_000);
        // Fresh session: no slide, no write.
        assert!(s.refresh(&sid, 1_000).is_none());
        // Just before half-life: still no slide.
        assert!(s.refresh(&sid, 1_000 + SESSION_TTL_SECS / 2 - 10).is_none());
        // Past half-life: slides to a full new TTL.
        let now = 1_000 + SESSION_TTL_SECS / 2 + 10;
        let new_exp = s.refresh(&sid, now).unwrap();
        assert_eq!(new_exp, now + SESSION_TTL_SECS);
        assert!(new_exp > exp);
        // A revoked session never refreshes.
        s.revoke(&sid);
        assert!(s.refresh(&sid, now).is_none());
    }

    #[test]
    fn store_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = SessionStore::load(dir.path());
        let (sid, _) = s.create("phone".into(), now_unix());
        // Reload from disk: the session survives a restart.
        let reloaded = SessionStore::load(dir.path());
        assert!(reloaded.is_active(&sid, now_unix()));
    }

    #[test]
    fn cookie_value_parses_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "foo=bar; jean_session=abc.def; baz=1".parse().unwrap(),
        );
        assert_eq!(
            session_cookie_from_headers(&headers).as_deref(),
            Some("abc.def")
        );
        assert!(session_cookie_from_headers(&HeaderMap::new()).is_none());
    }
}
