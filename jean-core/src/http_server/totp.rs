//! Time-based one-time passwords (RFC 6238) for the web/server login.
//!
//! The hub token alone is a bearer credential: whoever reads it once owns the
//! server for good, and `/ws` hands out terminals. A second factor makes a
//! leaked token useless on its own — the phone that holds the TOTP secret has
//! to agree, every time a new session is minted.
//!
//! Deliberately hand-rolled rather than pulled from a crate: the algorithm is
//! forty lines, the RFC ships test vectors we assert against below, and the
//! alternative is a dependency tree in a security-critical path.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::path::{Path, PathBuf};

/// Filename of the persisted second-factor secret, next to `web-sessions.json`.
/// Deleting it disables 2FA — that is exactly what `--disable-2fa` does.
const TWO_FACTOR_FILE: &str = "web-2fa.json";

/// Seconds per TOTP step. 30 is the value every authenticator app assumes.
const STEP_SECS: u64 = 30;

/// How many steps either side of "now" are accepted, to absorb clock drift
/// between the server and the phone. One step each way = a 90s window, the
/// usual compromise: wide enough that a correct code is never rejected,
/// narrow enough that a stolen code expires almost immediately.
const SKEW_STEPS: u64 = 1;

const DIGITS: u32 = 6;

// ── Base32 (RFC 4648) ────────────────────────────────────────────────────────
//
// Authenticator apps exchange secrets in base32, not base64 or hex.

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode without padding: `otpauth://` URLs carry the secret in a query
/// parameter, where `=` would have to be percent-encoded, and every app
/// accepts the unpadded form.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Decode, tolerating what a human retypes: lowercase, padding, and the spaces
/// apps insert every four characters when they display a secret.
pub fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in input.chars() {
        if c == '=' || c.is_whitespace() || c == '-' {
            continue;
        }
        let value = ALPHABET
            .iter()
            .position(|&a| a == c.to_ascii_uppercase() as u8)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

// ── The algorithm ────────────────────────────────────────────────────────────

/// HOTP (RFC 4226): HMAC-SHA1 over the counter, then dynamic truncation.
fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac =
        <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    // The low nibble of the last byte picks where to read the 4-byte window.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    binary % 10u32.pow(DIGITS)
}

fn format_code(value: u32) -> String {
    format!("{value:0width$}", width = DIGITS as usize)
}

/// The code a correct authenticator shows for `unix_secs`. Exposed for tests
/// and for the enrollment self-check, never to be sent to a client.
pub fn code_at(secret: &[u8], unix_secs: u64) -> String {
    format_code(hotp(secret, unix_secs / STEP_SECS))
}

/// Constant-time comparison of two codes. `==` on strings short-circuits on the
/// first differing byte, which leaks how much of the code was right.
fn codes_match(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Verify `code` against `secret` around `now`, returning the step it matched.
///
/// The caller needs the step, not just a bool: remembering the last accepted
/// step is what stops a code being replayed inside its own validity window.
pub fn verify_at(secret: &[u8], code: &str, now: u64) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize {
        return None;
    }
    let current = now / STEP_SECS;
    // Oldest step first, so a code valid in several steps (impossible in
    // practice, but the loop shouldn't depend on that) pins the earliest one.
    let first = current.saturating_sub(SKEW_STEPS);
    (first..=current.saturating_add(SKEW_STEPS))
        .find(|&step| codes_match(&format_code(hotp(secret, step)), &code))
}

/// The URI an authenticator app scans. `issuer` shows as the account's heading,
/// `account` distinguishes several Jean servers in the same app.
pub fn otpauth_url(secret_base32: &str, issuer: &str, account: &str) -> String {
    let encode = |s: &str| {
        s.chars()
            .map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
                other => other
                    .to_string()
                    .as_bytes()
                    .iter()
                    .map(|b| format!("%{b:02X}"))
                    .collect(),
            })
            .collect::<String>()
    };
    let issuer_enc = encode(issuer);
    let account_enc = encode(account);
    format!(
        "otpauth://totp/{issuer_enc}:{account_enc}?secret={secret_base32}&issuer={issuer_enc}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}"
    )
}

// ── Persisted enrollment state ───────────────────────────────────────────────

/// Result of checking a submitted code, so callers can tell "wrong code" from
/// "right code, already used" — the second deserves a different log line.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    Ok,
    Invalid,
    Replayed,
}

/// The server's second-factor state: at most one active secret, plus a pending
/// one while the user is enrolling.
///
/// Enrollment is two-phase on purpose. Activating on generation would lock the
/// user out whenever the QR code was mistyped or the phone's clock was wrong;
/// requiring one correct code first proves the app is really in sync before the
/// secret starts guarding anything.
#[derive(Default, Serialize, Deserialize)]
pub struct TwoFactorStore {
    /// Active secret, base32. `Some` means 2FA is enforced.
    #[serde(default)]
    secret: Option<String>,
    /// Secret awaiting its first correct code. Never enforced.
    #[serde(default)]
    pending: Option<String>,
    #[serde(default)]
    confirmed_at: Option<u64>,
    /// Last TOTP step accepted, to reject replays inside the skew window.
    #[serde(default)]
    last_step: Option<u64>,
    #[serde(skip)]
    path: PathBuf,
}

impl TwoFactorStore {
    /// Load from `<app_data_dir>/web-2fa.json`. A missing or corrupt file means
    /// "no second factor": fail *open* here, unlike the session store.
    ///
    /// That asymmetry is deliberate. A corrupt session file logs everyone out,
    /// which is recoverable — they log in again. A corrupt 2FA file that failed
    /// closed would demand a code nobody can produce, locking the owner out of
    /// their own server with no way back in through the UI.
    pub fn load(app_data_dir: &Path) -> Self {
        let path = app_data_dir.join(TWO_FACTOR_FILE);
        let mut store = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<TwoFactorStore>(&raw).ok())
            .unwrap_or_default();
        store.path = path;
        store
    }

    /// True once a secret has been confirmed — the flag that turns the raw
    /// token from "sufficient" into "first factor only".
    pub fn is_enabled(&self) -> bool {
        self.secret.is_some()
    }

    fn persist(&self) -> Result<(), String> {
        if self.path.as_os_str().is_empty() {
            return Ok(()); // in-memory store (tests)
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create app data dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize 2FA state: {e}"))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| format!("failed to write 2FA state: {e}"))?;
        restrict_permissions(&tmp);
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("failed to replace 2FA state file: {e}"))?;
        Ok(())
    }

    /// Start enrollment: mint a fresh 20-byte secret (the RFC 4226 recommended
    /// length for SHA-1) and hold it as pending. Restarting enrollment
    /// overwrites any half-finished attempt, so an abandoned QR code is dead.
    pub fn begin_enrollment(&mut self) -> String {
        use rand::Rng;
        let mut raw = [0u8; 20];
        rand::thread_rng().fill(&mut raw);
        let secret = base32_encode(&raw);
        self.pending = Some(secret.clone());
        if let Err(e) = self.persist() {
            log::warn!("Failed to persist pending 2FA secret: {e}");
        }
        secret
    }

    /// Confirm the pending secret with a code from the app. Only on success
    /// does the secret become active.
    pub fn confirm_at(&mut self, code: &str, now: u64) -> bool {
        let Some(pending) = self.pending.clone() else {
            return false;
        };
        let Some(bytes) = base32_decode(&pending) else {
            return false;
        };
        let Some(step) = verify_at(&bytes, code, now) else {
            return false;
        };
        self.secret = Some(pending);
        self.pending = None;
        self.confirmed_at = Some(now);
        self.last_step = Some(step);
        if let Err(e) = self.persist() {
            log::warn!("Failed to persist confirmed 2FA secret: {e}");
        }
        true
    }

    /// Check a login code against the active secret, refusing a step that was
    /// already spent.
    pub fn verify_login_at(&mut self, code: &str, now: u64) -> VerifyOutcome {
        let Some(secret) = self.secret.as_deref() else {
            return VerifyOutcome::Ok; // not enrolled: nothing to check
        };
        let Some(bytes) = base32_decode(secret) else {
            return VerifyOutcome::Invalid;
        };
        let Some(step) = verify_at(&bytes, code, now) else {
            return VerifyOutcome::Invalid;
        };
        if self.last_step.is_some_and(|last| step <= last) {
            return VerifyOutcome::Replayed;
        }
        self.last_step = Some(step);
        if let Err(e) = self.persist() {
            log::warn!("Failed to persist 2FA replay marker: {e}");
        }
        VerifyOutcome::Ok
    }

    /// Turn 2FA off. Callers reaching this from the network must verify a code
    /// first; the local CLI escape hatch does not, because standing at the
    /// machine (or holding its SSH key) already outranks the phone.
    pub fn disable(&mut self) {
        self.secret = None;
        self.pending = None;
        self.confirmed_at = None;
        self.last_step = None;
        if let Err(e) = self.persist() {
            log::warn!("Failed to persist 2FA removal: {e}");
        }
    }

    /// Verify a code against the active secret without consuming a step. Used
    /// by `disable` over the network, where a replay marker would be pointless
    /// (the secret is about to be destroyed either way).
    pub fn matches_active_at(&self, code: &str, now: u64) -> bool {
        self.secret
            .as_deref()
            .and_then(base32_decode)
            .is_some_and(|bytes| verify_at(&bytes, code, now).is_some())
    }
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

/// Remove the persisted second factor without a running server — the recovery
/// path for a lost phone. Returns whether anything was there to remove.
pub fn disable_from_disk(app_data_dir: &Path) -> Result<bool, String> {
    let path = app_data_dir.join(TWO_FACTOR_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("failed to remove {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 / RFC 6238 use this ASCII string as their shared secret.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn base32_matches_rfc4648_vectors() {
        // Unpadded, which is what `otpauth://` URLs carry.
        for (raw, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(raw.as_bytes()), encoded, "encoding {raw:?}");
            assert_eq!(
                base32_decode(encoded).as_deref(),
                Some(raw.as_bytes()),
                "decoding {encoded:?}"
            );
        }
    }

    #[test]
    fn base32_decode_forgives_how_apps_display_secrets() {
        // Padding, lowercase, and the four-character grouping people retype.
        let expected = Some(b"foobar".to_vec());
        assert_eq!(base32_decode("MZXW6YTBOI="), expected);
        assert_eq!(base32_decode("mzxw6ytboi"), expected);
        assert_eq!(base32_decode("MZXW 6YTB OI"), expected);
        assert_eq!(base32_decode("MZXW-6YTB-OI"), expected);
        assert_eq!(base32_decode("not base32!"), None);
    }

    #[test]
    fn hotp_matches_rfc4226_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(&format_code(hotp(RFC_SECRET, counter as u64)), code);
        }
    }

    #[test]
    fn totp_matches_rfc6238_vectors() {
        // The RFC tabulates 8 digits; Jean uses 6, i.e. the same value mod 1e6.
        for (time, code) in [
            (59u64, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ] {
            assert_eq!(code_at(RFC_SECRET, time), code, "at t={time}");
        }
    }

    #[test]
    fn verification_absorbs_clock_drift_but_not_more() {
        let now = 1_700_000_000;
        // A phone one step behind or ahead still gets in.
        for offset in [-(STEP_SECS as i64), 0, STEP_SECS as i64] {
            let code = code_at(RFC_SECRET, (now as i64 + offset) as u64);
            assert!(
                verify_at(RFC_SECRET, &code, now).is_some(),
                "offset {offset}s should be accepted"
            );
        }
        // Two steps out is a stale code, not drift.
        let stale = code_at(RFC_SECRET, now - 2 * STEP_SECS);
        assert!(verify_at(RFC_SECRET, &stale, now).is_none());
    }

    #[test]
    fn malformed_codes_are_rejected_without_panicking() {
        let now = 1_700_000_000;
        for code in ["", "12345", "1234567", "abcdef", "  "] {
            assert!(verify_at(RFC_SECRET, code, now).is_none(), "code {code:?}");
        }
    }

    fn store() -> TwoFactorStore {
        TwoFactorStore::default()
    }

    #[test]
    fn enrollment_only_activates_after_a_correct_code() {
        let now = 1_700_000_000;
        let mut store = store();
        let secret = store.begin_enrollment();

        assert!(
            !store.is_enabled(),
            "pending enrollment must not enforce yet"
        );
        assert!(
            !store.confirm_at("000000", now),
            "wrong code cannot confirm"
        );
        assert!(!store.is_enabled());

        let bytes = base32_decode(&secret).expect("generated secret is base32");
        assert!(store.confirm_at(&code_at(&bytes, now), now));
        assert!(store.is_enabled());
    }

    #[test]
    fn restarting_enrollment_kills_the_previous_qr_code() {
        let now = 1_700_000_000;
        let mut store = store();
        let abandoned = base32_decode(&store.begin_enrollment()).unwrap();
        store.begin_enrollment();

        assert!(
            !store.confirm_at(&code_at(&abandoned, now), now),
            "a code from the abandoned secret must not confirm the new one"
        );
    }

    #[test]
    fn a_code_cannot_be_replayed_inside_its_own_window() {
        let now = 1_700_000_000;
        let mut store = store();
        let secret = base32_decode(&store.begin_enrollment()).unwrap();
        // Confirm with an older code so the login code below is a later step.
        assert!(store.confirm_at(&code_at(&secret, now - STEP_SECS), now - STEP_SECS));

        let code = code_at(&secret, now);
        assert_eq!(store.verify_login_at(&code, now), VerifyOutcome::Ok);
        assert_eq!(
            store.verify_login_at(&code, now),
            VerifyOutcome::Replayed,
            "the same code must not open a second session"
        );
    }

    #[test]
    fn verification_passes_through_when_not_enrolled() {
        let mut store = store();
        assert_eq!(
            store.verify_login_at("", 1_700_000_000),
            VerifyOutcome::Ok,
            "a server without 2FA must not start demanding codes"
        );
    }

    #[test]
    fn disabling_clears_everything_including_the_replay_marker() {
        let now = 1_700_000_000;
        let mut store = store();
        let secret = base32_decode(&store.begin_enrollment()).unwrap();
        store.confirm_at(&code_at(&secret, now), now);

        store.disable();

        assert!(!store.is_enabled());
        assert!(store.pending.is_none());
        assert!(store.last_step.is_none());
    }

    #[test]
    fn otpauth_url_escapes_labels_and_carries_the_parameters_apps_read() {
        let url = otpauth_url("MZXW6YTBOI", "Jean", "jean@ct 115");
        assert!(
            url.starts_with("otpauth://totp/Jean:jean%40ct%20115?"),
            "{url}"
        );
        assert!(url.contains("secret=MZXW6YTBOI"));
        assert!(url.contains("issuer=Jean"));
        assert!(url.contains("digits=6"));
        assert!(url.contains("period=30"));
    }

    #[test]
    fn corrupt_state_file_disables_rather_than_locks_out() {
        let dir = std::env::temp_dir().join(format!("jean-2fa-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(TWO_FACTOR_FILE), "{ not json").unwrap();

        let store = TwoFactorStore::load(&dir);

        assert!(
            !store.is_enabled(),
            "an unreadable 2FA file must not demand a code nobody can produce"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cli_escape_hatch_removes_the_secret_from_disk() {
        let dir = std::env::temp_dir().join(format!("jean-2fa-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = TwoFactorStore::load(&dir);
        let secret = base32_decode(&store.begin_enrollment()).unwrap();
        store.confirm_at(&code_at(&secret, 1_700_000_000), 1_700_000_000);

        assert!(disable_from_disk(&dir).unwrap(), "file was there");
        assert!(!TwoFactorStore::load(&dir).is_enabled());
        assert!(!disable_from_disk(&dir).unwrap(), "second call is a no-op");
        std::fs::remove_dir_all(&dir).ok();
    }
}
