//! Brute-force protection for `POST /api/login`.
//!
//! The session-cookie login turned the access token into something a stranger
//! can submit repeatedly over HTTP. A 256-bit token is not guessable, but an
//! unmetered login endpoint on a publicly reachable hub is still an open door:
//! it costs an attacker nothing, leaves no trace, and any future weakening of
//! the token (shorter, user-chosen, reused) becomes immediately exploitable.
//!
//! Design constraints, in order of importance:
//!
//! 1. **The owner must never be locked out.** A hard global lockout is worse
//!    than no limit at all — a stranger could trigger it on purpose to deny the
//!    owner access to their own machine. Penalties are therefore per client,
//!    never global.
//! 2. **Rejection must not consume server resources.** Sleeping on a failed
//!    attempt (what this replaced) holds a connection and a task, so an
//!    attacker opening many sockets in parallel pays nothing and the delay
//!    buys nothing. A blocked client is refused immediately instead.
//! 3. **A few mistakes are free.** Pasting the wrong token happens; the first
//!    attempts carry no penalty so a fat-fingered owner is not punished.
//! 4. **Memory is bounded.** The table is capped and pruned, so an attacker
//!    rotating source addresses cannot grow it without limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Failed attempts allowed before penalties start (room for a typo or a stale
/// bookmark, not room for guessing).
const FREE_ATTEMPTS: u32 = 3;
/// Penalty applied at the first offending attempt, doubling from there.
const BASE_PENALTY: Duration = Duration::from_secs(1);
/// Ceiling for a single penalty window.
const MAX_PENALTY: Duration = Duration::from_secs(300);
/// A client that behaves for this long is forgiven and starts fresh.
const FORGET_AFTER: Duration = Duration::from_secs(900);
/// Upper bound on tracked clients, so rotating addresses cannot exhaust memory.
const MAX_TRACKED: usize = 4096;

#[derive(Debug, Clone)]
struct Attempts {
    failures: u32,
    /// Requests from this client are refused until this instant.
    blocked_until: Option<Instant>,
    last_seen: Instant,
}

/// Per-client failed-login accounting.
#[derive(Debug, Default)]
pub struct LoginGuard {
    clients: Mutex<HashMap<IpAddr, Attempts>>,
}

impl LoginGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remaining penalty for this client, or `None` when it may attempt a login.
    ///
    /// Callers must treat `Some` as "reject without checking the token": doing
    /// the comparison anyway would make the penalty cosmetic.
    pub fn blocked_for(&self, client: IpAddr) -> Option<Duration> {
        self.blocked_for_at(client, Instant::now())
    }

    fn blocked_for_at(&self, client: IpAddr, now: Instant) -> Option<Duration> {
        let clients = self.clients.lock().ok()?;
        let entry = clients.get(&client)?;
        let until = entry.blocked_until?;
        (until > now).then(|| until.saturating_duration_since(now))
    }

    /// Record a failed attempt and return the penalty now in force, if any.
    pub fn record_failure(&self, client: IpAddr) -> Option<Duration> {
        self.record_failure_at(client, Instant::now())
    }

    fn record_failure_at(&self, client: IpAddr, now: Instant) -> Option<Duration> {
        let Ok(mut clients) = self.clients.lock() else {
            return None;
        };
        prune(&mut clients, now);

        let entry = clients.entry(client).or_insert(Attempts {
            failures: 0,
            blocked_until: None,
            last_seen: now,
        });
        entry.failures = entry.failures.saturating_add(1);
        entry.last_seen = now;

        let over = entry.failures.saturating_sub(FREE_ATTEMPTS);
        if over == 0 {
            entry.blocked_until = None;
            return None;
        }

        // 1s, 2s, 4s, … capped. Saturating shift keeps a long-running attacker
        // from wrapping the exponent back to a short delay.
        let penalty = BASE_PENALTY
            .saturating_mul(1u32.checked_shl(over - 1).unwrap_or(u32::MAX))
            .min(MAX_PENALTY);
        entry.blocked_until = Some(now + penalty);
        Some(penalty)
    }

    /// Forget a client's history after it proves it holds the token.
    pub fn record_success(&self, client: IpAddr) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.remove(&client);
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.clients.lock().map(|c| c.len()).unwrap_or(0)
    }
}

fn prune(clients: &mut HashMap<IpAddr, Attempts>, now: Instant) {
    clients.retain(|_, entry| {
        let still_blocked = entry.blocked_until.is_some_and(|until| until > now);
        still_blocked || now.saturating_duration_since(entry.last_seen) < FORGET_AFTER
    });

    if clients.len() < MAX_TRACKED {
        return;
    }
    // Over the cap: drop the least recently seen entries. Clients under an
    // active penalty are kept first — they are the ones worth remembering.
    let mut by_age: Vec<(IpAddr, Instant, bool)> = clients
        .iter()
        .map(|(ip, entry)| {
            (
                *ip,
                entry.last_seen,
                entry.blocked_until.is_some_and(|until| until > now),
            )
        })
        .collect();
    by_age.sort_by_key(|(_, last_seen, blocked)| (*blocked, *last_seen));
    for (ip, _, _) in by_age.into_iter().take(clients.len() - MAX_TRACKED / 2) {
        clients.remove(&ip);
    }
}

/// Headers a fronting proxy may use to carry the original client address,
/// most trustworthy first.
///
/// `CF-Connecting-IP` comes first because Cloudflare sets it to a single
/// address it determined itself, whereas `X-Forwarded-For` is a list that
/// Cloudflare appends to — if the client sent one, its entries are still in
/// there.
const FORWARDED_CLIENT_HEADERS: [&str; 2] = ["cf-connecting-ip", "x-forwarded-for"];

/// Resolve the client address to bucket a login attempt under.
///
/// Forwarded headers are honoured **only** when the deployment declares a proxy
/// in front. Trusting them unconditionally would hand every attacker a fresh
/// bucket per request — they choose the header — and turn this guard into
/// decoration. Without a declared proxy the socket address is the only thing
/// the attacker cannot forge.
///
/// `lookup` receives a lowercase header name and returns its value.
pub fn client_ip<'a>(
    peer: Option<IpAddr>,
    lookup: impl Fn(&str) -> Option<&'a str>,
    trust_proxy: bool,
) -> Option<IpAddr> {
    if trust_proxy {
        for header in FORWARDED_CLIENT_HEADERS {
            let Some(value) = lookup(header) else { continue };
            // Left-most entry is the original client; the rest are proxies.
            let Some(first) = value.split(',').next() else {
                continue;
            };
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn first_mistakes_carry_no_penalty() {
        let guard = LoginGuard::new();
        let now = Instant::now();

        for _ in 0..FREE_ATTEMPTS {
            assert_eq!(guard.record_failure_at(ip(1), now), None);
        }
        assert_eq!(guard.blocked_for_at(ip(1), now), None);
    }

    #[test]
    fn penalty_grows_with_each_further_failure() {
        let guard = LoginGuard::new();
        let now = Instant::now();
        for _ in 0..FREE_ATTEMPTS {
            guard.record_failure_at(ip(1), now);
        }

        let first = guard.record_failure_at(ip(1), now).expect("penalty");
        let second = guard.record_failure_at(ip(1), now).expect("penalty");
        let third = guard.record_failure_at(ip(1), now).expect("penalty");

        assert_eq!(first, BASE_PENALTY);
        assert!(second > first, "{second:?} should exceed {first:?}");
        assert!(third > second, "{third:?} should exceed {second:?}");
    }

    #[test]
    fn penalty_is_capped() {
        let guard = LoginGuard::new();
        let now = Instant::now();
        for _ in 0..64 {
            guard.record_failure_at(ip(1), now);
        }
        assert_eq!(guard.blocked_for_at(ip(1), now), Some(MAX_PENALTY));
    }

    #[test]
    fn one_attacker_never_blocks_another_client() {
        // The whole point of bucketing per client: the owner must keep getting
        // in while a stranger is being throttled.
        let guard = LoginGuard::new();
        let now = Instant::now();
        for _ in 0..10 {
            guard.record_failure_at(ip(1), now);
        }

        assert!(guard.blocked_for_at(ip(1), now).is_some());
        assert_eq!(guard.blocked_for_at(ip(2), now), None);
    }

    #[test]
    fn block_expires_on_its_own() {
        let guard = LoginGuard::new();
        let now = Instant::now();
        for _ in 0..=FREE_ATTEMPTS {
            guard.record_failure_at(ip(1), now);
        }
        assert!(guard.blocked_for_at(ip(1), now).is_some());

        let later = now + BASE_PENALTY + Duration::from_millis(1);
        assert_eq!(guard.blocked_for_at(ip(1), later), None);
    }

    #[test]
    fn a_successful_login_clears_the_history() {
        let guard = LoginGuard::new();
        let now = Instant::now();
        for _ in 0..10 {
            guard.record_failure_at(ip(1), now);
        }

        guard.record_success(ip(1));

        assert_eq!(guard.blocked_for(ip(1)), None);
        assert_eq!(guard.tracked(), 0);
    }

    #[test]
    fn stale_clients_are_forgotten() {
        let guard = LoginGuard::new();
        let now = Instant::now();
        guard.record_failure_at(ip(1), now);
        assert_eq!(guard.tracked(), 1);

        // Any later write prunes clients that have been quiet long enough.
        guard.record_failure_at(ip(2), now + FORGET_AFTER + Duration::from_secs(1));

        assert_eq!(guard.tracked(), 1);
        assert_eq!(guard.blocked_for(ip(1)), None);
    }

    #[test]
    fn tracking_table_stays_bounded() {
        let guard = LoginGuard::new();
        let now = Instant::now();
        for i in 0..(MAX_TRACKED + 500) {
            let addr = IpAddr::V4(Ipv4Addr::from((i as u32).to_be_bytes()));
            guard.record_failure_at(addr, now);
        }
        assert!(
            guard.tracked() <= MAX_TRACKED,
            "tracked {} exceeds cap",
            guard.tracked()
        );
    }

    /// Header lookup helper mirroring what the handler passes in.
    fn headers(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<&'static str> {
        let owned: Vec<(&'static str, &'static str)> = pairs.to_vec();
        move |name: &str| {
            owned
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| *value)
        }
    }

    #[test]
    fn forwarded_headers_are_ignored_without_a_declared_proxy() {
        // Otherwise an attacker picks a new bucket per request by setting the
        // header themselves, and the guard stops guarding anything.
        let peer = ip(9);
        let resolved = client_ip(
            Some(peer),
            headers(&[
                ("cf-connecting-ip", "198.51.100.7"),
                ("x-forwarded-for", "198.51.100.8"),
            ]),
            false,
        );
        assert_eq!(resolved, Some(peer));
    }

    #[test]
    fn cloudflare_header_wins_over_forwarded_for() {
        // Cloudflare appends to X-Forwarded-For, so a client-supplied entry can
        // still be sitting in it. CF-Connecting-IP is the address Cloudflare
        // determined itself.
        let resolved = client_ip(
            Some(ip(9)),
            headers(&[
                ("x-forwarded-for", "10.0.0.99, 198.51.100.7"),
                ("cf-connecting-ip", "198.51.100.7"),
            ]),
            true,
        );
        assert_eq!(resolved, Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))));
    }

    #[test]
    fn forwarded_for_is_used_when_there_is_no_cloudflare_header() {
        let resolved = client_ip(
            Some(ip(9)),
            headers(&[("x-forwarded-for", "198.51.100.7, 10.0.0.1")]),
            true,
        );
        assert_eq!(resolved, Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))));
    }

    #[test]
    fn a_malformed_forwarded_header_falls_back_to_the_next_source() {
        let peer = ip(9);
        // Garbage in the Cloudflare header must not shadow a usable XFF.
        let resolved = client_ip(
            Some(peer),
            headers(&[
                ("cf-connecting-ip", "not-an-ip"),
                ("x-forwarded-for", "198.51.100.7"),
            ]),
            true,
        );
        assert_eq!(resolved, Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))));

        // Nothing usable anywhere: fall back to the socket.
        assert_eq!(
            client_ip(Some(peer), headers(&[("x-forwarded-for", "")]), true),
            Some(peer)
        );
        assert_eq!(client_ip(Some(peer), headers(&[]), true), Some(peer));
    }
}
