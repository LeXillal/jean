//! Remote-connection proxy.
//!
//! In web-access mode a browser used to connect directly to a remote Jean
//! server with that remote's URL *and* token. This module turns the hub (the
//! server the browser is talking to) into a reverse proxy: the browser calls
//! `<hub>/remote/<id>/api/...` (HTTP) and `<hub>/remote/<id>/ws` (WebSocket)
//! authenticated with only the *hub* token, and the hub forwards each request
//! to the selected remote, injecting the remote's own token. Remote tokens are
//! never exposed to the browser.
//!
//! Security notes:
//! - The hub token is required (when `token_required`) and is stripped from the
//!   query before forwarding, so it never leaks upstream.
//! - The remote token is injected server-side only, as an `Authorization:
//!   Bearer` header — never in the URL/query — so it stays out of the remote's
//!   access logs, `Referer` headers, and any intermediary proxy logs. This
//!   matters when the hub→remote hop may cross an untrusted network; that hop
//!   must still use `https`/`wss` for on-the-wire confidentiality.
//! - An anti-loop guard refuses to target the hub itself.
//! - No URL containing a query string (`?token=`) is ever logged.

use axum::{
    body::{Body, Bytes},
    extract::{
        ws::{CloseFrame as AxumCloseFrame, Message as AxumMessage, WebSocket, WebSocketUpgrade},
        OriginalUri, Path as AxumPath, Query, State,
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    handshake::client::Request as TsRequest,
    http::{header::AUTHORIZATION as TS_AUTHORIZATION, HeaderValue as TsHeaderValue},
    protocol::frame::coding::CloseCode as TsCloseCode,
    protocol::CloseFrame as TsCloseFrame,
    Message as TsMessage, Utf8Bytes as TsUtf8Bytes,
};

use super::server::{
    load_remote_connections, remote_connections_path, request_is_authorized, AppState,
    RemoteConnectionEntry, WsAuth,
};

/// Upstream request timeout. Kept short so a dead remote fails the browser
/// request quickly instead of hanging the connection.
const UPSTREAM_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

// ── Pure helpers (unit-tested) ───────────────────────────────────────────────

/// Find a remote connection by id.
pub(super) fn resolve_remote<'a>(
    entries: &'a [RemoteConnectionEntry],
    id: &str,
) -> Option<&'a RemoteConnectionEntry> {
    entries.iter().find(|entry| entry.id == id)
}

/// Extract the `token` value from a raw query string, if present.
fn token_from_raw_query(query: Option<&str>) -> Option<String> {
    let query = query?;
    let probe = reqwest::Url::parse(&format!("http://x/?{query}")).ok()?;
    probe
        .query_pairs()
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value.into_owned())
}

/// Build the upstream HTTP URL: `{remote_url}/api/{sub_path}` with the incoming
/// query merged in, minus any client-provided `token`. The remote's token is
/// NOT placed in the URL — it travels in an `Authorization: Bearer` header so it
/// never lands in the remote's access logs. See `remote_http_proxy_handler`.
pub(super) fn build_upstream_http_url(
    remote_url: &str,
    sub_path: &str,
    incoming_query: Option<&str>,
) -> Result<String, String> {
    let base = remote_url.trim_end_matches('/');
    let mut url = reqwest::Url::parse(&format!("{base}/api/{sub_path}"))
        .map_err(|e| format!("invalid upstream url: {e}"))?;

    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(query) = incoming_query.filter(|q| !q.is_empty()) {
        let probe = reqwest::Url::parse(&format!("http://x/?{query}"))
            .map_err(|e| format!("invalid query: {e}"))?;
        for (key, value) in probe.query_pairs() {
            if key == "token" {
                continue; // never forward the hub token upstream
            }
            pairs.push((key.into_owned(), value.into_owned()));
        }
    }
    if pairs.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(&pairs);
    }

    Ok(url.to_string())
}

/// Build the upstream WebSocket URL: `{remote_url}/ws` with the scheme swapped
/// http→ws / https→wss. The remote's token is NOT placed in the URL — it travels
/// in an `Authorization: Bearer` header on the handshake request. See
/// `remote_ws_proxy_handler`.
pub(super) fn build_upstream_ws_url(remote_url: &str) -> Result<String, String> {
    let base = remote_url.trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if base.starts_with("wss://") || base.starts_with("ws://") {
        base.to_string()
    } else {
        return Err("remote url must start with http(s):// or ws(s)://".to_string());
    };

    let url = reqwest::Url::parse(&format!("{ws_base}/ws"))
        .map_err(|e| format!("invalid upstream ws url: {e}"))?;
    Ok(url.to_string())
}

/// Build an `Authorization: Bearer <token>` header value, rejecting tokens that
/// contain bytes illegal in a header value.
fn bearer_header(token: &str) -> Result<HeaderValue, String> {
    HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| "remote token is not a valid header value".to_string())
}

/// Hop-by-hop headers that must not be forwarded (RFC 7230 §6.1) plus `host`,
/// which reqwest sets from the target URL.
pub(super) fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

fn is_loopback_host(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1" | "[::1]" | "0.0.0.0" | "::" | "[::]"
    )
}

/// Anti-loop guard: true when `remote_url` points back at the hub itself.
/// Conservative — only reports self when the port matches and the host is
/// either an exact match or both sides are loopback aliases.
pub(super) fn remote_targets_self(remote_url: &str, own_host: &str, own_port: u16) -> bool {
    let Ok(url) = reqwest::Url::parse(remote_url) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let Some(port) = url.port_or_known_default() else {
        return false;
    };
    if port != own_port {
        return false;
    }
    if host.eq_ignore_ascii_case(own_host) {
        return true;
    }
    is_loopback_host(host) && is_loopback_host(own_host)
}

/// True when a plaintext (`http`/`ws`) hop to `host` stays on a trusted local
/// network — loopback, an RFC1918 private range, link-local, or the CGNAT/tailnet
/// range (`100.64.0.0/10`). Public IPs and any non-IP hostname are NOT trusted
/// for plaintext (we can't be sure they stay off the open internet), so they
/// require TLS. IP literals only: a hostname could resolve anywhere.
fn plaintext_host_is_trusted(host: &str) -> bool {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip_is_private_or_loopback(&ip);
    }
    // "localhost" is the one name we can trust without DNS.
    host.eq_ignore_ascii_case("localhost")
}

fn ip_is_private_or_loopback(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            let is_cgnat = o[0] == 100 && (64..=127).contains(&o[1]); // 100.64/10
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || is_cgnat
        }
        std::net::IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            let is_unique_local = (first & 0xfe00) == 0xfc00; // fc00::/7
            let is_link_local = (first & 0xffc0) == 0xfe80; // fe80::/10
            v6.is_loopback() || is_unique_local || is_link_local
        }
    }
}

/// Reject a remote whose URL sends the injected bearer token over plaintext
/// (`http`/`ws`) to a non-private host — that would leak the token on the wire
/// the moment the hop crosses an untrusted network. `https`/`wss` and plaintext
/// on a private/loopback network are allowed. Unparseable URLs pass here and
/// fail later in the URL builder.
fn reject_untrusted_plaintext(remote_url: &str) -> Result<(), String> {
    let Ok(url) = reqwest::Url::parse(remote_url) else {
        return Ok(());
    };
    let scheme = url.scheme();
    if scheme != "http" && scheme != "ws" {
        return Ok(());
    }
    let host = url.host_str().unwrap_or_default();
    if plaintext_host_is_trusted(host) {
        Ok(())
    } else {
        Err(format!(
            "remote host '{host}' uses {scheme}:// on a non-private address; use https/wss (plaintext is only allowed on a loopback or private network)"
        ))
    }
}

// ── HTTP proxy handler ───────────────────────────────────────────────────────

pub(super) async fn remote_http_proxy_handler(
    AxumPath((id, sub_path)): AxumPath<(String, String)>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: Bytes,
) -> Response {
    // (a) Hub token auth.
    if state.token_required {
        let query_token = token_from_raw_query(uri.query());
        if !request_is_authorized(query_token.as_deref(), &headers, &state) {
            return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
        }
    }

    // (b) Resolve the remote.
    let path = match remote_connections_path(&state.app) {
        Ok(path) => path,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let entries = load_remote_connections(&path);
    let Some(entry) = resolve_remote(&entries, &id) else {
        return (StatusCode::NOT_FOUND, "Unknown remote").into_response();
    };

    // (c) Anti-loop.
    if remote_targets_self(&entry.url, &state.own_host, state.own_port) {
        return (StatusCode::BAD_REQUEST, "Remote targets this hub").into_response();
    }

    // (c') Refuse plaintext to a public host — the bearer token would leak on
    // the wire. https/wss and plaintext on a private network are fine.
    if let Err(message) = reject_untrusted_plaintext(&entry.url) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }

    // (d) Build the upstream URL. The remote token is NOT in the URL — it goes
    // in a bearer header below, so it never reaches the remote's access logs.
    let upstream_url = match build_upstream_http_url(&entry.url, &sub_path, uri.query()) {
        Ok(url) => url,
        Err(_) => return (StatusCode::BAD_GATEWAY, "invalid remote url").into_response(),
    };
    let authorization = match bearer_header(&entry.token) {
        Ok(value) => value,
        Err(_) => return (StatusCode::BAD_GATEWAY, "invalid remote token").into_response(),
    };

    // (e) Forward. Drop hop-by-hop + host, force identity encoding so the hub's
    // own CompressionLayer is the only thing that (re)compresses.
    let mut forward_headers = HeaderMap::new();
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        forward_headers.insert(name.clone(), value.clone());
    }
    forward_headers.insert(
        reqwest::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    // Inject the remote token last so it overrides any Authorization header the
    // client may have sent (which would carry the hub token, never forwarded).
    forward_headers.insert(reqwest::header::AUTHORIZATION, authorization);

    let upstream = state
        .http_client
        .request(method, upstream_url.as_str())
        .headers(forward_headers)
        .body(body)
        .timeout(UPSTREAM_HTTP_TIMEOUT)
        .send()
        .await;

    let upstream = match upstream {
        Ok(response) => response,
        Err(_) => return (StatusCode::BAD_GATEWAY, "remote unreachable").into_response(),
    };

    // (f) Re-emit: upstream status + filtered headers, streamed body.
    let mut builder = Response::builder().status(upstream.status());
    for (name, value) in upstream.headers().iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop(&lower) || lower == "content-length" || lower == "content-encoding" {
            continue;
        }
        builder = builder.header(name, value);
    }

    match builder.body(Body::from_stream(upstream.bytes_stream())) {
        Ok(response) => response,
        Err(_) => (StatusCode::BAD_GATEWAY, "proxy response error").into_response(),
    }
}

// ── WebSocket proxy handler ──────────────────────────────────────────────────

pub(super) async fn remote_ws_proxy_handler(
    ws: WebSocketUpgrade,
    AxumPath(id): AxumPath<String>,
    Query(auth): Query<WsAuth>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    // Hub token auth, before the upgrade.
    if state.token_required
        && !request_is_authorized(auth.token.as_deref(), &headers, &state)
    {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    let path = match remote_connections_path(&state.app) {
        Ok(path) => path,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let entries = load_remote_connections(&path);
    let Some(entry) = resolve_remote(&entries, &id) else {
        return (StatusCode::NOT_FOUND, "Unknown remote").into_response();
    };

    if remote_targets_self(&entry.url, &state.own_host, state.own_port) {
        return (StatusCode::BAD_REQUEST, "Remote targets this hub").into_response();
    }

    // Refuse plaintext ws to a public host — the bearer token would leak.
    if let Err(message) = reject_untrusted_plaintext(&entry.url) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }

    let upstream_url = match build_upstream_ws_url(&entry.url) {
        Ok(url) => url,
        Err(_) => return (StatusCode::BAD_GATEWAY, "invalid remote url").into_response(),
    };

    // Carry the remote token as a bearer header on the handshake (not in the
    // URL), so it never reaches the remote's access logs. The remote's /ws
    // handler already authenticates via Authorization: Bearer.
    let mut request = match upstream_url.as_str().into_client_request() {
        Ok(request) => request,
        Err(_) => return (StatusCode::BAD_GATEWAY, "invalid remote ws url").into_response(),
    };
    match TsHeaderValue::from_str(&format!("Bearer {}", entry.token)) {
        Ok(value) => {
            request.headers_mut().insert(TS_AUTHORIZATION, value);
        }
        Err(_) => return (StatusCode::BAD_GATEWAY, "invalid remote token").into_response(),
    }

    ws.on_upgrade(move |client_ws| proxy_ws(client_ws, request))
}

/// Pipe frames verbatim between the browser client and the upstream remote.
/// `request` carries the upstream URL plus the `Authorization: Bearer` header.
async fn proxy_ws(client_ws: WebSocket, request: TsRequest) {
    let upstream = match tokio_tungstenite::connect_async(request).await {
        Ok((stream, _response)) => stream,
        Err(_) => {
            // Upstream unreachable: close the client cleanly; the browser retries.
            let mut client_ws = client_ws;
            let _ = client_ws.send(AxumMessage::Close(None)).await;
            return;
        }
    };

    let (mut client_tx, mut client_rx) = client_ws.split();
    let (mut upstream_tx, mut upstream_rx) = upstream.split();

    // Client → upstream.
    let mut client_to_upstream = tokio::spawn(async move {
        while let Some(message) = client_rx.next().await {
            let Ok(message) = message else { break };
            if upstream_tx.send(axum_to_tungstenite(message)).await.is_err() {
                break;
            }
        }
        let _ = upstream_tx.close().await;
    });

    // Upstream → client.
    let mut upstream_to_client = tokio::spawn(async move {
        while let Some(message) = upstream_rx.next().await {
            let Ok(message) = message else { break };
            if let Some(message) = tungstenite_to_axum(message) {
                if client_tx.send(message).await.is_err() {
                    break;
                }
            }
        }
        let _ = client_tx.close().await;
    });

    // First side to finish tears down the other.
    tokio::select! {
        _ = &mut client_to_upstream => upstream_to_client.abort(),
        _ = &mut upstream_to_client => client_to_upstream.abort(),
    }
}

/// axum WebSocket message → tungstenite message. Binary/Ping/Pong payloads
/// share the same `bytes::Bytes` type across both crates, so they move without
/// copying; Text/Close carry a small re-wrap.
fn axum_to_tungstenite(message: AxumMessage) -> TsMessage {
    match message {
        AxumMessage::Text(text) => TsMessage::Text(TsUtf8Bytes::from(text.as_str())),
        AxumMessage::Binary(data) => TsMessage::Binary(data),
        AxumMessage::Ping(data) => TsMessage::Ping(data),
        AxumMessage::Pong(data) => TsMessage::Pong(data),
        AxumMessage::Close(frame) => TsMessage::Close(frame.map(|frame| TsCloseFrame {
            code: TsCloseCode::from(frame.code),
            reason: TsUtf8Bytes::from(frame.reason.as_str()),
        })),
    }
}

/// tungstenite message → axum WebSocket message. Raw `Frame` variants never
/// surface from the read stream, so they are dropped.
fn tungstenite_to_axum(message: TsMessage) -> Option<AxumMessage> {
    Some(match message {
        TsMessage::Text(text) => AxumMessage::Text(text.as_str().into()),
        TsMessage::Binary(data) => AxumMessage::Binary(data),
        TsMessage::Ping(data) => AxumMessage::Ping(data),
        TsMessage::Pong(data) => AxumMessage::Pong(data),
        TsMessage::Close(frame) => AxumMessage::Close(frame.map(|frame| AxumCloseFrame {
            code: frame.code.into(),
            reason: frame.reason.as_str().into(),
        })),
        TsMessage::Frame(_) => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, url: &str) -> RemoteConnectionEntry {
        RemoteConnectionEntry {
            id: id.into(),
            name: "name".into(),
            url: url.into(),
            token: "remote-token".into(),
            ssh_user: None,
            ssh_host: None,
            ssh_port: None,
            aggregate_sessions: None,
        }
    }

    #[test]
    fn resolve_remote_finds_and_misses() {
        let entries = vec![entry("a", "https://a.example"), entry("b", "https://b.example")];
        assert_eq!(resolve_remote(&entries, "b").unwrap().url, "https://b.example");
        assert!(resolve_remote(&entries, "missing").is_none());
    }

    #[test]
    fn build_http_url_joins_without_token() {
        let url =
            build_upstream_http_url("https://remote.example:8443/", "sessions/abc", None).unwrap();
        // Token is carried in a bearer header, never in the URL.
        assert_eq!(url, "https://remote.example:8443/api/sessions/abc");
    }

    #[test]
    fn build_http_url_merges_incoming_query_and_strips_client_token() {
        let url = build_upstream_http_url(
            "https://remote.example",
            "files/x.png",
            Some("token=HUB&foo=bar&baz=1"),
        )
        .unwrap();
        // Incoming client token is dropped; foo/baz kept; no token= in the URL.
        assert!(url.starts_with("https://remote.example/api/files/x.png?"));
        assert!(url.contains("foo=bar"));
        assert!(url.contains("baz=1"));
        assert!(!url.contains("token"));
        assert!(!url.contains("HUB"));
    }

    #[test]
    fn build_ws_url_swaps_scheme() {
        assert_eq!(
            build_upstream_ws_url("http://remote.example:3456").unwrap(),
            "ws://remote.example:3456/ws"
        );
        assert_eq!(
            build_upstream_ws_url("https://remote.example:8443/").unwrap(),
            "wss://remote.example:8443/ws"
        );
    }

    #[test]
    fn build_ws_url_rejects_non_http_scheme() {
        assert!(build_upstream_ws_url("ftp://x").is_err());
    }

    #[test]
    fn plaintext_allowed_on_private_and_loopback() {
        // LAN (RFC1918), loopback, CGNAT/tailnet, link-local over http → allowed.
        for url in [
            "http://192.168.1.61:3456",
            "http://10.0.0.5:3456",
            "http://172.16.4.2:3456",
            "http://127.0.0.1:3456",
            "http://localhost:3456",
            "http://100.92.116.51:3456", // tailnet CGNAT
            "ws://192.168.1.63:3456",
        ] {
            assert!(reject_untrusted_plaintext(url).is_ok(), "{url} should be allowed");
        }
    }

    #[test]
    fn plaintext_refused_on_public_hosts() {
        // Public IP and any hostname over http → refused (require TLS).
        for url in [
            "http://8.8.8.8:3456",
            "http://93.184.216.34",
            "http://remote.example.com:3456",
            "ws://remote.example.com/ws",
        ] {
            assert!(reject_untrusted_plaintext(url).is_err(), "{url} should be refused");
        }
    }

    #[test]
    fn https_always_allowed_regardless_of_host() {
        // TLS protects the wire, so any host is fine.
        assert!(reject_untrusted_plaintext("https://remote.example.com:8443").is_ok());
        assert!(reject_untrusted_plaintext("https://8.8.8.8").is_ok());
        assert!(reject_untrusted_plaintext("wss://remote.example.com/ws").is_ok());
    }

    #[test]
    fn bearer_header_wraps_and_rejects_bad_tokens() {
        assert_eq!(
            bearer_header("abc123").unwrap().to_str().unwrap(),
            "Bearer abc123"
        );
        // A newline is illegal in a header value → rejected, never silently sent.
        assert!(bearer_header("bad\ntoken").is_err());
    }

    #[test]
    fn hop_by_hop_detection() {
        for header in [
            "Connection",
            "keep-alive",
            "Proxy-Authenticate",
            "proxy-authorization",
            "TE",
            "trailer",
            "Transfer-Encoding",
            "Upgrade",
            "Host",
        ] {
            assert!(is_hop_by_hop(header), "{header} should be hop-by-hop");
        }
        for header in ["content-type", "authorization", "accept", "x-custom"] {
            assert!(!is_hop_by_hop(header), "{header} should pass through");
        }
    }

    #[test]
    fn remote_targets_self_detects_loop() {
        // Exact host + port.
        assert!(remote_targets_self("http://192.168.1.78:3456", "192.168.1.78", 3456));
        // Loopback aliases on both sides, same port.
        assert!(remote_targets_self("http://127.0.0.1:3456", "localhost", 3456));
        assert!(remote_targets_self("http://localhost:3456", "0.0.0.0", 3456));
    }

    #[test]
    fn remote_targets_self_allows_distinct_targets() {
        // Different port.
        assert!(!remote_targets_self("http://127.0.0.1:9999", "127.0.0.1", 3456));
        // Different, non-loopback host, same port.
        assert!(!remote_targets_self("https://huguette.example:3456", "127.0.0.1", 3456));
        // Unparseable URL is not treated as a loop (conservative).
        assert!(!remote_targets_self("not a url", "127.0.0.1", 3456));
    }

    #[test]
    fn token_from_raw_query_extracts() {
        assert_eq!(
            token_from_raw_query(Some("a=1&token=xyz&b=2")).as_deref(),
            Some("xyz")
        );
        assert!(token_from_raw_query(Some("a=1")).is_none());
        assert!(token_from_raw_query(None).is_none());
    }
}
