use axum::{
    body::Body,
    extract::{ws::WebSocketUpgrade, Path as AxumPath, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post},
    Json, Router,
};
use if_addrs::get_if_addrs;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tauri::AppHandle;
use tokio::sync::Mutex;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use super::assets;
use super::auth;
use super::login_guard;
use super::totp;
use super::websocket::handle_ws_connection;
use super::EmitExt;
use super::WsBroadcaster;

/// Shared state for the Axum server.
#[derive(Clone)]
pub(super) struct AppState {
    pub(super) app: AppHandle,
    pub(super) token: String,
    pub(super) token_required: bool,
    #[allow(dead_code)]
    pub(super) localhost_only: bool,
    pub(super) dist_path: std::path::PathBuf,
    /// HMAC key that signs web session cookies. Shared (Arc) because AppState is
    /// cloned per request. Loaded once at startup from app-data.
    pub(super) session_key: Arc<Vec<u8>>,
    /// Allowlist of sessions permitted to authenticate. A signed cookie only
    /// works while its `sid` is still listed here, which is what makes
    /// per-device revocation possible.
    pub(super) sessions: Arc<std::sync::RwLock<auth::SessionStore>>,
    /// Failed-login accounting for `/api/login`, per client address.
    pub(super) login_guard: Arc<login_guard::LoginGuard>,
    /// Second-factor enrollment. When a secret is active the raw token stops
    /// authorizing on its own: it becomes the first factor of `/api/login` and
    /// nothing else, so a leaked token no longer opens a terminal.
    pub(super) two_factor: Arc<std::sync::RwLock<totp::TwoFactorStore>>,
    /// Whether `X-Forwarded-For` may be believed when identifying a client.
    /// Only true when the deployment declares a reverse proxy in front, since
    /// the header is attacker-controlled otherwise.
    pub(super) trust_proxy: bool,
    /// Shared HTTP client for the remote proxy. Built once so connection pools
    /// and TLS setup are reused across proxied requests.
    pub(super) http_client: reqwest::Client,
    /// Host/port this hub is bound to, used by the remote proxy to refuse
    /// targeting the hub itself (anti-loop).
    pub(super) own_host: String,
    pub(super) own_port: u16,
}

/// Server handle for shutdown coordination.
pub struct HttpServerHandle {
    pub shutdown_tx: tokio::sync::oneshot::Sender<()>,
    pub port: u16,
    pub token: String,
    pub url: String,
    pub bind_host: String,
    pub localhost_only: bool,
    pub token_required: bool,
}

/// Status response for the HTTP server.
#[derive(Serialize, Clone)]
pub struct ServerStatus {
    pub running: bool,
    pub url: Option<String>,
    pub token: Option<String>,
    pub port: Option<u16>,
    pub bind_host: Option<String>,
    pub localhost_only: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct WsAuth {
    pub(super) token: Option<String>,
    /// Session value for clients that can neither hold a same-origin cookie nor
    /// set a header: browsers refuse to attach custom headers to a WebSocket
    /// handshake, so the native app puts its session here. Same signed value,
    /// same verification — see `session_value_from_request`.
    pub(super) session: Option<String>,
    /// Browser-provided selected project id. Overrides `ui_state.selected_project_id`
    /// when the disk copy is stale. Used to scope the init payload to only the
    /// worktrees/sessions the user is currently viewing.
    selected_project: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartCommitJobRequest {
    job_id: String,
    worktree_path: String,
    custom_prompt: Option<String>,
    push: bool,
    remote: Option<String>,
    pr_number: Option<u32>,
    model: Option<String>,
    custom_profile_name: Option<String>,
    reasoning_effort: Option<String>,
    specific_files: Option<Vec<String>>,
}

fn selected_project_id_for_init(
    selected_project: Option<&str>,
    ui_state: Option<&crate::UIState>,
) -> Option<String> {
    selected_project
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            ui_state
                .and_then(|u| u.active_project_id.clone())
                .filter(|s| !s.is_empty())
        })
}

#[derive(Serialize, Clone)]
pub struct BindHostOption {
    pub host: String,
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebBuildInfo {
    web_build_id: String,
    app_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    built_at: Option<String>,
}

impl Default for WebBuildInfo {
    fn default() -> Self {
        Self {
            web_build_id: env!("CARGO_PKG_VERSION").to_string(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            git_sha: None,
            built_at: None,
        }
    }
}

async fn read_web_build_info(dist_path: &std::path::Path) -> WebBuildInfo {
    let path = dist_path.join("jean-build.json");
    match tokio::fs::read_to_string(&path).await {
        Ok(contents) => serde_json::from_str::<WebBuildInfo>(&contents).unwrap_or_else(|e| {
            log::warn!("Failed to parse {}: {e}", path.display());
            WebBuildInfo::default()
        }),
        Err(e) => {
            log::debug!("No filesystem web build info at {}: {e}", path.display());
            assets::get("jean-build.json")
                .and_then(|data| serde_json::from_slice::<WebBuildInfo>(&data).ok())
                .unwrap_or_default()
        }
    }
}

/// Resolve the dist directory path at runtime.
/// Checks multiple locations for development and production scenarios.
fn resolve_dist_path(app: &AppHandle) -> std::path::PathBuf {
    // Development: prefer local dist output first so `vite build --watch`
    // changes are served immediately instead of stale bundled resources.
    let dev_dist = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dist");
    if cfg!(debug_assertions) && dev_dist.exists() && dev_dist.join("index.html").exists() {
        log::info!("Serving frontend from dev dist: {}", dev_dist.display());
        return dev_dist;
    }

    // 1. Check if app has a resource dir with dist/ (bundled via resources config)
    if let Ok(resource_dir) = app.path().resource_dir() {
        log::info!("Resource dir: {}", resource_dir.display());

        let dist = resource_dir.join("dist");
        if dist.exists() && dist.join("index.html").exists() {
            log::info!("Serving frontend from resource dir: {}", dist.display());
            return dist;
        }

        // 1b. Check resource dir itself (flat resources on some platforms)
        if resource_dir.join("index.html").exists() {
            log::info!(
                "Serving frontend from resource dir (flat): {}",
                resource_dir.display()
            );
            return resource_dir;
        }
    }

    // 2. Fallback to local dist path (also used in release if needed)
    if dev_dist.exists() && dev_dist.join("index.html").exists() {
        log::info!("Serving frontend from dev dist: {}", dev_dist.display());
        return dev_dist;
    }

    // 3. Fallback: relative to executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let dist = parent.join("dist");
            if dist.exists() && dist.join("index.html").exists() {
                log::info!(
                    "Serving frontend from exe-relative dist: {}",
                    dist.display()
                );
                return dist;
            }
        }
    }

    // Last resort: return dev path even if it doesn't exist yet
    log::warn!(
        "No dist directory found with index.html, using dev path: {}",
        dev_dist.display()
    );
    dev_dist
}

/// Start the HTTP + WebSocket server.
pub async fn start_server(
    app: AppHandle,
    port: u16,
    token: String,
    bind_host: String,
    token_required: bool,
) -> Result<HttpServerHandle, String> {
    let bind_ip = parse_bind_ip(&bind_host)?;
    let localhost_only = bind_ip.is_loopback();

    // Resolve the dist directory at runtime for static file serving
    let dist_path = resolve_dist_path(&app);

    // Load (or create) the key that signs session cookies, plus the session
    // allowlist. Both live in app-data so sessions survive restarts.
    let (session_key, sessions, two_factor) = {
        let dir = app
            .path()
            .app_data_dir()
            .map_err(|e| format!("Failed to resolve app data dir: {e}"))?;
        let key = Arc::new(auth::load_or_create_session_key(&dir)?);
        let store = Arc::new(std::sync::RwLock::new(auth::SessionStore::load(&dir)));
        let two_factor = Arc::new(std::sync::RwLock::new(totp::TwoFactorStore::load(&dir)));
        (key, store, two_factor)
    };
    // Bind first so the real (possibly ephemeral) port is known before building
    // AppState — the remote proxy's anti-loop check compares against it.
    let addr = SocketAddr::new(bind_ip, port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind to {bind_host}:{port}: {e}"))?;

    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("Failed to get local address: {e}"))?;

    let url = format_http_url(&display_host_for_bind_ip(bind_ip), local_addr.port());

    // Shared client for the remote proxy. Do not follow redirects — the browser
    // should observe upstream redirects verbatim.
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("Failed to build proxy HTTP client: {e}"))?;

    let state = AppState {
        app: app.clone(),
        token: token.clone(),
        token_required,
        localhost_only,
        dist_path: dist_path.clone(),
        session_key,
        sessions,
        login_guard: Arc::new(login_guard::LoginGuard::new()),
        two_factor,
        // Opt-in: only the operator knows whether something in front rewrites
        // the client address. Defaulting to true would let anyone spoof it.
        trust_proxy: std::env::var("JEAN_TRUSTED_PROXY")
            .map(|value| matches!(value.trim(), "1" | "true" | "yes"))
            .unwrap_or(false),
        http_client,
        own_host: bind_host.clone(),
        own_port: local_addr.port(),
    };

    let cors = cors_layer_from_env();

    let router = Router::new()
        .route("/healthz", get(health_handler))
        .route("/readyz", get(ready_handler))
        .route("/ws", get(ws_handler))
        .route("/api/auth", get(auth_handler))
        .route("/api/login", post(login_handler))
        .route("/api/logout", post(logout_handler))
        .route("/api/sessions", get(list_sessions_handler))
        .route("/api/sessions/{sid}", delete(revoke_session_handler))
        .route(
            "/api/sessions/revoke-others",
            post(revoke_other_sessions_handler),
        )
        .route("/api/2fa", get(two_factor_status_handler))
        .route("/api/2fa/enroll", post(two_factor_enroll_handler))
        .route("/api/2fa/confirm", post(two_factor_confirm_handler))
        .route("/api/2fa/disable", post(two_factor_disable_handler))
        .route("/api/commit-jobs", post(start_commit_job_handler))
        .route("/api/init", get(init_handler))
        .route(
            "/api/remote-connections",
            get(get_remote_connections_handler).put(put_remote_connections_handler),
        )
        .route("/api/version", get(version_handler))
        .route("/api/files/{*filepath}", get(file_handler))
        .route("/api/project-files/{*filepath}", get(project_file_handler))
        .route(
            "/remote/{id}/api/{*path}",
            any(super::remote_proxy::remote_http_proxy_handler),
        )
        .route(
            "/remote/{id}/ws",
            any(super::remote_proxy::remote_ws_proxy_handler),
        )
        .fallback(get(static_handler))
        .layer(CompressionLayer::new().br(true).gzip(true))
        .layer(cors)
        .with_state(state);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let bind_host_for_log = bind_host.clone();

    // Enable WS broadcasting only while the server runs — otherwise every
    // emitted event pays serialization/replay-buffering cost for no clients.
    if let Some(ws) = app.try_state::<WsBroadcaster>() {
        ws.set_active(true);
    }

    // Spawn the server
    let app_for_shutdown = app.clone();
    tokio::spawn(async move {
        log::info!(
            "HTTP server listening on {local_addr} (bind_host: {bind_host_for_log}, localhost_only: {localhost_only})"
        );
        axum::serve(
            listener,
            // Needed so /api/login can bucket failures by client address.
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
                log::info!("HTTP server shutting down");
            })
            .await
            .unwrap_or_else(|e| log::error!("HTTP server error: {e}"));
        if let Some(ws) = app_for_shutdown.try_state::<WsBroadcaster>() {
            ws.set_active(false);
        }
    });

    Ok(HttpServerHandle {
        shutdown_tx,
        port: local_addr.port(),
        token,
        url,
        bind_host,
        localhost_only,
        token_required,
    })
}

fn cors_layer_from_env() -> CorsLayer {
    let mut layer = CorsLayer::new().allow_methods(Any).allow_headers(Any);
    let raw = std::env::var("JEAN_ALLOWED_ORIGINS").unwrap_or_default();
    let origins = cors_origins(&raw);

    if raw.trim() == "*" {
        layer = layer.allow_origin(AllowOrigin::any());
    } else {
        layer = layer.allow_origin(AllowOrigin::list(origins));
    }

    layer
}

fn cors_origins(raw: &str) -> Vec<HeaderValue> {
    const NATIVE_CLIENT_ORIGINS: &[&str] = &[
        "tauri://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost",
        "http://localhost:1420",
    ];

    raw.split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .chain(NATIVE_CLIENT_ORIGINS.iter().copied())
        .filter_map(|origin| match HeaderValue::from_str(origin) {
            Ok(value) => Some(value),
            Err(e) => {
                log::warn!("Ignoring invalid JEAN_ALLOWED_ORIGINS entry '{origin}': {e}");
                None
            }
        })
        .collect()
}

async fn health_handler() -> Response {
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn ready_handler(State(state): State<AppState>) -> Response {
    let broadcaster_ready = state.app.try_state::<WsBroadcaster>().is_some();
    let status = if broadcaster_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(serde_json::json!({
            "ok": broadcaster_ready,
            "http": true,
            "websocket_broadcaster": broadcaster_ready,
        })),
    )
        .into_response()
}

/// WebSocket upgrade handler with token auth.
async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    // Validate token (skip if token not required)
    if state.token_required
        && !request_is_authorized(
            params.token.as_deref(),
            params.session.as_deref(),
            &headers,
            &state,
        )
    {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    // Get broadcast receiver for this client
    let broadcaster = state.app.try_state::<WsBroadcaster>();
    let event_rx = match broadcaster {
        Some(b) => b.subscribe(),
        None => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Server not initialized").into_response();
        }
    };

    let app = state.app.clone();
    ws.on_upgrade(move |socket| handle_ws_connection(socket, app, event_rx))
}

/// Token validation endpoint. Returns 200 with { ok: true } on success,
/// or 401 with { ok: false, error: "..." } on failure.
async fn auth_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    let build_info = read_web_build_info(&state.dist_path).await;

    // If token not required, always return success
    if !state.token_required {
        return Json(serde_json::json!({
            "ok": true,
            "token_required": false,
            "webBuildId": build_info.web_build_id,
            "appVersion": build_info.app_version,
        }))
        .into_response();
    }

    if request_is_authorized(
        params.token.as_deref(),
        params.session.as_deref(),
        &headers,
        &state,
    ) {
        let mut response = Json(serde_json::json!({
            "ok": true,
            "webBuildId": build_info.web_build_id,
            "appVersion": build_info.app_version,
        }))
        .into_response();
        // Sliding expiry: the browser hits this endpoint on every connect, so a
        // session in regular use keeps getting a fresh TTL. `refresh` only acts
        // (and only writes) once the session is past half-life.
        if let Some(sid) = active_session_sid(params.session.as_deref(), &headers, &state) {
            let now = now_unix_secs();
            let refreshed = state
                .sessions
                .write()
                .ok()
                .and_then(|mut store| store.refresh(&sid, now));
            if let Some(expires_at) = refreshed {
                let cookie = session_set_cookie(
                    &auth::issue_session_cookie(&state.session_key, &sid, expires_at),
                    request_is_https(&headers),
                    expires_at.saturating_sub(now),
                );
                if let Ok(value) = HeaderValue::from_str(&cookie) {
                    response.headers_mut().insert(header::SET_COOKIE, value);
                }
            }
        }
        response
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Invalid token" })),
        )
            .into_response()
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    token: String,
    /// TOTP code, required once a second factor is enrolled. Absent on the
    /// first attempt: the client only learns a code is needed after the token
    /// checks out, so a stranger guessing tokens learns nothing about the
    /// server's configuration.
    #[serde(default)]
    code: Option<String>,
    /// How the caller wants to carry the session. Browsers omit this and get
    /// the `HttpOnly` cookie, which JavaScript cannot read. The native app asks
    /// for `"header"` and receives the value in the response body, because it
    /// has no same-origin cookie jar to put it in.
    ///
    /// XSS in the browser cannot use this to exfiltrate a session: minting one
    /// still requires the token (and the code), and after login neither is
    /// anywhere JavaScript can reach.
    #[serde(default)]
    transport: Option<String>,
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// True when the request reached us over TLS. We only ever bind plain HTTP, so
/// TLS is terminated by a reverse proxy / tunnel that sets `X-Forwarded-Proto`.
/// The `Secure` cookie flag is set only then (so local http dev still works).
fn request_is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("https")
        })
        .unwrap_or(false)
}

/// Header the native app uses to carry its session value (see
/// `session_value_from_headers`).
pub(super) const SESSION_HEADER: &str = "x-jean-session";

fn session_set_cookie(value: &str, secure: bool, max_age: u64) -> String {
    let mut cookie = format!(
        "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}",
        auth::SESSION_COOKIE_NAME
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn json_ok_with_cookie(cookie: String) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"ok":true}"#))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "cookie error").into_response())
}

/// Exchange the raw token for an HttpOnly session cookie. Keeps the long-lived
/// token out of the browser's localStorage and out of the WebSocket URL.
async fn login_handler(
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Response {
    // With auth disabled a login is a no-op but harmless.
    if !state.token_required {
        return Json(serde_json::json!({ "ok": true, "token_required": false })).into_response();
    }

    let client = login_guard::client_ip(
        Some(peer.ip()),
        |name| headers.get(name).and_then(|value| value.to_str().ok()),
        state.trust_proxy,
    );

    // Refuse a penalised client *before* comparing tokens. Checking anyway
    // would make the penalty cosmetic: the attempt would still count.
    if let Some(client) = client {
        if let Some(remaining) = state.login_guard.blocked_for(client) {
            log::warn!("Rejected /api/login from {client}: too many failed attempts");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(
                    axum::http::header::RETRY_AFTER,
                    remaining.as_secs().max(1).to_string(),
                )],
                Json(serde_json::json!({
                    "ok": false,
                    "error": "Too many failed attempts. Try again shortly.",
                })),
            )
                .into_response();
        }
    }

    if !auth::validate_token(body.token.trim(), &state.token) {
        // Penalise instead of sleeping: a sleep holds a task and a connection,
        // so an attacker opening sockets in parallel pays nothing for it. The
        // budget is per client, so a stranger being throttled can never lock
        // the owner out of their own machine.
        if let Some(client) = client {
            if let Some(penalty) = state.login_guard.record_failure(client) {
                log::warn!(
                    "Failed /api/login from {client}: blocking further attempts for {}s",
                    penalty.as_secs()
                );
            }
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Invalid token" })),
        )
            .into_response();
    }

    // Token accepted. If a second factor is enrolled it must also check out —
    // otherwise a leaked token would still mint a session, which is the exact
    // hole 2FA exists to close.
    let now = now_unix_secs();
    match verify_second_factor(&state, body.code.as_deref(), now) {
        SecondFactor::NotEnrolled | SecondFactor::Accepted => {}
        SecondFactor::Required => {
            // Not a failed attempt: the client simply has not been asked yet.
            // Penalising here would lock the owner out over their own two-step
            // login. The code attempt that follows is what gets counted.
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "Enter the code from your authenticator app",
                    "code_required": true,
                })),
            )
                .into_response();
        }
        SecondFactor::Rejected(reason) => {
            if let Some(client) = client {
                if let Some(penalty) = state.login_guard.record_failure(client) {
                    log::warn!(
                        "Failed 2FA at /api/login from {client} ({reason}): blocking further attempts for {}s",
                        penalty.as_secs()
                    );
                }
            }
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "ok": false,
                    "error": reason,
                    "code_required": true,
                })),
            )
                .into_response();
        }
    }

    if let Some(client) = client {
        state.login_guard.record_success(client);
    }
    let (sid, expires_at) = {
        let Ok(mut store) = state.sessions.write() else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "session store poisoned").into_response();
        };
        store.create(auth::label_from_user_agent(&headers), now)
    };
    let value = auth::issue_session_cookie(&state.session_key, &sid, expires_at);
    if body.transport.as_deref() == Some("header") {
        return Json(serde_json::json!({
            "ok": true,
            "session": value,
            "expires_at": expires_at,
        }))
        .into_response();
    }
    json_ok_with_cookie(session_set_cookie(
        &value,
        request_is_https(&headers),
        expires_at.saturating_sub(now),
    ))
}

/// Sign out: revoke this device's session server-side (so its cookie stops
/// working even if it was copied elsewhere) and tell the browser to drop it.
async fn logout_handler(headers: HeaderMap, State(state): State<AppState>) -> Response {
    if let Some(raw) = session_value_from_request(None, &headers) {
        if let Some((sid, _)) = auth::parse_session_cookie(&state.session_key, &raw) {
            if let Ok(mut store) = state.sessions.write() {
                store.revoke(&sid);
            }
        }
    }
    json_ok_with_cookie(session_set_cookie("", request_is_https(&headers), 0))
}

// ── Second factor (TOTP) ─────────────────────────────────────────────────────
//
// All three mutating endpoints require an already-authorized request. Before
// enrollment that means the raw token, which is what lets a fresh server turn
// 2FA on in the first place; afterwards only a live session qualifies, so the
// phone is always involved in changing the phone's own role.

#[derive(Deserialize)]
struct TwoFactorCodeRequest {
    #[serde(default)]
    code: String,
}

/// Label an authenticator app shows for this server. Several Jean instances in
/// one app are otherwise indistinguishable.
fn two_factor_account_label(headers: &HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .unwrap_or("jean")
        .to_string()
}

async fn two_factor_status_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    if state.token_required
        && !request_is_authorized(
            params.token.as_deref(),
            params.session.as_deref(),
            &headers,
            &state,
        )
    {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }
    Json(serde_json::json!({ "enabled": two_factor_enabled(&state) })).into_response()
}

/// Mint a pending secret and hand back what the app needs to scan it. The
/// secret is not enforced until `/api/2fa/confirm` proves the app can produce a
/// matching code.
async fn two_factor_enroll_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    if state.token_required
        && !request_is_authorized(
            params.token.as_deref(),
            params.session.as_deref(),
            &headers,
            &state,
        )
    {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }
    let Ok(mut store) = state.two_factor.write() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "2FA state lock poisoned").into_response();
    };
    if store.is_enabled() {
        // Re-enrolling would silently swap the secret out from under the phone
        // that is currently guarding the server. Turn it off first, on purpose.
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "error": "Two-factor authentication is already enabled. Disable it first to enroll a new device.",
            })),
        )
            .into_response();
    }
    let secret = store.begin_enrollment();
    let url = totp::otpauth_url(&secret, "Jean", &two_factor_account_label(&headers));
    Json(serde_json::json!({ "ok": true, "secret": secret, "otpauth_url": url })).into_response()
}

async fn two_factor_confirm_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
    Json(body): Json<TwoFactorCodeRequest>,
) -> Response {
    let current_sid = active_session_sid(params.session.as_deref(), &headers, &state);
    if state.token_required
        && !request_is_authorized(
            params.token.as_deref(),
            params.session.as_deref(),
            &headers,
            &state,
        )
    {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }
    let Ok(mut store) = state.two_factor.write() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "2FA state lock poisoned").into_response();
    };
    if store.confirm_at(body.code.trim(), now_unix_secs()) {
        drop(store);
        if let Ok(mut sessions) = state.sessions.write() {
            sessions.revoke_all_except(current_sid.as_deref());
        } else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "session store poisoned").into_response();
        }
        log::info!("Two-factor authentication enabled");
        return Json(serde_json::json!({ "ok": true })).into_response();
    }
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "ok": false,
            "error": "That code did not match. Check your phone's clock and try the next one.",
        })),
    )
        .into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicSession {
    sid: String,
    issued_at: u64,
    last_seen: u64,
    expires_at: u64,
    label: String,
    current: bool,
}

/// Session administration deliberately requires a live session. The raw
/// access token never grants visibility into or control over device sessions.
fn current_session_sid(
    headers: &HeaderMap,
    params: &WsAuth,
    state: &AppState,
) -> Result<String, Response> {
    active_session_sid(params.session.as_deref(), headers, state)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Session required").into_response())
}

async fn list_sessions_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    let current = match current_session_sid(&headers, &params, &state) {
        Ok(sid) => sid,
        Err(response) => return response,
    };
    let Ok(store) = state.sessions.read() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "session store poisoned").into_response();
    };
    Json(
        store
            .active(now_unix_secs())
            .into_iter()
            .map(|session| PublicSession {
                current: session.sid == current,
                sid: session.sid,
                issued_at: session.issued_at,
                last_seen: session.last_seen,
                expires_at: session.expires_at,
                label: session.label,
            })
            .collect::<Vec<_>>(),
    )
    .into_response()
}

async fn revoke_session_handler(
    AxumPath(sid): AxumPath<String>,
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    if current_session_sid(&headers, &params, &state).is_err() {
        return (StatusCode::UNAUTHORIZED, "Session required").into_response();
    }
    let Ok(mut store) = state.sessions.write() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "session store poisoned").into_response();
    };
    store.revoke(&sid);
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn revoke_other_sessions_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    let current = match current_session_sid(&headers, &params, &state) {
        Ok(sid) => sid,
        Err(response) => return response,
    };
    let Ok(mut store) = state.sessions.write() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "session store poisoned").into_response();
    };
    store.revoke_all_except(Some(&current));
    Json(serde_json::json!({ "ok": true })).into_response()
}

/// Turn 2FA off from the network, which requires a current code: an attacker
/// who somehow holds a session must not be able to quietly remove the factor
/// that would keep them out next time. Lost the phone? Use `--disable-2fa` on
/// the machine itself.
async fn two_factor_disable_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
    Json(body): Json<TwoFactorCodeRequest>,
) -> Response {
    if state.token_required
        && !request_is_authorized(
            params.token.as_deref(),
            params.session.as_deref(),
            &headers,
            &state,
        )
    {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }
    let Ok(mut store) = state.two_factor.write() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "2FA state lock poisoned").into_response();
    };
    if !store.is_enabled() {
        return Json(serde_json::json!({ "ok": true })).into_response();
    }
    if !store.matches_active_at(body.code.trim(), now_unix_secs()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Invalid code" })),
        )
            .into_response();
    }
    store.disable();
    log::warn!("Two-factor authentication disabled");
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn start_commit_job_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
    Json(request): Json<StartCommitJobRequest>,
) -> Response {
    if state.token_required
        && !request_is_authorized(
            params.token.as_deref(),
            params.session.as_deref(),
            &headers,
            &state,
        )
    {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    match crate::projects::start_commit_job(
        state.app,
        request.worktree_path,
        request.custom_prompt,
        request.push,
        request.remote,
        request.pr_number,
        request.model,
        request.custom_profile_name,
        request.reasoning_effort,
        request.specific_files,
        Some(request.job_id),
    )
    .await
    {
        Ok(result) => (StatusCode::ACCEPTED, Json(result)).into_response(),
        Err(error) => (StatusCode::CONFLICT, error).into_response(),
    }
}

/// A remote Jean server saved by web clients. The list is stored on this
/// server (not in browser localStorage) so every device pointed at it shares
/// one configuration and tokens are never persisted in the browser.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct RemoteConnectionEntry {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) url: String,
    pub(super) token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ssh_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ssh_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ssh_port: Option<u16>,
    /// Aggregate this instance's sessions in the client sidebar. `None` means
    /// the default (on): entries written before the toggle existed keep
    /// aggregating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) aggregate_sessions: Option<bool>,
}

// Manual Debug so an accidental `{entry:?}` in a log never leaks the access
// token. All other fields stay visible for diagnostics.
impl std::fmt::Debug for RemoteConnectionEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteConnectionEntry")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("url", &self.url)
            .field("token", &"<redacted>")
            .field("ssh_user", &self.ssh_user)
            .field("ssh_host", &self.ssh_host)
            .field("ssh_port", &self.ssh_port)
            .field("aggregate_sessions", &self.aggregate_sessions)
            .finish()
    }
}

/// Public view of a remote connection: identical to `RemoteConnectionEntry`
/// minus the access token, which is never sent to the browser.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteConnectionPublic {
    id: String,
    name: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregate_sessions: Option<bool>,
}

impl From<&RemoteConnectionEntry> for RemoteConnectionPublic {
    fn from(entry: &RemoteConnectionEntry) -> Self {
        Self {
            id: entry.id.clone(),
            name: entry.name.clone(),
            url: entry.url.clone(),
            ssh_user: entry.ssh_user.clone(),
            ssh_host: entry.ssh_host.clone(),
            ssh_port: entry.ssh_port,
            aggregate_sessions: entry.aggregate_sessions,
        }
    }
}

/// Incoming remote connection from a PUT. The browser no longer holds tokens,
/// so `token` is optional/empty; the merge step keeps the stored token when the
/// client omits it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RemoteConnectionInput {
    id: String,
    name: String,
    url: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    ssh_user: Option<String>,
    #[serde(default)]
    ssh_host: Option<String>,
    #[serde(default)]
    ssh_port: Option<u16>,
    #[serde(default)]
    aggregate_sessions: Option<bool>,
}

/// Write-only-merge: for each incoming entry, keep the previously stored token
/// when the client sends an empty/absent token for an existing id. Pure so it
/// can be unit-tested without an `AppState`.
pub(super) fn merge_put_entries(
    existing: &[RemoteConnectionEntry],
    incoming: Vec<RemoteConnectionInput>,
) -> Vec<RemoteConnectionEntry> {
    incoming
        .into_iter()
        .map(|input| {
            let provided = input
                .token
                .as_deref()
                .map(str::trim)
                .filter(|token| !token.is_empty());
            let token = match provided {
                Some(token) => token.to_string(),
                None => existing
                    .iter()
                    .find(|entry| entry.id == input.id)
                    .map(|entry| entry.token.clone())
                    .unwrap_or_default(),
            };
            RemoteConnectionEntry {
                id: input.id,
                name: input.name,
                url: input.url,
                token,
                ssh_user: input.ssh_user,
                ssh_host: input.ssh_host,
                ssh_port: input.ssh_port,
                aggregate_sessions: input.aggregate_sessions,
            }
        })
        .collect()
}

const REMOTE_CONNECTIONS_FILE: &str = "remote-connections.json";
pub(super) const REMOTE_CONNECTIONS_MAX: usize = 100;

pub(super) fn remote_connections_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Cannot resolve app data dir: {e}"))?;
    Ok(app_data_dir.join(REMOTE_CONNECTIONS_FILE))
}

/// Missing or corrupt files yield an empty list — the browser falls back to
/// an empty picker rather than failing to boot.
pub(super) fn load_remote_connections(path: &std::path::Path) -> Vec<RemoteConnectionEntry> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

/// Atomic write (temp file + rename). The file holds access tokens for other
/// Jean servers, so restrict it to the owner on Unix.
fn save_remote_connections(
    path: &std::path::Path,
    entries: &[RemoteConnectionEntry],
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Cannot create app data dir: {e}"))?;
    }

    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| format!("Cannot serialize remote connections: {e}"))?;
    let temp_path = path.with_extension("tmp");
    std::fs::write(&temp_path, json)
        .map_err(|e| format!("Cannot write remote connections: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600));
    }

    std::fs::rename(&temp_path, path).map_err(|e| format!("Cannot persist remote connections: {e}"))
}

async fn get_remote_connections_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    if let Err(response) = validate_token(&params, &headers, &state) {
        return response;
    }

    let path = match remote_connections_path(&state.app) {
        Ok(path) => path,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let public: Vec<RemoteConnectionPublic> = load_remote_connections(&path)
        .iter()
        .map(RemoteConnectionPublic::from)
        .collect();
    Json(public).into_response()
}

async fn put_remote_connections_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
    Json(incoming): Json<Vec<RemoteConnectionInput>>,
) -> Response {
    if let Err(response) = validate_token(&params, &headers, &state) {
        return response;
    }

    if incoming.len() > REMOTE_CONNECTIONS_MAX {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Too many remote connections").into_response();
    }
    if incoming
        .iter()
        .any(|entry| entry.id.trim().is_empty() || entry.url.trim().is_empty())
    {
        return (
            StatusCode::BAD_REQUEST,
            "Remote connections need an id and a URL",
        )
            .into_response();
    }

    let path = match remote_connections_path(&state.app) {
        Ok(path) => path,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    // Merge against the stored list so tokens survive a browser that no longer
    // holds them (it PUTs an empty token for existing ids).
    let existing = load_remote_connections(&path);
    let entries = merge_put_entries(&existing, incoming);
    match save_remote_connections(&path, &entries) {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => {
            log::error!("Failed to save remote connections: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, e).into_response()
        }
    }
}

async fn version_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    if state.token_required
        && !request_is_authorized(
            params.token.as_deref(),
            params.session.as_deref(),
            &headers,
            &state,
        )
    {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    Json(read_web_build_info(&state.dist_path).await).into_response()
}

/// Maximum number of chat messages loaded per active session at init.
/// Older messages are fetched on-demand via `load_older_session_messages`
/// when the user scrolls up in the chat window.
const INIT_MESSAGE_WINDOW: usize = 50;

/// Maximum number of buffered WebSocket events replayed per focused running
/// session at init. Plenty to reconstruct an in-flight turn; full stream
/// continues over the WebSocket connection.
const INIT_REPLAY_EVENT_CAP: usize = 200;

type WorktreesByProject = std::collections::HashMap<String, Vec<crate::projects::types::Worktree>>;
type SessionsByWorktree = std::collections::HashMap<String, crate::chat::types::WorktreeSessions>;

/// Load windowed chat history for focused sessions that belong to the given
/// worktrees. Runs independently of session-list loading so init can overlap both.
async fn load_active_sessions_windowed(
    app: AppHandle,
    worktrees: &[crate::projects::types::Worktree],
    active_session_ids: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, crate::chat::types::Session> {
    if active_session_ids.is_empty() || worktrees.is_empty() {
        return std::collections::HashMap::new();
    }

    let worktree_map: std::collections::HashMap<&str, &crate::projects::types::Worktree> =
        worktrees.iter().map(|wt| (wt.id.as_str(), wt)).collect();

    let session_futures: Vec<_> = active_session_ids
        .iter()
        .filter_map(|(worktree_id, session_id)| {
            worktree_map.get(worktree_id.as_str()).map(|wt| {
                let app = app.clone();
                let wt_id = worktree_id.clone();
                let wt_path = wt.path.clone();
                let sess_id = session_id.clone();
                async move {
                    match crate::chat::get_session(
                        app,
                        wt_id,
                        wt_path,
                        sess_id.clone(),
                        Some(INIT_MESSAGE_WINDOW),
                    )
                    .await
                    {
                        Ok(session) => Some((sess_id, session)),
                        Err(e) => {
                            log::warn!("Failed to load active session {sess_id}: {e}");
                            None
                        }
                    }
                }
            })
        })
        .collect();

    futures_util::future::join_all(session_futures)
        .await
        .into_iter()
        .flatten()
        .collect()
}

/// Initial data endpoint. Returns only the data needed to render the view the
/// user lands on (project list + currently-selected project's worktrees +
/// windowed messages for the focused session). Additional data is lazy-loaded
/// by the frontend via TanStack Query hooks when the user navigates.
/// Strip secret preference values from an `/api/init` payload, replacing each
/// with a `<key>_configured: bool` marker (mirrors `server_preferences_value`).
/// Unlike that helper, client-only UI keys (theme, fonts, …) are kept because
/// the browser needs them to render. Secrets must never reach any client.
fn redact_preference_secrets(value: &mut Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for key in ["linear_api_key", "sentry_auth_token", "http_server_token"] {
        let configured = object
            .get(key)
            .is_some_and(|value| value.as_str().is_some_and(|secret| !secret.is_empty()));
        object.remove(key);
        object.insert(format!("{key}_configured"), Value::Bool(configured));
    }
}

async fn init_handler(
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    // Validate token (skip if token not required)
    if state.token_required
        && !request_is_authorized(
            params.token.as_deref(),
            params.session.as_deref(),
            &headers,
            &state,
        )
    {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    // Fetch base (always-included) data in parallel
    let (projects_result, preferences_result, ui_state_result) = tokio::join!(
        crate::projects::list_projects(state.app.clone()),
        crate::load_preferences(state.app.clone()),
        crate::load_ui_state(state.app.clone()),
    );

    let mut response = serde_json::json!({});
    let build_info = read_web_build_info(&state.dist_path).await;
    response["webBuildId"] = Value::String(build_info.web_build_id.clone());
    response["appVersion"] = Value::String(build_info.app_version.clone());
    response["serverPlatform"] = Value::String(crate::server_platform_name().to_string());
    response["nativeOpenAllowed"] = Value::Bool(crate::platform::native_open_allowed());

    let projects = match projects_result {
        Ok(projects) => projects,
        Err(e) => {
            log::error!("Failed to load projects for /api/init: {e}");
            vec![]
        }
    };

    let mut ui_state = match &ui_state_result {
        Ok(ui_state) => Some(ui_state.clone()),
        Err(_) => None,
    };

    // Resolve the "focused" project to scope the payload around.
    // Priority: browser override query param > ui_state.active_project_id.
    // Fall back to active_worktree_id's parent project if no active_project_id.
    let selected_project_id: Option<String> =
        selected_project_id_for_init(params.selected_project.as_deref(), ui_state.as_ref());

    // Validate the selected project exists and is a real project (not a folder).
    let selected_project = selected_project_id
        .as_deref()
        .and_then(|id| projects.iter().find(|p| p.id == id && !p.is_folder));

    // Fetch worktrees first (cheap JSON read), then overlap session lists with
    // windowed active-session messages so /api/init is one parallel disk phase.
    // Other projects stay lazy-loaded by the frontend on navigation.
    let (worktrees_by_project, sessions_by_worktree, mut active_sessions): (
        WorktreesByProject,
        SessionsByWorktree,
        std::collections::HashMap<String, crate::chat::types::Session>,
    ) = if let Some(project) = selected_project {
        let project_id = project.id.clone();
        let worktrees = crate::projects::list_worktrees(state.app.clone(), project_id.clone())
            .await
            .unwrap_or_default();

        let active_ids = ui_state
            .as_ref()
            .map(|ui| ui.active_session_ids.clone())
            .unwrap_or_default();

        let sessions_future = {
            let app = state.app.clone();
            let worktrees = worktrees.clone();
            async move {
                let futures: Vec<_> =
                    worktrees
                        .into_iter()
                        .map(|wt| {
                            let app = app.clone();
                            async move {
                                let worktree_id = wt.id.clone();
                                let sessions = crate::chat::get_sessions(
                                    app,
                                    worktree_id.clone(),
                                    wt.path,
                                    None,
                                    Some(true),
                                )
                                .await
                                .unwrap_or_else(|_| crate::chat::types::WorktreeSessions {
                                    worktree_id: worktree_id.clone(),
                                    sessions: vec![],
                                    active_session_id: None,
                                    default_model: None,
                                    version: 2,
                                    branch_naming_completed: false,
                                });
                                (worktree_id, sessions)
                            }
                        })
                        .collect();
                futures_util::future::join_all(futures)
                    .await
                    .into_iter()
                    .collect::<SessionsByWorktree>()
            }
        };

        let active_future =
            load_active_sessions_windowed(state.app.clone(), &worktrees, &active_ids);

        let (sessions_by_worktree, active_sessions) = tokio::join!(sessions_future, active_future);

        let mut worktrees_by_project = std::collections::HashMap::new();
        worktrees_by_project.insert(project_id, worktrees);
        (worktrees_by_project, sessions_by_worktree, active_sessions)
    } else {
        (
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        )
    };

    // Only worktrees in the selected project are "known" for validation/cleanup.
    // Entries in ui_state.active_session_ids for worktrees outside this scope
    // are left untouched — we don't have the data to judge them.
    let is_active_session_valid = |worktree_id: &str, session_id: &str| {
        sessions_by_worktree
            .get(worktree_id)
            .map(|ws| {
                ws.sessions
                    .iter()
                    .any(|s| s.id == session_id && s.archived_at.is_none())
            })
            .unwrap_or(false)
    };
    let is_worktree_in_scope = |worktree_id: &str| sessions_by_worktree.contains_key(worktree_id);

    let mut cleaned_active_sessions: Vec<(String, Option<String>)> = Vec::new();

    // Clean up stale active_session_ids that reference deleted/archived sessions.
    // Only operates on worktrees inside the selected project's scope (where
    // we have authoritative session data). Out-of-scope entries are preserved.
    if let Some(ref mut ui) = ui_state {
        let stale_keys: Vec<String> = ui
            .active_session_ids
            .iter()
            .filter(|(worktree_id, session_id)| {
                is_worktree_in_scope(worktree_id)
                    && !is_active_session_valid(worktree_id, session_id)
            })
            .map(|(k, _)| k.clone())
            .collect();

        for worktree_id in stale_keys {
            let old_id = ui.active_session_ids.remove(&worktree_id);
            // Drop the invalid windowed payload if we raced it with session lists.
            if let Some(ref stale_id) = old_id {
                active_sessions.remove(stale_id);
            }
            let fallback_session_id = sessions_by_worktree
                .get(&worktree_id)
                .and_then(|ws| ws.sessions.iter().find(|s| s.archived_at.is_none()))
                .map(|fallback| fallback.id.clone());

            if let Some(ref fallback_id) = fallback_session_id {
                log::info!(
                    "Replacing stale active session {} with {} for worktree {worktree_id}",
                    old_id.as_deref().unwrap_or("?"),
                    fallback_id
                );
                ui.active_session_ids
                    .insert(worktree_id.clone(), fallback_id.clone());
            } else {
                log::info!(
                    "Removed stale active session {} for worktree {worktree_id} (no fallback)",
                    old_id.as_deref().unwrap_or("?")
                );
            }

            cleaned_active_sessions.push((worktree_id, fallback_session_id));
        }
    }

    // If cleanup replaced a stale id with a fallback, load that session now
    // (uncommon path — only when the focused session was deleted/archived).
    if !cleaned_active_sessions.is_empty() {
        let worktree_map: std::collections::HashMap<&str, &crate::projects::types::Worktree> =
            worktrees_by_project
                .values()
                .flat_map(|wts| wts.iter())
                .map(|wt| (wt.id.as_str(), wt))
                .collect();

        let fallback_futures: Vec<_> = cleaned_active_sessions
            .iter()
            .filter_map(|(worktree_id, fallback_id)| {
                let session_id = fallback_id.as_ref()?;
                let wt = worktree_map.get(worktree_id.as_str())?;
                let app = state.app.clone();
                let wt_path = wt.path.clone();
                let sess_id = session_id.clone();
                let wt_id = worktree_id.clone();
                Some(async move {
                    match crate::chat::get_session(
                        app,
                        wt_id,
                        wt_path,
                        sess_id.clone(),
                        Some(INIT_MESSAGE_WINDOW),
                    )
                    .await
                    {
                        Ok(session) => Some((sess_id, session)),
                        Err(e) => {
                            log::warn!("Failed to load fallback active session {sess_id}: {e}");
                            None
                        }
                    }
                })
            })
            .collect();

        for (sess_id, session) in futures_util::future::join_all(fallback_futures)
            .await
            .into_iter()
            .flatten()
        {
            active_sessions.insert(sess_id, session);
        }

        match crate::load_ui_state(state.app.clone()).await {
            Ok(mut latest_ui_state) => {
                let mut persisted_cleanup = false;

                for (worktree_id, fallback_session_id) in &cleaned_active_sessions {
                    let should_update = latest_ui_state
                        .active_session_ids
                        .get(worktree_id)
                        .map(|session_id| !is_active_session_valid(worktree_id, session_id))
                        .unwrap_or(false);

                    if !should_update {
                        continue;
                    }

                    persisted_cleanup = true;

                    if let Some(fallback_id) = fallback_session_id {
                        latest_ui_state
                            .active_session_ids
                            .insert(worktree_id.clone(), fallback_id.clone());
                    } else {
                        latest_ui_state.active_session_ids.remove(worktree_id);
                    }
                }

                if persisted_cleanup {
                    if let Err(e) = crate::save_ui_state(state.app.clone(), latest_ui_state).await {
                        log::error!("Failed to persist cleaned ui_state for /api/init: {e}");
                    } else if let Err(e) = state.app.emit_all(
                        "cache:invalidate",
                        &serde_json::json!({ "keys": ["ui-state"] }),
                    ) {
                        log::error!("Failed to emit cache:invalidate after ui_state cleanup: {e}");
                    }
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to reload ui_state before persisting cleanup for /api/init: {e}"
                );
            }
        }
    }

    // Serialize projects (always included)
    if let Ok(val) = serde_json::to_value(&projects) {
        response["projects"] = val;
    }

    // Only emit worktrees/sessions keys when we actually have data.
    // Frontend checks `if (data.worktreesByProject)` etc. — omitting the key
    // signals lazy-load via TanStack Query hooks.
    if !worktrees_by_project.is_empty() {
        if let Ok(val) = serde_json::to_value(&worktrees_by_project) {
            response["worktreesByProject"] = val;
        }
    }

    if !sessions_by_worktree.is_empty() {
        if let Ok(val) = serde_json::to_value(&sessions_by_worktree) {
            response["sessionsByWorktree"] = val;
        }
    }

    if !active_sessions.is_empty() {
        if let Ok(val) = serde_json::to_value(&active_sessions) {
            response["activeSessions"] = val;
        }
    }

    if let Ok(app_data_dir) = state.app.path().app_data_dir() {
        response["appDataDir"] = Value::String(app_data_dir.to_string_lossy().to_string());
    }

    match preferences_result {
        Ok(preferences) => {
            if let Ok(mut val) = serde_json::to_value(&preferences) {
                redact_preference_secrets(&mut val);
                response["preferences"] = val;
            }
        }
        Err(e) => {
            log::error!("Failed to load preferences for /api/init: {e}");
            response["preferences"] = Value::Null;
        }
    }

    let running_sessions = crate::chat::registry::get_running_sessions();
    response["runningSessions"] = serde_json::to_value(&running_sessions).unwrap_or_default();

    // Replay events: only for running sessions that are also focused (in
    // active_sessions), capped at the last N events per session. The WebSocket
    // fresh WebSocket continues to stream the live event flow.
    if !running_sessions.is_empty() && !active_sessions.is_empty() {
        let focused: std::collections::HashSet<&String> = running_sessions
            .iter()
            .filter(|id| active_sessions.contains_key(id.as_str()))
            .collect();

        if !focused.is_empty() {
            let mut replay_events: Vec<Value> = state
                .app
                .try_state::<WsBroadcaster>()
                .map(|broadcaster| {
                    let mut events: Vec<Value> = focused
                        .iter()
                        .flat_map(|session_id| {
                            let buffered = broadcaster.replay_events(session_id, 0);
                            let start = buffered.len().saturating_sub(INIT_REPLAY_EVENT_CAP);
                            buffered[start..].to_vec()
                        })
                        .filter_map(|(_, json)| serde_json::from_str::<Value>(&json).ok())
                        .collect();
                    events.sort_by_key(|event| {
                        event
                            .get("seq")
                            .and_then(|seq| seq.as_u64())
                            .unwrap_or_default()
                    });
                    events
                })
                .unwrap_or_default();

            replay_events.dedup_by(|a, b| {
                a.get("seq").and_then(|seq| seq.as_u64())
                    == b.get("seq").and_then(|seq| seq.as_u64())
            });

            if !replay_events.is_empty() {
                response["replayEvents"] = Value::Array(replay_events);
            }
        }
    }

    match ui_state {
        Some(cleaned_ui) => {
            if let Ok(val) = serde_json::to_value(&cleaned_ui) {
                response["uiState"] = val;
            }
        }
        None => {
            if let Err(e) = &ui_state_result {
                log::error!("Failed to load ui_state for /api/init: {e}");
            }
            response["uiState"] = Value::Null;
        }
    }

    Json(response).into_response()
}

/// Guess MIME type from file extension.
fn mime_from_extension(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain; charset=utf-8",
        Some("json") => "application/json",
        Some("md") => "text/markdown; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Serve files from the app data directory (authenticated).
/// Used by the web view to load images, avatars, and other assets
/// that Tauri's asset:// protocol would serve in native mode.
async fn file_handler(
    AxumPath(filepath): AxumPath<String>,
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    // Validate token
    if state.token_required
        && !request_is_authorized(
            params.token.as_deref(),
            params.session.as_deref(),
            &headers,
            &state,
        )
    {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    // Resolve app data directory
    let app_data_dir = match state.app.path().app_data_dir() {
        Ok(dir) => dir,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Cannot resolve app data dir",
            )
                .into_response()
        }
    };

    // Build requested path and canonicalize
    let requested = app_data_dir.join(&filepath);
    let canonical = match requested.canonicalize() {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "File not found").into_response(),
    };

    // Security: ensure path is within app data dir (prevents traversal)
    let canonical_base = match app_data_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Cannot resolve base dir").into_response()
        }
    };
    if !canonical.starts_with(&canonical_base) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    // Only serve files, not directories
    if !canonical.is_file() {
        return (StatusCode::NOT_FOUND, "Not a file").into_response();
    }

    // Never expose secret-bearing files, even to an authenticated client. The
    // token itself is enough to read app data, but these hold OTHER servers'
    // tokens / API keys and are not asset content the browser should fetch.
    if is_secret_app_data_file(&canonical) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    // Read and serve the file
    let mime = mime_from_extension(&canonical);
    match tokio::fs::read(&canonical).await {
        Ok(bytes) => Response::builder()
            .header("Content-Type", mime)
            .header("Cache-Control", "private, max-age=3600")
            .body(axum::body::Body::from(bytes))
            .unwrap()
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Cannot read file").into_response(),
    }
}

/// True for app-data files that hold secrets and must never be served over the
/// file endpoint. Matches on the final (canonicalized) file name.
fn is_secret_app_data_file(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if matches!(
        name,
        "remote-connections.json" | "preferences.json" | "projects.json"
    ) {
        return true;
    }
    // `Path::extension()` returns None for a bare ".env", so match on the name:
    // covers ".env", "prod.env", etc.
    let lower = name.to_ascii_lowercase();
    lower == ".env" || lower.ends_with(".env")
}

fn validate_token(params: &WsAuth, headers: &HeaderMap, state: &AppState) -> Result<(), Response> {
    if state.token_required
        && !request_is_authorized(
            params.token.as_deref(),
            params.session.as_deref(),
            headers,
            state,
        )
    {
        return Err((StatusCode::UNAUTHORIZED, "Invalid token").into_response());
    }
    Ok(())
}

fn canonicalize_known_project_roots(app: &AppHandle) -> Result<Vec<std::path::PathBuf>, Response> {
    let data = crate::projects::storage::load_projects_data(app).map_err(|e| {
        log::warn!("Failed to load projects for project file request: {e}");
        (StatusCode::INTERNAL_SERVER_ERROR, "Cannot load projects").into_response()
    })?;

    let mut roots = Vec::new();
    for project in data.projects {
        if project.is_folder || project.path.is_empty() {
            continue;
        }
        if let Ok(path) = std::path::Path::new(&project.path).canonicalize() {
            roots.push(path);
        }
    }
    for worktree in data.worktrees {
        if let Ok(path) = std::path::Path::new(&worktree.path).canonicalize() {
            roots.push(path);
        }
    }

    Ok(roots)
}

fn path_is_in_known_roots(path: &std::path::Path, roots: &[std::path::PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

/// Serve files from known project/worktree directories (authenticated).
/// Used by browser-mode clients for auto-detected project avatars, matching
/// the native asset protocol's project directory allowlist.
async fn project_file_handler(
    AxumPath(filepath): AxumPath<String>,
    headers: HeaderMap,
    Query(params): Query<WsAuth>,
    State(state): State<AppState>,
) -> Response {
    if let Err(response) = validate_token(&params, &headers, &state) {
        return response;
    }

    let requested = std::path::PathBuf::from(&filepath);
    if !requested.is_absolute() {
        return (StatusCode::BAD_REQUEST, "Expected absolute file path").into_response();
    }

    let canonical = match requested.canonicalize() {
        Ok(path) => path,
        Err(_) => return (StatusCode::NOT_FOUND, "File not found").into_response(),
    };
    if !canonical.is_file() {
        return (StatusCode::NOT_FOUND, "Not a file").into_response();
    }

    let roots = match canonicalize_known_project_roots(&state.app) {
        Ok(roots) => roots,
        Err(response) => return response,
    };
    if !path_is_in_known_roots(&canonical, &roots) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let mime = mime_from_extension(&canonical);
    match tokio::fs::read(&canonical).await {
        Ok(bytes) => Response::builder()
            .header("Content-Type", mime)
            .header("Cache-Control", "private, max-age=3600")
            .body(Body::from(bytes))
            .unwrap()
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Cannot read file").into_response(),
    }
}

fn static_mime_from_extension(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

async fn static_handler(uri: Uri, State(state): State<AppState>) -> Response {
    let raw_path = uri.path().trim_start_matches('/');
    if raw_path.split('/').any(|part| part == "..") {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    if let Some(response) = try_static_filesystem_response(raw_path, &state.dist_path).await {
        return response;
    }

    embedded_static_response(raw_path)
}

async fn try_static_filesystem_response(
    raw_path: &str,
    dist_path: &std::path::Path,
) -> Option<Response> {
    let index_path = dist_path.join("index.html");
    let requested_path = if raw_path.is_empty() {
        index_path.clone()
    } else {
        dist_path.join(raw_path)
    };

    let path = match tokio::fs::metadata(&requested_path).await {
        Ok(metadata) if metadata.is_file() => requested_path,
        Ok(metadata) if metadata.is_dir() => requested_path.join("index.html"),
        _ => index_path.clone(),
    };

    let canonical_base = match tokio::fs::canonicalize(dist_path).await {
        Ok(path) => path,
        Err(_) => return None,
    };
    let canonical_path = match tokio::fs::canonicalize(&path).await {
        Ok(path) => path,
        Err(_) => return None,
    };
    if !canonical_path.starts_with(canonical_base) {
        return Some((StatusCode::FORBIDDEN, "Access denied").into_response());
    }

    let bytes = match tokio::fs::read(&canonical_path).await {
        Ok(bytes) => bytes,
        Err(_) => return None,
    };

    let canonical_index = index_path.canonicalize().unwrap_or(index_path);
    let is_index = canonical_path == canonical_index;
    let cache_control = if is_index || canonical_path.ends_with("jean-build.json") {
        "no-store"
    } else {
        "public, max-age=31536000, immutable"
    };

    Some(
        Response::builder()
            .header(
                header::CONTENT_TYPE,
                static_mime_from_extension(&canonical_path),
            )
            .header(header::CACHE_CONTROL, cache_control)
            .body(Body::from(bytes))
            .unwrap()
            .into_response(),
    )
}

fn embedded_asset_path_for_request(raw_path: &str) -> &str {
    if raw_path.is_empty() || !raw_path.contains('.') {
        "index.html"
    } else {
        raw_path
    }
}

fn embedded_static_response(raw_path: &str) -> Response {
    let asset_path = embedded_asset_path_for_request(raw_path);
    let data = assets::get(asset_path).or_else(|| assets::get("index.html"));

    let Some(data) = data else {
        return (
            StatusCode::NOT_FOUND,
            "Frontend assets not found. Run `bun run build` before building jean-server.",
        )
            .into_response();
    };

    let is_index = asset_path == "index.html";
    let cache_control = if is_index || asset_path == "jean-build.json" {
        "no-store"
    } else {
        "public, max-age=31536000, immutable"
    };

    Response::builder()
        .header(
            header::CONTENT_TYPE,
            static_mime_from_extension(std::path::Path::new(asset_path)),
        )
        .header(header::CACHE_CONTROL, cache_control)
        .body(Body::from(data.into_owned()))
        .unwrap()
}

fn parse_bind_ip(host: &str) -> Result<IpAddr, String> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err("Bind address cannot be empty".to_string());
    }

    if trimmed.eq_ignore_ascii_case("localhost") {
        return Ok(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    trimmed
        .parse::<IpAddr>()
        .map_err(|_| format!("Invalid bind address '{trimmed}'. Use an IP address or 'localhost'"))
}

pub(crate) fn validate_bind_host(host: &str) -> Result<String, String> {
    let trimmed = host.trim();
    parse_bind_ip(trimmed)?;

    if trimmed.eq_ignore_ascii_case("localhost") {
        Ok("localhost".to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn display_host_for_bind_ip(bind_ip: IpAddr) -> String {
    display_ip_for_bind_ip_with_candidates(
        bind_ip,
        get_if_addrs()
            .into_iter()
            .flatten()
            .map(|interface| interface.ip()),
    )
    .to_string()
}

fn display_ip_for_bind_ip_with_candidates(
    bind_ip: IpAddr,
    candidates: impl IntoIterator<Item = IpAddr>,
) -> IpAddr {
    if !bind_ip.is_unspecified() {
        return bind_ip;
    }

    let mut ipv4_candidate = None;
    let mut ipv6_candidate = None;

    for ip in candidates {
        if !is_displayable_bind_ip_candidate(ip) {
            continue;
        }

        match ip {
            IpAddr::V4(_) if ipv4_candidate.is_none() => ipv4_candidate = Some(ip),
            IpAddr::V6(_) if ipv6_candidate.is_none() => ipv6_candidate = Some(ip),
            _ => {}
        }
    }

    match bind_ip {
        IpAddr::V4(_) => ipv4_candidate.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        IpAddr::V6(_) => ipv6_candidate
            .or(ipv4_candidate)
            .unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    }
}

fn is_displayable_bind_ip_candidate(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }

    !matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
}

fn format_http_url(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("http://[{host}]:{port}")
    } else {
        format!("http://{host}:{port}")
    }
}

fn token_from_query_or_bearer(query_token: Option<&str>, headers: &HeaderMap) -> Option<String> {
    if let Some(token) = query_token.filter(|token| !token.is_empty()) {
        return Some(token.to_string());
    }

    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn request_is_authorized(
    query_token: Option<&str>,
    query_session: Option<&str>,
    headers: &HeaderMap,
    state: &AppState,
) -> bool {
    if active_session_sid(query_session, headers, state).is_some() {
        return true;
    }
    // Evaluate the token only when it can still matter: the comparison is
    // cheap, but skipping it keeps the rule in one place below.
    let token_matches = token_from_query_or_bearer(query_token, headers)
        .as_deref()
        .is_some_and(|provided| auth::validate_token(provided, &state.token));
    authorization_allows(false, two_factor_enabled(state), token_matches)
}

/// The rule itself, free of `AppState` so it can be asserted directly.
///
/// A live session always authorizes: it was minted by `/api/login`, which is
/// where both factors were checked. The raw token authorizes only while no
/// second factor is enrolled — once one is, the token is demoted to
/// `/api/login`'s first factor. Leaving it usable here is what would let a
/// leaked token reach `/ws`, and `/ws` hands out terminals.
fn authorization_allows(
    has_live_session: bool,
    two_factor_enabled: bool,
    token_matches: bool,
) -> bool {
    has_live_session || (token_matches && !two_factor_enabled)
}

/// Whether a second factor is enrolled.
///
/// A poisoned lock resolves to `true`: it downgrades the token to first-factor
/// only, which costs a working client one login and never grants access that
/// the intact state would have refused.
fn two_factor_enabled(state: &AppState) -> bool {
    match state.two_factor.read() {
        Ok(store) => store.is_enabled(),
        Err(_) => {
            log::error!("2FA state lock poisoned; refusing raw-token authorization");
            true
        }
    }
}

/// Outcome of the second-factor step of a login.
enum SecondFactor {
    NotEnrolled,
    Accepted,
    /// Enrolled, and the client has not sent a code yet.
    Required,
    /// Enrolled, code sent, code refused. Carries the message for the client.
    Rejected(&'static str),
}

fn verify_second_factor(state: &AppState, code: Option<&str>, now: u64) -> SecondFactor {
    let Ok(mut store) = state.two_factor.write() else {
        log::error!("2FA state lock poisoned; refusing login");
        return SecondFactor::Rejected("Server error verifying the code");
    };
    if !store.is_enabled() {
        return SecondFactor::NotEnrolled;
    }
    let Some(code) = code.map(str::trim).filter(|code| !code.is_empty()) else {
        return SecondFactor::Required;
    };
    match store.verify_login_at(code, now) {
        totp::VerifyOutcome::Ok => SecondFactor::Accepted,
        totp::VerifyOutcome::Invalid => SecondFactor::Rejected("Invalid code"),
        // Honest wording: the code was right, but a one-time password used
        // twice is either a double submit or someone replaying what they saw.
        totp::VerifyOutcome::Replayed => {
            SecondFactor::Rejected("That code was already used. Wait for the next one.")
        }
    }
}

/// Read the session value a request carries, from either transport.
///
/// Browsers send the `HttpOnly` cookie automatically. The native desktop app
/// talks to the server cross-origin (`tauri://localhost`), where a cookie would
/// need `SameSite=None` plus credentialed CORS; it sends the same signed value
/// in `X-Jean-Session` instead. The value is identical and is verified
/// identically — only the envelope differs.
fn session_value_from_request(query_session: Option<&str>, headers: &HeaderMap) -> Option<String> {
    let from_header = || {
        headers
            .get(SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    };
    let from_query = || {
        query_session
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    };
    // Cookie first: a browser's own credential outranks anything a query string
    // or a proxy in the path may also have supplied.
    auth::session_cookie_from_headers(headers)
        .or_else(from_header)
        .or_else(from_query)
}

/// Resolve the request's session cookie to a live `sid`: the signature must
/// verify, the embedded expiry must be in the future, AND the sid must still be
/// listed in the store (so a revoked device is rejected even though its cookie
/// is still perfectly signed).
fn active_session_sid(
    query_session: Option<&str>,
    headers: &HeaderMap,
    state: &AppState,
) -> Option<String> {
    let raw = session_value_from_request(query_session, headers)?;
    let (sid, expires_at) = auth::parse_session_cookie(&state.session_key, &raw)?;
    let now = now_unix_secs();
    if expires_at <= now {
        return None;
    }
    let store = state.sessions.read().ok()?;
    store.is_active(&sid, now).then_some(sid)
}

pub fn list_bind_host_options() -> Vec<BindHostOption> {
    let mut seen = HashSet::from([
        "127.0.0.1".to_string(),
        "0.0.0.0".to_string(),
        "::1".to_string(),
        "::".to_string(),
    ]);
    let mut options = vec![
        BindHostOption {
            host: "127.0.0.1".to_string(),
            label: "This device only (localhost)".to_string(),
        },
        BindHostOption {
            host: "0.0.0.0".to_string(),
            label: "All interfaces".to_string(),
        },
    ];
    let mut detected = Vec::new();

    if let Ok(interfaces) = get_if_addrs() {
        for interface in interfaces {
            let ip = interface.ip();
            if !is_displayable_bind_ip_candidate(ip) {
                continue;
            }

            let host = ip.to_string();
            if !seen.insert(host.clone()) {
                continue;
            }

            detected.push(BindHostOption {
                label: bind_host_option_label(&interface.name, ip),
                host,
            });
        }
    }

    detected.sort_by(|left, right| {
        bind_host_option_rank(&left.host)
            .cmp(&bind_host_option_rank(&right.host))
            .then_with(|| left.label.cmp(&right.label))
    });
    options.extend(detected);
    options
}

fn bind_host_option_label(interface_name: &str, ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) if is_tailscale_ipv4(v4) => format!("Tailscale ({v4})"),
        IpAddr::V6(v6) if is_tailscale_ipv6(v6) => format!("Tailscale ({v6})"),
        IpAddr::V4(v4) if v4.is_private() => format!("Local network ({interface_name}: {v4})"),
        IpAddr::V4(v4) => format!("{interface_name} ({v4})"),
        IpAddr::V6(v6) => format!("{interface_name} ({v6})"),
    }
}

fn bind_host_option_rank(host: &str) -> u8 {
    host.parse::<IpAddr>()
        .map(|ip| match ip {
            IpAddr::V4(v4) if is_tailscale_ipv4(v4) => 0,
            IpAddr::V6(v6) if is_tailscale_ipv6(v6) => 0,
            IpAddr::V4(v4) if v4.is_private() => 1,
            IpAddr::V4(_) => 2,
            IpAddr::V6(_) => 3,
        })
        .unwrap_or(4)
}

fn is_tailscale_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_tailscale_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
}

/// Get current server status. Called from dispatch.
pub async fn get_server_status(app: AppHandle) -> ServerStatus {
    match app.try_state::<Arc<Mutex<Option<HttpServerHandle>>>>() {
        Some(handle_state) => {
            let handle = handle_state.lock().await;
            match handle.as_ref() {
                Some(h) => ServerStatus {
                    running: true,
                    url: Some(h.url.clone()),
                    token: Some(h.token.clone()),
                    port: Some(h.port),
                    bind_host: Some(h.bind_host.clone()),
                    localhost_only: Some(h.localhost_only),
                },
                None => ServerStatus {
                    running: false,
                    url: None,
                    token: None,
                    port: None,
                    bind_host: None,
                    localhost_only: None,
                },
            }
        }
        None => ServerStatus {
            running: false,
            url: None,
            token: None,
            port: None,
            bind_host: None,
            localhost_only: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        authorization_allows, bind_host_option_label, bind_host_option_rank,
        display_host_for_bind_ip, display_ip_for_bind_ip_with_candidates,
        embedded_asset_path_for_request, format_http_url, is_secret_app_data_file,
        is_tailscale_ipv4, load_remote_connections, merge_put_entries, parse_bind_ip,
        path_is_in_known_roots, save_remote_connections, session_value_from_request,
        token_from_query_or_bearer, validate_bind_host, RemoteConnectionEntry,
        RemoteConnectionInput, RemoteConnectionPublic, SESSION_HEADER,
    };
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_valid_token_stops_authorizing_once_a_second_factor_is_enrolled() {
        // Before enrollment the token is the whole credential.
        assert!(authorization_allows(false, false, true));
        // After it, the same token must not reach /ws on its own — that is the
        // hole 2FA exists to close.
        assert!(!authorization_allows(false, true, true));
        // A session minted through /api/login (both factors) still works.
        assert!(authorization_allows(true, true, false));
        // And nothing lets a wrong token in either way.
        assert!(!authorization_allows(false, false, false));
    }

    #[test]
    fn session_value_is_read_from_the_cookie_or_the_native_header() {
        let mut cookie_only = HeaderMap::new();
        cookie_only.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("jean_session=v2.abc.99.sig"),
        );
        assert_eq!(
            session_value_from_request(None, &cookie_only).as_deref(),
            Some("v2.abc.99.sig")
        );

        let mut header_only = HeaderMap::new();
        header_only.insert(SESSION_HEADER, HeaderValue::from_static("v2.def.99.sig"));
        assert_eq!(
            session_value_from_request(None, &header_only).as_deref(),
            Some("v2.def.99.sig")
        );

        // An empty header is not a session; it must not shadow "no session".
        let mut blank = HeaderMap::new();
        blank.insert(SESSION_HEADER, HeaderValue::from_static("   "));
        assert_eq!(session_value_from_request(None, &blank), None);

        assert_eq!(session_value_from_request(None, &HeaderMap::new()), None);
    }

    #[test]
    fn the_cookie_wins_when_a_request_carries_both() {
        // A browser proxying through something that also sets the header must
        // keep using its own cookie, not the value someone else supplied.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("jean_session=v2.cookie.99.sig"),
        );
        headers.insert(SESSION_HEADER, HeaderValue::from_static("v2.header.99.sig"));
        assert_eq!(
            session_value_from_request(None, &headers).as_deref(),
            Some("v2.cookie.99.sig")
        );
    }

    #[test]
    fn parse_bind_ip_accepts_localhost_and_ip_literals() {
        assert_eq!(
            parse_bind_ip("localhost").unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            parse_bind_ip("100.64.0.1").unwrap(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
        );
        assert_eq!(
            parse_bind_ip("::1").unwrap(),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn token_auth_accepts_bearer_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret-token"),
        );

        assert_eq!(
            token_from_query_or_bearer(None, &headers),
            Some("secret-token".to_string())
        );
    }

    #[test]
    fn token_auth_prefers_query_token_for_browser_compatibility() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );

        assert_eq!(
            token_from_query_or_bearer(Some("query-token"), &headers),
            Some("query-token".to_string())
        );
    }

    #[test]
    fn parse_bind_ip_rejects_invalid_values() {
        let error = parse_bind_ip("tailscale").unwrap_err();
        assert!(error.contains("Invalid bind address"));

        let empty_error = parse_bind_ip("").unwrap_err();
        assert!(empty_error.contains("cannot be empty"));
    }

    #[test]
    fn validate_bind_host_trims_and_normalizes_localhost() {
        assert_eq!(validate_bind_host(" LOCALHOST ").unwrap(), "localhost");
        assert_eq!(
            validate_bind_host(" 100.110.76.47 ").unwrap(),
            "100.110.76.47"
        );
    }

    #[test]
    fn display_host_uses_specific_bind_ip_directly() {
        assert_eq!(
            display_host_for_bind_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
            "100.64.0.1"
        );
        assert_eq!(
            display_host_for_bind_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "::1"
        );
    }

    #[test]
    fn ipv4_wildcard_display_host_uses_first_valid_ipv4_candidate() {
        assert_eq!(
            display_ip_for_bind_ip_with_candidates(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                [
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 25)),
                    IpAddr::V6("fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap()),
                ],
            ),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 25))
        );
    }

    #[test]
    fn ipv6_wildcard_display_host_prefers_valid_ipv6_candidate() {
        assert_eq!(
            display_ip_for_bind_ip_with_candidates(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                [
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 25)),
                    IpAddr::V6("fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap()),
                ],
            ),
            IpAddr::V6("fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn ipv6_wildcard_display_host_falls_back_to_ipv4_when_needed() {
        assert_eq!(
            display_ip_for_bind_ip_with_candidates(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                [IpAddr::V4(Ipv4Addr::new(192, 168, 1, 25))],
            ),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 25))
        );
    }

    #[test]
    fn ipv6_wildcard_display_host_falls_back_to_ipv6_localhost_when_no_candidates() {
        assert_eq!(
            display_ip_for_bind_ip_with_candidates(IpAddr::V6(Ipv6Addr::UNSPECIFIED), []),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn format_http_url_wraps_ipv6_hosts() {
        assert_eq!(
            format_http_url("100.64.0.1", 3456),
            "http://100.64.0.1:3456"
        );
        assert_eq!(format_http_url("::1", 3456), "http://[::1]:3456");
    }

    #[test]
    fn embedded_asset_path_maps_root_and_spa_routes_to_index() {
        assert_eq!(embedded_asset_path_for_request(""), "index.html");
        assert_eq!(
            embedded_asset_path_for_request("projects/abc"),
            "index.html"
        );
    }

    #[test]
    fn embedded_asset_path_keeps_asset_paths() {
        assert_eq!(
            embedded_asset_path_for_request("assets/app.js"),
            "assets/app.js"
        );
    }

    #[test]
    fn wildcard_display_urls_never_use_unspecified_hosts() {
        let ipv6_url = format_http_url(
            &display_ip_for_bind_ip_with_candidates(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                [IpAddr::V6("fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap())],
            )
            .to_string(),
            3456,
        );
        assert_eq!(ipv6_url, "http://[fd7a:115c:a1e0::1]:3456");

        let fallback_url = format_http_url(
            &display_ip_for_bind_ip_with_candidates(IpAddr::V6(Ipv6Addr::UNSPECIFIED), [])
                .to_string(),
            3456,
        );
        assert_ne!(fallback_url, "http://[::]:3456");
        assert_eq!(fallback_url, "http://[::1]:3456");
    }

    #[test]
    fn tailscale_ipv4_detection_matches_cgnat_range() {
        assert!(is_tailscale_ipv4(Ipv4Addr::new(100, 110, 76, 47)));
        assert!(!is_tailscale_ipv4(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(!is_tailscale_ipv4(Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn tailscale_ipv6_detection_matches_known_prefix() {
        assert!(super::is_tailscale_ipv6(
            "fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(!super::is_tailscale_ipv6(
            "fd00::1".parse::<Ipv6Addr>().unwrap()
        ));
    }

    #[test]
    fn bind_host_labels_prioritize_tailscale_and_lan_ips() {
        assert_eq!(
            bind_host_option_label("utun4", IpAddr::V4(Ipv4Addr::new(100, 110, 76, 47))),
            "Tailscale (100.110.76.47)"
        );
        assert_eq!(
            bind_host_option_label("en0", IpAddr::V4(Ipv4Addr::new(192, 168, 18, 17))),
            "Local network (en0: 192.168.18.17)"
        );
        assert!(bind_host_option_rank("100.110.76.47") < bind_host_option_rank("192.168.18.17"));
    }

    #[test]
    fn bind_host_options_include_default_presets() {
        let options = super::list_bind_host_options();
        assert!(options.iter().any(|option| option.host == "127.0.0.1"));
        assert!(options.iter().any(|option| option.host == "0.0.0.0"));
    }

    #[test]
    fn selected_project_id_for_init_prefers_browser_state() {
        let ui_state = crate::UIState {
            active_project_id: Some("disk-project".to_string()),
            ..Default::default()
        };

        assert_eq!(
            super::selected_project_id_for_init(Some("browser-project"), Some(&ui_state)),
            Some("browser-project".to_string())
        );
    }

    #[test]
    fn selected_project_id_for_init_falls_back_to_ui_state() {
        let ui_state = crate::UIState {
            active_project_id: Some("disk-project".to_string()),
            ..Default::default()
        };

        assert_eq!(
            super::selected_project_id_for_init(None, Some(&ui_state)),
            Some("disk-project".to_string())
        );
    }

    #[test]
    fn selected_project_id_for_init_ignores_empty_values() {
        let ui_state = crate::UIState {
            active_project_id: Some(String::new()),
            ..Default::default()
        };

        assert_eq!(
            super::selected_project_id_for_init(Some(""), Some(&ui_state)),
            None
        );
    }

    #[test]
    fn server_platform_name_matches_supported_frontend_values() {
        assert!(matches!(
            crate::server_platform_name(),
            "mac" | "windows" | "linux"
        ));
    }

    #[test]
    fn default_cors_origins_allow_native_jean_clients() {
        let origins: Vec<String> = super::cors_origins("")
            .into_iter()
            .map(|value| value.to_str().expect("valid origin").to_string())
            .collect();

        assert!(origins.contains(&"tauri://localhost".to_string()));
        assert!(origins.contains(&"http://tauri.localhost".to_string()));
        assert!(origins.contains(&"https://tauri.localhost".to_string()));
        assert!(origins.contains(&"http://localhost:1420".to_string()));
    }

    #[test]
    fn test_path_is_in_known_roots_allows_nested_project_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("project");
        let nested = root.join("public").join("favicon.png");
        std::fs::create_dir_all(nested.parent().expect("nested parent")).expect("create dirs");
        std::fs::write(&nested, "png").expect("write file");

        let canonical_root = root.canonicalize().expect("canonical root");
        let canonical_nested = nested.canonicalize().expect("canonical nested");

        assert!(path_is_in_known_roots(&canonical_nested, &[canonical_root]));
    }

    #[test]
    fn test_path_is_in_known_roots_rejects_sibling_prefix() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("project");
        let sibling = dir.path().join("project-other").join("favicon.png");
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::create_dir_all(sibling.parent().expect("sibling parent")).expect("create sibling");
        std::fs::write(&sibling, "png").expect("write file");

        let canonical_root = root.canonicalize().expect("canonical root");
        let canonical_sibling = sibling.canonicalize().expect("canonical sibling");

        assert!(!path_is_in_known_roots(
            &canonical_sibling,
            &[canonical_root]
        ));
    }

    #[test]
    fn remote_connections_round_trip_preserves_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remote-connections.json");

        let entries = vec![
            RemoteConnectionEntry {
                id: "a".into(),
                name: "ses-temps".into(),
                url: "https://huguette.example:8443".into(),
                token: "tok-a".into(),
                ssh_user: Some("root".into()),
                ssh_host: Some("192.168.1.61".into()),
                ssh_port: Some(2222),
                aggregate_sessions: Some(false),
            },
            RemoteConnectionEntry {
                id: "b".into(),
                name: "jean".into(),
                url: "http://192.168.1.78:3456".into(),
                token: "tok-b".into(),
                ssh_user: None,
                ssh_host: None,
                ssh_port: None,
                aggregate_sessions: None,
            },
        ];

        save_remote_connections(&path, &entries).unwrap();
        assert_eq!(load_remote_connections(&path), entries);

        // Optional SSH fields are omitted from the stored JSON entirely.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("\"sshUser\": null"));
        // The sidebar opt-out survives a round trip; the default stays absent.
        assert!(raw.contains("\"aggregateSessions\": false"));
        assert_eq!(load_remote_connections(&path)[1].aggregate_sessions, None);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn remote_connections_missing_or_corrupt_file_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("remote-connections.json");
        assert!(load_remote_connections(&missing).is_empty());

        std::fs::write(&missing, "{not json").unwrap();
        assert!(load_remote_connections(&missing).is_empty());
    }

    fn sample_entry(id: &str, token: &str) -> RemoteConnectionEntry {
        RemoteConnectionEntry {
            id: id.into(),
            name: "name".into(),
            url: "https://remote.example".into(),
            token: token.into(),
            ssh_user: None,
            ssh_host: None,
            ssh_port: None,
            aggregate_sessions: None,
        }
    }

    #[test]
    fn public_view_never_serializes_token() {
        let entry = sample_entry("a", "super-secret");
        let value = serde_json::to_value(RemoteConnectionPublic::from(&entry)).unwrap();
        let object = value.as_object().unwrap();
        assert!(!object.contains_key("token"));
        assert_eq!(object.get("id").unwrap(), "a");
        assert_eq!(object.get("url").unwrap(), "https://remote.example");
        // The secret string must not appear anywhere in the serialized form.
        assert!(!value.to_string().contains("super-secret"));
    }

    #[test]
    fn merge_put_keeps_stored_token_when_incoming_is_empty() {
        let existing = vec![sample_entry("a", "stored-token")];

        // Empty-string token and absent token both preserve the stored value.
        let incoming = vec![
            RemoteConnectionInput {
                id: "a".into(),
                name: "renamed".into(),
                url: "https://remote.example".into(),
                token: Some("   ".into()),
                ssh_user: None,
                ssh_host: None,
                ssh_port: None,
                aggregate_sessions: None,
            },
            RemoteConnectionInput {
                id: "b".into(),
                name: "new".into(),
                url: "https://other.example".into(),
                token: Some("fresh-token".into()),
                ssh_user: None,
                ssh_host: None,
                ssh_port: None,
                aggregate_sessions: None,
            },
        ];

        let merged = merge_put_entries(&existing, incoming);
        assert_eq!(merged.len(), 2);
        // Existing id keeps its stored token but takes the new name.
        assert_eq!(merged[0].token, "stored-token");
        assert_eq!(merged[0].name, "renamed");
        // New id uses the provided token.
        assert_eq!(merged[1].token, "fresh-token");
    }

    #[test]
    fn merge_put_round_trips_the_sidebar_opt_out() {
        let merged = merge_put_entries(
            &[sample_entry("a", "stored-token")],
            vec![RemoteConnectionInput {
                id: "a".into(),
                name: "n".into(),
                url: "https://remote.example".into(),
                token: None,
                ssh_user: None,
                ssh_host: None,
                ssh_port: None,
                aggregate_sessions: Some(false),
            }],
        );
        assert_eq!(merged[0].aggregate_sessions, Some(false));
        // The flag is client-owned: it is never inherited from the stored
        // entry the way the write-only token is.
        assert_eq!(
            serde_json::to_value(RemoteConnectionPublic::from(&merged[0]))
                .unwrap()
                .get("aggregateSessions")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn merge_put_new_id_with_empty_token_yields_empty_token() {
        let merged = merge_put_entries(
            &[],
            vec![RemoteConnectionInput {
                id: "brand-new".into(),
                name: "n".into(),
                url: "https://remote.example".into(),
                token: None,
                ssh_user: None,
                ssh_host: None,
                ssh_port: None,
                aggregate_sessions: None,
            }],
        );
        assert_eq!(merged.len(), 1);
        assert!(merged[0].token.is_empty());
    }

    #[test]
    fn secret_app_data_files_are_rejected() {
        assert!(is_secret_app_data_file(std::path::Path::new(
            "/data/remote-connections.json"
        )));
        assert!(is_secret_app_data_file(std::path::Path::new(
            "/data/preferences.json"
        )));
        assert!(is_secret_app_data_file(std::path::Path::new(
            "/data/projects.json"
        )));
        assert!(is_secret_app_data_file(std::path::Path::new("/data/.env")));
        assert!(is_secret_app_data_file(std::path::Path::new(
            "/data/prod.env"
        )));
        assert!(!is_secret_app_data_file(std::path::Path::new(
            "/data/avatar.png"
        )));
        assert!(!is_secret_app_data_file(std::path::Path::new(
            "/data/sessions.json"
        )));
    }

    #[test]
    fn debug_redacts_token() {
        let entry = sample_entry("a", "super-secret");
        let rendered = format!("{entry:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret"));
    }
}
