# Web Access authentication

Web Access hands out terminals (`start_terminal` over `/ws`), so the credential
that opens it is worth as much as a shell on the machine. This is the model that
guards it.

## Credentials

| Credential | Lives | Revocable | Accepted on |
| --- | --- | --- | --- |
| Access token | `http_server_token` preference | Only by rotating it | `/api/login`, and every endpoint **while no second factor is enrolled** |
| Session | `web-sessions.json` allowlist | Per device | Every endpoint |
| TOTP secret | `web-2fa.json` | — | `/api/login` only |

A session cookie is `v2.<sid>.<expiry>.<sig>`, signed with the HMAC key in
`web-session-key`. The signature alone does not authorize: the `sid` must still
be listed in the allowlist, which is what makes per-device revocation possible.

## The rule

`request_is_authorized` (`jean-core/src/http_server/server.rs`) is the single
gate. Its decision is factored into `authorization_allows`, which is testable
without an `AppState`:

- a live session always authorizes;
- the raw token authorizes **only while no second factor is enrolled**.

Enrolling a second factor therefore does more than add a step to the login form:
it demotes the token to being `/api/login`'s first factor. Without that demotion
2FA would be decoration, because a leaked token could still open `/ws` directly
and never meet the phone.

Consequence to expect: enabling 2FA signs out anything that was authenticating
with the raw token until it logs in and obtains a session.

## Transports

The same signed session value reaches the server three ways, because the
clients differ in what they can carry:

| Client | Envelope | Why |
| --- | --- | --- |
| Browser | `jean_session` cookie, `HttpOnly` | JavaScript must not be able to read it; `Secure` is added when `X-Forwarded-Proto: https` |
| Native app, HTTP | `X-Jean-Session` header | Cross-origin from `tauri://localhost`, so a cookie would need `SameSite=None` plus credentialed CORS |
| Native app, WebSocket | `?session=` query parameter | Browsers refuse custom headers on a WebSocket handshake |

`POST /api/login` picks the envelope from the request body: `transport:
"header"` returns the value in the response, anything else sets the cookie. XSS
cannot use the header form to exfiltrate a session, because minting one still
requires the token — which, after a cookie login, is nowhere JavaScript can
reach.

## Second factor (TOTP)

RFC 6238, HMAC-SHA1, 6 digits, 30-second step, ±1 step of drift accepted.
Implemented in `jean-core/src/http_server/totp.rs` against the RFC's own test
vectors rather than pulled from a crate.

Enrollment is two-phase — `POST /api/2fa/enroll` mints a *pending* secret, and
only a correct code through `POST /api/2fa/confirm` activates it. Activating on
generation would lock the user out whenever the QR was mistyped or the phone's
clock was off.

Other properties worth not regressing:

- The accepted step is remembered, so a code cannot be replayed inside its own
  validity window.
- `/api/login` reveals that a code is needed **only after the token checks out**,
  so token guessing tells an attacker nothing about the server's configuration.
- Being asked for a code is not a failed attempt; only a submitted wrong code is
  counted by the login guard.
- Turning 2FA off over the network requires a current code. Someone who somehow
  holds a session must not be able to quietly remove the factor.
- A corrupt or unreadable `web-2fa.json` disables the factor rather than
  enforcing one nobody can satisfy. This is the opposite of the session store's
  fail-closed behaviour, and it is deliberate: a bad session file logs you out,
  a bad 2FA file would lock you out.

## Recovery

Lost the authenticator device:

```bash
jean-server --disable-2fa
```

Removes `web-2fa.json` and exits, without starting a server. A server that is
already running keeps its own copy in memory, so restart it afterwards.

The flag has no environment-variable equivalent on purpose: an env var left in a
unit file would silently strip the second factor on every restart.

## Rate limiting

`login_guard.rs` throttles failed `/api/login` attempts per client address, with
a growing penalty. Forwarded headers (`CF-Connecting-IP`, `X-Forwarded-For`) are
believed only when `JEAN_TRUSTED_PROXY` is set — which is only sound when the
server binds loopback behind exactly one proxy that overwrites them.

Note that the other endpoints are not rate limited. They do not need to be while
they accept only sessions and a 256-bit token, but the asymmetry is worth
remembering before making the token user-chosen.
