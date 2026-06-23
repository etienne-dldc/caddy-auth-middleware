# caddy-auth-middleware

A custom Caddy build that embeds the tower_auth HTTP middleware.

The middleware implements a proxy-first auth flow:
- redirect unauthenticated users to an auth server login page
- exchange one-time login tokens from query parameters
- set an app session cookie
- validate sessions on each request
- inject trusted identity headers before proxying to upstream apps

## Middleware directive

Use the handler directive in your Caddyfile:

tower_auth {
    auth_server http://tower-auth:3000
    public_auth_server https://auth.example.com
    cookie_name tower_auth
    logout_path /logout
}

Subdirectives:
- auth_server: required internal auth server base URL (used by Caddy for /exchange, /check, /logout)
- public_auth_server: optional public auth server URL used for browser redirects (defaults to auth_server)
- cookie_name: optional, default tower_auth
- logout_path: optional, default /logout

The global options block in the Caddyfile should include:

order tower_auth before reverse_proxy

## Security: Redirect Validation Is Mandatory

This middleware sends unauthenticated users to:

- <public_auth_server>/login?return=<full_current_url>

The auth server must treat return as untrusted input.

Minimum requirement:

- enforce an allowlist of accepted redirect URLs (or allowed hosts + paths)
- reject any return URL not explicitly allowed for the calling app
- never redirect to arbitrary user-provided domains

Recommended hardening:

- use exact URL matching whenever possible
- normalize URL before matching (scheme, host, port, path)
- issue short-lived, single-use login tokens
- bind tokens/codes to the expected redirect target and app/client

Without server-side redirect validation, an attacker may abuse open redirects to capture one-time login tokens or codes.

## Auth server contract

This middleware expects the auth server to expose the following endpoints and behavior.

### 1) Browser login entrypoint

- Method: GET
- Path: /login
- Query params:
  - return (required): URL where the user should be sent back after login
- Behavior:
  - validate return against your allowlist policy
  - authenticate user
  - redirect browser back to the validated return URL, adding token=<one-time-token>

Example redirect after successful login:

- https://app.example.com/some/path?token=abc123

### 2) Token exchange

- Method: POST
- Path: /exchange
- Content-Type: application/x-www-form-urlencoded
- Body:
  - token=<one-time-token>

Expected response on success:

- Status: 200
- JSON body:

```json
{
  "session": "session-id",
  "user": "alice",
  "email": "alice@example.com",
  "headers": {
    "X-User": "alice"
  }
}
```

Expected response on failure:

- Any non-200 status (middleware will redirect to login)

Notes:

- token should be short-lived and single-use
- token must be invalidated atomically when exchanged

### 3) Session check

- Method: GET
- Path: /check
- Auth input:
  - session cookie with the configured cookie_name

Expected response on valid session:

- Status: 200
- Identity headers returned as HTTP response headers (typically X-* headers)

Expected response on invalid/expired session:

- Any non-200 status (middleware clears cookie and redirects to login)

Notes:

- only trusted headers should be returned
- middleware forwards X-* response headers from /check to upstream request headers

### 4) Logout

- Method: POST
- Path: /logout
- Auth input:
  - session cookie with the configured cookie_name

Expected response:

- any status is acceptable to middleware
- middleware always clears local cookie and redirects browser to public_auth_server base URL

### URL roles used by middleware

- auth_server:
  - internal/server-to-server base URL
  - used for /exchange, /check, /logout
- public_auth_server (optional):
  - browser-facing base URL used for redirects
  - used for /login redirects and post-logout redirect
  - defaults to auth_server if omitted

## Build locally

From this repository root:

docker build -t ghcr.io/etienne-dldc/caddy-auth-middleware:local .

## Use from another stack

Example docker compose service:

services:
  caddy:
    image: ghcr.io/etienne-dldc/caddy-auth-middleware:latest
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./sites:/etc/caddy/sites:ro

## How the image is built

The Dockerfile uses xcaddy in a builder stage:
- compile Caddy
- include this plugin with --with github.com/etienne-dldc/caddy-auth-middleware=/src
- copy the final caddy binary into a runtime caddy image
