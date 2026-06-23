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
    cookie_name tower_auth
    logout_path /logout
}

Subdirectives:
- auth_server: required auth server base URL
- cookie_name: optional, default tower_auth
- logout_path: optional, default /logout

The global options block in the Caddyfile should include:

order tower_auth before reverse_proxy

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
