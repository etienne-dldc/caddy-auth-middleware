FROM caddy:2-builder AS builder

WORKDIR /src
COPY . .

RUN xcaddy build \
  --with github.com/etienne-dldc/caddy-auth-middleware=/src

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
