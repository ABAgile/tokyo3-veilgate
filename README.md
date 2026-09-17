# tokyo3-Veilgate

[![Release](https://img.shields.io/github/v/release/abagile/tokyo3-veilgate?sort=semver&logo=Go&color=%23007D9C)](https://github.com/abagile/tokyo3-veilgate/releases)
[![Test](https://github.com/abagile/tokyo3-veilgate/actions/workflows/test.yml/badge.svg)](https://github.com/abagile/tokyo3-veilgate/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/abagile/tokyo3-veilgate.svg)](https://pkg.go.dev/github.com/abagile/tokyo3-veilgate)
[![Go Report Card](https://goreportcard.com/badge/github.com/abagile/tokyo3-veilgate)](https://goreportcard.com/report/github.com/abagile/tokyo3-veilgate)
[![codecov](https://codecov.io/gh/abagile/tokyo3-veilgate/branch/main/graph/badge.svg)](https://codecov.io/gh/abagile/tokyo3-veilgate)

Veilgate is a secret-aware egress gateway for agent sandboxes. The daemon
binary is `veilgated`.

The current development stage provides a deliberately narrow security baseline:

- HTTPS-only forward proxy access with no plaintext proxy listener;
- controlled HTTPS interception for HTTP/2 and HTTP/1.1, with an opaque
  fallback when no interception CA is configured;
- explicit per-CONNECT HTTP/2 stream caps sized against the mediation limit;
- lifecycle-scoped bearer or Basic proxy credentials;
- per-client hostname and port allowlists;
- DNS resolution followed by public-address validation and IP-pinned dialing;
- bounded host/IP/port-keyed persistent upstream transports with HTTP/2
  multiplexing and HTTP/1.1 keep-alive;
- private, link-local, special-use, and direct-IP destination blocking;
- CONNECT-authority, TLS SNI, and decrypted HTTP Host consistency checks;
- persisted CONNECT session IDs grouping enclosed HTTP and WebSocket flows;
- short-lived, in-memory interception leaf certificates;
- host-side, client-and-host-scoped HTTPS header, query, JSON, form, and
  WebSocket JSON secret substitution;
- response-side configured-secret scrubbing for HTTP and HTTPS headers and
  bodies, plus WebSocket text/control frames;
- configured OAuth access/refresh-token virtualization with plaintext persisted
  recovery state in `/var/lib/veilgate/auth.json`;
- flush-preserving SSE and NDJSON response mediation with gzip, deflate,
  Brotli, and Zstandard support;
- bounded sanitized query, body, and WebSocket text capture plus metadata-only
  binary WebSocket records with SQLite persistence or in-memory fallback;
- read-only filtered web console with live SSE and policy-decision traces;
- bounded asynchronous flow recording with runtime backpressure warnings and a
  short priority wait for denied decisions;
- optional NATS JetStream audit publication through `tokyo3-base`.

Request replay and policy editing are **not implemented**. WebSocket mediation
supports text and binary messages plus `permessage-deflate` only when both
no-context-takeover parameters are negotiated. Binary bytes are forwarded but
never persisted; direction, size, and SHA-256 are retained. Sanitized HTTP
headers are captured, but authentication, cookie, token, API-key, credential,
secret, and proxy-credential values are redacted.
Configured secret values and placeholders are replaced by `[secret:name]`
markers before query strings, supported textual bodies, or frames are stored.

## Installation

### Published container image

Tagged releases publish a multi-architecture image for `linux/amd64` and
`linux/arm64` to GitHub Container Registry. The image contains the
`veilgated` daemon and uses `veilgated serve` as its default command:

```text
ghcr.io/abagile/tokyo3-veilgate:<version>
```

Pin a release rather than using `latest` in a deployment. For example:

```sh
docker pull ghcr.io/abagile/tokyo3-veilgate:0.1.0
docker run --rm ghcr.io/abagile/tokyo3-veilgate:0.1.0 version
```

### Image-based Compose setup

The following is a minimal deployment that runs the published image; it does
not require a Go installation or a checkout of this repository. Save it as
`compose.yml` in a separate deployment directory. The proxy is available only
to containers on the sandbox network, while the console is published to host
loopback. The two listener
addresses deliberately use network-specific aliases so sandbox containers
cannot reach the management listener through the sandbox network. The
checked-in `compose.yml` remains the source-build development rig described
under [Run](#run).

```yaml
services:
  veilgated:
    image: "${VEILGATE_IMAGE:-ghcr.io/abagile/tokyo3-veilgate:0.1.0}"
    command: ["serve"]
    user: "${VEILGATE_UID:-65532}:${VEILGATE_GID:-65532}"
    restart: unless-stopped
    init: true
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    environment:
      VEILGATED_ADDR: "veilgated-proxy:${VEILGATED_PROXY_PORT:-8080}"
      VEILGATED_CONSOLE_ADDR: "veilgated-console:${VEILGATED_CONSOLE_PORT:-8081}"
      VEILGATED_CONSOLE_USERNAME: "${VEILGATED_CONSOLE_USERNAME:?set VEILGATED_CONSOLE_USERNAME}"
      VEILGATED_CONSOLE_PASSWORD: "${VEILGATED_CONSOLE_PASSWORD:?set VEILGATED_CONSOLE_PASSWORD}"
      # An empty value is harmless when config/secrets.json is absent.
      VEILGATED_DEV_API_KEY: "${VEILGATED_DEV_API_KEY:-}"
    volumes:
      - type: bind
        source: ./config
        target: /etc/veilgate
        read_only: true
      - type: bind
        source: ./data
        target: /var/lib/veilgate
    ports:
      - "127.0.0.1:${VEILGATED_CONSOLE_PORT:-8081}:${VEILGATED_CONSOLE_PORT:-8081}"
    networks:
      management:
        aliases:
          - veilgated-console
      sandbox:
        aliases:
          - veilgated-proxy

networks:
  management:
    name: "${VEILGATE_MANAGEMENT_NETWORK:-veilgate-management}"
  sandbox:
    name: "${VEILGATE_SANDBOX_NETWORK:-veilgate-sandbox}"
```

Prepare the deployment directory and client policy. The example policy is a
starting point only: replace its development token, narrow its host and port
allowlist, and keep the resulting file private.

```sh
mkdir -p config data
chmod 700 config data

VERSION=0.1.0
RELEASE_TAG="v${VERSION}"
IMAGE="ghcr.io/abagile/tokyo3-veilgate:${VERSION}"
curl -fsSL \
  "https://raw.githubusercontent.com/abagile/tokyo3-veilgate/${RELEASE_TAG}/config/clients.example.json" \
  -o config/clients.json

# Generate a token of at least 24 characters and put it in clients.json.
openssl rand -base64 32
```

The static secret and OAuth policies are optional. Download and configure
them only when they are needed:

```sh
RELEASE_TAG="${RELEASE_TAG:-v0.1.0}"
# Static substitution (the example uses VEILGATED_DEV_API_KEY):
curl -fsSL \
  "https://raw.githubusercontent.com/abagile/tokyo3-veilgate/${RELEASE_TAG}/config/secrets.example.json" \
  -o config/secrets.json
# OAuth brokering:
curl -fsSL \
  "https://raw.githubusercontent.com/abagile/tokyo3-veilgate/${RELEASE_TAG}/config/oauth.example.json" \
  -o config/oauth.json
```

For a local test deployment, generate the proxy interception material with the
image itself and generate the console certificate with `mkcert`:

```sh
IMAGE="${IMAGE:-ghcr.io/abagile/tokyo3-veilgate:0.1.0}"
docker pull "$IMAGE"
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/config:/etc/veilgate" \
  "$IMAGE" ca init \
  --cert /etc/veilgate/intercept-ca.crt \
  --key /etc/veilgate/intercept-ca.key
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/config:/etc/veilgate" \
  "$IMAGE" ca sign \
  --ca-cert /etc/veilgate/intercept-ca.crt \
  --ca-key /etc/veilgate/intercept-ca.key \
  --cert /etc/veilgate/proxy.crt \
  --key /etc/veilgate/proxy.key \
  --san 'DNS:veilgated-proxy,DNS:localhost,IP:127.0.0.1,IP:::1'
mkcert -install
mkcert -cert-file config/console.crt -key-file config/console.key \
  localhost 127.0.0.1 ::1 veilgated.localhost
chmod 600 config/*key
```

For production, provision equivalent certificates and keys from the
organization's certificate or secret-management system instead. The proxy
certificate must contain the DNS names used by sandbox clients, and
`intercept-ca.crt` must be installed in each sandbox trust store. Never expose
`intercept-ca.key`, `proxy.key`, or `console.key` to a sandbox.

Run the image as a non-root deployment user. The Compose example defaults to
the image's `nonroot` UID (`65532`); when the files above are owned by the
current user, set the UID/GID and console credentials in `.env`:

```sh
cat > .env <<EOF
VEILGATE_IMAGE=ghcr.io/abagile/tokyo3-veilgate:0.1.0
VEILGATE_UID=$(id -u)
VEILGATE_GID=$(id -g)
VEILGATED_CONSOLE_USERNAME=operator
VEILGATED_CONSOLE_PASSWORD=$(openssl rand -hex 24)
# Set this when config/secrets.json is present.
# VEILGATED_DEV_API_KEY=replace-with-a-real-development-secret
EOF
chmod 600 .env

docker compose pull
docker compose up -d
docker compose logs -f veilgated
```

If `config/secrets.json` is present, uncomment and set its value environment
variable in `.env`; for the checked-in example this is
`VEILGATED_DEV_API_KEY`. A non-empty `config/oauth.json` enables the OAuth
broker and stores its plaintext recovery state in `data/auth.json`. Protect
both the `data` directory and its backups.

Containers attached to the sandbox network use
`https://veilgated-proxy:8080` and must trust `config/intercept-ca.crt`. A
sandbox in another Compose project can join the same network by declaring
`veilgate-sandbox` as an external network, or with:

```sh
docker network connect "${VEILGATE_SANDBOX_NETWORK:-veilgate-sandbox}" <sandbox-container>
```

The console is available at `https://127.0.0.1:8081` in this example;
`/healthz` is unauthenticated, while the other console routes require the
configured Basic credentials. Keep the management network private and put any
non-loopback console endpoint behind an authenticated operator gateway. Stop
the deployment without deleting its state with:

```sh
docker compose down
```

## Build

Compile `veilgated` into `bin/veilgated`:

```sh
make build
```

Build the server image locally:

```sh
make docker-build
```

The default image is `abagile/tokyo3-veilgate:dev-<commit>`. Override
`IMAGE_NAME`, `IMAGE_TAG`, and `TARGETARCH` as needed.

## Configure

Copy the example policy and replace the token with a cryptographically random
value of at least 24 characters:

```sh
cp config/clients.example.json config/clients.json
cp config/secrets.example.json config/secrets.json
cp config/oauth.example.json config/oauth.json
openssl rand -base64 32
```

A client allows exact hosts or leftmost-label wildcards:

```json
{
  "clients": [
    {
      "name": "agent-dev",
      "token": "a-long-random-lifecycle-scoped-token",
      "allowed_hosts": ["api.openai.com", "*.npmjs.org"],
      "opaque_hosts": ["registry.npmjs.org"],
      "allowed_ports": [443]
    }
  ]
}
```

`*.example.com` matches subdomains but not `example.com`. Direct IP targets are
rejected. When `allowed_ports` is omitted it defaults to `[443]`.

`opaque_hosts` uses the same exact-host and leftmost-label wildcard syntax. It
only selects the mediation mode; a destination must still pass `allowed_hosts`
(or `observe_all_public_hosts`) and `allowed_ports`. For HTTPS CONNECT targets
listed there, Veilgate keeps the connection as an opaque TCP tunnel even when
TLS interception is enabled. Authentication, public-DNS/IP checks, timeouts,
byte accounting, and audit recording still apply, but TLS application contents,
secret substitution, and application-data captures are unavailable for that session.

For a short-lived broad-egress client, explicit host matching can be replaced
with authenticated access to any valid hostname whose resolved address passes
Veilgate's public-IP checks:

```json
{
  "clients": [{
    "name": "inspection-agent",
    "token": "a-separate-short-lived-random-token",
    "observe_all_public_hosts": true,
    "allowed_ports": [443]
  }]
}
```

`observe_all_public_hosts` does not permit direct IP targets,
private/special-use addresses, or ports outside `allowed_ports`. With TLS
interception enabled, it also permits HTTPS content inspection; without
interception, HTTPS CONNECT sessions remain opaque TCP tunnels while
authentication, public-DNS resolution, port checks, timeouts, byte accounting,
and audit recording still apply. If `allowed_hosts` is also present, it is
redundant for this client's destination policy. This mode removes hostname
allowlisting as an egress boundary and should be limited to isolated
sandboxes with short retention and credentials.

### Secret substitution

Secret definitions contain an opaque sandbox-visible placeholder and the name
of a host-only environment variable holding the real value. Environment
variables automatically receive the `VEILGATED_` prefix, and placeholders
automatically receive the `VEILGATED_SECRET_` prefix if not already present:

```json
{
  "secrets": [{
    "name": "openai_api_key",
    "value_env": "VEILGATED_OPENAI_KEY",
    "placeholder": "VEILGATED_SECRET_high_entropy_random_value",
    "clients": ["agent-dev"],
    "allowed_hosts": ["api.openai.com"]
  }]
}
```

Set `VEILGATED_SECRETS_FILE` (or place a non-empty file at its default
`/etc/veilgate/secrets.json` path) to enable the broker. Missing or empty files
are ignored. Placeholders are replaced
after client, destination, SNI, Host, DNS, and IP checks pass. Supported
placements are HTTPS header values, exact query values, exact JSON string
values, exact form values, and exact JSON string values in outbound WebSocket
text messages. Basic authentication values are decoded, substituted, and
re-encoded. Embedded placeholder text inside JSON string or form values is
preserved as ordinary content unless it is the complete value. Placeholder
occurrences in headers, query names or values, JSON/form field names, URL paths,
binary or unsupported bodies, plaintext HTTP use, and use outside the
configured client/host scope fail closed. Secret definitions retain their
independent `clients` and `allowed_hosts` checks when a client enables
`observe_all_public_hosts`; broad destination observation never broadens a
secret's authorized hosts.

Resolved secret values must be 8–16384 bytes so response matching remains
specific. Configured values reflected through HTTPS response headers, bodies,
and WebSocket frames are replaced with the corresponding placeholder before the
sandbox receives them. Common URL, JSON, Base64, and prefix/mask/suffix
reflections are also detected.
Captures then replace both values and placeholders with
`[secret:name]`. The audit stream records names only and does not include
captured content.

### OAuth token broker

Dynamic OAuth virtualization is configured separately from static
`secrets.json` definitions:

```json
{
  "brokers": [{
    "name": "example",
    "clients": ["agent-dev"],
    "issuer_host": "login.example.com",
    "token_path": "/oauth/token",
    "api_hosts": ["api.example.com"],
    "access_token_field": "access_token",
    "refresh_token_field": "refresh_token"
  }]
}
```

Set `VEILGATED_OAUTH_FILE` (or place a non-empty file at its default
`/etc/veilgate/oauth.json` path) to enable a broker. Missing or empty files
are ignored. A successful configured token
response is rewritten for the sandbox with virtual access and refresh tokens.
A broker may optionally set `access_placeholder_prefix` when its client
requires a recognizable access-token shape; the prefix is preserved in the
virtual opaque token only when the real token starts with it. For example, the
Anthropic policy uses `"access_placeholder_prefix": "sk-ant-oat"`.
Subsequent requests containing those virtual values are replaced with the real
values only for the configured issuer/API hosts and sandbox client. Refresh
responses update the mapping; a response that omits `refresh_token` preserves
the existing refresh mapping as permitted by OAuth deployments.

Substitution is confined to the locations where a token legitimately travels.
Headers and query values are credential-carrying: a placeholder-shaped value
that resolves to no live token is rejected there, because it can only mean a
stale, rotated, or forged credential. Request bodies and WebSocket text carry
agent content, so they are substituted only for the configured issuer host,
where the refresh request lives. A live placeholder quoted in a body bound for
an API host — an agent reading back its own credential store or a log — is
forwarded verbatim and stays inert rather than being expanded into the real
token, and unknown placeholder-shaped text is never treated as a credential.

The real token mapping is persisted as **unencrypted plaintext** in
`VEILGATED_AUTH_FILE`, defaulting to `/var/lib/veilgate/auth.json`. The
Compose deployment stores this file beside `flows.db` in the single
`data`/`/var/lib/veilgate` volume. The file is written mode `0600` using
atomic replacement and is never mounted into a sandbox. Protect the volume and
backups; encryption at rest is not implemented yet.

`auth.json` is runtime state, not policy. It contains real access/refresh token
values for recovery and examination, while flow captures, audit events, logs,
and the console expose only virtual-token names or `[secret:name]` markers.
The broker supports opaque OAuth tokens. JWT access tokens are represented by
virtual JWTs that preserve the real JOSE header and payload claims, including
claims such as `sub`, `email`, `scope`, tenant/org identifiers, and `exp`; only
the signature is replaced with a dummy signature and an internal `_veilgate_id`
claim is added. Those claims are therefore visible to the sandbox: JWT
virtualization is not an opaque or claim-redacting mode. Virtual JWTs, like
opaque placeholders, are rejected in credential-bearing headers and query
values after their mapping is rotated or if they are forged. Applications that
locally validate JWT signatures, use DPoP or mTLS-bound tokens, or depend on
token fingerprints may need a specialized adapter and are not transparent under
this mode.

The checked-in `config/oauth.example.json` is mounted by Compose as an example
policy. OAuth brokering is enabled when `VEILGATED_OAUTH_FILE` is set or when
non-empty `/etc/veilgate/oauth.json` exists. Missing or empty files are
ignored. Replace the example or provide a deployment-specific OAuth policy
before using a real issuer; ensure the issuer and API hosts are also allowed by
the client policy.

### TLS interception CA

The proxy listener is always HTTPS and requires a proxy certificate and key.
The development proxy certificate is signed by the interception CA so one
public trust anchor can be installed in the sandbox. The management console is
also HTTPS; its development leaf certificate is signed by the local `mkcert`
root CA. Generate development material without overwriting existing files:

```sh
mkcert -install
make gen-certs
```

`mkcert -install` creates the local root CA when needed and installs its trust
anchor for the current development user. The Make target uses the root CA
reported by `mkcert -CAROOT` and refuses to generate the console certificate
if `rootCA.pem` is absent.

```sh
make gen-certs
```

For manual bootstrap, the Make target runs the equivalent commands:

```sh
veilgated ca init \
  --cert config/intercept-ca.crt --key config/intercept-ca.key
veilgated ca sign \
  --ca-cert config/intercept-ca.crt --ca-key config/intercept-ca.key \
  --cert config/proxy.crt --key config/proxy.key
mkcert -cert-file config/console.crt -key-file config/console.key \
  localhost 127.0.0.1 ::1 veilgated.localhost veilgated
```

These commands refuse to overwrite existing files. `ca sign` generates a
separate proxy endpoint key and signs it with the interception CA. `mkcert`
generates a separate console endpoint key and signs it with its `rootCA.pem`.

Make stores the development material in the default project configuration
folder:

- `config/intercept-ca.crt` is the public trust anchor to install in the
  sandbox;
- `config/intercept-ca.key` is the development signing key and stays with
  Veilgate;
- `config/proxy.crt` is the HTTPS proxy endpoint certificate;
- `config/proxy.key` is the HTTPS proxy endpoint private key and stays with
  Veilgate;
- `config/console.crt` is the HTTPS management-console certificate;
- `config/console.key` is the HTTPS management-console private key and stays
  with Veilgate.

The proxy endpoint certificate is a separately keyed leaf signed by the
interception CA; the CA private key is never used as the proxy endpoint key.
The console certificate is a separately keyed `mkcert` leaf signed by the
local development `rootCA.pem`. HTTPS interception is enabled when both
interception CA paths are configured.

The Compose development rig mounts the generated CA, proxy, and console files
from the external `tokyo3_hq_proj` volume using paths relative to
`abagile/veilgate/`; no host bind path is required. Generated certificate and
key material is gitignored. This shared-project arrangement is for the
containerized development rig only. Production deployments should keep the
private key outside sandbox-visible storage and provision a dedicated
interception CA through their secret-management process.

## Run

Run directly from source:

```sh
VEILGATED_CLIENTS_FILE=config/clients.json \
VEILGATED_INTERCEPT_CA_CERT=config/intercept-ca.crt \
VEILGATED_INTERCEPT_CA_KEY=config/intercept-ca.key \
VEILGATED_PROXY_CERT=config/proxy.crt \
VEILGATED_PROXY_KEY=config/proxy.key \
VEILGATED_CONSOLE_CERT=config/console.crt \
VEILGATED_CONSOLE_KEY=config/console.key \
VEILGATED_SECRETS_FILE=config/secrets.json \
VEILGATED_OAUTH_FILE=config/oauth.json \
VEILGATED_AUTH_FILE=./var/auth.json \
VEILGATED_DATABASE_URL=sqlite:./var/flows.db \
VEILGATED_DEV_API_KEY=replace-me \
  go run ./cmd/veilgated serve
```

The sandbox must trust `config/intercept-ca.crt` for both the HTTPS proxy
endpoint and intercepted destination certificates; it does not need either
private key. Configure the proxy URL with an `https://` scheme. There is no
plaintext HTTP proxy fallback. Because the development key resides
on the shared project volume, treat it as disposable and never reuse it outside
this test rig. CA material is loaded at daemon startup, so CA rotation currently
requires restarting `veilgated`.

For a local Compose test deployment, provide console credentials and run:

```sh
VEILGATED_CONSOLE_USERNAME=operator \
VEILGATED_CONSOLE_PASSWORD='replace-with-a-secret' \
  make docker-up
```

This command performs the complete test-run sequence:

1. builds a local `bin/veilgated` helper for certificate generation;
2. creates or reuses the project-local development interception CA;
3. builds the server image for the configured target platform as
   `abagile/tokyo3-veilgate:dev-<commit>`;
4. creates the external `tokyo3_hq_sandbox` network when absent;
5. requires the existing `tokyo3_hq_default` management network; and
6. starts `compose.yml` and waits for the service to run.

The Compose rig mounts `config/clients.example.json`,
`config/secrets.example.json`, and `config/oauth.example.json`, persists flows
and OAuth state in the single `data` volume, and uses this development proxy
identity:

```text
client: agent-dev
token:  use the development value in config/clients.example.json
```

The console listens on the `tokyo3_hq_default` management network at
`https://veilgated.localhost:8081` and is published to host loopback at
`https://127.0.0.1:8081` by default. Browsers must trust the mkcert root CA
reported by `mkcert -CAROOT`. It is not reachable by containers on
`tokyo3_hq_sandbox`. The current development credentials are supplied through
`VEILGATED_CONSOLE_USERNAME` and `VEILGATED_CONSOLE_PASSWORD`; do not use
the development defaults beyond an isolated network. Veilgated requires both
credentials when `VEILGATED_CONSOLE_ADDR` is not a loopback address. A loopback
console may omit both credentials, but the daemon logs an explicit
unauthenticated warning.
Sandbox containers on `tokyo3_hq_sandbox` can reach the
proxy at `https://veilgated-proxy:8080` by default; set
`VEILGATED_PROXY_PORT` to change the sandbox-facing listener port. The proxy
is not published to the host.

Stop the test deployment with:

```sh
make docker-down
```

Compose variables `VEILGATED_PROXY_PORT` (default `8080`) and
`VEILGATED_CONSOLE_PORT` (default `8081`) control the sandbox-facing proxy
listener and host-published console listener respectively. `IMAGE_NAME`,
`IMAGE_TAG`, and `TARGETARCH` may be passed to Make to customize image
packaging. The Makefile defaults `INTERCEPT_CA_CERT` and `INTERCEPT_CA_KEY` to
`config/intercept-ca.crt` and `config/intercept-ca.key`, `PROXY_CERT` and
`PROXY_KEY` to `config/proxy.crt` and `config/proxy.key`, and `CONSOLE_CERT`
and `CONSOLE_KEY` to `config/console.crt` and `config/console.key`; Compose
uses their filenames in the mounted `/etc/veilgate` config directory. The
Compose development service runs as UID/GID 1000 so it can read the mode-0600
keys created by the development container user through `tokyo3_hq_proj`. The
`data` volume must be initialized manually with matching ownership; Compose
intentionally has no privileged init container.

Set both console credential variables before starting Compose. Keep the
management network private and place the console behind an authenticated
operator gateway.

Test development secret substitution from a container attached to
`tokyo3_hq_sandbox` by placing the configured placeholder in a request header.
The Compose default resolves it from `VEILGATED_DEV_API_KEY`:

```sh
curl --proxy https://veilgated-proxy:8080 \
  --proxy-cacert config/intercept-ca.crt \
  --proxy-user 'agent-dev:YOUR_PROXY_TOKEN' \
  --cacert config/intercept-ca.crt \
  -H 'Authorization: Bearer VEILGATED_SECRET_5f73a1c9e2b84d60a7f3' \
  https://api.openai.com/v1/models
```

Override `VEILGATED_DEV_API_KEY` with a real development credential when
starting Compose. Do not use the checked-in development default outside this
test rig.

Configure a client using bearer proxy authentication. The proxy URL must use
`https://`; plaintext proxy connections are rejected because no HTTP listener
is started:

```sh
curl --proxy https://veilgated-proxy:8080 \
  --proxy-cacert config/intercept-ca.crt \
  --proxy-header 'Proxy-Authorization: Bearer YOUR_TOKEN' \
  --cacert config/intercept-ca.crt \
  https://api.openai.com/
```

For capture-display testing, temporarily allow `httpbin.org`,
`postman-echo.com`, and `echo.websocket.org` on port 443. These public endpoints
must not receive real credentials or sensitive prompts:

```sh
# JSON, HTML, JSONL-style streaming records, and an echoed JSON request.
curl --proxy https://veilgated-proxy:8080 --proxy-cacert config/intercept-ca.crt \
  --proxy-user "agent-dev:$TOKEN" --cacert config/intercept-ca.crt https://httpbin.org/json
curl --proxy https://veilgated-proxy:8080 --proxy-cacert config/intercept-ca.crt \
  --proxy-user "agent-dev:$TOKEN" --cacert config/intercept-ca.crt https://httpbin.org/html
curl --proxy https://veilgated-proxy:8080 --proxy-cacert config/intercept-ca.crt \
  --proxy-user "agent-dev:$TOKEN" --cacert config/intercept-ca.crt https://httpbin.org/stream/3
curl --proxy https://veilgated-proxy:8080 --proxy-cacert config/intercept-ca.crt \
  --proxy-user "agent-dev:$TOKEN" --cacert config/intercept-ca.crt \
  -H 'Content-Type: application/json' --data '{"agent":"veilgate","step":1}' \
  https://postman-echo.com/post

# Uncompressed WSS text-frame echo.
npx --yes wscat --connect wss://echo.websocket.org \
  --proxy "https://agent-dev:$TOKEN@veilgated-proxy:8080" \
  --ca config/intercept-ca.crt --execute '{"agent":"veilgate","step":1}' \
  --wait 2
```

Or use Basic proxy credentials, where the username is the configured client
name and the password is its token:

```sh
HTTPS_PROXY=https://agent-dev:YOUR_TOKEN@veilgated-proxy:8080 \
  SSL_CERT_FILE=config/intercept-ca.crt \
  curl https://api.openai.com/
```

Proxy credentials identify the sandbox; they are removed before forwarding and
never captured. Proxy environment variables alone are not an isolation
boundary. A sandbox deployment must block direct egress and access to other
clients' proxy endpoints.

### Capture security

Sanitized headers, query strings, supported request and response bodies, and
WebSocket text messages are retained in plaintext for operator
inspection. This can include unrelated credentials, personal data, prompts,
and model output that do not match a configured secret. Protect the console,
SQLite database, and plaintext OAuth `auth.json` accordingly, use short
retention, and do not treat configured secret scrubbing as general-purpose
data-loss prevention.

Ordinary HTTP bodies are mediated up to
`VEILGATED_MEDIATION_LIMIT_BYTES`; retained content is independently bounded by
`VEILGATED_CAPTURE_LIMIT_BYTES` and marked truncated without rejecting otherwise
safe traffic. Flow records keep `bytes_received` as the received/forwarded body
count and `bytes_received_decoded` as the decompressed response-body count when
mediation completes; the latter is zero when decoding is unavailable or the
flow has no mediated response body. SSE events and NDJSON records are scrubbed
and flushed incrementally; the mediation limit applies to each decoded event
or record, not the complete stream. The intercepted HTTP/2 stream cap reserves
up to 512 MiB of mediation buffer budget, so increasing this limit reduces the
number of concurrently admitted streams. HTTP `gzip`, `deflate`, Brotli (`br`), and Zstandard
(`zstd`) bodies and streams
are decoded for substitution, scrubbing, and capture, then re-encoded with their
original coding. Stacked or unknown codings fail closed. WebSocket text and
binary messages use the mediation limit. Outbound binary
placeholders and inbound configured secret material fail closed; binary bytes
are never persisted. Because a rejected frame drops the connection rather than
returning a status, the placeholder names involved are recorded on the flow and
in the failure reason so the drop is attributable; values are never included.
Unsupported HTTP binary response bodies are scrubbed before forwarding but
marked omitted in capture. When an upstream response omits `Content-Type`, Veilgate
conservatively recognizes valid SSE or JSON bodies for capture; other bodies
remain omitted.

## Environment

| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `VEILGATED_CLIENTS_FILE` | no | `/etc/veilgate/clients.json` | JSON client policy path |
| `VEILGATED_ADDR` | no | `127.0.0.1:8080` | HTTPS proxy listen address; proxy TLS is required |
| `VEILGATED_CONSOLE_ADDR` | no | `127.0.0.1:8081` | HTTPS console and API address |
| `VEILGATED_CONSOLE_CERT` | no | `/etc/veilgate/console.crt` | HTTPS console certificate PEM |
| `VEILGATED_CONSOLE_KEY` | no | `/etc/veilgate/console.key` | Matching HTTPS console private key PEM |
| `VEILGATED_CONSOLE_USERNAME` | conditional | — | Console HTTP Basic username; required with the password for non-loopback console addresses |
| `VEILGATED_CONSOLE_PASSWORD` | conditional | — | Console HTTP Basic password; required with the username for non-loopback console addresses |
| `VEILGATED_FLOW_RETENTION` | no | `1000` | Retained flow limit, 1–100000 |
| `VEILGATED_DATABASE_URL` | no | `sqlite:/var/lib/veilgate/flows.db` | `sqlite:<path>` durable flow store |
| `VEILGATED_SECRETS_FILE` | no | `/etc/veilgate/secrets.json` when non-empty | Static secret definitions JSON; requires interception |
| `VEILGATED_OAUTH_FILE` | no | `/etc/veilgate/oauth.json` when non-empty | OAuth broker policy JSON; requires interception |
| `VEILGATED_AUTH_FILE` | no | `/var/lib/veilgate/auth.json` | Plaintext OAuth runtime token state |
| `VEILGATED_DIAL_TIMEOUT` | no | `10s` | Upstream connection timeout |
| `VEILGATED_SESSION_IDLE_TIMEOUT` | no | `5m` | Close proxy sessions after inactivity; 1s–24h |
| `VEILGATED_SESSION_MAX_DURATION` | no | `30m` | Maximum proxy request/session lifetime; at most 168h |
| `VEILGATED_UPSTREAM_RESPONSE_HEADER_TIMEOUT` | no | `60s` | Maximum wait for upstream response headers; 1s–10m |
| `VEILGATED_CAPTURE_LIMIT_BYTES` | no | `1048576` | Maximum retained bytes per capture section; 1024–4194304 |
| `VEILGATED_MEDIATION_LIMIT_BYTES` | no | `8388608` | Maximum decoded body or WebSocket message; also sizes the intercepted HTTP/2 stream cap; at least capture limit, at most 67108864 |
| `VEILGATED_RECORD_QUEUE_CAPACITY` | no | `256` | Completed flows buffered for asynchronous recording; at least 1 |
| `VEILGATED_RECORD_WORKERS` | no | `4` | Concurrent flow-recording workers; at least 1 |
| `VEILGATED_INTERCEPT_CA_CERT` | no | `/etc/veilgate/intercept-ca.crt` when present | Interception CA certificate PEM |
| `VEILGATED_INTERCEPT_CA_KEY` | no | `/etc/veilgate/intercept-ca.key` when present | Matching interception CA key PEM |
| `VEILGATED_PROXY_CERT` | no | `/etc/veilgate/proxy.crt` | HTTPS proxy server certificate PEM |
| `VEILGATED_PROXY_KEY` | no | `/etc/veilgate/proxy.key` | Matching HTTPS proxy server private key PEM |
| `VEILGATED_DEBUG_ADDR` | no | disabled | Unauthenticated diagnostics address |
| `VEILGATED_NATS_URL` | no | disabled | NATS URL for flow audit events |
| `VEILGATED_NATS_CERT/KEY/CA` | no | workload material | NATS mTLS override |
| `VEILGATED_WORKLOAD_CERT/KEY/CA` | no | — | Shared Tokyo3 workload material |

The policy and certificate files marked as required remain required material;
the `no` values mean their environment variables may be omitted when the
files are at the documented defaults.

Compose variables `VEILGATED_PROXY_PORT` (default `8080`) and
`VEILGATED_CONSOLE_PORT` (default `8081`) control the sandbox-facing proxy
listener and host-published console listener respectively. `IMAGE_NAME`,
`IMAGE_TAG`, and `TARGETARCH` may be passed to Make to customize image
packaging. The Makefile defaults `INTERCEPT_CA_CERT` and `INTERCEPT_CA_KEY` to
`config/intercept-ca.crt` and `config/intercept-ca.key`, `PROXY_CERT` and
`PROXY_KEY` to `config/proxy.crt` and `config/proxy.key`, and `CONSOLE_CERT`
and `CONSOLE_KEY` to `config/console.crt` and `config/console.key`; Compose
uses their filenames in the mounted `/etc/veilgate` config directory. The
Compose development service runs as UID/GID 1000 so it can read the mode-0600
keys created by the development container user through `tokyo3_hq_proj`. The
`data` volume must be initialized manually with matching ownership; Compose
intentionally has no privileged init container.

Set both console credential variables when the console address is not
loopback; a lone variable is invalid. On a loopback address, both may be
omitted, but the daemon logs that the console is running unauthenticated. Keep
the `tokyo3_hq_default` management network private and place the console behind
an authenticated operator gateway. `/healthz` remains unauthenticated on the
management listener.

## HTTP surfaces

Proxy listener (HTTPS only):

- standard absolute-form HTTP proxy requests inside the proxy TLS connection;
- HTTPS `CONNECT host:port` requests, intercepted as HTTP/2 or HTTP/1.1 when CA
  material is configured;
- WSS upgrades with bounded text/binary mediation and no-context-takeover
  `permessage-deflate`; other selected extensions fail closed;
- `Proxy-Authorization: Bearer <token>`; or
- Basic proxy authentication using `<client-name>:<token>`.

Console listener:

- `GET /` — traffic console;
- `GET /healthz` — readiness response;
- `GET /api/v1/flows` — a newest-first page of flow summaries; optional
  exact-match `client`, `host`, `decision`, and `mode` filters, a `limit`, and a
  `before_id` keyset cursor. The response is an object with `flows`,
  `next_before_id` (cursor for the next older page), `has_more`, and
  `session_parents` (CONNECT parents supplied to complete groups whose parent
  precedes the page);
- `GET /api/v1/flows/{id}` — one retained flow with detailed sanitized capture;
- `GET /api/v1/events` — live flow-summary events over SSE with the same
  filters; the live tail ignores `before_id`.

Flows contain identity, CONNECT session ID, method, scheme, destination,
sanitized path, mediation mode, independently negotiated downstream/upstream
HTTP protocols, selected IP, policy trace, substituted and
scrubbed secret names, status, byte counts, duration, and a bounded error
reason. Intercepted HTTPS additionally retains bounded sanitized headers, query
values, supported textual request/response bodies, and WebSocket text messages.
Binary WebSocket records retain direction, size, and SHA-256 only.
Credential-bearing header values are `[redacted]`. Placeholders, configured
secret values, HTTP binary payloads, WebSocket binary bytes, and proxy
credentials are not retained. The console prettifies HTML, JSON, and
JSONL/NDJSON captures with built-in text-only formatter plugins and syntax
highlighting; each
formatted view can be switched back to the exact retained raw text. The flow
list always fills the workspace and loads newest-first in bounded pages,
revealing older flows through an end-of-list sentinel that auto-loads plus an
explicit "Load older flows" control. Selecting a flow opens an inline,
height-bounded detail drawer directly beneath its row, organized into Overview,
Request, Response, and WebSocket tabs; selecting the row again closes it.
CONNECT rows form collapsible session parents with enclosed requests beneath.

## Design

[`DESIGN.md`](DESIGN.md) is authoritative for the web console. It inherits the
Tokyo3 operations-console foundation and uses a deep-cyan palette to remain
distinct from Tokyo3 Auth and CA.

## License

Apache-2.0. See [LICENSE](LICENSE).
