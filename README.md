# Authrim Wordwarden

Authrim Wordwarden is a Directory Connector for Authrim.

It verifies directory-backed passwords against LDAP/Active Directory while keeping
the password verification path close to the organization's directory. Authrim can
then handle Passkey-first login, Email Code fallback, sessions, federation output,
audit correlation, and identity mapping.

## Status

Authrim Wordwarden is preparing for public beta. The first public beta target is
`v0.1.0-beta.1`.

The connector is intended for pilots where operators can run a small service
near LDAP/AD and understand the directory, network, TLS, and secret-management
boundaries. It is not a managed directory service and it does not turn Authrim
into a password database.

Current implementation slice:

- Go module
- Cobra CLI skeleton
- YAML config parsing and validation
- `env:` / `file:` secret references
- shallow `GET /healthz`
- `DirectoryClient` interface
- `go-ldap/ldap/v3` adapter
- `wordwarden ldap test`
- HMAC canonical request verifier with active/previous key support
- `POST /v1/auth/verify-password`
- outbound Authrim Relay WebSocket client for deployments without inbound exposure
- LDAP lookup modes: `search_then_bind`, `dn_template`, `direct_bind`
- local structured audit events with redacted username hashing
- username preprocessing
- connector concurrency protection hook
- connector storm protection for HMAC failures, malformed/replayed requests, and directory errors
- outbound relay protocol version negotiation and tenant/connector URL binding
- redacted diagnostics bundle, detailed health, and Prometheus-compatible counters
- OpenLDAP integration fixture
- CI for tests, example config validation, and Docker image build

The guarded OpenLDAP integration test is available under
`test/integration/openldap`.

## Deployment Modes

Wordwarden supports three deployment shapes:

| Mode | Inbound exposure | Typical use |
| --- | --- | --- |
| Direct HTTPS | Wordwarden exposes a hardened HTTPS endpoint | Existing reverse proxy, firewall, certificate, and monitoring operations are already mature. |
| Cloudflare Tunnel | Wordwarden stays private and `cloudflared` opens the outbound tunnel | Operators want a managed public hostname without publishing the connector host directly. |
| Authrim Relay | Wordwarden opens an outbound WebSocket to Authrim | The directory-side network should not expose an inbound connector endpoint. |

In every mode, HMAC remains the tenant/connector authentication boundary. Relay
mode reduces inbound exposure; it does not replace connector authentication.

## Security Model

- Wordwarden does not store plaintext passwords or password hashes.
- LDAP/AD remains the source of password truth.
- Password verification happens close to the organization's directory.
- Authrim stores sessions, profile data, Passkeys, Email Code state, and
  federation state, but not directory password credentials for this path.
- HMAC keys are tenant/connector scoped and support active/previous key
  rotation.
- Runtime LDAP paths require TLS verification; `--insecure` is diagnostic-only.
- Logs and audit events must not contain raw passwords.

See [SECURITY.md](SECURITY.md) and
[Production hardening](docs/production-hardening.md) before public pilots.

## Compatibility

`v0.1.0-beta.1` targets Authrim `0.3.2` or later with Directory Authentication
and Authrim Relay support enabled. Older Authrim deployments can use the direct
HTTPS connector path only if they include the Directory Password login
integration.

## Public Demo Paths

- Local OpenLDAP demo for a fully local verification path.
- Direct HTTPS or Cloudflare Tunnel demo for inbound connector deployments.
- Authrim Relay demo for outbound-only connector deployments.

## Documentation

- [Getting started](docs/getting-started.md)
- [Architecture overview](docs/architecture.md)
- [API contract](docs/api.md)
- [Configuration](docs/configuration.md)
- [Configuration examples](docs/config-examples.md)
- [Passwordless migration](docs/passwordless-migration.md)
- [Production hardening](docs/production-hardening.md)
- [Operations](docs/operations.md)
- [Outbound relay operations](docs/relay-operations.md)
- [Release process](docs/release.md)
- [Cloudflare Tunnel deployment](docs/cloudflare-tunnel.md)
- [Public HTTPS deployment](docs/public-https.md)
- [Deployment samples](deploy/README.md)

## Local Development

```bash
go test ./...
go run ./cmd/wordwarden --config config.example.yaml config validate
go run ./cmd/wordwarden --config config.example.yaml serve
```

Docker image:

```bash
docker build -t authrim-wordwarden:dev .
docker run --rm -p 8080:8080 \
  -v "$PWD/config.example.yaml:/etc/authrim-wordwarden/config.yaml:ro" \
  authrim-wordwarden:dev --config /etc/authrim-wordwarden/config.yaml serve
```

Deployment samples are under `deploy/`. Configuration changes require a process
restart in the current beta.

Health check:

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/healthz/details
curl http://127.0.0.1:8080/metrics
```

`/healthz/details` and `/metrics` are loopback-only by default. Expose them to
non-loopback clients only behind a private network or an allowlisted proxy.

LDAP diagnostics:

```bash
go run ./cmd/wordwarden --config config.example.yaml ldap test --tenant tenant-a
go run ./cmd/wordwarden --config config.example.yaml diagnostics bundle
```

OpenLDAP integration fixture:

```bash
./test/integration/openldap/generate-certs.sh
docker compose -f test/integration/openldap/docker-compose.yml up -d
WORDWARDEN_LDAP_INTEGRATION=1 go test ./internal/adapters/ldap -run TestOpenLDAPIntegration
docker compose -f test/integration/openldap/docker-compose.yml down -v
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
