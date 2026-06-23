# Authrim Wordwarden

Authrim Wordwarden is a Directory Connector for Authrim.

It verifies directory-backed passwords against LDAP/Active Directory while keeping
the password verification path close to the organization's directory. Authrim can
then handle Passkey-first login, Email Code fallback, sessions, federation output,
audit correlation, and identity mapping.

## Status

Authrim Wordwarden is in early alpha.

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
- LDAP lookup modes: `search_then_bind`, `dn_template`, `direct_bind`
- local structured audit events with redacted username hashing
- username preprocessing
- connector concurrency protection hook
- connector storm protection for HMAC failures, malformed/replayed requests, and directory errors
- OpenLDAP integration fixture
- CI for tests, example config validation, and Docker image build

The guarded OpenLDAP integration test is available under
`test/integration/openldap`.

## Documentation

- [Getting started](docs/getting-started.md)
- [API contract](docs/api.md)
- [Configuration](docs/configuration.md)
- [Configuration examples](docs/config-examples.md)
- [Passwordless migration](docs/passwordless-migration.md)
- [Production hardening](docs/production-hardening.md)
- [Operations](docs/operations.md)
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
restart in Alpha.

Health check:

```bash
curl http://127.0.0.1:8080/healthz
```

LDAP diagnostics:

```bash
go run ./cmd/wordwarden --config config.example.yaml ldap test --tenant tenant-a
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
