# Contributing

Authrim Wordwarden is early public beta software. The project welcomes bug
reports, deployment feedback, documentation corrections, and small focused
patches.

## Before You Start

- Read `README.md`, `docs/getting-started.md`, and `docs/production-hardening.md`.
- For security issues, follow `SECURITY.md` instead of opening a public issue.
- Keep changes narrowly scoped. Avoid unrelated refactors in feature or fix
  patches.

## Development

Use Go 1.25 or newer.

```sh
go test ./...
go run ./cmd/wordwarden --config config.example.yaml config validate
docker build -t authrim-wordwarden:dev .
```

The OpenLDAP integration fixture is optional and guarded:

```sh
./test/integration/openldap/generate-certs.sh
docker compose -f test/integration/openldap/docker-compose.yml up -d
WORDWARDEN_LDAP_INTEGRATION=1 go test ./internal/adapters/ldap -run TestOpenLDAPIntegration
docker compose -f test/integration/openldap/docker-compose.yml down -v
```

## Patch Expectations

- Add or update tests for behavior changes.
- Keep password, secret, and directory data out of logs, test fixtures, and
  documentation.
- Update public docs when changing configuration, deployment shape, API
  behavior, or security boundaries.
- Preserve Apache-2.0 licensing.

## Pull Requests

Use concise PRs with:

- summary of the behavior change
- affected deployment modes
- tests run
- security considerations when the change touches authentication, LDAP, relay,
  logging, secrets, or tenant boundaries
