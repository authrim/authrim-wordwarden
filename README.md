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

`verify-password` HTTP integration is next.

## Local Development

```bash
go test ./...
go run ./cmd/wordwarden --config config.example.yaml config validate
go run ./cmd/wordwarden --config config.example.yaml serve
```

Health check:

```bash
curl http://127.0.0.1:8080/healthz
```

LDAP diagnostics:

```bash
go run ./cmd/wordwarden --config config.example.yaml ldap test --tenant tenant-a
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
