# Operations

Authrim Wordwarden is an Alpha directory connector. It is designed to run near
LDAP/AD and expose only the password verification endpoint needed by Authrim.

## Runtime Model

- Keep LDAP/AD private.
- Expose Wordwarden through HTTPS, a tunnel, or a private network path.
- Use HMAC authentication for every Authrim-to-Wordwarden request.
- Keep tenant and connector ids stable.
- Restart the process after config, secret reference, LDAP CA, or tenant changes.

`SIGHUP` does not reload configuration in Alpha. It only logs that restart is
required.

## TLS

LDAP runtime traffic must verify TLS certificates. Use `ldap.tls.ca_file_ref`
for private CAs.

The HTTP listener can terminate TLS directly with `server.tls`, or it can run
behind an ingress/tunnel that terminates HTTPS. Do not expose plain HTTP on an
untrusted network.

## Diagnostics

Validate configuration without reading secret values:

```bash
wordwarden --config /etc/authrim-wordwarden/config.yaml config validate
```

Test LDAP reachability and service bind:

```bash
wordwarden --config /etc/authrim-wordwarden/config.yaml ldap test --tenant tenant-a
```

Test a user bind by passing the password through stdin:

```bash
printf '%s\n' "$USER_PASSWORD" | \
  wordwarden --config /etc/authrim-wordwarden/config.yaml ldap test \
    --tenant tenant-a \
    --username alice \
    --password-stdin
```

`--insecure` exists only for diagnostics and skips LDAP certificate verification.
Do not use it in runtime verification.

## Audit

Alpha audit events are written as local JSON events. Raw passwords are never
logged. Usernames are represented by `username_hash` when the audit hash secret
is configured.

Important event types:

- `directory_password.verify.success`
- `directory_password.verify.failure`
- `directory_password.verify.error`
- `directory_password.hmac.failure`
- `directory_password.replay.detected`
- `directory_password.config.error`

## OpenLDAP Fixture

The local OpenLDAP fixture is guarded by `WORDWARDEN_LDAP_INTEGRATION=1`.

```bash
./test/integration/openldap/generate-certs.sh
docker compose -f test/integration/openldap/docker-compose.yml up -d
WORDWARDEN_LDAP_INTEGRATION=1 go test ./internal/adapters/ldap -run TestOpenLDAPIntegration
docker compose -f test/integration/openldap/docker-compose.yml down -v
```

## Deployment Samples

Minimal systemd and Docker Compose samples are under `deploy/`.

These samples are starting points. Production deployments should add host-level
monitoring, log collection, secret management, and certificate rotation.
