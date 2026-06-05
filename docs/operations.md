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

## Extended Diagnostic Order

Use this order when debugging a failed login:

1. `config validate`
2. `ldap test --tenant <tenant_id>`
3. `ldap test --tenant <tenant_id> --username <user> --password-stdin`
4. local `GET /healthz`
5. public or tunnel `GET /healthz`
6. Authrim directory password login
7. Wordwarden audit event correlation by `request_id`

Interpretation:

- Step 1 failure means the process should not start.
- Step 2 failure means service bind, TLS, base DN, or directory reachability is
  broken.
- Step 3 failure means user lookup, DN construction, password bind, or directory
  account state is the likely issue.
- Step 4 failure means the Wordwarden process or listener is down.
- Step 5 failure means ingress, tunnel, reverse proxy, DNS, or certificate setup
  is broken.
- Step 6 failure with successful earlier steps usually means HMAC, connector id,
  tenant id, timeout, or Authrim identity mapping needs inspection.

## Health Check Runbook

`GET /healthz` is a shallow process check. It confirms that the Wordwarden HTTP
server is reachable and reports the connector binary version. It does not test
LDAP reachability, HMAC keys, tenant configuration, or password verification.

```bash
curl -fsS http://127.0.0.1:8080/healthz
```

Expected local response:

```json
{"ok":true,"connector":"authrim-wordwarden","version":"0.1.0"}
```

`GET /version` returns the same connector identity and version metadata without
the health `ok` field:

```bash
curl -fsS http://127.0.0.1:8080/version
```

Use this order when bringing up or debugging a deployment:

1. `wordwarden --config ... config validate`
2. `wordwarden --config ... ldap test --tenant <tenant_id>`
3. `curl .../healthz`
4. Authrim live login or the guarded Authrim live integration test

If `/healthz` fails, inspect the process manager or container logs first. If
`/healthz` passes but login fails, run `ldap test` and inspect Wordwarden audit
events for `directory_password.verify.error`, `directory_password.hmac.failure`,
or `directory_password.config.error`.

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

## LDAP Troubleshooting

Common causes:

- TLS verification fails:
  - confirm `ldap.tls.ca_file_ref`
  - confirm `ldap.tls.server_name`
  - confirm the LDAP server certificate SAN/CN
- Service bind fails:
  - confirm `bind_dn`
  - rotate or re-enter `bind_password_ref`
  - check directory ACLs for search access
- User is not found:
  - confirm `base_dn`
  - confirm `user_filter`
  - confirm username normalization and allowed domain settings
- Password bind fails:
  - confirm the user can bind directly with another LDAP tool
  - check account lockout, disabled, expired, or must-change states
  - inspect directory-side logs when available
- Authrim receives connector unavailable:
  - check Wordwarden audit events for HMAC, replay, rate limit, timeout, or
    directory errors
  - confirm Authrim and Wordwarden share the same tenant id, connector id, `kid`,
    and active secret

Do not use `/healthz` as proof that LDAP login works. `/healthz` is intentionally
shallow.

## OpenLDAP Fixture

The local OpenLDAP fixture is guarded by `WORDWARDEN_LDAP_INTEGRATION=1`.

```bash
./test/integration/openldap/generate-certs.sh
docker compose -f test/integration/openldap/docker-compose.yml up -d
WORDWARDEN_LDAP_INTEGRATION=1 go test ./internal/adapters/ldap -run TestOpenLDAPIntegration
docker compose -f test/integration/openldap/docker-compose.yml down -v
```

The local Docker Compose demo under `deploy/docker-compose/local-demo/` uses the
same fixture and disables OpenLDAP client certificate verification with
`LDAP_TLS_VERIFY_CLIENT=never`. Wordwarden still verifies the OpenLDAP server
certificate using the generated local CA.

The generated fixture server key is made host-readable so the OpenLDAP container
can copy it during bootstrap. These certificates are local test material only.

## Deployment Samples

Minimal systemd and Docker Compose samples are under `deploy/`. Cloudflare
Tunnel and Public HTTPS guides are under `docs/`.

These samples are starting points. Production deployments should add host-level
monitoring, log collection, secret management, and certificate rotation.
