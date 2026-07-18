# Operations

Authrim Wordwarden is a beta directory connector. It is designed to run near
LDAP/AD and expose only the password verification endpoint needed by Authrim.

## Runtime Model

- Keep LDAP/AD private.
- Expose Wordwarden through HTTPS, a tunnel, or a private network path.
- Use HMAC authentication for every Authrim-to-Wordwarden request.
- Keep tenant and connector ids stable.
- Restart the process after config, secret reference, LDAP CA, or tenant changes.

`SIGHUP` does not reload configuration in the current beta. It only logs that restart is
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

Create a redacted diagnostic bundle without reading HMAC, LDAP bind, or audit
hash secret values:

```bash
wordwarden --config /etc/authrim-wordwarden/config.yaml diagnostics bundle
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
5. local `GET /healthz/details`
6. local `GET /metrics`
7. public/tunnel `GET /healthz`, or Authrim relay health check
8. Authrim directory password login
9. Wordwarden audit event correlation by `request_id`

Interpretation:

- Step 1 failure means the process should not start.
- Step 2 failure means service bind, TLS, base DN, or directory reachability is
  broken.
- Step 3 failure means user lookup, DN construction, password bind, or directory
  account state is the likely issue.
- Step 4 failure means the Wordwarden process or listener is down.
- Step 5 failure means the local management surface is not healthy.
- Step 6 failure means the process-local metrics surface is not available.
  These operational endpoints are loopback-only unless
  `server.expose_operations: true` is set.
- Step 7 failure means ingress, tunnel, reverse proxy, DNS, certificate setup, or
  relay WebSocket registration is broken.
- Step 8 failure with successful earlier steps usually means HMAC, connector id,
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
{"ok":true,"connector":"authrim-wordwarden","version":"0.1.0-beta.1"}
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

Beta audit events are written as local JSON events. Raw passwords are never
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
- AD account status:
  - AD `data 532` is normalized to `policy_required/password_expired`
  - AD `data 773` is normalized to `policy_required/must_change_password`
  - AD `data 533` is normalized to `failure/account_disabled`
  - AD `data 775` is normalized to `failure/account_locked`
- Referrals:
  - `directory_referral` means the directory returned a referral and Wordwarden
    did not chase it automatically
  - check `base_dn`, `user_filter`, and referral policy before enabling a broader
    directory path

Do not use `/healthz` as proof that LDAP login works. `/healthz` is intentionally
shallow.

## Connector Fleet Operations

Use `docs/fleet-operations.md` for heartbeat triage, instance acknowledge /
deactivate / reactivate operations, heartbeat key rotation, and rolling upgrade
procedures.

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

## Samba AD Fixture

The local Samba AD fixture is guarded by `WORDWARDEN_SAMBA_AD_INTEGRATION=1`.
It is useful for checking Active Directory profile defaults such as `objectGUID`,
`sAMAccountName`, `memberOf`, and AD-style bind behavior.

```bash
docker compose -f test/integration/samba-ad/docker-compose.yml up -d --build
WORDWARDEN_SAMBA_AD_INTEGRATION=1 go test ./internal/adapters/ldap -run TestSambaADIntegration
docker compose -f test/integration/samba-ad/docker-compose.yml down -v
```

The fixture binds LDAP to `127.0.0.1:1390` only and disables Samba's strong LDAP
auth requirement for local testing only. Production AD deployments should use
LDAPS or StartTLS with certificate verification.

## Real AD Guarded Test

A real Active Directory smoke test is available but disabled by default. It is
intended for lab or customer-owned domain controllers only.

```bash
WORDWARDEN_REAL_AD_INTEGRATION=1 \
WORDWARDEN_REAL_AD_URL=ldaps://dc.example.edu:636 \
WORDWARDEN_REAL_AD_BIND_DN='CN=Wordwarden Bind,OU=Service Accounts,DC=example,DC=edu' \
WORDWARDEN_REAL_AD_BIND_PASSWORD='...' \
WORDWARDEN_REAL_AD_BASE_DN='DC=example,DC=edu' \
WORDWARDEN_REAL_AD_USERNAME='alice' \
WORDWARDEN_REAL_AD_PASSWORD='...' \
go test ./internal/adapters/ldap -run TestRealADIntegration
```

Optional variables include `WORDWARDEN_REAL_AD_CA_FILE`,
`WORDWARDEN_REAL_AD_TLS_SERVER_NAME`, `WORDWARDEN_REAL_AD_STARTTLS`,
`WORDWARDEN_REAL_AD_USER_FILTER`, `WORDWARDEN_REAL_AD_SUBJECT_ATTRIBUTE`,
`WORDWARDEN_REAL_AD_GROUP_STRATEGY`, and `WORDWARDEN_REAL_AD_GROUPS`.

## Deployment Samples

Minimal systemd and Docker Compose samples are under `deploy/`. Cloudflare
Tunnel and Public HTTPS guides are under `docs/`.

These samples are starting points. Production deployments should add host-level
monitoring, log collection, secret management, and certificate rotation.

For the production hardening checklist, threat model summary, load testing,
secret rotation, high availability, compatibility matrix, and incident response
runbook, see `docs/production-hardening.md`.

For outbound relay-specific operations, including Authrim one-time secrets,
WebSocket status, overload handling, and direct/tunnel/relay troubleshooting
differences, see `docs/relay-operations.md`.
