# Production Hardening

This guide is the M7 production hardening checklist for Authrim Wordwarden. It
does not make the Alpha connector a fully managed service. It defines the
security and operations boundary that must be true before broader pilots.

## Threat Model Summary

Protected assets:

- LDAP/AD user passwords submitted during verification
- LDAP bind credentials
- Authrim-to-Wordwarden HMAC secrets
- audit hash secrets
- directory attributes returned to Authrim
- tenant and connector separation

Primary threats:

- unauthenticated requests attempting directory password guessing
- replayed signed verification requests
- request body or audit logs leaking raw passwords
- cross-tenant or cross-connector request confusion
- directory outage causing noisy user-facing failures
- exposed inbound connector endpoint without HMAC enforcement
- stale HMAC key rotation leaving an unbounded previous key active

Required controls:

- HMAC request signing for every `POST /v1/auth/verify-password`
- tenant/connector scoped key ids and secrets
- replay cache keyed by connector id, key id, request id, and nonce
- strict request body size limits
- storm protection for HMAC failures, malformed requests, replay attempts, and
  directory errors
- username hashing in audit events
- no raw password in logs, audit events, metrics, traces, or diagnostics
- LDAP TLS verification in runtime paths

## Security Review Checklist

Before enabling a production pilot:

- Confirm the connector endpoint is reachable only through the intended network
  shape: Cloudflare Tunnel, private network/VPN, or hardened public HTTPS.
- Confirm HMAC is enabled and the Authrim-side `kid` and secret match the
  Wordwarden tenant connector.
- Confirm old HMAC keys are removed after the rotation window.
- Confirm `ldap.tls.verify` is true and private CA files are deployed with
  least privilege.
- Confirm `ldap test --tenant <tenant_id>` works without `--insecure`.
- Confirm `ldap test --tenant <tenant_id> --username <user> --password-stdin`
  works for a normal account and fails for a wrong password.
- Confirm Wordwarden audit events do not contain raw usernames or passwords.
- Confirm Authrim public login method discovery does not expose endpoint URLs,
  HMAC secrets, LDAP bind credentials, or directory internals.

## Secret Rotation

Wordwarden supports one active HMAC key and one previous HMAC key per tenant
connector.

Recommended HMAC rotation:

1. Add the new key as Authrim active and Wordwarden active.
2. Move the old key to Wordwarden previous.
3. Deploy/restart Wordwarden.
4. Verify Authrim login succeeds with the new `kid`.
5. Watch for requests still using the previous `kid`.
6. Remove the previous key after the agreed compatibility window.
7. Restart Wordwarden again.

LDAP bind password rotation:

1. Create or update the directory service account secret in the selected secret
   backend.
2. Update the `bind_password_ref` target or referenced value.
3. Restart Wordwarden.
4. Run `ldap test --tenant <tenant_id>`.
5. Run one guarded user-bind diagnostic with `--password-stdin`.

Audit hash secret rotation changes future `username_hash` values. Treat it as a
correlation boundary change and record the rotation time in the operations log.

## High Availability Guidance

Wordwarden is stateless except for in-memory replay and storm-protection state.
Run multiple instances only when Authrim or the ingress can route requests
consistently enough for the replay window you require.

Recommended baseline:

- two Wordwarden instances near the same LDAP/AD endpoint set
- identical config and HMAC key material
- health checks against `GET /healthz`
- external process supervision through systemd, container orchestration, or an
  ingress platform
- short request timeouts so Authrim can fail safely
- directory endpoint failover through `ldap.urls`

Important limitation:

- In-memory replay caches are per instance. If requests can be replayed to a
  different instance during the replay TTL, rely on HMAC nonce uniqueness at the
  caller and keep the public endpoint protected by rate limits. A shared replay
  store is a future hardening option.

## Load and Latency Testing

Use the local handler benchmark for code-path regressions:

```bash
go test ./internal/ports/httpapi -run '^$' -bench BenchmarkVerifyPasswordSuccess -benchmem
```

Use the OpenLDAP fixture for end-to-end latency checks:

```bash
./test/integration/openldap/generate-certs.sh
docker compose -f test/integration/openldap/docker-compose.yml up -d
WORDWARDEN_LDAP_INTEGRATION=1 go test ./internal/adapters/ldap -run TestOpenLDAPIntegration
docker compose -f test/integration/openldap/docker-compose.yml down -v
```

Pilot SLO targets:

| Measurement | Initial target |
| --- | --- |
| local handler benchmark allocations | no unexpected growth between releases |
| p50 directory password verification | under 500 ms |
| p95 directory password verification | under 1500 ms |
| connector unavailable response | under configured `request_ms` |

Treat these as pilot targets, not public guarantees.

## LDAP/AD Compatibility Matrix

Validate each production directory against this matrix:

| Area | Required check |
| --- | --- |
| Transport | LDAPS or StartTLS with certificate verification |
| Search mode | `search_then_bind`, `dn_template`, or `direct_bind` selected intentionally |
| Username formats | local part, email, or UPN tested with accepted and rejected examples |
| Account status | normal, wrong password, disabled, locked, expired, must-change where available |
| Attribute release | requested attributes intersect with connector allowlist |
| Groups | `memberOf` or chosen group attribute returns expected raw values when enabled |
| Failover | every `ldap.urls` endpoint tested independently |
| Referral behavior | referrals disabled or explicitly documented as unsupported |

Record product/version notes for Active Directory, OpenLDAP, 389 Directory
Server, or other LDAP-compatible directories used in pilots.

## Incident Response Runbook

Directory unavailable:

- Check `GET /healthz` to distinguish process outage from directory outage.
- Run `ldap test --tenant <tenant_id>`.
- Inspect `directory_password.verify.error` events.
- Fail over LDAP endpoints if configured.
- Disable the Authrim directory login method if outage impact is user-facing and
  Email Code, Passkey, or External IdP can carry the login flow.

Suspected HMAC secret exposure:

- Rotate the active HMAC key immediately.
- Remove any previous key that may be exposed.
- Restart Wordwarden.
- Inspect `directory_password.hmac.failure` and replay events.
- Review Authrim connector settings history.

Suspected password leakage:

- Treat it as a security incident even if only diagnostic output is suspected.
- Preserve logs according to incident policy.
- Search for raw password values only in restricted incident tooling, never in
  shared chat or tickets.
- Rotate affected directory credentials where appropriate.
- Add a regression test before closing the incident.

Repeated replay or storm events:

- Confirm Authrim request signing clock and nonce generation.
- Check for retry middleware replaying signed bodies.
- Review ingress logs for repeated source addresses.
- Tighten edge rate limits if the endpoint is public.
