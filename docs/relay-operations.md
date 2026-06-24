# Outbound Relay Operations

This runbook covers Wordwarden outbound relay mode, where Wordwarden opens a
WebSocket connection to Authrim and Authrim does not need inbound access to the
Wordwarden host.

## When to Use Relay

Use relay when the organization does not want to publish Wordwarden over HTTPS
or Cloudflare Tunnel. Wordwarden still verifies passwords against LDAP/AD
locally; Authrim receives only the verification result and selected attributes.

Do not use relay to bypass tenant or connector boundaries. The relay URL,
tenant id, connector id, key id, and secret must describe the same connector on
both sides.

## Authrim Setup

In Authrim Admin UI, create or edit a Directory Authentication connector:

- Transport: `Outbound Relay`
- Wordwarden Tenant ID: the Wordwarden `connector_id`
- Relay timeouts and pending request limit: keep defaults unless load tests show
  pressure
- Rotation grace: default `300000` ms

Use `Issue Secret` for first setup. Authrim returns a one-time `wwsec_...`
secret and stores only a managed secret reference. Copy the value into
Wordwarden as an environment variable or secret file. If the value is lost, use
`Rotate Secret`.

## Wordwarden Setup

Configure the active HMAC key with the Authrim-generated secret:

```yaml
tenants:
  - tenant_id: "tenant-a"
    connector_id: "wwcon_8K4M2Q9F7D3H6P1X"
    authrim:
      hmac_keys:
        active:
          kid: "kid_from_authrim"
          secret_ref: "env:AUTHRIM_WORDWARDEN_SECRET_ACTIVE"
      audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
      relay:
        enabled: true
        url: "wss://login.example.com/api/auth/directory-relay/connect/tenant-a/wwcon_8K4M2Q9F7D3H6P1X"
```

Wordwarden validates that the relay URL path tenant and connector match the
configured `tenant_id` and `connector_id`. This prevents accidental
cross-tenant or wrong-environment relay connections.

## Validation

Run these checks on the Wordwarden host:

```sh
wordwarden --config /etc/authrim-wordwarden/config.yaml config validate
wordwarden --config /etc/authrim-wordwarden/config.yaml diagnostics bundle
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/healthz/details
curl -fsS http://127.0.0.1:8080/metrics
```

Operational endpoints are loopback-only by default. If they must be reachable
through a proxy or private network, set `server.expose_operations: true` and
protect them with network allowlisting.

Then check Authrim Admin UI:

- Directory Authentication -> connector -> Health Check
- Directory Authentication -> Connector Fleet
- authenticated connections
- pending requests and max pending requests
- last authenticated / verify / disconnect timestamps
- disconnect reason
- relay protocol and version
- authenticated key id

Relay authentication sends Wordwarden `instance_id`, version, started time, and
config fingerprint metadata to Authrim Connector Fleet. The `instance_id` is
generated on first startup and stored under `server.state_dir`; keep that
directory persistent across restarts. If an instance is deactivated in Authrim,
that instance's relay registration is rejected without affecting other
instances for the same connector.

## Troubleshooting

Connector offline:

- Confirm Wordwarden process is running.
- Confirm outbound network access to the Authrim login host.
- Confirm the relay URL uses `wss://`, except local `ws://localhost`.
- Confirm `tenant_id`, `connector_id`, and Authrim connector settings match.

Authentication rejected:

- Confirm the Authrim Admin UI key id matches Wordwarden active key id.
- Confirm the one-time `wwsec_...` secret was copied to the configured
  `secret_ref`.
- Confirm clock skew is small enough for the short-lived challenge timestamp.
- Rotate the secret if the one-time value was lost.

Overloaded:

- Authrim returns `429 relay_overloaded` when pending requests exceed the
  connector limit.
- Increase `max_pending_requests` only after checking LDAP latency and
  Wordwarden concurrency.
- Use `/metrics` and local audit logs to separate invalid credentials from LDAP
  availability or storm-protection issues.

Direct HTTPS and Cloudflare Tunnel expose an inbound Wordwarden endpoint.
Outbound relay does not. For relay incidents, start with the WebSocket status in
Authrim and the Wordwarden process logs; for direct/tunnel incidents, start with
public `/healthz` reachability and HMAC request validation.

## Connector Fleet operations

Relay deployments register fleet metadata during WebSocket authentication. Use
`docs/fleet-operations.md` for incident triage, deactivation, reactivation,
heartbeat key rotation guidance, and rolling upgrades.
