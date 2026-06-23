# Configuration

Authrim Wordwarden uses a strict YAML configuration file. Unknown fields are
rejected, except under the optional `experimental:` namespace.

Configuration changes require a process restart in the current beta.

For deployment-ready templates, see `docs/config-examples.md`.

## Top Level

```yaml
deployment:
  mode: "single_tenant"

server:
  listen: "127.0.0.1:8080"
  public_base_url: "https://wordwarden.example.com"
  tls:
    enabled: false
```

`single_tenant` is the beta default and requires exactly one tenant. The schema
already supports `tenants:` as an array so multi-tenant separation is explicit
from the beginning.

## Secrets

Secret references use one of:

- `env:NAME`
- `file:/absolute/path`

Secret values are resolved only for commands that need them. `config validate`
validates reference syntax without reading secret values.

## Authrim Relay

Wordwarden supports two Authrim connection directions:

- Direct HTTPS: Authrim calls `POST /v1/auth/verify-password` on Wordwarden.
- Outbound Relay: Wordwarden opens a WebSocket to Authrim and receives
  verification requests through that connection.

Use outbound relay when the directory-side network should not expose a public
Wordwarden endpoint:

```yaml
authrim:
  hmac_keys:
    active:
      kid: "kid_2026_06"
      secret_ref: "env:AUTHRIM_WORDWARDEN_SECRET_ACTIVE"
  audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
  relay:
    enabled: true
    url: "wss://login.example.com/api/auth/directory-relay/connect/tenant-a/ww_tenant_a"
    reconnect_min_ms: 1000
    reconnect_max_ms: 30000
```

The relay uses the active HMAC key to answer Authrim's short-lived challenge.
`wss://` is required in production. `ws://localhost` is accepted for local
development only.

## LDAP Lookup Modes

## LDAP Transport and Endpoints

Use `ldap.url` for one endpoint or `ldap.urls` for failover:

```yaml
ldap:
  urls:
    - "ldaps://ldap-a.example.com:636"
    - "ldaps://ldap-b.example.com:636"
```

Wordwarden tries endpoints in order for each connection attempt. `ldaps://` is
the default production transport.

StartTLS is supported when the directory expects a clear LDAP connection first:

```yaml
ldap:
  url: "ldap://ldap.example.com:389"
  tls:
    verify: true
    start_tls: true
    server_name: "ldap.example.com"
```

`ldap://` is accepted only when `tls.start_tls` is true. LDAP TLS verification
remains required.

## LDAP Lookup Modes

`search_then_bind`:

- service-bind with `bind_dn` / `bind_password_ref`
- search under `base_dn` using `user_filter`; the filter must contain
  `{username}` and must resolve exactly one LDAP entry
- bind as the resolved user DN with the submitted password
- best default for LDAP/AD deployments

`dn_template`:

- derive the user DN from `dn_template`
- bind directly as that DN
- optionally use service-bind and search settings to return attributes

`direct_bind`:

- bind directly using the processed username as the bind name
- requires service-bind and search settings (`bind_dn`, `bind_password_ref`,
  `base_dn`, and `user_filter`)
- after a successful direct bind, service-bind and search must resolve exactly one
  LDAP entry under `base_dn` through `user_filter` before authentication succeeds

All modes apply username preprocessing before lookup or bind.

## Username Preprocessing

Supported controls:

- `allowed_formats`: `local_part`, `email`, `upn`
- `allowed_domains`
- `allowed_upn_suffixes`
- `normalization.trim`
- `normalization.unicode: "NFKC"`
- `normalization.case: "lower"`
- `normalization.reject_domain_mismatch`

This preprocessing happens before LDAP lookup. Authrim identity mapping remains
a post-auth concern.

## Protection

```yaml
protection:
  max_concurrent_requests: 8
  storm_window_ms: 10000
  storm_block_ms: 30000
  malformed_request_limit: 20
  replay_limit: 10
  directory_error_limit: 5
```

`max_concurrent_requests` protects the connector and LDAP/AD from bursts.
Storm protection temporarily blocks repeated HMAC failures, malformed requests,
replays, or directory errors for the same connector.

## Connection Pooling

LDAP connection pooling is disabled by default. Enable it only when the
directory and network path benefit from connection reuse:

```yaml
ldap:
  pool:
    max_idle: 2
```

Wordwarden only returns a connection to the idle pool after it can restore the
service-bind state. Connections that were user-bound and cannot be safely
restored are closed.

## Referral Policy

Referrals are disabled by default:

```yaml
ldap:
  referrals:
    mode: "disabled"
```

`allowlist` mode records the intended policy boundary for deployments that
explicitly allow referral hosts:

```yaml
ldap:
  referrals:
    mode: "allowlist"
    allowed_urls:
      - "ldaps://ldap-referral.example.com:636"
```

The current beta does not chase referrals automatically. A directory referral is normalized
as `directory_referral` so operators can fix base DN, filters, or referral
policy without silent cross-directory traversal.

## Attribute Release

Attributes returned to Authrim are the intersection of:

- `attribute_names` requested by Authrim
- the connector-local `ldap.attributes` allowlist

Wordwarden does not perform role mapping in the current beta.

## Group Lookup Primitive

Wordwarden can expose a raw group membership attribute as a connector fact. This
is not role mapping.

```yaml
ldap:
  attributes:
    - uid
    - mail
    - displayName
  groups:
    enabled: true
    member_attribute: "memberOf"
    response_attribute: "groups"
```

When Authrim requests `groups`, Wordwarden reads `memberOf` and returns those
values as `groups`. Authrim remains responsible for role mapping and final
attribute release.

## AD Status Normalization

Active Directory invalid-credentials bind diagnostics are normalized when AD
provides standard `data` codes:

| AD data code | Wordwarden result | Reason |
| --- | --- | --- |
| `532` | `policy_required` | `password_expired` |
| `533` | `failure` | `account_disabled` |
| `773` | `policy_required` | `must_change_password` |
| `775` | `failure` | `account_locked` |

`policy_required` is not a successful login and must not trigger Authrim session
creation.
