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
  expose_operations: false
  tls:
    enabled: false
```

`/healthz/details` and `/metrics` are operational endpoints. They are available
to loopback clients by default. Set `server.expose_operations: true` only when
another network control, such as a reverse proxy allowlist or private network,
protects those endpoints.

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
For managed relay secrets, Authrim Admin UI issues a one-time `wwsec_...` value.
Store that value in the configured `secret_ref`; do not paste the secret value
directly into YAML.
`wss://` is required in production. `ws://localhost` is accepted for local
development only.

## LDAP Lookup Modes

## Directory Profiles

Directory profiles provide safe defaults for common LDAP/AD schema differences.
They can be overridden per deployment:

```yaml
ldap:
  directory_profile:
    name: "active_directory"
    subject_attribute: "objectGUID"
    identifier_attributes:
      - sAMAccountName
      - userPrincipalName
      - mail
    group_strategy: "ad_matching_rule"
    status_normalization: "active_directory"
    paged_search:
      enabled: true
      page_size: 500
      max_entries: 5000
      timeout_ms: 3000
```

Initial built-in profiles are `active_directory`, `openldap`, and `generic`.
Active Directory defaults to `objectGUID` as the stable subject; OpenLDAP
defaults to `entryUUID`. `generic` deployments should set
`subject_attribute` explicitly when DN stability is not enough.
Binary subject attributes such as AD `objectGUID` are normalized to base64url
before they are returned as `subject.directory_id`.

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
    allow_service_bind_reuse: true
```

Referral chasing is disabled by default. When enabled, Wordwarden follows only a
single hop to an allowlisted LDAP/LDAPS endpoint. TLS verification is still
required, and service-bind credential reuse must be explicitly allowed with
`allow_service_bind_reuse: true`. Further referrals are rejected as
`directory_referral`.

## Attribute Release

Attributes returned to Authrim are the intersection of:

- `attribute_names` requested by Authrim
- the connector-local `ldap.attributes` allowlist

Wordwarden does not perform role mapping in the current beta.

## Group Lookup Primitive

Wordwarden can expose group facts. This is not role mapping.

```yaml
ldap:
  attributes:
    - uid
    - mail
    - displayName
  groups:
    enabled: true
    member_attribute: "memberOf"
    search_member_attribute: "member"
    response_attribute: "groups"
    id_attribute: "cn"
    display_attribute: "cn"
    search_base_dn: "ou=Groups,dc=example,dc=edu"
    max_depth: 2
    max_groups: 100
    timeout_ms: 1000
```

When Authrim requests `groups`, Wordwarden returns legacy `attributes.groups`
and structured `group_facts`. Group lookup strategy is controlled by
`directory_profile.group_strategy`: `member_attribute_only`,
`ad_matching_rule`, or `bfs_member_search`. Authrim remains responsible for role
mapping and final attribute release.

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
