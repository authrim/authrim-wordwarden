# Configuration

Authrim Wordwarden uses a strict YAML configuration file. Unknown fields are
rejected, except under the optional `experimental:` namespace.

Configuration changes require a process restart in Alpha.

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

`single_tenant` is the Alpha default and requires exactly one tenant. The schema
already supports `tenants:` as an array so multi-tenant separation is explicit
from the beginning.

## Secrets

Secret references use one of:

- `env:NAME`
- `file:/absolute/path`

Secret values are resolved only for commands that need them. `config validate`
validates reference syntax without reading secret values.

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
- optionally use service-bind and search settings to resolve attributes

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

## Attribute Release

Attributes returned to Authrim are the intersection of:

- `attribute_names` requested by Authrim
- the connector-local `ldap.attributes` allowlist

Wordwarden does not perform role mapping in Alpha.
