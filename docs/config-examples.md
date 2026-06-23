# Configuration Examples

This document contains practical Authrim Wordwarden configuration examples for
real deployments. The examples use the current Alpha schema and avoid features
that are planned but not implemented yet, such as advanced group mapping and
automatic referral chasing.

Use `docs/configuration.md` for field-level behavior and validation rules.

## Where Authrim Connection Settings Live

Wordwarden does not need the remote Authrim URL in Alpha because the runtime
request direction is Authrim -> Wordwarden.

Configure the Wordwarden endpoint in Authrim tenant settings:

```text
authentication-methods.directory_password.enabled=true
authentication-methods.directory_password.connector_id=campus

directory-connectors.campus.endpoint_url=https://wordwarden.example.edu
directory-connectors.campus.auth_mode=hmac
directory-connectors.campus.connector_id=ww_tenant_a
directory-connectors.campus.key_id=kid_2026_06
directory-connectors.campus.secret_ref=env:WORDWARDEN_SECRET
directory-connectors.campus.timeouts.request_ms=3000
directory-connectors.campus.attribute_names=mail,displayName,uid
```

Configure the matching HMAC key material in Wordwarden:

```yaml
authrim:
  hmac_keys:
    active:
      kid: "kid_2026_06"
      secret_ref: "env:AUTHRIM_WORDWARDEN_SECRET_ACTIVE"
```

`server.public_base_url` is Wordwarden's own public URL. It should match the
hostname Authrim uses as `directory-connectors.<id>.endpoint_url`; it is not the
Authrim login URL.

In the current Authrim Alpha integration, these settings are tenant-scoped
settings stored by Authrim's configuration system. Admin UI editing is planned
for a later milestone.

## Example 1: Cloudflare Tunnel with LDAPS

Use this shape when Wordwarden runs on the directory-side host and is exposed to
Authrim through Cloudflare Tunnel. Wordwarden listens on localhost HTTP because
the public Authrim-to-Wordwarden hop terminates at Cloudflare.

```yaml
deployment:
  mode: "single_tenant"

server:
  listen: "127.0.0.1:8080"
  public_base_url: "https://wordwarden.example.edu"
  tls:
    enabled: false
    cert_file_ref: null
    key_file_ref: null

tenants:
  - tenant_id: "tenant-a"
    connector_id: "ww_tenant_a"
    authrim:
      hmac_keys:
        active:
          kid: "kid_2026_06"
          secret_ref: "env:AUTHRIM_WORDWARDEN_SECRET_ACTIVE"
        previous:
          kid: "kid_2026_05"
          secret_ref: "file:/etc/authrim-wordwarden/secrets/hmac-previous"
      audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
    ldap:
      url: "ldaps://ldap.example.edu:636"
      tls:
        verify: true
        server_name: "ldap.example.edu"
        ca_file_ref: "file:/etc/authrim-wordwarden/ca/ldap-ca.pem"
      lookup_mode: "search_then_bind"
      username:
        allowed_formats:
          - local_part
          - email
        allowed_domains:
          - example.edu
        normalization:
          trim: true
          unicode: "NFKC"
          case: "lower"
          reject_domain_mismatch: true
      bind_dn: "cn=authrim-wordwarden,ou=Services,dc=example,dc=edu"
      bind_password_ref: "env:LDAP_BIND_PASSWORD"
      base_dn: "ou=People,dc=example,dc=edu"
      user_filter: "(uid={username})"
      filter_template_mode: "builtin_or_template"
      attributes:
        - uid
        - mail
        - displayName
    timeouts:
      ldap_connect_ms: 500
      ldap_bind_ms: 1500
      ldap_search_ms: 1000
      request_ms: 2500
    protection:
      max_concurrent_requests: 8
      storm_window_ms: 10000
      storm_block_ms: 30000
      malformed_request_limit: 20
      replay_limit: 10
      directory_error_limit: 5
```

Matching Authrim tenant settings:

```text
authentication-methods.directory_password.enabled=true
authentication-methods.directory_password.connector_id=campus

directory-connectors.campus.endpoint_url=https://wordwarden.example.edu
directory-connectors.campus.auth_mode=hmac
directory-connectors.campus.connector_id=ww_tenant_a
directory-connectors.campus.key_id=kid_2026_06
directory-connectors.campus.secret_ref=env:WORDWARDEN_SECRET
directory-connectors.campus.timeouts.request_ms=3000
directory-connectors.campus.attribute_names=mail,displayName,uid
```

## Example 2: Public HTTPS with Built-In TLS

Use this when Wordwarden is directly reachable over HTTPS and terminates TLS
itself. This is simple, but the organization must be comfortable exposing a
Wordwarden hostname and operating certificates, firewall rules, logs, and
monitoring.

```yaml
deployment:
  mode: "single_tenant"

server:
  listen: "0.0.0.0:8443"
  public_base_url: "https://wordwarden.example.edu:8443"
  tls:
    enabled: true
    cert_file_ref: "file:/etc/authrim-wordwarden/tls/fullchain.pem"
    key_file_ref: "file:/etc/authrim-wordwarden/tls/privkey.pem"

tenants:
  - tenant_id: "tenant-a"
    connector_id: "ww_tenant_a"
    authrim:
      hmac_keys:
        active:
          kid: "kid_2026_06"
          secret_ref: "env:AUTHRIM_WORDWARDEN_SECRET_ACTIVE"
      audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
    ldap:
      url: "ldaps://ldap.example.edu:636"
      tls:
        verify: true
        server_name: "ldap.example.edu"
        ca_file_ref: "file:/etc/authrim-wordwarden/ca/ldap-ca.pem"
      lookup_mode: "search_then_bind"
      username:
        allowed_formats:
          - local_part
          - email
          - upn
        allowed_domains:
          - example.edu
        allowed_upn_suffixes:
          - example.edu
        normalization:
          trim: true
          unicode: "NFKC"
          case: "lower"
          reject_domain_mismatch: true
      bind_dn: "cn=authrim-wordwarden,ou=Services,dc=example,dc=edu"
      bind_password_ref: "file:/etc/authrim-wordwarden/secrets/ldap-bind-password"
      base_dn: "dc=example,dc=edu"
      user_filter: "(|(uid={username})(mail={username})(userPrincipalName={username}))"
      filter_template_mode: "builtin_or_template"
      attributes:
        - uid
        - mail
        - displayName
        - userPrincipalName
    timeouts:
      ldap_connect_ms: 500
      ldap_bind_ms: 1500
      ldap_search_ms: 1000
      request_ms: 3000
    protection:
      max_concurrent_requests: 12
      storm_window_ms: 10000
      storm_block_ms: 30000
      malformed_request_limit: 20
      replay_limit: 10
      directory_error_limit: 5
```

Matching Authrim tenant settings:

```text
authentication-methods.directory_password.enabled=true
authentication-methods.directory_password.connector_id=campus

directory-connectors.campus.endpoint_url=https://wordwarden.example.edu:8443
directory-connectors.campus.auth_mode=hmac
directory-connectors.campus.connector_id=ww_tenant_a
directory-connectors.campus.key_id=kid_2026_06
directory-connectors.campus.secret_ref=env:WORDWARDEN_SECRET
directory-connectors.campus.timeouts.request_ms=3500
directory-connectors.campus.attribute_names=mail,displayName,uid,userPrincipalName
```

## Example 3: DN Template Lookup

Use `dn_template` only when usernames map predictably to user DNs. It avoids a
service search before password bind, but it is brittle when DNs include multiple
OUs, renamed accounts, or non-username RDNs.

```yaml
deployment:
  mode: "single_tenant"

server:
  listen: "127.0.0.1:8080"
  public_base_url: "https://wordwarden.example.edu"
  tls:
    enabled: false
    cert_file_ref: null
    key_file_ref: null

tenants:
  - tenant_id: "tenant-a"
    connector_id: "ww_tenant_a"
    authrim:
      hmac_keys:
        active:
          kid: "kid_2026_06"
          secret_ref: "env:AUTHRIM_WORDWARDEN_SECRET_ACTIVE"
      audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
    ldap:
      url: "ldaps://ldap.example.edu:636"
      tls:
        verify: true
        server_name: "ldap.example.edu"
        ca_file_ref: "file:/etc/authrim-wordwarden/ca/ldap-ca.pem"
      lookup_mode: "dn_template"
      username:
        allowed_formats:
          - local_part
        normalization:
          trim: true
          unicode: "NFKC"
          case: "lower"
          reject_domain_mismatch: true
      dn_template: "uid={username},ou=People,dc=example,dc=edu"
      bind_dn: "cn=authrim-wordwarden,ou=Services,dc=example,dc=edu"
      bind_password_ref: "env:LDAP_BIND_PASSWORD"
      base_dn: "ou=People,dc=example,dc=edu"
      user_filter: "(uid={username})"
      filter_template_mode: "builtin_or_template"
      attributes:
        - uid
        - mail
        - displayName
    timeouts:
      ldap_connect_ms: 500
      ldap_bind_ms: 1500
      ldap_search_ms: 1000
      request_ms: 2500
    protection:
      max_concurrent_requests: 8
      storm_window_ms: 10000
      storm_block_ms: 30000
      malformed_request_limit: 20
      replay_limit: 10
      directory_error_limit: 5
```

## Example 4: Direct Bind with UPN

Use `direct_bind` when the directory accepts the submitted username as the bind
name, such as an Active Directory UPN. This is useful when service search is not
available before password verification. Attribute lookup still needs service
bind settings if Authrim requires `mail` or `displayName`.

```yaml
deployment:
  mode: "single_tenant"

server:
  listen: "127.0.0.1:8080"
  public_base_url: "https://wordwarden.example.edu"
  tls:
    enabled: false
    cert_file_ref: null
    key_file_ref: null

tenants:
  - tenant_id: "tenant-a"
    connector_id: "ww_tenant_a"
    authrim:
      hmac_keys:
        active:
          kid: "kid_2026_06"
          secret_ref: "env:AUTHRIM_WORDWARDEN_SECRET_ACTIVE"
      audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
    ldap:
      url: "ldaps://ad.example.edu:636"
      tls:
        verify: true
        server_name: "ad.example.edu"
        ca_file_ref: "file:/etc/authrim-wordwarden/ca/ad-ca.pem"
      lookup_mode: "direct_bind"
      username:
        allowed_formats:
          - upn
        allowed_upn_suffixes:
          - example.edu
        normalization:
          trim: true
          unicode: "NFKC"
          case: "lower"
          reject_domain_mismatch: true
      bind_dn: "CN=authrim-wordwarden,OU=Services,DC=example,DC=edu"
      bind_password_ref: "env:LDAP_BIND_PASSWORD"
      base_dn: "DC=example,DC=edu"
      user_filter: "(userPrincipalName={username})"
      filter_template_mode: "builtin_or_template"
      attributes:
        - mail
        - displayName
        - userPrincipalName
    timeouts:
      ldap_connect_ms: 500
      ldap_bind_ms: 1500
      ldap_search_ms: 1000
      request_ms: 3000
    protection:
      max_concurrent_requests: 8
      storm_window_ms: 10000
      storm_block_ms: 30000
      malformed_request_limit: 20
      replay_limit: 10
      directory_error_limit: 5
```

## Example 5: Failover, StartTLS, Groups, and Pooling

This example shows the M4 production-variation options together. Use this only
when the directory actually expects StartTLS on `ldap://`.

```yaml
deployment:
  mode: "single_tenant"

server:
  listen: "127.0.0.1:8080"
  public_base_url: "https://wordwarden.example.edu"
  tls:
    enabled: false
    cert_file_ref: null
    key_file_ref: null

tenants:
  - tenant_id: "tenant-a"
    connector_id: "ww_tenant_a"
    authrim:
      hmac_keys:
        active:
          kid: "kid_2026_06"
          secret_ref: "env:AUTHRIM_WORDWARDEN_SECRET_ACTIVE"
      audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
    ldap:
      urls:
        - "ldap://ldap-a.example.edu:389"
        - "ldap://ldap-b.example.edu:389"
      tls:
        verify: true
        start_tls: true
        server_name: "ldap.example.edu"
        ca_file_ref: "file:/etc/authrim-wordwarden/ca/ldap-ca.pem"
      lookup_mode: "search_then_bind"
      username:
        allowed_formats:
          - local_part
          - email
        allowed_domains:
          - example.edu
        normalization:
          trim: true
          unicode: "NFKC"
          case: "lower"
          reject_domain_mismatch: true
      bind_dn: "cn=authrim-wordwarden,ou=Services,dc=example,dc=edu"
      bind_password_ref: "env:LDAP_BIND_PASSWORD"
      base_dn: "dc=example,dc=edu"
      user_filter: "(uid={username})"
      filter_template_mode: "builtin_or_template"
      attributes:
        - uid
        - mail
        - displayName
      groups:
        enabled: true
        member_attribute: "memberOf"
        response_attribute: "groups"
      referrals:
        mode: "disabled"
      pool:
        max_idle: 2
    timeouts:
      ldap_connect_ms: 500
      ldap_bind_ms: 1500
      ldap_search_ms: 1000
      request_ms: 3000
    protection:
      max_concurrent_requests: 8
      storm_window_ms: 10000
      storm_block_ms: 30000
      malformed_request_limit: 20
      replay_limit: 10
      directory_error_limit: 5
```

## Environment File Example

For systemd deployments, keep secrets outside `config.yaml`:

```env
AUTHRIM_WORDWARDEN_SECRET_ACTIVE=replace-with-random-hmac-secret
AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET=replace-with-random-audit-hash-secret
LDAP_BIND_PASSWORD=replace-with-directory-bind-password
```

Install it as:

```bash
sudo install -m 0640 -o root -g wordwarden wordwarden.env /etc/authrim-wordwarden/wordwarden.env
```

## Validation Commands

Run these before starting or after changing config:

```bash
wordwarden --config /etc/authrim-wordwarden/config.yaml config validate
wordwarden --config /etc/authrim-wordwarden/config.yaml ldap test --tenant tenant-a
```

For one real user:

```bash
printf '%s\n' "$USER_PASSWORD" | \
  wordwarden --config /etc/authrim-wordwarden/config.yaml ldap test \
    --tenant tenant-a \
    --username "$USERNAME" \
    --password-stdin
```
