# Architecture Overview

Authrim Wordwarden is a small directory-side connector. It verifies a username
and password against LDAP/Active Directory and returns a constrained result to
Authrim. Authrim owns the user-facing login experience, sessions, Passkeys,
Email Code fallback, federation output, and tenant policy.

## Components

```text
User browser
  -> Authrim Login UI / Auth Worker
  -> Wordwarden transport
  -> Wordwarden tenant runtime
  -> LDAP/Active Directory
```

Wordwarden has one runtime per configured tenant connector. Each runtime owns:

- HMAC key material references
- LDAP connection settings
- username normalization
- allowed attribute names
- request and LDAP timeouts
- concurrency and storm-protection settings

## Transport Modes

### Direct HTTPS

```text
Authrim Worker
  -> HTTPS POST /v1/auth/verify-password
  -> Wordwarden
  -> LDAPS / StartTLS
```

Direct HTTPS is the simplest runtime path when the organization is comfortable
publishing a hardened connector endpoint. HMAC signs every verification request;
TLS protects transport confidentiality and server identity.

### Cloudflare Tunnel

```text
Authrim Worker
  -> Cloudflare hostname
  -> cloudflared outbound tunnel
  -> Wordwarden on private host
  -> LDAPS / StartTLS
```

Tunnel mode keeps the connector host private while still giving Authrim a stable
HTTPS endpoint. HMAC remains required because the tunnel is a connectivity
layer, not the application authentication boundary.

### Authrim Relay

```text
Wordwarden
  -> outbound WebSocket
  -> Authrim Relay Durable Object
  -> Authrim directory password login flow
```

Relay mode avoids an inbound connector endpoint. Wordwarden opens an outbound
WebSocket to Authrim, authenticates with a short-lived HMAC challenge response,
and receives synchronous `verify-password` requests over that connection.

Relay mode is useful when the directory-side network does not want to publish a
connector URL. It still requires tenant/connector scoping, HMAC authentication,
timeouts, and careful operations.

## Security Boundaries

Wordwarden does not store passwords. During a login, it receives a password only
long enough to verify it against the directory. It should not log raw passwords.

Authrim stores the resulting session and profile state. Authrim should not store
directory password credentials or password hashes for this migration path.

Tenant isolation is enforced by:

- tenant-scoped connector settings in Authrim
- connector ids shared by Authrim and Wordwarden
- tenant/connector scoped HMAC keys
- request/response tenant and connector correlation
- per-connector concurrency and storm protection

## Attribute Flow

Authrim may request directory attributes such as `mail`, `displayName`, and
`uid`. Wordwarden returns only attributes allowed by the connector
configuration. Authrim then applies its own identity mapping and profile policy.

Keep the Wordwarden allowlist minimal. Use Authrim mapping and policy layers for
application-facing identity decisions.

## Operational Limits

`v0.1.0-beta.1` is a public beta candidate. It is suitable for controlled pilots,
not unattended broad production rollout.

Known initial limits:

- configuration changes require process restart
- no managed automatic Cloudflare Tunnel setup
- no complete account-status remediation flow for expired or must-change
  passwords
- no shared replay store across multiple Wordwarden instances
- complex group mapping remains intentionally limited

