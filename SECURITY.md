# Security Policy

Authrim Wordwarden handles directory password verification requests and can
reach LDAP/Active Directory. Treat security reports as private by default.

## Supported Versions

| Version | Status |
| --- | --- |
| `v0.1.0-beta.1` | Public beta candidate |

Pre-release versions are supported for pilot evaluation only. Security fixes may
ship as new beta tags without long-term patch branches.

## Reporting a Vulnerability

Do not open a public GitHub issue for vulnerabilities.

Send reports to `yuta@sgrastar.org` with:

- affected version or commit
- deployment mode: Direct HTTPS, Cloudflare Tunnel, or Authrim Relay
- concise reproduction steps
- expected impact
- whether credentials, logs, or directory attributes may have been exposed

Please do not include real user passwords, LDAP bind passwords, HMAC secrets, or
production directory dumps. If a proof of concept needs credentials, use a local
test directory.

## Security Boundaries

- Wordwarden does not store plaintext passwords or password hashes.
- LDAP/AD remains the password source of truth.
- HMAC is the baseline tenant/connector authentication mechanism.
- Relay mode removes the need for an inbound Wordwarden endpoint, but it does
  not replace HMAC authentication or tenant/connector scoping.
- Runtime LDAP connections must verify TLS certificates.
- Diagnostic `--insecure` LDAP testing must not be used for runtime service
  configuration.

## Secrets and Logs

Reports that demonstrate leakage of any of the following are security-sensitive:

- raw user passwords
- LDAP bind credentials
- HMAC secrets
- audit hash secrets
- raw directory dumps or broad attribute exports
- cross-tenant or cross-connector verification results

Wordwarden logs and audit events are expected to avoid raw passwords. Usernames
should be hashed in audit events when possible.

