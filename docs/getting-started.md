# Getting Started for Real Deployments

Authrim Wordwarden is a Directory Connector for organizations that already have
LDAP or Active Directory and want Authrim to verify directory passwords without
moving password storage into Authrim.

Wordwarden is not an identity provider by itself. It verifies a username and
password against the directory, returns a small signed result to Authrim, and
lets Authrim own the user-facing login experience, sessions, Passkeys, Email
Code, federation output, and audit correlation.

## Good Fit

Wordwarden is a good fit when:

- LDAP or Active Directory is already the source of password truth.
- The directory should stay private and close to the organization network.
- Authrim should provide Passkey-first or passwordless-capable login on top of
  existing directory accounts.
- The organization wants Authrim-managed sessions and SAML/OIDC output, but does
  not want to expose LDAP/AD directly to Authrim.
- Operators can run a small Linux service, container, or host-side connector near
  LDAP/AD.
- Password verification can be treated as one login method among others, not as
  the whole identity product.

Typical production environments:

- a campus or enterprise network with existing LDAP/AD
- an identity or infrastructure team that can operate one connector service
- a private network, VPN, reverse proxy, or Cloudflare Tunnel path from Authrim
  to Wordwarden
- organizations that want to introduce Passkeys gradually while keeping current
  directory passwords available

## Poor Fit

Wordwarden is usually not the right fit when:

- There is no LDAP/AD or equivalent directory to verify against.
- The organization wants Authrim to become the primary password database.
- LDAP/AD cannot be reached from any service host, container host, tunnel, or
  private network path.
- Operators cannot maintain a connector process, logs, certificates, and secrets.
- The deployment requires full group mapping, directory failover, referral
  handling, or account-status normalization on day one.
- The desired model is purely upstream SAML/OIDC federation into Authrim. In that
  case, connecting Authrim to the upstream IdP may be simpler than introducing a
  directory password connector.

## Deployment Overview

The normal production shape is:

```text
User browser
  -> Authrim Login UI / Worker
  -> Authrim Wordwarden HTTPS endpoint
  -> Wordwarden service near LDAP/AD
  -> LDAPS / LDAP directory
```

Authrim sends a short-lived HMAC-signed password verification request.
Wordwarden verifies the password against LDAP/AD and returns only the result and
allowed attributes. Authrim then creates the session and continues any
Passkey, SAML, OIDC, or application login flow.

## Understand the Boundaries

Before installing Wordwarden, decide these boundaries:

| Boundary | Decision |
| --- | --- |
| Tenant | Which Authrim tenant owns this connector? |
| Connector id | Which stable connector id will Authrim and Wordwarden share? |
| Endpoint | Will Authrim reach Wordwarden through Tunnel, public HTTPS, VPN, or another private path? |
| Secret | Which HMAC key id and secret will sign Authrim-to-Wordwarden requests? |
| Directory access | Which bind DN and directory ACL can search users safely? |
| Attributes | Which minimal LDAP attributes should Wordwarden return to Authrim? |
| User mapping | Which LDAP attribute maps to Authrim email and display name? |
| Network owner | Who owns DNS, reverse proxy, tunnel, firewall, and certificate changes? |
| Operations | Who owns logs, certificates, secret rotation, and restarts? |

Wordwarden does not create Authrim sessions, issue SAML/OIDC responses, enroll
Passkeys, or apply final attribute release policy. Authrim owns those layers.

## Choose the Network Shape

### Private or Tunnel-Based Endpoint

Use this when the organization does not want to expose an inbound Wordwarden
port. Wordwarden can listen on localhost, while `cloudflared` provides an
outbound tunnel to a Cloudflare hostname.

Guide: `docs/cloudflare-tunnel.md`

This is often the easiest production path for organizations that do not want to
publish a connector service directly.

### Public HTTPS Endpoint

Use this when the organization is comfortable publishing a Wordwarden HTTPS
hostname. Keep HMAC enabled even when HTTPS is strong.

Guide: `docs/public-https.md`

This is appropriate when the organization already operates reverse proxies,
firewalls, certificate automation, and monitoring for small HTTPS services.

### Host Service

Use this when Wordwarden should run as a small host service near LDAP/AD.

Guide: `deploy/systemd/README.md`

This can be combined with either Cloudflare Tunnel or Public HTTPS.

## Prepare Directory Information

Collect these values before writing the Wordwarden config:

| Item | Example |
| --- | --- |
| LDAP URL | `ldaps://ldap.example.edu:636` |
| LDAP server name | `ldap.example.edu` |
| CA certificate | `/etc/authrim-wordwarden/ca/ldap-ca.pem` |
| Search base DN | `ou=People,dc=example,dc=edu` |
| Service bind DN | `cn=authrim-wordwarden,ou=Services,dc=example,dc=edu` |
| User filter | `(uid={username})` |
| Username formats | local part, email, or UPN |
| Allowed domains | `example.edu` |
| Required attributes | `mail`, `displayName`, `uid` |

The service bind account should have only the search permissions needed for
login. It should not be a domain admin or broad directory administrator.

## Write the Wordwarden Config

Create a Wordwarden config with:

- `deployment.mode`
- `server.listen`
- `server.public_base_url`
- one `tenants` entry
- tenant-scoped HMAC key references
- LDAP URL, CA file, bind DN, and bind password reference
- username normalization rules
- lookup mode and user filter
- minimal allowed attributes
- request and LDAP timeouts

Validate before starting:

```bash
wordwarden --config /etc/authrim-wordwarden/config.yaml config validate
wordwarden --config /etc/authrim-wordwarden/config.yaml ldap test --tenant tenant-a
```

Then test one real user by passing the password through stdin:

```bash
printf '%s\n' "$USER_PASSWORD" | \
  wordwarden --config /etc/authrim-wordwarden/config.yaml ldap test \
    --tenant tenant-a \
    --username "$USERNAME" \
    --password-stdin
```

Do not use `--insecure` for runtime validation. It is only a diagnostic escape
hatch for LDAP certificate troubleshooting.

## Install and Run Wordwarden

For a host service, install the binary, config, env file, and CA file under the
layout described in `deploy/systemd/README.md`.

Recommended production layout:

```text
/usr/local/bin/wordwarden
/etc/authrim-wordwarden/config.yaml
/etc/authrim-wordwarden/wordwarden.env
/etc/authrim-wordwarden/ca/ldap-ca.pem
/etc/systemd/system/authrim-wordwarden.service
```

Start with:

```bash
sudo systemctl enable --now authrim-wordwarden
sudo systemctl status authrim-wordwarden
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/version
```

If Wordwarden is behind a tunnel or reverse proxy, confirm the public endpoint:

```bash
curl -fsS https://wordwarden.example.edu/healthz
```

## Connect Authrim

Authrim needs two related settings groups:

```text
login-methods.directory_password.enabled=true
login-methods.directory_password.connector_id=campus
```

```text
directory-connectors.campus.endpoint_url=https://wordwarden.example.edu
directory-connectors.campus.auth_mode=hmac
directory-connectors.campus.connector_id=ww_tenant_a
directory-connectors.campus.key_id=kid-active
directory-connectors.campus.secret_ref=env:WORDWARDEN_SECRET
directory-connectors.campus.timeouts.request_ms=3000
directory-connectors.campus.attribute_names=mail,displayName,uid
```

The Authrim-side HMAC secret must match the active Wordwarden key for the same
tenant and connector. Authrim should see only the connector endpoint and secret
reference, not LDAP bind credentials.

Wordwarden does not store the remote Authrim URL in Alpha. Authrim calls
Wordwarden, and Wordwarden authenticates those calls using the shared HMAC key
and connector id. `server.public_base_url` is the public Wordwarden URL, not the
Authrim login URL.

## Verify Before Enabling Users

Use this order:

1. `wordwarden config validate`
2. `wordwarden ldap test --tenant <tenant_id>`
3. `wordwarden ldap test --tenant <tenant_id> --username <user> --password-stdin`
4. `curl -fsS http://127.0.0.1:8080/healthz`
5. public or tunnel `GET /healthz`
6. Authrim directory password login
7. confirm Authrim session contains `amr=["pwd","directory"]`

If the first five steps work but Authrim login fails, inspect connector id, tenant
id, HMAC `kid`, HMAC secret, endpoint URL, and request timeout first.

Before enabling the method broadly:

- test at least one normal account
- test a wrong password
- test an unknown user
- test an account with missing `mail`
- test expected username forms, such as `alice` and `alice@example.edu`
- confirm user-facing errors do not reveal directory internals
- confirm Wordwarden audit events and Authrim events share a request id

## Production Readiness Checklist

Before production:

- LDAP TLS verification is enabled.
- LDAP CA and server name are correct.
- Wordwarden is not exposing plain HTTP on an untrusted network.
- HMAC secrets are tenant/connector scoped.
- Active and previous HMAC keys are ready for rotation.
- `config validate` and `ldap test` are part of the deployment runbook.
- Wordwarden logs are collected.
- Operators know where to inspect `directory_password.verify.*`,
  `directory_password.hmac.failure`, and `directory_password.replay.detected`.
- Restart procedure is documented; Alpha does not reload config in place.
- Authrim login method discovery does not expose connector endpoint or secret
  details to browsers.

## Optional Local Sandbox

Use the local Docker Compose demo when you want to validate the product flow
without touching production LDAP/AD.

From the repository root:

```bash
./test/integration/openldap/generate-certs.sh
cp deploy/docker-compose/local-demo/.env.example deploy/docker-compose/local-demo/.env
docker compose -f deploy/docker-compose/local-demo/compose.yaml up -d --build
curl -fsS http://127.0.0.1:8080/healthz
```

Then verify the demo user:

```bash
printf 'password\n' | docker compose -f deploy/docker-compose/local-demo/compose.yaml run --rm -T \
  wordwarden --config /etc/authrim-wordwarden/config.yaml ldap test \
    --tenant tenant-a \
    --username alice \
    --password-stdin
```

The demo user is `alice` with password `password`.

Stop the sandbox:

```bash
docker compose -f deploy/docker-compose/local-demo/compose.yaml down -v
```
