# Public HTTPS Deployment

This guide describes the Alpha deployment shape for exposing Authrim Wordwarden
as a directly reachable HTTPS service.

Use this shape only when the organization is willing to publish a Wordwarden
hostname. Prefer Cloudflare Tunnel, VPN, or another private path when inbound
exposure is not acceptable.

## Topology

```text
Authrim Worker
  -> https://wordwarden.example.edu
  -> reverse proxy or Wordwarden TLS listener
  -> Authrim Wordwarden
  -> LDAPS / LDAP to directory
```

Every Authrim request must still be authenticated with HMAC. TLS protects the
transport; HMAC is the application-level trust boundary.

mTLS is optional hardening for deployments that can operate client certificates
at the reverse proxy, load balancer, or direct Wordwarden TLS listener. Do not
replace HMAC with mTLS; use mTLS as an additional transport admission control.

## Listener Options

### Reverse Proxy Recommended

Run Wordwarden on localhost and terminate public HTTPS at an existing reverse
proxy:

```yaml
server:
  listen: "127.0.0.1:8080"
  public_base_url: "https://wordwarden.example.edu"
  tls:
    enabled: false
```

The reverse proxy should:

- redirect HTTP to HTTPS
- use a valid public certificate
- preserve the request body and headers
- pass through all `X-Authrim-*` headers unchanged
- enforce a small request body limit
- use short upstream timeouts

### Direct TLS

Wordwarden can terminate TLS itself when a reverse proxy is not available:

```yaml
server:
  listen: "0.0.0.0:8443"
  public_base_url: "https://wordwarden.example.edu:8443"
  tls:
    enabled: true
    cert_file_ref: "file:/etc/authrim-wordwarden/tls/fullchain.pem"
    key_file_ref: "file:/etc/authrim-wordwarden/tls/privkey.pem"
```

Keep certificate and key files readable only by the Wordwarden service user or
group.

## Authrim Connector Settings

```text
directory-connectors.campus.endpoint_url=https://wordwarden.example.edu
directory-connectors.campus.auth_mode=hmac
directory-connectors.campus.connector_id=ww_tenant_a
directory-connectors.campus.key_id=kid-active
directory-connectors.campus.secret_ref=env:WORDWARDEN_SECRET
directory-connectors.campus.timeouts.request_ms=3000
```

The `endpoint_url` must use HTTPS unless it is a loopback development endpoint.

## Hardening Checklist

- Bind Wordwarden to localhost when a reverse proxy is used.
- Keep HMAC signing enabled.
- Use tenant/connector scoped HMAC secrets.
- Rotate HMAC secrets with active/previous key ids.
- Add mTLS at the reverse proxy or direct listener when the deployment can
  operate client certificates reliably.
- Use LDAPS or StartTLS-capable deployment once StartTLS is implemented.
- Keep LDAP TLS certificate verification enabled.
- Restrict firewall ingress to known Authrim egress ranges when that is
  operationally possible.
- Use small body limits and request timeouts at the reverse proxy.
- Monitor Wordwarden audit events and process logs.
- Do not expose `config.yaml`, secret files, or local audit files through the
  reverse proxy.

## Verification

From the Wordwarden host:

```bash
wordwarden --config /etc/authrim-wordwarden/config.yaml config validate
wordwarden --config /etc/authrim-wordwarden/config.yaml ldap test --tenant tenant-a
curl -fsS http://127.0.0.1:8080/healthz
```

From outside the organization network:

```bash
curl -fsS https://wordwarden.example.edu/healthz
```

Then run an Authrim directory password login and confirm that Wordwarden emits
`directory_password.verify.success` and Authrim creates a session with
`amr=["pwd","directory"]`.

## Troubleshooting

If public health works but Authrim login fails, check:

- reverse proxy header pass-through for `X-Authrim-*`
- HMAC `kid` and secret alignment
- Authrim `endpoint_url`
- reverse proxy request body limits
- Wordwarden audit events for HMAC, replay, rate-limit, or directory errors

If local health works but public health fails, check:

- DNS record
- public certificate validity
- reverse proxy upstream target
- host firewall rules
- service status for Wordwarden and the reverse proxy
