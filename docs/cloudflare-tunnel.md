# Cloudflare Tunnel Deployment

This guide describes the beta deployment shape for exposing Authrim Wordwarden
to Authrim through Cloudflare Tunnel.

Cloudflare Tunnel is optional. It is useful when an organization does not want to
publish an inbound Wordwarden port directly. Wordwarden still verifies every
Authrim request with HMAC request signing, so Tunnel is a connectivity layer, not
the primary application authentication mechanism.

## Topology

```text
Authrim Worker
  -> HTTPS hostname on Cloudflare
  -> Cloudflare Tunnel
  -> cloudflared inside the organization network
  -> http://127.0.0.1:8080
  -> Authrim Wordwarden
  -> LDAPS / LDAP to directory
```

## Wordwarden Listener

In the Tunnel shape, Wordwarden can listen on localhost HTTP because it is not
directly exposed to the network:

```yaml
server:
  listen: "127.0.0.1:8080"
  public_base_url: "https://wordwarden.example.edu"
  tls:
    enabled: false
```

Production traffic from Authrim to the public hostname is HTTPS. The local
`cloudflared -> Wordwarden` hop stays on the same host or private network.

## Authrim Connector Settings

Configure Authrim tenant settings to point to the Tunnel hostname:

```text
authentication-methods.directory_password.enabled=true
authentication-methods.directory_password.connector_id=campus
directory-connectors.campus.endpoint_url=https://wordwarden.example.edu
directory-connectors.campus.auth_mode=hmac
directory-connectors.campus.connector_id=ww_tenant_a
directory-connectors.campus.key_id=kid-active
directory-connectors.campus.secret_ref=env:WORDWARDEN_SECRET
directory-connectors.campus.timeouts.request_ms=3000
```

The Authrim-side `secret_ref` should resolve to the same HMAC secret configured
as Wordwarden's active key for that tenant/connector.

## cloudflared Example

Create a named tunnel and route a hostname to it using Cloudflare's standard
`cloudflared` workflow. A minimal ingress config looks like:

```yaml
tunnel: <tunnel-id>
credentials-file: /etc/cloudflared/<tunnel-id>.json

ingress:
  - hostname: wordwarden.example.edu
    service: http://127.0.0.1:8080
  - service: http_status:404
```

An example file is available at `deploy/cloudflare-tunnel/config.yml.example`.

Run `cloudflared` as a host service near Wordwarden. Cloudflare recommends
running `cloudflared` as a service so it starts at boot and stays online with the
origin.

## Setup Checklist

On the Wordwarden host:

```bash
sudo install -d -m 0750 /etc/cloudflared
sudo install -m 0640 config.yml /etc/cloudflared/config.yml
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

Validate the ingress config before starting or after edits:

```bash
cloudflared tunnel ingress validate
cloudflared tunnel ingress rule https://wordwarden.example.edu/healthz
```

Then confirm both local and public health checks:

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS https://wordwarden.example.edu/healthz
```

## Hardening

- Keep Wordwarden's listener bound to `127.0.0.1` when cloudflared runs on the
  same host.
- Keep HMAC signing enabled; do not rely on Tunnel alone.
- Use tenant/connector scoped HMAC secrets.
- Rotate HMAC secrets with active/previous key ids.
- Restrict who can edit the Cloudflare hostname and tunnel configuration.
- Collect Wordwarden JSON audit logs.
- Monitor `directory_password.hmac.failure`, `directory_password.replay.detected`,
  and `directory_password.verify.error`.

Cloudflare Access Service Tokens can be added in front of the Tunnel hostname as
extra protection, but they are not the beta baseline because Wordwarden must
remain cloud-agnostic.

If Access Service Tokens are enabled, Authrim must add the service token headers
in addition to HMAC signing. Keep HMAC as the application-level trust boundary
even when Access is enabled.

Workers mTLS is not the baseline for Tunnel deployments. Cloudflare's Workers
mTLS certificate binding currently cannot be used for requests to a service that
is also a Cloudflare-proxied zone; that shape can return a 520. Use HMAC for the
portable baseline, and treat mTLS as an advanced deployment-specific hardening
option for non-proxied origins.

## Verification

From the Wordwarden host:

```bash
wordwarden --config /etc/authrim-wordwarden/config.yaml config validate
wordwarden --config /etc/authrim-wordwarden/config.yaml ldap test --tenant tenant-a
curl -fsS http://127.0.0.1:8080/healthz
```

From a network path that reaches the Cloudflare hostname:

```bash
curl -fsS https://wordwarden.example.edu/healthz
```

Then run an Authrim directory password login and confirm that Wordwarden emits
`directory_password.verify.success` and Authrim creates a session with
`amr=["pwd","directory"]`.

## Troubleshooting

If `https://wordwarden.example.edu/healthz` fails but local health works:

- Check `systemctl status cloudflared`.
- Check `journalctl -u cloudflared -f`.
- Run `cloudflared tunnel ingress validate`.
- Run `cloudflared tunnel ingress rule https://wordwarden.example.edu/healthz`.
- Confirm the hostname route points to the intended tunnel.

If public health works but Authrim login fails:

- Confirm Authrim uses the Tunnel hostname in `directory-connectors.*.endpoint_url`.
- Confirm Authrim and Wordwarden share the same HMAC `kid` and secret.
- Inspect Wordwarden audit logs for HMAC, replay, rate-limit, or directory
  errors.
- Run `wordwarden ldap test --tenant <tenant_id>` from the Wordwarden host.

## References

- Cloudflare Tunnel configuration file:
  `https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/`
- Cloudflare Tunnel as a service:
  `https://developers.cloudflare.com/tunnel/advanced/local-management/as-a-service/`
- Cloudflare Workers mTLS:
  `https://developers.cloudflare.com/workers/runtime-apis/bindings/mtls/`
