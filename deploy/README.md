# Deployment Samples

These samples are intentionally small Alpha deployment references.

Configuration changes require a process restart. `SIGHUP` is accepted only as an
operator signal that reports reload is not supported yet.

## systemd

Install the binary at `/usr/local/bin/wordwarden`, place configuration and secret
files under `/etc/authrim-wordwarden`, then install:

```bash
sudo install -m 0644 deploy/systemd/authrim-wordwarden.service /etc/systemd/system/authrim-wordwarden.service
sudo systemctl daemon-reload
sudo systemctl enable --now authrim-wordwarden
```

Restart after config, secret reference, LDAP CA, or tenant changes:

```bash
sudo systemctl restart authrim-wordwarden
```

See `deploy/systemd/README.md` for the full service user, env file, validation,
health check, and restart runbook.

## Docker Compose

Copy `deploy/docker-compose/compose.yaml` into an environment-specific directory,
mount a real `config.yaml`, and provide secrets through an env file or a secret
manager sidecar.

```bash
docker compose -f deploy/docker-compose/compose.yaml up -d
```

For a runnable local OpenLDAP + Wordwarden demo, use
`deploy/docker-compose/local-demo/`.

```bash
./test/integration/openldap/generate-certs.sh
cp deploy/docker-compose/local-demo/.env.example deploy/docker-compose/local-demo/.env
docker compose -f deploy/docker-compose/local-demo/compose.yaml up -d --build
curl http://127.0.0.1:8080/healthz
```

The local demo publishes Wordwarden on `127.0.0.1:8080` and OpenLDAP on
`127.0.0.1:1389` / `127.0.0.1:1636`.

## Cloudflare Tunnel

Use `docs/cloudflare-tunnel.md` with the sample config under
`deploy/cloudflare-tunnel/` when Wordwarden should remain behind an outbound
Tunnel instead of exposing an inbound port.

## Public HTTPS

Use `docs/public-https.md` when Wordwarden is exposed as a directly reachable
HTTPS service through a reverse proxy or the built-in TLS listener.
